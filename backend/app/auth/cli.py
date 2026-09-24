"""``cvedeck-admin``: administer an instance from a shell on the host (Req 16.12).

For when the password is lost, and for jobs that run on the host itself. Anyone
who can run this can already read the database file, so it grants nothing new --
which is why it may skip the current password the dashboard insists on, and why
the systemd feed timer uses ``refresh-feeds`` instead of an API token.

    docker exec -it --user 1000:1000 cvedeck cvedeck-admin reset-password
    docker exec -it --user 1000:1000 cvedeck cvedeck-admin create-user admin
    cvedeck-admin refresh-feeds

Run it as the user that owns the data directory (``PUID:PGID``), or SQLite may
leave a root-owned journal file behind that the server then cannot write.
"""

from __future__ import annotations

import argparse
import getpass
import sys

from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session

from .. import config
from ..data.migrations_runtime import upgrade_to_head
from ..data.schema import AuthSetup, User
from .service import AuthError, AuthService


def _read_password(from_stdin: bool) -> str:
    if from_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    first = getpass.getpass("New password: ")
    second = getpass.getpass("Repeat it: ")
    if first != second:
        raise AuthError("The two passwords did not match.")
    return first


def _session() -> Session:
    url = config.database_url()
    if url.startswith("sqlite"):
        config.data_dir().mkdir(parents=True, exist_ok=True)
    engine = create_engine(url)
    upgrade_to_head(engine)
    return Session(engine)


def _only_username(session: Session) -> str:
    names = list(session.scalars(select(User.username)))
    if not names:
        raise AuthError("There is no account yet. Use create-user, or the setup code in the logs.")
    if len(names) > 1:
        raise AuthError("There is more than one account; name it with --username.")
    return names[0]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="cvedeck-admin", description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    reset = sub.add_parser("reset-password", help="set a new password and sign out everywhere")
    reset.add_argument("--username", help="defaults to the only account")
    reset.add_argument("--password-stdin", action="store_true", help="read the password from stdin")

    create = sub.add_parser("create-user", help="create the account when none exists")
    create.add_argument("username")
    create.add_argument("--password-stdin", action="store_true", help="read the password from stdin")

    sub.add_parser(
        "refresh-feeds",
        help="download the CISA KEV and FIRST EPSS feeds into the local cache",
    )

    args = parser.parse_args(argv)
    if args.command == "refresh-feeds":
        return _refresh_feeds()
    try:
        with _session() as session:
            service = AuthService(session)
            if args.command == "reset-password":
                username = args.username or _only_username(session)
                revoked = service.reset_password(username, _read_password(args.password_stdin))
                session.commit()
                print(
                    f"Password reset for {username!r}. Every session has been signed "
                    f"out and {revoked} API token(s) revoked (Req 16.12)."
                )
            else:
                if service.has_users():
                    raise AuthError(
                        "An account already exists. Use reset-password to regain access."
                    )
                service.create_user(args.username, _read_password(args.password_stdin))
                session.query(AuthSetup).delete()
                session.commit()
                print(f"Created the account {args.username!r}. Sign in at the dashboard.")
    except AuthError as exc:
        print(f"cvedeck-admin: {exc}", file=sys.stderr)
        return 1
    return 0


def _refresh_feeds() -> int:
    """The same refresh as ``POST /api/feeds/refresh``, without going over HTTP.

    Exits non-zero if either feed failed, so a scheduler reports it. A refresh
    declined because the instance is in demo mode is **not** a failure: the
    documented deployment installs this command on a timer, and a timer that
    reports failure every hour on a working demo trains its operator to ignore
    it. It says what it did instead, because silently printing the usual
    success line is how the operator would never learn their fixture was safe
    only by accident (Req 15.6).
    """
    from ..data.repository import Repository
    from ..enums import FeedStatus
    from ..services.enrichment import refresh_feeds_and_reapply

    with _session() as session:
        outcomes, updated = refresh_feeds_and_reapply(Repository(session))
        session.commit()

    if outcomes and all(outcome.status is FeedStatus.SKIPPED for outcome in outcomes):
        print(
            "demo mode: no feed was refreshed. The seeded intel is a fixture "
            "and refreshing would overwrite it permanently."
        )
        return 0

    for outcome in outcomes:
        detail = f" ({outcome.error_detail})" if outcome.error_detail else ""
        if outcome.unchanged:
            detail = " (unchanged)" + detail
        print(f"{outcome.feed_name}: {outcome.status}, {outcome.record_count} records{detail}")
    print(f"findings updated: {updated}")
    return 0 if all(outcome.ok for outcome in outcomes) else 1


if __name__ == "__main__":
    raise SystemExit(main())
