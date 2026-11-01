"""``cvedeck-admin``: administer an instance from a shell on the host (Req 16.12).

For when the password is lost, and for jobs that run on the host itself. Anyone
who can run this can already read the database file, so it grants nothing new --
which is why it may skip the current password the dashboard insists on, and why
the systemd feed timer uses ``refresh-feeds`` instead of an API token.

    docker exec -it --user 1000:1000 cvedeck cvedeck-admin reset-password
    docker exec -it --user 1000:1000 cvedeck cvedeck-admin create-user admin
    cvedeck-admin refresh-feeds
    docker exec --user 1000:1000 cvedeck cvedeck-admin backup /data/backup.db

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
    from ..api.dependencies import SQLITE_BUSY_TIMEOUT

    url = config.database_url()
    connect_args = {}
    if url.startswith("sqlite"):
        config.data_dir().mkdir(parents=True, exist_ok=True)
        # Runs beside the server, against the same file: wait for its writes
        # the way it waits for ours.
        connect_args = {"timeout": SQLITE_BUSY_TIMEOUT}
    engine = create_engine(url, connect_args=connect_args)
    # The same journal as the server it runs beside (Req 13.10).
    from ..data.sqlite_journal import configure_sqlite

    configure_sqlite(engine, config.sqlite_journal())
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

    backup = sub.add_parser(
        "backup",
        help="write a consistent copy of the SQLite database while CveDeck runs",
    )
    backup.add_argument("target", help="file to write the copy to")
    backup.add_argument("--force", action="store_true", help="replace the target if it exists")

    args = parser.parse_args(argv)
    if args.command == "refresh-feeds":
        return _refresh_feeds()
    if args.command == "backup":
        return _backup(args.target, force=args.force)
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


def _backup(target: str, *, force: bool = False) -> int:
    """Copy the live SQLite database with SQLite's online backup API (Req 13.11).

    ``cp cvedeck.db`` copies whatever is on disk at that moment: under WAL the
    newest writes are still in ``cvedeck.db-wal``, and even with the rollback
    journal a copy taken mid-commit can be torn. The backup API takes a
    consistent snapshot while CveDeck keeps running, in either journal mode.
    The copy is then integrity-checked, so a backup that will not open is
    found now rather than on the day it is needed.

    Refuses to overwrite a file unless ``--force``, to write over the live
    database, and to run against PostgreSQL, which has ``pg_dump`` for this.
    Allowed in demo mode: it only reads the database it copies.
    """
    import os
    import sqlite3
    from pathlib import Path

    url = config.database_url()
    if not url.startswith("sqlite"):
        print(
            "cvedeck-admin: backup copies a SQLite database; this deployment uses "
            "PostgreSQL. Use pg_dump.",
            file=sys.stderr,
        )
        return 1
    from sqlalchemy.engine import make_url

    source = make_url(url).database
    if not source or source == ":memory:" or not Path(source).exists():
        print(f"cvedeck-admin: there is no database file at {source!r} to back up.", file=sys.stderr)
        return 1
    destination = Path(target)
    if destination.exists() and os.path.samefile(destination, source):
        print("cvedeck-admin: refusing to write the backup over the live database.", file=sys.stderr)
        return 1
    if destination.exists() and not force:
        print(f"cvedeck-admin: {destination} already exists; use --force to replace it.", file=sys.stderr)
        return 1
    partial = destination.with_name(destination.name + ".partial")
    partial.unlink(missing_ok=True)
    # An ordinary connection that only reads. Not mode=ro: a WAL database
    # opened read-only fails when its -wal and -shm files are absent, which is
    # exactly the state a clean stop leaves.
    live = sqlite3.connect(source, timeout=30.0)
    copy = sqlite3.connect(partial)
    try:
        live.backup(copy)
        result = _integrity_check(copy)
        # A self-contained file whatever journal the live database keeps.
        copy.execute("PRAGMA journal_mode=DELETE")
    finally:
        copy.close()
        live.close()
    if not result or result[0] != "ok":
        partial.unlink(missing_ok=True)
        print(f"cvedeck-admin: the copy failed its integrity check: {result}", file=sys.stderr)
        return 1
    os.replace(partial, destination)
    size = destination.stat().st_size
    print(f"Backed up {source} to {destination} ({size / 1_048_576:.1f} MB, integrity check ok).")
    return 0


def _integrity_check(connection) -> tuple | None:
    """SQLite's own verdict on a database: ``("ok",)`` when sound."""
    return connection.execute("PRAGMA integrity_check").fetchone()


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
        outcomes, updated = refresh_feeds_and_reapply(Repository(session), checkpoint=session.commit)
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
