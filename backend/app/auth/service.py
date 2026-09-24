"""Accounts, sessions, API tokens and the first-run setup code (Req 16).

:class:`AuthService` works on a SQLAlchemy session and commits nothing itself;
callers commit, as with the rest of the data layer. Time comes from an
injectable clock so expiry is testable without sleeping.

Datetimes are written timezone-aware in UTC and read back through
:func:`_as_utc`, because SQLite drops the offset on the way in and PostgreSQL
does not.
"""

from __future__ import annotations

import hmac
import logging
import uuid
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from sqlalchemy import delete, func, select
from sqlalchemy.orm import Session

from ..data.schema import ApiToken, AuthSession, AuthSetup, User
from . import passwords, tokens

logger = logging.getLogger(__name__)

#: A session ends this long after sign-in, however active (Req 16.5).
SESSION_ABSOLUTE = timedelta(days=30)
#: ...or after this long without a request, whichever comes first.
SESSION_IDLE = timedelta(days=7)
#: ``last_seen_at`` / ``last_used_at`` are written at most this often, so a
#: dashboard polling the API does not turn every read into a write.
TOUCH_INTERVAL = timedelta(minutes=5)
#: How long a logged setup code stays valid. A restart issues a new one.
SETUP_CODE_TTL = timedelta(hours=24)

USERNAME_MAX = 64
TOKEN_NAME_MAX = 80


class AuthError(Exception):
    """A refused auth operation. The message is safe to show the user."""


class WrongSecretError(AuthError):
    """A guessable secret was wrong: a setup code, or the current password.

    Its own type so that the routes count it towards throttling by what it is,
    not by matching the wording of its message -- which a reworded error would
    silently stop doing (Req 16.8).
    """


@dataclass(frozen=True)
class Principal:
    """Who a request is acting as.

    ``kind`` is ``session`` or ``token`` for an authenticated caller, and
    ``open`` when login is not required (auth disabled, or demo mode).
    """

    kind: str
    username: str | None = None
    session_token_hash: str | None = None


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _as_utc(value: datetime) -> datetime:
    return value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)


def _clean_username(username: str) -> str:
    cleaned = username.strip()
    if not cleaned:
        raise AuthError("Enter a username.")
    if len(cleaned) > USERNAME_MAX:
        raise AuthError(f"Use a username of at most {USERNAME_MAX} characters.")
    return cleaned


class AuthService:
    def __init__(self, session: Session, now: Callable[[], datetime] = _utcnow):
        self._session = session
        self._now = now

    # ------------------------------------------------------------------ #
    # Accounts
    # ------------------------------------------------------------------ #

    def has_users(self) -> bool:
        return bool(self._session.scalar(select(func.count()).select_from(User)))

    def get_user(self, username: str) -> User | None:
        return self._session.scalar(select(User).where(User.username == username.strip()))

    def create_user(self, username: str, password: str) -> User:
        """Create an account, applying the username and password policy."""
        name = _clean_username(username)
        try:
            passwords.check_policy(password)
        except passwords.PasswordPolicyError as exc:
            raise AuthError(str(exc)) from exc
        if self.get_user(name) is not None:
            raise AuthError("That username is already taken.")
        now = self._now()
        user = User(
            id=str(uuid.uuid4()),
            username=name,
            password_hash=passwords.hash_password(password),
            created_at=now,
            password_changed_at=now,
        )
        self._session.add(user)
        self._session.flush()
        return user

    def authenticate(self, username: str, password: str) -> User | None:
        """The account for these credentials, or ``None``.

        An unknown username costs the same scrypt work as a wrong password, so
        the two cannot be told apart by timing (Req 16.2).
        """
        user = self.get_user(username) if username.strip() else None
        if user is None:
            passwords.burn_time(password)
            return None
        if not passwords.verify_password(password, user.password_hash):
            return None
        if passwords.needs_rehash(user.password_hash):
            user.password_hash = passwords.hash_password(password)
        return user

    def change_password(
        self, username: str, current: str, new: str, keep_session_hash: str | None
    ) -> None:
        """Change a password and sign out every other session (Req 16.6)."""
        user = self.authenticate(username, current)
        if user is None:
            raise WrongSecretError("Your current password is incorrect.")
        self._set_password(user, new, keep_session_hash)

    def reset_password(self, username: str, new: str) -> int:
        """Set a password without the old one, sign out everywhere, revoke every token.

        Only reachable from ``cvedeck-admin``, i.e. from a shell on the host --
        which makes it the recovery path after a compromise, so it has to end
        every way in. Before 0.8.13 it ended sessions and left API tokens
        working: a token planted by whoever got in survived the reset meant to
        lock them out (Req 16.12). Returns how many tokens it revoked.
        """
        user = self.get_user(username)
        if user is None:
            raise AuthError(f"No account named {username!r}.")
        self._set_password(user, new, keep_session_hash=None)
        return self.revoke_all_api_tokens()

    def _set_password(self, user: User, new: str, keep_session_hash: str | None) -> None:
        try:
            passwords.check_policy(new)
        except passwords.PasswordPolicyError as exc:
            raise AuthError(str(exc)) from exc
        user.password_hash = passwords.hash_password(new)
        user.password_changed_at = self._now()
        stmt = delete(AuthSession).where(AuthSession.user_id == user.id)
        if keep_session_hash is not None:
            stmt = stmt.where(AuthSession.token_hash != keep_session_hash)
        self._session.execute(stmt)

    # ------------------------------------------------------------------ #
    # First run
    # ------------------------------------------------------------------ #

    def bootstrap_from_env(self, username: str | None, password: str | None) -> bool:
        """Create the account from configuration when none exists (Req 16.4).

        Never touches an existing account, so leaving the variables set does not
        reset a password that has since been changed in the dashboard.
        """
        if not username or not password or self.has_users():
            return False
        self.create_user(username, password)
        self._session.execute(delete(AuthSetup))
        return True

    def issue_setup_code(self) -> str | None:
        """A fresh setup code when no account exists, else ``None`` (Req 16.3).

        Replaces any earlier code, so only the most recently logged one works.
        """
        self._session.execute(delete(AuthSetup))
        if self.has_users():
            return None
        code = tokens.new_setup_code()
        self._session.add(
            AuthSetup(
                id=1,
                code_hash=tokens.hash_token(tokens.normalise_setup_code(code)),
                expires_at=self._now() + SETUP_CODE_TTL,
            )
        )
        return code

    def complete_setup(self, code: str, username: str, password: str) -> User:
        """Create the first account with a valid setup code, and spend the code."""
        if self.has_users():
            raise AuthError("This instance already has an account. Sign in instead.")
        row = self._session.scalar(select(AuthSetup))
        supplied = tokens.hash_token(tokens.normalise_setup_code(code))
        if (
            row is None
            or _as_utc(row.expires_at) <= self._now()
            or not _constant_eq(supplied, row.code_hash)
        ):
            raise WrongSecretError(
                "That setup code is not valid. Use the latest code from the "
                "container logs; restarting the container issues a new one."
            )
        user = self.create_user(username, password)
        self._session.execute(delete(AuthSetup))
        return user

    # ------------------------------------------------------------------ #
    # Sessions
    # ------------------------------------------------------------------ #

    def start_session(self, user: User) -> str:
        """A new session token for ``user``. Always new, never reused."""
        token = tokens.new_session_token()
        now = self._now()
        self._session.add(
            AuthSession(
                token_hash=tokens.hash_token(token),
                user_id=user.id,
                created_at=now,
                last_seen_at=now,
                expires_at=now + SESSION_ABSOLUTE,
            )
        )
        return token

    def end_session(self, token: str) -> None:
        self._session.execute(
            delete(AuthSession).where(AuthSession.token_hash == tokens.hash_token(token))
        )

    def resolve_session(self, token: str) -> Principal | None:
        """The principal for a session cookie, or ``None`` if it is not current."""
        token_hash = tokens.hash_token(token)
        row = self._session.get(AuthSession, token_hash)
        if row is None:
            return None
        now = self._now()
        if _as_utc(row.expires_at) <= now or _as_utc(row.last_seen_at) + SESSION_IDLE <= now:
            self._session.delete(row)
            return None
        user = self._session.get(User, row.user_id)
        if user is None:
            return None
        if now - _as_utc(row.last_seen_at) >= TOUCH_INTERVAL:
            row.last_seen_at = now
        return Principal(kind="session", username=user.username, session_token_hash=token_hash)

    # ------------------------------------------------------------------ #
    # API tokens
    # ------------------------------------------------------------------ #

    def create_api_token(self, name: str) -> tuple[ApiToken, str]:
        """Create a token. The plain value is returned here and nowhere else."""
        cleaned = name.strip()
        if not cleaned:
            raise AuthError("Give the token a name, such as what will use it.")
        if len(cleaned) > TOKEN_NAME_MAX:
            raise AuthError(f"Use a name of at most {TOKEN_NAME_MAX} characters.")
        token = tokens.new_api_token()
        row = ApiToken(
            id=str(uuid.uuid4()),
            name=cleaned,
            token_hash=tokens.hash_token(token),
            prefix=tokens.display_prefix(token),
            created_at=self._now(),
        )
        self._session.add(row)
        self._session.flush()
        return row, token

    def list_api_tokens(self) -> list[ApiToken]:
        return list(self._session.scalars(select(ApiToken).order_by(ApiToken.created_at)))

    def revoke_api_token(self, token_id: str) -> bool:
        row = self._session.get(ApiToken, token_id)
        if row is None:
            return False
        if row.revoked_at is None:
            row.revoked_at = self._now()
        return True

    def revoke_all_api_tokens(self) -> int:
        """Revoke every live API token; return how many there were (Req 16.18)."""
        now = self._now()
        live = list(self._session.scalars(select(ApiToken).where(ApiToken.revoked_at.is_(None))))
        for row in live:
            row.revoked_at = now
        return len(live)

    def resolve_api_token(self, token: str) -> Principal | None:
        row = self._session.scalar(
            select(ApiToken).where(ApiToken.token_hash == tokens.hash_token(token))
        )
        if row is None or row.revoked_at is not None:
            return None
        now = self._now()
        if row.last_used_at is None or now - _as_utc(row.last_used_at) >= TOUCH_INTERVAL:
            row.last_used_at = now
        return Principal(kind="token", username=f"token:{row.name}")


def _constant_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("ascii"), b.encode("ascii"))
