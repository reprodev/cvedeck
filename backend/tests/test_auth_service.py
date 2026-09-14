"""Accounts, sessions, tokens and the setup code, below the HTTP layer.

Validates Req 16.2, 16.3, 16.4, 16.5, 16.6, 16.7, 16.8, 16.9.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import config
from app.auth import passwords, tokens
from app.auth.service import (
    SESSION_ABSOLUTE,
    SESSION_IDLE,
    SETUP_CODE_TTL,
    AuthError,
    AuthService,
)
from app.auth.throttle import BASE_DELAY, FREE_ATTEMPTS, MAX_DELAY, LoginThrottle
from app.data.schema import ApiToken, AuthSession, AuthSetup, Base, User
from app.services import sync

GOOD = "correct horse battery"


class Clock:
    def __init__(self):
        self.now = datetime(2026, 9, 14, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now

    def advance(self, **kwargs):
        self.now += timedelta(**kwargs)


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


@pytest.fixture()
def clock():
    return Clock()


@pytest.fixture()
def service(session, clock):
    return AuthService(session, now=clock)


# --------------------------------------------------------------------------- #
# Passwords (Req 16.2)
# --------------------------------------------------------------------------- #


def test_a_password_verifies_against_its_own_hash_only():
    stored = passwords.hash_password(GOOD)

    assert stored.startswith("scrypt$")
    assert GOOD not in stored
    assert passwords.verify_password(GOOD, stored)
    assert not passwords.verify_password(GOOD + "!", stored)


def test_the_same_password_hashes_differently_each_time():
    assert passwords.hash_password(GOOD) != passwords.hash_password(GOOD)


@pytest.mark.parametrize("stored", ["", "plain", "bcrypt$x$y", "scrypt$a$b$c$d$e"])
def test_a_malformed_hash_is_a_mismatch_not_an_exception(stored):
    assert passwords.verify_password(GOOD, stored) is False


def test_weaker_parameters_are_flagged_for_rehash():
    assert not passwords.needs_rehash(passwords.hash_password(GOOD))
    assert passwords.needs_rehash("scrypt$16384$8$1$c2FsdA$aGFzaA")


@pytest.mark.parametrize("bad", ["", "short", "x" * (passwords.MIN_LENGTH - 1)])
def test_short_passwords_are_refused_with_the_reason(service, bad):
    with pytest.raises(AuthError, match="at least"):
        service.create_user("admin", bad)


def test_an_unknown_username_and_a_wrong_password_both_return_nothing(service):
    service.create_user("admin", GOOD)

    assert service.authenticate("admin", "wrong password here") is None
    assert service.authenticate("nobody", GOOD) is None
    assert service.authenticate("admin", GOOD) is not None


def test_an_unknown_username_still_does_the_hashing_work(service, monkeypatch):
    calls = []
    real = passwords.verify_password
    monkeypatch.setattr(
        passwords, "verify_password", lambda p, s: calls.append(s) or real(p, s)
    )

    service.authenticate("nobody", GOOD)

    assert len(calls) == 1, "unknown usernames must cost a verification, like real ones"


# --------------------------------------------------------------------------- #
# Setup code and environment bootstrap (Req 16.3, 16.4)
# --------------------------------------------------------------------------- #


def test_a_setup_code_is_issued_only_while_there_is_no_account(service, session):
    code = service.issue_setup_code()
    assert code is not None and len(tokens.normalise_setup_code(code)) == 12
    row = session.scalar(select(AuthSetup))
    assert code not in row.code_hash, "only a hash of the code is stored"

    service.complete_setup(code, "admin", GOOD)

    assert service.issue_setup_code() is None
    assert session.scalar(select(AuthSetup)) is None


def test_a_setup_code_works_once(service):
    code = service.issue_setup_code()
    service.complete_setup(code, "admin", GOOD)

    with pytest.raises(AuthError):
        service.complete_setup(code, "second", GOOD)


def test_a_setup_code_is_accepted_however_it_is_typed(service):
    code = service.issue_setup_code()

    service.complete_setup(code.lower().replace("-", " "), "admin", GOOD)


def test_a_wrong_setup_code_is_refused(service):
    service.issue_setup_code()

    with pytest.raises(AuthError, match="setup code"):
        service.complete_setup("AAAA-AAAA-AAAA", "admin", GOOD)
    assert not service.has_users()


def test_a_setup_code_expires(service, clock):
    code = service.issue_setup_code()
    clock.advance(seconds=SETUP_CODE_TTL.total_seconds() + 1)

    with pytest.raises(AuthError, match="setup code"):
        service.complete_setup(code, "admin", GOOD)


def test_issuing_a_new_code_invalidates_the_previous_one(service):
    old = service.issue_setup_code()
    new = service.issue_setup_code()

    with pytest.raises(AuthError):
        service.complete_setup(old, "admin", GOOD)
    service.complete_setup(new, "admin", GOOD)


def test_bootstrap_creates_the_account_when_none_exists(service):
    assert service.bootstrap_from_env("admin", GOOD) is True
    assert service.authenticate("admin", GOOD) is not None


def test_bootstrap_never_overwrites_an_existing_account(service):
    service.create_user("admin", GOOD)

    assert service.bootstrap_from_env("admin", "a different password") is False
    assert service.authenticate("admin", GOOD) is not None


def test_bootstrap_needs_both_values(service):
    assert service.bootstrap_from_env("admin", None) is False
    assert service.bootstrap_from_env(None, GOOD) is False
    assert not service.has_users()


# --------------------------------------------------------------------------- #
# Sessions (Req 16.5, 16.6)
# --------------------------------------------------------------------------- #


def _signed_in(service):
    user = service.create_user("admin", GOOD)
    return user, service.start_session(user)


def test_a_session_token_is_stored_only_as_a_hash(service, session):
    _, token = _signed_in(service)
    session.flush()

    stored = [row.token_hash for row in session.scalars(select(AuthSession))]
    assert stored == [tokens.hash_token(token)]


def test_every_sign_in_gets_a_new_token(service):
    user = service.create_user("admin", GOOD)

    assert service.start_session(user) != service.start_session(user)


def test_a_session_resolves_until_it_is_idle_too_long(service, clock):
    _, token = _signed_in(service)
    assert service.resolve_session(token).username == "admin"

    clock.advance(seconds=SESSION_IDLE.total_seconds() + 1)

    assert service.resolve_session(token) is None


def test_activity_keeps_a_session_alive_but_not_past_its_absolute_expiry(service, clock):
    _, token = _signed_in(service)

    elapsed = timedelta()
    while elapsed + timedelta(days=5) < SESSION_ABSOLUTE:
        clock.advance(days=5)
        elapsed += timedelta(days=5)
        assert service.resolve_session(token) is not None

    clock.advance(seconds=(SESSION_ABSOLUTE - elapsed).total_seconds() + 1)
    assert service.resolve_session(token) is None


def test_signing_out_ends_the_session(service):
    _, token = _signed_in(service)

    service.end_session(token)

    assert service.resolve_session(token) is None


def test_changing_the_password_signs_out_every_other_session(service):
    user = service.create_user("admin", GOOD)
    here = service.start_session(user)
    elsewhere = service.start_session(user)
    keep = service.resolve_session(here).session_token_hash

    service.change_password("admin", GOOD, "a brand new passphrase", keep_session_hash=keep)

    assert service.resolve_session(here) is not None
    assert service.resolve_session(elsewhere) is None
    assert service.authenticate("admin", "a brand new passphrase") is not None


def test_changing_the_password_needs_the_current_one(service):
    service.create_user("admin", GOOD)

    with pytest.raises(AuthError, match="current password"):
        service.change_password("admin", "not the password", "a brand new passphrase", None)


def test_a_reset_signs_out_everywhere(service):
    _, token = _signed_in(service)

    service.reset_password("admin", "a brand new passphrase")

    assert service.resolve_session(token) is None


# --------------------------------------------------------------------------- #
# API tokens (Req 16.7)
# --------------------------------------------------------------------------- #


def test_an_api_token_works_until_revoked(service, session):
    row, token = service.create_api_token("feed refresh cron")

    assert token.startswith(tokens.API_TOKEN_PREFIX)
    assert token not in {r.token_hash for r in session.scalars(select(ApiToken))}
    assert row.prefix == token[: len(row.prefix)] and len(row.prefix) < len(token)
    assert service.resolve_api_token(token).kind == "token"

    assert service.revoke_api_token(row.id) is True

    assert service.resolve_api_token(token) is None
    assert service.list_api_tokens()[0].revoked_at is not None


def test_a_token_records_when_it_was_last_used(service, clock):
    row, token = service.create_api_token("script")
    assert row.last_used_at is None

    service.resolve_api_token(token)

    assert row.last_used_at is not None


def test_a_token_needs_a_name(service):
    with pytest.raises(AuthError):
        service.create_api_token("   ")


def test_revoking_an_unknown_token_reports_it(service):
    assert service.revoke_api_token("missing") is False


# --------------------------------------------------------------------------- #
# Throttle (Req 16.8)
# --------------------------------------------------------------------------- #


def test_the_throttle_allows_a_few_failures_then_backs_off_and_doubles():
    now = [0.0]
    throttle = LoginThrottle(clock=lambda: now[0])

    for _ in range(FREE_ATTEMPTS - 1):
        throttle.record_failure("10.0.0.5", "admin")
    assert throttle.retry_after("10.0.0.5", "admin") == 0

    throttle.record_failure("10.0.0.5", "admin")
    assert throttle.retry_after("10.0.0.5", "admin") == int(BASE_DELAY)

    throttle.record_failure("10.0.0.5", "admin")
    assert throttle.retry_after("10.0.0.5", "admin") == int(BASE_DELAY * 2)

    for _ in range(40):
        throttle.record_failure("10.0.0.5", "admin")
    assert throttle.retry_after("10.0.0.5", "admin") == int(MAX_DELAY)


def test_the_throttle_is_per_address_and_username_and_clears_on_success():
    throttle = LoginThrottle(clock=lambda: 0.0)
    for _ in range(FREE_ATTEMPTS):
        throttle.record_failure("10.0.0.5", "Admin")

    assert throttle.retry_after("10.0.0.5", "admin") > 0
    assert throttle.retry_after("10.0.0.6", "admin") == 0
    assert throttle.retry_after("10.0.0.5", "someone-else") == 0

    throttle.record_success("10.0.0.5", "admin")
    assert throttle.retry_after("10.0.0.5", "admin") == 0


# --------------------------------------------------------------------------- #
# Configuration and isolation (Req 16.9)
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("value", [None, "", "enabled", "true", "disable", "flase", "nonsense"])
def test_login_stays_on_unless_explicitly_disabled(monkeypatch, value):
    if value is None:
        monkeypatch.delenv("CVEDECK_AUTH", raising=False)
    else:
        monkeypatch.setenv("CVEDECK_AUTH", value)

    assert config.auth_enabled() is True


@pytest.mark.parametrize("value", ["disabled", "DISABLED", "off", "false", "0", "no"])
def test_login_can_be_switched_off(monkeypatch, value):
    monkeypatch.setenv("CVEDECK_AUTH", value)

    assert config.auth_enabled() is False


def test_the_admin_password_can_come_from_a_file(monkeypatch, tmp_path):
    secret = tmp_path / "pw"
    secret.write_text(GOOD + "\n", encoding="utf-8")
    monkeypatch.setenv("CVEDECK_ADMIN_PASSWORD", "ignored when a file is given")
    monkeypatch.setenv("CVEDECK_ADMIN_PASSWORD_FILE", str(secret))

    assert config.admin_password() == GOOD


def test_auth_tables_are_never_synchronised():
    synced = {model.__tablename__ for model in sync._SYNC_ORDER}

    assert not synced & {"users", "auth_sessions", "api_tokens", "auth_setup"}
    assert not {User, AuthSession, ApiToken, AuthSetup} & set(sync._SYNC_ORDER)
