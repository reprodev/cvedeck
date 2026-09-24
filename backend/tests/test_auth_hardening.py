"""0.8.13: the costs and the recoveries around sign-in.

Req 16.12: resetting the password from the host ends every way in, API tokens
included -- it is the recovery after a compromise, and a token planted by
whoever got in used to survive it.

Req 16.18: every token can be revoked at once, for a leak nobody can pin to one.

Req 16.19: the actions that aim CveDeck at other machines, re-open trust in a
host, or show a guessing attack in progress leave a line in the security log.

Req 16.20: made-up usernames are throttled per address, and scrypt runs a
bounded number at a time -- each attempt costs about 32 MiB whether or not the
account exists, which is what keeps timing from revealing usernames.
"""

from __future__ import annotations

import logging
import threading
import time

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.app import create_app
from app.api.dependencies import get_session
from app.auth import passwords
from app.auth.service import AuthService, WrongSecretError
from app.auth.throttle import FREE_ATTEMPTS_PER_CLIENT, throttle
from app.data.repository import Repository
from app.data.schema import Base

GOOD = "correct horse battery"
ORIGIN = {"Origin": "http://testserver"}


@pytest.fixture(autouse=True)
def _login_on(monkeypatch):
    monkeypatch.delenv("CVEDECK_AUTH", raising=False)
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)
    throttle.reset()
    yield
    throttle.reset()


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}, poolclass=StaticPool
    )
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        AuthService(sess).create_user("admin", GOOD)
        sess.commit()
        yield sess


@pytest.fixture()
def client(session):
    app = create_app()
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


def _signed_in(client):
    assert client.post(
        "/api/auth/login", json={"username": "admin", "password": GOOD}, headers=ORIGIN
    ).status_code == 200
    return client


# --- Req 16.20 --------------------------------------------------------------


def test_spraying_made_up_usernames_is_throttled_per_address(client):
    """Each name is new, so the per-account count never trips; the address does."""
    for i in range(FREE_ATTEMPTS_PER_CLIENT):
        r = client.post("/api/auth/login", json={"username": f"nobody{i}", "password": "x" * 12})
        assert r.status_code == 401, i

    r = client.post("/api/auth/login", json={"username": "someone-else", "password": "x" * 12})

    assert r.status_code == 429


def test_one_person_mistyping_is_not_locked_out_by_the_address_limit(client):
    """The per-address limit is looser than the per-account one, on purpose."""
    for i in range(4):
        client.post("/api/auth/login", json={"username": f"typo{i}", "password": "x" * 12})

    assert client.post(
        "/api/auth/login", json={"username": "admin", "password": GOOD}, headers=ORIGIN
    ).status_code == 200


def test_scrypt_runs_a_bounded_number_at_a_time(monkeypatch):
    """However many sign-ins arrive together, memory is held by at most a few."""
    running = 0
    peak = 0
    lock = threading.Lock()

    def slow_scrypt(*args, **kwargs):
        nonlocal running, peak
        with lock:
            running += 1
            peak = max(peak, running)
        time.sleep(0.05)
        with lock:
            running -= 1
        return b"\0" * 32

    monkeypatch.setattr(passwords.hashlib, "scrypt", slow_scrypt)
    threads = [
        threading.Thread(target=passwords.burn_time, args=("password",)) for _ in range(16)
    ]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    # Asserted against the named bound, and the bound against a ceiling, so a
    # semaphore that was removed or widened to the thread pool fails here.
    assert passwords.SCRYPT_CONCURRENCY <= 8
    assert 1 <= peak <= passwords.SCRYPT_CONCURRENCY


# --- Req 16.8: throttling by kind, not by wording ---------------------------


def test_a_wrong_setup_code_is_a_wrong_secret(session):
    service = AuthService(session)
    # An account exists, so this refusal is not about the code...
    with pytest.raises(Exception) as excinfo:
        service.complete_setup("AAAA-AAAA-AAAA", "other", GOOD)
    assert not isinstance(excinfo.value, WrongSecretError)


def test_a_wrong_current_password_is_a_wrong_secret(session):
    with pytest.raises(WrongSecretError):
        AuthService(session).change_password("admin", "not it at all", GOOD + "!", None)


# --- Req 16.12, 16.18 -------------------------------------------------------


def test_a_reset_from_the_host_revokes_every_token(session):
    service = AuthService(session)
    service.create_api_token("one")
    service.create_api_token("two")
    session.commit()

    revoked = service.reset_password("admin", "a brand new password")
    session.commit()

    assert revoked == 2
    assert all(t.revoked_at is not None for t in service.list_api_tokens())


def test_revoke_all_ends_every_token(client, session):
    _signed_in(client)
    tokens = [
        client.post("/api/auth/tokens", json={"name": n}, headers=ORIGIN).json()["token"]
        for n in ("a", "b")
    ]

    r = client.delete("/api/auth/tokens", headers=ORIGIN)

    assert r.status_code == 200
    assert r.json() == {"revoked": 2}
    script = TestClient(client.app)
    for token in tokens:
        assert script.get("/api/machines", headers={"Authorization": f"Bearer {token}"}).status_code == 401


def test_a_token_cannot_revoke_all_tokens(client, session):
    _, token = AuthService(session).create_api_token("script")
    session.commit()

    r = client.delete("/api/auth/tokens", headers={"Authorization": f"Bearer {token}"})

    assert r.status_code == 403


# --- Req 16.19 --------------------------------------------------------------


def test_a_throttled_attempt_is_logged(client, caplog):
    for i in range(FREE_ATTEMPTS_PER_CLIENT):
        client.post("/api/auth/login", json={"username": f"n{i}", "password": "x" * 12})

    with caplog.at_level(logging.WARNING, logger="app.security"):
        client.post("/api/auth/login", json={"username": "n", "password": "x" * 12})

    assert "throttled" in caplog.text


def test_an_unknown_token_is_logged(client, caplog):
    with caplog.at_level(logging.WARNING, logger="app.security"):
        client.get("/api/machines", headers={"Authorization": "Bearer cvd_not-a-real-token"})

    assert "unknown or revoked API token" in caplog.text
    assert "cvd_not-a-real-token" not in caplog.text


def test_forgetting_a_host_key_is_logged_with_who_asked(client, session, caplog):
    Repository(session).pin_host_key(
        "web-01.lan", 22, key_type="ssh-ed25519", key_base64="AAAA", fingerprint_sha256="SHA256:x"
    )
    session.commit()
    _, token = AuthService(session).create_api_token("rotation")
    session.commit()

    with caplog.at_level(logging.INFO, logger="app.security"):
        r = client.delete(
            "/api/host-keys/web-01.lan?port=22", headers={"Authorization": f"Bearer {token}"}
        )

    assert r.status_code == 204
    assert "Host key forgotten by token:rotation" in caplog.text
    assert "web-01.lan:22" in caplog.text
