"""Signing in over HTTP: setup, sessions, tokens, cross-site requests, throttling.

Validates Req 16.1, 16.2, 16.3, 16.5, 16.6, 16.7, 16.8, 16.9, 16.10, 16.11.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.app import create_app
from app.api.dependencies import get_session
from app.auth.dependencies import SESSION_COOKIE
from app.auth.service import AuthService
from app.auth.throttle import FREE_ATTEMPTS, throttle
from app.data.schema import Base

GOOD = "correct horse battery"
ORIGIN = {"Origin": "http://testserver"}


@pytest.fixture(autouse=True)
def _login_on(monkeypatch):
    monkeypatch.delenv("CVEDECK_AUTH", raising=False)
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)
    monkeypatch.delenv("CVEDECK_COOKIE_SECURE", raising=False)
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
        yield sess


@pytest.fixture()
def client(session):
    app = create_app()
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


@pytest.fixture()
def account(session):
    AuthService(session).create_user("admin", GOOD)
    session.commit()


def _login(client, username="admin", password=GOOD):
    return client.post(
        "/api/auth/login", json={"username": username, "password": password}, headers=ORIGIN
    )


# --------------------------------------------------------------------------- #
# First run (Req 16.3)
# --------------------------------------------------------------------------- #


def test_a_new_instance_asks_for_setup(client):
    assert client.get("/api/auth/state").json()["state"] == "setup_required"


def test_setup_with_the_logged_code_creates_the_account_and_signs_in(client, session):
    code = AuthService(session).issue_setup_code()
    session.commit()

    response = client.post(
        "/api/auth/setup",
        json={"setup_code": code, "username": "admin", "password": GOOD},
        headers=ORIGIN,
    )

    assert response.status_code == 200
    assert response.json() == {"state": "signed_in", "username": "admin", "via": "session"}
    assert client.get("/api/machines").status_code == 200


def test_setup_with_a_wrong_code_creates_nothing(client, session):
    AuthService(session).issue_setup_code()
    session.commit()

    response = client.post(
        "/api/auth/setup",
        json={"setup_code": "AAAA-AAAA-AAAA", "username": "admin", "password": GOOD},
    )

    assert response.status_code == 400
    assert "setup code" in response.json()["detail"]
    assert client.get("/api/auth/state").json()["state"] == "setup_required"


def test_setup_is_refused_once_an_account_exists(client, account):
    response = client.post(
        "/api/auth/setup",
        json={"setup_code": "AAAA-AAAA-AAAA", "username": "intruder", "password": GOOD},
    )

    assert response.status_code == 400
    assert "already has an account" in response.json()["detail"]


# --------------------------------------------------------------------------- #
# Signing in and out (Req 16.2, 16.5)
# --------------------------------------------------------------------------- #


def test_sign_in_sets_a_hardened_session_cookie(client, account):
    response = _login(client)

    assert response.status_code == 200
    cookie = response.headers["set-cookie"]
    assert cookie.startswith(f"{SESSION_COOKIE}=")
    assert "HttpOnly" in cookie
    assert "SameSite=strict" in cookie or "SameSite=Strict" in cookie
    assert "Path=/" in cookie
    assert "Secure" not in cookie, "plain http in auto mode must not mark it Secure"


def test_the_cookie_is_secure_when_configured(client, account, monkeypatch):
    monkeypatch.setenv("CVEDECK_COOKIE_SECURE", "true")

    assert "Secure" in _login(client).headers["set-cookie"]


def test_signed_in_requests_work_and_sign_out_ends_them(client, account):
    assert client.get("/api/machines").status_code == 401
    _login(client)

    assert client.get("/api/machines").status_code == 200
    assert client.get("/api/auth/state").json()["username"] == "admin"

    assert client.post("/api/auth/logout", headers=ORIGIN).status_code == 204
    assert client.get("/api/machines").status_code == 401
    assert client.get("/api/auth/state").json()["state"] == "signed_out"


def test_a_wrong_password_and_an_unknown_user_get_the_same_answer(client, account):
    wrong = _login(client, password="not the password")
    unknown = _login(client, username="nobody")

    assert wrong.status_code == unknown.status_code == 401
    assert wrong.json() == unknown.json()


def test_a_forged_session_cookie_is_refused(client, account):
    client.cookies.set(SESSION_COOKIE, "made-up")

    assert client.get("/api/machines").status_code == 401


def test_health_describes_configuration_once_signed_in(client, account):
    assert "server_ssh_key" not in client.get("/api/health").json()["capabilities"]
    _login(client)

    assert "server_ssh_key" in client.get("/api/health").json()["capabilities"]


# --------------------------------------------------------------------------- #
# Cross-site requests (Req 16.10)
# --------------------------------------------------------------------------- #


def test_a_cookie_request_that_changes_something_must_come_from_the_dashboard(client, account):
    _login(client)

    foreign = client.post("/api/feeds/refresh", headers={"Origin": "https://evil.example"})
    missing = client.post("/api/feeds/refresh")

    assert foreign.status_code == 403
    assert missing.status_code == 403
    assert "API token" in foreign.json()["detail"]


def test_a_referer_from_the_dashboard_is_accepted_when_origin_is_absent(client, account):
    _login(client)

    response = client.put(
        "/api/auth/password",
        json={"current_password": "wrong one entirely", "new_password": "whatever new pass"},
        headers={"Referer": "http://testserver/#/settings"},
    )

    assert response.status_code == 400, "reached the handler, so the origin check passed"


def test_reading_needs_no_origin(client, account):
    _login(client)

    assert client.get("/api/machines").status_code == 200


# --------------------------------------------------------------------------- #
# API tokens (Req 16.7)
# --------------------------------------------------------------------------- #


def test_a_token_is_shown_once_works_without_an_origin_and_stops_when_revoked(client, account):
    _login(client)
    created = client.post("/api/auth/tokens", json={"name": "cron"}, headers=ORIGIN)
    assert created.status_code == 201
    token = created.json()["token"]
    token_id = created.json()["token_id"]

    listed = client.get("/api/auth/tokens").json()
    assert [t["name"] for t in listed] == ["cron"]
    assert all("token" not in t for t in listed)

    script = TestClient(client.app)
    bearer = {"Authorization": f"Bearer {token}"}
    assert script.get("/api/machines", headers=bearer).status_code == 200
    assert script.get("/api/feeds", headers=bearer).status_code == 200

    assert client.delete(f"/api/auth/tokens/{token_id}", headers=ORIGIN).status_code == 204
    assert script.get("/api/machines", headers=bearer).status_code == 401


def test_a_token_cannot_manage_the_account(client, account, session):
    _, token = AuthService(session).create_api_token("script")
    session.commit()
    bearer = {"Authorization": f"Bearer {token}"}

    assert client.get("/api/auth/tokens", headers=bearer).status_code == 403
    assert client.post("/api/auth/tokens", json={"name": "x"}, headers=bearer).status_code == 403


# --------------------------------------------------------------------------- #
# Password change (Req 16.6)
# --------------------------------------------------------------------------- #


def test_changing_the_password_keeps_this_session_and_ends_the_others(client, account):
    other = TestClient(client.app)
    _login(other)
    _login(client)

    response = client.put(
        "/api/auth/password",
        json={"current_password": GOOD, "new_password": "a brand new passphrase"},
        headers=ORIGIN,
    )

    assert response.status_code == 204
    assert client.get("/api/machines").status_code == 200
    assert other.get("/api/machines").status_code == 401
    assert _login(TestClient(client.app), password="a brand new passphrase").status_code == 200


def test_a_too_short_new_password_is_refused_with_the_reason(client, account):
    _login(client)

    response = client.put(
        "/api/auth/password",
        json={"current_password": GOOD, "new_password": "short"},
        headers=ORIGIN,
    )

    assert response.status_code == 400
    assert "at least" in response.json()["detail"]


# --------------------------------------------------------------------------- #
# Throttling (Req 16.8)
# --------------------------------------------------------------------------- #


def test_repeated_failures_are_throttled_even_for_the_right_password(client, account):
    for _ in range(FREE_ATTEMPTS):
        assert _login(client, password="not the password").status_code == 401

    blocked = _login(client)

    assert blocked.status_code == 429
    assert int(blocked.headers["Retry-After"]) > 0
    assert "Try again" in blocked.json()["detail"]


def test_repeated_wrong_setup_codes_are_throttled(client, session):
    AuthService(session).issue_setup_code()
    session.commit()
    body = {"setup_code": "AAAA-AAAA-AAAA", "username": "admin", "password": GOOD}

    for _ in range(FREE_ATTEMPTS):
        assert client.post("/api/auth/setup", json=body).status_code == 400

    assert client.post("/api/auth/setup", json=body).status_code == 429


# --------------------------------------------------------------------------- #
# Opting out (Req 16.9, 16.11)
# --------------------------------------------------------------------------- #


def test_disabling_login_opens_the_api(client, monkeypatch):
    monkeypatch.setenv("CVEDECK_AUTH", "disabled")

    assert client.get("/api/machines").status_code == 200
    assert client.get("/api/auth/state").json()["state"] == "open"
    assert client.post("/api/auth/login", json={"username": "a", "password": "b"}).status_code == 409


def test_a_mistyped_opt_out_leaves_login_on(client, monkeypatch):
    monkeypatch.setenv("CVEDECK_AUTH", "disable")

    assert client.get("/api/machines").status_code == 401


def test_demo_mode_needs_no_login(client, monkeypatch):
    monkeypatch.setenv("CVEDECK_DEMO_MODE", "true")

    assert client.get("/api/machines").status_code == 200
    assert client.get("/api/auth/state").json()["state"] == "open"
