"""What the browser is told, and who may send the browser here.

Req 16.15: every response carries the headers a browser needs -- no framing by
another site, no content sniffing, no referrer out, and a content policy that
runs only the dashboard's own code.

Req 16.16: with login switched off, a state-changing request that says it came
from another site is refused. Absence of an Origin is allowed, because that is
every script; a browser always sends one on a cross-site POST.

Req 16.17: a request whose Host is not one of this instance's names is refused
when CVEDECK_ALLOWED_HOSTS is set -- the defence against DNS rebinding, which an
Origin check cannot give.
"""

from __future__ import annotations

import io
import logging

import pytest
from fastapi.testclient import TestClient

from app import config
from app.api import security
from app.api.app import create_app
from app.api.dependencies import _prepare_access_control, get_sync_service


@pytest.fixture()
def dashboard(tmp_path, monkeypatch):
    static = tmp_path / "static"
    (static / "assets").mkdir(parents=True)
    io.open(static / "index.html", "w", encoding="utf-8").write("<!doctype html>")
    io.open(static / "assets" / "index-abc123.js", "w", encoding="utf-8").write("//")
    monkeypatch.setenv("CVEDECK_STATIC_DIR", str(static))
    monkeypatch.delenv("CVEDECK_ALLOWED_HOSTS", raising=False)
    return TestClient(create_app(wire_production=True))


@pytest.mark.parametrize("path", ["/", "/assets/index-abc123.js", "/api/health"])
def test_every_response_carries_the_browser_headers(dashboard, path):
    r = dashboard.get(path)

    assert r.status_code == 200
    assert r.headers["content-security-policy"] == security.DASHBOARD_CSP
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]


def test_the_dashboard_policy_allows_nothing_from_elsewhere():
    """No CDN, no inline script: the design language's rule, made enforceable."""
    assert "http" not in security.DASHBOARD_CSP
    assert "unsafe-inline" not in security.DASHBOARD_CSP
    assert "unsafe-eval" not in security.DASHBOARD_CSP


def test_an_error_carries_the_headers_too(dashboard):
    r = dashboard.get("/api/machines/does-not-exist")

    assert "content-security-policy" in r.headers


# --- Req 16.16: login switched off ------------------------------------------


@pytest.fixture()
def open_app(monkeypatch):
    monkeypatch.setenv("CVEDECK_AUTH", "disabled")
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)
    monkeypatch.delenv("CVEDECK_ALLOWED_HOSTS", raising=False)
    app = create_app()

    class _Sync:
        def sync(self):
            raise RuntimeError("reached the handler")

    app.dependency_overrides[get_sync_service] = lambda: _Sync()
    return TestClient(app, raise_server_exceptions=False)


def test_a_cross_site_post_is_refused_when_login_is_off(open_app):
    r = open_app.post("/api/sync", headers={"Origin": "https://evil.example"})

    assert r.status_code == 403
    assert "another site" in r.json()["detail"]


def test_a_cross_site_fetch_metadata_post_is_refused(open_app):
    r = open_app.post("/api/sync", headers={"Sec-Fetch-Site": "cross-site"})

    assert r.status_code == 403


def test_an_opaque_origin_is_refused(open_app):
    """A sandboxed iframe or a data: page sends Origin: null."""
    r = open_app.post("/api/sync", headers={"Origin": "null"})

    assert r.status_code == 403


def test_a_script_with_no_origin_still_works(open_app):
    """curl sends no Origin; refusing it would break every script."""
    r = open_app.post("/api/sync")

    assert r.status_code != 403


def test_the_dashboard_itself_still_works(open_app):
    r = open_app.post(
        "/api/sync",
        headers={"Origin": "http://testserver", "Sec-Fetch-Site": "same-origin"},
    )

    assert r.status_code != 403


# --- Req 16.17: the Host allowlist -------------------------------------------


@pytest.fixture()
def pinned(monkeypatch):
    monkeypatch.setenv("CVEDECK_ALLOWED_HOSTS", "cvedeck.lan, *.example.org")
    return TestClient(create_app())


@pytest.mark.parametrize(
    "host",
    ["cvedeck.lan", "cvedeck.lan:3325", "CVEDECK.LAN", "deck.example.org",
     "localhost:8000", "127.0.0.1", "[::1]:8000"],
)
def test_a_listed_host_is_served(pinned, host):
    assert pinned.get("/api/health", headers={"Host": host}).status_code == 200


@pytest.mark.parametrize(
    "host", ["attacker.example", "cvedeck.lan.attacker.example", "example.org", ""]
)
def test_an_unlisted_host_is_refused(pinned, host):
    """A rebinding page's requests carry its own name, not the dashboard's."""
    assert pinned.get("/api/health", headers={"Host": host}).status_code == 400


def test_no_allowlist_means_any_host(monkeypatch):
    monkeypatch.delenv("CVEDECK_ALLOWED_HOSTS", raising=False)
    client = TestClient(create_app())

    assert client.get("/api/health", headers={"Host": "anything.lan"}).status_code == 200


def test_login_off_without_an_allowlist_warns(monkeypatch, caplog):
    monkeypatch.setenv("CVEDECK_AUTH", "disabled")
    monkeypatch.delenv("CVEDECK_ALLOWED_HOSTS", raising=False)

    with caplog.at_level(logging.WARNING):
        _prepare_access_control(engine=None)

    assert "CVEDECK_ALLOWED_HOSTS" in caplog.text


# --- Req 16.16: a wildcard CORS origin ---------------------------------------


def test_a_wildcard_cors_origin_is_refused(monkeypatch):
    monkeypatch.setenv("CVEDECK_CORS_ORIGINS", "https://a.example, *")

    with pytest.raises(ValueError, match="may not contain"):
        config.cors_origins()
