"""Demo mode: what it advertises, and what it refuses.

The refusal is the security-relevant half. A public demo instance that still
accepted a hostname, a CIDR and a set of credentials would be an open SSH,
WinRM and port-scan proxy that anyone could aim at any address, with the
traffic originating from the demo's IP rather than theirs. Every route that
reaches the network from user-supplied input must be off, so each one is
asserted individually -- adding another such route and forgetting the guard is
exactly the mistake these tests exist to catch.

The intel refresh is refused for a second reason, and it is worth stating
separately because reasoning only about the first is what left it open through
0.8.8: it rewrites the seeded fleet. A refresh reapplies the feeds to stored
findings, which overwrites the deliberately unchecked findings Req 15.6 requires
the demo to carry, and nothing re-seeds them. It also reaches the network
without any user-supplied address at all, so "does this route take a hostname?"
was the wrong question to ask of it.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from app.enums import FeedStatus
from tests.auth_helpers import override_auth


@pytest.fixture()
def demo(monkeypatch):
    monkeypatch.setenv("CVEDECK_DEMO_MODE", "true")
    return TestClient(override_auth(create_app()))


@pytest.fixture()
def normal(monkeypatch):
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)
    return TestClient(override_auth(create_app()))


def test_health_advertises_demo_mode(demo):
    body = demo.get("/api/health").json()

    assert body["capabilities"]["demo_mode"] is True


def test_health_does_not_advertise_demo_mode_by_default(normal):
    body = normal.get("/api/health").json()

    assert body["capabilities"]["demo_mode"] is False


def test_demo_mode_reports_no_automatic_feed_refresh(demo):
    """And reports it honestly, rather than the configured interval.

    Demo mode switches the periodic refresh off, because since 0.8.8 a refresh
    reapplies the feeds to stored findings and the demo fleet is seeded with
    findings whose exploitation status was deliberately never checked. Health
    must report the interval that is running, not the one in the environment --
    claiming a 24-hour refresh that never happens is the same shape of lie the
    periodic refresh was added to remove (Req 10.14, 10.15).

    Takes only the ``demo`` fixture: ``normal`` unsets CVEDECK_DEMO_MODE, so a
    test that asked for both would run with demo mode off and pass vacuously.
    """
    body = demo.get("/api/health").json()

    assert body["capabilities"]["demo_mode"] is True
    assert body["capabilities"]["feed_refresh_hours"] == 0


def test_a_normal_instance_reports_its_refresh_interval(normal):
    """The other half of the pair, in its own test for the reason above."""
    body = normal.get("/api/health").json()

    assert body["capabilities"]["feed_refresh_hours"] == 24


def test_scanning_is_refused(demo):
    response = demo.post(
        "/api/scans",
        json={
            "targets": [
                {
                    "id": "m1",
                    "hostname": "example.invalid",
                    "platform": "linux",
                    "username": "root",
                    "password": "hunter2",
                }
            ]
        },
    )

    assert response.status_code == 403
    assert "demo mode" in response.json()["detail"].lower()


def test_discovery_sweep_is_refused(demo):
    response = demo.post("/api/discovery/sweep", json={"cidr": "192.0.2.0/30"})

    assert response.status_code == 403


def test_connection_test_is_refused(demo):
    response = demo.post(
        "/api/scans/test-connection",
        json={
            "hostname": "example.invalid",
            "platform": "linux",
            "username": "root",
            "password": "hunter2",
        },
    )

    assert response.status_code == 403


def test_forgetting_a_host_key_is_refused(demo):
    """Req 17.7: a demo visitor must not be able to drop a pinned key."""
    response = demo.delete("/api/host-keys/web-01.lan")

    assert response.status_code == 403


@pytest.mark.parametrize(
    "value,expected",
    [
        ("1", True),
        ("true", True),
        ("TRUE", True),
        ("yes", True),
        ("on", True),
        ("0", False),
        ("false", False),
        ("", False),
        ("maybe", False),
    ],
)
def test_flag_spellings(monkeypatch, value, expected):
    """`CVEDECK_DEMO_MODE=true` in a compose file must behave as written.

    An unrecognised value is off, not on: failing closed here would disable
    scanning on a real deployment because of a typo.
    """
    from app import config

    monkeypatch.setenv("CVEDECK_DEMO_MODE", value)

    assert config.demo_mode() is expected


def test_flag_is_off_when_unset(monkeypatch):
    from app import config

    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)

    assert config.demo_mode() is False


def test_pinned_host_keys_can_be_read_but_not_forgotten(demo):
    """Req 17.10 is a read; Req 17.7's forget stays refused (Req 15.3)."""
    assert demo.get("/api/host-keys").status_code == 200


def test_refreshing_intel_is_refused(demo):
    """The other door, closed in 0.8.9.

    0.8.8 switched the *periodic* refresh off in demo mode to protect the
    seeded findings whose exploitation status was deliberately never checked,
    and left this route wide open -- unauthenticated, since demo mode needs no
    login. One press reapplied the real catalogue over the fixture and turned
    every one of those unknowns into a definite answer, permanently: nothing
    re-seeds a fleet that is no longer empty.

    Listed beside the other refusals for the reason this module's docstring
    gives: each one is asserted individually so that adding a route and
    forgetting the guard is caught here.
    """
    response = demo.post("/api/feeds/refresh")

    assert response.status_code == 403
    assert "demo mode" in response.json()["detail"].lower()


def test_a_normal_instance_may_refresh_intel(normal, monkeypatch):
    """The guard must be demo-only -- a real deployment still refreshes.

    The upstreams are stubbed out: a test that let this route run for real
    would download the live KEV and EPSS feeds, which is minutes of network in
    a suite that otherwise touches none.
    """
    from app.services import enrichment

    class _Service:
        def refresh_all(self):
            return [
                enrichment.FeedRefreshOutcome(
                    "kev", FeedStatus.OK, record_count=3
                )
            ]

    monkeypatch.setattr(
        enrichment, "build_feed_refresh_service", lambda repo: _Service()
    )

    response = normal.post("/api/feeds/refresh")

    assert response.status_code == 200
    assert response.json()["results"][0]["feed_name"] == "kev"


# --- Req 15.9: demo mode is read-only by construction -------------------------

_READ_ONLY = {"GET", "HEAD", "OPTIONS"}


def _mutating_api_routes(app) -> list[tuple[str, str]]:
    """Every state-changing (method, path) outside the sign-in routes.

    Walks the generated OpenAPI document rather than a hand-kept list, so a
    route added next month is covered the day it is written -- the same shape
    as Property 12's walk in ``test_auth_enforcement.py``.
    """
    found = []
    for path, operations in app.openapi()["paths"].items():
        if not path.startswith("/api") or path.startswith("/api/auth"):
            continue
        for method in operations:
            if method.upper() not in _READ_ONLY:
                found.append((method.upper(), path))
    return sorted(found)


def _concrete(path: str) -> str:
    """Fill every ``{param}`` so the request routes."""
    import re

    return re.sub(r"\{[^}]+\}", "x", path)


def test_every_state_changing_route_is_refused(demo):
    """Req 15.9: nothing an anonymous visitor sends may change the demo.

    The body is deliberately empty. The refusal has to come from the router,
    before validation -- a guard that only fires once the body is well formed
    would let a visitor learn the schema and then walk straight past it.
    """
    routes = _mutating_api_routes(demo.app)

    # The walk must not pass vacuously: these are the routes that were open to
    # anonymous visitors through 0.8.12.
    for known in [
        ("POST", "/api/discovery/enroll"),
        ("POST", "/api/sync"),
        ("POST", "/api/machines/{machine_id}/cves/{cve_id}/remediation"),
        ("PUT", "/api/remediation/{record_id}"),
    ]:
        assert known in routes

    for method, path in routes:
        response = demo.request(method, _concrete(path), json={})
        assert response.status_code == 403, (method, path, response.status_code)
        assert "demo mode" in response.json()["detail"].lower()


def test_enroll_cannot_rewrite_a_seeded_machine(demo):
    """The sharp case: enroll upserts, so it could overwrite the fixture."""
    response = demo.post(
        "/api/discovery/enroll",
        json={"hosts": [{"ip": "192.0.2.10", "hostname": "web-01", "platform": "windows"}]},
    )

    assert response.status_code == 403


def test_a_normal_instance_still_accepts_writes(normal):
    """The guard is demo-only: an ordinary instance reaches the handler.

    404 is the handler's own answer for an unknown machine, which proves the
    request got past every router dependency.
    """
    response = normal.post(
        "/api/machines/nope/cves/CVE-2024-0001/remediation",
        json={"status": "open", "note": ""},
    )

    assert response.status_code == 404
