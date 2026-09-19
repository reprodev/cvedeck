"""Demo mode: what it advertises, and what it refuses.

The refusal is the security-relevant half. A public demo instance that still
accepted a hostname, a CIDR and a set of credentials would be an open SSH,
WinRM and port-scan proxy that anyone could aim at any address, with the
traffic originating from the demo's IP rather than theirs. Every route that
reaches the network from user-supplied input must be off, so each one is
asserted individually -- adding a fourth such route and forgetting the guard is
exactly the mistake these tests exist to catch.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
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
