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


@pytest.fixture()
def demo(monkeypatch):
    monkeypatch.setenv("CVEDECK_DEMO_MODE", "true")
    return TestClient(create_app())


@pytest.fixture()
def normal(monkeypatch):
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)
    return TestClient(create_app())


def test_health_advertises_demo_mode(demo):
    body = demo.get("/api/health").json()

    assert body["capabilities"]["demo_mode"] is True


def test_health_does_not_advertise_demo_mode_by_default(normal):
    body = normal.get("/api/health").json()

    assert body["capabilities"]["demo_mode"] is False


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
