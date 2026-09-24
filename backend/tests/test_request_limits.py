"""What one request may carry, and what a refusal may say back.

Req 16.13: every list and string a caller controls has an upper bound, checked
before anything acts on it. A scan batch runs synchronously inside its request,
a sweep's cost is addresses times ports, and a note is stored as sent -- so
without a bound, one signed-in request could pin a worker or fill the database.

Req 16.14: a refusal names the field and the reason, and never the value. The
value that fails validation on a scan target is quite often its password or its
private key.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.api import schemas
from app.api.app import create_app
from app.api.dependencies import get_scanner_engine
from tests.auth_helpers import override_auth

SECRET = "correct-horse-battery-staple-" + "x" * schemas.MAX_SECRET


@pytest.fixture()
def client(monkeypatch):
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)
    app = override_auth(create_app())
    # The scan route builds its engine before validation errors are raised,
    # and these tests must never reach one.
    app.dependency_overrides[get_scanner_engine] = lambda: None
    return TestClient(app)


def _target(**overrides):
    target = {"id": "m1", "hostname": "web-01.lan", "platform": "linux", "username": "scan"}
    target.update(overrides)
    return target


def test_an_oversized_password_is_refused_without_being_echoed(client):
    response = client.post("/api/scans", json={"targets": [_target(password=SECRET)]})

    assert response.status_code == 422
    assert SECRET not in response.text
    assert "correct-horse" not in response.text
    # Still useful: the client is told which field and why.
    detail = response.json()["detail"]
    assert detail[0]["loc"][-1] == "password"
    assert "msg" in detail[0]


def test_an_oversized_private_key_is_refused_without_being_echoed(client):
    key = "-----BEGIN OPENSSH PRIVATE KEY-----\n" + "A" * schemas.MAX_PRIVATE_KEY
    response = client.post(
        "/api/scans/test-connection",
        json={"hostname": "web-01.lan", "platform": "linux", "private_key": key},
    )

    assert response.status_code == 422
    assert "BEGIN OPENSSH" not in response.text


def test_a_sign_in_password_is_never_echoed(client, monkeypatch):
    """The login schema caps the password too; its 422 must not repeat it."""
    response = client.post(
        "/api/auth/login", json={"username": "admin", "password": SECRET * 3}
    )

    assert response.status_code == 422
    assert "correct-horse" not in response.text


def test_a_malformed_target_is_not_echoed_whole(client):
    """A missing field used to echo the whole object -- password included."""
    response = client.post(
        "/api/scans",
        json={"targets": [{"hostname": "web-01.lan", "password": "hunter2-secret"}]},
    )

    assert response.status_code == 422
    assert "hunter2-secret" not in response.text


def test_too_many_targets_are_refused(client):
    targets = [_target(id=f"m{i}") for i in range(schemas.MAX_BATCH + 1)]

    response = client.post("/api/scans", json={"targets": targets})

    assert response.status_code == 422


def test_too_many_enrolled_hosts_are_refused(client):
    hosts = [{"hostname": f"10.0.{i // 256}.{i % 256}"} for i in range(schemas.MAX_BATCH + 1)]

    response = client.post("/api/discovery/enroll", json={"hosts": hosts})

    assert response.status_code == 422


@pytest.mark.parametrize("port", [0, 65536, 70000, -1])
def test_a_port_out_of_range_is_refused(client, port):
    response = client.post(
        "/api/discovery/sweep", json={"cidr": "192.0.2.0/30", "ports": [port]}
    )

    assert response.status_code == 422


def test_too_many_ports_are_refused(client):
    ports = list(range(1, schemas.MAX_SWEEP_PORTS + 2))

    response = client.post("/api/discovery/sweep", json={"cidr": "192.0.2.0/30", "ports": ports})

    assert response.status_code == 422


def test_an_oversized_note_is_refused(client):
    response = client.post(
        "/api/machines/m1/cves/CVE-2024-0001/remediation",
        json={"status": "open", "note": "n" * (schemas.MAX_NOTE + 1)},
    )

    assert response.status_code == 422


def test_a_note_at_the_limit_reaches_the_handler(client):
    """The bound is not the refusal: a note at the limit is fine (404 = handler)."""
    response = client.post(
        "/api/machines/nope/cves/CVE-2024-0001/remediation",
        json={"status": "open", "note": "n" * schemas.MAX_NOTE},
    )

    assert response.status_code == 404
