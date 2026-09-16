"""The connection test dials what a scan of that platform would dial (Req 10.9).

The WinRM branch hardcoded ``http://host:5985`` while the scanner path honoured
``CVEDECK_WINRM_SCHEME`` / ``CVEDECK_WINRM_PORT``, so an instance configured for
HTTPS on 5986 still sent an NTLM password over plaintext 5985 from here. These
tests pin the endpoint the probe actually reaches, because that is the part that
was wrong and the part no response field used to show.

No Windows host is contacted: the socket pre-check and the ``winrm`` module are
both substituted.
"""

from __future__ import annotations

import socket
import sys
import types

import pytest
from fastapi.testclient import TestClient

from app.api.app import create_app
from tests.auth_helpers import override_auth

WINDOWS_TARGET = {
    "hostname": "198.51.100.10",
    "platform": "windows",
    "username": "Administrator",
    "password": "not-a-real-password",
}


@pytest.fixture()
def client():
    return TestClient(override_auth(create_app()))


@pytest.fixture()
def winrm_probe(monkeypatch):
    """Capture the endpoint and the port the probe dials, and answer as a host would."""
    seen: dict[str, object] = {}

    def fake_create_connection(address, timeout=None):
        seen["socket"] = address
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    monkeypatch.setattr(socket, "create_connection", fake_create_connection)

    class _Result:
        status_code = 0
        std_out = b"Microsoft Windows NT 10.0.20348.0"

    class _Session:
        def __init__(self, endpoint, **kwargs):
            seen["endpoint"] = endpoint

        def run_ps(self, script):
            return _Result()

    module = types.ModuleType("winrm")
    module.Session = _Session
    monkeypatch.setitem(sys.modules, "winrm", module)
    return seen


def _test_connection(client) -> dict:
    return client.post("/api/scans/test-connection", json=WINDOWS_TARGET).json()


def test_the_configured_scheme_and_port_are_dialled(client, winrm_probe, monkeypatch):
    """Validates Req 10.9."""
    monkeypatch.setenv("CVEDECK_WINRM_SCHEME", "https")
    monkeypatch.setenv("CVEDECK_WINRM_PORT", "5986")

    body = _test_connection(client)

    assert winrm_probe["endpoint"] == "https://198.51.100.10:5986/wsman"
    assert winrm_probe["socket"] == ("198.51.100.10", 5986)
    assert body["status"] == "SUCCESS"
    # The endpoint is in the message, so an operator expecting HTTPS can see
    # what actually went out.
    assert "https://198.51.100.10:5986/wsman" in body["message"]


def test_the_default_transport_is_unchanged(client, winrm_probe, monkeypatch):
    """The fix must not silently move an existing deployment off 5985."""
    monkeypatch.delenv("CVEDECK_WINRM_SCHEME", raising=False)
    monkeypatch.delenv("CVEDECK_WINRM_PORT", raising=False)

    _test_connection(client)

    assert winrm_probe["endpoint"] == "http://198.51.100.10:5985/wsman"
    assert winrm_probe["socket"] == ("198.51.100.10", 5985)


def test_an_unreachable_host_names_the_configured_port(client, monkeypatch):
    """The failure message hardcoded 5985 separately, so it lied about where it went."""
    monkeypatch.setenv("CVEDECK_WINRM_PORT", "5986")

    def refuse(address, timeout=None):
        raise OSError("connection refused")

    monkeypatch.setattr(socket, "create_connection", refuse)

    body = _test_connection(client)

    assert body["status"] == "CONNECTION_FAILURE"
    assert "Port 5986" in body["message"]
    assert "5985" not in body["message"]


def test_an_unusable_scheme_is_a_connection_failure_not_a_server_error(
    client, monkeypatch
):
    """``config.winrm_scheme`` raises on a bad value; a 500 would be the wrong answer."""
    monkeypatch.setenv("CVEDECK_WINRM_SCHEME", "ftp")

    response = client.post("/api/scans/test-connection", json=WINDOWS_TARGET)

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is False
    assert body["status"] == "CONNECTION_FAILURE"
    assert "CVEDECK_WINRM_SCHEME" in body["message"]
