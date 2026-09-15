"""Pinned SSH host keys (Req 17), against a real SSH handshake.

The unit tests elsewhere fake ``paramiko.SSHClient``, which cannot show the
claims that matter here: that a changed key is refused *before* the host is
offered a credential, and that a pinned key type is negotiated even when the
host prefers another. So these run a paramiko server on loopback and connect
to it with the real client. Nothing leaves the machine.
"""

from __future__ import annotations

import io
import socket
import threading
import time
from contextlib import contextmanager
from typing import Iterator

import paramiko
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app import config
from app.api.app import create_app
from app.api.dependencies import get_session
from app.api.wiring import RepositoryHostKeyStore, build_collector
from app.data.repository import Repository
from app.data.schema import Base
from app.enums import Platform, ScanStatus
from app.models import Credentials, TargetMachine
from app.scanner.collectors import LinuxCollector
from app.scanner.engine import ScannerEngine
from app.scanner.exceptions import HostKeyMismatchError, HostKeyUnknownError
from app.scanner.host_keys import (
    POLICY_STRICT,
    PinnedHostKey,
    connect_pinned,
    fingerprint,
)
from tests.auth_helpers import override_auth

PASSWORD = "correct-horse"
HOST = "127.0.0.1"


# ---------------------------------------------------------------------------
# A loopback SSH server
# ---------------------------------------------------------------------------


def _ed25519() -> paramiko.PKey:
    material = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    return paramiko.Ed25519Key(file_obj=io.StringIO(material.decode()))


class _Server(paramiko.ServerInterface):
    def __init__(self, record: dict) -> None:
        self._record = record

    def get_allowed_auths(self, username):
        return "password"

    def check_auth_password(self, username, password):
        self._record["auth_attempts"] += 1
        if password == PASSWORD:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_exec_request(self, channel, command):
        def reply() -> None:
            # Returning True is what sends the exec request's success reply,
            # so closing straight away can overtake it and the client sees
            # "Channel closed".
            time.sleep(0.1)
            try:
                channel.send(b"")
                channel.send_exit_status(0)
                channel.close()
            except (EOFError, OSError, paramiko.SSHException):
                pass  # the client already went away; nothing to answer

        threading.Thread(target=reply, daemon=True).start()
        return True


@contextmanager
def ssh_server(*host_keys: paramiko.PKey) -> Iterator[dict]:
    """Serve SSH on a free loopback port with the given host keys."""
    record = {"auth_attempts": 0, "port": 0}
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind((HOST, 0))
    listener.listen(8)
    listener.settimeout(0.2)
    record["port"] = listener.getsockname()[1]
    transports: list[paramiko.Transport] = []
    stop = threading.Event()

    def serve() -> None:
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except OSError:
                continue
            transport = paramiko.Transport(conn)
            for key in host_keys:
                transport.add_server_key(key)
            transports.append(transport)
            try:
                transport.start_server(server=_Server(record))
            except (paramiko.SSHException, EOFError, OSError):
                pass

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield record
    finally:
        stop.set()
        thread.join(timeout=2)
        for transport in transports:
            transport.close()
        listener.close()


class MemoryStore:
    def __init__(self) -> None:
        self.keys: dict[tuple[str, int], PinnedHostKey] = {}
        self.touched: list[tuple[str, int]] = []

    def get(self, hostname, port):
        return self.keys.get((hostname, port))

    def pin(self, hostname, port, key):
        self.keys[(hostname, port)] = key

    def touch(self, hostname, port):
        self.touched.append((hostname, port))


def _connect(port: int, store, *, password: str = PASSWORD, policy: str = "tofu") -> None:
    client = paramiko.SSHClient()
    try:
        connect_pinned(
            client,
            hostname=HOST,
            port=port,
            store=store,
            policy=policy,
            username="scanner",
            password=password,
            timeout=5,
            allow_agent=False,
            look_for_keys=False,
        )
    finally:
        client.close()


# ---------------------------------------------------------------------------
# connect_pinned
# ---------------------------------------------------------------------------


def test_first_successful_connection_pins_the_presented_key():
    """Validates Req 17.1."""
    key = _ed25519()
    store = MemoryStore()
    with ssh_server(key) as server:
        _connect(server["port"], store)

    pinned = store.get(HOST, server["port"])
    assert pinned is not None
    assert pinned.key_type == "ssh-ed25519"
    assert pinned.fingerprint_sha256 == fingerprint(key)
    assert pinned.fingerprint_sha256.startswith("SHA256:")


def test_a_rejected_login_pins_nothing():
    """Validates Req 17.1: only a connection that succeeded is trusted."""
    store = MemoryStore()
    with ssh_server(_ed25519()) as server:
        with pytest.raises(paramiko.AuthenticationException):
            _connect(server["port"], store, password="wrong")

    assert store.keys == {}


def test_an_unreachable_host_pins_nothing():
    store = MemoryStore()
    with socket.socket() as probe:
        probe.bind((HOST, 0))
        closed_port = probe.getsockname()[1]
    with pytest.raises((OSError, paramiko.SSHException)):
        _connect(closed_port, store)

    assert store.keys == {}


def test_a_successful_scan_pins_through_the_collector():
    """Validates Req 17.1 on the scan path, not only in the helper."""
    key = _ed25519()
    store = MemoryStore()
    target = TargetMachine(id="m1", hostname=HOST, platform=Platform.LINUX)
    with ssh_server(key) as server:
        LinuxCollector(port=server["port"], host_key_store=store).collect(
            target, Credentials(username="scanner", password=PASSWORD)
        )

    assert store.get(HOST, server["port"]).fingerprint_sha256 == fingerprint(key)


def test_the_pinned_key_is_accepted_again_and_touched():
    """Validates Req 17.2."""
    key = _ed25519()
    store = MemoryStore()
    with ssh_server(key) as server:
        _connect(server["port"], store)
        _connect(server["port"], store)

    assert store.touched == [(HOST, server["port"])]


def test_a_changed_key_is_refused_before_any_credential_is_offered():
    """Validates Req 17.3."""
    original, replacement = _ed25519(), _ed25519()
    store = MemoryStore()
    with ssh_server(replacement) as second:
        store.pin(HOST, second["port"], PinnedHostKey.from_key(original))
        with pytest.raises(HostKeyMismatchError) as caught:
            _connect(second["port"], store)
        assert second["auth_attempts"] == 0

    error = caught.value
    assert error.pinned == fingerprint(original)
    assert error.presented == fingerprint(replacement)
    assert fingerprint(original) in str(error)
    assert fingerprint(replacement) in str(error)
    # The pin is not replaced by the refused key.
    assert store.get(HOST, second["port"]).fingerprint_sha256 == fingerprint(original)


def test_a_pinned_key_type_is_negotiated_when_the_host_prefers_another():
    """Validates Req 17.4.

    The host offers ed25519, which paramiko prefers, as well as RSA. With the
    RSA key pinned, the handshake must ask for RSA; negotiating ed25519 would
    report a perfectly good host as changed.
    """
    rsa = paramiko.RSAKey.generate(2048)
    store = MemoryStore()
    with ssh_server(_ed25519(), rsa) as server:
        store.pin(HOST, server["port"], PinnedHostKey.from_key(rsa))
        _connect(server["port"], store)

    assert store.touched == [(HOST, server["port"])]


def test_strict_policy_refuses_an_unpinned_host_before_authenticating():
    """Validates Req 17.5."""
    key = _ed25519()
    store = MemoryStore()
    with ssh_server(key) as server:
        with pytest.raises(HostKeyUnknownError) as caught:
            _connect(server["port"], store, policy=POLICY_STRICT)
        assert server["auth_attempts"] == 0

    assert store.keys == {}
    assert caught.value.presented == fingerprint(key)
    assert caught.value.hostname == HOST


def test_strict_policy_accepts_a_pinned_host():
    """Validates Req 17.5: strict refuses the unknown, not the known."""
    key = _ed25519()
    store = MemoryStore()
    with ssh_server(key) as server:
        store.pin(HOST, server["port"], PinnedHostKey.from_key(key))
        _connect(server["port"], store, policy=POLICY_STRICT)

    assert store.touched == [(HOST, server["port"])]


def test_the_policy_setting_rejects_unknown_values(monkeypatch):
    monkeypatch.setenv("CVEDECK_SSH_HOST_KEY_POLICY", "yolo")
    with pytest.raises(ValueError):
        config.ssh_host_key_policy()
    monkeypatch.setenv("CVEDECK_SSH_HOST_KEY_POLICY", " Strict ")
    assert config.ssh_host_key_policy() == "strict"
    monkeypatch.delenv("CVEDECK_SSH_HOST_KEY_POLICY")
    assert config.ssh_host_key_policy() == "tofu"


# ---------------------------------------------------------------------------
# Collector and engine
# ---------------------------------------------------------------------------


def test_a_changed_key_is_a_host_key_mismatch_not_a_connection_failure():
    """Validates Req 17.3 through the collector and the engine."""
    store = MemoryStore()
    target = TargetMachine(id="m1", hostname=HOST, platform=Platform.LINUX)
    with ssh_server(_ed25519()) as server:
        store.pin(HOST, server["port"], PinnedHostKey.from_key(_ed25519()))
        collector = LinuxCollector(port=server["port"], host_key_store=store)
        engine = ScannerEngine(
            repository=object(),
            credentials_for=lambda _t: Credentials(username="scanner", password=PASSWORD),
            collector_factory=lambda _platform: collector,
        )
        result = engine.scan([target])
        assert server["auth_attempts"] == 0

    (scan,) = result.machine_scans
    assert scan.status is ScanStatus.HOST_KEY_MISMATCH
    assert "has changed" in scan.message


def test_a_strict_refusal_is_host_key_unknown():
    """Validates Req 17.5 through the collector and the engine."""
    target = TargetMachine(id="m1", hostname=HOST, platform=Platform.LINUX)
    with ssh_server(_ed25519()) as server:
        collector = LinuxCollector(
            port=server["port"], host_key_store=MemoryStore(), host_key_policy=POLICY_STRICT
        )
        engine = ScannerEngine(
            repository=object(),
            credentials_for=lambda _t: Credentials(username="scanner", password=PASSWORD),
            collector_factory=lambda _platform: collector,
        )
        (scan,) = engine.scan([target]).machine_scans

    assert scan.status is ScanStatus.HOST_KEY_UNKNOWN


# ---------------------------------------------------------------------------
# The database store, shared by scans and connection tests
# ---------------------------------------------------------------------------


@pytest.fixture()
def session():
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


def _pin(repo: Repository, hostname: str, port: int = 22) -> None:
    repo.pin_host_key(
        hostname,
        port,
        key_type="ssh-ed25519",
        key_base64="AAAA",
        fingerprint_sha256="SHA256:abc",
    )


def test_pins_are_per_address_and_case_insensitive(session):
    repo = Repository(session)
    _pin(repo, "Web-01.LAN")

    assert repo.get_host_key("web-01.lan", 22) is not None
    assert repo.get_host_key("web-01.lan", 2222) is None


def test_a_pin_is_never_silently_replaced(session):
    """Validates Req 17.7: changing trust goes through forgetting."""
    repo = Repository(session)
    _pin(repo, "web-01.lan")
    with pytest.raises(ValueError):
        _pin(repo, "WEB-01.lan")

    assert repo.forget_host_key("web-01.lan", 22) is True
    assert repo.forget_host_key("web-01.lan", 22) is False
    _pin(repo, "web-01.lan")


def test_a_key_accepted_by_a_connection_test_holds_the_next_scan(session, monkeypatch):
    """Validates Req 17.6: one store behind both SSH paths."""
    app = override_auth(create_app())
    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app)

    with ssh_server(_ed25519()) as first:
        monkeypatch.setenv("CVEDECK_SSH_PORT", str(first["port"]))
        response = client.post(
            "/api/scans/test-connection",
            json={
                "hostname": HOST,
                "platform": "linux",
                "username": "scanner",
                "password": PASSWORD,
            },
        )
        body = response.json()
        assert body["status"] == "SUCCESS", body
        assert body["host_key_fingerprint"].startswith("SHA256:")
        port = first["port"]

    # The same address now answers with a different key.
    repo = Repository(session)
    row = repo.get_host_key(HOST, port)
    with ssh_server(_ed25519()) as second:
        row.port = second["port"]
        session.commit()
        monkeypatch.setenv("CVEDECK_SSH_PORT", str(second["port"]))

        collector = build_collector(Platform.LINUX, RepositoryHostKeyStore(repo))
        engine = ScannerEngine(
            repository=object(),
            credentials_for=lambda _t: Credentials(username="scanner", password=PASSWORD),
            collector_factory=lambda _platform: collector,
        )
        target = TargetMachine(id="m1", hostname=HOST, platform=Platform.LINUX)
        (scan,) = engine.scan([target]).machine_scans

        retest = client.post(
            "/api/scans/test-connection",
            json={
                "hostname": HOST,
                "platform": "linux",
                "username": "scanner",
                "password": PASSWORD,
            },
        ).json()
        assert second["auth_attempts"] == 0

    assert scan.status is ScanStatus.HOST_KEY_MISMATCH
    assert retest["status"] == "HOST_KEY_MISMATCH"
    assert retest["success"] is False
    assert retest["host_key_fingerprint"] == body["host_key_fingerprint"]


def test_forgetting_a_host_key_needs_a_pin_and_removes_it(session):
    """Validates Req 17.7."""
    app = override_auth(create_app())
    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app)
    _pin(Repository(session), "web-01.lan")
    session.commit()

    assert client.delete("/api/host-keys/web-01.lan", params={"port": 22}).status_code == 204
    assert Repository(session).get_host_key("web-01.lan", 22) is None
    assert client.delete("/api/host-keys/web-01.lan").status_code == 404


def test_the_machine_summary_carries_the_pinned_fingerprint(session):
    """Validates Req 17.8."""
    app = override_auth(create_app())
    app.dependency_overrides[get_session] = lambda: session
    client = TestClient(app)
    repo = Repository(session)
    repo.upsert_target_machine("m1", "Web-01.lan", Platform.LINUX)
    repo.upsert_target_machine("m2", "db-01.lan", Platform.LINUX)
    _pin(repo, "web-01.lan")
    session.commit()

    by_id = {m["machine_id"]: m for m in client.get("/api/machines").json()}
    assert by_id["m1"]["host_key_fingerprint"] == "SHA256:abc"
    assert by_id["m2"]["host_key_fingerprint"] is None
    assert client.get("/api/machines/m1").json()["host_key_fingerprint"] == "SHA256:abc"
