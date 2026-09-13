"""Unit/contract tests for the Backend_API action endpoints (task 8.2).

These verify the remediation, scan, and sync action routes against an in-memory
SQLite session injected by overriding ``get_session``. The scan and sync
endpoints depend on overridable providers (``get_scanner_engine`` /
``get_sync_service``) so the wiring is exercised without touching real SSH/WinRM
hosts or an online database:

- ``POST /api/machines/{id}/cves/{cve_id}/remediation`` adds a record via
  ``RemediationService`` and returns it; 404 for an unknown machine (Req 4.1).
- ``PUT /api/remediation/{record_id}`` updates a record via ``RemediationService``;
  404 when the record is missing (Req 4.3).
- ``POST /api/scans`` initiates a scan via an injected ``ScannerEngine`` built
  with stubbed collectors; per-target failures are recorded as statuses
  (Req 1.1, 1.2).
- ``POST /api/sync`` triggers synchronization via an injected ``SyncService``
  backed by an in-memory online store (Req 5.2).
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.app import create_app
from app.api.dependencies import (
    get_scanner_engine,
    get_session,
    get_sync_service,
)
from app.data.repository import FindingInput, RemediationInput, Repository
from app.data.schema import Base, CveFinding, TargetMachine
from app.enums import (
    Platform,
    RemediationStatus,
    ScanStatus,
    Severity,
    SyncStatus,
)
from app.models import Credentials, Inventory, OsInfo, Package
from app.scanner.engine import ScannerEngine
from app.scanner.exceptions import AuthError
from app.services.sync import SyncService


@pytest.fixture()
def session():
    """In-memory SQLite session with all tables created."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


@pytest.fixture()
def app(session):
    """App with the session dependency overridden to the test session."""
    application = create_app()
    application.dependency_overrides[get_session] = lambda: session
    return application


@pytest.fixture()
def client(app):
    """TestClient over the configured app."""
    return TestClient(app)


def _make_machine(
    session: Session,
    machine_id: str,
    hostname: str = "host.example.com",
    platform: Platform = Platform.LINUX,
) -> TargetMachine:
    machine = TargetMachine(
        id=machine_id,
        hostname=hostname,
        platform=platform,
        last_scan_status=ScanStatus.SUCCESS,
        last_scanned_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        sync_status=SyncStatus.PENDING_SYNC,
    )
    session.add(machine)
    session.flush()
    return machine


# --------------------------------------------------------------------------- #
# POST /api/machines/{id}/cves/{cve_id}/remediation
# --------------------------------------------------------------------------- #
def test_add_remediation_persists_and_returns_record(session, client):
    _make_machine(session, "m1")
    session.commit()

    resp = client.post(
        "/api/machines/m1/cves/CVE-2024-1/remediation",
        json={"status": "in_progress", "note": "patching"},
    )

    assert resp.status_code == 201
    body = resp.json()
    assert body["machine_id"] == "m1"
    assert body["cve_id"] == "CVE-2024-1"
    assert body["status"] == "in_progress"
    assert body["note"] == "patching"
    assert body["record_id"]

    # Persisted to the Local_Database.
    records = Repository(session).get_remediations_for_machine("m1")
    assert len(records) == 1
    assert records[0].cve_id == "CVE-2024-1"
    assert records[0].status == RemediationStatus.IN_PROGRESS


def test_add_remediation_unknown_machine_returns_404(client):
    resp = client.post(
        "/api/machines/nope/cves/CVE-1/remediation",
        json={"status": "open", "note": ""},
    )
    assert resp.status_code == 404


def test_add_remediation_invalid_status_returns_422(session, client):
    _make_machine(session, "m1")
    session.commit()
    resp = client.post(
        "/api/machines/m1/cves/CVE-1/remediation",
        json={"status": "not-a-status", "note": "x"},
    )
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# PUT /api/remediation/{record_id}
# --------------------------------------------------------------------------- #
def test_update_remediation_reflects_last_write(session, client):
    _make_machine(session, "m1")
    record = Repository(session).add_remediation(
        "m1", "CVE-1", RemediationInput(status=RemediationStatus.OPEN, note="triage")
    )
    session.commit()

    resp = client.put(
        f"/api/remediation/{record.id}",
        json={"status": "remediated", "note": "done"},
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["record_id"] == record.id
    assert body["status"] == "remediated"
    assert body["note"] == "done"

    reread = Repository(session).get_remediation(record.id)
    assert reread.status == RemediationStatus.REMEDIATED
    assert reread.note == "done"


def test_update_remediation_unknown_record_returns_404(client):
    resp = client.put(
        "/api/remediation/does-not-exist",
        json={"status": "open", "note": ""},
    )
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# POST /api/scans
# --------------------------------------------------------------------------- #
class _StubCollector:
    """Collector that returns a fixed inventory or raises to simulate failure.

    ``fail_hosts`` limits the failure to the named hostnames, so batch fault
    isolation can be exercised within a single platform.
    """

    def __init__(
        self, *, fail: Exception | None = None, fail_hosts: set[str] | None = None
    ) -> None:
        self._fail = fail
        self._fail_hosts = fail_hosts

    def collect(self, target, credentials) -> Inventory:
        if self._fail is not None and (
            self._fail_hosts is None or target.hostname in self._fail_hosts
        ):
            raise self._fail
        return Inventory(
            machine_id=target.id,
            os_info=OsInfo(name="Ubuntu", version="22.04"),
            packages=[Package(name="openssl", version="3.0.2")],
            collected_at=datetime(2024, 5, 1, tzinfo=timezone.utc),
        )


class _StubNvd:
    """NVD client returning one OS-level CVE for any OS."""

    def match_os(self, os_info):
        from app.scanner.matcher import RawCve

        return [RawCve(cve_id="CVE-OS-1", cvss_score=9.2)]


def _install_scan_engine(app, session, *, collector_by_platform):
    """Override get_scanner_engine with an engine using stubbed collectors."""
    repo = Repository(session)

    def collector_factory(platform):
        return collector_by_platform[platform]

    engine = ScannerEngine(
        repository=repo,
        credentials_for=lambda t: Credentials(username="x", password="y"),
        nvd=_StubNvd(),
        osv=None,
        collector_factory=collector_factory,
    )
    app.dependency_overrides[get_scanner_engine] = lambda: engine
    return engine


def test_scan_success_persists_and_reports_findings(app, client, session):
    _install_scan_engine(
        app,
        session,
        collector_by_platform={Platform.LINUX: _StubCollector()},
    )

    resp = client.post(
        "/api/scans",
        json={
            "targets": [
                {
                    "id": "m1",
                    "hostname": "alpha.example.com",
                    "platform": "linux",
                    "username": "root",
                    "password": "secret",
                }
            ]
        },
    )

    assert resp.status_code == 200
    body = resp.json()
    assert len(body["machine_scans"]) == 1
    scan = body["machine_scans"][0]
    assert scan["machine_id"] == "m1"
    assert scan["status"] == "success"
    assert scan["finding_count"] == 1

    # Findings were persisted by the engine.
    findings = session.execute(
        select(CveFinding).where(CveFinding.machine_id == "m1")
    ).scalars().all()
    assert [f.cve_id for f in findings] == ["CVE-OS-1"]


def test_scan_isolates_auth_failure_across_batch(app, client, session):
    """One target's auth failure does not abort the batch (Req 1.4, 1.5).

    Both targets are Linux: this previously paired a Linux target with a
    Windows one, which Req 10.8 now refuses outright.
    """
    _install_scan_engine(
        app,
        session,
        collector_by_platform={
            Platform.LINUX: _StubCollector(fail=AuthError("bad creds"), fail_hosts={"beta"}),
        },
    )

    resp = client.post(
        "/api/scans",
        json={
            "targets": [
                {
                    "id": "m1",
                    "hostname": "alpha",
                    "platform": "linux",
                    "username": "root",
                    "password": "s",
                },
                {
                    "id": "m2",
                    "hostname": "beta",
                    "platform": "linux",
                    "username": "admin",
                    "password": "s",
                },
            ]
        },
    )

    assert resp.status_code == 200
    scans = {s["machine_id"]: s for s in resp.json()["machine_scans"]}
    assert scans["m1"]["status"] == "success"
    assert scans["m2"]["status"] == "auth_failure"
    assert scans["m2"]["finding_count"] == 0


def test_scan_refuses_windows_targets(app, client, session):
    """A Windows target is refused with a reason, never scanned (Req 10.8)."""
    collector = _StubCollector()
    _install_scan_engine(
        app,
        session,
        collector_by_platform={Platform.LINUX: collector, Platform.WINDOWS: collector},
    )

    resp = client.post(
        "/api/scans",
        json={"targets": [{"id": "w1", "hostname": "win-01", "platform": "windows",
                           "username": "admin", "password": "s"}]},
    )

    assert resp.status_code == 422
    detail = resp.json()["detail"]
    assert "Windows scanning is not supported yet" in detail
    assert "win-01" in detail


def test_scan_refuses_a_batch_containing_any_windows_target(app, client, session):
    """A mixed batch is refused whole and nothing is recorded for any target (Req 10.8).

    Dropping the Windows target and scanning the rest would report the batch as
    complete when part of it was never attempted.
    """
    _install_scan_engine(
        app,
        session,
        collector_by_platform={Platform.LINUX: _StubCollector()},
    )

    resp = client.post(
        "/api/scans",
        json={"targets": [
            {"id": "m1", "hostname": "alpha", "platform": "linux", "username": "root", "password": "s"},
            {"id": "w1", "hostname": "win-01", "platform": "windows", "username": "admin", "password": "s"},
        ]},
    )

    assert resp.status_code == 422
    assert "win-01" in resp.json()["detail"]
    assert "alpha" not in resp.json()["detail"]
    assert client.get("/api/machines").json() == []


def test_scan_empty_targets_returns_422(app, client, session):
    _install_scan_engine(
        app,
        session,
        collector_by_platform={Platform.LINUX: _StubCollector()},
    )
    resp = client.post("/api/scans", json={"targets": []})
    assert resp.status_code == 422


def test_scan_password_not_echoed(app, client, session):
    _install_scan_engine(
        app,
        session,
        collector_by_platform={Platform.LINUX: _StubCollector()},
    )
    resp = client.post(
        "/api/scans",
        json={
            "targets": [
                {
                    "id": "m1",
                    "hostname": "alpha",
                    "platform": "linux",
                    "username": "root",
                    "password": "topsecret",
                }
            ]
        },
    )
    assert resp.status_code == 200
    assert "topsecret" not in resp.text


# --------------------------------------------------------------------------- #
# POST /api/sync
# --------------------------------------------------------------------------- #
def _seed_pending_finding(session):
    _make_machine(session, "m1")
    Repository(session).save_findings(
        "m1", [FindingInput(cve_id="CVE-1", cvss_score=9.1, severity=Severity.CRITICAL, source="nvd")]
    )
    session.commit()


def test_sync_reachable_online_converges(app, client, session):
    _seed_pending_finding(session)

    online_engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(online_engine)
    online_factory = sessionmaker(bind=online_engine)
    service = SyncService(session, online_factory)
    app.dependency_overrides[get_sync_service] = lambda: service

    resp = client.post("/api/sync")

    assert resp.status_code == 200
    body = resp.json()
    assert body["online_reachable"] is True
    assert body["total_pending"] == 0
    assert body["total_propagated"] > 0


def test_sync_unreachable_online_retains_pending(app, client, session):
    _seed_pending_finding(session)

    def unreachable_factory():
        raise ConnectionError("online unreachable")

    service = SyncService(session, unreachable_factory)
    app.dependency_overrides[get_sync_service] = lambda: service

    resp = client.post("/api/sync")

    assert resp.status_code == 200
    body = resp.json()
    assert body["online_reachable"] is False
    assert body["total_propagated"] == 0
    assert body["total_pending"] > 0


def test_test_connection_unreachable_host(client):
    resp = client.post(
        "/api/scans/test-connection",
        json={
            "hostname": "127.0.0.1",
            "platform": "linux",
            "username": "root",
            "password": "secretpassword",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is False
    assert body["status"] in ("CONNECTION_FAILURE", "AUTH_FAILURE")


def test_test_connection_ssh_success(monkeypatch, client):
    import socket
    import paramiko

    # Mock TCP socket connect
    def mock_create_connection(address, timeout=None):
        mock_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        return mock_sock

    monkeypatch.setattr(socket, "create_connection", mock_create_connection)

    # Mock Paramiko SSHClient
    class MockSSHClient:
        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, hostname, port, username, password, timeout, look_for_keys, allow_agent):
            pass

        def exec_command(self, cmd, timeout=None):
            class MockStdout:
                def read(self):
                    return b"Linux test-host 5.15.0 #1 SMP Ubuntu 22.04 LTS x86_64\n"

            class MockChannel:
                def recv_exit_status(self):
                    return 0

            return None, MockStdout(), None

        def close(self):
            pass

    monkeypatch.setattr(paramiko, "SSHClient", MockSSHClient)

    resp = client.post(
        "/api/scans/test-connection",
        json={
            "hostname": "192.168.1.50",
            "platform": "linux",
            "username": "ubuntu",
            "password": "correctpassword",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is True
    assert body["status"] == "SUCCESS"
    assert "Ubuntu 22.04 LTS" in body["os_banner"]
    assert body["latency_ms"] >= 0


def test_test_connection_ssh_auth_failure(monkeypatch, client):
    import socket
    import paramiko

    def mock_create_connection(address, timeout=None):
        return socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    monkeypatch.setattr(socket, "create_connection", mock_create_connection)

    class MockAuthFailSSHClient:
        def set_missing_host_key_policy(self, policy):
            pass

        def connect(self, hostname, port, username, password, timeout, look_for_keys, allow_agent):
            raise paramiko.AuthenticationException("Permission denied (publickey,password).")

        def close(self):
            pass

    monkeypatch.setattr(paramiko, "SSHClient", MockAuthFailSSHClient)

    resp = client.post(
        "/api/scans/test-connection",
        json={
            "hostname": "192.168.1.50",
            "platform": "linux",
            "username": "ubuntu",
            "password": "wrongpassword",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["success"] is False
    assert body["status"] == "AUTH_FAILURE"
    assert "rejected" in body["message"].lower() or "auth" in body["message"].lower()

