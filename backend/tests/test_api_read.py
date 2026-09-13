"""Unit/contract tests for the Backend_API read endpoints (task 8.1).

These verify the machine and CVE read routes against an in-memory SQLite
session injected by overriding the ``get_session`` dependency:

- ``GET /api/machines`` returns scanned machines with severity-grouped counts
  (Req 6.1, 3.2).
- ``GET /api/machines/{id}`` returns a machine summary and 404 for an unknown
  machine (Req 6.4).
- ``GET /api/machines/{id}/cves?severity=`` returns per-machine CVEs, optionally
  severity-filtered, carrying CVE id, severity, and CVSS score (Req 6.2, 6.3);
  404 for an unknown machine (Req 6.4).
- ``GET /api/cves?severity=`` returns all CVEs, optionally severity-filtered
  (Req 3.3, 6.3).
- Responses are structured JSON (Req 6.5).
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.app import create_app
from app.api.dependencies import get_session
from app.data.repository import FindingInput, RemediationInput, Repository
from app.data.schema import Base, TargetMachine
from app.enums import (
    Platform,
    RemediationStatus,
    ScanStatus,
    Severity,
    SyncStatus,
)


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
def client(session):
    """TestClient with the app's session dependency overridden to the test session."""
    app = create_app()
    app.dependency_overrides[get_session] = lambda: session
    return TestClient(app)


def _make_machine(
    session: Session,
    machine_id: str,
    hostname: str,
    platform: Platform = Platform.LINUX,
    status: ScanStatus = ScanStatus.SUCCESS,
) -> TargetMachine:
    machine = TargetMachine(
        id=machine_id,
        hostname=hostname,
        platform=platform,
        last_scan_status=status,
        last_scanned_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        sync_status=SyncStatus.PENDING_SYNC,
    )
    session.add(machine)
    session.flush()
    return machine


def _finding(
    cve_id: str,
    cvss: float,
    severity: Severity,
    source: str = "nvd",
    package_identifier: str | None = None,
) -> FindingInput:
    return FindingInput(
        cve_id=cve_id,
        cvss_score=cvss,
        severity=severity,
        source=source,
        package_identifier=package_identifier,
    )


# --------------------------------------------------------------------------- #
# GET /api/machines
# --------------------------------------------------------------------------- #
def test_list_machines_returns_severity_grouped_counts(session, client):
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com", Platform.LINUX)
    _make_machine(session, "m2", "beta.example.com", Platform.WINDOWS)
    repo.save_findings(
        "m1",
        [
            _finding("CVE-1", 9.5, Severity.CRITICAL),
            _finding("CVE-2", 7.5, Severity.HIGH),
            _finding("CVE-3", 7.1, Severity.HIGH),
        ],
    )
    session.commit()

    resp = client.get("/api/machines")
    assert resp.status_code == 200
    body = resp.json()
    assert len(body) == 2

    by_id = {m["machine_id"]: m for m in body}
    m1 = by_id["m1"]
    assert m1["hostname"] == "alpha.example.com"
    assert m1["platform"] == "linux"
    assert m1["last_scan_status"] == "success"
    assert m1["cve_counts"] == {"critical": 1, "high": 2, "medium": 0, "low": 0}

    m2 = by_id["m2"]
    assert m2["cve_counts"] == {"critical": 0, "high": 0, "medium": 0, "low": 0}


def test_list_machines_empty(client):
    resp = client.get("/api/machines")
    assert resp.status_code == 200
    assert resp.json() == []


# --------------------------------------------------------------------------- #
# GET /api/machines/{id}
# --------------------------------------------------------------------------- #
def test_get_machine_returns_summary(session, client):
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com")
    repo.save_findings("m1", [_finding("CVE-1", 5.0, Severity.MEDIUM)])
    session.commit()

    resp = client.get("/api/machines/m1")
    assert resp.status_code == 200
    body = resp.json()
    assert body["machine_id"] == "m1"
    assert body["cve_counts"] == {"critical": 0, "high": 0, "medium": 1, "low": 0}


def test_get_unknown_machine_returns_404(client):
    resp = client.get("/api/machines/does-not-exist")
    assert resp.status_code == 404


# --------------------------------------------------------------------------- #
# GET /api/machines/{id}/cves
# --------------------------------------------------------------------------- #
def test_get_machine_cves_includes_id_severity_and_score(session, client):
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com")
    repo.save_findings(
        "m1",
        [
            _finding("CVE-crit", 9.8, Severity.CRITICAL),
            _finding("CVE-osv", 6.0, Severity.MEDIUM, source="osv", package_identifier="pkg:pypi/requests"),
        ],
    )
    session.commit()

    resp = client.get("/api/machines/m1/cves")
    assert resp.status_code == 200
    findings = resp.json()
    assert len(findings) == 2
    for f in findings:
        assert "cve_id" in f
        assert "severity" in f
        assert "cvss_score" in f

    osv = next(f for f in findings if f["cve_id"] == "CVE-osv")
    assert osv["package_identifier"] == "pkg:pypi/requests"


def test_get_machine_cves_severity_filter(session, client):
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com")
    repo.save_findings(
        "m1",
        [
            _finding("CVE-crit", 9.8, Severity.CRITICAL),
            _finding("CVE-high", 7.5, Severity.HIGH),
            _finding("CVE-crit2", 9.1, Severity.CRITICAL),
        ],
    )
    session.commit()

    resp = client.get("/api/machines/m1/cves", params={"severity": "critical"})
    assert resp.status_code == 200
    findings = resp.json()
    assert {f["cve_id"] for f in findings} == {"CVE-crit", "CVE-crit2"}
    assert all(f["severity"] == "critical" for f in findings)


def test_get_machine_cves_includes_remediation_status(session, client):
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com")
    repo.save_findings("m1", [_finding("CVE-1", 9.8, Severity.CRITICAL)])
    repo.add_remediation(
        "m1", "CVE-1", RemediationInput(status=RemediationStatus.IN_PROGRESS, note="patching")
    )
    session.commit()

    resp = client.get("/api/machines/m1/cves")
    assert resp.status_code == 200
    finding = resp.json()[0]
    assert finding["remediation_status"] == "in_progress"


def test_get_machine_cves_includes_remediation_record_id_and_note(session, client):
    """The record id is what lets a client PUT an update instead of adding again."""
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com")
    repo.save_findings("m1", [_finding("CVE-1", 9.8, Severity.CRITICAL)])
    record = repo.add_remediation(
        "m1",
        "CVE-1",
        RemediationInput(status=RemediationStatus.IN_PROGRESS, note="patching"),
    )
    session.commit()

    resp = client.get("/api/machines/m1/cves")
    assert resp.status_code == 200
    finding = resp.json()[0]
    assert finding["remediation_record_id"] == record.id
    assert finding["remediation_note"] == "patching"


def test_get_machine_cves_remediation_fields_are_null_without_a_record(
    session, client
):
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com")
    repo.save_findings("m1", [_finding("CVE-1", 9.8, Severity.CRITICAL)])
    session.commit()

    resp = client.get("/api/machines/m1/cves")
    assert resp.status_code == 200
    finding = resp.json()[0]
    assert finding["remediation_status"] is None
    assert finding["remediation_record_id"] is None
    assert finding["remediation_note"] is None


def test_latest_remediation_record_wins_per_cve(session, client):
    """Two records for one CVE: the most recently updated one is surfaced."""
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com")
    repo.save_findings("m1", [_finding("CVE-1", 9.8, Severity.CRITICAL)])
    repo.add_remediation(
        "m1", "CVE-1", RemediationInput(status=RemediationStatus.OPEN, note="first")
    )
    latest = repo.add_remediation(
        "m1",
        "CVE-1",
        RemediationInput(status=RemediationStatus.REMEDIATED, note="second"),
    )
    session.commit()

    finding = client.get("/api/machines/m1/cves").json()[0]
    assert finding["remediation_record_id"] == latest.id
    assert finding["remediation_status"] == "remediated"
    assert finding["remediation_note"] == "second"


def test_list_all_cves_includes_remediation_record_id(session, client):
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com")
    repo.save_findings("m1", [_finding("CVE-1", 9.8, Severity.CRITICAL)])
    record = repo.add_remediation(
        "m1", "CVE-1", RemediationInput(status=RemediationStatus.OPEN, note="triage")
    )
    session.commit()

    finding = client.get("/api/cves").json()[0]
    assert finding["remediation_record_id"] == record.id
    assert finding["remediation_note"] == "triage"


def test_get_cves_for_unknown_machine_returns_404(client):
    resp = client.get("/api/machines/nope/cves")
    assert resp.status_code == 404


def test_get_machine_cves_invalid_severity_returns_422(session, client):
    _make_machine(session, "m1", "alpha.example.com")
    session.commit()
    resp = client.get("/api/machines/m1/cves", params={"severity": "bogus"})
    assert resp.status_code == 422


# --------------------------------------------------------------------------- #
# GET /api/cves
# --------------------------------------------------------------------------- #
def test_list_all_cves(session, client):
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com")
    _make_machine(session, "m2", "beta.example.com")
    repo.save_findings("m1", [_finding("CVE-1", 9.8, Severity.CRITICAL)])
    repo.save_findings("m2", [_finding("CVE-2", 5.0, Severity.MEDIUM)])
    session.commit()

    resp = client.get("/api/cves")
    assert resp.status_code == 200
    findings = resp.json()
    assert {f["cve_id"] for f in findings} == {"CVE-1", "CVE-2"}


def test_list_all_cves_severity_filter(session, client):
    repo = Repository(session)
    _make_machine(session, "m1", "alpha.example.com")
    _make_machine(session, "m2", "beta.example.com")
    repo.save_findings("m1", [_finding("CVE-1", 9.8, Severity.CRITICAL)])
    repo.save_findings("m2", [_finding("CVE-2", 5.0, Severity.MEDIUM)])
    session.commit()

    resp = client.get("/api/cves", params={"severity": "medium"})
    assert resp.status_code == 200
    findings = resp.json()
    assert {f["cve_id"] for f in findings} == {"CVE-2"}
    assert all(f["severity"] == "medium" for f in findings)
