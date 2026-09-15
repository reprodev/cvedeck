"""Integration tests for the Backend_API contracts (task 8.5).

These exercise the outward-facing API at a higher fidelity than the endpoint
unit tests in ``test_api_read.py`` / ``test_api_actions.py``. They stand up the
full FastAPI application via ``create_app`` and drive it through
``fastapi.testclient.TestClient`` over an in-memory SQLite session injected by
overriding the ``get_session`` dependency, so the routing, dependency wiring,
Pydantic validation, and JSON serialization are all covered end to end.

The focus is the three contract concerns called out by the Testing Strategy:

- **Machine-list read (Req 6.1):** ``GET /api/machines`` returns the scanned
  machines as well-formed structured JSON matching the documented
  ``MachineSummary`` shape (Req 6.5).
- **404 for unknown machine (Req 6.4):** every GET endpoint scoped to a machine
  returns HTTP 404 with a JSON body for an unknown machine id.
- **JSON schema / validation (Req 6.5):** malformed requests (invalid severity
  query, malformed remediation/scan bodies) are rejected with HTTP 422 and a
  structured JSON validation body, and successful responses are valid JSON that
  matches the documented response shapes.

These tests deliberately add a new module and do not modify the application
under test or the existing endpoint test modules.
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.app import create_app
from tests.auth_helpers import override_auth
from app.api.dependencies import get_scanner_engine, get_session
from app.api.schemas import CveFindingOut, MachineSummary
from app.data.repository import FindingInput, RemediationInput, Repository
from app.data.schema import Base, TargetMachine
from app.enums import (
    Platform,
    RemediationStatus,
    ScanStatus,
    Severity,
    SyncStatus,
)


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #
@pytest.fixture()
def session():
    """In-memory SQLite session with all tables created.

    A ``StaticPool`` keeps the single in-memory database alive for the lifetime
    of the fixture so the app and the test share the same data.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


class _UnusedScannerEngine:
    """Stub scanner engine that must never be reached.

    The scan endpoint depends on ``get_scanner_engine``, which FastAPI resolves
    while solving dependencies -- before the request body is handed to the
    endpoint. Overriding it with this stub lets the malformed-body tests reach
    Pydantic body validation (producing the expected 422) instead of tripping
    over the unconfigured default provider. A well-formed body would call
    ``scan`` and fail the test, proving the 422 came from validation and not
    from the engine.
    """

    def set_credentials(self, credentials_by_id):  # pragma: no cover - guard
        raise AssertionError("scanner engine must not run for malformed requests")

    def scan(self, targets):  # pragma: no cover - guard
        raise AssertionError("scanner engine must not run for malformed requests")


@pytest.fixture()
def client(session):
    """TestClient over the full app with test dependencies overridden.

    ``get_session`` is bound to the in-memory test session. ``get_scanner_engine``
    is bound to a stub so the scan endpoint's dependency resolution succeeds and
    malformed scan bodies are rejected by validation (422) rather than by the
    unconfigured default engine provider.
    """
    app = override_auth(create_app())
    app.dependency_overrides[get_session] = lambda: session
    app.dependency_overrides[get_scanner_engine] = lambda: _UnusedScannerEngine()
    return TestClient(app)


# --------------------------------------------------------------------------- #
# Seed helpers
# --------------------------------------------------------------------------- #
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


def _assert_json_response(resp) -> object:
    """Assert the response advertises JSON and parses as JSON (Req 6.5)."""
    assert resp.headers["content-type"].startswith("application/json")
    return resp.json()


# The documented MachineSummary contract fields and their JSON types.
_MACHINE_SUMMARY_KEYS = {
    "machine_id": str,
    "hostname": str,
    "platform": str,
    "last_scan_status": str,
    # None until the machine has been scanned, so the type check allows both.
    "last_scanned_at": (str, type(None)),
    "last_scan_sources_ok": bool,
    "cve_counts": dict,
    # Findings confirmed as actively exploited. Zero means "none confirmed",
    # which on a fleet whose intel feeds never loaded is not the same as "none
    # exist" -- GET /api/feeds is what distinguishes them.
    "kev_count": int,
    # The pinned SSH host key's fingerprint; None until one is pinned.
    "host_key_fingerprint": (str, type(None)),
    # What the latest successful scan changed. Null is "not assessed" -- no
    # successful scan, a baseline, or (resolved only) a partial scan.
    "last_scan_new": (int, type(None)),
    "last_scan_resolved": (int, type(None)),
    "last_scan_baseline": bool,
}
_SEVERITY_COUNT_KEYS = {"critical", "high", "medium", "low"}
_FINDING_KEYS = {
    "cve_id": str,
    "severity": str,
    "cvss_score": (int, float),
    "package_identifier": (str, type(None)),
    # Structure parsed out of package_identifier server-side, so clients never
    # have to search its prose for "fixed in".
    "package_name": (str, type(None)),
    "fixed_version": (str, type(None)),
    "has_fix": bool,
    # Where the fix is (Req 14.7, 14.8): "available" on the host's own release,
    # "newer_release" or "upstream" naming the release that has it, or "none".
    "fix_status": str,
    "fix_release": (str, type(None)),
    "fix_release_version": (str, type(None)),
    "remediation_status": (str, type(None)),
    # The record id lets a client update an existing remediation record rather
    # than only add new ones; the note carries its free-text detail (Req 4.2).
    "remediation_record_id": (str, type(None)),
    "remediation_note": (str, type(None)),
    "dependencies": list,
    "depended_on_by": list,
    "blast_radius": str,
    # Threat-intel enrichment. Every one of these is nullable on purpose:
    # null means "not enriched", which a client must render as unknown rather
    # than as a negative. Only an explicit false on kev_listed means the CVE
    # was checked against the catalogue and is genuinely absent from it.
    "kev_listed": (bool, type(None)),
    "kev_due_date": (str, type(None)),
    "epss_score": (int, float, type(None)),
    "epss_percentile": (int, float, type(None)),
    # Scan history (Req 18.5, 18.6).
    "first_seen_at": (str, type(None)),
    "is_new": bool,
}


def _assert_machine_summary_shape(obj: dict) -> None:
    """Assert a JSON object matches the documented MachineSummary shape."""
    assert set(obj) == set(_MACHINE_SUMMARY_KEYS)
    for key, typ in _MACHINE_SUMMARY_KEYS.items():
        assert isinstance(obj[key], typ), f"{key} has wrong type"
    counts = obj["cve_counts"]
    assert set(counts) == _SEVERITY_COUNT_KEYS
    assert all(isinstance(counts[k], int) for k in _SEVERITY_COUNT_KEYS)
    # The shape must round-trip through the documented Pydantic model.
    MachineSummary.model_validate(obj)


def _assert_finding_shape(obj: dict) -> None:
    """Assert a JSON object matches the documented CveFindingOut shape."""
    assert set(obj) == set(_FINDING_KEYS)
    for key, typ in _FINDING_KEYS.items():
        assert isinstance(obj[key], typ), f"{key} has wrong type"
    CveFindingOut.model_validate(obj)


# --------------------------------------------------------------------------- #
# Req 6.1: machine-list read contract
# --------------------------------------------------------------------------- #
def test_machine_list_read_returns_all_scanned_machines(session, client):
    """GET /api/machines returns every scanned machine as JSON (Req 6.1, 6.5)."""
    _make_machine(session, "m1", "alpha.example.com", Platform.LINUX)
    _make_machine(session, "m2", "beta.example.com", Platform.WINDOWS)
    _make_machine(
        session, "m3", "gamma.example.com", Platform.LINUX, ScanStatus.AUTH_FAILURE
    )
    Repository(session).save_findings(
        "m1",
        [
            _finding("CVE-1", 9.5, Severity.CRITICAL),
            _finding("CVE-2", 7.5, Severity.HIGH),
            _finding("CVE-3", 5.0, Severity.MEDIUM),
            _finding("CVE-4", 2.0, Severity.LOW),
        ],
    )
    session.commit()

    resp = client.get("/api/machines")
    assert resp.status_code == 200
    body = _assert_json_response(resp)

    assert isinstance(body, list)
    assert {m["machine_id"] for m in body} == {"m1", "m2", "m3"}
    for entry in body:
        _assert_machine_summary_shape(entry)

    by_id = {m["machine_id"]: m for m in body}
    assert by_id["m1"]["cve_counts"] == {
        "critical": 1,
        "high": 1,
        "medium": 1,
        "low": 1,
    }
    assert by_id["m2"]["platform"] == "windows"
    assert by_id["m3"]["last_scan_status"] == "auth_failure"


def test_machine_list_read_empty_is_well_formed_json_array(client):
    """GET /api/machines with no data is a valid empty JSON array (Req 6.1)."""
    resp = client.get("/api/machines")
    assert resp.status_code == 200
    body = _assert_json_response(resp)
    assert body == []


def test_machine_list_read_counts_sum_to_findings(session, client):
    """The severity-grouped counts add up to the machine's finding total."""
    _make_machine(session, "m1", "alpha.example.com")
    Repository(session).save_findings(
        "m1",
        [
            _finding("CVE-1", 9.5, Severity.CRITICAL),
            _finding("CVE-2", 9.1, Severity.CRITICAL),
            _finding("CVE-3", 7.5, Severity.HIGH),
        ],
    )
    session.commit()

    resp = client.get("/api/machines")
    counts = resp.json()[0]["cve_counts"]
    assert sum(counts.values()) == 3
    assert counts == {"critical": 2, "high": 1, "medium": 0, "low": 0}


# --------------------------------------------------------------------------- #
# Req 6.4: 404 for unknown machine across machine-scoped GET endpoints
# --------------------------------------------------------------------------- #
@pytest.mark.parametrize(
    "path",
    [
        "/api/machines/ghost",
        "/api/machines/ghost/cves",
    ],
)
def test_unknown_machine_returns_404_json(client, path):
    """Machine-scoped GET endpoints return 404 with a JSON body (Req 6.4)."""
    resp = client.get(path)
    assert resp.status_code == 404
    body = _assert_json_response(resp)
    assert "detail" in body


def test_unknown_machine_cves_with_severity_filter_still_404(client):
    """A severity filter does not mask the 404 for an unknown machine (Req 6.4)."""
    resp = client.get("/api/machines/ghost/cves", params={"severity": "critical"})
    assert resp.status_code == 404
    _assert_json_response(resp)


def test_known_machine_is_not_404(session, client):
    """A machine that exists is reachable (guards against false 404s)."""
    _make_machine(session, "real", "real.example.com")
    session.commit()

    detail = client.get("/api/machines/real")
    assert detail.status_code == 200
    _assert_machine_summary_shape(detail.json())

    cves = client.get("/api/machines/real/cves")
    assert cves.status_code == 200
    assert cves.json() == []


# --------------------------------------------------------------------------- #
# Req 6.5: JSON schema / validation -> 422 on malformed requests
# --------------------------------------------------------------------------- #
def _assert_validation_error(resp) -> None:
    """Assert a 422 with the structured FastAPI validation JSON body."""
    assert resp.status_code == 422
    body = _assert_json_response(resp)
    assert isinstance(body, dict)
    assert isinstance(body["detail"], list)
    assert body["detail"], "validation error detail should be non-empty"


def test_invalid_severity_query_on_machine_cves_returns_422(session, client):
    """An out-of-enum severity query is rejected with 422 (Req 6.5)."""
    _make_machine(session, "m1", "alpha.example.com")
    session.commit()
    resp = client.get("/api/machines/m1/cves", params={"severity": "extreme"})
    _assert_validation_error(resp)


def test_invalid_severity_query_on_all_cves_returns_422(client):
    """An out-of-enum severity query on the collection endpoint is 422 (Req 6.5)."""
    resp = client.get("/api/cves", params={"severity": "extreme"})
    _assert_validation_error(resp)


def test_valid_severity_query_is_accepted(session, client):
    """Every documented severity value is accepted (contrast to the 422 case)."""
    _make_machine(session, "m1", "alpha.example.com")
    Repository(session).save_findings(
        "m1",
        [
            _finding("CVE-c", 9.5, Severity.CRITICAL),
            _finding("CVE-h", 7.5, Severity.HIGH),
            _finding("CVE-m", 5.0, Severity.MEDIUM),
            _finding("CVE-l", 2.0, Severity.LOW),
        ],
    )
    session.commit()

    for value in ("critical", "high", "medium", "low"):
        resp = client.get("/api/cves", params={"severity": value})
        assert resp.status_code == 200
        findings = _assert_json_response(resp)
        assert all(f["severity"] == value for f in findings)
        for f in findings:
            _assert_finding_shape(f)


def test_malformed_remediation_body_invalid_status_returns_422(session, client):
    """A remediation body with an out-of-enum status is 422 (Req 6.5)."""
    _make_machine(session, "m1", "alpha.example.com")
    session.commit()
    resp = client.post(
        "/api/machines/m1/cves/CVE-1/remediation",
        json={"status": "not-a-status", "note": "x"},
    )
    _assert_validation_error(resp)


def test_malformed_remediation_body_wrong_note_type_returns_422(session, client):
    """A remediation body with a wrong-typed note is 422 (Req 6.5)."""
    _make_machine(session, "m1", "alpha.example.com")
    session.commit()
    resp = client.post(
        "/api/machines/m1/cves/CVE-1/remediation",
        json={"status": "open", "note": {"unexpected": "object"}},
    )
    _assert_validation_error(resp)


def test_malformed_remediation_body_missing_status_returns_422(session, client):
    """A remediation body missing the required status is 422 (Req 6.5)."""
    _make_machine(session, "m1", "alpha.example.com")
    session.commit()
    resp = client.post(
        "/api/machines/m1/cves/CVE-1/remediation",
        json={"note": "no status provided"},
    )
    _assert_validation_error(resp)


def test_malformed_remediation_update_body_returns_422(session, client):
    """A malformed PUT remediation body is rejected before touching state (Req 6.5)."""
    _make_machine(session, "m1", "alpha.example.com")
    record = Repository(session).add_remediation(
        "m1", "CVE-1", RemediationInput(status=RemediationStatus.OPEN, note="triage")
    )
    session.commit()
    resp = client.put(
        f"/api/remediation/{record.id}",
        json={"status": "definitely-not-valid"},
    )
    _assert_validation_error(resp)


def test_malformed_scan_body_empty_targets_returns_422(client):
    """A scan request with no targets violates the min-length rule (Req 6.5)."""
    resp = client.post("/api/scans", json={"targets": []})
    _assert_validation_error(resp)


def test_malformed_scan_body_missing_target_fields_returns_422(client):
    """A scan target missing required fields is rejected with 422 (Req 6.5)."""
    resp = client.post(
        "/api/scans",
        json={"targets": [{"id": "m1", "hostname": "alpha"}]},
    )
    _assert_validation_error(resp)


def test_malformed_scan_body_invalid_platform_returns_422(client):
    """A scan target with an out-of-enum platform is rejected with 422 (Req 6.5)."""
    resp = client.post(
        "/api/scans",
        json={
            "targets": [
                {
                    "id": "m1",
                    "hostname": "alpha",
                    "platform": "solaris",
                    "username": "root",
                    "password": "s",
                }
            ]
        },
    )
    _assert_validation_error(resp)


def test_malformed_scan_body_not_json_object_returns_422(client):
    """A scan request whose body is not the documented object is 422 (Req 6.5)."""
    resp = client.post("/api/scans", json=["not", "an", "object"])
    _assert_validation_error(resp)


# --------------------------------------------------------------------------- #
# Req 6.5: successful responses are well-formed JSON matching documented shapes
# --------------------------------------------------------------------------- #
def test_machine_cves_response_matches_documented_shape(session, client):
    """Per-machine CVE responses match the documented CveFindingOut shape."""
    _make_machine(session, "m1", "alpha.example.com")
    repo = Repository(session)
    repo.save_findings(
        "m1",
        [
            _finding("CVE-nvd", 9.8, Severity.CRITICAL),
            _finding(
                "CVE-osv",
                6.0,
                Severity.MEDIUM,
                source="osv",
                package_identifier="pkg:pypi/requests",
            ),
        ],
    )
    repo.add_remediation(
        "m1",
        "CVE-nvd",
        RemediationInput(status=RemediationStatus.IN_PROGRESS, note="patching"),
    )
    session.commit()

    resp = client.get("/api/machines/m1/cves")
    assert resp.status_code == 200
    findings = _assert_json_response(resp)
    assert isinstance(findings, list)
    assert len(findings) == 2
    for finding in findings:
        _assert_finding_shape(finding)

    by_id = {f["cve_id"]: f for f in findings}
    assert by_id["CVE-nvd"]["remediation_status"] == "in_progress"
    assert by_id["CVE-nvd"]["package_identifier"] is None
    assert by_id["CVE-osv"]["package_identifier"] == "pkg:pypi/requests"
    assert by_id["CVE-osv"]["remediation_status"] is None


def test_all_cves_response_matches_documented_shape(session, client):
    """The collection CVE endpoint returns documented-shape JSON objects."""
    _make_machine(session, "m1", "alpha.example.com")
    _make_machine(session, "m2", "beta.example.com")
    repo = Repository(session)
    repo.save_findings("m1", [_finding("CVE-1", 9.8, Severity.CRITICAL)])
    repo.save_findings("m2", [_finding("CVE-2", 5.0, Severity.MEDIUM)])
    session.commit()

    resp = client.get("/api/cves")
    assert resp.status_code == 200
    findings = _assert_json_response(resp)
    assert {f["cve_id"] for f in findings} == {"CVE-1", "CVE-2"}
    for finding in findings:
        _assert_finding_shape(finding)
