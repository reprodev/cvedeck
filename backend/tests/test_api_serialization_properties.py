"""Property-based test for Backend_API serialization completeness (task 8.4).

Feature: cvedeck
Property 8: Finding rendering and serialization completeness
Validates: Requirements 3.5, 6.2

For any finding serialized in an API response, the output includes the CVE
identifier, the Severity_Level, and the CVSS_Score.

The test generates arbitrary findings across several machines, seeds them via
the repository into an in-memory SQLite session wired into a FastAPI
``TestClient``, then calls the per-machine CVE endpoint (Req 6.2) and the
all-CVEs endpoint, asserting every serialized finding carries a non-empty
``cve_id``, a valid ``severity``, and a ``cvss_score`` that is numeric, or
null exactly when the severity is ``unscored``.
"""

from __future__ import annotations

from datetime import datetime, timezone

from fastapi.testclient import TestClient
from hypothesis import given, settings
from hypothesis import strategies as st
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.app import create_app
from tests.auth_helpers import override_auth
from app.api.dependencies import get_session
from app.data.repository import FindingInput, Repository
from app.data.schema import Base, TargetMachine
from app.enums import Platform, ScanStatus, Severity, SyncStatus

# Valid severity string values the serialized output must be drawn from.
_VALID_SEVERITIES = {s.value for s in Severity}


# --------------------------------------------------------------------------- #
# Hypothesis strategies
# --------------------------------------------------------------------------- #
# Non-empty CVE identifiers so serialized findings always carry a meaningful id.
_cve_ids = st.text(min_size=1, max_size=30)

# CVSS scores across the documented 0.0-10.0 range.
_cvss_scores = st.floats(min_value=0.0, max_value=10.0)


@st.composite
def _findings(draw) -> FindingInput:
    """Generate an arbitrary CVE finding to persist.

    Exercises both NVD-sourced findings (no package identifier) and
    OSV-sourced findings (with a package identifier) so serialization is
    covered for both shapes.
    """
    severity = draw(st.sampled_from(list(Severity)))
    source = draw(st.sampled_from(["nvd", "osv"]))
    # An unscored finding is one with no score -- that is what the band means
    # (Req 2.7). Drawing a score for it would generate a row the scanner can
    # never produce and would leave the null path untested.
    cvss_score = None if severity is Severity.UNSCORED else draw(_cvss_scores)
    package_identifier = (
        draw(st.text(min_size=1, max_size=40)) if source == "osv" else None
    )
    return FindingInput(
        cve_id=draw(_cve_ids),
        cvss_score=cvss_score,
        severity=severity,
        source=source,
        package_identifier=package_identifier,
    )


def _make_session() -> Session:
    """Create a fresh in-memory SQLite session with all tables created."""
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine)


def _add_machine(session: Session, machine_id: str) -> None:
    session.add(
        TargetMachine(
            id=machine_id,
            hostname=f"{machine_id}.example.com",
            platform=Platform.LINUX,
            last_scan_status=ScanStatus.SUCCESS,
            last_scanned_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            sync_status=SyncStatus.PENDING_SYNC,
        )
    )
    session.flush()


def _assert_serialized_finding_complete(finding: dict) -> None:
    """Assert a serialized finding carries id, severity, and CVSS score."""
    assert isinstance(finding.get("cve_id"), str) and finding["cve_id"], (
        "serialized finding must include a non-empty cve_id"
    )
    assert finding.get("severity") in _VALID_SEVERITIES, (
        "serialized finding must include a valid severity"
    )
    # A score is numeric, or explicitly null for an unscored finding -- and the
    # key is always present either way, so a client is never left to read an
    # absent score as a zero (Req 2.7, 10.11).
    assert "cvss_score" in finding, "serialized finding must include cvss_score"
    if finding["severity"] == Severity.UNSCORED.value:
        assert finding["cvss_score"] is None, (
            "an unscored finding must serialize a null score, not a number"
        )
    else:
        assert isinstance(finding["cvss_score"], (int, float)), (
            "a scored finding must serialize a numeric cvss_score"
        )


@settings()
@given(
    findings_per_machine=st.lists(
        st.lists(_findings(), min_size=0, max_size=6),
        min_size=1,
        max_size=4,
    )
)
def test_api_serialization_completeness(findings_per_machine):
    """Every finding serialized by the API carries id, severity, and score.

    Feature: cvedeck
    Property 8: Finding rendering and serialization completeness
    Validates: Requirements 3.5, 6.2
    """
    session = _make_session()
    try:
        repo = Repository(session)
        machine_ids: list[str] = []
        for index, findings in enumerate(findings_per_machine):
            machine_id = f"m{index}"
            machine_ids.append(machine_id)
            _add_machine(session, machine_id)
            repo.save_findings(machine_id, findings)
        session.commit()

        app = override_auth(create_app())
        app.dependency_overrides[get_session] = lambda: session
        client = TestClient(app)

        # Per-machine CVE endpoint (Req 6.2).
        for machine_id in machine_ids:
            resp = client.get(f"/api/machines/{machine_id}/cves")
            assert resp.status_code == 200
            for finding in resp.json():
                _assert_serialized_finding_complete(finding)

        # All-CVEs endpoint: every serialized finding must be complete too.
        resp = client.get("/api/cves")
        assert resp.status_code == 200
        serialized = resp.json()
        for finding in serialized:
            _assert_serialized_finding_complete(finding)

        # Sanity: the total serialized findings match what was seeded, so the
        # completeness assertions actually cover every stored finding.
        expected_total = sum(len(f) for f in findings_per_machine)
        assert len(serialized) == expected_total
    finally:
        session.close()
