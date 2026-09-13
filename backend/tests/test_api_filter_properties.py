"""Property-based tests for API severity filtering (task 8.3).

Feature: cvedeck
Property 7: Severity filtering is sound and complete (API side)
Validates: Requirements 3.3, 6.3

For any set of findings and any selected Severity_Level, filtering applied via
the API SHALL return every finding with that severity and no finding with any
other severity. This exercises both severity-filtered read endpoints:

- ``GET /api/cves?severity=`` (all machines, Req 3.3, 6.3)
- ``GET /api/machines/{id}/cves?severity=`` (per machine, Req 6.3)

Findings are generated arbitrarily, seeded through the repository against an
in-memory SQLite session wired into a FastAPI ``TestClient`` via
``dependency_overrides``, then filtered through the live HTTP surface.
"""

from collections import Counter

from hypothesis import given, strategies as st
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from app.api.app import create_app
from app.api.dependencies import get_session
from app.data.repository import FindingInput, Repository
from app.data.schema import Base, TargetMachine
from app.enums import Platform, ScanStatus, Severity, SyncStatus


# --------------------------------------------------------------------------- #
# Hypothesis strategies
# --------------------------------------------------------------------------- #
# A finding, described by the fields the filter endpoints key on: a CVE id and a
# severity. The CVSS score is drawn within its severity band so the persisted
# rows are internally consistent, but filtering keys on the stored severity
# column, not the score.
_severities = st.sampled_from(list(Severity))

_SEVERITY_SCORE_BAND = {
    Severity.CRITICAL: (9.0, 10.0),
    Severity.HIGH: (7.0, 8.9),
    Severity.MEDIUM: (4.0, 6.9),
    Severity.LOW: (0.0, 3.9),
}


@st.composite
def _finding_sets(draw):
    """Generate a list of findings as (cve_id, severity) pairs.

    CVE ids are made unique by index so that filtering can be asserted by exact
    id-set membership. Sizes span empty through moderately large sets.
    """
    severities = draw(st.lists(_severities, min_size=0, max_size=25))
    return [
        (f"CVE-{i:04d}", sev) for i, sev in enumerate(severities)
    ]


def _to_finding_input(cve_id: str, severity: Severity) -> FindingInput:
    low, high = _SEVERITY_SCORE_BAND[severity]
    # Midpoint of the band keeps the stored score consistent with the severity.
    score = round((low + high) / 2, 1)
    return FindingInput(
        cve_id=cve_id,
        cvss_score=score,
        severity=severity,
        source="nvd",
    )


# --------------------------------------------------------------------------- #
# Property 7: Severity filtering is sound and complete (API)
# --------------------------------------------------------------------------- #
@given(findings=_finding_sets(), selected=_severities)
def test_property_7_api_severity_filtering_sound_and_complete(findings, selected):
    """Property 7 (Requirements 3.3, 6.3): for any set of findings and any
    selected severity, the API filter returns exactly the findings of that
    severity - every one (complete) and no other (sound).

    A fresh in-memory SQLite engine, machine, and TestClient are built per
    example so cases are fully isolated.
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as session:
            session.add(
                TargetMachine(
                    id="m1",
                    hostname="host.example.com",
                    platform=Platform.LINUX,
                    last_scan_status=ScanStatus.SUCCESS,
                    last_scanned_at=None,
                    sync_status=SyncStatus.PENDING_SYNC,
                )
            )
            session.flush()

            repo = Repository(session)
            repo.save_findings(
                "m1",
                [_to_finding_input(cve_id, sev) for cve_id, sev in findings],
            )
            session.commit()

            app = create_app()
            app.dependency_overrides[get_session] = lambda: session
            client = TestClient(app)

            # Expected id-set for the selected severity.
            expected_ids = {
                cve_id for cve_id, sev in findings if sev == selected
            }
            # Ids that must NOT appear (belong to other severities).
            other_ids = {
                cve_id for cve_id, sev in findings if sev != selected
            }

            for path in ("/api/cves", "/api/machines/m1/cves"):
                resp = client.get(path, params={"severity": selected.value})
                assert resp.status_code == 200, (path, resp.text)
                returned_ids = {f["cve_id"] for f in resp.json()}

                # Completeness: every finding of the selected severity is present.
                assert expected_ids <= returned_ids, (
                    path,
                    "missing findings of selected severity",
                )
                # Soundness: no finding of any other severity is present, and the
                # response carries only the selected severity.
                assert returned_ids.isdisjoint(other_ids), (
                    path,
                    "returned findings of a non-selected severity",
                )
                assert returned_ids == expected_ids, (path, "exact set mismatch")
                assert all(
                    f["severity"] == selected.value for f in resp.json()
                ), (path, "response contained a non-selected severity value")
    finally:
        engine.dispose()


@given(findings=_finding_sets())
def test_property_7_api_partitions_by_severity(findings):
    """Complement to the per-severity check: the union of all four
    severity-filtered API responses SHALL exactly reproduce the full unfiltered
    set, with each finding appearing under precisely one severity (Req 3.3, 6.3).
    """
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as session:
            session.add(
                TargetMachine(
                    id="m1",
                    hostname="host.example.com",
                    platform=Platform.LINUX,
                    last_scan_status=ScanStatus.SUCCESS,
                    last_scanned_at=None,
                    sync_status=SyncStatus.PENDING_SYNC,
                )
            )
            session.flush()
            repo = Repository(session)
            repo.save_findings(
                "m1",
                [_to_finding_input(cve_id, sev) for cve_id, sev in findings],
            )
            session.commit()

            app = create_app()
            app.dependency_overrides[get_session] = lambda: session
            client = TestClient(app)

            all_ids = {cve_id for cve_id, _ in findings}
            unfiltered = {
                f["cve_id"] for f in client.get("/api/cves").json()
            }
            assert unfiltered == all_ids

            # Partition: filtered subsets are disjoint and cover the whole set.
            seen: Counter = Counter()
            for sev in Severity:
                resp = client.get("/api/cves", params={"severity": sev.value})
                assert resp.status_code == 200
                for f in resp.json():
                    seen[f["cve_id"]] += 1
            # Every finding appears under exactly one severity filter.
            assert set(seen) == all_ids
            assert all(count == 1 for count in seen.values())
    finally:
        engine.dispose()
