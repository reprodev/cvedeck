"""Property-based tests for durable synchronization convergence.

Feature: cvedeck
Property 10: Durable synchronization convergence with field preservation
Validates: Requirements 5.2, 5.3, 5.4, 7.3

For any set of local writes, if the Online_Database is unreachable then those
items SHALL remain in the Local_Database marked PENDING_SYNC; and once the
Online_Database becomes reachable and synchronization runs, the Online_Database
SHALL converge to the Local_Database with no items left pending, preserving
each finding's package identifier and dependency-path association.

The Local_Database and Online_Database are modeled as two independent in-memory
SQLite engines sharing the identical schema. An "unreachable" online store is a
session factory that raises on connect (Req 5.3); a reachable one is a real
sessionmaker bound to the second engine (Req 5.2, 5.4).
"""

from datetime import datetime, timezone

from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.data.schema import (
    Base,
    CveFinding,
    DependencyPath,
    TargetMachine,
)
from app.enums import Platform, ScanStatus, Severity, SyncStatus
from app.services.sync import SyncService

# ---------------------------------------------------------------------------
# Strategies
# ---------------------------------------------------------------------------

# Printable text that SQLite text columns round-trip cleanly (no surrogates /
# control characters).
_text = st.text(
    alphabet=st.characters(
        min_codepoint=32, max_codepoint=0x10FFFF, blacklist_categories=("Cs",)
    ),
    min_size=1,
    max_size=40,
)
_optional_text = st.one_of(st.none(), _text)
_severity = st.sampled_from(list(Severity))
_platform = st.sampled_from(list(Platform))
_scan_status = st.sampled_from(list(ScanStatus))
_cvss = st.floats(min_value=0.0, max_value=10.0, allow_nan=False, allow_infinity=False)


@st.composite
def local_writes(draw):
    """An arbitrary, non-empty set of local writes to synchronize.

    Produces a batch of machines, each with an arbitrary number of dependency
    paths and findings. Every finding links to one of its machine's dependency
    paths and carries an arbitrary package_identifier, so the association whose
    preservation Property 10 asserts is always present. All rows are written
    locally as PENDING_SYNC (the state ``enqueue`` produces, Req 5.2).
    """
    machine_count = draw(st.integers(min_value=1, max_value=4))
    machines = []
    for mi in range(machine_count):
        machine_id = f"m{mi}"
        dep_count = draw(st.integers(min_value=1, max_value=3))
        deps = []
        for di in range(dep_count):
            deps.append(
                {
                    "id": f"{machine_id}_dp{di}",
                    "package_identifier": draw(_optional_text),
                    "path_expression": draw(_optional_text),
                }
            )

        finding_count = draw(st.integers(min_value=1, max_value=4))
        findings = []
        for fi in range(finding_count):
            dep = draw(st.sampled_from(deps))
            findings.append(
                {
                    "id": f"{machine_id}_f{fi}",
                    "cve_id": draw(_text),
                    "cvss_score": draw(_cvss),
                    "severity": draw(_severity),
                    "source": draw(st.sampled_from(["nvd", "osv"])),
                    "package_identifier": draw(_optional_text),
                    "dependency_path_id": dep["id"],
                }
            )

        machines.append(
            {
                "id": machine_id,
                "hostname": draw(_text),
                "platform": draw(_platform),
                "last_scan_status": draw(_scan_status),
                "deps": deps,
                "findings": findings,
            }
        )
    return machines


def _unreachable_factory():
    """Factory simulating an unreachable Online_Database (raises on connect)."""
    raise ConnectionError("online database unreachable")


def _seed_local(session: Session, machines) -> None:
    """Persist the generated write set to the Local_Database as PENDING_SYNC."""
    now = datetime(2024, 1, 1, tzinfo=timezone.utc)
    for m in machines:
        session.add(
            TargetMachine(
                id=m["id"],
                hostname=m["hostname"],
                platform=m["platform"],
                last_scan_status=m["last_scan_status"],
                last_scanned_at=now,
                sync_status=SyncStatus.PENDING_SYNC,
            )
        )
        for dep in m["deps"]:
            session.add(
                DependencyPath(
                    id=dep["id"],
                    machine_id=m["id"],
                    package_identifier=dep["package_identifier"],
                    path_expression=dep["path_expression"],
                    parent_path_id=None,
                    sync_status=SyncStatus.PENDING_SYNC,
                )
            )
        for f in m["findings"]:
            session.add(
                CveFinding(
                    id=f["id"],
                    machine_id=m["id"],
                    cve_id=f["cve_id"],
                    cvss_score=f["cvss_score"],
                    severity=f["severity"],
                    source=f["source"],
                    package_identifier=f["package_identifier"],
                    dependency_path_id=f["dependency_path_id"],
                    sync_status=SyncStatus.PENDING_SYNC,
                )
            )
    session.commit()


# ---------------------------------------------------------------------------
# Property 10
# ---------------------------------------------------------------------------


@given(machines=local_writes())
def test_property_10_durable_sync_convergence(machines):
    """Property 10 (Requirements 5.2, 5.3, 5.4, 7.3).

    Phase 1: with an unreachable Online_Database, every local row stays
    PENDING_SYNC and nothing reaches the online store (Req 5.2, 5.3).
    Phase 2: once the Online_Database is reachable, sync converges it to the
    Local_Database with nothing left pending locally (Req 5.4), preserving each
    finding's package_identifier and dependency_path_id (Req 7.3).
    """
    # Two independent in-memory databases with the identical schema.
    local_engine = create_engine("sqlite:///:memory:")
    online_engine = create_engine(
        "sqlite:///:memory:", connect_args={"check_same_thread": False}
    )
    Base.metadata.create_all(local_engine)
    Base.metadata.create_all(online_engine)

    expected_findings = {
        f["id"]: (f["package_identifier"], f["dependency_path_id"])
        for m in machines
        for f in m["findings"]
    }

    with Session(local_engine) as local:
        _seed_local(local, machines)

        # --- Phase 1: Online_Database unreachable (Req 5.3) ---------------- #
        report = SyncService(local, _unreachable_factory).sync()

        assert report.online_reachable is False
        assert report.total_propagated == 0
        assert report.total_pending > 0

        # Every local row remains PENDING_SYNC.
        for model in (TargetMachine, DependencyPath, CveFinding):
            rows = local.execute(select(model)).scalars().all()
            assert rows
            assert all(r.sync_status == SyncStatus.PENDING_SYNC for r in rows)

        # Nothing was written to the Online_Database.
        with Session(online_engine) as online:
            for model in (TargetMachine, DependencyPath, CveFinding):
                assert online.execute(select(model)).scalars().all() == []

        # --- Phase 2: Online_Database reachable -> converge (Req 5.2, 5.4) - #
        reachable_factory = sessionmaker(bind=online_engine)
        report = SyncService(local, reachable_factory).sync()

        assert report.online_reachable is True
        assert report.total_pending == 0
        assert report.total_propagated > 0

        # Nothing left pending locally; every row is SYNCED.
        for model in (TargetMachine, DependencyPath, CveFinding):
            rows = local.execute(select(model)).scalars().all()
            assert all(r.sync_status == SyncStatus.SYNCED for r in rows)

    # Online converged to local, preserving associations (Req 5.4, 7.3).
    with Session(online_engine) as online:
        for m in machines:
            assert online.get(TargetMachine, m["id"]) is not None
            for dep in m["deps"]:
                assert online.get(DependencyPath, dep["id"]) is not None

        online_findings = online.execute(select(CveFinding)).scalars().all()
        assert {f.id for f in online_findings} == set(expected_findings)
        for f in online_findings:
            exp_pkg, exp_dep = expected_findings[f.id]
            assert f.package_identifier == exp_pkg
            assert f.dependency_path_id == exp_dep
            assert f.sync_status == SyncStatus.SYNCED
