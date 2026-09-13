"""Unit tests for the synchronization service (task 6.4).

These verify the Local_Database -> Online_Database propagation using two
independent in-memory SQLite engines (local + online) sharing the identical
schema. They cover: pending retention when the Online_Database is unreachable
(Req 5.3), convergence once it becomes reachable again (Req 5.2, 5.4), and
preservation of a finding's package identifier and dependency-path association
across the sync (Req 7.3).
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session, sessionmaker

from app.data.schema import (
    Base,
    CveFinding,
    DependencyPath,
    Inventory,
    Package,
    RemediationRecord,
    TargetMachine,
)
from app.enums import (
    Platform,
    RemediationStatus,
    ScanStatus,
    Severity,
    SyncStatus,
)
from app.services.sync import SyncService


@pytest.fixture()
def local_session():
    """In-memory SQLite session for the Local_Database."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


@pytest.fixture()
def online_engine():
    """In-memory SQLite engine for the Online_Database (identical schema)."""
    # A single shared connection keeps the in-memory DB alive across the
    # per-sync sessions produced by the reachable factory.
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    return engine


@pytest.fixture()
def reachable_factory(online_engine):
    """Factory producing a session bound to the reachable Online_Database."""
    maker = sessionmaker(bind=online_engine)
    return maker


def _unreachable_factory():
    """Factory simulating an unreachable Online_Database (raises on connect)."""
    raise ConnectionError("online database unreachable")


# --------------------------------------------------------------------------- #
# Fixture builders
# --------------------------------------------------------------------------- #
def _seed_machine(session: Session, machine_id: str = "m1") -> TargetMachine:
    machine = TargetMachine(
        id=machine_id,
        hostname="host.example.com",
        platform=Platform.LINUX,
        last_scan_status=ScanStatus.SUCCESS,
        last_scanned_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        sync_status=SyncStatus.PENDING_SYNC,
    )
    session.add(machine)
    session.flush()
    return machine


def _seed_finding_with_association(session: Session) -> tuple[str, str]:
    """Create a machine, dependency path, and a finding linking them.

    Returns (finding_id, dependency_path_id).
    """
    _seed_machine(session)
    dep = DependencyPath(
        id="dp1",
        machine_id="m1",
        package_identifier="PyPI:requests",
        path_expression="app -> requests",
        parent_path_id=None,
        sync_status=SyncStatus.PENDING_SYNC,
    )
    session.add(dep)
    session.flush()
    finding = CveFinding(
        id="f1",
        machine_id="m1",
        cve_id="CVE-2024-0001",
        cvss_score=9.1,
        severity=Severity.CRITICAL,
        source="osv",
        package_identifier="PyPI:requests@2.31.0",
        dependency_path_id="dp1",
        sync_status=SyncStatus.PENDING_SYNC,
    )
    session.add(finding)
    session.flush()
    session.commit()
    return finding.id, dep.id


# --------------------------------------------------------------------------- #
# enqueue
# --------------------------------------------------------------------------- #
def test_enqueue_marks_entity_pending(local_session, reachable_factory):
    machine = TargetMachine(
        id="m9",
        hostname="h",
        platform=Platform.WINDOWS,
        last_scan_status=ScanStatus.SUCCESS,
        last_scanned_at=None,
        sync_status=SyncStatus.SYNCED,
    )
    service = SyncService(local_session, reachable_factory)

    service.enqueue(machine)

    assert machine.sync_status == SyncStatus.PENDING_SYNC


# --------------------------------------------------------------------------- #
# Unreachable online DB -> retain locally, stay PENDING_SYNC (Req 5.3)
# --------------------------------------------------------------------------- #
def test_unreachable_online_retains_pending(local_session):
    _seed_finding_with_association(local_session)
    service = SyncService(local_session, _unreachable_factory)

    report = service.sync()

    assert report.online_reachable is False
    assert report.total_propagated == 0
    assert report.total_pending > 0
    # All local rows remain PENDING_SYNC.
    for model in (TargetMachine, DependencyPath, CveFinding):
        rows = local_session.execute(select(model)).scalars().all()
        assert rows
        assert all(r.sync_status == SyncStatus.PENDING_SYNC for r in rows)


def test_unreachable_online_writes_nothing_online(
    local_session, reachable_factory, online_engine
):
    _seed_finding_with_association(local_session)
    service = SyncService(local_session, _unreachable_factory)

    service.sync()

    with Session(online_engine) as online:
        assert online.execute(select(CveFinding)).scalars().all() == []
        assert online.execute(select(TargetMachine)).scalars().all() == []


# --------------------------------------------------------------------------- #
# Reachable online DB -> convergence, nothing pending (Req 5.2, 5.4)
# --------------------------------------------------------------------------- #
def test_successful_sync_marks_local_synced(local_session, reachable_factory):
    _seed_finding_with_association(local_session)
    service = SyncService(local_session, reachable_factory)

    report = service.sync()

    assert report.online_reachable is True
    assert report.total_pending == 0
    assert report.total_propagated > 0
    for model in (TargetMachine, DependencyPath, CveFinding):
        rows = local_session.execute(select(model)).scalars().all()
        assert all(r.sync_status == SyncStatus.SYNCED for r in rows)


def test_successful_sync_converges_online_to_local(
    local_session, reachable_factory, online_engine
):
    finding_id, dep_id = _seed_finding_with_association(local_session)
    service = SyncService(local_session, reachable_factory)

    service.sync()

    with Session(online_engine) as online:
        machine = online.get(TargetMachine, "m1")
        assert machine is not None and machine.sync_status == SyncStatus.SYNCED
        finding = online.get(CveFinding, finding_id)
        assert finding is not None and finding.sync_status == SyncStatus.SYNCED
        dep = online.get(DependencyPath, dep_id)
        assert dep is not None and dep.sync_status == SyncStatus.SYNCED


def test_convergence_after_reconnect(
    local_session, reachable_factory, online_engine
):
    """Unreachable first (retained), reachable next (propagated) — Req 5.4."""
    finding_id, _ = _seed_finding_with_association(local_session)
    service = SyncService(local_session, _unreachable_factory)
    first = service.sync()
    assert first.online_reachable is False
    assert first.total_pending > 0

    # Reconnect: same local rows, now a reachable online store.
    service = SyncService(local_session, reachable_factory)
    second = service.sync()

    assert second.online_reachable is True
    assert second.total_pending == 0
    with Session(online_engine) as online:
        assert online.get(CveFinding, finding_id) is not None


# --------------------------------------------------------------------------- #
# Field preservation across sync (Req 7.3)
# --------------------------------------------------------------------------- #
def test_sync_preserves_package_identifier_and_dependency_path(
    local_session, reachable_factory, online_engine
):
    finding_id, dep_id = _seed_finding_with_association(local_session)
    service = SyncService(local_session, reachable_factory)

    service.sync()

    with Session(online_engine) as online:
        finding = online.get(CveFinding, finding_id)
        assert finding is not None
        assert finding.package_identifier == "PyPI:requests@2.31.0"
        assert finding.dependency_path_id == dep_id
        # The linked dependency path itself round-trips too.
        dep = online.get(DependencyPath, dep_id)
        assert dep is not None
        assert dep.package_identifier == "PyPI:requests"
        assert dep.path_expression == "app -> requests"


# --------------------------------------------------------------------------- #
# Inventory + child packages ride along with the parent
# --------------------------------------------------------------------------- #
def test_sync_propagates_inventory_and_packages(
    local_session, reachable_factory, online_engine
):
    _seed_machine(local_session)
    inv = Inventory(
        id="inv1",
        machine_id="m1",
        os_name="Ubuntu",
        os_version="22.04",
        collected_at=datetime(2024, 3, 1, tzinfo=timezone.utc),
        sync_status=SyncStatus.PENDING_SYNC,
    )
    inv.packages.append(
        Package(id="pkg1", name="openssl", version="3.0.2", ecosystem=None)
    )
    inv.packages.append(
        Package(id="pkg2", name="requests", version="2.31.0", ecosystem="PyPI")
    )
    local_session.add(inv)
    local_session.commit()

    SyncService(local_session, reachable_factory).sync()

    with Session(online_engine) as online:
        online_inv = online.get(Inventory, "inv1")
        assert online_inv is not None
        assert online_inv.sync_status == SyncStatus.SYNCED
        pkgs = {(p.name, p.version, p.ecosystem) for p in online_inv.packages}
        assert pkgs == {
            ("openssl", "3.0.2", None),
            ("requests", "2.31.0", "PyPI"),
        }


# --------------------------------------------------------------------------- #
# Idempotent re-sync: already-synced rows are not re-propagated
# --------------------------------------------------------------------------- #
def test_second_sync_has_nothing_pending(local_session, reachable_factory):
    _seed_finding_with_association(local_session)
    service = SyncService(local_session, reachable_factory)
    service.sync()

    report = service.sync()

    assert report.total_propagated == 0
    assert report.total_pending == 0


def test_update_after_sync_repropagates(
    local_session, reachable_factory, online_engine
):
    """A row re-marked PENDING_SYNC after a sync is propagated again (upsert)."""
    finding_id, _ = _seed_finding_with_association(local_session)
    service = SyncService(local_session, reachable_factory)
    service.sync()

    rec = RemediationRecord(
        id="r1",
        machine_id="m1",
        cve_id="CVE-2024-0001",
        status=RemediationStatus.OPEN,
        note="triage",
        updated_at=datetime(2024, 4, 1, tzinfo=timezone.utc),
        sync_status=SyncStatus.PENDING_SYNC,
    )
    local_session.add(rec)
    local_session.commit()
    service.sync()

    # Mutate + re-enqueue, then sync: online should reflect the last write.
    rec.note = "patched"
    service.enqueue(rec)
    service.sync()

    with Session(online_engine) as online:
        online_rec = online.get(RemediationRecord, "r1")
        assert online_rec is not None
        assert online_rec.note == "patched"
        assert online_rec.sync_status == SyncStatus.SYNCED
