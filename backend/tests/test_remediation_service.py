"""Unit tests for the RemediationService (task 6.1).

These verify that the administrator-initiated ``add``/``update`` operations
persist a remediation record (status + free-text note) to the Local_Database and
read back correctly (Req 4.1, 4.2, 4.3). The service is only exercised through
its explicit method calls — there is no scheduler/automated trigger (Req 4.5).
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.data.repository import Repository
from app.data.schema import Base, TargetMachine
from app.enums import Platform, RemediationStatus, ScanStatus, SyncStatus
from app.services.remediation import (
    RemediationRecordNotFoundError,
    RemediationService,
)


@pytest.fixture()
def session():
    """In-memory SQLite session with all tables created."""
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as sess:
        yield sess


@pytest.fixture()
def repo(session):
    return Repository(session)


@pytest.fixture()
def service(repo):
    return RemediationService(repo)


def _make_machine(session: Session, machine_id: str = "m1") -> TargetMachine:
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


def test_add_persists_status_and_note(session, repo, service):
    _make_machine(session)

    record = service.add(
        "m1", "CVE-2024-0001", RemediationStatus.OPEN, "initial triage"
    )
    session.commit()

    loaded = repo.get_remediation(record.id)
    assert loaded is not None
    assert loaded.machine_id == "m1"
    assert loaded.cve_id == "CVE-2024-0001"
    assert loaded.status == RemediationStatus.OPEN
    assert loaded.note == "initial triage"
    # Persisted as pending so the sync service can propagate it (Req 5.1).
    assert loaded.sync_status == SyncStatus.PENDING_SYNC


def test_update_persists_new_status_and_note(session, repo, service):
    _make_machine(session)
    record = service.add(
        "m1", "CVE-2024-0001", RemediationStatus.OPEN, "initial triage"
    )
    session.commit()

    updated = service.update(
        record.id, RemediationStatus.REMEDIATED, "patched in 3.0.3"
    )
    session.commit()

    assert updated.id == record.id
    reloaded = repo.get_remediation(record.id)
    assert reloaded is not None
    assert reloaded.status == RemediationStatus.REMEDIATED
    assert reloaded.note == "patched in 3.0.3"


def test_update_missing_record_raises(service):
    with pytest.raises(RemediationRecordNotFoundError) as exc_info:
        service.update("does-not-exist", RemediationStatus.OPEN, "x")
    assert exc_info.value.record_id == "does-not-exist"


def test_add_supports_all_remediation_statuses(session, repo, service):
    _make_machine(session)

    for i, status in enumerate(RemediationStatus):
        record = service.add("m1", f"CVE-2024-{i:04d}", status, f"note {i}")
        session.commit()
        loaded = repo.get_remediation(record.id)
        assert loaded is not None
        assert loaded.status == status
        assert loaded.note == f"note {i}"
