"""Property-based tests for remediation persistence (task 6.2).

Feature: cvedeck
Property 9: Remediation persistence reflects last write
Validates: Requirements 4.1, 4.3

For any remediation record and any subsequent sequence of updates to it, reading
the record back from the Local_Database reflects the most recently written status
and note.
"""

from datetime import datetime, timezone

from hypothesis import given, strategies as st
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.data.repository import Repository
from app.data.schema import Base, TargetMachine
from app.enums import Platform, RemediationStatus, ScanStatus, SyncStatus
from app.services.remediation import RemediationService

# --------------------------------------------------------------------------- #
# Hypothesis strategies
# --------------------------------------------------------------------------- #
_statuses = st.sampled_from(list(RemediationStatus))
# Notes are free-text (Req 4.2); exercise empty and arbitrary content.
_notes = st.text(max_size=80)
# A (status, note) pair representing one write to a remediation record.
_writes = st.tuples(_statuses, _notes)


def _make_machine(session: Session, machine_id: str = "m1") -> None:
    """Create the referenced Target_Machine row the record associates with."""
    session.add(
        TargetMachine(
            id=machine_id,
            hostname="host.example.com",
            platform=Platform.LINUX,
            last_scan_status=ScanStatus.SUCCESS,
            last_scanned_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
            sync_status=SyncStatus.PENDING_SYNC,
        )
    )
    session.flush()


# --------------------------------------------------------------------------- #
# Property 9: Remediation persistence reflects last write
# --------------------------------------------------------------------------- #
@given(
    initial=_writes,
    updates=st.lists(_writes, max_size=8),
)
def test_property_9_remediation_persistence_reflects_last_write(initial, updates):
    """Property 9 (Requirements 4.1, 4.3): after an add followed by an arbitrary
    sequence of updates, reading the record back reflects the last written
    status and note.

    A fresh in-memory SQLite engine and machine row are created per example so
    each case is isolated.
    """
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    try:
        with Session(engine) as session:
            _make_machine(session)
            service = RemediationService(Repository(session))
            repo = Repository(session)

            initial_status, initial_note = initial
            record = service.add(
                "m1", "CVE-2024-0001", initial_status, initial_note
            )
            session.commit()

            # Track the most recently written state locally to compare against.
            expected_status, expected_note = initial_status, initial_note
            for status, note in updates:
                service.update(record.id, status, note)
                session.commit()
                expected_status, expected_note = status, note

            # Read the record back from the Local_Database and confirm it
            # reflects the most recent write.
            loaded = repo.get_remediation(record.id)
            assert loaded is not None
            assert loaded.status == expected_status
            assert loaded.note == expected_note
    finally:
        engine.dispose()
