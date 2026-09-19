"""Tests for the deployment wiring (``app/api/wiring.py``).

This module had no tests. Every suite that touches a scan overrides
``get_scanner_engine``/``get_sync_service`` specifically to avoid it, so the code
that actually runs in the container -- the host-key race tie-break, the machine
upsert on rename or re-platform, the scan-status write -- was exercised only by
hand.

The host-key branch is the subtle one. Two first connections to the same new
address race, both read no pin, both write, and one loses. The loser has already
completed a handshake, so the only question that matters is whether the two saw
the same key: the same key is the race and is fine, a different key is a host
that changed under us and must be refused (Req 17.2, 17.9).
"""

from __future__ import annotations

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.wiring import DeploymentScannerEngine, RepositoryHostKeyStore
from app.data.repository import Repository
from app.data.schema import Base, TargetMachine as TargetMachineRow
from app.enums import Platform, ScanStatus, SyncStatus
from app.models import TargetMachine
from app.scanner.engine import MachineScan
from app.scanner.exceptions import AuthError, HostKeyMismatchError
from app.scanner.host_keys import PinnedHostKey


@pytest.fixture()
def session():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s


def _key(base64: str = "AAAAB3NzaC1hostA", fingerprint: str = "fp-A") -> PinnedHostKey:
    return PinnedHostKey(
        key_type="ssh-ed25519", key_base64=base64, fingerprint_sha256=fingerprint
    )


# --- RepositoryHostKeyStore --------------------------------------------------


def test_pin_then_get_round_trips(session):
    store = RepositoryHostKeyStore(Repository(session), session)

    store.pin("host.example", 22, _key())
    session.commit()

    pinned = store.get("host.example", 22)
    assert pinned is not None
    assert pinned.key_base64 == "AAAAB3NzaC1hostA"
    assert pinned.fingerprint_sha256 == "fp-A"
    assert pinned.key_type == "ssh-ed25519"


def test_get_returns_none_for_an_unpinned_address(session):
    store = RepositoryHostKeyStore(Repository(session), session)
    assert store.get("never.seen", 22) is None


def test_a_port_is_part_of_the_identity(session):
    """The same hostname on two ports is two hosts."""
    store = RepositoryHostKeyStore(Repository(session), session)
    store.pin("host.example", 22, _key("keyA", "fp-A"))
    session.commit()

    assert store.get("host.example", 2222) is None
    assert store.get("host.example", 22) is not None


def test_pinning_the_same_key_twice_is_the_race_and_is_accepted(session):
    """The loser of a first-connection race saw the same host. Accept it.

    Raising here would fail a scan that did nothing wrong, on a host whose key
    is exactly what we already trust (Req 17.9).
    """
    store = RepositoryHostKeyStore(Repository(session), session)
    store.pin("host.example", 22, _key())
    session.commit()

    store.pin("host.example", 22, _key())  # must not raise
    session.commit()

    assert store.get("host.example", 22).key_base64 == "AAAAB3NzaC1hostA"


def test_pinning_a_different_key_is_refused_as_a_mismatch(session):
    """A different key on an already-pinned address is a changed host."""
    store = RepositoryHostKeyStore(Repository(session), session)
    store.pin("host.example", 22, _key("keyA", "fp-A"))
    session.commit()

    with pytest.raises(HostKeyMismatchError) as excinfo:
        store.pin("host.example", 22, _key("keyB", "fp-B"))

    # Both fingerprints are reported, so the operator can compare them.
    message = str(excinfo.value)
    assert "fp-A" in message and "fp-B" in message


def test_the_session_survives_a_refused_pin(session):
    """The savepoint is load-bearing, not decorative.

    A failed flush poisons the surrounding transaction. Without the nested
    begin, the request's own commit would fail afterwards and the caller would
    see a server error by an unrelated route instead of the mismatch.
    """
    store = RepositoryHostKeyStore(Repository(session), session)
    store.pin("host.example", 22, _key("keyA", "fp-A"))
    session.commit()

    with pytest.raises(HostKeyMismatchError):
        store.pin("host.example", 22, _key("keyB", "fp-B"))

    # The session is still usable: this is what the savepoint buys.
    session.add(
        TargetMachineRow(
            id="m-after",
            hostname="after.example",
            platform=Platform.LINUX,
            last_scan_status=ScanStatus.NEVER_SCANNED,
            sync_status=SyncStatus.PENDING_SYNC,
        )
    )
    session.commit()
    assert session.get(TargetMachineRow, "m-after") is not None


def test_touch_does_not_change_the_pinned_key(session):
    store = RepositoryHostKeyStore(Repository(session), session)
    store.pin("host.example", 22, _key())
    session.commit()

    store.touch("host.example", 22)
    session.commit()

    assert store.get("host.example", 22).key_base64 == "AAAAB3NzaC1hostA"


# --- DeploymentScannerEngine._upsert_machine / _record_scan_status ------------


def _engine(session: Session) -> DeploymentScannerEngine:
    """An engine bound to this session.

    Only the persistence half is under test here -- the upsert and the status
    write -- and the scanning half has its own suite, so no host is ever
    contacted. Constructing the real clients touches no network.
    """
    return DeploymentScannerEngine(session)


def _target(machine_id="m1", hostname="host-01", platform=Platform.LINUX):
    return TargetMachine(id=machine_id, hostname=hostname, platform=platform)


def test_upsert_creates_a_never_scanned_row(session):
    """A freshly enrolled host is NEVER_SCANNED, not a connection failure.

    This is what stops the fleet view showing a red badge for a host nothing has
    tried to reach yet.
    """
    engine = _engine(session)

    row = engine._upsert_machine(_target())
    session.commit()

    assert row.last_scan_status is ScanStatus.NEVER_SCANNED
    assert row.sync_status is SyncStatus.PENDING_SYNC
    assert row.hostname == "host-01"


def test_upsert_records_a_rename_and_a_replatform(session):
    """A machine may be renamed or re-platformed between scans."""
    engine = _engine(session)
    engine._upsert_machine(_target())
    session.commit()

    row = engine._upsert_machine(
        _target(hostname="renamed-01", platform=Platform.WINDOWS)
    )
    session.commit()

    assert row.id == "m1"
    assert row.hostname == "renamed-01"
    assert row.platform is Platform.WINDOWS
    # Only one row: an upsert, not an insert.
    assert session.query(TargetMachineRow).count() == 1


def test_upsert_does_not_reset_a_scanned_host_to_never_scanned(session):
    """The provisional status is for new rows only.

    Resetting it on a rescan would erase the previous outcome for the window
    between the upsert and the status write.
    """
    engine = _engine(session)
    engine._upsert_machine(_target())
    session.commit()
    row = session.get(TargetMachineRow, "m1")
    row.last_scan_status = ScanStatus.SUCCESS
    session.commit()

    engine._upsert_machine(_target(hostname="host-01b"))
    session.commit()

    assert session.get(TargetMachineRow, "m1").last_scan_status is ScanStatus.SUCCESS


@pytest.mark.parametrize("sources_ok", [True, False])
def test_record_scan_status_keeps_source_health(session, sources_ok):
    """``last_scan_sources_ok`` is what separates 'few findings' from 'partial'.

    Without it a scan that ran against an unreachable advisory source is indexed
    as a clean host.
    """
    engine = _engine(session)
    engine._upsert_machine(_target())
    session.commit()

    engine._record_scan_status(
        _target(),
        MachineScan(
            machine_id="m1",
            status=ScanStatus.SUCCESS,
            # sources_ok is derived: an empty tuple means everything answered.
            unavailable_sources=() if sources_ok else ("osv",),
        ),
    )
    session.commit()

    row = session.get(TargetMachineRow, "m1")
    assert row.last_scan_status is ScanStatus.SUCCESS
    assert row.last_scan_sources_ok is sources_ok
    assert row.last_scanned_at is not None
    assert row.sync_status is SyncStatus.PENDING_SYNC


def test_record_scan_status_keeps_a_failure_and_its_reason(session):
    """Every attempt reaches the history, failures included (Req 18.1, 18.10)."""
    engine = _engine(session)
    engine._upsert_machine(_target())
    session.commit()

    engine._record_scan_status(
        _target(),
        MachineScan(
            machine_id="m1",
            status=ScanStatus.AUTH_FAILURE,
            # message is derived from the originating exception.
            error=AuthError("Authentication failed for scanner@host-01"),
        ),
    )
    session.commit()

    row = session.get(TargetMachineRow, "m1")
    assert row.last_scan_status is ScanStatus.AUTH_FAILURE

    runs = Repository(session).list_scan_runs("m1")
    assert len(runs) == 1
    assert runs[0].status is ScanStatus.AUTH_FAILURE
    assert "Authentication failed" in (runs[0].error_detail or "")
