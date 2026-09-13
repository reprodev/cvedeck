"""Smoke test for the absence of automated remediation triggers (task 6.3).

Requirement 4.5 states: "THE CVE_Scanner_System SHALL perform remediation
actions only when initiated manually by an administrator." The design reinforces
this for the RemediationService: "Remediation is only ever invoked through these
explicit administrator-initiated calls; there is no scheduler or automated
trigger."

This module is a focused smoke test, not a property test. It verifies two things
without touching the service implementation:

1. Constructing a ``RemediationService`` performs no writes — no remediation
   records exist after construction, i.e. instantiation triggers no automatic
   activity. State only changes when ``add``/``update`` are explicitly called.
2. The remediation module/service defines no scheduler, thread, timer, or other
   background trigger hook. Every callable attribute the service exposes is one
   of the explicit administrator-initiated operations.
"""

import inspect

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.data.repository import Repository
from app.data.schema import Base, RemediationRecord
from app.enums import RemediationStatus
from app.services import remediation as remediation_module
from app.services.remediation import RemediationService


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


def _count_remediation_records(session: Session) -> int:
    return session.query(RemediationRecord).count()


def test_construction_performs_no_writes(session, repo):
    """Instantiating the service must not create any remediation records.

    If the service started a scheduler/background task, constructing it (and
    letting control return) could produce remediation activity. We assert the
    store is untouched by construction alone (Req 4.5).
    """
    assert _count_remediation_records(session) == 0

    RemediationService(repo)
    session.commit()

    # No automatic activity: construction wrote nothing.
    assert _count_remediation_records(session) == 0


def test_state_changes_only_via_explicit_add(session, repo):
    """A remediation record appears only after an explicit ``add`` call (Req 4.5)."""
    service = RemediationService(repo)

    # Before any explicit call, nothing exists.
    assert _count_remediation_records(session) == 0

    machine_id = "m1"
    # Add via the explicit administrator-initiated call.
    from datetime import datetime, timezone

    from app.data.schema import TargetMachine
    from app.enums import Platform, ScanStatus, SyncStatus

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

    service.add(machine_id, "CVE-2024-0001", RemediationStatus.OPEN, "triage")
    session.commit()

    # Exactly one record — the one we explicitly added, nothing more.
    assert _count_remediation_records(session) == 1


def test_service_exposes_only_explicit_operations():
    """The service's public callables are only the explicit admin operations.

    No scheduler/thread/timer/background-trigger method is exposed. This guards
    against an automated trigger being added to the service surface (Req 4.5).
    """
    public_callables = {
        name
        for name, member in inspect.getmembers(RemediationService, callable)
        if not name.startswith("_")
    }
    assert public_callables == {"add", "update"}

    forbidden_fragments = (
        "schedule",
        "scheduler",
        "thread",
        "timer",
        "interval",
        "cron",
        "poll",
        "background",
        "start",
        "run_forever",
        "loop",
    )
    for name in public_callables:
        lowered = name.lower()
        for fragment in forbidden_fragments:
            assert fragment not in lowered, (
                f"RemediationService exposes {name!r}, which looks like an "
                f"automated trigger (contains {fragment!r})"
            )


def test_module_defines_no_scheduler_or_timer_hooks():
    """The remediation module imports/defines no scheduler/timer/thread machinery.

    Req 4.5 forbids any automated trigger. We check the module namespace for
    references to common scheduling/background primitives (threading.Timer,
    sched, asyncio loops, APScheduler, etc.).
    """
    forbidden_symbols = (
        "threading",
        "Timer",
        "sched",
        "asyncio",
        "APScheduler",
        "BackgroundScheduler",
        "Thread",
        "schedule",
        "Celery",
        "celery",
    )
    module_symbols = set(vars(remediation_module).keys())
    leaked = module_symbols.intersection(forbidden_symbols)
    assert not leaked, (
        f"remediation module references scheduler/background symbols: {sorted(leaked)}"
    )

    # Also inspect the source text for any timer/scheduler wiring.
    source = inspect.getsource(remediation_module)
    for symbol in ("threading.Timer", "asyncio.get_event_loop", "sched.scheduler"):
        assert symbol not in source, (
            f"remediation module source wires up {symbol!r}"
        )
