"""Scheduled scans (Req 20): when a slot is due, what runs, and which hosts.

Feature: cvedeck, Property 19 -- the schedule runs each daily slot at most
once, and never misses one while the process is up to see it.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from pathlib import Path

import pytest
from hypothesis import given
from hypothesis import strategies as st
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.data.repository import Repository
from app.data.schema import Base, ScanJob, ScanSchedule, TargetMachine as TargetMachineRow
from app.enums import Platform, ScanJobStatus, ScanStatus
from app.models import Credentials, TargetMachine
from app.scanner.engine import MachineScan, ScanResult
from app.services import scan_jobs, scan_schedule
from app.services.scan_schedule import latest_slot, next_due

BASE = datetime(2026, 3, 1, 12, 0)


# --------------------------------------------------------------------------- #
# Property 19: next_due
# --------------------------------------------------------------------------- #
@given(
    time_of_day=st.sampled_from(["00:00", "03:00", "12:00", "12:01", "23:59"]),
    gaps=st.lists(st.integers(min_value=1, max_value=36 * 60), min_size=1, max_size=40),
)
def test_each_slot_runs_once_and_none_is_missed(time_of_day, gaps):
    """Property 19, simulated: a ticker that runs whatever ``next_due`` says.

    Every slot the ticker was up to see -- a tick at or after the slot and
    before the next one -- runs exactly once; nothing before the schedule was
    armed runs; and a slot the process slept through entirely is not run late,
    because a newer slot replaced it.
    """
    ticks, now = [], BASE
    for minutes in gaps:
        now += timedelta(minutes=minutes)
        ticks.append(now)

    since, runs = BASE, []
    for tick in ticks:
        slot = next_due(tick, time_of_day, since)
        if slot is not None:
            assert slot <= tick
            runs.append(slot)
            since = tick

    expected = {latest_slot(t, time_of_day) for t in ticks} - {
        s for s in {latest_slot(t, time_of_day) for t in ticks} if s <= BASE
    }
    assert len(runs) == len(set(runs))
    assert set(runs) == expected


def test_switching_on_after_todays_slot_does_not_scan_at_once():
    """Validates Req 20.1: armed at 10:00 for 03:00 waits for tomorrow."""
    armed = datetime(2026, 3, 1, 10, 0)
    assert next_due(datetime(2026, 3, 1, 10, 1), "03:00", armed) is None
    assert next_due(datetime(2026, 3, 2, 3, 0), "03:00", armed) == datetime(2026, 3, 2, 3, 0)


def test_a_slot_missed_while_down_runs_once_when_back():
    """Validates Req 20.4: down at 03:00, up at 07:00 -- one run, at 07:00."""
    last_run = datetime(2026, 3, 1, 3, 0, 5)
    back = datetime(2026, 3, 2, 7, 0)
    assert next_due(back, "03:00", last_run) == datetime(2026, 3, 2, 3, 0)
    assert next_due(back + timedelta(minutes=1), "03:00", back) is None


def test_a_day_slept_through_is_not_caught_up_twice():
    """Validates Req 20.4: down for three days, one run on return -- not three."""
    last_run = datetime(2026, 3, 1, 3, 0)
    back = datetime(2026, 3, 4, 9, 0)
    assert next_due(back, "03:00", last_run) == datetime(2026, 3, 4, 3, 0)


@pytest.mark.parametrize("bad", ["3:00", "24:00", "12:60", "noon", ""])
def test_a_time_that_is_not_hh_mm_is_refused(bad):
    with pytest.raises(ValueError):
        scan_schedule.parse_time_of_day(bad)


# --------------------------------------------------------------------------- #
# The ticker and the eligible hosts, on a database file
# --------------------------------------------------------------------------- #
@pytest.fixture()
def db(tmp_path):
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'cvedeck.db').as_posix()}",
        connect_args={"check_same_thread": False},
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()
    scan_jobs._credentials.clear()


@pytest.fixture()
def key(monkeypatch, tmp_path):
    """A server-managed key and user, as a deployment configures them."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    path = tmp_path / "id_ed25519"
    path.write_bytes(
        Ed25519PrivateKey.generate().private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.OpenSSH,
            serialization.NoEncryption(),
        )
    )
    monkeypatch.setenv("CVEDECK_DEFAULT_SSH_KEY_PATH", str(path))
    monkeypatch.setenv("CVEDECK_DEFAULT_SSH_USER", "scanner")
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)
    submitted: list[str] = []
    monkeypatch.setattr(scan_jobs, "submit", submitted.append)
    return submitted


def _host(session, machine_id, *, server_key, platform=Platform.LINUX):
    Repository(session).upsert_target_machine(machine_id, f"{machine_id}.lan", platform, ScanStatus.SUCCESS)
    session.get(TargetMachineRow, machine_id).last_scan_server_key = server_key
    session.commit()


def _arm(session, at: datetime, time_of_day="03:00"):
    row = scan_schedule.get_schedule(session)
    row.enabled, row.time_of_day = True, time_of_day
    row.armed_at = at.astimezone()  # stored as an aware moment, as update() does
    session.commit()


def test_a_due_slot_scans_exactly_the_hosts_the_key_reached(db, key):
    """Validates Req 20.3, 20.6: one job, from the schedule, of the key hosts only."""
    with Session(db) as session:
        _host(session, "k1", server_key=True)
        _host(session, "k2", server_key=True)
        _host(session, "pw", server_key=False)
        _host(session, "new", server_key=None)
        _host(session, "win", server_key=True, platform=Platform.WINDOWS)
        _arm(session, datetime(2026, 3, 1, 12, 0))

        note = scan_schedule.tick(session, now=datetime(2026, 3, 2, 3, 0, 30))

        (job,) = session.query(ScanJob).all()
        assert job.requested_by == "schedule"
        assert sorted(t.machine_id for t in job.targets) == ["k1", "k2"]
        assert all(t.server_key for t in job.targets)
        assert key == [job.id]
        assert "2 host" in note
        # The same slot, a minute later: already handled.
        assert scan_schedule.tick(session, now=datetime(2026, 3, 2, 3, 1, 30)) is None
        assert session.query(ScanJob).count() == 1


@pytest.mark.parametrize(
    "why, setup",
    [
        ("demo mode", lambda mp, s: mp.setenv("CVEDECK_DEMO_MODE", "true")),
        ("no server-managed ssh key", lambda mp, s: mp.delenv("CVEDECK_DEFAULT_SSH_KEY_PATH")),
        ("no hosts yet", lambda mp, s: None),
        ("still running", lambda mp, s: _running_scheduled_job(s)),
    ],
)
def test_a_slot_that_cannot_run_is_skipped_once_with_the_reason(db, key, monkeypatch, why, setup):
    """Validates Req 20.5: recorded, not retried every minute, nothing queued."""
    with Session(db) as session:
        if why != "no hosts yet":
            _host(session, "k1", server_key=True)
        _arm(session, datetime(2026, 3, 1, 12, 0))
        setup(monkeypatch, session)
        before = session.query(ScanJob).count()

        note = scan_schedule.tick(session, now=datetime(2026, 3, 2, 3, 0, 30))

        assert why in note.lower()
        assert session.query(ScanJob).count() == before
        assert scan_schedule.get_schedule(session).last_note == note
        assert scan_schedule.tick(session, now=datetime(2026, 3, 2, 3, 1, 30)) is None


def _running_scheduled_job(session):
    scan_jobs.create_job(
        session,
        targets=[TargetMachine(id="k1", hostname="k1.lan", platform=Platform.LINUX)],
        credentials_by_id={"k1": Credentials(username="u", password="p")},
        unresolved=[],
        requested_by="schedule",
    )


def test_a_disabled_schedule_does_nothing(db, key):
    """Validates Req 20.1: off by default, and off means off."""
    with Session(db) as session:
        _host(session, "k1", server_key=True)
        assert scan_schedule.get_schedule(session).enabled is False
        assert scan_schedule.tick(session, now=datetime(2026, 3, 2, 3, 0, 30)) is None
        assert session.query(ScanJob).count() == 0


# --------------------------------------------------------------------------- #
# Which hosts the key reached: set by a successful scan, kept by a failed one
# --------------------------------------------------------------------------- #
class _Engine:
    """Reports a fixed outcome per host, through the progress hooks."""

    def __init__(self, outcomes: dict[str, ScanStatus]) -> None:
        self._outcomes = outcomes
        self.on_target_start = self.on_target_done = None

    def set_credentials(self, credentials):
        pass

    def scan(self, targets):
        scans = []
        for target in targets:
            scan = MachineScan(machine_id=target.id, status=self._outcomes[target.id])
            self.on_target_done(target, scan)
            scans.append(scan)
        return ScanResult(machine_scans=scans)


@pytest.mark.parametrize(
    "used_key, outcome, before, after",
    [
        (True, ScanStatus.SUCCESS, None, True),
        (False, ScanStatus.SUCCESS, True, False),
        (True, ScanStatus.AUTH_FAILURE, None, None),
        (False, ScanStatus.CONNECTION_FAILURE, True, True),
    ],
)
def test_a_successful_scan_records_whether_the_key_reached_the_host(db, used_key, outcome, before, after):
    """Validates Req 20.3: success sets it either way; failure leaves it alone."""
    with Session(db) as session:
        _host(session, "m1", server_key=before)
        job = scan_jobs.create_job(
            session,
            targets=[TargetMachine(id="m1", hostname="m1.lan", platform=Platform.LINUX)],
            credentials_by_id={"m1": Credentials(username="u", password="p")},
            unresolved=[],
            requested_by="test",
            server_key_ids={"m1"} if used_key else set(),
        )
        scan_jobs.run_job(session, job.id, _Engine({"m1": outcome}))

        session.expire_all()
        assert session.get(TargetMachineRow, "m1").last_scan_server_key is after
        assert session.get(ScanJob, job.id).status is ScanJobStatus.FINISHED


# --------------------------------------------------------------------------- #
# The API
# --------------------------------------------------------------------------- #
@pytest.fixture()
def client(db):
    from fastapi.testclient import TestClient

    from app.api.app import create_app
    from app.api.dependencies import get_session
    from tests.auth_helpers import override_auth

    app = override_auth(create_app())

    def session_per_request():
        with Session(db) as session:
            yield session

    app.dependency_overrides[get_session] = session_per_request
    return TestClient(app)


_SCHEDULE_KEYS = {
    "enabled", "time_of_day", "timezone", "next_run_at", "last_run_at", "last_job_id",
    "last_note", "eligible_hosts", "server_key_configured",
}


def test_the_schedule_starts_off_and_says_so(client, key):
    """Validates Req 20.1, 20.2: off by default, at 03:00, with nothing next."""
    body = client.get("/api/scan-schedule").json()

    assert set(body) == _SCHEDULE_KEYS
    assert body["enabled"] is False and body["time_of_day"] == "03:00"
    assert body["next_run_at"] is None
    assert body["server_key_configured"] is True


def test_switching_it_on_sets_the_time_and_the_next_run(client, key, db):
    """Validates Req 20.2: set from the dashboard, no restart."""
    with Session(db) as session:
        _host(session, "k1", server_key=True)

    response = client.put("/api/scan-schedule", json={"enabled": True, "time_of_day": "04:30"})

    assert response.status_code == 200
    body = response.json()
    assert body["enabled"] is True and body["time_of_day"] == "04:30"
    assert body["next_run_at"] is not None
    assert body["eligible_hosts"] == 1


def test_switching_it_on_without_a_server_key_is_refused(client, monkeypatch):
    """Validates Req 20.3: it could never run, so it is not allowed to look on."""
    monkeypatch.delenv("CVEDECK_DEFAULT_SSH_KEY_PATH", raising=False)
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)

    response = client.put("/api/scan-schedule", json={"enabled": True, "time_of_day": "03:00"})

    assert response.status_code == 409
    assert "server-managed SSH key" in response.json()["detail"]
    assert client.get("/api/scan-schedule").json()["enabled"] is False


@pytest.mark.parametrize("bad", ["3:00", "25:00", "03:00:00", "soon"])
def test_a_time_that_is_not_hh_mm_is_a_422(client, key, bad):
    assert client.put("/api/scan-schedule", json={"enabled": False, "time_of_day": bad}).status_code == 422


def test_a_failing_check_does_not_stop_the_ticker(monkeypatch):
    """A bad minute -- the database busy, say -- must not end scheduled scanning."""
    import asyncio

    calls: list[int] = []

    def flaky(engine):
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database is locked")

    async def no_sleep(seconds):
        return None

    monkeypatch.setattr(scan_schedule, "_tick_once", flaky)
    asyncio.run(scan_schedule.run_schedule(object(), sleep=no_sleep, iterations=3))

    assert len(calls) == 3
