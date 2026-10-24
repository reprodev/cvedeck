"""Cancelling a scan job (Req 19.7-19.9).

Same harness as ``test_scan_jobs.py``: a database file with a session per
request, and scans parked mid-collection on a gate, so "cancel while a host is
being scanned" is a fact of the test rather than a race it hopes to win.
"""

from __future__ import annotations

import threading
import time

from sqlalchemy.orm import Session

from app.data.repository import Repository
from app.data.schema import ScanJob, TargetMachine as TargetMachineRow
from app.enums import Platform, ScanJobStatus, ScanStatus
from app.models import Credentials, TargetMachine
from app.services import scan_jobs
from tests.test_scan_jobs import (  # noqa: F401 -- fixtures are used by name
    _SENTINEL,
    _body,
    _job,
    _wait_for,
    build_engine,
    client,
    collector,
    db,
    worker,
)
from tests.test_write_concurrency import _Gate


def _ended(client, job_id):
    return _wait_for(lambda: (j := _job(client, job_id))["status"] not in ("queued", "running") and j)


def _record_collections(collector) -> list[str]:
    """The hosts the collector is asked for -- the ones actually scanned."""
    asked: list[str] = []
    collect = collector.collect

    def recording(target, credentials):
        asked.append(target.id)
        return collect(target, credentials)

    collector.collect = recording
    return asked


def test_a_queued_job_cancelled_never_runs_and_drops_its_credentials(client, worker, collector, db):
    """Validates Req 19.7: cancelled at once, never started, credentials gone."""
    asked = _record_collections(collector)
    gate = _Gate()
    collector.gates["m1"] = gate
    running = client.post("/api/scans/jobs", json=_body("m1")).json()["job_id"]
    gate.wait_reached()
    try:
        queued = client.post("/api/scans/jobs", json=_body("m2", password=_SENTINEL)).json()["job_id"]
        assert _job(client, queued)["cancellable"] is True

        response = client.post(f"/api/scans/jobs/{queued}/cancel")

        assert response.status_code == 202
        job = response.json()
        assert job["status"] == "cancelled"
        assert job["cancellable"] is False and job["cancel_requested"] is False
        assert [t["state"] for t in job["targets"]] == ["cancelled"]
        assert job["targets"][0]["outcome"] is None
        assert "before it started" in job["error_detail"]
        assert queued not in scan_jobs._credentials
    finally:
        gate.release.set()

    assert _ended(client, running)["status"] == "finished"
    time.sleep(0.2)  # the worker reaches the cancelled job's id in its queue
    job = _job(client, queued)
    assert job["status"] == "cancelled" and job["started_at"] is None
    assert asked == ["m1"]
    with open(db.url.database, "rb") as handle:
        assert _SENTINEL.encode() not in handle.read()


def test_a_running_job_finishes_its_host_and_cancels_the_rest(client, worker, collector, db):
    """Validates Req 19.8: the host in progress is recorded; the others are untouched."""
    # m2 is known from an earlier scan; its record must survive the cancelled job.
    with Session(db) as session:
        Repository(session).upsert_target_machine("m2", "m2.lan", Platform.LINUX, ScanStatus.AUTH_FAILURE)
        session.get(TargetMachineRow, "m2").last_scan_server_key = True
        session.commit()
    asked = _record_collections(collector)

    gate = _Gate()
    collector.gates["m1"] = gate
    job_id = client.post("/api/scans/jobs", json=_body("m1", "m2", "m3")).json()["job_id"]
    gate.wait_reached()
    try:
        response = client.post(f"/api/scans/jobs/{job_id}/cancel")
        assert response.status_code == 202
        assert response.json()["status"] == "running"
        assert response.json()["cancel_requested"] is True
        assert _job(client, job_id)["cancel_requested"] is True
    finally:
        gate.release.set()

    job = _ended(client, job_id)
    assert job["status"] == "cancelled"
    assert job["cancel_requested"] is False and job["cancellable"] is False
    states = [(t["machine_id"], t["state"]) for t in job["targets"]]
    assert states == [("m1", "done"), ("m2", "cancelled"), ("m3", "cancelled")]
    assert job["targets"][0]["outcome"]["status"] == "success"
    assert [t["outcome"] for t in job["targets"][1:]] == [None, None]
    assert job["error_detail"].endswith("after 1 of 3 hosts.")

    assert asked == ["m1"]
    with Session(db) as session:
        m2 = session.get(TargetMachineRow, "m2")
        assert m2.last_scan_status is ScanStatus.AUTH_FAILURE
        assert m2.last_scan_server_key is True  # not rewritten from this job's password
        assert session.get(TargetMachineRow, "m3") is None


def test_a_job_the_old_endpoint_waits_on_cannot_be_cancelled(client, worker, collector):
    """Validates Req 19.9: POST /api/scans keeps its contract; its job refuses a cancel."""
    gate = _Gate()
    collector.gates["m1"] = gate
    running = client.post("/api/scans/jobs", json=_body("m1")).json()["job_id"]
    gate.wait_reached()

    box: dict = {}
    waiting = threading.Thread(target=lambda: box.setdefault("r", client.post("/api/scans", json=_body("m2"))))
    waiting.start()
    try:
        handed = _wait_for(lambda: [j for j in client.get("/api/scans/jobs").json() if j["id"] != running])[0]
        assert handed["cancellable"] is False

        response = client.post(f"/api/scans/jobs/{handed['id']}/cancel")

        assert response.status_code == 409
        assert "POST /api/scans" in response.json()["detail"]
    finally:
        gate.release.set()
    waiting.join(10)

    assert box["r"].status_code == 200
    assert box["r"].json()["machine_scans"][0]["status"] == "success"


def test_an_ended_job_cannot_be_cancelled(client, worker):
    """Validates Req 19.9: nothing to stop."""
    job_id = client.post("/api/scans/jobs", json=_body("m1")).json()["job_id"]
    _ended(client, job_id)

    response = client.post(f"/api/scans/jobs/{job_id}/cancel")

    assert response.status_code == 409
    assert "already ended" in response.json()["detail"]
    assert _job(client, job_id)["status"] == "finished"


def test_cancelling_an_unknown_job_is_a_404(client):
    assert client.post("/api/scans/jobs/nope/cancel").status_code == 404


def test_a_cancel_is_audit_logged(client, worker, collector, caplog):
    """Validates Req 16.19 for the new write: who stopped which scan."""
    gate = _Gate()
    collector.gates["m1"] = gate
    job_id = client.post("/api/scans/jobs", json=_body("m1")).json()["job_id"]
    gate.wait_reached()
    try:
        with caplog.at_level("INFO", logger="app.security"):
            client.post(f"/api/scans/jobs/{job_id}/cancel")
    finally:
        gate.release.set()
    assert any("Cancel scan" in r.getMessage() and job_id in r.getMessage() for r in caplog.records)


# --- Who owns a queued job: settled by its credentials -----------------------


def _queued_job(session) -> ScanJob:
    return scan_jobs.create_job(
        session,
        targets=[TargetMachine(id="m1", hostname="m1.lan", platform=Platform.LINUX)],
        credentials_by_id={"m1": Credentials(username="u", password="p")},
        unresolved=[],
        requested_by="test",
    )


class _HookLock:
    """The real lock, running a hook once just after the next release."""

    def __init__(self, inner) -> None:
        self._inner = inner
        self.after_release = None

    def __enter__(self):
        return self._inner.__enter__()

    def __exit__(self, *exc):
        result = self._inner.__exit__(*exc)
        hook, self.after_release = self.after_release, None
        if hook is not None:
            hook()
        return result


def test_a_cancel_arriving_as_the_job_starts_stops_it_before_any_host(db, build_engine, collector, monkeypatch):
    """Validates Req 19.7, 19.8: run_job took the credentials, so the job is running.

    The cancel lands in the one window where the database still says QUEUED
    but the job is already the worker's. It must become a cooperative stop --
    cancelled before its first host -- never a job the worker then runs in full
    or one marked interrupted.
    """
    lock = _HookLock(scan_jobs._credentials_lock)
    with Session(db) as session:
        job = _queued_job(session)
        job_id = job.id
    monkeypatch.setattr(scan_jobs, "_credentials_lock", lock)

    def cancel_now():
        with Session(db) as other:
            assert other.get(ScanJob, job_id).status is ScanJobStatus.QUEUED
            scan_jobs.cancel_job(other, job_id, by="tester")

    lock.after_release = cancel_now  # right after run_job pops the credentials
    with Session(db) as session:
        done = scan_jobs.run_job(session, job_id, build_engine(session))

        assert done.status is ScanJobStatus.CANCELLED
        assert done.error_detail == "Cancelled by tester after 0 of 1 hosts."
        assert [t.state.value for t in done.targets] == ["cancelled"]
    assert job_id not in scan_jobs._cancel_requested


def test_a_job_cancelled_before_the_worker_reaches_it_stays_cancelled(db, build_engine):
    """Validates Req 19.7: the worker finds it ended and leaves it alone."""
    with Session(db) as session:
        job_id = _queued_job(session).id
        scan_jobs.cancel_job(session, job_id, by="tester")
    with Session(db) as session:
        done = scan_jobs.run_job(session, job_id, build_engine(session))
        assert done.status is ScanJobStatus.CANCELLED
        assert done.started_at is None


def test_the_worker_never_marks_interrupted_a_job_being_cancelled(db, build_engine):
    """Validates Req 19.7: the canceller holds the credentials but has not yet committed.

    The worker finds no credentials. Without the cancel mark it would record
    the job as interrupted, and the canceller's commit would race that write.
    """
    with Session(db) as session:
        job_id = _queued_job(session).id
    with scan_jobs._credentials_lock:  # what cancel_job does under the lock
        scan_jobs._cancel_requested[job_id] = "tester"
        scan_jobs._credentials.pop(job_id)
    try:
        with Session(db) as session:
            scan_jobs.run_job(session, job_id, build_engine(session))
        with Session(db) as session:
            assert session.get(ScanJob, job_id).status is ScanJobStatus.QUEUED
    finally:
        scan_jobs._cancel_requested.clear()


def test_a_restart_forgets_cancels_and_waiting_requests(db):
    """Validates Req 19.4: nothing in memory outlives the process's jobs."""
    scan_jobs._cancel_requested["a"] = "x"
    scan_jobs._handoffs.add("b")
    with Session(db) as session:
        scan_jobs.interrupt_unfinished(session)
    assert scan_jobs._cancel_requested == {} and scan_jobs._handoffs == set()
