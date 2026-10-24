"""Background scan jobs (Req 19), and POST /api/scans unchanged on top of them.

These run against a database *file* with a session per request, because the
point is what happens when a second request arrives while a scan is running --
and two requests cannot share the single in-memory session most suites use.
Scans are parked mid-collection on a gate, so "while a scan runs" is a fact of
the test, not a race it hopes to win.
"""

from __future__ import annotations

import threading
import time

import pytest
from fastapi import Depends
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api.app import create_app
from app.api.dependencies import get_scanner_engine, get_session
from app.data.repository import Repository
from app.data.schema import Base, ScanJob
from app.enums import Platform, ScanJobStatus, ScanStatus, Severity
from app.models import Credentials, Inventory, OsInfo, Package, TargetMachine
from app.scanner.engine import ScannerEngine
from app.scanner.matcher import Finding, MatchResult, SourceStatus
from app.services import scan_jobs
from tests.auth_helpers import override_auth
from tests.test_write_concurrency import _Gate

_SENTINEL = "never-written-sentinel-7f3a9c"


class _Collector:
    """Returns a small inventory; parks at a gate the test sets for a host."""

    def __init__(self) -> None:
        self.gates: dict[str, _Gate] = {}

    def collect(self, target, credentials):
        gate = self.gates.pop(target.id, None)
        if gate is not None:
            gate.park()
        return Inventory(
            machine_id=target.id,
            os_info=OsInfo(name="Debian", version="12"),
            packages=[Package(name="openssl", version="3.0.2", ecosystem="Debian:12")],
        )


class _Matcher:
    def match(self, inventory, nvd, osv):
        return MatchResult(
            machine_id=inventory.machine_id,
            findings=[
                Finding(
                    machine_id=inventory.machine_id,
                    cve_id="CVE-2024-0001",
                    cvss_score=7.5,
                    severity=Severity.HIGH,
                    source="osv",
                    package_identifier="Debian:12:openssl@3.0.2",
                )
            ],
            nvd_status=SourceStatus.OK,
            osv_status=SourceStatus.OK,
        )


@pytest.fixture()
def db(tmp_path):
    engine = create_engine(
        f"sqlite:///{(tmp_path / 'cvedeck.db').as_posix()}",
        connect_args={"check_same_thread": False, "timeout": 5.0},
    )
    Base.metadata.create_all(engine)
    yield engine
    engine.dispose()


@pytest.fixture()
def collector():
    return _Collector()


@pytest.fixture()
def build_engine(collector):
    def build(session: Session) -> ScannerEngine:
        return ScannerEngine(
            Repository(session),
            lambda target: Credentials(username="u", password="p"),
            matcher=_Matcher(),
            osv=object(),
            collector_factory=lambda platform: collector,
        )

    return build


@pytest.fixture()
def worker(db, build_engine):
    started = scan_jobs.start_worker(lambda: Session(db), build_engine)
    yield started
    scan_jobs.stop_worker()


@pytest.fixture()
def client(db, build_engine, monkeypatch):
    monkeypatch.delenv("CVEDECK_DEMO_MODE", raising=False)
    app = override_auth(create_app())

    def session_per_request():
        with Session(db) as session:
            yield session

    def engine_for_request(session: Session = Depends(get_session)) -> ScannerEngine:
        return build_engine(session)

    app.dependency_overrides[get_session] = session_per_request
    app.dependency_overrides[get_scanner_engine] = engine_for_request
    return TestClient(app, raise_server_exceptions=False)


def _body(*machine_ids: str, password: str = "secret") -> dict:
    return {
        "targets": [
            {"id": m, "hostname": f"{m}.lan", "platform": "linux", "username": "root", "password": password}
            for m in machine_ids
        ]
    }


def _wait_for(predicate, timeout: float = 10.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = predicate()
        if value:
            return value
        time.sleep(0.02)
    raise AssertionError("condition not reached")


def _job(client, job_id):
    response = client.get(f"/api/scans/jobs/{job_id}")
    assert response.status_code == 200
    return response.json()


def _finished(client, job_id):
    return _wait_for(lambda: (j := _job(client, job_id))["status"] == "finished" and j)


def test_a_job_reports_progress_host_by_host(client, worker, collector):
    """Validates Req 19.1, 19.2: queued at once, then each host's state and outcome."""
    gate = _Gate()
    collector.gates["m2"] = gate

    response = client.post("/api/scans/jobs", json=_body("m1", "m2"))
    assert response.status_code == 202
    job_id = response.json()["job_id"]

    gate.wait_reached()
    try:
        job = _job(client, job_id)
        assert job["status"] == "running"
        first, second = job["targets"]
        assert first["state"] == "done" and first["outcome"]["status"] == "success"
        assert first["outcome"]["finding_count"] == 1
        assert second["state"] == "running" and second["outcome"] is None
    finally:
        gate.release.set()

    job = _finished(client, job_id)
    assert [t["outcome"]["status"] for t in job["targets"]] == ["success", "success"]
    assert job["started_at"] and job["finished_at"]


def test_jobs_run_one_at_a_time_and_in_order(client, worker, collector):
    """Validates Req 19.1: a second job waits, untouched, until the first is done."""
    gate = _Gate()
    collector.gates["m1"] = gate
    first = client.post("/api/scans/jobs", json=_body("m1")).json()["job_id"]
    gate.wait_reached()
    try:
        second = client.post("/api/scans/jobs", json=_body("m2")).json()["job_id"]
        time.sleep(0.2)
        queued = _job(client, second)
        assert queued["status"] == "queued"
        assert [t["state"] for t in queued["targets"]] == ["queued"]
    finally:
        gate.release.set()

    a, b = _finished(client, first), _finished(client, second)
    assert b["started_at"] >= a["finished_at"]


def test_the_old_scan_endpoint_waits_its_turn_and_answers_as_before(client, worker, collector):
    """Validates Req 19.5 and 13.9: same request, same response, no overlap.

    Before 0.11.0 a second scan of a host being scanned was refused with 409;
    now it waits behind the running scan and then answers exactly as it always
    has. The keys are pinned, so a script reading them keeps working.
    """
    gate = _Gate()
    collector.gates["m1"] = gate
    running = client.post("/api/scans/jobs", json=_body("m1")).json()["job_id"]
    gate.wait_reached()

    box: dict = {}
    waiting = threading.Thread(target=lambda: box.setdefault("r", client.post("/api/scans", json=_body("m1"))))
    waiting.start()
    time.sleep(0.3)
    try:
        assert waiting.is_alive(), "the old endpoint should wait behind the running scan"
    finally:
        gate.release.set()
    waiting.join(10)

    response = box["r"]
    assert response.status_code == 200
    (outcome,) = response.json()["machine_scans"]
    assert set(response.json()) == {"machine_scans"}
    assert set(outcome) == {
        "machine_id", "status", "finding_count", "sources_ok", "unavailable_sources",
        "message", "new_count", "resolved_count", "baseline",
    }
    assert outcome["machine_id"] == "m1" and outcome["status"] == "success"
    assert _job(client, running)["status"] == "finished"
    # It ran as a job too, so the dashboard can see it.
    assert len(client.get("/api/scans/jobs").json()) == 2


def test_the_old_endpoint_never_overtakes_a_job_queued_before_it(client, worker, collector):
    """Validates Req 19.1 across both routes: oldest first.

    Found by the 0.11.0 container run. The old endpoint ran its job itself and
    merely competed for the scan slot, so it overtook a dashboard job that had
    been waiting longer. It now takes its place in the worker's queue.
    """
    gate = _Gate()
    collector.gates["m1"] = gate
    running = client.post("/api/scans/jobs", json=_body("m1")).json()["job_id"]
    gate.wait_reached()
    queued = client.post("/api/scans/jobs", json=_body("m2")).json()["job_id"]

    box: dict = {}
    waiting = threading.Thread(target=lambda: box.setdefault("r", client.post("/api/scans", json=_body("m3"))))
    waiting.start()
    time.sleep(0.3)
    gate.release.set()
    waiting.join(10)

    assert box["r"].status_code == 200
    _finished(client, running)
    earlier = _finished(client, queued)
    (latest,) = [j for j in client.get("/api/scans/jobs").json() if j["id"] not in (running, queued)]
    assert latest["started_at"] >= earlier["finished_at"]


def test_the_old_endpoint_still_lists_credential_failures_first(client):
    """Validates Req 19.5: a target whose credentials cannot be worked out is
    an AUTH_FAILURE at the head of the response, as it always was."""
    body = _body("m1", "m2")
    body["targets"][1].pop("password")  # m2: no password, no key, no server key

    response = client.post("/api/scans", json=body)

    statuses = [(s["machine_id"], s["status"]) for s in response.json()["machine_scans"]]
    assert statuses == [("m2", "auth_failure"), ("m1", "success")]


def test_credentials_are_never_written_to_the_database(client, worker, db):
    """Validates Req 19.3: not in a row, not in the file."""
    job_id = client.post("/api/scans/jobs", json=_body("m1", password=_SENTINEL)).json()["job_id"]
    _finished(client, job_id)
    db.dispose()

    assert _SENTINEL.encode() not in (db.url.database and open(db.url.database, "rb").read())
    assert job_id not in scan_jobs._credentials


def test_a_restart_marks_unfinished_jobs_interrupted(client, db):
    """Validates Req 19.4: a job whose credentials died with the process says so."""
    with Session(db) as session:
        job = scan_jobs.create_job(
            session,
            targets=[TargetMachine(id="m1", hostname="m1.lan", platform=Platform.LINUX)],
            credentials_by_id={"m1": Credentials(username="u", password="p")},
            unresolved=[],
            requested_by="test",
        )
        job_id = job.id
        assert scan_jobs.interrupt_unfinished(session) == 1

    shown = _job(client, job_id)
    assert shown["status"] == "interrupted"
    assert shown["error_detail"] == scan_jobs.INTERRUPTED_DETAIL
    assert job_id not in scan_jobs._credentials
    assert client.get("/api/scans/jobs?active=true").json() == []


def test_a_scan_that_crashes_marks_its_job_and_frees_the_slot(client, db):
    """Validates Req 19.1: a crashed scan never holds up the next one."""

    class _Exploding:
        on_target_start = on_target_done = None

        def set_credentials(self, credentials):
            pass

        def scan(self, targets):
            raise RuntimeError("engine defect")

    client.app.dependency_overrides[get_scanner_engine] = lambda: _Exploding()
    assert client.post("/api/scans", json=_body("m1")).status_code == 500
    assert not scan_jobs._scan_slot.locked()

    (job,) = client.get("/api/scans/jobs").json()
    assert job["status"] == "interrupted"
    assert "engine defect" in job["error_detail"]


def test_an_unknown_job_is_a_404(client):
    assert client.get("/api/scans/jobs/nope").status_code == 404


def test_the_job_route_refuses_windows_like_the_scan_route(client):
    body = _body("w1")
    body["targets"][0]["platform"] = "windows"
    assert client.post("/api/scans/jobs", json=body).status_code == 422


def test_old_jobs_are_pruned_but_never_an_active_one(db):
    """Validates Req 19.2: history is bounded, the queue is not.

    The newest ``MAX_JOBS`` are kept, and an active job older than all of them
    is kept as well: pruning a queued scan would silently drop it.
    """
    target = TargetMachine(id="m1", hostname="m1.lan", platform=Platform.LINUX)
    with Session(db) as session:
        active = scan_jobs.create_job(
            session, targets=[target], credentials_by_id={"m1": Credentials(username="u", password="p")},
            unresolved=[], requested_by="test",
        )
        for _ in range(scan_jobs.MAX_JOBS + 5):
            scan_jobs.create_job(
                session, targets=[], credentials_by_id={}, unresolved=[(target, "no credentials")],
                requested_by="test",
            )
        active_id = active.id
        assert session.query(ScanJob).count() == scan_jobs.MAX_JOBS + 1
        assert session.get(ScanJob, active_id).status is ScanJobStatus.QUEUED
    scan_jobs._credentials.clear()


def test_the_job_list_takes_a_limit_up_to_every_job_kept(client, db):
    """Validates Req 19.10: Scan history asks for all 100; the default stays 20."""
    with Session(db) as session:
        for i in range(25):
            job = scan_jobs.create_job(
                session,
                targets=[],
                credentials_by_id={},
                unresolved=[],
                requested_by=f"user{i}",
            )
            job.created_at = job.created_at.replace(year=2020, minute=i)
        session.commit()

    assert len(client.get("/api/scans/jobs").json()) == 20
    listed = client.get("/api/scans/jobs?limit=100").json()
    assert len(listed) == 25
    assert [j["requested_by"] for j in listed[:2]] == ["user24", "user23"]
    for bad in (0, scan_jobs.MAX_JOBS + 1):
        assert client.get(f"/api/scans/jobs?limit={bad}").status_code == 422
