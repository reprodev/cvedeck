"""A scan or a feed refresh must not lock every other writer out (Req 13.6-13.8).

SQLite allows one writer at a time, and a write transaction holds that lock
until it commits. Up to 0.10.2 two paths held one open across network I/O: a
scan upserted every target, then contacted every host and advisory source, and
committed once at the end; and a feed refresh wrote KEV, then downloaded EPSS
and each Ubuntu feed, inside one transaction. Anything else that wrote in the
meantime -- a second scan, an enrollment, a remediation note, the periodic
refresh, a signed-in session's touch -- waited out SQLite's busy timeout and
failed as an HTTP 500. In a container it took one enrollment fired three
seconds into a two-host scan.

These tests run against a database *file*, because an in-memory database on a
single shared connection cannot show locking at all. Each one parks the scan or
refresh mid-network-call on an event and checks that a second connection, with
a short busy timeout, can write and commit in the meantime.
"""

from __future__ import annotations

import sqlite3
import threading

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session

from app.api import wiring
from app.api.app import create_app
from app.api.routes import _get_repository
from app.data.repository import Repository
from app.data.schema import Base, TargetMachine as TargetMachineRow
from app.enums import Platform, ScanStatus, Severity, SyncStatus
from app.models import Credentials, Inventory, OsInfo, Package, TargetMachine
from app.scanner.epss_client import EpssRecord
from app.scanner.host_keys import PinnedHostKey
from app.scanner.kev_client import KevRecord
from app.scanner.matcher import Finding, MatchResult, SourceStatus
from app.scanner.ubuntu_kernel_feed import FetchResult
from app.services.enrichment import FeedRefreshService
from tests.auth_helpers import override_auth

#: Long enough that a test never fails on a slow machine while waiting for the
#: other thread to reach its parking point.
_WAIT = 10.0
#: The bystander's busy timeout. Short on purpose: a writer that holds the lock
#: across a parked network call holds it far longer than this.
_BYSTANDER_TIMEOUT = 0.5


@pytest.fixture()
def db_path(tmp_path):
    path = tmp_path / "cvedeck.db"
    engine = create_engine(f"sqlite:///{path.as_posix()}")
    Base.metadata.create_all(engine)
    engine.dispose()
    return path


def _engine(path, timeout: float = 5.0):
    return create_engine(
        f"sqlite:///{path.as_posix()}",
        connect_args={"check_same_thread": False, "timeout": timeout},
    )


_bystanders = iter(range(1_000_000))


def _bystander_write(path) -> str | None:
    """Write and commit from another connection. ``None`` on success, else why not."""
    engine = _engine(path, timeout=_BYSTANDER_TIMEOUT)
    try:
        with Session(engine) as session:
            session.add(
                TargetMachineRow(
                    id=f"bystander-{next(_bystanders)}",
                    hostname="192.0.2.50",
                    platform=Platform.LINUX,
                    last_scan_status=ScanStatus.NEVER_SCANNED,
                    sync_status=SyncStatus.PENDING_SYNC,
                )
            )
            session.commit()
        return None
    except OperationalError as exc:
        return str(exc.orig)
    finally:
        engine.dispose()


class _Gate:
    """A point a worker thread parks at until the test lets it go."""

    def __init__(self) -> None:
        self.reached = threading.Event()
        self.release = threading.Event()

    def park(self) -> None:
        self.reached.set()
        assert self.release.wait(_WAIT), "the test never released the gate"

    def wait_reached(self) -> None:
        assert self.reached.wait(_WAIT), "the worker never reached the gate"


def _run(fn):
    """Run ``fn`` in a thread; return (thread, box) where box holds its result."""
    box: dict = {}

    def target():
        try:
            box["result"] = fn()
        except BaseException as exc:  # surfaced by the test, not swallowed
            box["error"] = exc

    thread = threading.Thread(target=target, daemon=True)
    thread.start()
    return thread, box


def _finish(thread, box):
    thread.join(_WAIT * 3)
    assert not thread.is_alive(), "the worker did not finish"
    if "error" in box:
        raise box["error"]
    return box["result"]


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
class _Collector:
    """Connects the way the SSH collector does -- pin or touch the host key --
    parking before or after it at whatever gate the test set for that target."""

    def __init__(self, store) -> None:
        self._store = store

    gates_before_connect: dict[str, _Gate] = {}
    gates_after_connect: dict[str, _Gate] = {}

    def collect(self, target, credentials):
        gate = self.gates_before_connect.get(target.id)
        if gate is not None:
            gate.park()
        key = PinnedHostKey(
            key_type="ssh-ed25519",
            key_base64=f"AAAAkey-{target.id}",
            fingerprint_sha256=f"fp-{target.id}",
        )
        if self._store.get(target.hostname, 22) is None:
            self._store.pin(target.hostname, 22, key)
        else:
            self._store.touch(target.hostname, 22)
        gate = self.gates_after_connect.get(target.id)
        if gate is not None:
            gate.park()
        return Inventory(
            machine_id=target.id,
            os_info=OsInfo(name="Debian", version="12"),
            packages=[Package(name="openssl", version="3.0.2", ecosystem="Debian:12")],
        )


class _Matcher:
    gates: dict[str, _Gate] = {}

    def match(self, inventory, nvd, osv):
        gate = self.gates.get(inventory.machine_id)
        if gate is not None:
            gate.park()
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
def scanner(monkeypatch, db_path):
    """Build a deployment engine over the file database, in the calling thread."""
    _Collector.gates_before_connect = {}
    _Collector.gates_after_connect = {}
    _Matcher.gates = {}
    monkeypatch.setattr(wiring, "build_collector", lambda platform, store=None: _Collector(store))
    engines = []

    def scan(target_ids, timeout: float = 5.0):
        engine = _engine(db_path, timeout=timeout)
        engines.append(engine)
        with Session(engine) as session:
            built = wiring.DeploymentScannerEngine(session, osv=object(), nvd=None)
            built._matcher = _Matcher()
            built.set_credentials(
                {t: Credentials(username="u", password="p") for t in target_ids}
            )
            return built.scan(
                [TargetMachine(id=t, hostname=f"{t}.lan", platform=Platform.LINUX) for t in target_ids]
            )

    yield scan
    for engine in engines:
        engine.dispose()


@pytest.mark.parametrize("stage", ["connect", "match"])
@pytest.mark.parametrize("first_contact", [True, False])
def test_another_writer_can_commit_while_a_scan_is_out_on_the_network(
    scanner, db_path, stage, first_contact
):
    """Validates Req 13.6: a write made during a scan succeeds.

    Parked just after the SSH connect (host key pinned or touched, nothing
    collected yet) and again inside advisory matching -- the two places 0.10.2
    already held the lock: the upfront upsert, the pin or touch, and
    ``save_inventory`` ahead of the OSV queries.
    """
    if not first_contact:
        scanner(["m1"])  # pins the key, so this scan only touches it

    gate = _Gate()
    if stage == "connect":
        _Collector.gates_after_connect["m1"] = gate
    else:
        _Matcher.gates["m1"] = gate

    thread, box = _run(lambda: scanner(["m1"]))
    gate.wait_reached()
    try:
        assert _bystander_write(db_path) is None
    finally:
        gate.release.set()
    result = _finish(thread, box)

    assert [s.status for s in result.machine_scans] == [ScanStatus.SUCCESS]
    with Session(_engine(db_path)) as session:
        assert len(Repository(session).get_findings_for_machine("m1")) == 1


def test_a_target_whose_results_cannot_be_written_fails_alone(scanner, db_path):
    """Validates Req 13.6 with Property 1: losing the lock costs one target, not the batch.

    Another connection holds the write lock while m1's results are persisted,
    with the scan's busy timeout short enough to give up. m1 is reported as a
    failure naming the lock, the scan carries on, and m2 -- persisted once the
    lock is free -- succeeds. Before 0.10.3 the batch committed once at the end,
    so nothing could be written at all while it ran.
    """
    m1_collected, m2_starting = _Gate(), _Gate()
    _Collector.gates_after_connect["m1"] = m1_collected
    _Collector.gates_before_connect["m2"] = m2_starting

    thread, box = _run(lambda: scanner(["m1", "m2"], timeout=0.2))

    m1_collected.wait_reached()
    holder = sqlite3.connect(str(db_path), timeout=_BYSTANDER_TIMEOUT)
    try:
        holder.execute("BEGIN IMMEDIATE")  # take the write lock
        m1_collected.release.set()
        m2_starting.wait_reached()
    finally:
        holder.rollback()
        holder.close()
    m2_starting.release.set()
    result = _finish(thread, box)

    by_id = {s.machine_id: s for s in result.machine_scans}
    assert by_id["m1"].status is ScanStatus.CONNECTION_FAILURE
    assert "locked" in (by_id["m1"].message or "")
    assert by_id["m2"].status is ScanStatus.SUCCESS
    with Session(_engine(db_path)) as session:
        repo = Repository(session)
        assert repo.get_findings_for_machine("m1") == []
        assert len(repo.get_findings_for_machine("m2")) == 1


# --------------------------------------------------------------------------- #
# Feed refresh
# --------------------------------------------------------------------------- #
class _Source:
    def __init__(self, records=None, error: Exception | None = None, gate: _Gate | None = None):
        self._records = records or []
        self._error = error
        self._gate = gate

    def fetch(self):
        if self._gate is not None:
            self._gate.park()
        if self._error is not None:
            raise self._error
        return self._records


class _UbuntuSource:
    def __init__(self, gate: _Gate) -> None:
        self._gate = gate

    def fetch(self, codename, etag=None):
        self._gate.park()
        return FetchResult(table=None, etag=etag)


_KEV = [KevRecord(cve_id="CVE-2021-44228", due_date="2026-01-01")]
_EPSS = [EpssRecord(cve_id="CVE-2021-44228", score=0.94, percentile=0.99)]


def _refresh(db_path, **sources):
    engine = _engine(db_path)
    try:
        with Session(engine) as session:
            outcomes = FeedRefreshService(Repository(session), **sources).refresh_all()
            session.commit()
            return outcomes
    finally:
        engine.dispose()


@pytest.mark.parametrize("kev", ["ok", "failed", "unchanged"])
def test_another_writer_can_commit_while_a_feed_downloads(db_path, kev):
    """Validates Req 13.7: no write lock is held while a feed downloads.

    KEV is refreshed first and EPSS parks mid-download. Every KEV outcome writes
    something -- the catalogue, a failure record, or the advanced
    ``last_refreshed_at`` of an unchanged one -- and each of those used to take
    the lock and keep it for the length of the EPSS download.
    """
    if kev == "unchanged":
        _refresh(db_path, kev_source=_Source(_KEV))
    kev_source = _Source(error=ConnectionError("cisa.gov unreachable")) if kev == "failed" else _Source(_KEV)
    gate = _Gate()

    thread, box = _run(
        lambda: _refresh(db_path, kev_source=kev_source, epss_source=_Source(_EPSS, gate=gate))
    )
    gate.wait_reached()
    try:
        assert _bystander_write(db_path) is None
    finally:
        gate.release.set()
    outcomes = _finish(thread, box)

    assert [o.ok for o in outcomes] == [kev != "failed", True]
    with Session(_engine(db_path)) as session:
        assert Repository(session).count_epss_scores() == 1


def test_another_writer_can_commit_while_an_ubuntu_feed_downloads(db_path):
    """Validates Req 13.7 for Canonical's feed, fetched after KEV and EPSS are in hand."""
    with Session(_engine(db_path)) as session:
        repo = Repository(session)
        repo.upsert_target_machine("u1", "u1", Platform.LINUX, ScanStatus.SUCCESS)
        repo.save_inventory(
            Inventory(
                machine_id="u1",
                os_info=OsInfo(name="Ubuntu", version="22.04"),
                packages=[Package(name="libc6", version="2.35", ecosystem="Ubuntu:22.04:LTS")],
            )
        )
        session.commit()
    gate = _Gate()

    thread, box = _run(
        lambda: _refresh(
            db_path,
            kev_source=_Source(_KEV),
            epss_source=_Source(_EPSS),
            ubuntu_kernel_source=_UbuntuSource(gate),
        )
    )
    gate.wait_reached()
    try:
        assert _bystander_write(db_path) is None
    finally:
        gate.release.set()
    outcomes = _finish(thread, box)

    assert all(o.ok for o in outcomes)
    assert len(outcomes) == 3


def test_a_failed_download_still_keeps_the_previous_cache(db_path):
    """Moving the writes after the downloads must not loosen "a failed refresh
    never overwrites a good cache": EPSS failing leaves its cache as it was,
    while KEV, which succeeded, is applied."""
    _refresh(db_path, epss_source=_Source(_EPSS))

    outcomes = _refresh(
        db_path,
        kev_source=_Source(_KEV),
        epss_source=_Source(error=ConnectionError("api.first.org unreachable")),
    )

    assert [o.ok for o in outcomes] == [True, False]
    with Session(_engine(db_path)) as session:
        repo = Repository(session)
        assert repo.count_kev_entries() == 1
        assert repo.count_epss_scores() == 1


# --------------------------------------------------------------------------- #
# Whatever contention is left is a 503, never a 500
# --------------------------------------------------------------------------- #
def _app_whose_reads_raise(error: Exception):
    app = override_auth(create_app())

    def broken():
        raise error

    app.dependency_overrides[_get_repository] = broken
    return TestClient(app, raise_server_exceptions=False)


def test_a_locked_database_is_reported_as_busy_not_as_a_server_error():
    """Validates Req 13.8."""
    client = _app_whose_reads_raise(
        OperationalError("INSERT INTO target_machines", {}, sqlite3.OperationalError("database is locked"))
    )

    response = client.get("/api/machines")

    assert response.status_code == 503
    assert response.headers.get("Retry-After")
    assert "busy" in response.json()["detail"]


def test_any_other_database_error_is_still_a_server_error():
    """Only contention is mapped. A missing table is a defect, and reporting it
    as "busy, try again" would send the operator round in circles."""
    client = _app_whose_reads_raise(
        OperationalError("SELECT 1", {}, sqlite3.OperationalError("no such table: target_machines"))
    )

    assert client.get("/api/machines").status_code == 500


def test_the_bystander_check_itself_detects_a_held_lock(db_path):
    """The helper every test above relies on must be able to fail."""
    holder = _engine(db_path)
    with holder.connect() as connection:
        connection.execute(text("BEGIN IMMEDIATE"))
        assert "locked" in (_bystander_write(db_path) or "")
        connection.rollback()
    holder.dispose()
