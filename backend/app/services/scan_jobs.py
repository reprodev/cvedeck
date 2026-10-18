"""Background scan jobs: queued, run one at a time, with per-host progress (Req 19).

A scan used to run inside its HTTP request. The dashboard waited up to ten
minutes for one, a deployment needed a 900-second proxy timeout, nothing showed
which host was being scanned, and two scans could only be kept apart by
refusing the second (0.10.4's 409).

Now a scan is a job. It is written down first -- a ``scan_jobs`` row and a row
per host -- and run by whoever holds the process's one **scan slot**: the
worker thread for a job started from the dashboard, or the request itself for
``POST /api/scans``, which keeps its old contract and simply waits its turn
(Req 19.5). One slot means one scan at a time, so two scans of a host cannot
overlap (Req 13.9, 19.1). One process is the right scope: the deployment runs a
single uvicorn worker over SQLite.

Credentials are never written down (Req 19.3). They wait for their job in
``_credentials``, in memory, and are dropped the moment it starts. A job a
restart caught before it finished therefore cannot be resumed, and is marked
``INTERRUPTED`` at startup rather than left reading "running" forever (Req 19.4).
"""

from __future__ import annotations

import logging
import queue
import threading
import uuid
from datetime import datetime, timezone
from typing import Callable

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from ..data.schema import ScanJob, ScanJobTarget, TargetMachine as TargetMachineRow
from ..enums import ScanJobStatus, ScanJobTargetState, ScanStatus
from ..models import Credentials, TargetMachine
from ..scanner.engine import MachineScan, ScannerEngine

_LOGGER = logging.getLogger(__name__)

#: Jobs kept, newest first; older finished ones are pruned when a job is added.
MAX_JOBS = 100
INTERRUPTED_DETAIL = "CveDeck restarted before this scan finished; run it again."
_ACTIVE = (ScanJobStatus.QUEUED, ScanJobStatus.RUNNING)

#: One scan at a time in this process, whichever route asked (Req 19.1).
_scan_slot = threading.Lock()
#: Credentials of jobs not yet started, by job id -- the only place they exist.
_credentials: dict[str, dict[str, Credentials]] = {}
_credentials_lock = threading.Lock()


def _now() -> datetime:
    return datetime.now(timezone.utc)


def diff_counts(scan: MachineScan) -> dict[str, object]:
    """A scan outcome's new and resolved counts, as ``None`` where not assessed (Req 18.2)."""
    diff = scan.diff
    if diff is None or diff.baseline:
        return {"new_count": None, "resolved_count": None, "baseline": diff is not None}
    return {
        "new_count": len(diff.new),
        "resolved_count": len(diff.resolved) if diff.resolved_assessed else None,
        "baseline": False,
    }


def _record_outcome(session: Session, row: ScanJobTarget, scan: MachineScan) -> None:
    """Write a host's outcome, and on success whether the server key reached it (Req 20.3).

    A failure leaves the machine's flag alone: a host the key used to reach,
    whose key access broke, stays scheduled and keeps reporting the failure.
    """
    if scan.status is ScanStatus.SUCCESS:
        machine = session.get(TargetMachineRow, row.machine_id)
        if machine is not None:
            machine.last_scan_server_key = row.server_key
    row.state = ScanJobTargetState.DONE
    row.status = scan.status
    row.finding_count = len(scan.findings)
    row.sources_ok = scan.sources_ok
    row.unavailable_sources = ",".join(scan.unavailable_sources)
    row.message = scan.message
    for name, value in diff_counts(scan).items():
        setattr(row, name, value)


def create_job(
    session: Session,
    *,
    targets: list[TargetMachine],
    credentials_by_id: dict[str, Credentials],
    unresolved: list[tuple[TargetMachine, str]],
    requested_by: str,
    server_key_ids: set[str] | frozenset[str] = frozenset(),
) -> ScanJob:
    """Write a job down, queued, and hold its credentials in memory (Req 19.1, 19.3).

    ``unresolved`` are targets whose credentials could not be worked out; each is
    recorded at once as an authentication failure, as a scan always reported
    them, and placed first, where the scan response always listed them.
    """
    job = ScanJob(
        id=uuid.uuid4().hex,
        status=ScanJobStatus.QUEUED,
        requested_by=requested_by,
        created_at=_now(),
    )
    position = 0
    for target, message in unresolved:
        job.targets.append(
            ScanJobTarget(
                position=position,
                machine_id=target.id,
                hostname=target.hostname,
                platform=target.platform,
                state=ScanJobTargetState.DONE,
                status=ScanStatus.AUTH_FAILURE,
                finding_count=0,
                sources_ok=False,
                unavailable_sources="",
                message=message,
                baseline=False,
            )
        )
        position += 1
    for target in targets:
        job.targets.append(
            ScanJobTarget(
                position=position,
                machine_id=target.id,
                hostname=target.hostname,
                platform=target.platform,
                state=ScanJobTargetState.QUEUED,
                server_key=target.id in server_key_ids,
            )
        )
        position += 1
    if not targets:
        job.status = ScanJobStatus.FINISHED
        job.started_at = job.finished_at = job.created_at
    session.add(job)
    session.flush()
    _prune(session)
    session.commit()
    if targets:
        with _credentials_lock:
            _credentials[job.id] = dict(credentials_by_id)
    return job


def _prune(session: Session) -> None:
    """Drop finished jobs beyond the newest ``MAX_JOBS``; never an active one.

    Targets are deleted explicitly: SQLite enforces ``ON DELETE CASCADE`` only
    with foreign keys switched on, and this database does not switch them on.
    """
    keep = select(ScanJob.id).order_by(ScanJob.created_at.desc()).limit(MAX_JOBS)
    doomed = list(
        session.execute(
            select(ScanJob.id).where(ScanJob.id.not_in(keep), ScanJob.status.not_in(_ACTIVE))
        ).scalars()
    )
    if not doomed:
        return
    session.execute(
        delete(ScanJobTarget)
        .where(ScanJobTarget.job_id.in_(doomed))
        .execution_options(synchronize_session=False)
    )
    session.execute(
        delete(ScanJob).where(ScanJob.id.in_(doomed)).execution_options(synchronize_session=False)
    )


def run_job(session: Session, job_id: str, engine: ScannerEngine) -> ScanJob | None:
    """Run a queued job, holding the scan slot until it is done (Req 19.1, 19.2).

    Each host is marked running before it is scanned and its outcome written
    after, each committed at once, so progress is visible while the job runs.
    An engine that reports nothing until the end still has its outcomes written
    then. A job that is not queued -- already run, or interrupted -- is returned
    untouched.
    """
    with _scan_slot:
        job = session.get(ScanJob, job_id)
        if job is None or job.status is not ScanJobStatus.QUEUED:
            return job
        with _credentials_lock:
            credentials = _credentials.pop(job_id, None)
        if credentials is None:
            _interrupt(job, "This scan's credentials are no longer held; run it again.")
            session.commit()
            return job

        job.status = ScanJobStatus.RUNNING
        job.started_at = _now()
        session.commit()
        pending = [row for row in job.targets if row.state is not ScanJobTargetState.DONE]

        def row_for(machine_id: str) -> ScanJobTarget | None:
            return next(
                (r for r in pending if r.machine_id == machine_id and r.state is not ScanJobTargetState.DONE),
                None,
            )

        def started(target: TargetMachine) -> None:
            row = row_for(target.id)
            if row is not None:
                row.state = ScanJobTargetState.RUNNING
                session.commit()

        def done(target: TargetMachine, scan: MachineScan) -> None:
            row = row_for(target.id)
            if row is not None:
                _record_outcome(session, row, scan)
                session.commit()

        engine.set_credentials(credentials)
        engine.on_target_start = started
        engine.on_target_done = done
        try:
            result = engine.scan(
                [TargetMachine(id=r.machine_id, hostname=r.hostname, platform=r.platform) for r in pending]
            )
        except Exception as exc:
            session.rollback()
            job = session.get(ScanJob, job_id)
            _interrupt(job, f"The scan stopped unexpectedly: {exc}"[:500])
            session.commit()
            raise
        for scan in result.machine_scans:
            row = row_for(scan.machine_id)
            if row is not None:
                _record_outcome(session, row, scan)
        job.status = ScanJobStatus.FINISHED
        job.finished_at = _now()
        session.commit()
        return job


def _interrupt(job: ScanJob, detail: str) -> None:
    job.status = ScanJobStatus.INTERRUPTED
    job.error_detail = detail
    job.finished_at = _now()


def interrupt_unfinished(session: Session) -> int:
    """Mark every queued or running job interrupted -- called at startup (Req 19.4)."""
    jobs = session.execute(select(ScanJob).where(ScanJob.status.in_(_ACTIVE))).scalars().all()
    for job in jobs:
        _interrupt(job, INTERRUPTED_DETAIL)
    session.commit()
    with _credentials_lock:
        _credentials.clear()
    return len(jobs)


def get_job(session: Session, job_id: str) -> ScanJob | None:
    return session.get(ScanJob, job_id)


def list_jobs(session: Session, *, active_only: bool = False, limit: int = 20) -> list[ScanJob]:
    stmt = select(ScanJob).order_by(ScanJob.created_at.desc()).limit(limit)
    if active_only:
        stmt = stmt.where(ScanJob.status.in_(_ACTIVE))
    return list(session.execute(stmt).scalars().all())


class _Handoff:
    """A job a request runs with its own session and engine, waiting for its turn."""

    def __init__(self, job_id: str, session: Session, engine: ScannerEngine) -> None:
        self.job_id = job_id
        self.session = session
        self.engine = engine
        self.done = threading.Event()
        self.error: BaseException | None = None


class ScanJobWorker:
    """The thread that runs every job, oldest first (Req 19.1).

    Dashboard jobs arrive as ids and run on a session and engine of the
    worker's own. A ``POST /api/scans`` job arrives as a :class:`_Handoff`
    carrying the request's session and engine -- the request is blocked
    waiting on it, so they are never used by two threads at once -- and runs in
    its place in the queue. Both routes sharing one queue is what makes "oldest
    first" true across them: when the request ran the job itself and merely
    competed for the slot, it overtook a dashboard job queued before it.
    """

    def __init__(
        self,
        session_factory: Callable[[], Session],
        engine_factory: Callable[[Session], ScannerEngine],
    ) -> None:
        self._session_factory = session_factory
        self._engine_factory = engine_factory
        self._queue: queue.Queue[str | _Handoff | None] = queue.Queue()
        self._thread: threading.Thread | None = None

    def submit(self, job_id: str) -> None:
        self._queue.put(job_id)

    def run_in_turn(self, job_id: str, session: Session, engine: ScannerEngine) -> ScanJob | None:
        """Queue a request's job behind everything before it and wait for it."""
        handoff = _Handoff(job_id, session, engine)
        self._queue.put(handoff)
        handoff.done.wait()
        if handoff.error is not None:
            raise handoff.error
        return session.get(ScanJob, job_id)

    def start(self) -> None:
        self._thread = threading.Thread(target=self._run, name="scan-jobs", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        """Stop after the current job. A scan in progress is not cut off mid-command."""
        self._queue.put(None)
        if self._thread is not None:
            self._thread.join(timeout)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            if isinstance(item, _Handoff):
                try:
                    run_job(item.session, item.job_id, item.engine)
                except BaseException as exc:  # handed back to the waiting request
                    item.error = exc
                finally:
                    item.done.set()
                continue
            try:
                with self._session_factory() as session:
                    run_job(session, item, self._engine_factory(session))
            except Exception:
                # Recorded on the job by run_job; the worker carries on.
                _LOGGER.exception("Scan job %s failed", item)


_worker: ScanJobWorker | None = None


def start_worker(
    session_factory: Callable[[], Session],
    engine_factory: Callable[[Session], ScannerEngine],
) -> ScanJobWorker:
    global _worker
    _worker = ScanJobWorker(session_factory, engine_factory)
    _worker.start()
    return _worker


def stop_worker() -> None:
    global _worker
    if _worker is not None:
        _worker.stop()
        _worker = None


def run_in_turn(session: Session, job_id: str, engine: ScannerEngine) -> ScanJob | None:
    """Run a request's job in its place in the queue, and wait for it (Req 19.1, 19.5).

    Without a worker -- a test app, which has no lifespan -- there is no queue
    to take a place in, and the job runs here, still holding the scan slot.
    """
    if _worker is None:
        return run_job(session, job_id, engine)
    return _worker.run_in_turn(job_id, session, engine)


def submit(job_id: str) -> None:
    """Hand a job to the worker. Without one -- a test app -- the job stays queued."""
    if _worker is None:
        _LOGGER.warning("No scan worker is running; job %s stays queued", job_id)
        return
    _worker.submit(job_id)
