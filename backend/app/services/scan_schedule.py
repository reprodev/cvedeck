"""Scheduled scans: a daily scan of every host the server key reaches (Req 20).

Credentials are never stored, so an unattended scan has only the
server-managed SSH key -- and only hosts whose last successful scan used it are
scheduled (Req 20.3). A host that needs a password is left alone, rather than
failing, and showing red, every night.

The schedule lives in the database and is set from the dashboard (Req 20.2).
A ticker started with the app checks it once a minute and, when a slot is due,
queues an ordinary scan job through ``services.scan_jobs`` -- the same queue and
the same scan slot as every other scan (Req 20.6). It is deliberately not part
of ``feed_scheduler``: the feed refresher is idempotent and owns no scan.
"""

from __future__ import annotations

import asyncio
import logging
import re
from dataclasses import dataclass
from datetime import datetime, time, timedelta, timezone

from sqlalchemy import select
from sqlalchemy.engine import Engine
from sqlalchemy.orm import Session

from .. import config
from ..data.schema import ScanJob, ScanSchedule, TargetMachine as TargetMachineRow
from ..enums import Platform, ScanJobStatus
from ..models import TargetMachine
from . import scan_jobs

_LOGGER = logging.getLogger(__name__)

TICK_SECONDS = 60
DEFAULT_TIME = "03:00"
_HHMM = re.compile(r"^([01]\d|2[0-3]):([0-5]\d)$")


def parse_time_of_day(value: str) -> time:
    """``"03:00"`` -> ``time(3, 0)``; anything else is a ``ValueError``."""
    match = _HHMM.match(value or "")
    if match is None:
        raise ValueError(f"time_of_day must be HH:MM on a 24-hour clock, got {value!r}")
    return time(int(match.group(1)), int(match.group(2)))


def latest_slot(now: datetime, time_of_day: str) -> datetime:
    """The most recent daily slot at or before ``now``, in the same wall-clock terms."""
    slot = datetime.combine(now.date(), parse_time_of_day(time_of_day))
    return slot if slot <= now else slot - timedelta(days=1)


def next_due(now: datetime, time_of_day: str, since: datetime | None) -> datetime | None:
    """The slot to run now, or ``None`` (Property 19, Req 20.4).

    Everything is naive local wall-clock time: "03:00" means 03:00 on the
    server's clock, through daylight-saving changes. ``since`` is the later of
    the last run and when the schedule was last armed.

    Only the most recent slot is ever considered, so a process that was down
    at 03:00 and is back at 07:00 runs once, at 07:00 -- and a slot older than
    a day is never caught up, because a newer one has replaced it. A slot at or
    before ``since`` has been run, or predates the schedule, and is not due.
    """
    slot = latest_slot(now, time_of_day)
    if since is not None and slot <= since:
        return None
    return slot


def _local(moment: datetime | None) -> datetime | None:
    """A stored UTC time as naive local wall-clock time, for comparing with slots."""
    if moment is None:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone().replace(tzinfo=None)


def server_timezone() -> str:
    return datetime.now().astimezone().tzname() or "local"


def get_schedule(session: Session) -> ScanSchedule:
    """The one schedule row, created off on first use (Req 20.1)."""
    row = session.get(ScanSchedule, 1)
    if row is None:
        row = ScanSchedule(id=1, enabled=False, time_of_day=DEFAULT_TIME)
        session.add(row)
        session.flush()
    return row


def eligible_hosts(session: Session) -> list[TargetMachineRow]:
    """Linux hosts whose last successful scan used the server key (Req 20.3)."""
    return list(
        session.execute(
            select(TargetMachineRow)
            .where(
                TargetMachineRow.platform == Platform.LINUX,
                TargetMachineRow.last_scan_server_key.is_(True),
            )
            .order_by(TargetMachineRow.hostname)
        ).scalars()
    )


@dataclass(frozen=True)
class ScheduleView:
    enabled: bool
    time_of_day: str
    timezone: str
    next_run_at: datetime | None
    last_run_at: datetime | None
    last_job_id: str | None
    last_note: str | None
    eligible_hosts: int
    server_key_configured: bool


def describe(session: Session, now: datetime | None = None) -> ScheduleView:
    row = get_schedule(session)
    now_local = now or datetime.now()
    next_run = None
    if row.enabled:
        slot = latest_slot(now_local, row.time_of_day)
        since = max(filter(None, [_local(row.last_run_at), _local(row.armed_at)]), default=None)
        if since is not None and slot <= since:
            slot += timedelta(days=1)
        next_run = slot.astimezone(timezone.utc)
    return ScheduleView(
        enabled=row.enabled,
        time_of_day=row.time_of_day,
        timezone=server_timezone(),
        next_run_at=next_run,
        last_run_at=row.last_run_at,
        last_job_id=row.last_job_id,
        last_note=row.last_note,
        eligible_hosts=len(eligible_hosts(session)),
        server_key_configured=config.default_ssh_key_path() is not None,
    )


def update(session: Session, *, enabled: bool, time_of_day: str) -> ScanSchedule:
    """Switch the schedule on or off and set its time (Req 20.1, 20.2).

    Arming -- switching on, or moving the time -- records ``armed_at``, so a
    slot that has already passed today is not run on the spot.
    """
    parse_time_of_day(time_of_day)
    row = get_schedule(session)
    if enabled and (not row.enabled or row.time_of_day != time_of_day):
        row.armed_at = datetime.now(timezone.utc)
    row.enabled = enabled
    row.time_of_day = time_of_day
    session.commit()
    return row


def tick(session: Session, now: datetime | None = None) -> str | None:
    """Run the schedule if a slot is due; return what happened, or ``None`` (Req 20.4-20.6).

    A due slot is always recorded as handled -- run, or skipped with the reason
    in ``last_note`` -- so a slot that cannot run is not retried every minute.
    """
    row = get_schedule(session)
    if not row.enabled:
        return None
    now_local = now or datetime.now()
    since = max(filter(None, [_local(row.last_run_at), _local(row.armed_at)]), default=None)
    slot = next_due(now_local, row.time_of_day, since)
    if slot is None:
        return None

    note, job_id = _start(session)
    row.last_run_at = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
    row.last_note = note
    if job_id is not None:
        row.last_job_id = job_id
    session.commit()
    _LOGGER.info("Scheduled scan for %s: %s", slot.strftime("%Y-%m-%d %H:%M"), note)
    return note


def _start(session: Session) -> tuple[str, str | None]:
    if config.demo_mode():
        return "Skipped: scheduled scans are off in demo mode.", None
    if config.default_ssh_key_path() is None:
        return "Skipped: no server-managed SSH key is configured.", None
    active = session.execute(
        select(ScanJob.id).where(
            ScanJob.requested_by == "schedule",
            ScanJob.status.in_((ScanJobStatus.QUEUED, ScanJobStatus.RUNNING)),
        )
    ).first()
    if active is not None:
        return "Skipped: the previous scheduled scan is still running.", None
    hosts = eligible_hosts(session)
    if not hosts:
        return (
            "Skipped: no hosts yet -- a host joins once a scan reaches it with the server key.",
            None,
        )

    from ..api.credentials import CredentialResolutionError, resolve_credentials

    targets = [TargetMachine(id=h.id, hostname=h.hostname, platform=h.platform) for h in hosts]
    credentials, unresolved = {}, []
    for target in targets:
        try:
            credentials[target.id] = resolve_credentials(target.platform)
        except CredentialResolutionError as exc:
            unresolved.append((target, str(exc)))
    job = scan_jobs.create_job(
        session,
        targets=[t for t in targets if t.id in credentials],
        credentials_by_id=credentials,
        unresolved=unresolved,
        requested_by="schedule",
        server_key_ids={t.id for t in targets},
    )
    if job.status is ScanJobStatus.QUEUED:
        scan_jobs.submit(job.id)
    return f"Started a scan of {len(targets)} host(s).", job.id


async def run_schedule(engine: Engine, *, sleep=asyncio.sleep, iterations: int | None = None) -> None:
    """Check the schedule every minute until cancelled. A bad tick never ends the loop."""
    done = 0
    while iterations is None or done < iterations:
        try:
            await asyncio.to_thread(_tick_once, engine)
        except asyncio.CancelledError:
            raise
        except Exception:
            _LOGGER.exception("Scheduled scan check failed")
        done += 1
        if iterations is not None and done >= iterations:
            break
        await sleep(TICK_SECONDS)


def _tick_once(engine: Engine) -> None:
    with Session(engine) as session:
        tick(session)


def start_scan_schedule(engine: Engine) -> asyncio.Task | None:
    """Start the ticker; ``None`` in demo mode, which never scans (Req 20.7)."""
    if config.demo_mode():
        return None
    return asyncio.create_task(run_schedule(engine))


async def stop_scan_schedule(task: asyncio.Task | None) -> None:
    if task is None:
        return
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass
