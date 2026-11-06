"""Alerts when a scheduled scan finds something new (Req 21).

One message per scheduled job, and only when there is something to act on: a
new finding that is KEV-listed or over the threshold, or a host whose data
cannot be trusted. Never an all-clear -- a nightly "nothing new" teaches people
to mute the channel -- and never a baseline's thousand findings.

The module is in three layers, so the rules can be tested without a network:

* :func:`build_digest` -- pure: what the job found that is worth saying
  (Property 23).
* :func:`render_ntfy` / :func:`render_webhook` -- pure: the bytes and headers.
  Headers are built from counts alone (Req 21.11): hostnames and package names
  come from the scanned hosts, and a compromised host chooses its own.
* :func:`notify_after_job` -- reads the job, sends through
  :mod:`app.services.notify_destination`, records the result. It never raises
  and never holds a database transaction across the network call.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
import unicodedata
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.data.repository import FindingDiff, Repository
from app.data.schema import NotificationSettings, ScanJob
from app.enums import (
    SEVERITY_RANK,
    NotificationStatus,
    NotificationThreshold,
    ScanJobStatus,
    ScanStatus,
    Severity,
)
from app.package_identifier import parse_package_name
from app.services import notify_destination
from app.services.notify_destination import Destination, SendResult

_LOGGER = logging.getLogger(__name__)
_SECURITY_LOG = logging.getLogger("app.security")

#: ``ScanJob.requested_by`` of a scheduled job (set by ``scan_schedule``).
SCHEDULE_REQUESTER = "schedule"

#: Longest string taken from scan data that reaches a message (Req 21.11).
MAX_FIELD_LENGTH = 128

#: ntfy turns a body over 4,096 bytes into an attachment; stay well under.
NTFY_BODY_BUDGET = 3800

#: How long a stored error may be.
_MAX_ERROR_LENGTH = 300


def clean(value: str | None) -> str | None:
    """Scan-derived text made safe to place in a message body (Req 21.11).

    Control and format characters go (a hostname with a CR/LF, a package name
    with a bidi override), then the length is capped. JSON encoding handles the
    rest; nothing here is ever put in a header.
    """
    if value is None:
        return None
    text = "".join(ch for ch in value if not unicodedata.category(ch).startswith("C"))
    text = text.strip()
    if len(text) > MAX_FIELD_LENGTH:
        text = text[: MAX_FIELD_LENGTH - 1] + "…"
    return text


# --- Digest (Property 23) ----------------------------------------------------


@dataclass(frozen=True)
class HostOutcome:
    """One completed host of a job, as the digest needs it."""

    hostname: str
    status: ScanStatus
    sources_ok: bool
    diff: FindingDiff | None


@dataclass(frozen=True)
class NewFinding:
    cve_id: str
    severity: Severity
    cvss: float | None
    #: Three-valued, as everywhere else: ``None`` means nobody checked.
    kev_listed: bool | None
    package: str | None


@dataclass(frozen=True)
class HostAlert:
    hostname: str
    findings: tuple[NewFinding, ...]


@dataclass(frozen=True)
class NotCheckedHost:
    hostname: str
    #: A ``ScanStatus`` value, or ``"partial"`` for a source that did not answer.
    reason: str


@dataclass(frozen=True)
class Digest:
    hosts_checked: int
    hosts_with_new: int
    qualifying: int
    #: Qualifying findings CISA lists. Never includes an unknown (Req 21.4).
    kev: int
    #: Qualifying findings whose KEV state nobody checked.
    kev_unknown: int
    kev_feed_usable: bool
    cancelled: bool
    finished_at: datetime | None
    hosts: tuple[HostAlert, ...]
    not_checked: tuple[NotCheckedHost, ...]


def qualifies(severity: Severity, kev_listed: bool | None,
              threshold: NotificationThreshold) -> bool:
    """Whether a new finding is worth an alert (Req 21.4).

    ``kev_listed is True``, never truthiness: ``None`` is "not checked", and
    an unchecked answer must not be promoted, or demoted, to a real one.
    """
    if kev_listed is True:
        return True
    if threshold is NotificationThreshold.KEV:
        return False
    return SEVERITY_RANK[severity] <= SEVERITY_RANK[Severity(threshold.value)]


def build_digest(
    *,
    job_status: ScanJobStatus,
    requested_by: str,
    finished_at: datetime | None,
    outcomes: Sequence[HostOutcome],
    threshold: NotificationThreshold,
    include_not_checked: bool,
    kev_feed_usable: bool,
) -> Digest | None:
    """What a job found that is worth a message, or ``None`` (Property 23).

    ``None`` for a job a person started, for one that did not end finished or
    cancelled (Req 21.2), and when nothing qualifies and every host was checked
    (Req 21.6). A baseline contributes nothing (Req 21.3): ``FindingDiff``
    already leaves its ``new`` empty, and it is skipped here as well so the
    rule does not rest on one caller.
    """
    if requested_by != SCHEDULE_REQUESTER:
        return None
    if job_status not in (ScanJobStatus.FINISHED, ScanJobStatus.CANCELLED):
        return None

    hosts: list[HostAlert] = []
    not_checked: list[NotCheckedHost] = []
    kev = kev_unknown = 0
    for outcome in outcomes:
        hostname = clean(outcome.hostname) or "?"
        if outcome.status is not ScanStatus.SUCCESS:
            not_checked.append(NotCheckedHost(hostname, outcome.status.value))
            continue
        if not outcome.sources_ok:
            not_checked.append(NotCheckedHost(hostname, "partial"))
        diff = outcome.diff
        if diff is None or diff.baseline:
            continue
        found: list[NewFinding] = []
        for snap in diff.new:
            if not qualifies(snap.severity, snap.kev_listed, threshold):
                continue
            if snap.kev_listed is True:
                kev += 1
            elif snap.kev_listed is None:
                kev_unknown += 1
            found.append(
                NewFinding(
                    cve_id=clean(snap.cve_id) or "?",
                    severity=snap.severity,
                    cvss=snap.cvss_score,
                    kev_listed=snap.kev_listed,
                    package=clean(parse_package_name(snap.package_identifier)),
                )
            )
        if found:
            # Exploited first, then by severity: the order a reader acts in.
            found.sort(key=lambda f: (f.kev_listed is not True, SEVERITY_RANK[f.severity], f.cve_id))
            hosts.append(HostAlert(hostname, tuple(found)))

    if not include_not_checked:
        not_checked = []
    qualifying = sum(len(h.findings) for h in hosts)
    if qualifying == 0 and not not_checked:
        return None
    return Digest(
        hosts_checked=len(outcomes),
        hosts_with_new=len(hosts),
        qualifying=qualifying,
        kev=kev,
        kev_unknown=kev_unknown,
        kev_feed_usable=kev_feed_usable,
        cancelled=job_status is ScanJobStatus.CANCELLED,
        finished_at=finished_at,
        hosts=tuple(hosts),
        not_checked=tuple(not_checked),
    )


# --- Rendering ---------------------------------------------------------------


def _plural(n: int, one: str, many: str | None = None) -> str:
    return f"{n} {one if n == 1 else (many or one + 's')}"


def title(digest: Digest) -> str:
    """The one-line headline: counts only, never scan data (Req 21.11)."""
    parts: list[str] = []
    if digest.kev:
        parts.append(f"{digest.kev} actively exploited")
    others = digest.qualifying - digest.kev
    if others:
        parts.append(_plural(others, "new finding") if not digest.kev else f"{others} more new")
    if digest.not_checked:
        parts.append(f"{_plural(len(digest.not_checked), 'host')} not checked")
    return "CveDeck: " + ", ".join(parts)


def summary_lines(digest: Digest) -> list[str]:
    """The body every message carries: counts, and nothing naming a machine."""
    when = (
        digest.finished_at.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        if digest.finished_at
        else "just now"
    )
    lines = [f"Scheduled scan finished {when}."]
    if digest.cancelled:
        lines.append("It was cancelled; this covers the hosts it finished.")
    if digest.qualifying:
        exploited = f", {digest.kev} actively exploited" if digest.kev else ""
        lines.append(
            f"{digest.hosts_with_new} of {_plural(digest.hosts_checked, 'host')} "
            f"{'has' if digest.hosts_with_new == 1 else 'have'} new findings: "
            f"{digest.qualifying} worth acting on{exploited}."
        )
    if not digest.kev_feed_usable:
        lines.append(
            "The exploitation check did not run: CISA's KEV catalogue has not been "
            "downloaded, so none of these is known to be exploited or not."
        )
    elif digest.kev_unknown:
        lines.append(
            f"{_plural(digest.kev_unknown, 'finding')} "
            f"{'has' if digest.kev_unknown == 1 else 'have'} no exploitation answer yet."
        )
    if digest.not_checked:
        lines.append(
            f"{_plural(len(digest.not_checked), 'host')} could not be checked, so "
            "their results are missing or partial."
        )
    return lines


def _finding_line(f: NewFinding) -> str:
    marks = [f.severity.value]
    if f.kev_listed is True:
        marks.append("actively exploited")
    elif f.kev_listed is None:
        marks.append("KEV unknown")
    package = f" in {f.package}" if f.package else ""
    return f"  {f.cve_id} ({', '.join(marks)}){package}"


def detail_lines(digest: Digest, budget: int) -> list[str]:
    """Per-host lines for a detailed message, cut to ``budget`` bytes."""
    rendered: list[str] = []
    for host in digest.hosts:
        rendered.append(f"{host.hostname}:")
        rendered.extend(_finding_line(f) for f in host.findings)
    for host in digest.not_checked:
        rendered.append(f"{host.hostname}: not checked ({host.reason})")
    kept: list[str] = []
    used = 0
    for i, line in enumerate(rendered):
        cost = len(line.encode("utf-8")) + 1
        if used + cost > budget:
            kept.append(f"and {len(rendered) - i} more lines")
            break
        kept.append(line)
        used += cost
    return kept


def render_ntfy(digest: Digest, destination: Destination, *, test: bool = False
                ) -> tuple[dict[str, str], bytes]:
    """Headers and body for ntfy (Req 21.7, 21.11, 21.16).

    No ``Markdown`` header: with markdown off, a package name shaped like a link
    stays text. ``Click`` only with the link opt-in.
    """
    headers = {
        "Title": "CveDeck: test alert" if test else title(digest),
        "Priority": "5" if digest.kev else ("4" if digest.qualifying else "3"),
        "Tags": "rotating_light" if digest.kev else "warning",
        "Content-Type": "text/plain; charset=utf-8",
    }
    if destination.link_url:
        headers["Click"] = destination.link_url + "/#/jobs"
    lines = ["This is a test alert from CveDeck."] if test else summary_lines(digest)
    if destination.detail == "detailed" and not test:
        head = "\n".join(lines).encode("utf-8")
        lines += [""] + detail_lines(digest, NTFY_BODY_BUDGET - len(head) - 2)
    return headers, "\n".join(lines).encode("utf-8")


def webhook_payload(digest: Digest, destination: Destination, *, test: bool = False
                    ) -> dict[str, object]:
    """The JSON object a webhook receives (Req 21.7, 21.16)."""
    payload: dict[str, object] = {
        "event": "test" if test else "scheduled_scan.finished",
        "finished_at": digest.finished_at.astimezone(timezone.utc).isoformat()
        if digest.finished_at
        else None,
        "title": "CveDeck: test alert" if test else title(digest),
        "message": "\n".join(summary_lines(digest)) if not test else "This is a test alert from CveDeck.",
        "summary": {
            "hosts_checked": digest.hosts_checked,
            "hosts_with_new": digest.hosts_with_new,
            "qualifying": digest.qualifying,
            "kev": digest.kev,
            "kev_unknown": digest.kev_unknown,
            "kev_feed_usable": digest.kev_feed_usable,
            "not_checked": len(digest.not_checked),
            "cancelled": digest.cancelled,
        },
    }
    if destination.link_url:
        payload["dashboard_url"] = destination.link_url + "/#/jobs"
    if destination.detail == "detailed":
        from app.api.app import _VERSION  # local: the API layer imports this module

        payload["cvedeck_version"] = _VERSION
        payload["hosts"] = [
            {
                "hostname": h.hostname,
                "new": [
                    {
                        "cve_id": f.cve_id,
                        "severity": f.severity.value,
                        "cvss": f.cvss,
                        "kev_listed": f.kev_listed,
                        "package": f.package,
                    }
                    for f in h.findings
                ],
            }
            for h in digest.hosts
        ]
        payload["not_checked"] = [
            {"hostname": h.hostname, "status": h.reason} for h in digest.not_checked
        ]
    return payload


def sign(secret: str, timestamp: str, body: bytes) -> str:
    """``sha256=<hex>`` over ``timestamp + "." + body`` (Req 21.13)."""
    mac = hmac.new(secret.encode("utf-8"), timestamp.encode("ascii") + b"." + body, hashlib.sha256)
    return "sha256=" + mac.hexdigest()


def render_webhook(digest: Digest, destination: Destination, *, test: bool = False,
                   now: Callable[[], float] = time.time) -> tuple[dict[str, str], bytes]:
    body = json.dumps(webhook_payload(digest, destination, test=test), ensure_ascii=False).encode("utf-8")
    headers = {"Content-Type": "application/json"}
    if destination.secret is not None:
        timestamp = str(int(now()))
        headers["X-CveDeck-Timestamp"] = timestamp
        headers["X-CveDeck-Signature"] = sign(destination.secret, timestamp, body)
    return headers, body


def render(digest: Digest, destination: Destination, *, test: bool = False
           ) -> tuple[dict[str, str], bytes]:
    if destination.kind == "ntfy":
        return render_ntfy(digest, destination, test=test)
    return render_webhook(digest, destination, test=test)


TEST_DIGEST = Digest(
    hosts_checked=0, hosts_with_new=0, qualifying=0, kev=0, kev_unknown=0,
    kev_feed_usable=True, cancelled=False, finished_at=None, hosts=(), not_checked=(),
)


# --- Settings and delivery ---------------------------------------------------


def get_notification_settings(session: Session) -> NotificationSettings:
    """The one settings row, created switched off on first use (Req 21.1)."""
    row = session.get(NotificationSettings, 1)
    if row is None:
        row = NotificationSettings(
            id=1,
            enabled=False,
            threshold=NotificationThreshold.CRITICAL.value,
            include_not_checked=True,
        )
        session.add(row)
        session.flush()
    return row


def threshold_of(row: NotificationSettings) -> NotificationThreshold:
    try:
        return NotificationThreshold(row.threshold)
    except ValueError:
        return NotificationThreshold.CRITICAL


def _kev_feed_usable(session: Session) -> bool:
    from app.services.enrichment import KEV_FEED, FindingEnricher

    return FindingEnricher(Repository(session)).feed_health(KEV_FEED).usable


def _outcomes_for(job: ScanJob, scans: Sequence[object]) -> list[HostOutcome]:
    hostnames = {t.machine_id: t.hostname for t in job.targets}
    result: list[HostOutcome] = []
    for scan in scans:
        machine_id = getattr(scan, "machine_id")
        result.append(
            HostOutcome(
                hostname=hostnames.get(machine_id, machine_id),
                status=getattr(scan, "status"),
                sources_ok=getattr(scan, "sources_ok"),
                diff=getattr(scan, "diff"),
            )
        )
    return result


SendFn = Callable[..., SendResult]


def notify_after_job(
    session_factory: Callable[[], Session],
    job_id: str,
    scans: Sequence[object],
    *,
    send: SendFn | None = None,
) -> NotificationStatus | None:
    """Send a finished scheduled job's alert, and record what happened (Req 21.2, 21.8).

    Called by the worker after the job is committed and the scan slot released.
    Reads in one session, sends with no transaction open -- a slow receiver must
    not hold a SQLite lock -- then records in another. Returns the status
    recorded, or ``None`` when the job sends no alert at all.

    Never raises. A notifier bug must not take down the worker thread that runs
    every later scan, so the outer handler is deliberately broad and logs.
    """
    try:
        return _notify_after_job(session_factory, job_id, scans, send or notify_destination.send)
    except Exception:  # noqa: BLE001 -- see docstring
        _LOGGER.exception("Notification for scan job %s failed unexpectedly", job_id)
        return None


def _notify_after_job(session_factory, job_id, scans, send) -> NotificationStatus | None:
    with session_factory() as session:
        job = session.get(ScanJob, job_id)
        if job is None or job.requested_by != SCHEDULE_REQUESTER:
            return None
        settings = get_notification_settings(session)
        enabled = settings.enabled
        threshold = threshold_of(settings)
        include_not_checked = settings.include_not_checked
        job_status, finished_at = job.status, job.finished_at
        outcomes = _outcomes_for(job, scans)
        kev_usable = _kev_feed_usable(session)
        session.commit()
    if not enabled:
        return None

    policy = notify_destination.evaluate(notify_destination.read_config())
    if not policy.configured:
        result = SendResult(NotificationStatus.REFUSED, "No destination is configured.")
    elif not policy.usable:
        result = SendResult(NotificationStatus.REFUSED, "; ".join(policy.problems))
    else:
        digest = build_digest(
            job_status=job_status,
            requested_by=SCHEDULE_REQUESTER,
            finished_at=finished_at,
            outcomes=outcomes,
            threshold=threshold,
            include_not_checked=include_not_checked,
            kev_feed_usable=kev_usable,
        )
        if digest is None:
            result = SendResult(NotificationStatus.NOTHING_TO_SEND)
        else:
            assert policy.destination is not None
            headers, body = render(digest, policy.destination)
            result = send(policy.destination, headers=headers, body=body)

    record(session_factory, job_id, result)
    if result.status in (NotificationStatus.FAILED, NotificationStatus.REFUSED):
        _SECURITY_LOG.warning("Alert for scan job %s %s: %s", job_id, result.status.value, result.error)
    return result.status


def record(session_factory: Callable[[], Session], job_id: str | None, result: SendResult) -> None:
    """Store an attempt's result on the job and the settings row (Req 21.8)."""
    error = (result.error or "")[:_MAX_ERROR_LENGTH] or None
    with session_factory() as session:
        if job_id is not None:
            job = session.get(ScanJob, job_id)
            if job is not None:
                job.notification_status = result.status.value
                job.notification_error = error
        settings = get_notification_settings(session)
        if result.status is not NotificationStatus.NOTHING_TO_SEND:
            settings.last_sent_at = datetime.now(timezone.utc)
            settings.last_status = result.status.value
            settings.last_error = error
            settings.last_job_id = job_id
        session.commit()


def send_test(session_factory: Callable[[], Session], *, send: SendFn | None = None
              ) -> SendResult:
    """Send one message labelled as a test, through the same policy (Req 21.9)."""
    send = send or notify_destination.send
    policy = notify_destination.evaluate(notify_destination.read_config())
    if not policy.configured:
        result = SendResult(NotificationStatus.REFUSED, "No destination is configured.")
    elif not policy.usable:
        result = SendResult(NotificationStatus.REFUSED, "; ".join(policy.problems))
    else:
        assert policy.destination is not None
        headers, body = render(TEST_DIGEST, policy.destination, test=True)
        result = send(policy.destination, headers=headers, body=body)
    record(session_factory, None, result)
    return result
