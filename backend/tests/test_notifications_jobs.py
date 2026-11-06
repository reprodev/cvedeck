"""Alerts from the scan worker, and the routes that configure them (Req 21).

Every send goes through a stub that records what it was asked to send, so
nothing here reaches a network.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.api import actions
from app.data.repository import FindingDiff, FindingSnapshot
from app.data.schema import Base, ScanJob
from app.enums import NotificationStatus, Platform, ScanJobStatus, ScanStatus, Severity
from app.models import Credentials, TargetMachine
from app.scanner.engine import MachineScan, ScanResult
from app.services import notifications, notify_destination, scan_jobs
from app.services.notify_destination import SendResult

LAN_URL = "https://alerts.home.example.org/hook/s3cr3t-path"


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
def configured(monkeypatch):
    for name in ("CVEDECK_NOTIFY_KIND", "CVEDECK_NOTIFY_TOKEN", "CVEDECK_NOTIFY_SECRET",
                 "CVEDECK_NOTIFY_DETAIL", "CVEDECK_NOTIFY_ALLOW_PUBLIC", "CVEDECK_NOTIFY_ALLOW_HTTP",
                 "CVEDECK_NOTIFY_LINK", "CVEDECK_DEMO_MODE"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("CVEDECK_NOTIFY_URL", LAN_URL)
    monkeypatch.setenv("CVEDECK_NOTIFY_TOKEN", "tk_secret")


class _Sent:
    """A stand-in for notify_destination.send that records each call."""

    def __init__(self, result=SendResult(NotificationStatus.SENT)):
        self.result = result
        self.calls: list[tuple[dict, bytes]] = []

    def __call__(self, destination, *, headers, body, **_):
        if isinstance(self.result, Exception):
            raise self.result
        self.calls.append((headers, body))
        return self.result


@pytest.fixture()
def sent(monkeypatch):
    stub = _Sent()
    monkeypatch.setattr(notify_destination, "send", stub)
    return stub


def _enable(db, **fields):
    with Session(db) as session:
        row = notifications.get_notification_settings(session)
        row.enabled = True
        for name, value in fields.items():
            setattr(row, name, value)
        session.commit()


class _Engine:
    """Reports each host's outcome, with a diff, through the progress hooks."""

    def __init__(self, scans: dict[str, MachineScan]) -> None:
        self._scans = scans
        self.on_target_start = self.on_target_done = None
        self.should_stop = None

    def set_credentials(self, credentials):
        pass

    def scan(self, targets):
        out = []
        for target in targets:
            scan = self._scans[target.id]
            self.on_target_done(target, scan)
            out.append(scan)
        return ScanResult(machine_scans=out)


def _new(kev: bool | None, *, baseline=False) -> FindingDiff:
    snap = FindingSnapshot("CVE-2026-0001", "deb:openssl@3.0.1", Severity.CRITICAL, 9.8, kev)
    return FindingDiff(new=() if baseline else (snap,), resolved=(), baseline=baseline,
                       resolved_assessed=True, scanned_at=datetime.now(timezone.utc))


def _run(db, requested_by: str, scans: dict[str, MachineScan]) -> str:
    """Queue a job and run it through the real worker loop, synchronously."""
    with Session(db) as session:
        job = scan_jobs.create_job(
            session,
            targets=[TargetMachine(id=m, hostname=f"{m}.lan", platform=Platform.LINUX) for m in scans],
            credentials_by_id={m: Credentials(username="u", password="p") for m in scans},
            unresolved=[],
            requested_by=requested_by,
        )
        job_id = job.id
    worker = scan_jobs.ScanJobWorker(lambda: Session(db), lambda session: _Engine(scans))
    worker.submit(job_id)
    worker._queue.put(None)
    worker._run()
    return job_id


def _job(db, job_id) -> ScanJob:
    with Session(db) as session:
        job = session.get(ScanJob, job_id)
        session.expunge(job)
        return job


def _ok(machine_id: str, diff: FindingDiff | None) -> MachineScan:
    return MachineScan(machine_id=machine_id, status=ScanStatus.SUCCESS, diff=diff)


# --- The worker --------------------------------------------------------------


def test_a_scheduled_job_with_something_new_sends_one_alert(db, configured, sent):
    """Req 21.2, 21.8."""
    _enable(db)
    job_id = _run(db, "schedule", {"m1": _ok("m1", _new(kev=True)), "m2": _ok("m2", _new(kev=None))})
    assert len(sent.calls) == 1
    job = _job(db, job_id)
    assert job.status is ScanJobStatus.FINISHED
    assert job.notification_status == NotificationStatus.SENT.value
    payload = json.loads(sent.calls[0][1])
    assert payload["summary"]["kev"] == 1 and payload["summary"]["kev_unknown"] == 1
    assert "hosts" not in payload  # summary by default (Req 21.7)


def test_a_job_a_person_started_sends_nothing(db, configured, sent):
    _enable(db)
    job_id = _run(db, "admin", {"m1": _ok("m1", _new(kev=True))})
    assert sent.calls == [] and _job(db, job_id).notification_status is None


def test_alerts_are_off_until_switched_on(db, configured, sent):
    """Req 21.1."""
    job_id = _run(db, "schedule", {"m1": _ok("m1", _new(kev=True))})
    assert sent.calls == [] and _job(db, job_id).notification_status is None


def test_a_baseline_is_nothing_to_send(db, configured, sent):
    """Req 21.3, 21.6: recorded, so the dashboard can say the alert was considered."""
    _enable(db)
    job_id = _run(db, "schedule", {"m1": _ok("m1", _new(kev=True, baseline=True))})
    assert sent.calls == []
    assert _job(db, job_id).notification_status == NotificationStatus.NOTHING_TO_SEND.value


def test_a_failed_send_never_changes_the_job(db, configured, monkeypatch):
    """Req 21.8."""
    monkeypatch.setattr(notify_destination, "send",
                        _Sent(SendResult(NotificationStatus.FAILED, "alerts.home.example.org: HTTP 500")))
    _enable(db)
    job_id = _run(db, "schedule", {"m1": _ok("m1", _new(kev=True))})
    job = _job(db, job_id)
    assert job.status is ScanJobStatus.FINISHED
    assert job.notification_status == "failed"
    assert job.notification_error == "alerts.home.example.org: HTTP 500"


def test_a_notifier_bug_does_not_stop_the_worker(db, configured, monkeypatch):
    """Req 21.8: the worker runs every later scan; a crash here would end them all."""
    monkeypatch.setattr(notify_destination, "send", _Sent(RuntimeError("bug")))
    _enable(db)
    first = _run(db, "schedule", {"m1": _ok("m1", _new(kev=True))})
    second = _run(db, "schedule", {"m2": _ok("m2", None)})
    assert _job(db, first).status is ScanJobStatus.FINISHED
    assert _job(db, second).status is ScanJobStatus.FINISHED


def test_a_refused_destination_is_recorded_not_sent(db, configured, monkeypatch, sent):
    monkeypatch.setenv("CVEDECK_NOTIFY_URL", "http://alerts.home.example.org/hook")  # token over http
    _enable(db)
    job_id = _run(db, "schedule", {"m1": _ok("m1", _new(kev=True))})
    job = _job(db, job_id)
    assert sent.calls == []
    assert job.notification_status == "refused" and "plain http" in job.notification_error


# --- The routes --------------------------------------------------------------


@pytest.fixture()
def client(db):
    from app.api.app import create_app
    from app.api.dependencies import get_session
    from tests.auth_helpers import override_auth

    app = override_auth(create_app())

    def session_per_request():
        with Session(db) as session:
            yield session

    app.dependency_overrides[get_session] = session_per_request
    actions._last_test_alert.clear()
    yield TestClient(app)
    actions._last_test_alert.clear()


def test_get_never_shows_the_url_token_or_secret(client, configured, monkeypatch):
    """Req 21.10."""
    monkeypatch.setenv("CVEDECK_NOTIFY_SECRET", "hmac_secret")
    response = client.get("/api/notifications")
    assert response.status_code == 200
    text = response.text
    for secret in ("s3cr3t-path", "tk_secret", "hmac_secret", "/hook"):
        assert secret not in text
    body = response.json()
    assert body["destination_host"] == "alerts.home.example.org"
    assert body["configured"] is True and body["enabled"] is False
    assert body["threshold"] == "critical" and body["include_not_checked"] is True
    assert body["signed"] is True


def test_put_changes_only_what_the_dashboard_may(client, configured):
    """Req 21.10: a destination or detail level in the body is rejected, not ignored."""
    ok = client.put("/api/notifications",
                    json={"enabled": True, "threshold": "kev", "include_not_checked": False})
    assert ok.status_code == 200 and ok.json()["threshold"] == "kev"
    for extra in ({"url": "https://198.51.100.7/"}, {"detail": "detailed"}, {"token": "x"}):
        bad = client.put("/api/notifications",
                         json={"enabled": True, "threshold": "kev", "include_not_checked": False, **extra})
        assert bad.status_code == 422


def test_switching_on_with_no_destination_is_refused(client, monkeypatch):
    monkeypatch.delenv("CVEDECK_NOTIFY_URL", raising=False)
    response = client.put("/api/notifications",
                          json={"enabled": True, "threshold": "critical", "include_not_checked": True})
    assert response.status_code == 409 and "CVEDECK_NOTIFY_URL" in response.json()["detail"]


def test_a_test_alert_is_sent_and_rate_limited(client, configured, sent):
    """Req 21.9: one per 30 seconds, whoever asks."""
    first = client.post("/api/notifications/test")
    assert first.status_code == 200 and first.json() == {"status": "sent", "error": None}
    assert json.loads(sent.calls[0][1])["event"] == "test"
    second = client.post("/api/notifications/test")
    assert second.status_code == 429 and int(second.headers["Retry-After"]) > 0
    assert len(sent.calls) == 1
    assert client.get("/api/notifications").json()["last_status"] == "sent"


def test_a_test_alert_to_a_public_address_is_refused_before_connecting(client, configured, monkeypatch):
    """Req 21.15, through the real policy with a stubbed resolver."""
    monkeypatch.setenv("CVEDECK_NOTIFY_URL", "https://203.0.113.7/hook")
    response = client.post("/api/notifications/test")
    assert response.json()["status"] == "refused"
    assert "203.0.113.7" in response.json()["error"]
    assert "/hook" not in response.json()["error"]


def test_scan_jobs_report_their_alert(client, db, configured, sent):
    _enable(db)
    job_id = _run(db, "schedule", {"m1": _ok("m1", _new(kev=True))})
    body = client.get(f"/api/scans/jobs/{job_id}").json()
    assert body["notification_status"] == "sent" and body["notification_error"] is None
