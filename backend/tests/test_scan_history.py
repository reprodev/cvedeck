"""Scan history and what changed between scans (Req 18).

Feature: cvedeck
Property 13: A scan's diff is exact, and a partial scan resolves nothing
Validates: Requirements 18.2, 18.3, 18.5

The property drives the repository with arbitrary before-and-after finding
sets. The examples drive the deployment engine and the API through a sequence
of real outcomes -- baseline, change, failure, partial -- because the trust
rules are about what happens *between* scans, which no single call shows.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from hypothesis import given, settings, strategies as st
from sqlalchemy import create_engine, inspect, text
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app import config
from app.api import wiring
from app.api.app import create_app
from app.api.dependencies import get_session
from app.data.repository import FindingInput, RemediationInput, Repository, finding_key
from app.data.schema import Base, ScanFindingChange, ScanRun, TargetMachine
from app.enums import (
    Platform,
    RemediationStatus,
    ScanStatus,
    Severity,
    SourceStatus,
    SyncStatus,
)
from app.models import Credentials, Inventory, OsInfo
from app.models import TargetMachine as DomainTarget
from app.scanner.matcher import Finding, MatchResult
from app.services.sync import SyncService
from tests.auth_helpers import override_auth


def _session() -> Session:
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    return Session(engine)


def _machine(session: Session, machine_id: str = "m1") -> None:
    session.add(
        TargetMachine(
            id=machine_id,
            hostname=f"{machine_id}.lan",
            platform=Platform.LINUX,
            last_scan_status=ScanStatus.NEVER_SCANNED,
            sync_status=SyncStatus.SYNCED,
        )
    )
    session.flush()


def _finding(cve: str, package: str | None = "openssl", version: str = "3.0.2") -> FindingInput:
    identifier = None if package is None else f"Debian:13:{package}@{version}"
    return FindingInput(cve, 7.5, Severity.HIGH, "osv", identifier)


def _keys(items) -> set:
    return {finding_key(i.cve_id, i.package_identifier) for i in items}


def _baseline(repo: Repository, findings: list[FindingInput], machine_id: str = "m1"):
    diff = repo.save_findings(machine_id, findings)
    repo.record_scan_run(
        machine_id,
        status=ScanStatus.SUCCESS,
        sources_ok=True,
        scanned_at=diff.scanned_at,
        diff=diff,
        keep=50,
    )
    return diff


# --------------------------------------------------------------------------- #
# Property 13
# --------------------------------------------------------------------------- #
_findings = st.lists(
    st.builds(
        _finding,
        cve=st.sampled_from([f"CVE-2026-{n:04d}" for n in range(1, 7)]),
        package=st.sampled_from(["openssl", "curl", "Red Hat:glibc", None]),
        version=st.sampled_from(["1.0", "1:2.0-1"]),
    ),
    max_size=10,
)


@settings(max_examples=100, deadline=None)
@given(before=_findings, after=_findings, partial=st.booleans())
def test_property_13_the_diff_is_exact_and_partial_scans_resolve_nothing(before, after, partial):
    with _session() as session:
        _machine(session)
        repo = Repository(session)
        _baseline(repo, before)
        first_seen = {
            finding_key(f.cve_id, f.package_identifier): f.first_seen_at
            for f in repo.get_findings_for_machine("m1")
        }

        diff = repo.save_findings(
            "m1",
            after,
            suppress_resolved=partial,
            scanned_at=datetime.now(timezone.utc) + timedelta(days=1),
        )
        stored = repo.get_findings_for_machine("m1")

        assert not diff.baseline
        assert _keys(diff.new) == _keys(after) - _keys(before)
        assert len(diff.new) == len(_keys(diff.new))
        if partial:
            assert diff.resolved == ()
            assert not diff.resolved_assessed
            # Nothing unreported disappears: an unreachable source is not a patch.
            assert _keys(stored) == _keys(before) | _keys(after)
        else:
            assert _keys(diff.resolved) == _keys(before) - _keys(after)
            assert _keys(stored) == _keys(after)
        for row in stored:
            key = finding_key(row.cve_id, row.package_identifier)
            if key in first_seen:
                assert row.first_seen_at == first_seen[key]


# --------------------------------------------------------------------------- #
# Repository examples
# --------------------------------------------------------------------------- #
def test_an_upgrade_that_stays_vulnerable_is_neither_new_nor_resolved():
    """Validates Req 18.2: the key leaves the version out."""
    with _session() as session:
        _machine(session)
        repo = Repository(session)
        _baseline(repo, [_finding("CVE-2026-0001", version="3.0.2")])

        diff = repo.save_findings("m1", [_finding("CVE-2026-0001", version="3.0.15")])

        assert diff.new == () and diff.resolved == ()


def test_the_first_successful_scan_is_a_baseline():
    """Validates Req 18.4, including a machine with findings from before history."""
    with _session() as session:
        _machine(session)
        repo = Repository(session)
        repo.save_findings("m1", [_finding("CVE-2026-0001")])  # no run recorded

        diff = repo.save_findings("m1", [_finding("CVE-2026-0002")])
        run = repo.record_scan_run(
            "m1", status=ScanStatus.SUCCESS, sources_ok=True,
            scanned_at=diff.scanned_at, diff=diff, keep=50,
        )

        assert diff.baseline and diff.new == () and diff.resolved == ()
        assert run.baseline and run.new_count is None and run.resolved_count is None
        assert session.query(ScanFindingChange).count() == 0


def test_retention_keeps_the_newest_runs_and_the_latest_success():
    """Validates Req 18.7."""
    with _session() as session:
        _machine(session)
        repo = Repository(session)
        diff = _baseline(repo, [_finding("CVE-2026-0001")])
        success_id = repo.list_scan_runs("m1")[0].id
        for hours in (1, 2, 3):
            repo.record_scan_run(
                "m1", status=ScanStatus.CONNECTION_FAILURE, sources_ok=True,
                scanned_at=diff.scanned_at + timedelta(hours=hours), diff=None, keep=2,
            )

        runs = repo.list_scan_runs("m1")
        assert [r.status for r in runs] == [
            ScanStatus.CONNECTION_FAILURE,
            ScanStatus.CONNECTION_FAILURE,
            ScanStatus.SUCCESS,
        ]
        # Older than both kept failures, and kept anyway: the "new" badges are
        # read from it.
        assert runs[-1].id == success_id


def test_config_rejects_a_history_limit_below_one(monkeypatch):
    monkeypatch.setenv("CVEDECK_SCAN_HISTORY_LIMIT", "0")
    with pytest.raises(ValueError):
        config.scan_history_limit()
    monkeypatch.delenv("CVEDECK_SCAN_HISTORY_LIMIT")
    assert config.scan_history_limit() == 50


# --------------------------------------------------------------------------- #
# Through the deployment engine and the API
# --------------------------------------------------------------------------- #
class _Collector:
    def __init__(self) -> None:
        self.fail = False

    def collect(self, target, credentials):
        if self.fail:
            raise ConnectionError("could not connect to m1.lan:22")
        return Inventory(machine_id=target.id, os_info=OsInfo(name="Debian", version="13"))


class _Matcher:
    def __init__(self) -> None:
        self.cves: list[str] = []
        self.osv_status = SourceStatus.OK

    def match(self, inventory, nvd, osv):
        return MatchResult(
            machine_id=inventory.machine_id,
            findings=[
                Finding(
                    machine_id=inventory.machine_id,
                    cve_id=cve,
                    cvss_score=7.5,
                    severity=Severity.HIGH,
                    source="osv",
                    package_identifier="Debian:13:openssl@3.0.2",
                )
                for cve in self.cves
            ],
            nvd_status=SourceStatus.OK,
            osv_status=self.osv_status,
        )


@pytest.fixture()
def fleet(monkeypatch):
    session = _session()
    collector, matcher = _Collector(), _Matcher()
    monkeypatch.setattr(wiring, "build_collector", lambda platform, store=None: collector)
    app = override_auth(create_app())
    app.dependency_overrides[get_session] = lambda: session

    def scan() -> None:
        engine = wiring.DeploymentScannerEngine(session, osv=object(), nvd=None)
        engine._matcher = matcher
        engine.set_credentials({"m1": Credentials(username="u", password="p")})
        engine.scan([DomainTarget(id="m1", hostname="m1.lan", platform=Platform.LINUX)])

    yield session, TestClient(app), collector, matcher, scan
    session.close()


def test_history_across_baseline_change_failure_and_partial_scans(fleet):
    """Validates Req 18.1-18.4 and 18.6 end to end."""
    session, client, collector, matcher, scan = fleet

    matcher.cves = ["CVE-A", "CVE-B"]
    scan()  # baseline
    matcher.cves = ["CVE-B", "CVE-C"]
    scan()  # C new, A resolved
    collector.fail = True
    scan()  # failed: findings untouched, no diff
    collector.fail = False
    matcher.cves, matcher.osv_status = ["CVE-C", "CVE-D"], SourceStatus.DATA_SOURCE_UNAVAILABLE
    scan()  # partial: D new, nothing resolved, B kept

    runs = client.get("/api/machines/m1/scans").json()
    assert [(r["status"], r["baseline"], r["new_count"], r["resolved_count"]) for r in runs] == [
        ("success", False, 1, None),
        ("connection_failure", False, None, None),
        ("success", False, 1, 1),
        ("success", True, None, None),
    ]
    assert runs[0]["sources_ok"] is False

    changes = client.get(f"/api/machines/m1/scans/{runs[2]['run_id']}/changes").json()
    assert [(c["change"], c["cve_id"], c["package_name"]) for c in changes] == [
        ("new", "CVE-C", "openssl"),
        ("resolved", "CVE-A", "openssl"),
    ]

    findings = {f["cve_id"]: f for f in client.get("/api/machines/m1/cves").json()}
    assert set(findings) == {"CVE-B", "CVE-C", "CVE-D"}
    assert [cve for cve, f in findings.items() if f["is_new"]] == ["CVE-D"]
    assert findings["CVE-B"]["first_seen_at"] < findings["CVE-C"]["first_seen_at"]

    summary = client.get("/api/machines/m1").json()
    assert summary["last_scan_new"] == 1
    assert summary["last_scan_resolved"] is None
    assert summary["last_scan_baseline"] is False


def test_the_scan_response_reports_what_changed(fleet, monkeypatch):
    """Validates Req 18.2 on POST /api/scans."""
    session, client, collector, matcher, _scan = fleet
    app = client.app
    from app.api.dependencies import get_scanner_engine

    def engine():
        built = wiring.DeploymentScannerEngine(session, osv=object(), nvd=None)
        built._matcher = matcher
        return built

    app.dependency_overrides[get_scanner_engine] = engine
    body = {"targets": [{"id": "m1", "hostname": "m1.lan", "platform": "linux",
                         "username": "u", "password": "p"}]}

    matcher.cves = ["CVE-A"]
    first = client.post("/api/scans", json=body).json()["machine_scans"][0]
    matcher.cves = ["CVE-B"]
    second = client.post("/api/scans", json=body).json()["machine_scans"][0]

    assert (first["baseline"], first["new_count"], first["resolved_count"]) == (True, None, None)
    assert (second["baseline"], second["new_count"], second["resolved_count"]) == (False, 1, 1)


def test_resolution_never_touches_a_remediation_record(fleet):
    """Validates Req 18.9."""
    session, client, collector, matcher, scan = fleet
    matcher.cves = ["CVE-A"]
    scan()
    record = Repository(session).add_remediation(
        "m1", "CVE-A", RemediationInput(status=RemediationStatus.IN_PROGRESS, note="patching")
    )
    session.commit()
    matcher.cves = []
    scan()

    session.refresh(record)
    assert record.status is RemediationStatus.IN_PROGRESS
    run_id = client.get("/api/machines/m1/scans").json()[0]["run_id"]
    (change,) = client.get(f"/api/machines/m1/scans/{run_id}/changes").json()
    assert change["change"] == "resolved"
    assert change["remediation_status"] == "in_progress"


def test_history_endpoints_404_for_unknown_machines_and_runs(fleet):
    session, client, *_ = fleet
    assert client.get("/api/machines/ghost/scans").status_code == 404
    assert client.get("/api/machines/ghost/scans/nope/changes").status_code == 404


def test_history_is_synchronized(fleet):
    """Validates Req 18.8."""
    session, client, collector, matcher, scan = fleet
    matcher.cves = ["CVE-A"]
    scan()
    matcher.cves = ["CVE-B"]
    scan()

    online = create_engine("sqlite:///:memory:", poolclass=StaticPool,
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(online)
    report = SyncService(session, sessionmaker(bind=online)).sync()

    assert report.online_reachable
    with Session(online) as remote:
        assert remote.query(ScanRun).count() == 2
        assert remote.query(ScanFindingChange).count() == 2


# --------------------------------------------------------------------------- #
# Migration
# --------------------------------------------------------------------------- #
def test_a_0_7_3_database_upgrades_with_first_seen_backfilled(tmp_path):
    """Validates Req 18.4, 18.5: an upgraded machine has dates and no runs."""
    from alembic import command

    from app.data.migrations_runtime import alembic_config, upgrade_to_head

    engine = create_engine(f"sqlite:///{(tmp_path / 'v073.db').as_posix()}")
    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "b3abe7f1ff0c")
        connection.execute(text(
            "INSERT INTO target_machines (id, hostname, platform, last_scan_status, "
            "last_scanned_at, last_scan_sources_ok, sync_status) VALUES "
            "('m1', 'a', 'LINUX', 'SUCCESS', '2026-09-01 10:00:00.000000', 1, 'SYNCED'), "
            "('m2', 'b', 'LINUX', 'NEVER_SCANNED', NULL, 1, 'SYNCED')"
        ))
        connection.execute(text(
            "INSERT INTO cve_findings (id, machine_id, cve_id, cvss_score, severity, source, "
            "sync_status) VALUES ('f1', 'm1', 'CVE-A', 7.5, 'HIGH', 'osv', 'SYNCED'), "
            "('f2', 'm2', 'CVE-B', 7.5, 'HIGH', 'osv', 'SYNCED')"
        ))

    upgrade_to_head(engine)

    assert {"scan_runs", "scan_finding_changes"} <= set(inspect(engine).get_table_names())
    with Session(engine) as session:
        repo = Repository(session)
        (m1,) = repo.get_findings_for_machine("m1")
        (m2,) = repo.get_findings_for_machine("m2")
        assert m1.first_seen_at == datetime(2026, 9, 1, 10, 0)
        assert m2.first_seen_at is not None
        assert repo.list_scan_runs("m1") == []
        # So the first scan after upgrading is a baseline.
        assert repo.save_findings("m1", []).baseline


def test_the_scan_history_migration_round_trips(tmp_path):
    from alembic import command

    from app.data.migrations_runtime import alembic_config, upgrade_to_head

    engine = create_engine(f"sqlite:///{(tmp_path / 'history.db').as_posix()}")
    upgrade_to_head(engine)
    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.downgrade(cfg, "b3abe7f1ff0c")
    assert not {"scan_runs", "scan_finding_changes"} & set(inspect(engine).get_table_names())
    assert "first_seen_at" not in {c["name"] for c in inspect(engine).get_columns("cve_findings")}

    with engine.begin() as connection:
        cfg = alembic_config()
        cfg.attributes["connection"] = connection
        command.upgrade(cfg, "head")


# --------------------------------------------------------------------------- #
# Req 18.10: a failed run says why
# --------------------------------------------------------------------------- #


def test_a_failed_run_keeps_the_reason_it_failed():
    """Validates Req 18.10."""
    with _session() as session:
        _machine(session)
        repo = Repository(session)

        repo.record_scan_run(
            "m1",
            status=ScanStatus.AUTH_FAILURE,
            sources_ok=True,
            scanned_at=datetime.now(timezone.utc),
            diff=None,
            keep=50,
            error_detail="password authentication rejected for scanner@web-01.lan",
        )
        session.flush()

        run = repo.list_scan_runs("m1", 10)[0]
        assert run.status is ScanStatus.AUTH_FAILURE
        assert (
            run.error_detail
            == "password authentication rejected for scanner@web-01.lan"
        )


def test_a_successful_run_keeps_no_reason():
    """Validates Req 18.10: a run that worked has nothing to explain."""
    with _session() as session:
        _machine(session)
        repo = Repository(session)
        diff = repo.save_findings("m1", [_finding("CVE-2026-0001")])

        repo.record_scan_run(
            "m1",
            status=ScanStatus.SUCCESS,
            sources_ok=True,
            scanned_at=diff.scanned_at,
            diff=diff,
            keep=50,
            # Even where a caller passes one through, success drops it.
            error_detail="stale message from an earlier attempt",
        )
        session.flush()

        assert repo.list_scan_runs("m1", 10)[0].error_detail is None


def test_a_chatty_host_cannot_fill_the_history_row():
    """Validates Req 18.10: the reason is bounded."""
    with _session() as session:
        _machine(session)
        repo = Repository(session)

        repo.record_scan_run(
            "m1",
            status=ScanStatus.CONNECTION_FAILURE,
            sources_ok=True,
            scanned_at=datetime.now(timezone.utc),
            diff=None,
            keep=50,
            error_detail="x" * 5000,
        )
        session.flush()

        detail = repo.list_scan_runs("m1", 10)[0].error_detail
        assert len(detail) == 500
        assert detail.endswith("…")
