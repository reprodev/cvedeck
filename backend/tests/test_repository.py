"""Unit tests for the persistence-layer repository (task 3.2).

These verify the read/write operations against an in-memory SQLite engine:
inventory persist/round-trip (Req 1.6, 5.1), finding persistence and per-machine
reads (Req 2.3, 3.4, 6.2), remediation persist/update round-trip (Req 4.1, 4.3),
and the dashboard/API read queries: machine list with severity-grouped counts
(Req 3.2, 6.1) and severity-filtered per-machine CVEs (Req 3.3, 6.3).
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.data.repository import (
    FindingInput,
    RemediationInput,
    Repository,
)
from app.data.schema import Base, TargetMachine
from app.enums import (
    Platform,
    RemediationStatus,
    ScanStatus,
    Severity,
    SyncStatus,
)
from app.models import Inventory as DomainInventory
from app.models import OsInfo
from app.models import Package as DomainPackage


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


def _make_machine(
    session: Session,
    machine_id: str = "m1",
    hostname: str = "host.example.com",
    platform: Platform = Platform.LINUX,
) -> TargetMachine:
    machine = TargetMachine(
        id=machine_id,
        hostname=hostname,
        platform=platform,
        last_scan_status=ScanStatus.SUCCESS,
        last_scanned_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        sync_status=SyncStatus.PENDING_SYNC,
    )
    session.add(machine)
    session.flush()
    return machine


# --------------------------------------------------------------------------- #
# Inventory
# --------------------------------------------------------------------------- #
def test_save_and_read_back_inventory_round_trip(session, repo):
    _make_machine(session)
    now = datetime(2024, 3, 1, tzinfo=timezone.utc)
    domain_inv = DomainInventory(
        machine_id="m1",
        os_info=OsInfo(name="Ubuntu", version="22.04"),
        packages=[
            DomainPackage(name="requests", version="2.31.0", ecosystem="PyPI"),
            DomainPackage(name="openssl", version="3.0.2", ecosystem=None),
        ],
        collected_at=now,
    )

    row = repo.save_inventory(domain_inv)
    session.commit()

    loaded = repo.get_inventory(row.id)
    assert loaded is not None
    assert loaded.machine_id == "m1"
    assert loaded.os_info == OsInfo(name="Ubuntu", version="22.04")
    # SQLite stores naive datetimes; compare the wall-clock instant.
    assert loaded.collected_at.replace(tzinfo=timezone.utc) == now
    assert {(p.name, p.version, p.ecosystem) for p in loaded.packages} == {
        ("requests", "2.31.0", "PyPI"),
        ("openssl", "3.0.2", None),
    }


def test_saved_inventory_row_is_pending_sync(session, repo):
    _make_machine(session)
    row = repo.save_inventory(
        DomainInventory(
            machine_id="m1",
            os_info=OsInfo(name="Debian", version="12"),
            packages=[],
        )
    )
    assert row.sync_status == SyncStatus.PENDING_SYNC


def test_get_inventory_missing_returns_none(repo):
    assert repo.get_inventory("does-not-exist") is None


def test_get_latest_inventory_returns_most_recent(session, repo):
    _make_machine(session)
    repo.save_inventory(
        DomainInventory(
            machine_id="m1",
            os_info=OsInfo(name="Ubuntu", version="20.04"),
            packages=[],
            collected_at=datetime(2024, 1, 1, tzinfo=timezone.utc),
        )
    )
    repo.save_inventory(
        DomainInventory(
            machine_id="m1",
            os_info=OsInfo(name="Ubuntu", version="22.04"),
            packages=[],
            collected_at=datetime(2024, 6, 1, tzinfo=timezone.utc),
        )
    )
    session.commit()

    latest = repo.get_latest_inventory_for_machine("m1")
    assert latest is not None
    assert latest.os_info.version == "22.04"


def test_get_latest_inventory_missing_machine_returns_none(repo):
    assert repo.get_latest_inventory_for_machine("nope") is None


# --------------------------------------------------------------------------- #
# Findings
# --------------------------------------------------------------------------- #
def test_save_and_read_findings_for_machine(session, repo):
    _make_machine(session)
    repo.save_findings(
        "m1",
        [
            FindingInput(
                cve_id="CVE-2024-0001",
                cvss_score=9.1,
                severity=Severity.CRITICAL,
                source="osv",
                package_identifier="PyPI:requests",
            ),
            FindingInput(
                cve_id="CVE-2024-0002",
                cvss_score=5.0,
                severity=Severity.MEDIUM,
                source="nvd",
            ),
        ],
    )
    session.commit()

    findings = repo.get_findings_for_machine("m1")
    assert [f.cve_id for f in findings] == ["CVE-2024-0001", "CVE-2024-0002"]
    assert findings[0].package_identifier == "PyPI:requests"
    assert findings[0].sync_status == SyncStatus.PENDING_SYNC


def test_get_findings_filtered_by_severity(session, repo):
    _make_machine(session)
    repo.save_findings(
        "m1",
        [
            FindingInput("CVE-A", 9.5, Severity.CRITICAL, "nvd"),
            FindingInput("CVE-B", 7.5, Severity.HIGH, "nvd"),
            FindingInput("CVE-C", 9.0, Severity.CRITICAL, "osv"),
        ],
    )
    session.commit()

    critical = repo.get_findings_for_machine("m1", severity=Severity.CRITICAL)
    assert {f.cve_id for f in critical} == {"CVE-A", "CVE-C"}
    assert all(f.severity == Severity.CRITICAL for f in critical)


def test_get_findings_for_machine_with_none(repo):
    assert repo.get_findings_for_machine("unknown") == []


def test_rescan_replaces_findings_without_duplicates(session, repo):
    _make_machine(session)
    repo.save_findings(
        "m1",
        [
            FindingInput("CVE-2024-0001", 9.1, Severity.CRITICAL, "osv"),
            FindingInput("CVE-2024-0002", 5.0, Severity.MEDIUM, "nvd"),
        ],
    )
    session.commit()
    assert len(repo.get_findings_for_machine("m1")) == 2

    # Second scan discovers only CVE-2024-0001
    repo.save_findings(
        "m1",
        [
            FindingInput("CVE-2024-0001", 9.1, Severity.CRITICAL, "osv"),
        ],
    )
    session.commit()
    findings = repo.get_findings_for_machine("m1")
    assert len(findings) == 1
    assert findings[0].cve_id == "CVE-2024-0001"


# --------------------------------------------------------------------------- #
# Remediation records
# --------------------------------------------------------------------------- #
def test_add_and_read_remediation(session, repo):
    _make_machine(session)
    row = repo.add_remediation(
        "m1",
        "CVE-2024-0001",
        RemediationInput(status=RemediationStatus.OPEN, note="triage"),
    )
    session.commit()

    loaded = repo.get_remediation(row.id)
    assert loaded is not None
    assert loaded.status == RemediationStatus.OPEN
    assert loaded.note == "triage"
    assert loaded.sync_status == SyncStatus.PENDING_SYNC


def test_update_remediation_reflects_last_write(session, repo):
    _make_machine(session)
    row = repo.add_remediation(
        "m1",
        "CVE-2024-0001",
        RemediationInput(status=RemediationStatus.OPEN, note="triage"),
    )
    session.commit()

    updated = repo.update_remediation(
        row.id,
        RemediationInput(
            status=RemediationStatus.REMEDIATED, note="patched in 3.0.3"
        ),
    )
    session.commit()

    assert updated is not None
    reloaded = repo.get_remediation(row.id)
    assert reloaded.status == RemediationStatus.REMEDIATED
    assert reloaded.note == "patched in 3.0.3"


def test_update_missing_remediation_returns_none(repo):
    assert (
        repo.update_remediation(
            "nope", RemediationInput(status=RemediationStatus.OPEN, note="x")
        )
        is None
    )


def test_get_remediations_for_machine(session, repo):
    _make_machine(session)
    repo.add_remediation(
        "m1", "CVE-1", RemediationInput(RemediationStatus.OPEN, "a")
    )
    repo.add_remediation(
        "m1", "CVE-2", RemediationInput(RemediationStatus.IN_PROGRESS, "b")
    )
    session.commit()

    records = repo.get_remediations_for_machine("m1")
    assert {r.cve_id for r in records} == {"CVE-1", "CVE-2"}


# --------------------------------------------------------------------------- #
# Dashboard / API read queries
# --------------------------------------------------------------------------- #
def test_severity_counts_tally(session, repo):
    _make_machine(session)
    repo.save_findings(
        "m1",
        [
            FindingInput("CVE-1", 9.5, Severity.CRITICAL, "nvd"),
            FindingInput("CVE-2", 9.0, Severity.CRITICAL, "nvd"),
            FindingInput("CVE-3", 7.5, Severity.HIGH, "nvd"),
            FindingInput("CVE-4", 5.0, Severity.MEDIUM, "osv"),
            FindingInput("CVE-5", 1.0, Severity.LOW, "osv"),
        ],
    )
    session.commit()

    counts = repo.get_severity_counts("m1")
    assert (counts.critical, counts.high, counts.medium, counts.low) == (2, 1, 1, 1)
    assert counts.total == 5


def test_severity_counts_empty_machine_is_zero(session, repo):
    _make_machine(session)
    session.commit()
    counts = repo.get_severity_counts("m1")
    assert (counts.critical, counts.high, counts.medium, counts.low) == (0, 0, 0, 0)
    assert counts.total == 0


def test_list_machines_with_grouped_counts(session, repo):
    _make_machine(session, machine_id="m1", hostname="alpha")
    _make_machine(session, machine_id="m2", hostname="beta", platform=Platform.WINDOWS)
    repo.save_findings(
        "m1",
        [
            FindingInput("CVE-1", 9.5, Severity.CRITICAL, "nvd"),
            FindingInput("CVE-2", 7.5, Severity.HIGH, "nvd"),
        ],
    )
    # m2 has no findings
    session.commit()

    entries = repo.list_machines()
    # ordered by hostname: alpha then beta
    assert [e.machine.id for e in entries] == ["m1", "m2"]
    m1_entry, m2_entry = entries
    assert (m1_entry.cve_counts.critical, m1_entry.cve_counts.high) == (1, 1)
    assert m1_entry.cve_counts.total == 2
    assert m2_entry.cve_counts.total == 0


def test_get_machine_missing_returns_none(repo):
    assert repo.get_machine("nope") is None


def test_get_machine_returns_row(session, repo):
    _make_machine(session, machine_id="m9")
    session.commit()
    machine = repo.get_machine("m9")
    assert machine is not None
    assert machine.id == "m9"


def test_counting_findings_agrees_with_listing_them(session, repo):
    """The COUNT a scan run records must match what the machine's page lists."""
    _make_machine(session)
    _make_machine(session, machine_id="m2", hostname="other.example.com")
    repo.save_findings(
        "m1",
        [
            FindingInput("CVE-2024-0001", 9.1, Severity.CRITICAL, "osv"),
            FindingInput("CVE-2024-0002", 5.0, Severity.MEDIUM, "nvd"),
            FindingInput("CVE-2024-0003", 9.8, Severity.CRITICAL, "osv"),
        ],
    )
    # A second machine's findings must not be counted into the first's.
    repo.save_findings("m2", [FindingInput("CVE-2024-0009", 7.5, Severity.HIGH, "osv")])
    session.commit()

    assert repo.count_findings_for_machine("m1") == len(
        repo.get_findings_for_machine("m1")
    ) == 3
    assert repo.count_findings_for_machine("m1", Severity.CRITICAL) == len(
        repo.get_findings_for_machine("m1", Severity.CRITICAL)
    ) == 2
    assert repo.count_findings_for_machine("m2") == 1
    assert repo.count_findings_for_machine("unknown") == 0
