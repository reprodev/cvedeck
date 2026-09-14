"""Unit tests for the SQLAlchemy ORM schema (persistence layer).

These verify the models create tables cleanly against an in-memory SQLite
engine and that the schema exposes the extensibility fields required by the
design (sync_status on syncable rows, package_identifier / dependency_path_id
on CveFinding, and the DependencyPath.parent_path_id self-reference).
"""

from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine, inspect
from sqlalchemy.orm import Session

from app.data.schema import (
    Base,
    CveFinding,
    DependencyPath,
    Inventory,
    Package,
    RemediationRecord,
    TargetMachine,
)
from app.enums import (
    Platform,
    RemediationStatus,
    ScanStatus,
    Severity,
    SyncStatus,
)


@pytest.fixture()
def engine():
    """In-memory SQLite engine with all tables created."""
    eng = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(eng)
    return eng


def test_create_all_creates_every_table(engine):
    tables = set(inspect(engine).get_table_names())
    assert tables == {
        "target_machines",
        "inventories",
        "packages",
        "dependency_paths",
        "cve_findings",
        "remediation_records",
        # Threat-intel feed caches. Deliberately not syncable: they hold public
        # upstream data each instance refreshes for itself, not scan results.
        "kev_entries",
        "epss_scores",
        "feed_refreshes",
        # Access control (Req 16). Not syncable either: credentials belong to
        # this instance and must never be copied to the Online_Database.
        "users",
        "auth_sessions",
        "api_tokens",
        "auth_setup",
    }


def test_syncable_rows_have_sync_status_column(engine):
    inspector = inspect(engine)
    for table in (
        "target_machines",
        "inventories",
        "dependency_paths",
        "cve_findings",
        "remediation_records",
    ):
        columns = {c["name"] for c in inspector.get_columns(table)}
        assert "sync_status" in columns, f"{table} missing sync_status"


def test_cve_finding_has_extensibility_fields(engine):
    columns = {c["name"] for c in inspect(engine).get_columns("cve_findings")}
    assert "package_identifier" in columns
    assert "dependency_path_id" in columns


def test_dependency_path_has_self_reference(engine):
    fks = inspect(engine).get_foreign_keys("dependency_paths")
    self_refs = [fk for fk in fks if fk["referred_table"] == "dependency_paths"]
    assert self_refs, "DependencyPath should self-reference via parent_path_id"
    assert self_refs[0]["constrained_columns"] == ["parent_path_id"]


def test_full_graph_round_trip(engine):
    now = datetime(2024, 1, 1, tzinfo=timezone.utc)
    with Session(engine) as session:
        machine = TargetMachine(
            id="m1",
            hostname="host.example.com",
            platform=Platform.LINUX,
            last_scan_status=ScanStatus.SUCCESS,
            last_scanned_at=now,
            sync_status=SyncStatus.PENDING_SYNC,
        )
        inventory = Inventory(
            id="inv1",
            machine_id="m1",
            os_name="Ubuntu",
            os_version="22.04",
            collected_at=now,
            sync_status=SyncStatus.PENDING_SYNC,
        )
        inventory.packages.append(
            Package(
                id="pkg1",
                inventory_id="inv1",
                name="requests",
                version="2.31.0",
                ecosystem="PyPI",
            )
        )
        parent_path = DependencyPath(
            id="dp_parent",
            machine_id="m1",
            package_identifier="app",
            path_expression="app",
            parent_path_id=None,
            sync_status=SyncStatus.PENDING_SYNC,
        )
        child_path = DependencyPath(
            id="dp_child",
            machine_id="m1",
            package_identifier="PyPI:requests",
            path_expression="app -> requests",
            parent_path_id="dp_parent",
            sync_status=SyncStatus.PENDING_SYNC,
        )
        finding = CveFinding(
            id="f1",
            machine_id="m1",
            cve_id="CVE-2024-0001",
            cvss_score=9.1,
            severity=Severity.CRITICAL,
            source="osv",
            package_identifier="PyPI:requests",
            dependency_path_id="dp_child",
            sync_status=SyncStatus.PENDING_SYNC,
        )
        remediation = RemediationRecord(
            id="r1",
            machine_id="m1",
            cve_id="CVE-2024-0001",
            status=RemediationStatus.IN_PROGRESS,
            note="patch scheduled",
            updated_at=now,
            sync_status=SyncStatus.PENDING_SYNC,
        )
        session.add_all(
            [machine, inventory, parent_path, child_path, finding, remediation]
        )
        session.commit()

    with Session(engine) as session:
        loaded = session.get(CveFinding, "f1")
        assert loaded is not None
        assert loaded.severity == Severity.CRITICAL
        assert loaded.package_identifier == "PyPI:requests"
        assert loaded.dependency_path is not None
        assert loaded.dependency_path.parent_path is not None
        assert loaded.dependency_path.parent_path.id == "dp_parent"

        machine = session.get(TargetMachine, "m1")
        assert machine.platform == Platform.LINUX
        assert len(machine.inventories) == 1
        assert machine.inventories[0].packages[0].name == "requests"
        assert len(machine.remediation_records) == 1
