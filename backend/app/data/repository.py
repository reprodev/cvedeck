"""Repository read/write operations for the Local_Database.

This module provides the persistence layer's read/write surface on top of the
SQLAlchemy ORM schema in :mod:`app.data.schema`. It owns:

- Write operations that persist collected inventory (Req 1.6, 5.1), CVE findings
  (Req 2.3, 5.1), and manually maintained remediation records (Req 4.1, 4.3, 5.1)
  to the Local_Database.
- Read operations used by the dashboard and outward-facing API: reading an
  inventory back by machine (round-trip, Req 5.1), the machine list with
  severity-grouped CVE counts (Req 3.2, 6.1), and the per-machine CVE list
  (Req 3.4, 6.2).

The domain-side inventory produced by collectors (``app.models.Inventory``) is
mapped to/from the ORM rows here. Findings and remediation records are described
by lightweight input value objects (:class:`FindingInput`,
:class:`RemediationInput`) so this layer does not depend on later matcher/service
types; the ORM rows remain the single source of truth.

All rows are written with ``sync_status = PENDING_SYNC`` so the (separately
implemented) synchronization service can propagate them to the Online_Database.
Callers own transaction boundaries: methods ``flush`` to assign/verify state but
do not ``commit``, letting a caller batch several writes atomically.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from ..enums import FeedStatus, Platform, ScanStatus, Severity, SyncStatus
from ..models import Inventory as DomainInventory
from ..models import OsInfo
from ..models import Package as DomainPackage
from .schema import (
    CveFinding,
    EpssScore,
    FeedRefresh,
    Inventory,
    KevEntry,
    Package,
    RemediationRecord,
    TargetMachine,
)


#: Maximum CVE ids bound into a single ``IN`` clause. Kept well under SQLite's
#: 999-parameter ceiling (its limit before 3.32) so enrichment lookups do not
#: depend on the host's SQLite build.
_IN_CLAUSE_CHUNK = 500


def _new_id() -> str:
    """Generate a unique string primary key for a new row."""
    return uuid.uuid4().hex


@dataclass(frozen=True)
class FindingInput:
    """A CVE finding to persist for a machine.

    Mirrors the persistable fields of a matcher-produced finding without
    depending on the matcher's own types. ``package_identifier`` is set for
    OSV/package-level findings (Req 7.1) and ``dependency_path_id`` optionally
    links the finding to a stored ``DependencyPath`` (Req 5.5, 7.2).
    """

    cve_id: str
    cvss_score: float
    severity: Severity
    source: str
    package_identifier: str | None = None
    dependency_path_id: str | None = None
    # Threat-intel enrichment. ``None`` means the finding was not enriched --
    # distinct from ``kev_listed=False``, which means it was checked and is
    # genuinely absent from the KEV catalogue. Callers must not conflate them.
    kev_listed: bool | None = None
    kev_due_date: str | None = None
    epss_score: float | None = None
    epss_percentile: float | None = None


@dataclass(frozen=True)
class RemediationInput:
    """A remediation record's mutable state (status + free-text note)."""

    status: object  # RemediationStatus; kept loose to avoid a hard import cycle
    note: str


@dataclass(frozen=True)
class SeverityCounts:
    """CVE counts for a machine grouped by ``Severity`` (Req 3.2)."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        """Total number of findings across all severity levels."""
        return self.critical + self.high + self.medium + self.low


@dataclass(frozen=True)
class MachineListEntry:
    """A machine list row with its severity-grouped CVE counts (Req 3.2, 6.1)."""

    machine: TargetMachine
    cve_counts: SeverityCounts
    #: Findings on this machine confirmed as actively exploited (CISA KEV).
    #: Counts only ``kev_listed IS TRUE`` -- a NULL means the finding was never
    #: enriched, which is not evidence that it is safe, so it must not be
    #: folded into either side of this tally.
    kev_count: int = 0


class Repository:
    """Read/write operations against the Local_Database.

    A repository wraps a single SQLAlchemy :class:`~sqlalchemy.orm.Session`.
    Write methods ``flush`` so generated identifiers and constraints are applied,
    but leave the ``commit`` to the caller so multiple writes can be committed
    together.
    """

    def __init__(self, session: Session) -> None:
        self._session = session

    # ------------------------------------------------------------------ #
    # Inventory
    # ------------------------------------------------------------------ #
    def save_inventory(self, inventory: DomainInventory) -> Inventory:
        """Persist a collected domain inventory to the Local_Database.

        Maps ``app.models.Inventory`` (OS info + package list) to an
        ``Inventory`` row with child ``Package`` rows (Req 1.6, 5.1). The target
        machine referenced by ``inventory.machine_id`` must already exist.

        Args:
            inventory: The collected inventory to store.

        Returns:
            The persisted ``Inventory`` ORM row (with generated id).
        """
        collected_at = inventory.collected_at or datetime.now(timezone.utc)
        row = Inventory(
            id=_new_id(),
            machine_id=inventory.machine_id,
            os_name=inventory.os_info.name,
            os_version=inventory.os_info.version,
            kernel_version=inventory.kernel_version,
            reboot_required=inventory.reboot_required,
            collected_at=collected_at,
            sync_status=SyncStatus.PENDING_SYNC,
        )
        for pkg in inventory.packages:
            row.packages.append(
                Package(
                    id=_new_id(),
                    name=pkg.name,
                    version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    dependencies=",".join(pkg.dependencies) if pkg.dependencies else None,
                )
            )
        self._session.add(row)
        self._session.flush()
        return row

    def get_inventory(self, inventory_id: str) -> DomainInventory | None:
        """Read a stored inventory back as an ``app.models.Inventory``.

        Reconstructs the domain structure (round-trip, Req 5.1). Returns
        ``None`` if no inventory with ``inventory_id`` exists.
        """
        row = self._session.get(Inventory, inventory_id)
        if row is None:
            return None
        return self._to_domain_inventory(row)

    def get_latest_inventory_for_machine(
        self, machine_id: str
    ) -> DomainInventory | None:
        """Read back the most recently collected inventory for a machine.

        Returns ``None`` when the machine has no stored inventory.
        """
        stmt = (
            select(Inventory)
            .where(Inventory.machine_id == machine_id)
            .order_by(Inventory.collected_at.desc())
            .limit(1)
            .options(selectinload(Inventory.packages))
        )
        row = self._session.execute(stmt).scalar_one_or_none()
        if row is None:
            return None
        return self._to_domain_inventory(row)

    @staticmethod
    def _to_domain_inventory(row: Inventory) -> DomainInventory:
        """Map an ``Inventory`` ORM row to the domain ``Inventory`` model."""
        return DomainInventory(
            machine_id=row.machine_id,
            os_info=OsInfo(name=row.os_name, version=row.os_version),
            packages=[
                DomainPackage(
                    name=pkg.name,
                    version=pkg.version,
                    ecosystem=pkg.ecosystem,
                    dependencies=(
                        [d for d in pkg.dependencies.split(",") if d]
                        if pkg.dependencies
                        else []
                    ),
                )
                for pkg in row.packages
            ],
            collected_at=row.collected_at,
        )

    # ------------------------------------------------------------------ #
    def delete_findings_for_machine(self, machine_id: str) -> None:
        """Remove all existing CVE findings for a machine."""
        from sqlalchemy import delete

        stmt = delete(CveFinding).where(CveFinding.machine_id == machine_id)
        self._session.execute(stmt)
        self._session.flush()

    def save_finding(self, machine_id: str, finding: FindingInput) -> CveFinding:
        """Persist a single CVE finding for a machine (Req 2.3, 5.1)."""
        row = CveFinding(
            id=_new_id(),
            machine_id=machine_id,
            cve_id=finding.cve_id,
            cvss_score=finding.cvss_score,
            severity=finding.severity,
            source=finding.source,
            package_identifier=finding.package_identifier,
            dependency_path_id=finding.dependency_path_id,
            kev_listed=finding.kev_listed,
            kev_due_date=finding.kev_due_date,
            epss_score=finding.epss_score,
            epss_percentile=finding.epss_percentile,
            sync_status=SyncStatus.PENDING_SYNC,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def save_findings(
        self, machine_id: str, findings: list[FindingInput]
    ) -> list[CveFinding]:
        """Persist multiple CVE findings for a machine (Req 2.3, 5.1).

        Replaces any previously stored findings for this machine so subsequent
        scans reflect the latest scan state rather than accumulating duplicates.
        """
        self.delete_findings_for_machine(machine_id)
        return [self.save_finding(machine_id, f) for f in findings]

    def get_findings_for_machine(
        self, machine_id: str, severity: Severity | None = None
    ) -> list[CveFinding]:
        """Read the CVE findings for a machine (Req 3.4, 6.2).

        When ``severity`` is provided, only findings of that severity are
        returned (Req 3.3, 6.3). Ordered by descending CVSS score so the most
        severe findings surface first.
        """
        stmt = select(CveFinding).where(CveFinding.machine_id == machine_id)
        if severity is not None:
            stmt = stmt.where(CveFinding.severity == severity)
        stmt = stmt.order_by(CveFinding.cvss_score.desc(), CveFinding.cve_id)
        return list(self._session.execute(stmt).scalars().all())

    # ------------------------------------------------------------------ #
    # Threat-intel feed caches (KEV / EPSS)
    # ------------------------------------------------------------------ #
    def replace_kev_entries(self, entries: list[KevEntry]) -> int:
        """Replace the cached KEV catalogue wholesale.

        Replacement rather than upsert because CISA occasionally *removes*
        entries, and an upsert would leave a withdrawn CVE flagged as
        known-exploited forever. The delete and the insert share the caller's
        transaction, so a failure mid-refresh rolls back to the previous
        catalogue rather than leaving an empty one.

        Returns:
            The number of entries written.
        """
        from sqlalchemy import delete

        self._session.execute(delete(KevEntry))
        for entry in entries:
            self._session.add(entry)
        self._session.flush()
        return len(entries)

    def replace_epss_scores(self, scores: list[EpssScore]) -> int:
        """Replace the cached EPSS score set wholesale.

        Same reasoning as :meth:`replace_kev_entries`: EPSS is a complete daily
        snapshot, so merging yesterday's rows into today's would leave stale
        scores for any CVE dropped from the model.

        Returns:
            The number of scores written.
        """
        from sqlalchemy import delete

        self._session.execute(delete(EpssScore))
        # ``bulk_save_objects`` rather than per-row ``add``: the EPSS set is
        # ~280k rows, and the ORM's per-object identity bookkeeping dominates
        # the runtime at that size.
        self._session.bulk_save_objects(scores)
        self._session.flush()
        return len(scores)

    def record_feed_refresh(
        self,
        feed_name: str,
        *,
        status: FeedStatus,
        record_count: int = 0,
        error_detail: str | None = None,
    ) -> FeedRefresh:
        """Record the outcome of a feed refresh attempt.

        ``last_refreshed_at`` advances only on success, so the age reported by
        the dashboard is the age of the *data*, not of the last attempt. A feed
        that has been failing for a week therefore reports a week-old cache,
        which is the fact a user needs.
        """
        now = datetime.now(timezone.utc)
        row = self._session.get(FeedRefresh, feed_name)
        if row is None:
            row = FeedRefresh(feed_name=feed_name, last_status=status)
            self._session.add(row)

        row.last_status = status
        row.last_attempted_at = now
        if status is FeedStatus.OK:
            row.last_refreshed_at = now
            row.record_count = record_count
            row.error_detail = None
        else:
            row.error_detail = error_detail
        self._session.flush()
        return row

    def get_feed_refresh(self, feed_name: str) -> FeedRefresh | None:
        """Read one feed's refresh state, or ``None`` if it has never run."""
        return self._session.get(FeedRefresh, feed_name)

    def list_feed_refreshes(self) -> list[FeedRefresh]:
        """Read the refresh state of every feed that has been attempted."""
        stmt = select(FeedRefresh).order_by(FeedRefresh.feed_name)
        return list(self._session.execute(stmt).scalars().all())

    def get_kev_map(self, cve_ids: set[str]) -> dict[str, KevEntry]:
        """Look up KEV entries for the given CVE ids, keyed by id.

        An absent key means the CVE is not in the catalogue. Distinguishing
        that from "the catalogue is empty because the refresh failed" is the
        caller's job, using :meth:`get_feed_refresh`.
        """
        return {
            row.cve_id: row
            for row in self._lookup_by_cve_ids(KevEntry, KevEntry.cve_id, cve_ids)
        }

    def get_epss_map(self, cve_ids: set[str]) -> dict[str, EpssScore]:
        """Look up EPSS scores for the given CVE ids, keyed by CVE id."""
        return {
            row.cve_id: row
            for row in self._lookup_by_cve_ids(EpssScore, EpssScore.cve_id, cve_ids)
        }

    def _lookup_by_cve_ids(self, entity, column, cve_ids: set[str]) -> list:
        """Fetch rows of ``entity`` whose ``column`` is in ``cve_ids``.

        Chunked because a fleet-wide enrichment pass can ask about tens of
        thousands of CVE ids at once, and SQLite caps the number of bound
        parameters in a single statement (999 before 3.32). An unchunked
        ``IN`` clause works fine on a laptop's test fixture and then raises
        ``OperationalError`` on the first real fleet.
        """
        if not cve_ids:
            return []
        ids = list(cve_ids)
        rows: list = []
        for start in range(0, len(ids), _IN_CLAUSE_CHUNK):
            chunk = ids[start : start + _IN_CLAUSE_CHUNK]
            stmt = select(entity).where(column.in_(chunk))
            rows.extend(self._session.execute(stmt).scalars().all())
        return rows

    # ------------------------------------------------------------------ #
    # Remediation records
    # ------------------------------------------------------------------ #
    def add_remediation(
        self, machine_id: str, cve_id: str, remediation: RemediationInput
    ) -> RemediationRecord:
        """Persist a new remediation record for a CVE on a machine (Req 4.1)."""
        row = RemediationRecord(
            id=_new_id(),
            machine_id=machine_id,
            cve_id=cve_id,
            status=remediation.status,
            note=remediation.note,
            updated_at=datetime.now(timezone.utc),
            sync_status=SyncStatus.PENDING_SYNC,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def update_remediation(
        self, record_id: str, remediation: RemediationInput
    ) -> RemediationRecord | None:
        """Update an existing remediation record's status/note (Req 4.3).

        Refreshes ``updated_at`` and re-marks the row ``PENDING_SYNC`` so the
        change propagates. Returns ``None`` if no record with ``record_id``
        exists.
        """
        row = self._session.get(RemediationRecord, record_id)
        if row is None:
            return None
        row.status = remediation.status
        row.note = remediation.note
        row.updated_at = datetime.now(timezone.utc)
        row.sync_status = SyncStatus.PENDING_SYNC
        self._session.flush()
        return row

    def get_remediation(self, record_id: str) -> RemediationRecord | None:
        """Read a remediation record back by id (round-trip, Req 5.1)."""
        return self._session.get(RemediationRecord, record_id)

    def get_remediations_for_machine(
        self, machine_id: str
    ) -> list[RemediationRecord]:
        """Read all remediation records for a machine."""
        stmt = select(RemediationRecord).where(
            RemediationRecord.machine_id == machine_id
        )
        return list(self._session.execute(stmt).scalars().all())

    # ------------------------------------------------------------------ #
    # Dashboard / API read queries
    # ------------------------------------------------------------------ #
    def get_severity_counts(self, machine_id: str) -> SeverityCounts:
        """Tally a machine's CVE findings grouped by severity (Req 3.2)."""
        stmt = (
            select(CveFinding.severity, func.count(CveFinding.id))
            .where(CveFinding.machine_id == machine_id)
            .group_by(CveFinding.severity)
        )
        tally: dict[Severity, int] = {
            sev: count for sev, count in self._session.execute(stmt).all()
        }
        return SeverityCounts(
            critical=tally.get(Severity.CRITICAL, 0),
            high=tally.get(Severity.HIGH, 0),
            medium=tally.get(Severity.MEDIUM, 0),
            low=tally.get(Severity.LOW, 0),
        )

    def get_kev_count(self, machine_id: str) -> int:
        """Count a machine's findings confirmed as actively exploited.

        ``is_(True)`` rather than a truthiness test: ``kev_listed`` is
        three-valued, and NULL means the finding was never checked against the
        catalogue. Counting NULLs on either side would turn "unknown" into a
        claim.
        """
        stmt = (
            select(func.count(CveFinding.id))
            .where(CveFinding.machine_id == machine_id)
            .where(CveFinding.kev_listed.is_(True))
        )
        return int(self._session.execute(stmt).scalar_one() or 0)

    def list_machines(self) -> list[MachineListEntry]:
        """List scanned machines with severity-grouped CVE counts (Req 3.2, 6.1).

        Returns one entry per ``TargetMachine`` (ordered by hostname), each
        carrying the machine row and its :class:`SeverityCounts`. Machines with
        no findings report zero counts.
        """
        machines_stmt = select(TargetMachine).order_by(TargetMachine.hostname)
        machines = list(self._session.execute(machines_stmt).scalars().all())

        counts_stmt = select(
            CveFinding.machine_id,
            CveFinding.severity,
            func.count(CveFinding.id),
        ).group_by(CveFinding.machine_id, CveFinding.severity)

        per_machine: dict[str, dict[Severity, int]] = {}
        for machine_id, severity, count in self._session.execute(counts_stmt).all():
            per_machine.setdefault(machine_id, {})[severity] = count

        # One grouped query rather than a per-machine count, so the fleet view
        # stays a fixed number of statements regardless of fleet size.
        kev_stmt = (
            select(CveFinding.machine_id, func.count(CveFinding.id))
            .where(CveFinding.kev_listed.is_(True))
            .group_by(CveFinding.machine_id)
        )
        kev_per_machine: dict[str, int] = dict(
            self._session.execute(kev_stmt).all()
        )

        entries: list[MachineListEntry] = []
        for machine in machines:
            tally = per_machine.get(machine.id, {})
            entries.append(
                MachineListEntry(
                    machine=machine,
                    cve_counts=SeverityCounts(
                        critical=tally.get(Severity.CRITICAL, 0),
                        high=tally.get(Severity.HIGH, 0),
                        medium=tally.get(Severity.MEDIUM, 0),
                        low=tally.get(Severity.LOW, 0),
                    ),
                    kev_count=kev_per_machine.get(machine.id, 0),
                )
            )
        return entries

    def get_machine(self, machine_id: str) -> TargetMachine | None:
        """Read a single machine by id, or ``None`` if it does not exist."""
        return self._session.get(TargetMachine, machine_id)

    def upsert_target_machine(
        self,
        machine_id: str,
        hostname: str,
        platform: Platform,
        last_scan_status: ScanStatus = ScanStatus.NEVER_SCANNED,
    ) -> TargetMachine:
        """Insert or update a target machine in the fleet roster.

        Sets ``sync_status = PENDING_SYNC`` so newly registered fleet machines
        propagate to the Online_Database.
        """
        row = self._session.get(TargetMachine, machine_id)
        if row is None:
            row = TargetMachine(
                id=machine_id,
                hostname=hostname,
                platform=platform,
                last_scan_status=last_scan_status,
                sync_status=SyncStatus.PENDING_SYNC,
            )
            self._session.add(row)
        else:
            row.hostname = hostname
            row.platform = platform
            row.last_scan_status = last_scan_status
            row.sync_status = SyncStatus.PENDING_SYNC
        self._session.flush()
        return row

