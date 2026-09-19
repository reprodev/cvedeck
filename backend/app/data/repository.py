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
from typing import Iterable, Iterator

from sqlalchemy import String, case, cast, func, select
from sqlalchemy.orm import Session, selectinload

from ..enums import (
    SEVERITY_RANK,
    FeedStatus,
    FindingChange,
    Platform,
    ScanStatus,
    Severity,
    SyncStatus,
)
from ..models import Inventory as DomainInventory
from ..models import OsInfo
from ..models import Package as DomainPackage
from ..package_identifier import parse_package_name
from .schema import (
    CveFinding,
    EpssScore,
    FeedRefresh,
    Inventory,
    KevEntry,
    Package,
    RemediationRecord,
    ScanFindingChange,
    ScanRun,
    SshHostKey,
    TargetMachine,
)


#: Maximum CVE ids bound into a single ``IN`` clause. Kept well under SQLite's
#: 999-parameter ceiling (its limit before 3.32) so enrichment lookups do not
#: depend on the host's SQLite build.
_IN_CLAUSE_CHUNK = 500

#: How many findings a fleet-wide reapply keeps resident at once (Req 10.15).
#: Larger than the ``IN``-clause chunk because nothing is bound as a parameter
#: here -- it only bounds how much of the result set the session holds.
_ENRICHMENT_CHUNK = 1000


def _as_utc(moment: datetime) -> datetime:
    """Compare stored and in-session times alike.

    SQLite hands datetimes back naive, while a row written earlier in the same
    session still holds the aware value it was given. Both are UTC.
    """
    return moment if moment.tzinfo is not None else moment.replace(tzinfo=timezone.utc)


def _snapshot(finding: FindingInput | CveFinding) -> FindingSnapshot:
    return FindingSnapshot(
        cve_id=finding.cve_id,
        package_identifier=finding.package_identifier,
        severity=finding.severity,
        cvss_score=finding.cvss_score,
        kev_listed=finding.kev_listed,
    )


def _host_key_name(hostname: str) -> str:
    """The form a hostname is pinned under; see ``SshHostKey``."""
    return hostname.strip().lower()


def _new_id() -> str:
    """Generate a unique string primary key for a new row."""
    return uuid.uuid4().hex


#: How much of a failure message a scan run keeps (Req 18.10). Long enough for
#: "SSH host key for host:22 has changed: pinned ..., presented ...", short
#: enough that a host echoing a wall of text cannot bloat the history.
_ERROR_DETAIL_LIMIT = 500


def _truncate(text: str | None, limit: int) -> str | None:
    """Trim a message to ``limit`` characters, marking that it was cut."""
    if text is None:
        return None
    stripped = text.strip()
    if not stripped:
        return None
    return stripped if len(stripped) <= limit else stripped[: limit - 1] + "…"


@dataclass(frozen=True)
class FindingInput:
    """A CVE finding to persist for a machine.

    Mirrors the persistable fields of a matcher-produced finding without
    depending on the matcher's own types. ``package_identifier`` is set for
    OSV/package-level findings (Req 7.1) and ``dependency_path_id`` optionally
    links the finding to a stored ``DependencyPath`` (Req 5.5, 7.2).
    """

    cve_id: str
    #: ``None`` when the advisory publishes no score (Req 2.7).
    cvss_score: float | None
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


FindingKey = tuple[str, str | None]


def finding_key(cve_id: str, package_identifier: str | None) -> FindingKey:
    """What makes two scans' findings the same finding (Req 18.2).

    The CVE and the package *name*. The version is left out on purpose: a
    package upgraded to a version that is still vulnerable is the same
    unresolved problem, not one finding resolved and another new.
    """
    return cve_id, parse_package_name(package_identifier)


@dataclass(frozen=True)
class FindingSnapshot:
    """What a finding was, kept on a scan run's change rows."""

    cve_id: str
    package_identifier: str | None
    severity: Severity
    cvss_score: float | None
    kev_listed: bool | None


@dataclass(frozen=True)
class FindingDiff:
    """How a successful scan's findings differ from the machine's previous ones.

    ``baseline`` marks a machine's first successful run, which has nothing to
    compare with, so ``new`` and ``resolved`` are empty (Req 18.4).
    ``resolved_assessed`` is ``False`` for a partial scan, which never resolves
    anything (Req 18.3).
    """

    new: tuple[FindingSnapshot, ...]
    resolved: tuple[FindingSnapshot, ...]
    baseline: bool
    resolved_assessed: bool
    scanned_at: datetime


@dataclass(frozen=True)
class RemediationInput:
    """A remediation record's mutable state (status + free-text note)."""

    status: object  # RemediationStatus; kept loose to avoid a hard import cycle
    note: str


@dataclass(frozen=True)
class SeverityCounts:
    """CVE counts for a machine grouped by ``Severity`` (Req 3.2).

    Five counts, in ranking order. ``unscored`` is not a sub-total of the
    others: a finding is counted in exactly one of the five, so the sum is
    still the finding total (Req 10.11).
    """

    critical: int = 0
    unscored: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0

    @property
    def total(self) -> int:
        """Total number of findings across all severity levels."""
        return (
            self.critical + self.unscored + self.high + self.medium + self.low
        )


#: The rank keyed by the string actually stored in the severity column.
#:
#: SQLAlchemy's Enum persists a member's *name*, so the column holds
#: "CRITICAL", not "critical". Passing ``SEVERITY_RANK`` itself to ``case()``
#: binds the members, which render as their *values* -- so no WHEN ever matched,
#: every row took the ELSE, and the ordering silently did nothing while still
#: producing a plausible-looking order from the tiebreakers underneath it.
_SEVERITY_RANK_BY_STORED_NAME: dict[str, int] = {
    member.name: rank for member, rank in SEVERITY_RANK.items()
}


def severity_order(column):
    """Rank a Severity column for ORDER BY: Critical, Unscored, High, Med, Low.

    Ranking by ``cvss_score DESC`` alone stopped being possible once a finding
    may have no score, and falling back to the store's default null ordering
    would not be the same answer twice: SQLite sorts NULL lowest, so DESC
    trails it, while PostgreSQL puts NULLS FIRST by default on DESC. Two
    supported deployments would rank the same fleet differently (Req 10.12).

    Ordering by this rank first also puts an unscored finding where it belongs
    -- below Critical, above High -- rather than wherever its absent number
    happened to land (Req 10.11).

    The column is cast to text so the comparison is against the stored label on
    both dialects -- a plain string on SQLite, the enum label on PostgreSQL --
    rather than against a value SQLAlchemy would render from the enum member.
    """
    return case(
        _SEVERITY_RANK_BY_STORED_NAME,
        value=cast(column, String),
        else_=len(SEVERITY_RANK),
    )


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

    def save_finding(
        self,
        machine_id: str,
        finding: FindingInput,
        first_seen_at: datetime | None = None,
    ) -> CveFinding:
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
            first_seen_at=first_seen_at or datetime.now(timezone.utc),
            sync_status=SyncStatus.PENDING_SYNC,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def save_findings(
        self,
        machine_id: str,
        findings: list[FindingInput],
        *,
        suppress_resolved: bool = False,
        scanned_at: datetime | None = None,
    ) -> FindingDiff:
        """Persist a scan's findings for a machine and say what changed (Req 2.3, 18).

        A complete scan replaces the machine's findings, so a re-scan reflects
        the host as it is now rather than accumulating duplicates. Each finding
        keeps the ``first_seen_at`` of the finding it matches by
        :func:`finding_key` (Req 18.5).

        ``suppress_resolved`` is for a partial scan, one where a configured
        source did not answer (Req 18.3). Nothing is resolved by it: a finding
        it did not report is kept as it was, because an unreachable source is
        not a patch. Findings it did report are written as usual, and new ones
        are still new.

        A machine with no successful scan run yet gets a baseline, with no new
        or resolved findings, so its first scan after upgrading does not report
        every finding as new (Req 18.4).
        """
        now = scanned_at or datetime.now(timezone.utc)
        baseline = not self._has_successful_run(machine_id)

        old_rows = list(
            self._session.execute(
                select(CveFinding).where(CveFinding.machine_id == machine_id)
            ).scalars()
        )
        old_by_key: dict[FindingKey, CveFinding] = {}
        first_seen: dict[FindingKey, datetime] = {}
        for row in old_rows:
            key = finding_key(row.cve_id, row.package_identifier)
            old_by_key.setdefault(key, row)
            if key not in first_seen or _as_utc(row.first_seen_at) < _as_utc(first_seen[key]):
                first_seen[key] = row.first_seen_at

        new_keys = {finding_key(f.cve_id, f.package_identifier) for f in findings}
        stale = [
            row
            for row in old_rows
            if not suppress_resolved
            or finding_key(row.cve_id, row.package_identifier) in new_keys
        ]
        if stale:
            from sqlalchemy import delete

            self._session.execute(
                delete(CveFinding).where(CveFinding.id.in_([r.id for r in stale]))
            )
            self._session.flush()

        new: list[FindingSnapshot] = []
        reported: set[FindingKey] = set()
        for finding in findings:
            key = finding_key(finding.cve_id, finding.package_identifier)
            self.save_finding(machine_id, finding, first_seen.get(key, now))
            if key not in old_by_key and key not in reported:
                new.append(_snapshot(finding))
            reported.add(key)

        resolved: list[FindingSnapshot] = []
        if not suppress_resolved:
            resolved = [
                _snapshot(row) for key, row in old_by_key.items() if key not in new_keys
            ]

        return FindingDiff(
            new=() if baseline else tuple(new),
            resolved=() if baseline else tuple(resolved),
            baseline=baseline,
            resolved_assessed=not suppress_resolved,
            scanned_at=now,
        )

    # ------------------------------------------------------------------ #
    # Scan history (Req 18)
    # ------------------------------------------------------------------ #
    def _has_successful_run(self, machine_id: str) -> bool:
        stmt = (
            select(ScanRun.id)
            .where(ScanRun.machine_id == machine_id)
            .where(ScanRun.status == ScanStatus.SUCCESS)
            .limit(1)
        )
        return self._session.execute(stmt).first() is not None

    def record_scan_run(
        self,
        machine_id: str,
        *,
        status: ScanStatus,
        sources_ok: bool,
        scanned_at: datetime,
        diff: FindingDiff | None,
        keep: int,
        error_detail: str | None = None,
    ) -> ScanRun:
        """Record one scan attempt and what it changed (Req 18.1, 18.2).

        A failed attempt is recorded too, with no counts: the findings it
        leaves in place are the previous scan's, and saying "0 new" would claim
        an answer it does not have. Keeps the newest ``keep`` runs for the
        machine, and never prunes its latest successful one, which the "new"
        badges are read from (Req 18.7).

        ``error_detail`` is why a failed attempt failed (Req 18.10), truncated
        so a chatty host cannot fill the row, and dropped entirely on success:
        a successful run has nothing to explain.
        """
        succeeded = status is ScanStatus.SUCCESS and diff is not None
        baseline = succeeded and diff.baseline
        compared = succeeded and not baseline
        run = ScanRun(
            id=_new_id(),
            machine_id=machine_id,
            scanned_at=scanned_at,
            status=status,
            sources_ok=sources_ok,
            finding_count=(
                self.count_findings_for_machine(machine_id) if succeeded else 0
            ),
            new_count=len(diff.new) if compared else None,
            resolved_count=(
                len(diff.resolved) if compared and diff.resolved_assessed else None
            ),
            baseline=baseline,
            sync_status=SyncStatus.PENDING_SYNC,
            error_detail=(
                None
                if status is ScanStatus.SUCCESS
                else _truncate(error_detail, _ERROR_DETAIL_LIMIT)
            ),
        )
        self._session.add(run)
        if compared:
            for kind, snapshots in (
                (FindingChange.NEW, diff.new),
                (FindingChange.RESOLVED, diff.resolved),
            ):
                for snap in snapshots:
                    self._session.add(
                        ScanFindingChange(
                            id=_new_id(),
                            scan_run_id=run.id,
                            change=kind,
                            cve_id=snap.cve_id,
                            package_identifier=snap.package_identifier,
                            severity=snap.severity,
                            cvss_score=snap.cvss_score,
                            kev_listed=snap.kev_listed,
                            sync_status=SyncStatus.PENDING_SYNC,
                        )
                    )
        self._session.flush()
        self._prune_scan_runs(machine_id, keep)
        return run

    def _prune_scan_runs(self, machine_id: str, keep: int) -> None:
        runs = self.list_scan_runs(machine_id)
        latest_success = next(
            (r.id for r in runs if r.status is ScanStatus.SUCCESS), None
        )
        for run in runs[max(keep, 1):]:
            if run.id != latest_success:
                # Through the session, so the ORM cascade removes its changes
                # on SQLite, which does not enforce ON DELETE by default.
                self._session.delete(run)
        self._session.flush()

    def list_scan_runs(
        self, machine_id: str, limit: int | None = None
    ) -> list[ScanRun]:
        """A machine's scan runs, newest first."""
        stmt = (
            select(ScanRun)
            .where(ScanRun.machine_id == machine_id)
            .order_by(ScanRun.scanned_at.desc())
        )
        if limit is not None:
            stmt = stmt.limit(limit)
        return list(self._session.execute(stmt).scalars())

    def get_scan_run(self, machine_id: str, run_id: str) -> ScanRun | None:
        run = self._session.get(ScanRun, run_id)
        return run if run is not None and run.machine_id == machine_id else None

    def get_scan_changes(self, run_id: str) -> list[ScanFindingChange]:
        """A run's changes: new before resolved, then highest CVSS first."""
        stmt = (
            select(ScanFindingChange)
            .where(ScanFindingChange.scan_run_id == run_id)
            .order_by(
                ScanFindingChange.change,
                severity_order(ScanFindingChange.severity),
                ScanFindingChange.cvss_score.desc().nullsfirst(),
                ScanFindingChange.cve_id,
            )
        )
        return list(self._session.execute(stmt).scalars())

    def latest_successful_runs(self) -> dict[str, ScanRun]:
        """Each machine's most recent successful run, in one query."""
        latest = (
            select(ScanRun.machine_id, func.max(ScanRun.scanned_at).label("at"))
            .where(ScanRun.status == ScanStatus.SUCCESS)
            .group_by(ScanRun.machine_id)
            .subquery()
        )
        stmt = select(ScanRun).join(
            latest,
            (ScanRun.machine_id == latest.c.machine_id)
            & (ScanRun.scanned_at == latest.c.at),
        )
        return {run.machine_id: run for run in self._session.execute(stmt).scalars()}

    def latest_successful_run(self, machine_id: str) -> ScanRun | None:
        stmt = (
            select(ScanRun)
            .where(ScanRun.machine_id == machine_id)
            .where(ScanRun.status == ScanStatus.SUCCESS)
            .order_by(ScanRun.scanned_at.desc())
            .limit(1)
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def new_finding_keys(self, run: ScanRun | None) -> set[FindingKey]:
        """The findings a run reported as new, by :func:`finding_key`."""
        if run is None:
            return set()
        stmt = select(
            ScanFindingChange.cve_id, ScanFindingChange.package_identifier
        ).where(
            ScanFindingChange.scan_run_id == run.id,
            ScanFindingChange.change == FindingChange.NEW,
        )
        return {finding_key(cve, pkg) for cve, pkg in self._session.execute(stmt)}

    def new_finding_keys_for_runs(
        self, runs: "Iterable[ScanRun]"
    ) -> dict[str, set[FindingKey]]:
        """What each run reported as new, keyed by machine (Req 18.6).

        The fleet-wide counterpart of :meth:`new_finding_keys`, so a list
        covering every machine costs one query rather than one per machine.
        Chunked like :meth:`_lookup_by_cve_ids`: a fleet has more runs than
        SQLite will bind parameters for.
        """
        by_run = {run.id: run.machine_id for run in runs}
        if not by_run:
            return {}
        keys: dict[str, set[FindingKey]] = {
            machine_id: set() for machine_id in by_run.values()
        }
        run_ids = list(by_run)
        for start in range(0, len(run_ids), _IN_CLAUSE_CHUNK):
            chunk = run_ids[start : start + _IN_CLAUSE_CHUNK]
            stmt = select(
                ScanFindingChange.scan_run_id,
                ScanFindingChange.cve_id,
                ScanFindingChange.package_identifier,
            ).where(
                ScanFindingChange.scan_run_id.in_(chunk),
                ScanFindingChange.change == FindingChange.NEW,
            )
            for run_id, cve_id, package_identifier in self._session.execute(stmt):
                keys[by_run[run_id]].add(finding_key(cve_id, package_identifier))
        return keys

    def get_findings_for_machine(
        self, machine_id: str, severity: Severity | None = None
    ) -> list[CveFinding]:
        """Read the CVE findings for a machine (Req 3.4, 6.2).

        When ``severity`` is provided, only findings of that severity are
        returned (Req 3.3, 6.3). Ordered by severity rank and then descending
        CVSS score, so the most severe findings surface first and an unscored
        one is not buried by having no number to sort on (Req 10.11, 10.12).
        """
        stmt = select(CveFinding).where(CveFinding.machine_id == machine_id)
        if severity is not None:
            stmt = stmt.where(CveFinding.severity == severity)
        stmt = stmt.order_by(
            severity_order(CveFinding.severity),
            # nullsfirst, explicitly: within a band a null score means the band
            # is known and the magnitude is not, and a qualitative "High" could
            # be an 8.9. Sorting it below every measured High -- which is what
            # SQLite's default would do -- is the silent demotion this release
            # removes (Req 10.12).
            CveFinding.cvss_score.desc().nullsfirst(),
            CveFinding.cve_id,
        )
        return list(self._session.execute(stmt).scalars().all())

    def count_findings_for_machine(
        self, machine_id: str, severity: Severity | None = None
    ) -> int:
        """How many findings a machine has, without loading them.

        The matched pair of :meth:`get_findings_for_machine`: same filters, but
        it answers the question a scan run asks after every scan, where the rows
        themselves are never looked at.
        """
        stmt = select(func.count(CveFinding.id)).where(
            CveFinding.machine_id == machine_id
        )
        if severity is not None:
            stmt = stmt.where(CveFinding.severity == severity)
        return int(self._session.execute(stmt).scalar_one() or 0)

    def all_finding_cve_ids(self) -> set[str]:
        """Every distinct CVE id across the stored findings (Req 10.15).

        Distinct in the query rather than in Python: a fleet's findings repeat
        the same CVE across every host that carries the package, and the point
        of this set is to ask the feed caches about each id once.
        """
        stmt = select(CveFinding.cve_id).distinct()
        return {row.upper() for row in self._session.execute(stmt).scalars() if row}

    def iter_findings_for_enrichment(
        self, *, chunk_size: int = _ENRICHMENT_CHUNK
    ) -> Iterator[CveFinding]:
        """Stream the stored findings so their intel fields can be reapplied.

        Streamed rather than returned as a list (Req 10.15): a fleet-wide
        reapply touches every finding the deployment has ever recorded, and
        loading a large fleet's worth into the session at once to update four
        columns is a lot of memory for no benefit. ``yield_per`` keeps one chunk
        resident at a time.

        The rows are live ORM objects, so a caller that assigns to them is
        writing through the unit of work; committing stays the caller's job, as
        it is everywhere else in this class.
        """
        stmt = (
            select(CveFinding)
            .where(CveFinding.cve_id.is_not(None))
            .order_by(CveFinding.id)
            .execution_options(yield_per=chunk_size)
        )
        yield from self._session.execute(stmt).scalars()

    def latest_remediation_records(self) -> dict[str, dict[str, RemediationRecord]]:
        """Every machine's current remediation record per CVE, in one query.

        The fleet-wide counterpart of the per-machine map the read routes build.
        Ordered by ``updated_at`` so the newest record for a (machine, CVE) wins,
        which is the same tie-break the per-machine version applies.
        """
        stmt = select(RemediationRecord).order_by(
            RemediationRecord.machine_id, RemediationRecord.updated_at
        )
        by_machine: dict[str, dict[str, RemediationRecord]] = {}
        for record in self._session.execute(stmt).scalars():
            by_machine.setdefault(record.machine_id, {})[record.cve_id] = record
        return by_machine

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
            unscored=tally.get(Severity.UNSCORED, 0),
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
                        unscored=tally.get(Severity.UNSCORED, 0),
                        high=tally.get(Severity.HIGH, 0),
                        medium=tally.get(Severity.MEDIUM, 0),
                        low=tally.get(Severity.LOW, 0),
                    ),
                    kev_count=kev_per_machine.get(machine.id, 0),
                )
            )
        return entries

    # ------------------------------------------------------------------ #
    # Pinned SSH host keys (Req 17)
    # ------------------------------------------------------------------ #
    def get_host_key(self, hostname: str, port: int) -> SshHostKey | None:
        """The key pinned for an address, or ``None``."""
        stmt = select(SshHostKey).where(
            SshHostKey.hostname == _host_key_name(hostname),
            SshHostKey.port == port,
        )
        return self._session.execute(stmt).scalar_one_or_none()

    def pin_host_key(
        self,
        hostname: str,
        port: int,
        *,
        key_type: str,
        key_base64: str,
        fingerprint_sha256: str,
    ) -> SshHostKey:
        """Pin a key for an address that has none (Req 17.1).

        Never replaces an existing pin: changing which key a host is trusted
        with goes through :meth:`forget_host_key`, a separate and deliberate
        act (Req 17.7).
        """
        if self.get_host_key(hostname, port) is not None:
            raise ValueError(f"a host key is already pinned for {hostname}:{port}")
        now = datetime.now(timezone.utc)
        row = SshHostKey(
            id=_new_id(),
            hostname=_host_key_name(hostname),
            port=port,
            key_type=key_type,
            key_base64=key_base64,
            fingerprint_sha256=fingerprint_sha256,
            first_seen_at=now,
            last_seen_at=now,
        )
        self._session.add(row)
        self._session.flush()
        return row

    def touch_host_key(self, hostname: str, port: int) -> None:
        """Record that the pinned key was presented again."""
        row = self.get_host_key(hostname, port)
        if row is not None:
            row.last_seen_at = datetime.now(timezone.utc)
            self._session.flush()

    def forget_host_key(self, hostname: str, port: int) -> bool:
        """Remove an address's pin; ``False`` when there was none (Req 17.7)."""
        row = self.get_host_key(hostname, port)
        if row is None:
            return False
        self._session.delete(row)
        self._session.flush()
        return True

    def host_key_pins(self, port: int) -> dict[str, SshHostKey]:
        """Every pin on a port, by lower-cased hostname.

        One query for the whole fleet view rather than one per machine. The row
        rather than just the fingerprint, because the machine page shows the key
        *type* beside it -- that is what says which ``/etc/ssh/ssh_host_*.pub``
        an operator should run ``ssh-keygen -lf`` against (Req 17.8).
        """
        stmt = select(SshHostKey).where(SshHostKey.port == port)
        return {row.hostname: row for row in self._session.execute(stmt).scalars()}

    def list_host_keys(self) -> list[tuple[SshHostKey, str | None]]:
        """Every pin, with the id of the machine enrolled at its address (Req 17.10).

        Two queries, never one per pin. A pin whose address matches no enrolled
        machine comes back with ``None``: those are the ones with nowhere else to
        appear -- made by a connection test to an address never enrolled, or on a
        port the deployment has since moved off -- and they are the reason this
        listing exists.
        """
        pins = list(
            self._session.execute(
                select(SshHostKey).order_by(SshHostKey.hostname, SshHostKey.port)
            ).scalars()
        )
        if not pins:
            return []
        machines = self._session.execute(
            select(TargetMachine.hostname, TargetMachine.id)
        ).all()
        # Pins are stored lower-cased; machine hostnames are stored as entered.
        by_hostname = {hostname.strip().lower(): machine_id for hostname, machine_id in machines}
        return [(pin, by_hostname.get(pin.hostname)) for pin in pins]

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

