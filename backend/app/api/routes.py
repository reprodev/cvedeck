"""Read routes for the Backend_API (machines and CVEs).

This router exposes the outward-facing read surface described in the design's
Backend API table:

- ``GET /api/machines`` -- list scanned machines with severity-grouped CVE
  counts (Req 6.1, 3.2).
- ``GET /api/machines/{machine_id}`` -- a single machine's summary; 404 when the
  machine is unknown (Req 6.4).
- ``GET /api/machines/{machine_id}/cves`` -- the CVE findings for a machine,
  optionally filtered by ``severity`` (Req 6.2, 6.3); 404 for an unknown
  machine.
- ``GET /api/cves`` -- all CVE findings across machines, optionally filtered by
  ``severity`` (Req 3.3, 6.3).

Every response is a Pydantic model serialized to structured JSON (Req 6.5). The
router reads through the :class:`~app.data.repository.Repository` over a
request-scoped session provided by :func:`app.api.dependencies.get_session`.

Action endpoints (POST scans/remediation/sync, PUT remediation) are intentionally
not defined here; task 8.2 will add an action router to the same app factory.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select
from sqlalchemy.orm import Session

from .. import config
from ..data.repository import MachineListEntry, Repository
from ..data.schema import CveFinding, RemediationRecord, TargetMachine
from ..enums import Severity
from ..models import Package as DomainPackage
from ..package_identifier import parse_fix, parse_package_name
from ..services.enrichment import FindingEnricher
from .dependencies import get_session
from .schemas import (
    CveFindingOut,
    FeedHealthOut,
    MachineSummary,
    SeverityCounts,
)

router = APIRouter(prefix="/api", tags=["read"])


def _get_repository(session: Session = Depends(get_session)) -> Repository:
    """Provide a :class:`Repository` bound to the request-scoped session."""
    return Repository(session)


def _to_machine_summary(entry: MachineListEntry) -> MachineSummary:
    """Map a repository machine-list entry to the API summary model."""
    machine = entry.machine
    counts = entry.cve_counts
    return MachineSummary(
        machine_id=machine.id,
        hostname=machine.hostname,
        platform=machine.platform,
        last_scan_status=machine.last_scan_status,
        last_scanned_at=machine.last_scanned_at,
        last_scan_sources_ok=machine.last_scan_sources_ok,
        cve_counts=SeverityCounts(
            critical=counts.critical,
            high=counts.high,
            medium=counts.medium,
            low=counts.low,
        ),
        kev_count=entry.kev_count,
    )


# One parser for the whole backend; see app/package_identifier.py for why the
# name is read from the right.
_parse_pkg_name = parse_package_name


def _build_dependency_maps(
    packages: list[DomainPackage],
) -> tuple[dict[str, list[str]], dict[str, list[str]]]:
    """Build direct and reverse dependency lookup maps from collected inventory packages."""
    direct_deps: dict[str, list[str]] = {}
    depended_on_by: dict[str, list[str]] = {}
    for pkg in packages:
        direct_deps[pkg.name] = pkg.dependencies
        for dep in pkg.dependencies:
            depended_on_by.setdefault(dep, []).append(pkg.name)
    return direct_deps, depended_on_by


def _to_finding_out(
    finding: CveFinding,
    remediation_by_cve: dict[str, RemediationRecord],
    direct_deps: dict[str, list[str]] | None = None,
    depended_on_by: dict[str, list[str]] | None = None,
) -> CveFindingOut:
    """Map a stored finding to the API finding model.

    Attaches the current remediation record for the finding's CVE when one
    exists for it on the same machine, plus dependency impact and blast-radius details.
    """
    record = remediation_by_cve.get(finding.cve_id)
    pkg_name = _parse_pkg_name(finding.package_identifier)
    fixed_version = _parse_fixed_version(finding.package_identifier)
    fix_status, fix_release, fix_release_version = parse_fix(finding.package_identifier)
    if fix_status == "available":
        # The host's own fix travels in fixed_version; the release fields are
        # only for a fix that lives somewhere else.
        fix_release = fix_release_version = None
        if fixed_version is None:
            fix_status = "none"

    deps = (direct_deps or {}).get(pkg_name, []) if pkg_name else []
    dependents = (depended_on_by or {}).get(pkg_name, []) if pkg_name else []
    blast_radius = (
        "high"
        if len(dependents) >= 10
        else ("medium" if len(dependents) >= 3 else "low")
    )

    return CveFindingOut(
        cve_id=finding.cve_id,
        severity=finding.severity,
        cvss_score=finding.cvss_score,
        package_identifier=finding.package_identifier,
        package_name=pkg_name,
        fixed_version=fixed_version,
        has_fix=fix_status == "available",
        fix_status=fix_status,
        fix_release=fix_release,
        fix_release_version=fix_release_version,
        remediation_status=record.status if record is not None else None,
        remediation_record_id=record.id if record is not None else None,
        remediation_note=record.note if record is not None else None,
        dependencies=deps,
        depended_on_by=dependents,
        blast_radius=blast_radius,
        kev_listed=finding.kev_listed,
        kev_due_date=finding.kev_due_date,
        epss_score=finding.epss_score,
        epss_percentile=finding.epss_percentile,
    )


def _parse_fixed_version(pkg_identifier: str | None) -> str | None:
    """Extract the fix version from a ``package_identifier`` display string.

    The matcher formats identifiers as
    ``"<ecosystem>:<name>@<version> (fixed in <fixed>)"``. Parsing that back
    into structure belongs here, once, rather than in every client: the
    frontend previously searched for the substring ``"fixed in"`` in nine
    separate places, which made the exact prose an unversioned API contract.
    """
    if not pkg_identifier:
        return None
    marker = "(fixed in "
    start = pkg_identifier.find(marker)
    if start == -1:
        return None
    remainder = pkg_identifier[start + len(marker) :]
    end = remainder.find(")")
    fixed = (remainder if end == -1 else remainder[:end]).strip()
    return fixed or None


def _remediation_map(
    session: Session, machine_id: str
) -> dict[str, RemediationRecord]:
    """Return the latest remediation record per CVE for a machine.

    When several remediation records exist for the same CVE, the most recently
    updated one wins.
    """
    stmt = (
        select(RemediationRecord)
        .where(RemediationRecord.machine_id == machine_id)
        .order_by(RemediationRecord.updated_at)
    )
    record_by_cve: dict[str, RemediationRecord] = {}
    for record in session.execute(stmt).scalars().all():
        record_by_cve[record.cve_id] = record
    return record_by_cve


@router.get("/machines", response_model=list[MachineSummary])
def list_machines(
    repo: Repository = Depends(_get_repository),
) -> list[MachineSummary]:
    """List scanned machines with severity-grouped CVE counts (Req 6.1, 3.2)."""
    return [_to_machine_summary(entry) for entry in repo.list_machines()]


@router.get("/machines/{machine_id}", response_model=MachineSummary)
def get_machine(
    machine_id: str,
    repo: Repository = Depends(_get_repository),
) -> MachineSummary:
    """Return a single machine's summary; 404 if unknown (Req 6.4)."""
    machine = repo.get_machine(machine_id)
    if machine is None:
        raise HTTPException(status_code=404, detail="Machine not found")
    return _to_machine_summary(
        MachineListEntry(
            machine=machine,
            cve_counts=repo.get_severity_counts(machine_id),
            kev_count=repo.get_kev_count(machine_id),
        )
    )


@router.get(
    "/machines/{machine_id}/cves", response_model=list[CveFindingOut]
)
def get_machine_cves(
    machine_id: str,
    severity: Severity | None = Query(default=None),
    repo: Repository = Depends(_get_repository),
    session: Session = Depends(get_session),
) -> list[CveFindingOut]:
    """Return a machine's CVEs, optionally severity-filtered (Req 6.2, 6.3).

    Returns 404 for an unknown machine (Req 6.4).
    """
    if repo.get_machine(machine_id) is None:
        raise HTTPException(status_code=404, detail="Machine not found")
    findings = repo.get_findings_for_machine(machine_id, severity)
    remediation_by_cve = _remediation_map(session, machine_id)
    inventory = repo.get_latest_inventory_for_machine(machine_id)
    direct_deps, depended_on_by = (
        _build_dependency_maps(inventory.packages)
        if inventory is not None
        else ({}, {})
    )
    return [
        _to_finding_out(f, remediation_by_cve, direct_deps, depended_on_by)
        for f in findings
    ]


@router.get("/cves", response_model=list[CveFindingOut])
def list_cves(
    severity: Severity | None = Query(default=None),
    session: Session = Depends(get_session),
) -> list[CveFindingOut]:
    """Return all CVE findings, optionally severity-filtered (Req 3.3, 6.3)."""
    stmt = select(CveFinding)
    if severity is not None:
        stmt = stmt.where(CveFinding.severity == severity)
    stmt = stmt.order_by(CveFinding.cvss_score.desc(), CveFinding.cve_id)
    findings = list(session.execute(stmt).scalars().all())

    # Remediation is keyed per machine+CVE; build a per-machine map lazily.
    remediation_maps: dict[str, dict[str, RemediationRecord]] = {}
    results: list[CveFindingOut] = []
    for finding in findings:
        if finding.machine_id not in remediation_maps:
            remediation_maps[finding.machine_id] = _remediation_map(
                session, finding.machine_id
            )
        results.append(
            _to_finding_out(finding, remediation_maps[finding.machine_id])
        )
    return results


@router.get("/feeds", response_model=list[FeedHealthOut], tags=["read"])
def list_feeds(
    session: Session = Depends(get_session),
) -> list[FeedHealthOut]:
    """Report the cache state of each threat-intel feed (KEV, EPSS).

    Both feeds are always reported, including one that has never been fetched,
    so the dashboard can say "KEV has never been refreshed" rather than
    omitting the row and implying the signal does not exist.
    """
    enricher = FindingEnricher(
        Repository(session), max_age_hours=config.feed_max_age_hours()
    )
    return [
        FeedHealthOut(
            feed_name=health.feed_name,
            status=health.status,
            last_refreshed_at=health.last_refreshed_at,
            last_attempted_at=health.last_attempted_at,
            record_count=health.record_count,
            error_detail=health.error_detail,
            stale=health.stale,
            usable=health.usable,
        )
        for health in enricher.all_feed_health()
    ]
