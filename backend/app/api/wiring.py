"""Concrete dependency wiring for deployments.

:mod:`app.api.dependencies` leaves ``get_scanner_engine`` and
``get_sync_service`` deliberately unconfigured -- a real scan needs collectors
that reach live hosts, and synchronization needs an environment-specific online
database. This module supplies the concrete implementations that a deployed
process installs via ``app.dependency_overrides`` (see
:func:`app.api.app.create_app` with ``wire_production=True``). Tests are
untouched: they create the app without production wiring and inject their own
stubs.

Two responsibilities live here that the route layer deliberately does not own:

- **Registering targets.** ``POST /api/scans`` accepts arbitrary targets, but
  :meth:`app.data.repository.Repository.save_inventory` writes a row whose
  foreign key references ``target_machines``. The engine therefore upserts each
  target before scanning it.
- **Committing.** ``Repository`` methods ``flush`` and leave transaction
  boundaries to the caller (see its module docstring), so the engine commits
  once the whole batch has been scanned.

- **Enriching.** Findings are enriched with cached KEV/EPSS signals after
  matching and before persistence (see :mod:`app.services.enrichment`). The
  enricher reads the same request session, so a scan and its enrichment commit
  together.

OSV.dev is always wired. NVD is opt-in via ``CVEDECK_NVD_ENABLED`` because
its rate limits (5 requests per 30s unkeyed) make an unkeyed fleet scan slow;
:class:`app.scanner.matcher.Matcher` treats the resulting ``None`` client as an
unconfigured source rather than an outage, so scans that leave it off are not
marked partial.
"""

from __future__ import annotations

from datetime import datetime, timezone
from functools import lru_cache

from fastapi import Depends, HTTPException
from sqlalchemy import Engine, create_engine
from sqlalchemy.orm import Session, sessionmaker

from .. import config
from ..data.migrations_runtime import upgrade_to_head
from ..data.repository import Repository
from ..data.schema import TargetMachine as TargetMachineRow
from ..enums import Platform, ScanStatus, SyncStatus
from ..models import Credentials, TargetMachine
from ..scanner.collectors import (
    InventoryCollector,
    LinuxCollector,
    WindowsCollector,
)
from ..scanner.engine import MachineScan, ScannerEngine, ScanResult
from ..scanner.matcher import NvdClient, OsvClient
from ..scanner.nvd_client import NvdHttpClient
from ..scanner.osv_client import OsvHttpClient
from ..services.enrichment import FindingEnricher
from ..services.sync import SyncService
from .dependencies import get_session


def build_collector(platform: Platform) -> InventoryCollector:
    """Return the collector for a platform, using the configured ports.

    Mirrors :func:`app.scanner.collectors.get_collector` but honors the
    deployment's port/scheme configuration, so a fleet that runs SSH on a
    non-standard port or WinRM over HTTPS needs no code change.
    """
    if platform is Platform.LINUX:
        return LinuxCollector(port=config.ssh_port())
    if platform is Platform.WINDOWS:
        return WindowsCollector(
            scheme=config.winrm_scheme(), port=config.winrm_port()
        )
    raise ValueError(f"unsupported platform: {platform!r}")


def build_osv_client() -> OsvClient:
    """Return an OSV.dev HTTP client configured from the deployment environment."""
    return OsvHttpClient(
        base_url=config.osv_api_url(),
        timeout=config.http_timeout(),
    )


def build_nvd_client() -> NvdClient | None:
    """Return an NVD client when the deployment has opted into OS-level matching.

    ``None`` when disabled, which the matcher reads as "source not configured"
    rather than "source down" -- so leaving NVD off does not brand every scan
    as partial.
    """
    if not config.nvd_enabled():
        return None
    return NvdHttpClient(
        config.nvd_api_url(),
        api_key=config.nvd_api_key(),
        timeout=config.http_timeout(),
    )


def _no_credentials(target: TargetMachine) -> Credentials:
    """Placeholder resolver used before the request installs real credentials.

    ``POST /api/scans`` calls :meth:`ScannerEngine.set_credentials` with the
    per-target credentials from the request body, replacing this resolver. If a
    caller ever scans without doing so, failing loudly beats connecting with
    nothing.
    """
    raise KeyError(f"no credentials supplied for target {target.id!r}")


class DeploymentScannerEngine(ScannerEngine):
    """Scanner engine that owns target registration and the transaction.

    Wraps :meth:`ScannerEngine.scan` so a batch is durable: targets are upserted
    first (the inventory foreign key requires them), the inherited per-target
    fault isolation runs untouched, and the whole batch commits at the end. A
    failure that escapes the engine leaves the transaction uncommitted, and the
    request-scoped session rolls it back.
    """

    def __init__(
        self,
        session: Session,
        *,
        osv: OsvClient | None = None,
        nvd: NvdClient | None = None,
    ) -> None:
        repository = Repository(session)
        super().__init__(
            repository=repository,
            credentials_for=_no_credentials,
            collector_factory=build_collector,
            record_status=self._record_scan_status,
            osv=osv if osv is not None else build_osv_client(),
            nvd=nvd if nvd is not None else build_nvd_client(),
            enricher=FindingEnricher(
                repository, max_age_hours=config.feed_max_age_hours()
            ),
        )
        self._session = session

    def scan(self, targets: list[TargetMachine]) -> ScanResult:
        """Register every target, scan the batch, then commit once."""
        for target in targets:
            self._upsert_machine(target)
        self._session.flush()
        result = super().scan(targets)
        self._session.commit()
        return result

    def _upsert_machine(self, target: TargetMachine) -> TargetMachineRow:
        """Insert or refresh the ``target_machines`` row for a target.

        A new row starts as ``NEVER_SCANNED``. ``_record_scan_status`` overwrites
        it with the real outcome within the same uncommitted transaction, so no
        reader ever observes the provisional value here -- but a host enrolled
        from network discovery keeps it until someone scans it, which is what
        stops the fleet view showing a red failure badge for a host nothing has
        tried to reach yet.
        """
        row = self._session.get(TargetMachineRow, target.id)
        if row is None:
            row = TargetMachineRow(
                id=target.id,
                hostname=target.hostname,
                platform=target.platform,
                last_scan_status=ScanStatus.NEVER_SCANNED,
                sync_status=SyncStatus.PENDING_SYNC,
            )
            self._session.add(row)
            return row

        # An existing machine may have been renamed or re-platformed.
        row.hostname = target.hostname
        row.platform = target.platform
        row.sync_status = SyncStatus.PENDING_SYNC
        return row

    def _record_scan_status(
        self, target: TargetMachine, scan: MachineScan
    ) -> None:
        """Persist a target's scan outcome, timestamp, and data-source health.

        ``last_scan_sources_ok`` is what lets the fleet view distinguish a host
        with genuinely few findings from one whose scan ran against an
        unreachable advisory source. Without it a partial scan is indexed as a
        clean one.
        """
        row = self._session.get(TargetMachineRow, target.id)
        if row is None:  # pragma: no cover - upserted before the scan runs
            return
        row.last_scan_status = scan.status
        row.last_scanned_at = datetime.now(timezone.utc)
        row.last_scan_sources_ok = scan.sources_ok
        row.sync_status = SyncStatus.PENDING_SYNC


def build_scanner_engine(
    session: Session = Depends(get_session),
) -> DeploymentScannerEngine:
    """Provide a request-scoped :class:`ScannerEngine` bound to the request session.

    Request-scoped rather than process-wide on purpose: ``POST /api/scans``
    mutates the engine via :meth:`ScannerEngine.set_credentials`, so sharing one
    engine across concurrent requests would leak one request's credentials into
    another's scan.
    """
    return DeploymentScannerEngine(session)


@lru_cache(maxsize=1)
def _online_engine(url: str) -> Engine:
    """Return the process-wide engine for the Online_Database.

    The schema is brought to head on first use, matching how the Local_Database
    is set up, so pointing at an empty online database just works and an
    existing one is migrated. The two schemas are identical by design (Req 5.5),
    so sync stays a direct row propagation.
    """
    engine = create_engine(url)
    upgrade_to_head(engine)
    return engine


def build_sync_service(
    session: Session = Depends(get_session),
) -> SyncService:
    """Provide a :class:`SyncService` bound to the request and online databases.

    Raises HTTP 503 when ``CVEDECK_ONLINE_DB_URL`` is unset, so a deployment
    that has no online database reports the feature as unconfigured rather than
    failing as a server error.
    """
    url = config.online_database_url()
    if url is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "Synchronization is not configured. Set CVEDECK_ONLINE_DB_URL "
                "to the Online_Database URL to enable it."
            ),
        )
    return SyncService(session, sessionmaker(bind=_online_engine(url)))
