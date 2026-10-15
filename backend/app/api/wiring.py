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

import logging
from datetime import datetime, timezone
from functools import lru_cache

from fastapi import Depends, HTTPException
from sqlalchemy import Engine, create_engine
from sqlalchemy.exc import DBAPIError, IntegrityError
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
from ..scanner.exceptions import HostKeyMismatchError
from ..scanner.host_keys import HostKeyStore, PinnedHostKey
from ..scanner.matcher import NvdClient, OsvClient
from ..scanner.nvd_client import NvdHttpClient
from ..scanner.osv_client import OsvHttpClient
from ..services.enrichment import FindingEnricher
from ..services.sync import SyncService
from .dependencies import get_session

_LOGGER = logging.getLogger(__name__)


class RepositoryHostKeyStore:
    """The :class:`~app.scanner.host_keys.HostKeyStore` over the request session.

    Scans and connection tests both build one, which is what makes a key
    accepted by a connection test the key the next scan is held to (Req 17.6).
    Writes flush and join the caller's transaction like every repository write
    -- unless ``commit_writes`` is set, which a scan sets (Req 13.6). A pin or a
    touch happens during the SSH handshake, before the host is even read, and an
    uncommitted write there would hold SQLite's single write lock through the
    whole collection and every advisory query after it. A scan always kept its
    pins anyway, failed authentication included, so committing at once changes
    nothing a scan records. The connection test commits right after the
    handshake itself, for its own reason, and leaves this off.
    """

    def __init__(
        self, repository: Repository, session: Session, *, commit_writes: bool = False
    ) -> None:
        self._repository = repository
        self._session = session
        self._commit_writes = commit_writes

    def _written(self) -> None:
        if not self._commit_writes:
            return
        try:
            self._session.commit()
        except Exception:
            self._session.rollback()
            raise

    def get(self, hostname: str, port: int) -> PinnedHostKey | None:
        row = self._repository.get_host_key(hostname, port)
        if row is None:
            return None
        return PinnedHostKey(
            key_type=row.key_type,
            key_base64=row.key_base64,
            fingerprint_sha256=row.fingerprint_sha256,
        )

    def pin(self, hostname: str, port: int, key: PinnedHostKey) -> None:
        """Pin a key, tolerating another connection that pinned first (Req 17.9).

        Two first connections to the same new address race: both read no pin,
        both write, and one loses -- on the unique constraint if the other
        commit lands after this read, or on the repository's own guard if it
        lands before. Either way the loser has already completed a handshake
        with the host, so what matters is whether the two saw the same key.

        The savepoint is load-bearing rather than decorative: a failed flush
        poisons the surrounding transaction, so without it the request's own
        commit fails afterwards and the caller sees a server error by a
        different route.
        """
        try:
            with self._session.begin_nested():
                self._repository.pin_host_key(
                    hostname,
                    port,
                    key_type=key.key_type,
                    key_base64=key.key_base64,
                    fingerprint_sha256=key.fingerprint_sha256,
                )
        except (IntegrityError, ValueError):
            pinned = self.get(hostname, port)
            if pinned is None:
                # Not the race: nothing is pinned, so the write failed for a
                # reason inventing a success here would hide.
                raise
            if pinned.key_base64 != key.key_base64:
                # Compared as key bytes, not as the digest we computed from
                # them. The other connection saw a different host.
                raise HostKeyMismatchError(
                    hostname,
                    port,
                    pinned=pinned.fingerprint_sha256,
                    presented=key.fingerprint_sha256,
                ) from None
            # The same key, pinned by whoever got there first (Req 17.2).
            self.touch(hostname, port)
            return
        self._written()

    def touch(self, hostname: str, port: int) -> None:
        self._repository.touch_host_key(hostname, port)
        self._written()


def build_collector(
    platform: Platform, host_key_store: HostKeyStore | None = None
) -> InventoryCollector:
    """Return the collector for a platform, using the configured ports.

    Mirrors :func:`app.scanner.collectors.get_collector` but honors the
    deployment's port/scheme configuration, so a fleet that runs SSH on a
    non-standard port or WinRM over HTTPS needs no code change. SSH host keys
    are pinned in ``host_key_store`` under the configured policy (Req 17).
    """
    if platform is Platform.LINUX:
        return LinuxCollector(
            port=config.ssh_port(),
            host_key_store=host_key_store,
            host_key_policy=config.ssh_host_key_policy(),
        )
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


def _ubuntu_kernel_source():
    """The Ubuntu kernel feed client a scan may fetch with, or ``None`` (Req 12.11).

    None when the feed is switched off, and in demo mode, where nothing is
    ever fetched (Req 15.6).
    """
    if not config.ubuntu_kernel_feed_enabled() or config.demo_mode():
        return None
    from ..scanner.ubuntu_kernel_feed import UbuntuKernelFeedClient

    return UbuntuKernelFeedClient(config.ubuntu_kernel_feed_url(), timeout=config.feed_timeout())


class DeploymentScannerEngine(ScannerEngine):
    """Scanner engine that owns target registration and the transactions.

    Targets are upserted and committed first (the inventory foreign key requires
    them), then each target is scanned and committed on its own, with the
    inherited per-target fault isolation untouched.

    **One commit per target, never one per batch (Req 13.6).** SQLite has a
    single writer, and a write transaction holds the lock until it commits. Up
    to 0.10.2 the batch committed once at the end, so a scan held the lock for
    its whole length -- every SSH session and advisory query, up to the request
    timeout -- and anything else that wrote meanwhile, a second scan, an
    enrollment, a remediation note, the periodic feed refresh, failed as an
    HTTP 500. Now nothing is written while a host is being read or matched:
    host keys commit at the handshake (see :class:`RepositoryHostKeyStore`), and
    :meth:`ScannerEngine._scan_one` persists only after its last network call.

    A target whose results cannot be written -- the lock still busy after the
    timeout, say -- is reported as a failure naming the database, and the batch
    goes on, as for any other per-target failure (Property 1).
    """

    def __init__(
        self,
        session: Session,
        *,
        osv: OsvClient | None = None,
        nvd: NvdClient | None = None,
    ) -> None:
        repository = Repository(session)
        host_keys = RepositoryHostKeyStore(repository, session, commit_writes=True)
        super().__init__(
            repository=repository,
            credentials_for=_no_credentials,
            collector_factory=lambda platform: build_collector(platform, host_keys),
            record_status=self._record_scan_status,
            osv=osv if osv is not None else build_osv_client(),
            nvd=nvd if nvd is not None else build_nvd_client(),
            enricher=FindingEnricher(
                repository, max_age_hours=config.feed_max_age_hours()
            ),
            ubuntu_kernel_source=_ubuntu_kernel_source(),
        )
        self._session = session
        self._repo = repository

    def scan(self, targets: list[TargetMachine]) -> ScanResult:
        """Register every target, then scan and commit them one at a time."""
        for target in targets:
            self._upsert_machine(target)
        self._session.commit()
        return super().scan(targets)

    def _scan_one(self, target: TargetMachine) -> MachineScan:
        """Scan a target, turning a failed database write into a reportable error.

        Rolled back here, before the base class records the failure, so that
        record is written on a clean session rather than one a failed flush
        has poisoned.
        """
        try:
            return super()._scan_one(target)
        except DBAPIError as exc:
            self._session.rollback()
            raise _unsaved(exc) from exc

    def _scan_target(self, target: TargetMachine) -> MachineScan:
        """Scan one target and commit it, so the write lock is never held for long (Req 13.6)."""
        try:
            scan = super()._scan_target(target)
            self._session.commit()
            return scan
        except DBAPIError as exc:
            # Recording the outcome failed too, or its commit did. The target
            # is reported failed, and the batch carries on (Property 1).
            self._session.rollback()
            _LOGGER.warning("Could not save the scan of %s: %s", target.id, exc.orig)
            return MachineScan(
                machine_id=target.id,
                status=ScanStatus.CONNECTION_FAILURE,
                error=_unsaved(exc),
            )

    def _upsert_machine(self, target: TargetMachine) -> TargetMachineRow:
        """Insert or refresh the ``target_machines`` row for a target.

        A new row starts as ``NEVER_SCANNED``, and since targets are committed
        before they are scanned (Req 13.6), that is what the fleet view shows
        while its first scan is in flight -- which is true, and renders neutral.
        ``_record_scan_status`` overwrites it with the real outcome. A host
        enrolled from network discovery keeps it until someone scans it, which
        is what stops the fleet view showing a red failure badge for a host
        nothing has tried to reach yet.
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
        now = datetime.now(timezone.utc)
        row.last_scan_status = scan.status
        row.last_scanned_at = now
        row.last_scan_sources_ok = scan.sources_ok
        row.sync_status = SyncStatus.PENDING_SYNC
        # Every attempt, failed ones included, goes into the history (Req 18.1).
        self._repo.record_scan_run(
            target.id,
            status=scan.status,
            sources_ok=scan.sources_ok,
            scanned_at=scan.diff.scanned_at if scan.diff is not None else now,
            diff=scan.diff,
            keep=config.scan_history_limit(),
            # The same text the scan response shows, kept with the run so the
            # history can still say why a week later (Req 18.10).
            error_detail=scan.message,
        )


def _unsaved(exc: DBAPIError) -> RuntimeError:
    """The error a scan reports when its results could not be written.

    The driver's own message ("database is locked"), not SQLAlchemy's, which
    appends the statement and its parameters -- package data that means nothing
    to an operator reading the scan result.
    """
    return RuntimeError(f"Could not save the results to the database: {exc.orig}")


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
