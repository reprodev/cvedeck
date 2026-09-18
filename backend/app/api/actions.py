"""Action routes for the Backend_API (remediation, scans, sync).

This router exposes the write/action surface described in the design's Backend
API table, deliberately kept separate from the read router in
:mod:`app.api.routes` so the read surface is untouched (task 8.2):

- ``POST /api/machines/{machine_id}/cves/{cve_id}/remediation`` -- add a
  remediation record for a CVE on a machine via :class:`RemediationService`
  (Req 4.1); 404 when the machine is unknown.
- ``PUT /api/remediation/{record_id}`` -- update an existing remediation record
  via :class:`RemediationService` (Req 4.3); 404 when the record is unknown.
- ``POST /api/scans`` -- manually initiate a scan over a batch of targets via
  the injected :class:`ScannerEngine` (Req 1.1, 1.2).
- ``POST /api/sync`` -- manually trigger synchronization via the injected
  :class:`SyncService` (Req 5.2).

Every response is a Pydantic model serialized to structured JSON (Req 6.5).
Remediation is wired straight to the repository-backed service. The scan and
sync endpoints depend on overridable providers
(:func:`app.api.dependencies.get_scanner_engine` /
:func:`app.api.dependencies.get_sync_service`) so tests inject engines/services
that never touch real hosts or an online database.
"""

import socket
import time
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response
import paramiko
from sqlalchemy.orm import Session

from .. import config
from ..data.repository import Repository
from ..enums import Platform, ScanStatus
from ..models import Credentials, TargetMachine
from ..scanner.collectors import parse_private_key
from ..scanner.engine import MachineScan, ScannerEngine
from ..scanner.epss_client import EpssHttpClient
from ..scanner.kev_client import KevHttpClient
from ..scanner.exceptions import AuthError, HostKeyError, HostKeyMismatchError
from ..scanner.host_keys import connect_pinned
from ..services.remediation import (
    RemediationRecordNotFoundError,
    RemediationService,
)
from ..services.sync import SyncService
from .credentials import CredentialResolutionError, resolve_credentials
from .dependencies import get_scanner_engine, get_session, get_sync_service
from .wiring import RepositoryHostKeyStore
from .schemas import (
    DiscoveredHostOut,
    DiscoveredServiceOut,
    DiscoverySweepRequest,
    DiscoverySweepResponse,
    FeedRefreshResponse,
    FeedRefreshResultOut,
    HostEnrollBatchIn,
    HostEnrollIn,
    HostEnrollResponse,
    MachineScanOut,
    MachineSummary,
    RemediationIn,
    RemediationOut,
    ScanRequest,
    ScanResponse,
    SeverityCounts,
    SyncResponse,
    TestConnectionRequest,
    TestConnectionResponse,
)

router = APIRouter(prefix="/api", tags=["actions"])


def _get_remediation_service(
    session: Session = Depends(get_session),
) -> RemediationService:
    """Provide a :class:`RemediationService` bound to the request session."""
    return RemediationService(Repository(session))


def _to_remediation_out(record) -> RemediationOut:
    """Map a persisted remediation record to the API response model."""
    return RemediationOut(
        record_id=record.id,
        machine_id=record.machine_id,
        cve_id=record.cve_id,
        status=record.status,
        note=record.note,
    )


def _demo_guard(action: str):
    """Build a route dependency that refuses `action` when in demo mode.

    Implements Req 15.3: every route that opens a connection to a
    user-supplied address is refused, with the reason reported.

    Demo mode exists so strangers can click around a populated dashboard. Every
    route that reaches the network from a user-supplied address is off: a scan,
    a discovery sweep and a connection test each take a hostname or a CIDR plus
    credentials and connect to it. Left enabled on a public instance, that is an
    open SSH/WinRM and port-scan proxy anyone can aim anywhere, with the traffic
    coming from the demo's IP rather than theirs.

    This is a route-level dependency rather than a check inside the handler
    because FastAPI resolves a handler's parameter dependencies before its body
    runs. As a body check on POST /api/scans, the ScannerEngine was constructed
    first and its own failure surfaced instead of this 403. Dependencies
    declared on the decorator are inserted ahead of the handler's own, so this
    runs before anything else is built.

    403 rather than 404: the capability exists, this deployment declines to
    offer it, and saying so plainly is more useful than pretending the route is
    missing.
    """

    def guard() -> None:
        if config.demo_mode():
            raise HTTPException(
                status_code=403,
                detail=(
                    f"{action} is disabled in demo mode. "
                    "Run your own instance to scan real hosts."
                ),
            )

    return guard


@router.post(
    "/machines/{machine_id}/cves/{cve_id}/remediation",
    response_model=RemediationOut,
    status_code=201,
)
def add_remediation(
    machine_id: str,
    cve_id: str,
    body: RemediationIn,
    session: Session = Depends(get_session),
    service: RemediationService = Depends(_get_remediation_service),
) -> RemediationOut:
    """Add a remediation record for a CVE on a machine (Req 4.1).

    Returns 404 when the machine is unknown. The created record is persisted to
    the Local_Database and returned.
    """
    repo = Repository(session)
    if repo.get_machine(machine_id) is None:
        raise HTTPException(status_code=404, detail="Machine not found")
    record = service.add(machine_id, cve_id, body.status, body.note)
    session.commit()
    return _to_remediation_out(record)


@router.put("/remediation/{record_id}", response_model=RemediationOut)
def update_remediation(
    record_id: str,
    body: RemediationIn,
    session: Session = Depends(get_session),
    service: RemediationService = Depends(_get_remediation_service),
) -> RemediationOut:
    """Update an existing remediation record (Req 4.3).

    Returns 404 when no record with ``record_id`` exists. The updated record is
    persisted to the Local_Database and returned.
    """
    try:
        record = service.update(record_id, body.status, body.note)
    except RemediationRecordNotFoundError:
        raise HTTPException(status_code=404, detail="Remediation record not found")
    session.commit()
    return _to_remediation_out(record)


def _refuse_unsupported_platforms(body: ScanRequest) -> None:
    """Refuse a scan that includes a platform CveDeck cannot yet assess (Req 10.8).

    Windows collection over WinRM exists, but Windows *matching* does not: OSV
    has no Windows ecosystem, OS-level Windows exposure lives in cumulative KB
    updates that nothing here maps yet, and NVD is off by default. A Windows scan
    would therefore finish with zero findings -- and a scan with zero findings is
    exactly what a clean host looks like. Refusing is the only honest answer
    until matching exists; see the methodology document's Windows roadmap.

    The whole request is refused rather than the Windows targets being dropped
    or given a failure status. Dropping them silently would report a batch as
    done when part of it was never attempted, and recording CONNECTION_FAILURE
    or AUTH_FAILURE would put a false reason on the machine.

    A route-level dependency, like the demo guard, so it runs before the scanner
    engine is constructed.
    """
    windows = [t.hostname for t in body.targets if t.platform is Platform.WINDOWS]
    if windows:
        raise HTTPException(
            status_code=422,
            detail=(
                "Windows scanning is not supported yet: CveDeck cannot match "
                "Windows software or updates against vulnerability data, so a "
                "Windows scan would report a host as clean without having "
                "checked it. Remove these targets and scan Linux hosts only: "
                + ", ".join(windows)
            ),
        )


@router.post(
    "/scans",
    response_model=ScanResponse,
    dependencies=[
        Depends(_demo_guard("Scanning")),
        Depends(_refuse_unsupported_platforms),
    ],
)
def initiate_scan(
    body: ScanRequest,
    engine: ScannerEngine = Depends(get_scanner_engine),
) -> ScanResponse:
    """Manually initiate a scan over a batch of Linux targets (Req 1.1, 13.1).

    Maps the request targets to domain :class:`TargetMachine` objects, hands
    the credentials to the injected engine via a per-request lookup, and returns
    the per-target scan outcomes. Per-target connection/auth failures are
    recorded as statuses by the engine and never abort the batch (Req 11.9).
    """
    targets = [
        TargetMachine(id=t.id, hostname=t.hostname, platform=t.platform)
        for t in body.targets
    ]

    # Resolve every target's credentials up front. A target may supply a
    # password or a private key, or omit both and fall back to the deployment's
    # server-managed SSH key -- which is what lets a fleet re-scan run without
    # retyping credentials per host.
    credentials_by_id: dict[str, Credentials] = {}
    unresolved: list[MachineScanOut] = []
    for target in body.targets:
        try:
            credentials_by_id[target.id] = resolve_credentials(
                target.platform,
                username=target.username,
                password=target.password,
                private_key=target.private_key,
                passphrase=target.passphrase,
            )
        except CredentialResolutionError as exc:
            # A credential problem is that target's failure, not the batch's.
            # Fault isolation is the engine's defining behaviour, and it has to
            # hold for targets that never reach the engine too.
            unresolved.append(
                MachineScanOut(
                    machine_id=target.id,
                    status=ScanStatus.AUTH_FAILURE,
                    finding_count=0,
                    sources_ok=False,
                    message=str(exc),
                )
            )

    scannable = [t for t in targets if t.id in credentials_by_id]
    if not scannable:
        return ScanResponse(machine_scans=unresolved)

    engine.set_credentials(credentials_by_id)
    result = engine.scan(scannable)
    return ScanResponse(
        machine_scans=unresolved
        + [
            MachineScanOut(
                machine_id=scan.machine_id,
                status=scan.status,
                finding_count=len(scan.findings),
                sources_ok=scan.sources_ok,
                unavailable_sources=list(scan.unavailable_sources),
                message=scan.message,
                **_diff_counts(scan),
            )
            for scan in result.machine_scans
        ]
    )


def _diff_counts(scan: MachineScan) -> dict[str, object]:
    """A scan outcome's new and resolved counts, as ``None`` where not assessed (Req 18.2)."""
    diff = scan.diff
    if diff is None or diff.baseline:
        return {"new_count": None, "resolved_count": None, "baseline": diff is not None}
    return {
        "new_count": len(diff.new),
        "resolved_count": len(diff.resolved) if diff.resolved_assessed else None,
        "baseline": False,
    }


@router.delete(
    "/host-keys/{hostname}",
    status_code=204,
    dependencies=[Depends(_demo_guard("Forgetting a host key"))],
)
def forget_host_key(
    hostname: str,
    port: int | None = Query(default=None, ge=1, le=65535),
    session: Session = Depends(get_session),
) -> Response:
    """Forget the SSH host key pinned for an address (Req 17.7).

    ``port`` defaults to the configured SSH port, the one scans dial.

    The only way a pin changes. The next connection to the address trusts
    whatever key the host presents, so this is an explicit, signed-in action
    and never something a scan does on its own. 404 when nothing is pinned.
    """
    if not Repository(session).forget_host_key(
        hostname, port if port is not None else config.ssh_port()
    ):
        raise HTTPException(status_code=404, detail="No host key is pinned for that address")
    session.commit()
    return Response(status_code=204)


@router.post("/sync", response_model=SyncResponse)
def trigger_sync(
    service: SyncService = Depends(get_sync_service),
) -> SyncResponse:
    """Manually trigger synchronization to the Online_Database (Req 5.2).

    Delegates to the injected :class:`SyncService` and surfaces its report:
    whether the Online_Database was reachable and the per-table propagated /
    pending counts.
    """
    report = service.sync()
    return SyncResponse(
        online_reachable=report.online_reachable,
        total_propagated=report.total_propagated,
        total_pending=report.total_pending,
        propagated=dict(report.propagated),
        pending=dict(report.pending),
    )


@router.post("/feeds/refresh", response_model=FeedRefreshResponse)
def refresh_feeds(
    session: Session = Depends(get_session),
) -> FeedRefreshResponse:
    """Refresh the cached threat-intel feeds (CISA KEV, FIRST EPSS).

    Downloads each feed whole and replaces the local cache. The two are
    refreshed independently, so an outage at one upstream does not cost the
    other's update.

    A failed download leaves the previous cache in place rather than emptying
    it: an empty KEV cache would silently reclassify every known-exploited
    finding as unremarkable, which is worse than serving yesterday's answer.

    Findings are enriched at scan time from whatever the cache holds, so a
    refresh takes effect on the next scan rather than retroactively.
    """
    from ..services.enrichment import FeedRefreshService

    service = FeedRefreshService(
        Repository(session),
        kev_source=KevHttpClient(
            config.kev_feed_url(), timeout=config.feed_timeout()
        ),
        epss_source=EpssHttpClient(
            config.epss_feed_url(), timeout=config.feed_timeout()
        ),
    )
    outcomes = service.refresh_all()
    session.commit()

    return FeedRefreshResponse(
        ok=all(outcome.ok for outcome in outcomes),
        results=[
            FeedRefreshResultOut(
                feed_name=outcome.feed_name,
                status=outcome.status,
                record_count=outcome.record_count,
                error_detail=outcome.error_detail,
            )
            for outcome in outcomes
        ],
    )


@router.post(
    "/discovery/sweep",
    response_model=DiscoverySweepResponse,
    dependencies=[Depends(_demo_guard("Network discovery"))],
)
def discovery_sweep(
    body: DiscoverySweepRequest,
) -> DiscoverySweepResponse:
    """Zero-touch network discovery sweep (Phase 1) (Req 8.1, 8.3).

    Scans a network CIDR using ICMP ping, TCP connect probes, and
    unauthenticated banner grabbing to discover active hosts and their exposed
    services. No credentials are required and no host configuration is modified.

    Returns a list of discovered hosts with their open ports, service banners,
    and best-effort OS identification.
    """
    import ipaddress

    from ..scanner.discovery import NetworkDiscoveryEngine

    # Validate CIDR before running the sweep.
    try:
        network = ipaddress.IPv4Network(body.cidr, strict=False)
    except (ipaddress.AddressValueError, ValueError):
        raise HTTPException(status_code=422, detail=f"Invalid CIDR: {body.cidr!r}")

    # Limit sweep to /20 (4096 hosts) to prevent accidental resource
    # exhaustion (Req 8.2).
    if network.num_addresses > 4096:
        raise HTTPException(
            status_code=422,
            detail=(
                f"Network {body.cidr} contains {network.num_addresses} addresses. "
                f"Maximum allowed is /20 (4096 addresses)."
            ),
        )

    engine = NetworkDiscoveryEngine(
        ports=body.ports,
        grab_banners=body.grab_banners,
    )
    sweep = engine.sweep(body.cidr)
    discovered = sweep.hosts

    hosts_out = [
        DiscoveredHostOut(
            ip=host.ip,
            hostname=host.hostname,
            responds_to_ping=host.responds_to_ping,
            open_ports=host.open_ports,
            services=[
                DiscoveredServiceOut(
                    port=svc.port,
                    protocol=svc.protocol,
                    banner=svc.banner,
                    product=svc.product,
                    version=svc.version,
                    extra_info=svc.extra_info,
                )
                for svc in host.services
            ],
            os_guess=host.os_guess,
        )
        for host in discovered
    ]

    total_scanned = len(list(network.hosts())) or 1
    return DiscoverySweepResponse(
        cidr=body.cidr,
        total_hosts_scanned=total_scanned,
        total_hosts_discovered=len(hosts_out),
        icmp_checked=sweep.icmp_checked,
        probe_errors=sweep.probe_errors,
        hosts=hosts_out,
    )


@router.post("/discovery/enroll", response_model=HostEnrollResponse, status_code=201)
def enroll_discovered_hosts(
    body: HostEnrollBatchIn,
    session: Session = Depends(get_session),
) -> HostEnrollResponse:
    """Enroll one or more discovered hosts into the fleet roster (Req 8.4).

    Persists target machine entries to the database so they appear in the
    fleet overview and can be scanned on demand with credentials. Rows are
    written ``PENDING_SYNC`` by :meth:`Repository.upsert_target_machine`, so
    the separately triggered sync picks them up.
    """
    repo = Repository(session)
    enrolled_summaries: list[MachineSummary] = []

    for host in body.hosts:
        machine_id = host.id or host.hostname
        machine = repo.upsert_target_machine(
            machine_id=machine_id,
            hostname=host.hostname,
            platform=host.platform,
        )
        counts = repo.get_severity_counts(machine_id)
        enrolled_summaries.append(
            MachineSummary(
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
            )
        )

    session.commit()
    return HostEnrollResponse(
        enrolled=enrolled_summaries,
        total_enrolled=len(enrolled_summaries),
    )


@router.post(
    "/scans/test-connection",
    response_model=TestConnectionResponse,
    dependencies=[Depends(_demo_guard("Connection testing"))],
)
def test_scan_connection(
    body: TestConnectionRequest,
    session: Session = Depends(get_session),
) -> TestConnectionResponse:
    """Pre-flight test connection reachability and credentials for a target.

    Performs a fast, non-invasive transport probe without initiating a full CVE scan.

    Both platforms dial exactly what a scan of that platform would dial
    (Req 10.9): SSH on ``CVEDECK_SSH_PORT``, holding the host to the same pinned
    key store (Req 17.6); WinRM on ``CVEDECK_WINRM_SCHEME`` and
    ``CVEDECK_WINRM_PORT``. A pre-flight that succeeded over a different
    transport than the scan uses is evidence about the wrong path -- and on the
    WinRM side it meant sending a password over a plaintext channel the
    deployment had configured away.

    Windows *scans* are refused (Req 10.8) while this probe still connects. The
    refusal is there because a Windows scan would report zero findings, which
    reads as a clean host; a connection test claims only reachability and
    authentication, so it cannot be mistaken for one.
    """
    start_time = time.perf_counter()
    target_host = body.hostname.strip()

    # Resolve the same way a real scan would, so pre-flight and the scan never
    # disagree about which credentials are in play.
    try:
        credentials = resolve_credentials(
            body.platform,
            username=body.username,
            password=body.password,
            private_key=body.private_key,
            passphrase=body.passphrase,
        )
    except CredentialResolutionError as exc:
        return TestConnectionResponse(
            success=False,
            status="AUTH_FAILURE",
            message=str(exc),
            latency_ms=round((time.perf_counter() - start_time) * 1000.0, 2),
        )

    username = credentials.username

    if body.platform == Platform.LINUX:
        port = config.ssh_port()
        host_keys = RepositoryHostKeyStore(Repository(session), session)
        # Fast TCP pre-flight check
        try:
            with socket.create_connection((target_host, port), timeout=2.5):
                pass
        except (socket.timeout, OSError) as exc:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return TestConnectionResponse(
                success=False,
                status="CONNECTION_FAILURE",
                message=f"Port {port} (SSH) is unreachable on {target_host} ({exc})",
                latency_ms=round(elapsed, 2),
            )

        # Test SSH authentication and read-only identity probe
        client = paramiko.SSHClient()
        try:
            auth_kwargs: dict[str, object] = {}
            if credentials.uses_key:
                auth_kwargs["pkey"] = parse_private_key(
                    credentials.private_key.get_secret_value(),
                    credentials.passphrase.get_secret_value()
                    if credentials.passphrase is not None
                    else None,
                )
            else:
                auth_kwargs["password"] = credentials.password.get_secret_value()

            connect_pinned(
                client,
                hostname=target_host,
                port=port,
                store=host_keys,
                policy=config.ssh_host_key_policy(),
                username=username,
                timeout=4.0,
                allow_agent=False,
                look_for_keys=False,
                **auth_kwargs,
            )
            # The host proved its key and accepted the credentials, so a
            # first-use pin stands even if the probe below fails.
            session.commit()
            pinned = host_keys.get(target_host, port)
            # Query OS release
            _stdin, stdout, _stderr = client.exec_command(
                "cat /etc/os-release 2>/dev/null || uname -srm", timeout=3.0
            )
            raw = stdout.read()
            banner_text = (
                raw.decode("utf-8", errors="replace").strip()
                if isinstance(raw, bytes)
                else str(raw).strip()
            )
            os_line = ""
            for line in banner_text.splitlines():
                if line.startswith("PRETTY_NAME="):
                    os_line = line.partition("=")[2].strip('"\'')
                    break
            if not os_line and banner_text:
                os_line = banner_text.splitlines()[0]

            elapsed = (time.perf_counter() - start_time) * 1000.0
            return TestConnectionResponse(
                success=True,
                status="SUCCESS",
                message=f"SSH authenticated successfully for {username}@{target_host}",
                latency_ms=round(elapsed, 2),
                os_banner=os_line,
                host_key_fingerprint=pinned.fingerprint_sha256 if pinned else None,
            )
        except HostKeyError as exc:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return TestConnectionResponse(
                success=False,
                status=(
                    "HOST_KEY_MISMATCH"
                    if isinstance(exc, HostKeyMismatchError)
                    else "HOST_KEY_UNKNOWN"
                ),
                message=str(exc),
                latency_ms=round(elapsed, 2),
                host_key_fingerprint=getattr(exc, "pinned", None),
            )
        except AuthError as exc:
            # A malformed key or wrong passphrase, caught before the network.
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return TestConnectionResponse(
                success=False,
                status="AUTH_FAILURE",
                message=str(exc),
                latency_ms=round(elapsed, 2),
            )
        except paramiko.AuthenticationException:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            method = "key" if credentials.uses_key else "password"
            return TestConnectionResponse(
                success=False,
                status="AUTH_FAILURE",
                message=(
                    f"SSH {method} authentication rejected for user "
                    f"'{username}' on {target_host}"
                ),
                latency_ms=round(elapsed, 2),
            )
        except (paramiko.SSHException, socket.error, OSError) as exc:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return TestConnectionResponse(
                success=False,
                status="CONNECTION_FAILURE",
                message=f"SSH connection failed to {target_host}: {exc}",
                latency_ms=round(elapsed, 2),
            )
        finally:
            client.close()

    else:
        # Windows (WinRM). The deployment's transport, exactly as a scan of this
        # platform would dial it (Req 10.9) -- this used to be a hardcoded
        # http://host:5985, so an instance configured for HTTPS on 5986 still
        # sent its password over plaintext 5985 from here.
        try:
            port = config.winrm_port()
            scheme = config.winrm_scheme()
        except ValueError as exc:
            # An unrecognised CVEDECK_WINRM_SCHEME. Reported like every other
            # refusal on this route rather than as a server error.
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return TestConnectionResponse(
                success=False,
                status="CONNECTION_FAILURE",
                message=str(exc),
                latency_ms=round(elapsed, 2),
            )

        try:
            with socket.create_connection((target_host, port), timeout=2.5):
                pass
        except (socket.timeout, OSError) as exc:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return TestConnectionResponse(
                success=False,
                status="CONNECTION_FAILURE",
                message=f"Port {port} (WinRM) is unreachable on {target_host} ({exc})",
                latency_ms=round(elapsed, 2),
            )

        # Built before the probe, so the failure handler below can name it even
        # when the failure was the import itself.
        # The scheme travels in the message too: an operator who expected HTTPS
        # should be able to see that this went out over http.
        endpoint = f"{scheme}://{target_host}:{port}/wsman"

        try:
            import winrm

            session = winrm.Session(
                endpoint,
                auth=(username, credentials.password.get_secret_value()),
                transport="ntlm",
                read_timeout_sec=4,
                operation_timeout_sec=4,
            )
            r = session.run_ps("[System.Environment]::OSVersion.VersionString")
            if r.status_code == 0:
                os_banner = (
                    r.std_out.decode("utf-8", errors="replace").strip()
                    if isinstance(r.std_out, bytes)
                    else str(r.std_out).strip()
                )
                elapsed = (time.perf_counter() - start_time) * 1000.0
                return TestConnectionResponse(
                    success=True,
                    status="SUCCESS",
                    message=(
                        f"WinRM authenticated successfully for {username}@{target_host} "
                        f"over {endpoint}"
                    ),
                    latency_ms=round(elapsed, 2),
                    os_banner=os_banner,
                )
            else:
                elapsed = (time.perf_counter() - start_time) * 1000.0
                return TestConnectionResponse(
                    success=False,
                    status="AUTH_FAILURE",
                    message=f"WinRM probe returned non-zero exit code ({r.status_code})",
                    latency_ms=round(elapsed, 2),
                )
        except Exception as exc:
            elapsed = (time.perf_counter() - start_time) * 1000.0
            return TestConnectionResponse(
                success=False,
                status="AUTH_FAILURE" if "401" in str(exc) else "CONNECTION_FAILURE",
                message=f"WinRM probe error against {endpoint}: {exc}",
                latency_ms=round(elapsed, 2),
            )


