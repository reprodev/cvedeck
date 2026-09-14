"""Pydantic response models for the outward-facing Backend_API.

These models serialize scan and vulnerability data to structured JSON (Req 6.5).
They mirror the design's response contracts:

- :class:`SeverityCounts` -- CVE counts for a machine grouped by Severity_Level
  (Req 3.2).
- :class:`MachineSummary` -- a machine list row with its severity-grouped counts
  (Req 6.1, 3.2).
- :class:`CveFindingOut` -- a single CVE finding carrying the CVE identifier,
  Severity_Level, and CVSS_Score (Req 6.2), plus the package identifier for
  OSV-sourced findings and the current remediation status when known.

The models are deliberately independent of the ORM rows and repository value
objects; the API layer maps stored rows into these outward-facing shapes so the
JSON contract stays stable regardless of internal representation.
"""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from ..enums import FeedStatus, Platform, RemediationStatus, ScanStatus, Severity


class SeverityCounts(BaseModel):
    """CVE counts for a machine grouped by Severity_Level (Req 3.2)."""

    critical: int
    high: int
    medium: int
    low: int


class MachineSummary(BaseModel):
    """A scanned machine with its severity-grouped CVE counts (Req 6.1, 3.2).

    ``last_scanned_at`` and ``last_scan_sources_ok`` exist so a client can tell
    the difference between three states that otherwise all look like "0 CVEs":
    never scanned, scanned long ago, and scanned just now against an advisory
    source that was unreachable.
    """

    machine_id: str
    hostname: str
    platform: Platform
    last_scan_status: ScanStatus = ScanStatus.NEVER_SCANNED
    last_scanned_at: datetime | None = None
    last_scan_sources_ok: bool = True
    cve_counts: SeverityCounts
    #: Findings on this machine confirmed as actively exploited (CISA KEV).
    #: Counts only findings explicitly checked and found in the catalogue, so a
    #: fleet whose intel feeds have never loaded reports 0 here -- which is why
    #: ``GET /api/feeds`` exists alongside it. Zero means "none confirmed", not
    #: "none exist"; the feed health is what tells those two apart.
    kev_count: int = 0


class CveFindingOut(BaseModel):
    """A CVE finding serialized for an API response (Req 6.2, 6.5).

    Always carries the CVE identifier, Severity_Level, and CVSS_Score.
    ``package_identifier`` is present for OSV-sourced (package-level) findings.

    The remaining three fields describe the manually maintained remediation
    state for this CVE on this machine, and are all ``None`` when no remediation
    record exists yet (Req 4.4). ``remediation_record_id`` is what lets a client
    update an existing record through ``PUT /api/remediation/{record_id}``
    rather than only ever adding new ones, and ``remediation_note`` surfaces the
    free-text note captured with the status (Req 4.2).
    """

    cve_id: str
    severity: Severity
    cvss_score: float
    package_identifier: str | None = None
    #: The affected package name, parsed out of ``package_identifier``. Parsed
    #: here rather than in each client: the identifier is a display string
    #: ("Ubuntu:22.04:LTS:openssl@3.0.2 (fixed in 3.0.2-0ubuntu1.16)"), and
    #: every consumer re-deriving structure from prose is a bug waiting to
    #: happen.
    package_name: str | None = None
    #: The version that fixes this CVE, or ``None`` when no fix is published.
    fixed_version: str | None = None
    #: Whether an actionable fix exists. Clients previously determined this by
    #: searching the identifier for the substring "fixed in".
    has_fix: bool = False
    #: How the finding can be fixed on this host (Req 14.7, 14.8):
    #: ``available`` -- the host's own release ships ``fixed_version``;
    #: ``newer_release`` -- only ``fix_release`` (a newer release, or Ubuntu Pro)
    #: ships a fix, so upgrading packages cannot clear it;
    #: ``upstream`` -- ``fix_release`` has a fix, but the host's release could not
    #: be matched, so availability is unconfirmed;
    #: ``none`` -- no fix is published.
    fix_status: str = "none"
    #: The release that has the fix, for ``newer_release`` and ``upstream``.
    fix_release: str | None = None
    #: The fixed version in that release.
    fix_release_version: str | None = None
    remediation_status: RemediationStatus | None = None
    remediation_record_id: str | None = None
    remediation_note: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    depended_on_by: list[str] = Field(default_factory=list)
    blast_radius: str = "low"

    # --- Threat-intel enrichment ------------------------------------------
    # ``None`` throughout means "not enriched", which clients must render as
    # unknown rather than as a negative. ``kev_listed=false`` is a checked
    # answer; ``kev_listed=null`` is no answer. Collapsing the two would
    # present a stale or failed feed as "nothing here is being exploited".
    #: Whether CISA lists this CVE as actively exploited in the wild.
    kev_listed: bool | None = None
    #: CISA's remediation due date for a KEV-listed CVE, when published.
    kev_due_date: str | None = None
    #: FIRST's modelled probability (0.0-1.0) of exploitation within 30 days.
    epss_score: float | None = None
    #: That probability's rank among all scored CVEs. Carried alongside the raw
    #: score because the EPSS distribution is heavily skewed -- 0.08 sounds
    #: negligible and is in fact the 94th percentile.
    epss_percentile: float | None = None


class FeedHealthOut(BaseModel):
    """The cache state of one threat-intel feed (Milestone 1).

    Exposed so the dashboard can distinguish "no findings are known-exploited"
    from "the KEV feed has not refreshed in three weeks". Without this, a feed
    that has been failing silently looks identical to a healthy fleet -- the
    same false-negative failure mode ``last_scan_sources_ok`` prevents for
    scan sources.
    """

    feed_name: str
    status: FeedStatus
    last_refreshed_at: datetime | None = None
    last_attempted_at: datetime | None = None
    record_count: int = 0
    error_detail: str | None = None
    #: Cache is older than the configured maximum age, or was never populated.
    stale: bool = True
    #: Whether the cache holds data that can enrich findings at all.
    usable: bool = False


class FeedRefreshResultOut(BaseModel):
    """The outcome of refreshing one feed via ``POST /api/feeds/refresh``."""

    feed_name: str
    status: FeedStatus
    record_count: int = 0
    error_detail: str | None = None


class FeedRefreshResponse(BaseModel):
    """Aggregate outcome of a manually triggered feed refresh.

    ``ok`` is false when any feed failed, so a client can surface a partial
    refresh without inspecting each result.
    """

    ok: bool
    results: list[FeedRefreshResultOut]


# --------------------------------------------------------------------------- #
# Action endpoint request/response models (task 8.2)
# --------------------------------------------------------------------------- #


class RemediationIn(BaseModel):
    """Request body to add or update a remediation record (Req 4.1, 4.3).

    Carries the remediation ``status`` and a free-text ``note`` (Req 4.2). The
    machine and CVE for an ``add`` come from the path; an ``update`` targets an
    existing record by its id in the path.
    """

    status: RemediationStatus
    note: str = ""


class RemediationOut(BaseModel):
    """A persisted remediation record serialized for an API response.

    Reflects the record's current manually maintained state (status + note)
    after an add/update, along with its identifiers and last-updated time.
    """

    record_id: str
    machine_id: str
    cve_id: str
    status: RemediationStatus
    note: str


class TargetIn(BaseModel):
    """A single scan target with the credentials used to reach it (Req 1.1, 1.2).

    ``platform`` selects the collector (SSH for Linux, WinRM for Windows).

    Credentials are accepted in the request body and never echoed back in any
    response model. Supply a ``password``, or a ``private_key`` (Ed25519/ECDSA/
    RSA, PEM or OpenSSH) with an optional ``passphrase``. Both may be omitted
    entirely for a Linux target when the deployment configures
    ``CVEDECK_DEFAULT_SSH_KEY_PATH``, which is what allows a fleet re-scan
    without retyping credentials for every host.
    """

    id: str
    hostname: str
    platform: Platform
    username: str | None = None
    password: str | None = None
    private_key: str | None = None
    passphrase: str | None = None


class ScanRequest(BaseModel):
    """Request body to manually initiate a scan over a batch of targets.

    Lists the targets (with credentials) to scan. An empty list is rejected by
    validation so a scan always has at least one target (Req 1.1, 1.2).
    """

    targets: list[TargetIn] = Field(min_length=1)


class MachineScanOut(BaseModel):
    """Per-target outcome of a scan serialized for an API response.

    ``status`` is the recorded ``ScanStatus`` for the target; ``finding_count``
    is the number of CVE findings produced (zero for a failed target).

    ``message`` explains the outcome -- the originating error on a failure, or a
    partial-results notice when a source was unreachable. Without it a client
    can only render a bare ``auth_failure`` with no hint whether the cause was a
    bad password, a bad username, or a rejected key.

    ``sources_ok`` is ``False`` when a configured data source did not answer, so
    ``finding_count`` is an undercount rather than a clean bill of health.
    """

    machine_id: str
    status: ScanStatus
    finding_count: int
    sources_ok: bool = True
    unavailable_sources: list[str] = Field(default_factory=list)
    message: str | None = None


class ScanResponse(BaseModel):
    """Aggregate outcome of a manually initiated scan (Req 1.1, 1.2)."""

    machine_scans: list[MachineScanOut]


class SyncResponse(BaseModel):
    """Outcome of a manually triggered synchronization run (Req 5.2).

    Mirrors the service's ``SyncReport``: whether the Online_Database was
    reachable, and the per-table counts propagated and still pending.
    """

    online_reachable: bool
    total_propagated: int
    total_pending: int
    propagated: dict[str, int]
    pending: dict[str, int]


# --------------------------------------------------------------------------- #
# Network Discovery (Phase 1 zero-touch sweep)
# --------------------------------------------------------------------------- #


class DiscoverySweepRequest(BaseModel):
    """Request body to initiate a zero-touch network discovery sweep.

    Accepts a CIDR range (e.g. ``192.168.0.0/24``) and optional port list.
    No credentials are required — discovery uses only ICMP ping, TCP connect
    scans, and unauthenticated banner grabbing.
    """

    cidr: str = Field(
        ...,
        description="IPv4 network in CIDR notation, e.g. '192.168.0.0/24'",
        examples=["192.168.0.0/24", "10.0.1.0/24"],
    )
    ports: list[int] | None = Field(
        default=None,
        description="TCP ports to probe (defaults to 22, 80, 443, 445, 3389, 5985)",
    )
    grab_banners: bool = Field(
        default=True,
        description="Whether to read service banners from open ports",
    )


class DiscoveredServiceOut(BaseModel):
    """Information about a single open port on a discovered host."""

    port: int
    protocol: str = ""
    banner: str = ""
    product: str = ""
    version: str = ""
    extra_info: str = ""


class DiscoveredHostOut(BaseModel):
    """A host found during network discovery."""

    ip: str
    hostname: str = ""
    responds_to_ping: bool = False
    open_ports: list[int] = Field(default_factory=list)
    services: list[DiscoveredServiceOut] = Field(default_factory=list)
    os_guess: str = ""


class DiscoverySweepResponse(BaseModel):
    """Aggregate result of a zero-touch network discovery sweep."""

    cidr: str
    total_hosts_scanned: int
    total_hosts_discovered: int
    hosts: list[DiscoveredHostOut]


class HostEnrollIn(BaseModel):
    """A discovered host to enroll into the fleet roster."""

    id: str | None = Field(
        default=None,
        description="Machine ID (defaults to hostname if not specified)",
    )
    hostname: str = Field(..., description="Target hostname or IP address")
    platform: Platform = Field(
        default=Platform.LINUX,
        description="Operating system family (linux or windows)",
    )


class HostEnrollBatchIn(BaseModel):
    """Batch of discovered hosts to enroll into the fleet roster."""

    hosts: list[HostEnrollIn] = Field(
        min_length=1,
        description="List of hosts to enroll into the target fleet",
    )


class HostEnrollResponse(BaseModel):
    """Result of enrolling discovered hosts into the fleet roster."""

    enrolled: list[MachineSummary]
    total_enrolled: int


class TestConnectionRequest(BaseModel):
    """Request payload to pre-flight test connection and credentials for a target."""

    hostname: str = Field(..., min_length=1, description="Target hostname or IP address")
    platform: Platform = Field(
        default=Platform.LINUX,
        description="Target platform family (linux or windows)",
    )
    username: str | None = Field(
        default=None,
        description="SSH or WinRM username; omit to use the server-managed default",
    )
    password: str | None = Field(default=None, description="SSH or WinRM password")
    private_key: str | None = Field(
        default=None, description="SSH private key (PEM or OpenSSH format)"
    )
    passphrase: str | None = Field(
        default=None, description="Passphrase for an encrypted private key"
    )


class TestConnectionResponse(BaseModel):
    """Result of pre-flight connection and authentication test."""

    success: bool
    status: str
    message: str
    latency_ms: float
    os_banner: str = ""


# --------------------------------------------------------------------------- #
# Access control (Req 16)
# --------------------------------------------------------------------------- #


class AuthStateOut(BaseModel):
    """What the dashboard should show before anything else (Req 16.3).

    ``state`` is one of ``setup_required`` (no account yet), ``signed_out``,
    ``signed_in``, or ``open`` (login is not required: disabled, or demo mode).
    """

    state: str
    username: str | None = None
    #: ``session`` or ``token`` when signed in.
    via: str | None = None


class LoginIn(BaseModel):
    username: str = Field(max_length=256)
    password: str = Field(max_length=2048)


class SetupIn(BaseModel):
    setup_code: str = Field(max_length=64)
    username: str = Field(max_length=256)
    password: str = Field(max_length=2048)


class PasswordChangeIn(BaseModel):
    current_password: str = Field(max_length=2048)
    new_password: str = Field(max_length=2048)


class ApiTokenIn(BaseModel):
    name: str = Field(max_length=256)


class ApiTokenOut(BaseModel):
    """An API token as listed. Never carries the token itself."""

    token_id: str
    name: str
    prefix: str
    created_at: datetime
    last_used_at: datetime | None = None
    revoked_at: datetime | None = None


class ApiTokenCreatedOut(ApiTokenOut):
    """The one response that includes the token. It is not retrievable later."""

    token: str


