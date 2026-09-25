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

from typing import Annotated

from pydantic import BaseModel, Field

from ..enums import (
    FeedStatus,
    FindingChange,
    Platform,
    RemediationStatus,
    ScanStatus,
    Severity,
)


class SeverityCounts(BaseModel):
    """CVE counts for a machine grouped by Severity_Level (Req 3.2).

    Five counts, in triage-ranking order. A finding falls in exactly one, so
    the sum is the finding total (Req 10.11).
    """

    critical: int
    unscored: int
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
    #: Findings on this machine never checked against the catalogue. The
    #: dashboard needs this to tell "checked, none exploited" from "nobody
    #: asked about all of them": a zero ``kev_count`` is a claim, and it is
    #: only safe to render as one when this is zero too. Fleet-wide feed
    #: health cannot answer it, because a host re-scanned while a feed was
    #: down carries unchecked findings whatever the feed reports now
    #: (Req 10.16).
    kev_unchecked_count: int = 0
    #: SHA-256 fingerprint of the SSH host key pinned for this machine's
    #: hostname on the configured port, or ``None`` when nothing is pinned
    #: (Req 17.8).
    host_key_fingerprint: str | None = None
    #: The pinned key's type, e.g. ``ssh-ed25519`` (Req 17.8). Paired with the
    #: fingerprint because the type is what names the key file on the host.
    host_key_type: str | None = None
    #: The port that pin is on, which is the configured SSH port whenever there
    #: is one. The machine page lists this machine's pins on every other port
    #: beside it, and needs this to tell them apart without guessing from the
    #: fingerprint -- one sshd on two ports presents one key (Req 17.11).
    host_key_port: int | None = None
    #: What the latest successful scan changed (Req 18.6). ``None`` when it
    #: cannot say: no successful scan yet, or a baseline. ``last_scan_resolved``
    #: alone is ``None`` after a partial scan, which resolves nothing. ``None``
    #: is "not assessed" and must not be rendered as zero.
    last_scan_new: int | None = None
    last_scan_resolved: int | None = None
    #: Whether the latest successful scan was this machine's baseline.
    last_scan_baseline: bool = False
    #: Installed kernel packages that were not checked against advisories,
    #: because kernel matching is not built yet (Req 12.5). ``None`` when no
    #: inventory has been collected. Not zero, and not "no kernel findings":
    #: a question that was not asked.
    kernel_packages_unchecked: int | None = None


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
    #: ``None`` when the advisory publishes no score. Required-but-nullable
    #: rather than defaulted: a client must be handed an explicit ``null`` to
    #: render as "unscored", not an absent key it could read as zero
    #: (Req 2.7, 10.11).
    cvss_score: float | None
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
    #: ``None`` where there is no package identifier to read it from, which is
    #: not the same claim as "no fix is published" (Req 14.9).
    fix_status: str | None = None
    #: The release that has the fix, for ``newer_release`` and ``upstream``.
    fix_release: str | None = None
    #: The fixed version in that release.
    fix_release_version: str | None = None
    remediation_status: RemediationStatus | None = None
    remediation_record_id: str | None = None
    remediation_note: str | None = None
    dependencies: list[str] = Field(default_factory=list)
    depended_on_by: list[str] = Field(default_factory=list)
    #: Every installed binary built from the same source package as
    #: ``package_name``, including it (Req 2.8). A finding is reported once per
    #: source, against one representative binary; upgrading only that binary
    #: would leave the others vulnerable, so a fix command must name them all.
    #: Just ``[package_name]`` for an inventory collected before 0.8.15, and
    #: empty where no inventory was loaded.
    affected_packages: list[str] = Field(default_factory=list)
    #: How much of the host depends on this package: "low", "medium", "high",
    #: or ``None`` when the dependency graph was not built for this response
    #: (Req 10.10). ``None`` is not "low": the fleet-wide list omits the graph
    #: by design, and a default of "low" there stated an impact nobody
    #: measured. Clients must render it as unassessed.
    blast_radius: str | None = None

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

    # --- Scan history (Req 18.5, 18.6) ---------------------------------------
    #: When this finding was first seen on this machine.
    first_seen_at: datetime | None = None
    #: Whether the machine's latest successful scan reported this finding as
    #: new. Always ``False`` after a baseline, which has nothing to compare.
    is_new: bool = False


class HostKeyOut(BaseModel):
    """One pinned SSH host key (Req 17.10).

    ``machine_id`` is the enrolled machine at this address, when there is one.
    ``None`` means nothing in the fleet matches it -- a pin made by a connection
    test to an address that was never enrolled, or one on a port the deployment
    no longer uses. Those are invisible everywhere else, which is why this
    listing includes them rather than filtering to the current SSH port.
    """

    hostname: str
    port: int
    key_type: str
    fingerprint_sha256: str
    first_seen_at: datetime
    last_seen_at: datetime
    machine_id: str | None = None


class ScanRunOut(BaseModel):
    """One scan attempt on a machine (Req 18.1).

    ``new_count`` and ``resolved_count`` are ``None`` when the run cannot say:
    both for a failed scan or a baseline, ``resolved_count`` alone for a
    partial scan. ``finding_count`` is the findings stored after a successful
    run, and 0 for a failed one, whose findings are the previous scan's.
    """

    run_id: str
    scanned_at: datetime
    status: ScanStatus
    sources_ok: bool
    finding_count: int
    new_count: int | None = None
    resolved_count: int | None = None
    baseline: bool = False
    #: Why a failed run failed (Req 18.10); ``None`` when it succeeded.
    error_detail: str | None = None


class FindingChangeOut(BaseModel):
    """A finding that appeared or cleared in one scan run (Req 18.2).

    ``remediation_status`` is the CVE's current manual remediation record on
    the machine, if any. A resolved finding keeps its record untouched
    (Req 18.9), so a client can show "cleared by scan" beside a record that is
    still open.
    """

    change: FindingChange
    cve_id: str
    package_identifier: str | None = None
    package_name: str | None = None
    severity: Severity
    #: ``None`` when the finding had no published score; see
    #: :attr:`CveFindingOut.cvss_score`.
    cvss_score: float | None
    kev_listed: bool | None = None
    remediation_status: RemediationStatus | None = None


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
    #: The download succeeded and carried exactly what was already cached, so
    #: nothing was rewritten (Req 10.14). Distinct from a refresh that replaced
    #: the catalogue with identical-looking numbers.
    unchanged: bool = False


class FeedRefreshResponse(BaseModel):
    """Aggregate outcome of a manually triggered feed refresh.

    ``ok`` is false when any feed failed, so a client can surface a partial
    refresh without inspecting each result.
    """

    ok: bool
    results: list[FeedRefreshResultOut]
    #: How many stored findings the refreshed feeds changed (Req 10.15). Zero
    #: means the refresh brought no news, which is most days -- not that the
    #: reapply was skipped.
    findings_updated: int = 0


# --------------------------------------------------------------------------- #
# Action endpoint request/response models (task 8.2)
# --------------------------------------------------------------------------- #

# Upper bounds on what a request may carry (Req 16.13). Each is far above any
# honest value and exists so that one request cannot pin a worker or fill the
# database: a scan batch runs synchronously inside its request, a sweep's cost
# is addresses times ports, and a note is stored as sent.
#: The most targets in one scan batch, and hosts in one enroll -- the size of
#: the largest sweep (a /20), which is where an enroll batch comes from.
MAX_BATCH = 4096
#: A DNS name is at most 253 characters; an id or username has no business
#: being longer than a filesystem name.
MAX_HOSTNAME = 253
MAX_NAME = 255
#: A password or key passphrase.
MAX_SECRET = 1024
#: An RSA-8192 private key in PEM is under 7 KiB.
MAX_PRIVATE_KEY = 16 * 1024
#: A remediation note.
MAX_NOTE = 10_000
#: Distinct TCP ports probed per discovered address.
MAX_SWEEP_PORTS = 64

Port = Annotated[int, Field(ge=1, le=65535)]


class RemediationIn(BaseModel):
    """Request body to add or update a remediation record (Req 4.1, 4.3).

    Carries the remediation ``status`` and a free-text ``note`` (Req 4.2). The
    machine and CVE for an ``add`` come from the path; an ``update`` targets an
    existing record by its id in the path.
    """

    status: RemediationStatus
    note: str = Field(default="", max_length=MAX_NOTE)


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

    id: str = Field(max_length=MAX_NAME)
    hostname: str = Field(max_length=MAX_HOSTNAME)
    platform: Platform
    username: str | None = Field(default=None, max_length=MAX_NAME)
    password: str | None = Field(default=None, max_length=MAX_SECRET)
    private_key: str | None = Field(default=None, max_length=MAX_PRIVATE_KEY)
    passphrase: str | None = Field(default=None, max_length=MAX_SECRET)


class ScanRequest(BaseModel):
    """Request body to manually initiate a scan over a batch of targets.

    Lists the targets (with credentials) to scan. An empty list is rejected by
    validation so a scan always has at least one target (Req 1.1, 1.2).
    """

    targets: list[TargetIn] = Field(min_length=1, max_length=MAX_BATCH)


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
    #: What this scan changed (Req 18.2). ``None`` for a failed scan or a
    #: baseline; ``resolved_count`` alone is ``None`` for a partial scan.
    new_count: int | None = None
    resolved_count: int | None = None
    baseline: bool = False


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
    ports: list[Port] | None = Field(
        default=None,
        max_length=MAX_SWEEP_PORTS,
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
    #: True answered, False did not, None never asked (Req 8.11).
    responds_to_ping: bool | None = None
    open_ports: list[int] = Field(default_factory=list)
    services: list[DiscoveredServiceOut] = Field(default_factory=list)
    os_guess: str = ""


class DiscoverySweepResponse(BaseModel):
    """Aggregate result of a zero-touch network discovery sweep."""

    cidr: str
    total_hosts_scanned: int
    total_hosts_discovered: int
    #: False when this deployment cannot send ICMP at all, which makes an empty
    #: host list a statement about the sweep rather than the subnet (Req 8.11).
    icmp_checked: bool = True
    #: Addresses whose probe failed outright, so the sweep did not cover them
    #: (Req 8.12). Zero is the normal case.
    probe_errors: int = 0
    hosts: list[DiscoveredHostOut]


class HostEnrollIn(BaseModel):
    """A discovered host to enroll into the fleet roster."""

    id: str | None = Field(
        default=None,
        max_length=MAX_NAME,
        description="Machine ID (defaults to hostname if not specified)",
    )
    hostname: str = Field(
        ..., max_length=MAX_HOSTNAME, description="Target hostname or IP address"
    )
    platform: Platform = Field(
        default=Platform.LINUX,
        description="Operating system family (linux or windows)",
    )


class HostEnrollBatchIn(BaseModel):
    """Batch of discovered hosts to enroll into the fleet roster."""

    hosts: list[HostEnrollIn] = Field(
        min_length=1,
        max_length=MAX_BATCH,
        description="List of hosts to enroll into the target fleet",
    )


class HostEnrollResponse(BaseModel):
    """Result of enrolling discovered hosts into the fleet roster."""

    enrolled: list[MachineSummary]
    total_enrolled: int


class TestConnectionRequest(BaseModel):
    """Request payload to pre-flight test connection and credentials for a target."""

    hostname: str = Field(
        ..., min_length=1, max_length=MAX_HOSTNAME, description="Target hostname or IP address"
    )
    platform: Platform = Field(
        default=Platform.LINUX,
        description="Target platform family (linux or windows)",
    )
    username: str | None = Field(
        default=None,
        max_length=MAX_NAME,
        description="SSH or WinRM username; omit to use the server-managed default",
    )
    password: str | None = Field(
        default=None, max_length=MAX_SECRET, description="SSH or WinRM password"
    )
    private_key: str | None = Field(
        default=None,
        max_length=MAX_PRIVATE_KEY,
        description="SSH private key (PEM or OpenSSH format)",
    )
    passphrase: str | None = Field(
        default=None, max_length=MAX_SECRET, description="Passphrase for an encrypted private key"
    )


class TestConnectionResponse(BaseModel):
    """Result of pre-flight connection and authentication test."""

    success: bool
    status: str
    message: str
    latency_ms: float
    os_banner: str = ""
    #: The SSH host key pinned for this address after the test, or the pinned
    #: key a mismatched host failed to present (Req 17.3, 17.8).
    host_key_fingerprint: str | None = None


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


