// API client for the CveDeck backend.
//
// Surfaces the server's own explanation for a failure rather than a bare
// status code (Req 10.6), and aborts a request that exceeds its deadline
// rather than awaiting indefinitely (Req 10.7).
//
// Endpoints (see design.md "Backend API"):
//   GET  /api/machines                                     -> MachineSummary[]
//   GET  /api/machines/{id}                                -> MachineSummary (404 if unknown)
//   GET  /api/machines/{id}/cves?severity=                 -> CveFinding[]
//   GET  /api/cves?severity=                               -> CveFinding[]
//   POST /api/machines/{id}/cves/{cveId}/remediation       -> RemediationRecord
//   PUT  /api/remediation/{recordId}                       -> RemediationRecord
//   POST /api/scans                                        -> scan trigger
//   POST /api/sync                                         -> sync trigger
//   GET  /api/feeds                                        -> FeedHealth[]
//   POST /api/feeds/refresh                                -> FeedRefreshOutcome

import type {
  CveFinding,
  DiscoveredHost,
  DiscoveredService,
  DiscoverySweepResult,
  HostEnrollInput,
  MachineSummary,
  RemediationInput,
  RemediationRecord,
  FindingChangeRow,
  HostKeyPin,
  ScanOutcome,
  ScanRun,
  ScanTargetInput,
  Severity,
  TestConnectionInput,
  TestConnectionResult,
  ServerCapabilities,
  FeedHealth,
  FeedRefreshOutcome,
  FeedStatus,
  ApiToken,
  AuthState,
  CreatedApiToken,
} from "../types";

/** Error thrown when the backend returns a non-2xx response. */
export class ApiError extends Error {
  readonly status: number;
  /** The backend's `detail` string, when it sent one. */
  readonly detail: string | null;

  constructor(status: number, message: string, detail: string | null = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

/** Thrown when a request exceeds its deadline or is cancelled by the caller. */
export class ApiTimeoutError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "ApiTimeoutError";
  }
}

/**
 * Pull a human-readable reason out of an error response body.
 *
 * FastAPI puts the only useful explanation in `detail` -- a string for
 * `HTTPException`, or an array of per-field objects for a 422 validation
 * error. Reporting just the status code turns "Invalid CIDR: '10.0.0'" into
 * "failed with status 422", which tells the user nothing they can act on.
 */
async function readErrorDetail(response: Response): Promise<string | null> {
  let raw: string;
  try {
    raw = await response.text();
  } catch {
    return null;
  }
  if (!raw) return null;

  try {
    const parsed = JSON.parse(raw) as unknown;
    const detail = (parsed as { detail?: unknown })?.detail;
    if (typeof detail === "string" && detail.trim()) {
      return detail.trim();
    }
    if (Array.isArray(detail)) {
      // 422 validation errors: [{loc: [...], msg: "..."}]
      const messages = detail
        .map((item) => {
          const msg = (item as { msg?: unknown })?.msg;
          const loc = (item as { loc?: unknown })?.loc;
          const field = Array.isArray(loc) ? loc.slice(1).join(".") : "";
          if (typeof msg !== "string") return null;
          return field ? `${field}: ${msg}` : msg;
        })
        .filter((m): m is string => Boolean(m));
      if (messages.length) return messages.join("; ");
    }
  } catch {
    // Not JSON -- a proxy error page or a plain-text body. Use it as-is if it
    // is short enough to be a message rather than a document.
    const trimmed = raw.trim();
    if (trimmed && trimmed.length <= 300 && !trimmed.startsWith("<")) {
      return trimmed;
    }
  }
  return null;
}

/**
 * Default per-request deadline. A scan is synchronous and can legitimately take
 * minutes on a host with thousands of packages, so this is deliberately long --
 * it exists to bound a hang, not to enforce a latency budget.
 */
const DEFAULT_TIMEOUT_MS = 10 * 60 * 1000;

export interface ApiClientOptions {
  /** Base URL for the backend API. Defaults to same-origin (proxied in dev). */
  baseUrl?: string;
  /** Injectable fetch implementation, primarily for testing. */
  fetchImpl?: typeof fetch;
  /**
   * Per-request deadline in milliseconds. Generous by default because a scan
   * SSHes into a host, enumerates every package, and queries OSV synchronously.
   * Set to 0 to disable.
   */
  timeoutMs?: number;
  /**
   * Called when a request is refused for want of a session (HTTP 401), other
   * than the sign-in routes themselves. The auth gate uses it to return to the
   * sign-in page when a session expires mid-use, rather than leaving every
   * panel to show its own error (Req 16.5).
   */
  onUnauthorized?: () => void;
}

// --------------------------------------------------------------------------- //
// Backend wire shapes and mapping
//
// The backend serializes its Pydantic response models with snake_case keys
// (see backend/app/api/schemas.py: MachineSummary, CveFindingOut,
// RemediationOut). The frontend domain types (src/types.ts) use camelCase, so
// the client maps each response from the wire shape into the frontend shape.
// This is the seam that makes the end-to-end data flow resolve.
// --------------------------------------------------------------------------- //

/** Wire shape of a machine summary as serialized by the backend. */
interface MachineSummaryWire {
  machine_id: string;
  hostname: string;
  platform: MachineSummary["platform"];
  last_scan_status: string;
  last_scanned_at?: string | null;
  last_scan_sources_ok?: boolean;
  cve_counts: MachineSummary["cveCounts"];
  kev_count?: number;
  host_key_fingerprint?: string | null;
  host_key_type?: string | null;
  last_scan_new?: number | null;
  last_scan_resolved?: number | null;
  last_scan_baseline?: boolean;
}

/** Wire shape of a CVE finding as serialized by the backend. */
interface CveFindingWire {
  cve_id: string;
  severity: CveFinding["severity"];
  cvss_score: number;
  package_identifier: string | null;
  package_name?: string | null;
  fixed_version?: string | null;
  has_fix?: boolean;
  fix_status?: CveFinding["fixStatus"];
  fix_release?: string | null;
  fix_release_version?: string | null;
  remediation_status: string | null;
  remediation_record_id: string | null;
  remediation_note: string | null;
  dependencies?: string[];
  depended_on_by?: string[];
  blast_radius?: "low" | "medium" | "high";
  // Threat-intel enrichment. Null means unenriched, not safe -- see types.ts.
  kev_listed?: boolean | null;
  kev_due_date?: string | null;
  epss_score?: number | null;
  epss_percentile?: number | null;
  first_seen_at?: string | null;
  is_new?: boolean;
}

/** Wire shape of a per-target scan outcome as serialized by the backend. */
interface MachineScanWire {
  machine_id: string;
  status: string;
  finding_count: number;
  sources_ok?: boolean;
  unavailable_sources?: string[];
  message?: string | null;
  new_count?: number | null;
  resolved_count?: number | null;
  baseline?: boolean;
}

/** Wire shape of GET /api/host-keys. */
interface HostKeyWire {
  hostname: string;
  port: number;
  key_type: string;
  fingerprint_sha256: string;
  first_seen_at: string;
  last_seen_at: string;
  machine_id: string | null;
}

/** Wire shape of GET /api/machines/{id}/scans. */
interface ScanRunWire {
  run_id: string;
  scanned_at: string;
  status: string;
  sources_ok: boolean;
  finding_count: number;
  new_count: number | null;
  resolved_count: number | null;
  baseline: boolean;
}

/** Wire shape of GET /api/machines/{id}/scans/{run_id}/changes. */
interface FindingChangeWire {
  change: "new" | "resolved";
  cve_id: string;
  package_identifier: string | null;
  package_name: string | null;
  severity: Severity;
  cvss_score: number;
  kev_listed: boolean | null;
  remediation_status: string | null;
}

/** Wire shape of the POST /api/scans response. */
/** Deployment capabilities reported by GET /api/health. */
interface HealthWire {
  status: string;
  version: string;
  capabilities?: {
    server_ssh_key?: boolean;
    default_ssh_user?: boolean;
    demo_mode?: boolean;
    login_required?: boolean;
  };
}

interface AuthStateWire {
  state: AuthState["state"];
  username?: string | null;
}

interface ApiTokenWire {
  token_id: string;
  name: string;
  prefix: string;
  created_at: string;
  last_used_at?: string | null;
  revoked_at?: string | null;
}

function toApiToken(wire: ApiTokenWire): ApiToken {
  return {
    tokenId: wire.token_id,
    name: wire.name,
    prefix: wire.prefix,
    createdAt: wire.created_at,
    lastUsedAt: wire.last_used_at ?? null,
    revokedAt: wire.revoked_at ?? null,
  };
}

interface ScanResponseWire {
  machine_scans: MachineScanWire[];
}

/** Wire shape of a remediation record as serialized by the backend. */
interface RemediationRecordWire {
  record_id: string;
  machine_id: string;
  cve_id: string;
  status: string;
  note: string;
}

/** Wire shape of a discovered service as serialized by the backend. */
interface DiscoveredServiceWire {
  port: number;
  protocol: string;
  banner: string;
  product: string;
  version: string;
  extra_info: string;
}

/** Wire shape of a discovered host as serialized by the backend. */
interface DiscoveredHostWire {
  ip: string;
  hostname: string;
  responds_to_ping: boolean;
  open_ports: number[];
  services: DiscoveredServiceWire[];
  os_guess: string;
}

/** Wire shape of the POST /api/discovery/sweep response. */
interface DiscoverySweepResponseWire {
  cidr: string;
  total_hosts_scanned: number;
  total_hosts_discovered: number;
  hosts: DiscoveredHostWire[];
}

/** Wire shape of the POST /api/discovery/enroll response. */
interface HostEnrollResponseWire {
  enrolled: MachineSummaryWire[];
  total_enrolled: number;
}

function toMachineSummary(wire: MachineSummaryWire): MachineSummary {
  return {
    machineId: wire.machine_id,
    hostname: wire.hostname,
    platform: wire.platform,
    lastScanStatus: wire.last_scan_status,
    lastScannedAt: wire.last_scanned_at ?? null,
    lastScanSourcesOk: wire.last_scan_sources_ok ?? true,
    cveCounts: {
      critical: wire.cve_counts.critical,
      high: wire.cve_counts.high,
      medium: wire.cve_counts.medium,
      low: wire.cve_counts.low,
    },
    kevCount: wire.kev_count ?? 0,
    hostKeyFingerprint: wire.host_key_fingerprint ?? null,
    hostKeyType: wire.host_key_type ?? null,
    lastScanNew: wire.last_scan_new ?? null,
    lastScanResolved: wire.last_scan_resolved ?? null,
    lastScanBaseline: wire.last_scan_baseline ?? false,
  };
}

function toCveFinding(wire: CveFindingWire): CveFinding {
  return {
    cveId: wire.cve_id,
    severity: wire.severity,
    cvssScore: wire.cvss_score,
    packageIdentifier: wire.package_identifier ?? null,
    packageName: wire.package_name ?? null,
    fixedVersion: wire.fixed_version ?? null,
    hasFix: wire.has_fix ?? undefined,
    fixStatus: wire.fix_status ?? undefined,
    fixRelease: wire.fix_release ?? null,
    fixReleaseVersion: wire.fix_release_version ?? null,
    remediationStatus: wire.remediation_status ?? null,
    remediationRecordId: wire.remediation_record_id ?? null,
    remediationNote: wire.remediation_note ?? null,
    dependencies: wire.dependencies ?? [],
    dependedOnBy: wire.depended_on_by ?? [],
    blastRadius: wire.blast_radius ?? "low",
    // `?? null` deliberately, never `?? false`: an absent field means the
    // backend did not enrich this finding, which is not the same claim as
    // "this CVE is not being exploited".
    kevListed: wire.kev_listed ?? null,
    kevDueDate: wire.kev_due_date ?? null,
    epssScore: wire.epss_score ?? null,
    epssPercentile: wire.epss_percentile ?? null,
    firstSeenAt: wire.first_seen_at ?? null,
    isNew: wire.is_new ?? false,
  };
}

/** Wire shape of one feed's cache health. */
interface FeedHealthWire {
  feed_name: string;
  status: FeedStatus;
  last_refreshed_at?: string | null;
  last_attempted_at?: string | null;
  record_count?: number;
  error_detail?: string | null;
  stale?: boolean;
  usable?: boolean;
}

interface FeedRefreshResultWire {
  feed_name: string;
  status: FeedStatus;
  record_count?: number;
  error_detail?: string | null;
}

interface FeedRefreshResponseWire {
  ok: boolean;
  results: FeedRefreshResultWire[];
}

function toFeedHealth(wire: FeedHealthWire): FeedHealth {
  return {
    feedName: wire.feed_name,
    status: wire.status,
    lastRefreshedAt: wire.last_refreshed_at ?? null,
    lastAttemptedAt: wire.last_attempted_at ?? null,
    recordCount: wire.record_count ?? 0,
    errorDetail: wire.error_detail ?? null,
    // Both default to the pessimistic reading. If the backend omitted these,
    // claiming the cache is fresh and usable would be a guess in the one
    // direction that hides a degraded feed.
    stale: wire.stale ?? true,
    usable: wire.usable ?? false,
  };
}

function toScanOutcome(wire: MachineScanWire): ScanOutcome {
  return {
    machineId: wire.machine_id,
    status: wire.status,
    findingCount: wire.finding_count,
    sourcesOk: wire.sources_ok ?? true,
    unavailableSources: wire.unavailable_sources ?? [],
    message: wire.message ?? null,
    newCount: wire.new_count ?? null,
    resolvedCount: wire.resolved_count ?? null,
    baseline: wire.baseline ?? false,
  };
}

function toRemediationRecord(wire: RemediationRecordWire): RemediationRecord {
  return {
    recordId: wire.record_id,
    machineId: wire.machine_id,
    cveId: wire.cve_id,
    status: wire.status,
    note: wire.note,
  };
}

function toDiscoveredService(wire: DiscoveredServiceWire): DiscoveredService {
  return {
    port: wire.port,
    protocol: wire.protocol,
    banner: wire.banner,
    product: wire.product,
    version: wire.version,
    extraInfo: wire.extra_info,
  };
}

function toDiscoveredHost(wire: DiscoveredHostWire): DiscoveredHost {
  return {
    ip: wire.ip,
    hostname: wire.hostname,
    respondsToPing: wire.responds_to_ping,
    openPorts: wire.open_ports,
    services: wire.services.map(toDiscoveredService),
    osGuess: wire.os_guess,
  };
}

interface TestConnectionResponseWire {
  success: boolean;
  status: string;
  message: string;
  latency_ms: number;
  os_banner: string;
  host_key_fingerprint?: string | null;
}

function toTestConnectionResult(wire: TestConnectionResponseWire): TestConnectionResult {
  return {
    success: wire.success,
    status: wire.status,
    message: wire.message,
    latencyMs: wire.latency_ms,
    osBanner: wire.os_banner,
    hostKeyFingerprint: wire.host_key_fingerprint ?? null,
  };
}

function toDiscoverySweepResult(wire: DiscoverySweepResponseWire): DiscoverySweepResult {
  return {
    cidr: wire.cidr,
    totalHostsScanned: wire.total_hosts_scanned,
    totalHostsDiscovered: wire.total_hosts_discovered,
    hosts: wire.hosts.map(toDiscoveredHost),
  };
}

/**
 * Routes whose 401 is an answer about the form, not an expired session: a wrong
 * password on the sign-in page must show an error there, not bounce to it.
 */
const PUBLIC_AUTH_PATHS = new Set([
  "/api/auth/state",
  "/api/auth/login",
  "/api/auth/setup",
  "/api/auth/logout",
]);

export class CveScannerApiClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: typeof fetch;
  private readonly timeoutMs: number;
  private readonly onUnauthorized: (() => void) | undefined;

  constructor(options: ApiClientOptions = {}) {
    // Strip any trailing slash so path joins are predictable.
    this.baseUrl = (options.baseUrl ?? "").replace(/\/$/, "");
    // Bound to globalThis on purpose: the default is called as this.fetchImpl,
    // which would otherwise invoke the browser's fetch with the client as its
    // receiver. Browsers reject that with "Illegal invocation".
    this.fetchImpl = options.fetchImpl ?? fetch.bind(globalThis);
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.onUnauthorized = options.onUnauthorized;
  }

  // ------------------------------------------------------------------------ //
  // Access control (Req 16)
  // ------------------------------------------------------------------------ //

  /** GET /api/auth/state -- setup, sign-in, or straight to the dashboard. */
  async getAuthState(): Promise<AuthState> {
    const wire = await this.request<AuthStateWire>("GET", "/api/auth/state");
    return { state: wire.state, username: wire.username ?? null };
  }

  /** POST /api/auth/login -- the response sets the session cookie. */
  async login(username: string, password: string): Promise<AuthState> {
    const wire = await this.request<AuthStateWire>("POST", "/api/auth/login", {
      username,
      password,
    });
    return { state: wire.state, username: wire.username ?? null };
  }

  /** POST /api/auth/setup -- create the first account with the logged code. */
  async completeSetup(
    setupCode: string,
    username: string,
    password: string,
  ): Promise<AuthState> {
    const wire = await this.request<AuthStateWire>("POST", "/api/auth/setup", {
      setup_code: setupCode,
      username,
      password,
    });
    return { state: wire.state, username: wire.username ?? null };
  }

  /** POST /api/auth/logout */
  async logout(): Promise<void> {
    await this.request<void>("POST", "/api/auth/logout");
  }

  /** PUT /api/auth/password -- signs out every other session. */
  async changePassword(currentPassword: string, newPassword: string): Promise<void> {
    await this.request<void>("PUT", "/api/auth/password", {
      current_password: currentPassword,
      new_password: newPassword,
    });
  }

  /** GET /api/auth/tokens */
  async listApiTokens(): Promise<ApiToken[]> {
    const wire = await this.request<ApiTokenWire[]>("GET", "/api/auth/tokens");
    return (wire ?? []).map(toApiToken);
  }

  /** POST /api/auth/tokens -- the only response that carries the token. */
  async createApiToken(name: string): Promise<CreatedApiToken> {
    const wire = await this.request<ApiTokenWire & { token: string }>(
      "POST",
      "/api/auth/tokens",
      { name },
    );
    return { ...toApiToken(wire), token: wire.token };
  }

  /** DELETE /api/auth/tokens/{tokenId} */
  async revokeApiToken(tokenId: string): Promise<void> {
    await this.request<void>(
      "DELETE",
      `/api/auth/tokens/${encodeURIComponent(tokenId)}`,
    );
  }

  /** GET /api/host-keys -- every pinned SSH host key (Req 17.10). */
  async listHostKeys(): Promise<HostKeyPin[]> {
    const wire = await this.request<HostKeyWire[]>("GET", "/api/host-keys");
    return wire.map((pin) => ({
      hostname: pin.hostname,
      port: pin.port,
      keyType: pin.key_type,
      fingerprint: pin.fingerprint_sha256,
      firstSeenAt: pin.first_seen_at,
      lastSeenAt: pin.last_seen_at,
      machineId: pin.machine_id,
    }));
  }

  /**
   * DELETE /api/host-keys/{hostname} -- forget the pinned SSH host key, so the
   * next connection trusts whatever key the host presents (Req 17.7).
   *
   * The port is part of the address a key is pinned under, so it travels with
   * the request; omitted, the server forgets the pin on the configured SSH
   * port, which is the one a machine page shows.
   */
  async forgetHostKey(hostname: string, port?: number): Promise<void> {
    const query = port === undefined ? "" : `?port=${port}`;
    await this.request<void>(
      "DELETE",
      `/api/host-keys/${encodeURIComponent(hostname)}${query}`,
    );
  }

  /** GET /api/machines/{id}/scans -- a host's scan runs, newest first (Req 18.1). */
  async listScanRuns(machineId: string, limit = 20): Promise<ScanRun[]> {
    const wire = await this.request<ScanRunWire[]>(
      "GET",
      `/api/machines/${encodeURIComponent(machineId)}/scans?limit=${limit}`,
    );
    return wire.map((run) => ({
      runId: run.run_id,
      scannedAt: run.scanned_at,
      status: run.status,
      sourcesOk: run.sources_ok,
      findingCount: run.finding_count,
      newCount: run.new_count,
      resolvedCount: run.resolved_count,
      baseline: run.baseline,
    }));
  }

  /** GET /api/machines/{id}/scans/{run_id}/changes (Req 18.2). */
  async listScanChanges(machineId: string, runId: string): Promise<FindingChangeRow[]> {
    const wire = await this.request<FindingChangeWire[]>(
      "GET",
      `/api/machines/${encodeURIComponent(machineId)}/scans/${encodeURIComponent(runId)}/changes`,
    );
    return wire.map((c) => ({
      change: c.change,
      cveId: c.cve_id,
      packageIdentifier: c.package_identifier,
      packageName: c.package_name,
      severity: c.severity,
      cvssScore: c.cvss_score,
      kevListed: c.kev_listed,
      remediationStatus: c.remediation_status,
    }));
  }

  /** GET /api/machines */
  async listMachines(): Promise<MachineSummary[]> {
    const wire = await this.request<MachineSummaryWire[]>(
      "GET",
      "/api/machines",
    );
    return wire.map(toMachineSummary);
  }

  /** GET /api/machines/{machineId} */
  async getMachine(machineId: string): Promise<MachineSummary> {
    const wire = await this.request<MachineSummaryWire>(
      "GET",
      `/api/machines/${encodeURIComponent(machineId)}`,
    );
    return toMachineSummary(wire);
  }

  /** GET /api/machines/{machineId}/cves?severity= */
  async getMachineCves(
    machineId: string,
    severity?: Severity,
  ): Promise<CveFinding[]> {
    const path = `/api/machines/${encodeURIComponent(machineId)}/cves`;
    const wire = await this.request<CveFindingWire[]>(
      "GET",
      this.withSeverity(path, severity),
    );
    return wire.map(toCveFinding);
  }

  /** GET /api/cves?severity= */
  async listCves(severity?: Severity): Promise<CveFinding[]> {
    const wire = await this.request<CveFindingWire[]>(
      "GET",
      this.withSeverity("/api/cves", severity),
    );
    return wire.map(toCveFinding);
  }

  /** POST /api/machines/{machineId}/cves/{cveId}/remediation */
  async addRemediation(
    machineId: string,
    cveId: string,
    input: RemediationInput,
  ): Promise<RemediationRecord> {
    const path =
      `/api/machines/${encodeURIComponent(machineId)}` +
      `/cves/${encodeURIComponent(cveId)}/remediation`;
    const wire = await this.request<RemediationRecordWire>(
      "POST",
      path,
      input,
    );
    return toRemediationRecord(wire);
  }

  /** PUT /api/remediation/{recordId} */
  async updateRemediation(
    recordId: string,
    input: RemediationInput,
  ): Promise<RemediationRecord> {
    const wire = await this.request<RemediationRecordWire>(
      "PUT",
      `/api/remediation/${encodeURIComponent(recordId)}`,
      input,
    );
    return toRemediationRecord(wire);
  }

  /**
   * POST /api/scans -- scan a batch of targets and return the per-target outcome.
   *
   * The backend rejects an empty target list (ScanRequest requires at least
   * one), so callers must supply at least one target. Credentials travel in the
   * request body and are never echoed back in the response.
   */
  /**
   * Deployment capabilities, used to decide what the UI may offer.
   *
   * Fleet re-scan needs a server-managed SSH key; without one those scans have
   * no credentials, so the UI hides the controls rather than showing buttons
   * that are guaranteed to fail.
   */
  async getCapabilities(): Promise<ServerCapabilities> {
    const wire = await this.request<HealthWire>("GET", "/api/health");
    return {
      serverSshKey: wire.capabilities?.server_ssh_key ?? false,
      defaultSshUser: wire.capabilities?.default_ssh_user ?? false,
      version: wire.version ?? null,
      demoMode: wire.capabilities?.demo_mode ?? false,
      loginRequired: wire.capabilities?.login_required ?? false,
    };
  }

  /**
   * POST /api/scans -- scan a batch of targets.
   *
   * Credential fields are mapped explicitly rather than spreading the input:
   * the wire format is snake_case, so a spread would send `privateKey` and the
   * backend would silently ignore it and fall back to the server key. Omitted
   * fields are left out entirely so the backend's own default applies.
   */
  async startScan(targets: ScanTargetInput[]): Promise<ScanOutcome[]> {
    const wire = await this.request<ScanResponseWire>("POST", "/api/scans", {
      targets: targets.map((target) => ({
        id: target.id,
        hostname: target.hostname,
        platform: target.platform,
        username: target.username ?? null,
        password: target.password ?? null,
        private_key: target.privateKey ?? null,
        passphrase: target.passphrase ?? null,
      })),
    });
    return wire.machine_scans.map(toScanOutcome);
  }

  /**
   * GET /api/feeds -- cache health for each threat-intel feed (KEV, EPSS).
   *
   * Drives the staleness banner. Without it the dashboard cannot tell a fleet
   * with nothing known-exploited from one whose KEV feed stopped updating.
   */
  async getFeeds(): Promise<FeedHealth[]> {
    const wire = await this.request<FeedHealthWire[]>("GET", "/api/feeds");
    return (wire ?? []).map(toFeedHealth);
  }

  /**
   * POST /api/feeds/refresh -- pull the KEV and EPSS feeds.
   *
   * Downloads a few megabytes from two upstreams, so it is slower than a
   * typical action. Enrichment is applied at scan time, so a refresh takes
   * effect on the next scan rather than retroactively.
   */
  async refreshFeeds(): Promise<FeedRefreshOutcome> {
    const wire = await this.request<FeedRefreshResponseWire>(
      "POST",
      "/api/feeds/refresh",
    );
    return {
      ok: wire.ok,
      results: (wire.results ?? []).map((result) => ({
        feedName: result.feed_name,
        status: result.status,
        recordCount: result.record_count ?? 0,
        errorDetail: result.error_detail ?? null,
      })),
    };
  }

  /** POST /api/sync */
  triggerSync(): Promise<unknown> {
    return this.request<unknown>("POST", "/api/sync", {});
  }

  /**
   * POST /api/discovery/sweep -- zero-touch network discovery.
   *
   * Scans a CIDR range using ICMP ping, TCP connect probes, and
   * unauthenticated banner grabbing. No credentials required.
   */
  async discoverySweep(
    cidr: string,
    options?: { ports?: number[]; grabBanners?: boolean },
  ): Promise<DiscoverySweepResult> {
    const wire = await this.request<DiscoverySweepResponseWire>(
      "POST",
      "/api/discovery/sweep",
      {
        cidr,
        ports: options?.ports ?? null,
        grab_banners: options?.grabBanners ?? true,
      },
    );
    return toDiscoverySweepResult(wire);
  }

  /**
   * POST /api/discovery/enroll -- enroll discovered hosts into the fleet roster.
   */
  async enrollHosts(hosts: HostEnrollInput[]): Promise<MachineSummary[]> {
    const wire = await this.request<HostEnrollResponseWire>(
      "POST",
      "/api/discovery/enroll",
      {
        hosts: hosts.map((h) => ({
          id: h.id ?? null,
          hostname: h.hostname,
          platform: h.platform,
        })),
      },
    );
    return wire.enrolled.map(toMachineSummary);
  }

  /**
   * POST /api/scans/test-connection -- test credentials and connectivity before full scan.
   */
  async testConnection(input: TestConnectionInput): Promise<TestConnectionResult> {
    const wire = await this.request<TestConnectionResponseWire>(
      "POST",
      "/api/scans/test-connection",
      {
        hostname: input.hostname,
        platform: input.platform,
        // Mapped explicitly to snake_case, like startScan: a spread would send
        // camelCase privateKey and the backend would silently ignore it.
        username: input.username ?? null,
        password: input.password ?? null,
        private_key: input.privateKey ?? null,
        passphrase: input.passphrase ?? null,
      },
    );
    return toTestConnectionResult(wire);
  }

  private withSeverity(path: string, severity?: Severity): string {
    if (!severity) {
      return path;
    }
    const query = new URLSearchParams({ severity });
    return `${path}?${query.toString()}`;
  }

  private async request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    const headers: Record<string, string> = {};
    let payload: string | undefined;
    if (body !== undefined) {
      headers["Content-Type"] = "application/json";
      payload = JSON.stringify(body);
    }

    // Without a deadline a hung backend leaves the caller awaiting forever,
    // which in the UI means a permanently disabled button and no way back
    // short of a reload (Req 10.7).
    const controller =
      typeof AbortController !== "undefined" ? new AbortController() : null;
    const timer =
      controller && this.timeoutMs > 0
        ? setTimeout(() => controller.abort(), this.timeoutMs)
        : null;

    let response: Response;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method,
        headers,
        body: payload,
        signal: controller?.signal,
        // The session is a cookie. Same-origin requests send it anyway;
        // "include" keeps a split deployment (CVEDECK_CORS_ORIGINS) working.
        credentials: "include",
      });
    } catch (error) {
      if ((error as { name?: string })?.name === "AbortError") {
        throw new ApiTimeoutError(
          `Request ${method} ${path} timed out after ${Math.round(
            this.timeoutMs / 1000,
          )}s. The server may still be working -- check the machine list.`,
        );
      }
      throw error;
    } finally {
      if (timer !== null) clearTimeout(timer);
    }

    if (response.status === 401 && !PUBLIC_AUTH_PATHS.has(path)) {
      this.onUnauthorized?.();
    }

    if (!response.ok) {
      const detail = await readErrorDetail(response);
      throw new ApiError(
        response.status,
        detail ?? `Request ${method} ${path} failed with status ${response.status}`,
        detail,
      );
    }

    // 204 No Content or empty bodies resolve to undefined.
    if (response.status === 204) {
      return undefined as T;
    }

    const text = await response.text();
    if (text.length === 0) {
      return undefined as T;
    }
    return JSON.parse(text) as T;
  }
}
