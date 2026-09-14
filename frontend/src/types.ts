// Domain types for the CveDeck frontend.
// These mirror the backend Pydantic response models (see design.md:
// "Frontend Interfaces" and the "Backend API" response models).

/** Platform of a scanned target machine. */
export type Platform = "linux" | "windows";

/** Severity band derived from a CVE's CVSS score. */
export type Severity = "critical" | "high" | "medium" | "low";

/** Ordered list of all severity levels (highest to lowest). */
export const SEVERITIES: readonly Severity[] = [
  "critical",
  "high",
  "medium",
  "low",
];

/** Count of CVE findings grouped by severity level. */
export interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
}

/** Summary of a scanned machine as shown in the machine list. */
export interface MachineSummary {
  machineId: string;
  hostname: string;
  platform: Platform;
  /** "never_scanned", "success", "connection_failure", or "auth_failure". */
  lastScanStatus: string;
  /** ISO-8601 timestamp of the last scan, or null if never scanned. */
  lastScannedAt: string | null;
  /**
   * False when an advisory source was unreachable during the last scan, so the
   * counts are an undercount rather than a clean bill of health.
   */
  lastScanSourcesOk: boolean;
  cveCounts: SeverityCounts;
  /**
   * Findings on this host confirmed as actively exploited (CISA KEV).
   *
   * Zero means "none confirmed", not "none exist". On a deployment whose intel
   * feeds have never loaded, every host reports zero -- which is why the fleet
   * view pairs this with the enrichment warning from GET /api/feeds rather
   * than presenting a zero as reassurance.
   */
  kevCount: number;
}

/** A single CVE finding for a machine, as shown in the drill-down view. */
export interface CveFinding {
  cveId: string;
  severity: Severity;
  cvssScore: number;
  /** Affected package name, parsed server-side out of packageIdentifier. */
  packageName?: string | null;
  /** Version that fixes this CVE, or null when no fix is published. */
  fixedVersion?: string | null;
  /**
   * Whether an actionable fix exists. Replaces searching packageIdentifier for
   * the substring "fixed in", which made the exact prose an API contract.
   */
  hasFix?: boolean;
  packageIdentifier: string | null;
  remediationStatus: string | null;
  /**
   * Id of the existing remediation record, when one exists. Its presence is
   * what decides whether saving a remediation adds a new record (POST) or
   * updates the existing one (PUT).
   */
  remediationRecordId: string | null;
  /** Free-text note stored with the remediation record, when one exists. */
  remediationNote: string | null;
  /** List of package names this component directly requires. */
  dependencies?: string[];
  /** List of installed application and library packages that depend on this component (reverse dependencies). */
  dependedOnBy?: string[];
  /** Calculated blast radius risk indicator (low, medium, high). */
  blastRadius?: "low" | "medium" | "high";

  // --- Threat-intel enrichment ---------------------------------------------
  // Every field here is nullable, and null means "not enriched" -- NOT "safe".
  // Render null as unknown. Only an explicit `false` on kevListed means the CVE
  // was checked against CISA's catalogue and is genuinely absent from it.
  // Treating null as false would tell a user nothing in their fleet is being
  // exploited on the basis of a feed that was never downloaded.
  /** Whether CISA lists this CVE as actively exploited in the wild. */
  kevListed?: boolean | null;
  /** CISA's remediation due date for a KEV-listed CVE, when published. */
  kevDueDate?: string | null;
  /** FIRST's modelled probability (0.0-1.0) of exploitation within 30 days. */
  epssScore?: number | null;
  /**
   * That probability's rank among all scored CVEs. Carried alongside the raw
   * score because the EPSS distribution is heavily skewed: 0.08 sounds
   * negligible and is in fact around the 94th percentile.
   */
  epssPercentile?: number | null;
}

/** Refresh state of one locally cached threat-intel feed. */
export type FeedStatus = "never_refreshed" | "ok" | "failed";

/**
 * Cache health for one intel feed (KEV or EPSS).
 *
 * This exists so the dashboard can distinguish "no findings are
 * known-exploited" from "the KEV feed has not refreshed in three weeks". A
 * silently failing feed otherwise looks exactly like a healthy fleet.
 */
export interface FeedHealth {
  feedName: string;
  status: FeedStatus;
  /** When the feed last refreshed successfully; null if it never has. */
  lastRefreshedAt: string | null;
  /** When a refresh was last attempted, successful or not. */
  lastAttemptedAt: string | null;
  recordCount: number;
  errorDetail: string | null;
  /** Cache is older than the configured maximum age, or was never populated. */
  stale: boolean;
  /** Whether the cache holds data that can enrich findings at all. */
  usable: boolean;
}

/** Outcome of refreshing one feed via POST /api/feeds/refresh. */
export interface FeedRefreshResult {
  feedName: string;
  status: FeedStatus;
  recordCount: number;
  errorDetail: string | null;
}

/** Aggregate outcome of a manually triggered feed refresh. */
export interface FeedRefreshOutcome {
  /** False when any feed failed, so a partial refresh is visible at a glance. */
  ok: boolean;
  results: FeedRefreshResult[];
}

/** Manually maintained remediation state for a CVE on a machine. */
export type RemediationStatus =
  | "open"
  | "in_progress"
  | "remediated"
  | "accepted_risk";

/** Ordered list of all remediation statuses, as offered in the UI. */
export const REMEDIATION_STATUSES: readonly RemediationStatus[] = [
  "open",
  "in_progress",
  "remediated",
  "accepted_risk",
];

/** Payload for creating a remediation record. */
export interface RemediationInput {
  status: string;
  note: string;
}

/** A target machine to scan, with the credentials used to reach it. */
export interface ScanTargetInput {
  id: string;
  hostname: string;
  platform: Platform;
  /**
   * Credentials are all optional: a Linux target may omit them entirely and
   * authenticate with the deployment's server-managed SSH key, which is what
   * makes a fleet re-scan possible without retyping a password per host. Supply
   * either a password or a privateKey, never both.
   */
  username?: string;
  password?: string;
  privateKey?: string;
  passphrase?: string;
}

/** Per-target outcome of a scan, as reported by POST /api/scans. */
export interface ScanOutcome {
  machineId: string;
  /** "never_scanned", "success", "connection_failure", or "auth_failure". */
  status: string;
  findingCount: number;
  /** False when a configured advisory source did not answer. */
  sourcesOk: boolean;
  /** Names of the sources that did not answer (e.g. ["OSV"]). */
  unavailableSources: string[];
  /** The originating error, or a partial-results notice. Null on a clean run. */
  message: string | null;
}

/** Deployment capabilities reported by the backend. */
export interface ServerCapabilities {
  /** Whether a server-managed SSH key is configured, enabling fleet re-scan. */
  serverSshKey: boolean;
  /** Whether a default SSH username is configured. */
  defaultSshUser: boolean;
  /**
   * The backend's version string, as reported by GET /api/health.
   *
   * The header badge renders this rather than a literal, because the version a
   * user quotes in a bug report has to be the version that is actually running.
   * A hardcoded badge is a fourth place for the number to drift -- and the one
   * place nothing verifies, since the release workflow only gates pyproject.toml
   * and app.py. Null until the first health response arrives, or if it fails.
   */
  version: string | null;
  /**
   * Whether this deployment is a public demo.
   *
   * When true the backend refuses scans, discovery sweeps and connection
   * tests, so the UI says so rather than offering controls that are certain to
   * return 403.
   */
  demoMode: boolean;
  /**
   * Whether this deployment asks for a login (Req 16.9). False when login is
   * disabled or in demo mode, which is when the account controls are hidden.
   */
  loginRequired: boolean;
}

/**
 * What the dashboard shows before anything else (Req 16.3).
 *
 * - `setup_required`: no account exists yet; show the setup page.
 * - `signed_out`: show the sign-in page.
 * - `signed_in`: show the dashboard, with the account controls.
 * - `open`: login is not required here; show the dashboard without them.
 */
export type AuthStateName = "setup_required" | "signed_out" | "signed_in" | "open";

export interface AuthState {
  state: AuthStateName;
  username: string | null;
}

/** An API token as listed. Never carries the token itself (Req 16.7). */
export interface ApiToken {
  tokenId: string;
  name: string;
  /** The first characters, enough to recognise it and no more. */
  prefix: string;
  createdAt: string;
  lastUsedAt: string | null;
  revokedAt: string | null;
}

/** The one response that includes the token; it cannot be fetched again. */
export interface CreatedApiToken extends ApiToken {
  token: string;
}

/** A persisted remediation record returned by the backend. */
export interface RemediationRecord {
  recordId: string;
  machineId: string;
  cveId: string;
  status: string;
  note: string;
}

// --------------------------------------------------------------------------- //
// Network Discovery (Phase 1 zero-touch sweep)
// --------------------------------------------------------------------------- //

/** Information about a single open port on a discovered host. */
export interface DiscoveredService {
  port: number;
  protocol: string;
  banner: string;
  product: string;
  version: string;
  extraInfo: string;
}

/** A host found during network discovery. */
export interface DiscoveredHost {
  ip: string;
  hostname: string;
  respondsToPing: boolean;
  openPorts: number[];
  services: DiscoveredService[];
  osGuess: string;
}

/** Aggregate result of a zero-touch network discovery sweep. */
export interface DiscoverySweepResult {
  cidr: string;
  totalHostsScanned: number;
  totalHostsDiscovered: number;
  hosts: DiscoveredHost[];
}

/** Input payload to enroll a discovered host into the fleet roster. */
export interface HostEnrollInput {
  id?: string;
  hostname: string;
  platform: Platform;
}

/** Input payload for pre-flight connection test. */
export interface TestConnectionInput {
  hostname: string;
  platform: Platform;
  /**
   * Credentials mirror ScanTargetInput so pre-flight and the real scan cannot
   * disagree about how a host is reached. All optional: a Linux target may omit
   * them and use the server-managed SSH key.
   */
  username?: string;
  password?: string;
  privateKey?: string;
  passphrase?: string;
}

/** Result of pre-flight connection test. */
export interface TestConnectionResult {
  success: boolean;
  status: string;
  message: string;
  latencyMs: number;
  osBanner: string;
}


