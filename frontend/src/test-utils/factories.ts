// Test data builders.
//
// Tests construct domain objects with only the fields they actually assert on;
// these builders supply sensible values for the rest. Without them, every new
// field on a domain type breaks every test fixture that ever built one, which
// creates pressure to make fields optional purely to keep tests compiling.

import type {
  CveFinding,
  MachineSummary,
  ScanJob,
  ScanSchedule,
  ScanOutcome,
  SeverityCounts,
} from "../types";

const NO_CVES: SeverityCounts = {
  critical: 0,
  unscored: 0,
  high: 0,
  medium: 0,
  low: 0,
};

export function makeMachine(
  overrides: Partial<MachineSummary> = {},
): MachineSummary {
  return {
    machineId: "m1",
    hostname: "host-1.example.com",
    platform: "linux",
    lastScanStatus: "success",
    lastScannedAt: "2026-09-01T12:00:00Z",
    lastScanSourcesOk: true,
    cveCounts: { ...NO_CVES },
    kevCount: 0,
    kevUncheckedCount: 0,
    hostKeyFingerprint: null,
    hostKeyType: null,
    hostKeyPort: null,
    lastScanNew: null,
    lastScanResolved: null,
    kernelPackagesUnchecked: null,
    lastScanBaseline: false,
    ...overrides,
  };
}

export function makeScanOutcome(
  overrides: Partial<ScanOutcome> = {},
): ScanOutcome {
  return {
    machineId: "m1",
    status: "success",
    findingCount: 0,
    sourcesOk: true,
    unavailableSources: [],
    message: null,
    newCount: null,
    resolvedCount: null,
    baseline: false,
    ...overrides,
  };
}

/** A background scan job (Req 19): one host, finished, by default. */
export function makeScanJob(overrides: Partial<ScanJob> = {}): ScanJob {
  return {
    id: "job-1",
    status: "finished",
    requestedBy: "open",
    createdAt: "2026-10-18T10:00:00Z",
    startedAt: "2026-10-18T10:00:00Z",
    finishedAt: "2026-10-18T10:00:05Z",
    errorDetail: null,
    cancellable: false,
    cancelRequested: false,
    targets: [{ machineId: "m1", hostname: "web-01", state: "done", outcome: makeScanOutcome() }],
    ...overrides,
  };
}

/** The daily scheduled scan (Req 20): off, with a server key and two hosts, by default. */
export function makeScanSchedule(overrides: Partial<ScanSchedule> = {}): ScanSchedule {
  return {
    enabled: false,
    timeOfDay: "03:00",
    timezone: "UTC",
    nextRunAt: null,
    lastRunAt: null,
    lastJobId: null,
    lastNote: null,
    eligibleHosts: 2,
    serverKeyConfigured: true,
    ...overrides,
  };
}

export function makeFinding(overrides: Partial<CveFinding> = {}): CveFinding {
  return {
    cveId: "CVE-2024-0001",
    severity: "high",
    cvssScore: 7.5,
    packageIdentifier: null,
    remediationStatus: null,
    remediationRecordId: null,
    remediationNote: null,
    dependencies: [],
    dependedOnBy: [],
    blastRadius: "low",
    ...overrides,
  };
}
