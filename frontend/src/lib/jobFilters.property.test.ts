// Property-based tests for the cvedeck feature.
//
// Property 22: Narrowing the scan history never hides a match
// For any list of scan jobs and any host, outcome and requester filter, the
// history SHALL show exactly the jobs that match every filter, in their
// original order, where a job matches an outcome when any one of its hosts had
// it; and with no filter set it SHALL show every job.
//
// **Validates: Requirements 19.12**

import { describe, expect, it } from "vitest";
import fc from "fast-check";

import { filterJobs, JOB_OUTCOME_FILTERS, NO_JOB_FILTERS } from "./jobFilters";
import type { JobFilters, JobOutcomeFilter } from "./jobFilters";
import { makeScanJob, makeScanOutcome } from "../test-utils/factories";
import type { ScanJob, ScanJobTarget, ScanOutcome } from "../types";

const STATUSES = ["queued", "running", "finished", "interrupted", "cancelled"];
const HOST_RESULTS = ["success", "connection_failure", "auth_failure", "host_key_mismatch"];
const HOSTS = ["web-01", "WEB-02", "db-01", "nas", "10.0.0.5"];
const REQUESTERS = ["schedule", "admin", "token:ci", "open"];

const outcomeArb: fc.Arbitrary<ScanOutcome> = fc.record({
  machineId: fc.constant("m"),
  status: fc.constantFrom(...HOST_RESULTS),
  findingCount: fc.nat(50),
  sourcesOk: fc.boolean(),
  unavailableSources: fc.constant([]),
  message: fc.constant(null),
  newCount: fc.constant(null),
  resolvedCount: fc.constant(null),
  baseline: fc.boolean(),
});

const targetArb: fc.Arbitrary<ScanJobTarget> = fc.record({
  machineId: fc.constantFrom(...HOSTS),
  hostname: fc.constantFrom(...HOSTS),
  state: fc.constantFrom("queued", "running", "done", "cancelled"),
  outcome: fc.option(outcomeArb, { nil: null }),
});

const jobArb: fc.Arbitrary<ScanJob> = fc.record({
  id: fc.uuid(),
  status: fc.constantFrom(...STATUSES),
  requestedBy: fc.constantFrom(...REQUESTERS),
  createdAt: fc.constant("2026-11-01T00:00:00"),
  startedAt: fc.constant(null),
  finishedAt: fc.constant(null),
  errorDetail: fc.constant(null),
  cancellable: fc.boolean(),
  cancelRequested: fc.boolean(),
  targets: fc.array(targetArb, { maxLength: 4 }),
});

const filtersArb: fc.Arbitrary<JobFilters> = fc.record({
  host: fc.oneof(fc.constant(""), fc.constantFrom("web", "Web", " db-01 ", "nas", "zz", "10.0")),
  outcome: fc.constantFrom(...JOB_OUTCOME_FILTERS.map((f) => f.value)),
  requestedBy: fc.constantFrom("", ...REQUESTERS),
});

// The specification restated host by host, independently of the code under
// test: which outcomes each host contributes, then which the job adds itself.
function outcomesOf(job: ScanJob): Set<JobOutcomeFilter> {
  const found = new Set<JobOutcomeFilter>(["all"]);
  for (const target of job.targets) {
    if (!target.outcome) continue;
    if (target.outcome.status !== "success") found.add("failed");
    else if (!target.outcome.sourcesOk) found.add("partial");
  }
  if (job.status === "interrupted") found.add("failed");
  if (job.status === "cancelled") found.add("cancelled");
  if (job.status === "queued" || job.status === "running") found.add("active");
  const allClean =
    job.targets.length > 0 &&
    job.targets.every((t) => t.outcome !== null && t.outcome.status === "success" && t.outcome.sourcesOk);
  if (job.status === "finished" && allClean) found.add("clean");
  return found;
}

function matches(job: ScanJob, filters: JobFilters): boolean {
  const needle = filters.host.trim().toLowerCase();
  const hostOk =
    needle === "" ||
    job.targets.some((t) => [t.hostname, t.machineId].some((name) => name.toLowerCase().includes(needle)));
  const requesterOk = filters.requestedBy === "" || filters.requestedBy === job.requestedBy;
  return hostOk && requesterOk && outcomesOf(job).has(filters.outcome);
}

describe("filterJobs (Property 22: Narrowing the scan history never hides a match)", () => {
  it("keeps exactly the jobs matching every filter, in order", () => {
    fc.assert(
      fc.property(fc.array(jobArb, { maxLength: 30 }), filtersArb, (jobs, filters) => {
        expect(filterJobs(jobs, filters)).toEqual(jobs.filter((job) => matches(job, filters)));
      }),
      { numRuns: 100 },
    );
  });

  it("is the intersection of each filter applied alone", () => {
    fc.assert(
      fc.property(fc.array(jobArb, { maxLength: 30 }), filtersArb, (jobs, filters) => {
        const alone = [
          filterJobs(jobs, { ...NO_JOB_FILTERS, host: filters.host }),
          filterJobs(jobs, { ...NO_JOB_FILTERS, outcome: filters.outcome }),
          filterJobs(jobs, { ...NO_JOB_FILTERS, requestedBy: filters.requestedBy }),
        ];
        expect(filterJobs(jobs, filters)).toEqual(jobs.filter((job) => alone.every((kept) => kept.includes(job))));
      }),
      { numRuns: 100 },
    );
  });

  it("hides nothing when no filter is set", () => {
    fc.assert(
      fc.property(fc.array(jobArb, { maxLength: 30 }), (jobs) => {
        expect(filterJobs(jobs, NO_JOB_FILTERS)).toEqual(jobs);
      }),
      { numRuns: 100 },
    );
  });

  it("lists a job with one failed and one partial host under both", () => {
    const job = makeScanJob({
      targets: [
        { machineId: "a", hostname: "a", state: "done", outcome: makeScanOutcome({ status: "auth_failure" }) },
        { machineId: "b", hostname: "b", state: "done", outcome: makeScanOutcome({ sourcesOk: false }) },
      ],
    });
    for (const outcome of ["failed", "partial"] as const) {
      expect(filterJobs([job], { ...NO_JOB_FILTERS, outcome })).toEqual([job]);
    }
    expect(filterJobs([job], { ...NO_JOB_FILTERS, outcome: "clean" })).toEqual([]);
  });
});
