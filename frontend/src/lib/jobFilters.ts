/**
 * Narrowing the scan history (Req 19.12, Property 22).
 *
 * The history keeps a hundred jobs, and the question asked of it is nearly
 * always narrower than "what ran": did last night's schedule fail anywhere,
 * when was web-01 last scanned, what did the CI token start. A job here can
 * carry several outcomes at once -- one host failed, another came back partial
 * -- so an outcome matches when ANY host had it. Ranking a job by its worst
 * host instead would hide a partial behind a failure in the same job, and
 * hiding the thing being looked for is the one thing a filter must not do.
 */
import type { ScanJob } from "../types";

export type JobOutcomeFilter = "all" | "active" | "clean" | "partial" | "failed" | "cancelled";

export const JOB_OUTCOME_FILTERS: { value: JobOutcomeFilter; label: string }[] = [
  { value: "all", label: "All outcomes" },
  { value: "failed", label: "Failed or interrupted" },
  { value: "partial", label: "Partial" },
  { value: "clean", label: "Clean" },
  { value: "cancelled", label: "Cancelled" },
  { value: "active", label: "Queued or running" },
];

export interface JobFilters {
  /** Matched, ignoring case, against each host's hostname and machine id. */
  host: string;
  outcome: JobOutcomeFilter;
  /** A `requestedBy` value exactly, or "" for anyone. */
  requestedBy: string;
}

export const NO_JOB_FILTERS: JobFilters = { host: "", outcome: "all", requestedBy: "" };

/** Whether a job had the outcome: any host having it is enough. */
export function jobHasOutcome(job: ScanJob, outcome: JobOutcomeFilter): boolean {
  const outcomes = job.targets.flatMap((target) => (target.outcome ? [target.outcome] : []));
  switch (outcome) {
    case "all":
      return true;
    case "active":
      return job.status === "queued" || job.status === "running";
    case "cancelled":
      return job.status === "cancelled";
    case "failed":
      return job.status === "interrupted" || outcomes.some((o) => o.status !== "success");
    case "partial":
      return outcomes.some((o) => o.status === "success" && !o.sourcesOk);
    case "clean":
      // Every host scanned, with every source answering. A finished job with
      // no hosts is not clean: nothing was checked.
      return (
        job.status === "finished" &&
        job.targets.length > 0 &&
        job.targets.every((t) => t.outcome?.status === "success" && t.outcome.sourcesOk)
      );
  }
}

export function filterJobs(jobs: ScanJob[], filters: JobFilters): ScanJob[] {
  const host = filters.host.trim().toLowerCase();
  return jobs.filter(
    (job) =>
      (!host ||
        job.targets.some(
          (t) => t.hostname.toLowerCase().includes(host) || t.machineId.toLowerCase().includes(host),
        )) &&
      (!filters.requestedBy || job.requestedBy === filters.requestedBy) &&
      jobHasOutcome(job, filters.outcome),
  );
}
