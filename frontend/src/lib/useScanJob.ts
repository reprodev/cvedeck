/**
 * Follow a background scan job: start it, poll it, resume it after a reload
 * (Req 19.1, 19.2).
 *
 * A scan used to be one long request the dashboard held open for minutes. Now
 * the backend answers at once with a job, and this hook polls it every
 * {@link POLL_MS} for each host's progress, calling `onFinished` exactly once
 * when the job ends. The job runs server-side, so navigating away changes
 * nothing; and on mount the hook asks for any job still active, so a reload
 * picks up a scan started before it. A job can be cancelled (Req 19.7-19.9);
 * a running one stops after the host it is scanning.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import type { CveScannerApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { ScanJob, ScanTargetInput } from "../types";

/** How often a running job is polled. */
export const POLL_MS = 2000;
/** How often an idle page asks whether a scan it did not start is running. */
export const IDLE_POLL_MS = 30000;

const ENDED = new Set(["finished", "interrupted", "cancelled"]);

/** "Scanning 2 of 5: web-01", or "Waiting for another scan to finish". */
export function progressLabel(job: ScanJob): string {
  if (job.status === "queued") return "Waiting for another scan to finish...";
  const total = job.targets.length;
  const running = job.targets.findIndex((target) => target.state === "running");
  if (job.cancelRequested) {
    return running >= 0 ? `Stopping after ${job.targets[running].hostname}...` : "Stopping...";
  }
  if (running >= 0) {
    return `Scanning ${running + 1} of ${total}: ${job.targets[running].hostname}`;
  }
  const done = job.targets.filter((target) => target.state === "done").length;
  return `Scanning... ${done} of ${total} done`;
}

/**
 * A job's outcome in a few words, with the tone to show it in (Req 19.10).
 *
 * What Scan history shows per row. A running job reads as its progress line;
 * a finished one counts its hosts. Tones are the scan-status tones: a failed
 * host is a failure, a partial scan a caveat, and nothing here is red, which
 * is for exploitation alone.
 */
export function jobOutcomeLabel(job: ScanJob): {
  text: string;
  tone: "success" | "neutral" | "warn" | "failure";
} {
  const total = job.targets.length;
  const outcomes = job.targets.flatMap((target) => (target.outcome ? [target.outcome] : []));
  switch (job.status) {
    case "queued":
      return { text: "Waiting", tone: "neutral" };
    case "running":
      return { text: progressLabel(job), tone: "neutral" };
    case "interrupted":
      return { text: "Interrupted", tone: "warn" };
    case "cancelled": {
      const done = job.targets.filter((target) => target.state === "done").length;
      return { text: `Cancelled after ${done} of ${total}`, tone: "neutral" };
    }
    default: {
      if (total === 0) return { text: "No hosts", tone: "neutral" };
      const failed = outcomes.filter((o) => o.status !== "success").length;
      const partial = outcomes.filter((o) => o.status === "success" && !o.sourcesOk).length;
      const succeeded = outcomes.length - failed;
      const parts = [`${succeeded} succeeded`];
      if (partial > 0) parts.push(`${partial} partial`);
      if (failed > 0) parts.push(`${failed} failed`);
      return {
        text: parts.join(" · "),
        tone: failed > 0 ? "failure" : partial > 0 ? "warn" : "success",
      };
    }
  }
}

export interface ScanJobState {
  /** The job being followed, or null when none is active. */
  job: ScanJob | null;
  /** Queue a scan and start following it. Rejects if the backend refuses it. */
  start: (targets: ScanTargetInput[]) => Promise<void>;
  /** Cancel the job being followed. Rejects if the backend refuses (409). */
  cancel: () => Promise<void>;
  /** True while a cancel request is in flight. */
  cancelling: boolean;
}

export function useScanJob(
  api: Pick<
    CveScannerApiClient,
    "startScanJob" | "getScanJob" | "listActiveScanJobs" | "cancelScanJob"
  >,
  onFinished: (job: ScanJob) => void,
  onLost: (message: string) => void,
): ScanJobState {
  const [job, setJob] = useState<ScanJob | null>(null);
  const [cancelling, setCancelling] = useState(false);
  // The latest callbacks, so the polling effect need not restart when a
  // parent re-renders with new closures.
  const finished = useRef(onFinished);
  const lost = useRef(onLost);
  finished.current = onFinished;
  lost.current = onLost;

  const follow = useCallback((next: ScanJob) => {
    if (ENDED.has(next.status)) {
      setJob(null);
      finished.current(next);
    } else {
      setJob(next);
    }
  }, []);

  const start = useCallback(
    async (targets: ScanTargetInput[]) => {
      const id = await api.startScanJob(targets);
      follow(await api.getScanJob(id));
    },
    [api, follow],
  );

  const jobId = job?.id ?? null;

  const cancel = useCallback(async () => {
    if (jobId === null) return;
    setCancelling(true);
    try {
      follow(await api.cancelScanJob(jobId));
    } finally {
      setCancelling(false);
    }
  }, [api, follow, jobId]);

  // A scan this page did not start -- one running before a reload, or one the
  // schedule started (Req 20.6) -- is found by asking now and then while idle.
  useEffect(() => {
    if (jobId !== null) return;
    let cancelled = false;
    const look = () => {
      api
        .listActiveScanJobs()
        .then((active) => {
          if (!cancelled && active.length > 0) setJob((current) => current ?? active[0]);
        })
        .catch(() => {
          // Not knowing about another scan is not worth an error: its results
          // reach the fleet view whether or not this page follows it.
        });
    };
    look();
    const timer = window.setInterval(look, IDLE_POLL_MS);
    return () => {
      cancelled = true;
      window.clearInterval(timer);
    };
  }, [api, jobId]);
  useEffect(() => {
    if (jobId === null) return;
    let busy = false;
    const timer = window.setInterval(() => {
      if (busy) return;
      busy = true;
      api
        .getScanJob(jobId)
        .then(follow)
        .catch((err: unknown) => {
          if (err instanceof ApiError && err.status === 404) {
            window.clearInterval(timer);
            setJob(null);
            lost.current("The scan could no longer be found; check the fleet view for its results.");
          }
          // Anything else -- a dropped connection -- is retried on the next tick.
        })
        .finally(() => {
          busy = false;
        });
    }, POLL_MS);
    return () => window.clearInterval(timer);
  }, [api, follow, jobId]);

  return { job, start, cancel, cancelling };
}
