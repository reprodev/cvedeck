/**
 * Follow a background scan job: start it, poll it, resume it after a reload
 * (Req 19.1, 19.2).
 *
 * A scan used to be one long request the dashboard held open for minutes. Now
 * the backend answers at once with a job, and this hook polls it every
 * {@link POLL_MS} for each host's progress, calling `onFinished` exactly once
 * when the job ends. The job runs server-side, so navigating away changes
 * nothing; and on mount the hook asks for any job still active, so a reload
 * picks up a scan started before it.
 */
import { useCallback, useEffect, useRef, useState } from "react";
import type { CveScannerApiClient } from "../api/client";
import { ApiError } from "../api/client";
import type { ScanJob, ScanTargetInput } from "../types";

/** How often a running job is polled. */
export const POLL_MS = 2000;

const ENDED = new Set(["finished", "interrupted"]);

/** "Scanning 2 of 5: web-01", or "Waiting for another scan to finish". */
export function progressLabel(job: ScanJob): string {
  if (job.status === "queued") return "Waiting for another scan to finish...";
  const total = job.targets.length;
  const running = job.targets.findIndex((target) => target.state === "running");
  if (running >= 0) {
    return `Scanning ${running + 1} of ${total}: ${job.targets[running].hostname}`;
  }
  const done = job.targets.filter((target) => target.state === "done").length;
  return `Scanning... ${done} of ${total} done`;
}

export interface ScanJobState {
  /** The job being followed, or null when none is active. */
  job: ScanJob | null;
  /** Queue a scan and start following it. Rejects if the backend refuses it. */
  start: (targets: ScanTargetInput[]) => Promise<void>;
}

export function useScanJob(
  api: Pick<CveScannerApiClient, "startScanJob" | "getScanJob" | "listActiveScanJobs">,
  onFinished: (job: ScanJob) => void,
  onLost: (message: string) => void,
): ScanJobState {
  const [job, setJob] = useState<ScanJob | null>(null);
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

  // A scan started before a reload is still running on the server.
  useEffect(() => {
    let cancelled = false;
    api
      .listActiveScanJobs()
      .then((active) => {
        if (!cancelled && active.length > 0) setJob((current) => current ?? active[0]);
      })
      .catch(() => {
        // Not knowing about an older scan is not worth an error: its results
        // reach the fleet view whether or not this page follows it.
      });
    return () => {
      cancelled = true;
    };
  }, [api]);

  const jobId = job?.id ?? null;
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

  return { job, start };
}
