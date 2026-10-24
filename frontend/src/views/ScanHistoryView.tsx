/**
 * Scan history: every scan job the server keeps, newest first (Req 19.10).
 *
 * Since 0.11.0 a scan has been a job, and the server keeps the newest 100 with
 * each host's outcome -- but the dashboard only ever showed the one running, in
 * its progress line. A scan the schedule ran overnight, or one somebody
 * cancelled, left nothing to look back on. Each row here is one job; it opens
 * in place to show its hosts, each linking to that host.
 *
 * The list polls while a job is queued or running, so a scan finishing while
 * the page is open turns up without a refresh, and stops polling once nothing
 * is under way.
 */
import { Fragment, useCallback, useEffect, useMemo, useState } from "react";

import type { CveScannerApiClient } from "../api/client";
import { EmptyState } from "../components/EmptyState";
import { Icon } from "../components/Icon";
import { useToast } from "../components/Toast";
import {
  durationLabel,
  formatServerTime,
  relativeTime,
  requestedByLabel,
  statusLabel,
  statusTone,
} from "../lib/labels";
import { jobOutcomeLabel } from "../lib/useScanJob";
import type { ScanJob, ScanJobTarget } from "../types";

/** How often the list is re-read while a job is queued or running. */
export const HISTORY_POLL_MS = 5000;
/** Every job the server keeps (backend `MAX_JOBS`). */
export const HISTORY_LIMIT = 100;
const PAGE_SIZES = [15, 25, 50, 100];

const ACTIVE = new Set(["queued", "running"]);

function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export interface ScanHistoryViewProps {
  api: Pick<CveScannerApiClient, "listScanJobs" | "cancelScanJob">;
  /** Open a host's drill-down. */
  onSelectMachine: (machineId: string) => void;
  /** Open New Scan, from the empty state. */
  onNavigateScan: () => void;
  /** Changes when a scan this page followed ends, so the list re-reads at once. */
  refreshKey?: number;
}

/** A host's line in an open job: its outcome, or why it has none. */
function hostState(target: ScanJobTarget): { text: string; tone: string } {
  if (target.outcome) {
    return { text: statusLabel(target.outcome.status), tone: statusTone(target.outcome.status) };
  }
  switch (target.state) {
    case "running":
      return { text: "Scanning", tone: "neutral" };
    case "cancelled":
      return { text: "Cancelled -- not reached", tone: "neutral" };
    default:
      return { text: "Queued", tone: "neutral" };
  }
}

function findingsText(target: ScanJobTarget): string {
  const outcome = target.outcome;
  if (!outcome || outcome.status !== "success") return "–";
  const counts =
    outcome.baseline || outcome.newCount === null
      ? ""
      : ` (${outcome.newCount} new, ${outcome.resolvedCount ?? "not assessed"} resolved)`;
  return `${outcome.findingCount}${counts}`;
}

export function ScanHistoryView({
  api,
  onSelectMachine,
  onNavigateScan,
  refreshKey = 0,
}: ScanHistoryViewProps) {
  const toast = useToast();
  const [jobs, setJobs] = useState<ScanJob[] | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [cancelling, setCancelling] = useState<string | null>(null);
  const [page, setPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);

  const load = useCallback(async () => {
    try {
      setJobs(await api.listScanJobs(HISTORY_LIMIT));
    } catch (err: unknown) {
      toast.error(`Could not load scan history: ${errorMessage(err)}`);
      setJobs((current) => current ?? []);
    }
  }, [api, toast]);

  useEffect(() => {
    void load();
  }, [load, refreshKey]);

  const anyActive = (jobs ?? []).some((job) => ACTIVE.has(job.status));
  useEffect(() => {
    if (!anyActive) return;
    const timer = window.setInterval(() => void load(), HISTORY_POLL_MS);
    return () => window.clearInterval(timer);
  }, [anyActive, load]);

  const cancel = async (job: ScanJob) => {
    setCancelling(job.id);
    try {
      await api.cancelScanJob(job.id);
    } catch (err: unknown) {
      toast.error(errorMessage(err));
    } finally {
      setCancelling(null);
      void load();
    }
  };

  const total = jobs?.length ?? 0;
  const pages = Math.max(1, Math.ceil(total / pageSize));
  const safePage = Math.min(page, pages);
  const shown = useMemo(
    () => (jobs ?? []).slice((safePage - 1) * pageSize, safePage * pageSize),
    [jobs, safePage, pageSize],
  );

  return (
    <section className="scan-history" aria-labelledby="scan-history-title">
      <div className="scan-history-header">
        <h2 className="view-title" id="scan-history-title">
          Scan history
        </h2>
        <button type="button" className="pagination-btn" onClick={() => void load()}>
          <Icon name="refresh" /> Refresh
        </button>
      </div>

      {jobs === null ? (
        <p className="hint" role="status">
          Loading scan history...
        </p>
      ) : total === 0 ? (
        <EmptyState
          title="No scans yet."
          action={
            <button type="button" onClick={onNavigateScan}>
              <Icon name="zap" /> New scan
            </button>
          }
        >
          Every scan -- from this dashboard, the schedule or the API -- is listed here
          once it starts.
        </EmptyState>
      ) : (
        <>
          <div className="pagination-bar">
            <span>
              Showing {(safePage - 1) * pageSize + 1} to {Math.min(safePage * pageSize, total)} of{" "}
              {total} scans
            </span>
            <div className="pagination-nav">
              <button
                type="button"
                className="pagination-btn"
                disabled={safePage <= 1}
                onClick={() => setPage(safePage - 1)}
              >
                ◀ Prev
              </button>
              <span>
                Page {safePage} of {pages}
              </span>
              <button
                type="button"
                className="pagination-btn"
                disabled={safePage >= pages}
                onClick={() => setPage(safePage + 1)}
              >
                Next ▶
              </button>
              <select
                className="page-size-select"
                value={pageSize}
                onChange={(e) => {
                  setPageSize(Number(e.target.value));
                  setPage(1);
                }}
                aria-label="Scans per page"
              >
                {PAGE_SIZES.map((size) => (
                  <option key={size} value={size}>
                    {size} / page
                  </option>
                ))}
              </select>
            </div>
          </div>

          <div className="table-container">
            <table className="scan-history-table">
              <thead>
                <tr>
                  <th scope="col">Started</th>
                  <th scope="col" data-col="requested-by">
                    Requested by
                  </th>
                  <th scope="col">Hosts</th>
                  <th scope="col">Outcome</th>
                  <th scope="col" data-col="duration">
                    Duration
                  </th>
                  <th scope="col">
                    <span className="visually-hidden">Actions</span>
                  </th>
                </tr>
              </thead>
              <tbody>
                {shown.map((job) => {
                  const open = expanded === job.id;
                  const outcome = jobOutcomeLabel(job);
                  const when = job.startedAt ?? job.createdAt;
                  const detailsId = `scan-job-${job.id}`;
                  return (
                    <Fragment key={job.id}>
                      <tr>
                        <td data-label="Started">
                          <button
                            type="button"
                            className="drawer-toggle-btn"
                            aria-expanded={open}
                            aria-controls={detailsId}
                            onClick={() => setExpanded(open ? null : job.id)}
                          >
                            {open ? "▲" : "▼"} {formatServerTime(when)}
                          </button>
                          <span className="hint scan-history-age">{relativeTime(when)}</span>
                        </td>
                        <td data-label="Requested by" data-col="requested-by">
                          {requestedByLabel(job.requestedBy)}
                        </td>
                        <td data-label="Hosts">{job.targets.length}</td>
                        <td data-label="Outcome">
                          <span className={`badge badge-status-${outcome.tone}`}>{outcome.text}</span>
                        </td>
                        <td data-label="Duration" data-col="duration">
                          {durationLabel(job.startedAt, job.finishedAt)}
                        </td>
                        <td data-label="Actions">
                          {job.cancellable && (
                            <button
                              type="button"
                              className="pagination-btn"
                              disabled={cancelling === job.id || job.cancelRequested}
                              onClick={() => void cancel(job)}
                            >
                              {job.cancelRequested ? "Stopping..." : "Cancel"}
                            </button>
                          )}
                        </td>
                      </tr>
                      {open && (
                        <tr id={detailsId}>
                          <td colSpan={6}>
                            {job.errorDetail && <p className="scan-history-detail">{job.errorDetail}</p>}
                            <table className="scan-history-hosts">
                              <thead>
                                <tr>
                                  <th scope="col">Host</th>
                                  <th scope="col">Result</th>
                                  <th scope="col">Findings</th>
                                  <th scope="col">Detail</th>
                                </tr>
                              </thead>
                              <tbody>
                                {job.targets.map((target) => {
                                  const state = hostState(target);
                                  return (
                                    <tr key={`${job.id}-${target.machineId}`}>
                                      <td data-label="Host">
                                        <button
                                          type="button"
                                          className="hostname-link"
                                          onClick={() => onSelectMachine(target.machineId)}
                                        >
                                          {target.hostname}
                                        </button>
                                      </td>
                                      <td data-label="Result">
                                        <span className={`badge badge-status-${state.tone}`}>{state.text}</span>
                                        {target.outcome?.status === "success" && !target.outcome.sourcesOk && (
                                          <span className="hint"> partial</span>
                                        )}
                                      </td>
                                      <td data-label="Findings">{findingsText(target)}</td>
                                      <td data-label="Detail">{target.outcome?.message ?? ""}</td>
                                    </tr>
                                  );
                                })}
                              </tbody>
                            </table>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
          <p className="hint">CveDeck keeps the newest {HISTORY_LIMIT} scans.</p>
        </>
      )}
    </section>
  );
}
