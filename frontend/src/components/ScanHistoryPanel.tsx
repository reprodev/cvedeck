// A host's scan runs and what each one changed (Req 18.1, 18.2, 18.6, 18.9).
//
// Collapsed by default and loaded on first open: the history is for the
// question "did my patching work", which is asked after a re-scan, not on every
// visit to the page.

import { Fragment, useCallback, useState } from "react";
import type { FindingChangeRow, ScanRun } from "../types";
import { relativeTime, remediationStatusLabel, severityLabel, statusLabel, statusTone } from "../lib/labels";
import { Icon } from "./Icon";

export interface ScanHistoryPanelProps {
  /** Load at most `limit` runs, newest first. */
  onLoadRuns: (limit: number) => Promise<ScanRun[]>;
  onLoadChanges: (runId: string) => Promise<FindingChangeRow[]>;
}

/** Runs shown before asking for more. */
const PAGE_SIZE = 20;

/**
 * The most this panel will ask for, matching the route's own cap. Retention
 * (CVEDECK_SCAN_HISTORY_LIMIT) defaults to 50 per host but can be raised, so
 * "show more" has to stop somewhere rather than promise the whole history.
 */
const MAX_RUNS = 200;

/** A count, or a dash that says why there is none. Never a zero standing in for null. */
function Count({ value, reason }: { value: number | null; reason: string }) {
  if (value === null) {
    return (
      <span className="scan-history-na" title={reason}>
        {"—"}
      </span>
    );
  }
  return <>{value}</>;
}

function notAssessed(run: ScanRun, which: "new" | "resolved"): string {
  if (run.status !== "success") return "Not assessed: the scan did not complete.";
  if (run.baseline) return "Not assessed: this was the host's baseline scan.";
  if (which === "resolved") return "Not assessed: an advisory source did not answer.";
  return "Not assessed.";
}

function errorText(err: unknown): string {
  return err instanceof Error ? err.message : "The scan history could not be loaded.";
}

export function ScanHistoryPanel({ onLoadRuns, onLoadChanges }: ScanHistoryPanelProps) {
  const [runs, setRuns] = useState<ScanRun[] | null>(null);
  const [limit, setLimit] = useState(PAGE_SIZE);
  const [error, setError] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [changes, setChanges] = useState<Record<string, FindingChangeRow[]>>({});
  const [changesError, setChangesError] = useState<string | null>(null);

  const load = useCallback(
    async (next: number) => {
      setError(null);
      try {
        setRuns(await onLoadRuns(next));
        setLimit(next);
      } catch (err) {
        setError(errorText(err));
      }
    },
    [onLoadRuns],
  );

  // A full page back means the host may have more runs kept than are shown.
  const mayHaveMore = runs !== null && runs.length >= limit && limit < MAX_RUNS;

  const toggleRun = async (runId: string) => {
    if (expanded === runId) {
      setExpanded(null);
      return;
    }
    setExpanded(runId);
    setChangesError(null);
    if (!changes[runId]) {
      try {
        const rows = await onLoadChanges(runId);
        setChanges((current) => ({ ...current, [runId]: rows }));
      } catch (err) {
        setChangesError(errorText(err));
      }
    }
  };

  return (
    <details
      className="card scan-history"
      data-testid="scan-history"
      onToggle={(event) => {
        if ((event.currentTarget as HTMLDetailsElement).open && runs === null) {
          void load(PAGE_SIZE);
        }
      }}
    >
      <summary>
        <Icon name="clock" /> Scan history
      </summary>
      {error && <p role="alert">{error}</p>}
      {runs === null && !error && <p className="hint">Loading...</p>}
      {runs !== null && runs.length === 0 && (
        <p className="hint">No scans recorded yet. History starts with the next scan.</p>
      )}
      {runs !== null && runs.length > 0 && (
        <div className="table-container">
          <table>
            <thead>
              <tr>
                <th scope="col">Scanned</th>
                <th scope="col">Result</th>
                <th scope="col">Findings</th>
                <th scope="col">New</th>
                <th scope="col">Resolved</th>
                <th scope="col">
                  <span className="visually-hidden">Changes</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {runs.map((run) => {
                const hasChanges = (run.newCount ?? 0) + (run.resolvedCount ?? 0) > 0;
                const open = expanded === run.runId;
                const rows = changes[run.runId];
                return (
                  <Fragment key={run.runId}>
                    <tr>
                      <td title={new Date(run.scannedAt).toLocaleString()}>
                        {relativeTime(run.scannedAt)}
                      </td>
                      <td>
                        <span className={`badge badge-status-${statusTone(run.status)}`}>
                          {statusLabel(run.status)}
                        </span>
                        {run.baseline && <span className="badge badge-status-neutral">Baseline</span>}
                        {run.status === "success" && !run.sourcesOk && (
                          <span className="badge badge-partial">
                            <Icon name="alert" /> Partial
                          </span>
                        )}
                      </td>
                      <td>
                        <Count
                          value={run.status === "success" ? run.findingCount : null}
                          reason={notAssessed(run, "new")}
                        />
                      </td>
                      <td>
                        <Count value={run.newCount} reason={notAssessed(run, "new")} />
                      </td>
                      <td>
                        <Count value={run.resolvedCount} reason={notAssessed(run, "resolved")} />
                      </td>
                      <td>
                        {hasChanges && (
                          <button
                            type="button"
                            className="btn-secondary scan-history-toggle"
                            aria-expanded={open}
                            onClick={() => void toggleRun(run.runId)}
                          >
                            {open ? "Hide changes" : "Show changes"}
                          </button>
                        )}
                      </td>
                    </tr>
                    {open && (
                      <tr className="scan-history-changes">
                        <td colSpan={6}>
                          {changesError && <p role="alert">{changesError}</p>}
                          {!rows && !changesError && <p className="hint">Loading...</p>}
                          {rows && (
                            <ul>
                              {rows.map((row) => (
                                <li
                                  key={`${row.change}:${row.cveId}:${row.packageIdentifier}`}
                                  data-change={row.change}
                                >
                                  <span className="scan-change-kind">
                                    {row.change === "new" ? "New" : "Resolved"}
                                  </span>
                                  <code>{row.cveId}</code>
                                  {row.packageName && <span>{row.packageName}</span>}
                                  <span className={`badge badge-${row.severity}`}>
                                    {severityLabel(row.severity)}
                                  </span>
                                  <span>CVSS {row.cvssScore.toFixed(1)}</span>
                                  {row.change === "resolved" &&
                                    row.remediationStatus &&
                                    row.remediationStatus !== "remediated" && (
                                      <span className="hint">
                                        Cleared by this scan; its remediation record is still{" "}
                                        {remediationStatusLabel(row.remediationStatus)}.
                                      </span>
                                    )}
                                </li>
                              ))}
                            </ul>
                          )}
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
          {mayHaveMore && (
            <p className="scan-history-more">
              <button
                type="button"
                className="btn-secondary"
                onClick={() => void load(MAX_RUNS)}
              >
                Show more
              </button>
              <span className="hint">Showing the {runs.length} most recent runs.</span>
            </p>
          )}
        </div>
      )}
    </details>
  );
}
