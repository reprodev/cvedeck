// MachineListView renders the list of scanned machines with severity-grouped
// CVE counts, interactive fleet KPI summary cards, and single pane of glass
// fleet health posture insights.
//
// Requirements:
//   3.1 - display a list of scanned machines
//   3.2 - display each machine's CVE count grouped by severity
//   3.3 - a severity filter narrows the displayed severity counts

import { useCallback, useMemo, useState } from "react";
import { exportFleetCsv } from "../lib/csvExport";
import type { FeedHealth, MachineSummary, Platform, Severity } from "../types";
import { SEVERITIES } from "../types";
import {
  isStale,
  relativeTime,
  severityLabel,
  statusLabel,
  statusTone,
  isHostKeyStatus,
} from "../lib/labels";
import { enrichmentWarning, feedLabel, formatFeedAge } from "../lib/intel";
import { scanDelta } from "../lib/scanDelta";
import { sortIndicator, useSort } from "../lib/useSort";
import { EmptyState } from "../components/EmptyState";
import { SkeletonRows } from "../components/Skeleton";
import { Icon } from "../components/Icon";
import { isScannable, WINDOWS_SCAN_UNSUPPORTED } from "../lib/platform";

export interface MachineListViewProps {
  /** Machines to display. */
  machines: MachineSummary[];
  /**
   * Called when a machine row is selected, to open its drill-down view
   * (Requirement 3.4). Wiring lives in the app shell.
   */
  onSelectMachine?: (machineId: string) => void;
  /** Quick scan a specific machine (pre-fills the scan form). */
  onQuickScan?: (host: { hostname: string; platform: Platform }) => void;
  /** Navigate to the dedicated New Scan page. */
  onNavigateScan?: () => void;
  /**
   * Re-scan machines in one batch using the server-managed SSH key, without
   * per-host credentials. Absent when the deployment has no default key
   * configured, in which case the bulk controls are hidden rather than
   * offered and then failing.
   */
  onRescan?: (machines: MachineSummary[]) => void;
  /** Whether a scan is currently running, to disable the controls. */
  scanning?: boolean;
  /**
   * Whether the first fleet fetch is still in flight.
   *
   * Distinct from an empty fleet: without it, "still loading" and "you have
   * no machines" render identically, and the reassuring reading is the wrong
   * one -- the same failure mode the feed-health captions exist to prevent.
   */
  loading?: boolean;
  /**
   * Cache health of the threat-intel feeds, used to caption the exploited
   * count. Without it a zero in the "Actively Exploited" card is ambiguous
   * between "nothing is being exploited" and "we never downloaded the
   * catalogue", and the reassuring reading is the wrong one.
   */
  feeds?: FeedHealth[];
  /** Pull the KEV and EPSS feeds. Absent when the caller cannot refresh. */
  onRefreshFeeds?: () => void;
  /** Whether a feed refresh is in flight, to disable the control. */
  refreshingFeeds?: boolean;
}

/** Columns the fleet table can be ordered by. */
type FleetSortKey =
  | "hostname"
  | "platform"
  | "status"
  | "lastScanned"
  | "exploited"
  | "risk"
  | Severity;

export function MachineListView({
  machines,
  onSelectMachine,
  onQuickScan,
  onNavigateScan,
  onRescan,
  scanning = false,
  loading = false,
  feeds = [],
  onRefreshFeeds,
  refreshingFeeds = false,
}: MachineListViewProps) {
  const [severityFilter, setSeverityFilter] = useState<Severity | null>(null);
  const [platformFilter, setPlatformFilter] = useState<"all" | "linux" | "windows">("all");
  const [quickFilter, setQuickFilter] = useState<
    "all" | "exploited" | "critical" | "high" | "attention" | "new"
  >("all");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedIds, setSelectedIds] = useState<ReadonlySet<string>>(new Set());

  const linuxCount = useMemo(() => machines.filter((m) => m.platform === "linux").length, [machines]);
  const windowsCount = useMemo(() => machines.filter((m) => m.platform === "windows").length, [machines]);

  // Aggregate fleet metrics
  const fleetTotals = useMemo(() => {
    const totals = {
      critical: 0,
      unscored: 0,
      high: 0,
      medium: 0,
      low: 0,
      totalFindings: 0,
    };
    for (const m of machines) {
      totals.critical += m.cveCounts.critical;
      totals.unscored += m.cveCounts.unscored;
      totals.high += m.cveCounts.high;
      totals.medium += m.cveCounts.medium;
      totals.low += m.cveCounts.low;
    }
    totals.totalFindings =
      totals.critical +
      totals.unscored +
      totals.high +
      totals.medium +
      totals.low;
    return totals;
  }, [machines]);

  // Which severity columns to show given the current filter.
  const visibleSeverities = useMemo<readonly Severity[]>(
    () => (severityFilter ? [severityFilter] : SEVERITIES),
    [severityFilter],
  );

  // Filter machines by search query and platform
  // Sorted after filtering so the visible rows are what get ordered.
  const sortAccessors: Record<
    FleetSortKey,
    (m: MachineSummary) => string | number | null
  > = useMemo(
    () => ({
      hostname: (m: MachineSummary) => m.hostname,
      platform: (m: MachineSummary) => m.platform,
      status: (m: MachineSummary) => m.lastScanStatus,
      // Sorted on the parsed timestamp, not the rendered "3d ago" string, which
      // would order lexicographically and put "9d" before "10d".
      lastScanned: (m: MachineSummary) =>
        m.lastScannedAt ? Date.parse(m.lastScannedAt) : null,
      exploited: (m: MachineSummary) => m.kevCount,
      // Default order. Observed exploitation first, then critical, then high --
      // the same ranking the findings table uses, applied to hosts. Alphabetical
      // by hostname is a filing order, not a triage order: it buried an actively
      // exploited host eleventh out of twelve.
      // Unscored sits between critical and high here too, so a host whose
      // findings nobody has measured does not sort as though it had none
      // (Req 10.11).
      risk: (m: MachineSummary) =>
        m.kevCount * 1_000_000 +
        m.cveCounts.critical * 1_000 +
        m.cveCounts.unscored * 100 +
        m.cveCounts.high,
      critical: (m: MachineSummary) => m.cveCounts.critical,
      unscored: (m: MachineSummary) => m.cveCounts.unscored,
      high: (m: MachineSummary) => m.cveCounts.high,
      medium: (m: MachineSummary) => m.cveCounts.medium,
      low: (m: MachineSummary) => m.cveCounts.low,
    }),
    [],
  );

  const exploitedHostCount = useMemo(
    () => machines.filter((m) => m.kevCount > 0).length,
    [machines],
  );
  const exploitedFindingCount = useMemo(
    () => machines.reduce((total, m) => total + m.kevCount, 0),
    [machines],
  );
  const intelWarning = useMemo(() => enrichmentWarning(feeds), [feeds]);
  const intelUsable = useMemo(() => feeds.some((feed) => feed.usable), [feeds]);

  // A host needs attention when its findings cannot be trusted as current:
  // never scanned, last scan failed, or the data is over a week old. Grouped
  // because the question a user actually asks is "whose data is stale", not
  // "how many are specifically auth failures".
  const attention = useMemo(() => {
    const never = machines.filter((m) => m.lastScanStatus === "never_scanned");
    // Its own group: a refused host key is not a flaky connection to retry,
    // and folding it into "failed" would hide the one that needs a person.
    const hostKey = machines.filter((m) => isHostKeyStatus(m.lastScanStatus));
    const failed = machines.filter(
      (m) =>
        m.lastScanStatus === "connection_failure" ||
        m.lastScanStatus === "auth_failure" ||
        // The host answered and authenticated, but nothing could be read from
        // it. A failure, not a quiet zero-finding success (Req 1.7).
        m.lastScanStatus === "inventory_unavailable",
    );
    const stale = machines.filter(
      (m) => m.lastScanStatus === "success" && isStale(m.lastScannedAt),
    );
    return {
      never,
      failed,
      stale,
      hostKey,
      all: [...never, ...failed, ...stale, ...hostKey],
    };
  }, [machines]);

  const attentionCount = attention.all.length;

  // Set rather than repeated array scans: the filter runs on every keystroke in
  // the search box, once per machine.
  const attentionIds = useMemo(
    () => new Set(attention.all.map((m) => m.machineId)),
    [attention],
  );

  /** "1 host" / "4 hosts" -- the unit is the point of this row. */
  const hostUnit = (n: number) => `${n} host${n === 1 ? "" : "s"}`;

  const attentionSummary = useMemo(() => {
    const parts: string[] = [];
    if (attention.hostKey.length) {
      parts.push(`${hostUnit(attention.hostKey.length)} refused on host key`);
    }
    if (attention.failed.length) parts.push(`${attention.failed.length} failed`);
    if (attention.stale.length) parts.push(`${attention.stale.length} stale`);
    if (attention.never.length) parts.push(`${attention.never.length} never scanned`);
    return parts.length ? parts.join(" · ") : "all hosts scanned recently";
  }, [attention]);

  // Hosts whose latest successful scan found something that the scan before it
  // did not. A null count is "not assessed" -- a baseline, or no successful
  // scan -- and must not be read as zero (Req 18.6).
  const newHostCount = useMemo(
    () => machines.filter((m) => (m.lastScanNew ?? 0) > 0).length,
    [machines],
  );
  const newFindingCount = useMemo(
    () => machines.reduce((total, m) => total + (m.lastScanNew ?? 0), 0),
    [machines],
  );

  const criticalHostCount = useMemo(() => machines.filter((m) => m.cveCounts.critical > 0).length, [machines]);
  const highHostCount = useMemo(() => machines.filter((m) => m.cveCounts.high > 0).length, [machines]);

  const filteredMachines = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    return machines.filter((m) => {
      if (platformFilter !== "all" && m.platform !== platformFilter) {
        return false;
      }
      if (quickFilter === "exploited" && m.kevCount === 0) {
        return false;
      }
      if (quickFilter === "critical" && m.cveCounts.critical === 0) {
        return false;
      }
      if (quickFilter === "high" && m.cveCounts.high === 0) {
        return false;
      }
      if (quickFilter === "new" && (m.lastScanNew ?? 0) === 0) {
        return false;
      }
      if (quickFilter === "attention" && !attentionIds.has(m.machineId)) {
        return false;
      }
      if (!q) return true;
      return (
        m.hostname.toLowerCase().includes(q) ||
        m.platform.toLowerCase().includes(q) ||
        m.lastScanStatus.toLowerCase().includes(q)
      );
    });
  }, [machines, searchQuery, platformFilter, quickFilter, attentionIds]);

  // Explicitly parameterised: passing an initial key lets inference narrow K to
  // that single literal, which then rejects every other column header.
  const { headerProps, sort, sorted: sortedMachines } = useSort<
    FleetSortKey,
    MachineSummary
  >(
    filteredMachines,
    sortAccessors,
    // useSort defaults to descending, which is what risk order wants.
    "risk",
  );

  // Selection is intersected with what is visible: selecting rows, then
  // filtering them away, must not silently re-scan hosts the user can no
  // longer see.
  const selectedVisible = useMemo(
    () => sortedMachines.filter((m) => selectedIds.has(m.machineId)),
    [sortedMachines, selectedIds],
  );

  // Re-scans only ever send hosts that can be scanned (Req 10.8). Windows hosts
  // stay selectable -- they are real fleet members -- but are left out of the
  // batch and counted, so the button never claims to scan more than it will.
  // The backend refuses a batch containing any Windows target, so sending them
  // would fail the whole re-scan rather than just those hosts.
  const rescanSelected = useMemo(
    () => selectedVisible.filter((m) => isScannable(m.platform)),
    [selectedVisible],
  );
  const rescanShown = useMemo(
    () => sortedMachines.filter((m) => isScannable(m.platform)),
    [sortedMachines],
  );
  const unscannableInView = sortedMachines.length - rescanShown.length;
  const allVisibleSelected =
    sortedMachines.length > 0 && selectedVisible.length === sortedMachines.length;

  const toggleRow = useCallback((machineId: string) => {
    setSelectedIds((current) => {
      const next = new Set(current);
      if (next.has(machineId)) next.delete(machineId);
      else next.add(machineId);
      return next;
    });
  }, []);

  const toggleAllVisible = useCallback(() => {
    setSelectedIds((current) => {
      const visibleIds = sortedMachines.map((m) => m.machineId);
      const everySelected = visibleIds.every((id) => current.has(id));
      const next = new Set(current);
      for (const id of visibleIds) {
        if (everySelected) next.delete(id);
        else next.add(id);
      }
      return next;
    });
  }, [sortedMachines]);

  return (
    <section aria-label="Scanned machines">
      <div className="view-header" style={{ marginBottom: "1.25rem", paddingBottom: "0.75rem" }}>
        <div>
          <h2 style={{ margin: 0 }}>Fleet Overview</h2>
          <span className="view-subtitle">Active monitored infrastructure and vulnerability posture</span>
        </div>
        {onNavigateScan && (
          <button
            type="button"
            onClick={onNavigateScan}
            style={{
              display: "inline-flex",
              alignItems: "center",
              gap: "0.4rem",
              padding: "0.45rem 0.95rem",
              fontSize: "0.85rem",
            }}
          >
            <span>
              <Icon name="wrench" />
            </span>
            <span>+ New Scan</span>
          </button>
        )}
      </div>

      {intelWarning && (
        <div
          className="banner banner-warning"
          role="status"
          style={{
            marginBottom: "1rem",
            padding: "0.7rem 0.9rem",
            border: "1px solid var(--medium)",
            borderRadius: "6px",
            display: "flex",
            alignItems: "center",
            gap: "0.75rem",
            flexWrap: "wrap",
            fontSize: "0.85rem",
          }}
        >
          <span aria-hidden="true">
            <Icon name="alert" />
          </span>
          <span style={{ flex: "1 1 20rem" }}>{intelWarning}</span>
          <span style={{ opacity: 0.75, fontSize: "0.78rem" }}>
            {feeds
              .map((feed) => `${feedLabel(feed.feedName)}: ${formatFeedAge(feed.lastRefreshedAt)}`)
              .join(" · ")}
          </span>
          {onRefreshFeeds && (
            <button
              type="button"
              onClick={onRefreshFeeds}
              disabled={refreshingFeeds}
              style={{ padding: "0.35rem 0.8rem", fontSize: "0.8rem" }}
            >
              {refreshingFeeds ? "Refreshing…" : "Refresh intel"}
            </button>
          )}
        </div>
      )}

      {/*
        One triage row, one unit. Every card here counts HOSTS, and the strip
        below counts FINDINGS -- deliberately given a different visual treatment,
        because the previous layout stacked two five-card rows of identical
        weight where one counted hosts and the other findings, with nothing on
        screen to say so.

        Ordered by what should be acted on first: observed exploitation beats a
        high score, and a host nobody can scan beats a host with a known finding,
        because an unscannable host has an unknown number of them.
      */}
      {machines.length > 0 && (
        <div className="triage-row">
          {/*
            The only card that gets red, and only when the intel that would
            justify it actually loaded.

            This sat on data-tone="critical" -- the same amber as the Critical
            findings card beside it -- so the one distinction the whole ranking
            is built on was not encoded in the palette at all. Red is reserved
            for exploitation precisely so a CVSS 9.8 nobody has touched cannot
            compete with a 6.5 being used today; spending it here is what that
            reservation was for.

            When the KEV feed has never loaded the count is zero for lack of an
            answer, not lack of exploitation, so the card drops to a neutral
            tone. Painting an unbacked zero red would be alarming about nothing;
            the real problem is that we do not know, which the unit line says.
          */}
          <button
            type="button"
            className={`triage-card ${quickFilter === "exploited" ? "active" : ""}`}
            data-tone={intelUsable ? "exploit" : undefined}
            aria-pressed={quickFilter === "exploited"}
            onClick={() => setQuickFilter(quickFilter === "exploited" ? "all" : "exploited")}
          >
            <span className="triage-card-label">
              <Icon name="target" /> Actively exploited
            </span>
            {/*
              Without usable intel the count is not an answer either way.
              Findings can still carry kev_listed from an earlier refresh (or
              from the demo seed), and "6" above "no exploit data loaded"
              contradicts itself -- so the value goes to a dash, like the
              Exploited column below.
            */}
            <span className="triage-card-value">
              {intelUsable ? exploitedHostCount : "—"}
            </span>
            <span className="triage-card-unit">
              {intelUsable
                ? `${hostUnit(exploitedHostCount)} · ${exploitedFindingCount} on CISA KEV`
                : "no exploit data loaded"}
            </span>
          </button>

          <button
            type="button"
            className={`triage-card ${quickFilter === "critical" ? "active" : ""}`}
            data-tone="critical"
            aria-pressed={quickFilter === "critical"}
            onClick={() => setQuickFilter(quickFilter === "critical" ? "all" : "critical")}
          >
            <span className="triage-card-label">
              <Icon name="siren" /> Critical findings
            </span>
            <span className="triage-card-value">{criticalHostCount}</span>
            <span className="triage-card-unit">
              {hostUnit(criticalHostCount)} · {fleetTotals.critical} findings
            </span>
          </button>

          <button
            type="button"
            className={`triage-card ${quickFilter === "high" ? "active" : ""}`}
            data-tone="high"
            aria-pressed={quickFilter === "high"}
            onClick={() => setQuickFilter(quickFilter === "high" ? "all" : "high")}
          >
            <span className="triage-card-label">
              <Icon name="alert" /> High findings
            </span>
            <span className="triage-card-value">{highHostCount}</span>
            <span className="triage-card-unit">
              {hostUnit(highHostCount)} · {fleetTotals.high} findings
            </span>
          </button>

          {/*
            Three weak cards (stale / never-scanned / failed) folded into one.
            They were separately actionable in theory and separately ignorable in
            practice; together they answer a question worth asking daily, which is
            "whose data can I not trust right now".
          */}
          <button
            type="button"
            className={`triage-card ${quickFilter === "attention" ? "active" : ""}`}
            data-tone="warn"
            aria-pressed={quickFilter === "attention"}
            onClick={() => setQuickFilter(quickFilter === "attention" ? "all" : "attention")}
          >
            <span className="triage-card-label">
              <Icon name="wrench" /> Needs attention
            </span>
            <span className="triage-card-value">{attentionCount}</span>
            <span className="triage-card-unit">{attentionSummary}</span>
          </button>
        </div>
      )}

      {/*
        Findings, not hosts -- hence the strip rather than more cards. Doubles as
        the severity filter, replacing a separate dropdown that did the same job
        further down the page.
      */}
      {machines.length > 0 && (
        <div className="findings-strip">
          <span className="findings-strip-total">
            <strong>{fleetTotals.totalFindings}</strong> findings across{" "}
            <strong>{machines.length}</strong> hosts
          </span>
          <div className="findings-strip-chips">
            <button
              type="button"
              className={`sev-chip ${severityFilter === null ? "active" : ""}`}
              aria-pressed={severityFilter === null}
              onClick={() => setSeverityFilter(null)}
            >
              All
            </button>
            {SEVERITIES.map((sev) => (
              <button
                key={sev}
                type="button"
                className={`sev-chip ${severityFilter === sev ? "active" : ""}`}
                data-severity={sev}
                aria-pressed={severityFilter === sev}
                onClick={() => setSeverityFilter(severityFilter === sev ? null : sev)}
              >
                {severityLabel(sev)} {fleetTotals[sev]}
              </button>
            ))}
          </div>
        </div>
      )}

      {/* Toolbar with Search and Dropdown Filter */}
      <div className="toolbar">
        <div className="search-box">
          <span className="search-icon">
            <Icon name="search" />
          </span>
          <input
            type="text"
            className="search-input"
            placeholder="Search host or platform..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>

        <div style={{ display: "flex", gap: "0.35rem", alignItems: "center" }}>
          <button
            type="button"
            className={`pagination-btn ${platformFilter === "all" ? "active" : ""}`}
            style={{
              padding: "0.42rem 0.7rem",
              fontSize: "0.82rem",
              background: platformFilter === "all" ? "var(--accent)" : "var(--surface)",
              color: platformFilter === "all" ? "var(--accent-text)" : "var(--text)",
              fontWeight: platformFilter === "all" ? 600 : 400,
            }}
            onClick={() => setPlatformFilter("all")}
          >
            All ({machines.length})
          </button>
          <button
            type="button"
            className={`pagination-btn ${platformFilter === "linux" ? "active" : ""}`}
            style={{
              padding: "0.42rem 0.7rem",
              fontSize: "0.82rem",
              background: platformFilter === "linux" ? "var(--accent)" : "var(--surface)",
              color: platformFilter === "linux" ? "var(--accent-text)" : "var(--text)",
              fontWeight: platformFilter === "linux" ? 600 : 400,
            }}
            onClick={() => setPlatformFilter(platformFilter === "linux" ? "all" : "linux")}
          >
            <Icon name="linux" /> Linux ({linuxCount})
          </button>
          <button
            type="button"
            className={`pagination-btn ${platformFilter === "windows" ? "active" : ""}`}
            style={{
              padding: "0.42rem 0.7rem",
              fontSize: "0.82rem",
              background: platformFilter === "windows" ? "var(--accent)" : "var(--surface)",
              color: platformFilter === "windows" ? "var(--accent-text)" : "var(--text)",
              fontWeight: platformFilter === "windows" ? 600 : 400,
            }}
            onClick={() => setPlatformFilter(platformFilter === "windows" ? "all" : "windows")}
          >
            <Icon name="windows" /> Windows ({windowsCount})
          </button>
        </div>

        {/*
          Beside the platform filters rather than as a fifth triage card: both
          of these filter which hosts the table lists, and that card row was
          deliberately cut from five cards to four -- see .triage-row in
          index.css for what the fifth one did to the layout.

          Hidden when nothing is new, like the host page's New chip. A fleet
          where the last round of scanning turned up nothing does not need a
          control saying so.
        */}
        {newHostCount > 0 && (
          <button
            type="button"
            className={`pagination-btn ${quickFilter === "new" ? "active" : ""}`}
            style={{
              padding: "0.42rem 0.7rem",
              fontSize: "0.82rem",
              background: quickFilter === "new" ? "var(--accent)" : "var(--surface)",
              color: quickFilter === "new" ? "var(--accent-text)" : "var(--text)",
              fontWeight: quickFilter === "new" ? 600 : 400,
            }}
            aria-pressed={quickFilter === "new"}
            title={`${newFindingCount} findings these hosts' latest scans found that the scan before did not`}
            onClick={() => setQuickFilter(quickFilter === "new" ? "all" : "new")}
          >
            <Icon name="plus" /> New findings ({newHostCount})
          </button>
        )}

        {/* The severity dropdown that stood here is now the chip row in the
            findings strip above -- same filter, one control. */}

        {machines.length > 0 && (
          <button
            type="button"
            className="pagination-btn"
            onClick={() => exportFleetCsv(filteredMachines, { intelUsable })}
            style={{
              padding: "0.55rem 0.9rem",
              fontSize: "0.85rem",
              fontWeight: 600,
              background: "var(--surface)",
              color: "var(--text)",
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
            }}
            title="Download RFC 4180 CSV export of fleet posture"
          >
            <span>
              <Icon name="file-down" /> Export Fleet CSV
            </span>
          </button>
        )}
      </div>

      {/* Both empty states are gated on !loading. Gating only the first one
          moves the problem rather than fixing it: with zero machines in flight,
          the filter branch matches instead and claims no machines match filters
          the user has not set. */}
      {machines.length === 0 && !loading ? (
        <EmptyState title="No machines yet.">
          Run a network discovery sweep to find hosts, or scan one directly with
          the form above.
        </EmptyState>
      ) : filteredMachines.length === 0 && !loading ? (
        <EmptyState
          title="No machines match the current filters."
          filters={[
            { label: "search", value: searchQuery.trim() },
            {
              label: "platform",
              value: platformFilter === "all" ? "" : platformFilter,
            },
          ]}
          onClearFilters={() => {
            setSearchQuery("");
            setPlatformFilter("all");
          }}
        />
      ) : (
        <div className="table-container">
          {onRescan && (
            <div className="bulk-action-bar">
              <span>
                {selectedVisible.length > 0
                  ? `${selectedVisible.length} selected`
                  : "Select hosts to re-scan"}
              </span>
              <button
                type="button"
                className="pagination-btn"
                disabled={scanning || rescanSelected.length === 0}
                onClick={() => onRescan(rescanSelected)}
              >
                {scanning ? "Scanning..." : `Re-scan selected (${rescanSelected.length})`}
              </button>
              <button
                type="button"
                className="pagination-btn"
                disabled={scanning || rescanShown.length === 0}
                onClick={() => onRescan(rescanShown)}
                title="Re-scan every Linux host matching the current filters"
              >
                {`Re-scan all shown (${rescanShown.length})`}
              </button>
              {unscannableInView > 0 && (
                <span className="hint" title={WINDOWS_SCAN_UNSUPPORTED} data-testid="rescan-skipped">
                  {unscannableInView} Windows {unscannableInView === 1 ? "host" : "hosts"} not
                  included: Windows scanning is not supported yet
                </span>
              )}
            </div>
          )}

          <table>
            <thead>
              <tr>
                {onRescan && (
                  <th scope="col" className="select-col">
                    <input
                      type="checkbox"
                      checked={allVisibleSelected}
                      // Some-but-not-all selected reads as indeterminate, so the
                      // control does not claim a state it is not in.
                      ref={(el) => {
                        if (el) {
                          el.indeterminate =
                            selectedVisible.length > 0 && !allVisibleSelected;
                        }
                      }}
                      onChange={toggleAllVisible}
                      aria-label="Select all shown machines"
                    />
                  </th>
                )}
                <th scope="col" {...headerProps("hostname")}>
                  Hostname{sortIndicator(sort, "hostname")}
                </th>
                <th scope="col" data-col="platform" {...headerProps("platform")}>
                  Platform{sortIndicator(sort, "platform")}
                </th>
                <th scope="col" {...headerProps("status")}>
                  Last scan status{sortIndicator(sort, "status")}
                </th>
                <th scope="col" {...headerProps("lastScanned")}>
                  Last scanned{sortIndicator(sort, "lastScanned")}
                </th>
                <th scope="col" {...headerProps("exploited")}>
                  Exploited{sortIndicator(sort, "exploited")}
                </th>
                {visibleSeverities.map((severity) => (
                  <th key={severity} scope="col" data-col={severity} {...headerProps(severity)}>
                    {severityLabel(severity)}
                    {sortIndicator(sort, severity)}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {loading && sortedMachines.length === 0 && (
                <SkeletonRows rows={6} columns={onRescan ? 10 : 9} />
              )}
              {sortedMachines.map((machine) => (
                <tr key={machine.machineId}>
                  {onRescan && (
                    <td className="select-col">
                      <input
                        type="checkbox"
                        checked={selectedIds.has(machine.machineId)}
                        onChange={() => toggleRow(machine.machineId)}
                        aria-label={`Select ${machine.hostname}`}
                      />
                    </td>
                  )}
                  <td className="host-col">
                    <div style={{ display: "flex", alignItems: "center", gap: "0.5rem" }}>
                      <button
                        type="button"
                        className="hostname-link"
                        onClick={() => onSelectMachine?.(machine.machineId)}
                      >
                        {machine.hostname}
                      </button>
                      {onQuickScan && (
                        <button
                          type="button"
                          className="pagination-btn"
                          disabled={!isScannable(machine.platform)}
                          onClick={() =>
                            onQuickScan({
                              hostname: machine.hostname,
                              platform: machine.platform,
                            })
                          }
                          style={{
                            fontSize: "0.72rem",
                            padding: "0.15rem 0.45rem",
                            background: "var(--accent-subtle)",
                            borderColor: "var(--accent)",
                            color: "var(--accent)",
                            fontWeight: 600,
                          }}
                          title={
                            isScannable(machine.platform)
                              ? `Quick scan ${machine.hostname}`
                              : WINDOWS_SCAN_UNSUPPORTED
                          }
                        >
                          <Icon name="zap" /> Scan
                        </button>
                      )}
                    </div>
                  </td>
                  <td data-label="Platform" data-col="platform">
                    <span className="badge badge-platform">
                      {machine.platform === "linux" ? <><Icon name="linux" /> linux</> : <><Icon name="windows" /> windows</>}
                    </span>
                  </td>
                  <td data-label="Last scan">
                    <span
                      className={`badge badge-status-${statusTone(
                        machine.lastScanStatus,
                      )}`}
                    >
                      {statusLabel(machine.lastScanStatus)}
                    </span>
                    {(() => {
                      // What the last successful scan changed, with its units
                      // (Req 18.6). Nothing for a baseline or an unchanged host.
                      const delta = scanDelta(machine);
                      return delta?.short ? (
                        <span
                          className="scan-delta"
                          title={delta.long}
                          aria-label={delta.long}
                        >
                          {delta.short}
                        </span>
                      ) : null;
                    })()}
                    {machine.lastScanStatus === "success" &&
                      !machine.lastScanSourcesOk && (
                        <span
                          className="badge badge-partial"
                          title="An advisory source was unreachable during this scan, so these counts are an undercount -- not a clean result."
                        >
                          <Icon name="alert" /> Partial
                        </span>
                      )}
                  </td>
                  <td data-label="Scanned">
                    <span
                      className={
                        isStale(machine.lastScannedAt)
                          ? "scan-age scan-age-stale"
                          : "scan-age"
                      }
                      title={machine.lastScannedAt ?? "Never scanned"}
                    >
                      {relativeTime(machine.lastScannedAt)}
                    </span>
                  </td>
                  {/*
                    Three states, not two. A dash when intel has never loaded
                    means "not checked" -- rendering a zero there would tell the
                    user this host is clear on the authority of a feed nobody
                    downloaded.
                  */}
                  <td className="kev-cell" data-label="Exploited">
                    {!intelUsable ? (
                      <span
                        className="kev-unknown"
                        title="Threat intel has not been loaded, so exploitation status is unknown. This is not evidence the host is clear."
                      >
                        —
                      </span>
                    ) : machine.kevCount > 0 ? (
                      <span
                        className="badge badge-exploit"
                        title={`${machine.kevCount} finding${machine.kevCount === 1 ? "" : "s"} on CISA's Known Exploited Vulnerabilities list`}
                      >
                        <Icon name="target" /> {machine.kevCount}
                      </span>
                    ) : (
                      <span className="kev-none" title="No findings on CISA KEV">
                        0
                      </span>
                    )}
                  </td>
                  {visibleSeverities.map((severity) => {
                    const count = machine.cveCounts[severity];
                    // A host nobody has scanned has no counts. Four zeros are
                    // the same shape as a clean host, and this row is what the
                    // eye and the column sort go to (Req 10.10).
                    const measured = machine.lastScannedAt !== null;
                    return (
                      <td key={severity} data-col={severity} data-label={severityLabel(severity)}>
                        {measured ? (
                          <span
                            className={`badge ${
                              count > 0 ? `badge-${severity}` : ""
                            }`}
                          >
                            {count}
                          </span>
                        ) : (
                          <span
                            className="kev-unknown"
                            title="This host has never been scanned, so nothing has been counted. This is not evidence that it is clear."
                          >
                            —
                          </span>
                        )}
                      </td>
                    );
                  })}
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
