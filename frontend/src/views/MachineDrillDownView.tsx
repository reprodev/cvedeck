// MachineDrillDownView renders the CVE findings for a single machine with
// interactive KPI filter cards, host vulnerability hotspot widgets, search,
// By-CVE vs By-Package views, and 1-click fix remediation helpers.
//
// Requirements:
//   3.3 - filter the displayed CVEs by severity
//   3.4 - display the drill-down view listing CVEs for the selected machine
//   3.5 - display each CVE identifier, its severity, and its CVSS score
//   4.1 / 4.2 / 4.3 - record and update a remediation status with a note
//   4.4 - display the current remediation status of each CVE

import { Fragment, useCallback, useEffect, useMemo, useState } from "react";
import { exportFindingsCsv } from "../lib/csvExport";
import { compareBySeverity, filterBySeverity } from "../lib/severity";
import {
  type CveFinding,
  type FindingChangeRow,
  type HostKeyPin,
  type Platform,
  type ScanRun,
  type RemediationStatus,
  type Severity,
} from "../types";
import { EmptyState } from "../components/EmptyState";
import { useToast } from "../components/Toast";
import {
  buildBulkFixScript,
  findingFix,
  findingPackageName,
  fixElsewhereExplanation,
  fixElsewhereLabel,
  getDistroTooling,
  hasFix as findingHasFix,
} from "../lib/remediation";
import { useClipboard } from "../lib/useClipboard";
import { isHostKeyStatus, relativeTime, remediationStatusLabel, severityLabel, statusLabel } from "../lib/labels";
import { scanDelta } from "../lib/scanDelta";
import { ScanHistoryPanel } from "../components/ScanHistoryPanel";
import { RemediationCell } from "../components/RemediationCell";
import { CveDetailModal } from "../components/CveDetailModal";
import { OtherPortPins } from "../components/OtherPortPins";
import { impactBadgeLabel, impactTone } from "../lib/impact";
import { Modal } from "../components/Modal";
import { Icon } from "../components/Icon";
import {
  exploitStatus,
  hostExploitSummary,
  isKnownExploited,
  formatEpssPercentile,
  formatEpssScore,
  sortByRisk,
} from "../lib/intel";

export interface MachineDrillDownViewProps {
  /** Identifier of the machine whose findings are shown. */
  machineId: string;
  /** Optional human-readable hostname for the heading. */
  hostname?: string;
  /** Platform of this machine; selects the remediation tooling family. */
  platform?: Platform;
  /** Reported OS name, when known; refines the tooling family. */
  osName?: string;
  /** CVE findings for the machine. */
  findings: CveFinding[];
  /** Called to return to the machine list. Wiring lives in the app shell. */
  onBack?: () => void;
  /**
   * Called to persist a remediation for one CVE. The shell decides whether that
   * adds a new record or updates the existing one, based on the finding's
   * remediationRecordId.
   */
  onSaveRemediation?: (
    finding: CveFinding,
    status: RemediationStatus,
    note: string,
  ) => void;
  /** The machine's last scan status, when known. */
  lastScanStatus?: string;
  /** SHA-256 fingerprint of the host's pinned SSH host key (Req 17.8). */
  hostKeyFingerprint?: string | null;
  /** That key's type, e.g. "ssh-ed25519" -- it names the file on the host. */
  hostKeyType?: string | null;
  /**
   * Forget the pinned host key (Req 17.7). Omitted where forgetting is not
   * allowed, such as demo mode, which hides the action.
   */
  onForgetHostKey?: () => Promise<void>;
  /**
   * False while this machine's findings are still being loaded. An empty list
   * then says nothing about the host, so the page must not call it clean.
   */
  findingsLoaded?: boolean;
  /** False when the last scan ran against an unreachable advisory source. */
  lastScanSourcesOk?: boolean;
  /** Port of the pin above; null when there is none (Req 17.11). */
  hostKeyPort?: number | null;
  /**
   * List every pinned key, to show this machine's pins on other ports
   * (Req 17.11). Omitted, those are not shown.
   */
  onListHostKeys?: () => Promise<HostKeyPin[]>;
  /** Forget a pin on another port. Omitted where forgetting is not allowed. */
  onForgetHostKeyAt?: (hostname: string, port: number) => Promise<void>;
  /** What the latest successful scan changed (Req 18.6); null is not assessed. */
  lastScanNew?: number | null;
  lastScanResolved?: number | null;
  lastScanBaseline?: boolean;
  /** Load the host's scan runs. Omitted, the scan history panel is not shown. */
  onLoadScanRuns?: (limit: number) => Promise<ScanRun[]>;
  /** Load one run's new and resolved findings. */
  onLoadScanChanges?: (runId: string) => Promise<FindingChangeRow[]>;
}

/** Human-readable label for a severity level. */
/** Fallback label when no remediation record exists for a finding. */
function remediationLabel(status: string | null): string {
  return status === null ? "No remediation record" : remediationStatusLabel(status);
}

/**
 * Whether any finding in a package group has a fix in this host's own release.
 *
 * Decided from the findings' structured fix status, never from the text of the
 * identifier: searching it for "fixed in" once counted fixes that only a newer
 * release had (Req 14.7).
 */
function groupHasFix(group: { findings: CveFinding[] }): boolean {
  return group.findings.some(findingHasFix);
}

/** The label for a group whose fix lives in another release, if any. */
function groupElsewhere(group: { findings: CveFinding[] }) {
  for (const finding of group.findings) {
    const fix = findingFix(finding);
    const label = fixElsewhereLabel(fix);
    if (label) return { label, explanation: fixElsewhereExplanation(fix) ?? label };
  }
  return null;
}

/** "Pending vendor patch", or which release already has the fix. */
function PendingBadge({ group }: { group: { findings: CveFinding[] } }) {
  const elsewhere = groupElsewhere(group);
  if (elsewhere) {
    return (
      <span className="fix-elsewhere" title={elsewhere.explanation}>
        <Icon name="alert" /> {elsewhere.label}
      </span>
    );
  }
  return (
    <span className="badge badge-platform" style={{ fontSize: "0.78rem" }}>
      <Icon name="clock" /> Pending vendor patch
    </span>
  );
}

export function MachineDrillDownView({
  machineId,
  hostname,
  platform,
  osName,
  findings,
  onBack,
  onSaveRemediation,
  lastScanStatus,
  hostKeyFingerprint = null,
  hostKeyType = null,
  onForgetHostKey,
  lastScanSourcesOk,
  findingsLoaded = true,
  hostKeyPort = null,
  onListHostKeys,
  onForgetHostKeyAt,
  lastScanNew = null,
  lastScanResolved = null,
  lastScanBaseline = false,
  onLoadScanRuns,
  onLoadScanChanges,
}: MachineDrillDownViewProps) {
  const delta = scanDelta({ lastScanNew, lastScanResolved, lastScanBaseline });
  // What an empty list actually means for this host. "No CVEs identified" is a
  // claim about the host, and it was made for a host nobody had scanned, and
  // for one whose every scan had failed (Req 10.10, 1.4, 1.5, 1.7).
  const scanned = lastScanStatus === "success";
  const emptyTitle = !findingsLoaded
    ? "Loading this host's findings…"
    : lastScanStatus === undefined || lastScanStatus === "never_scanned"
      ? "This host has not been scanned yet."
      : scanned
        ? "No CVE findings recorded for this machine."
        : `The last scan did not complete: ${statusLabel(lastScanStatus).toLowerCase()}.`;
  const emptyDetail = !findingsLoaded
    ? "Nothing here is an answer about this host yet."
    : lastScanStatus === undefined || lastScanStatus === "never_scanned"
      ? "Nothing has been assessed on it, which is not the same as finding nothing. Run a scan to see where it stands."
      : scanned
        ? lastScanSourcesOk === false
          ? "The last scan ran against an advisory source that did not answer, so this is an undercount rather than a clean result. Scan again once the source is reachable."
          : "The last scan completed and matched nothing. If an advisory source had been unreachable, the fleet view would show a partial-results warning for this host."
        : "The findings shown here are whatever the last successful scan recorded; a failed scan neither adds nor clears any. Fix the cause and scan again.";
  const [newOnly, setNewOnly] = useState(false);
  const [confirmForget, setConfirmForget] = useState(false);
  const [forgetting, setForgetting] = useState(false);
  const [forgetError, setForgetError] = useState<string | null>(null);

  const forgetHostKey = async () => {
    if (!onForgetHostKey) return;
    setForgetting(true);
    setForgetError(null);
    try {
      await onForgetHostKey();
      setConfirmForget(false);
    } catch (err) {
      setForgetError(err instanceof Error ? err.message : "The host key could not be forgotten.");
    } finally {
      setForgetting(false);
    }
  };

  const [severityFilter, setSeverityFilter] = useState<Severity | "all">("all");
  const [patchFilter, setPatchFilter] = useState<"all" | "fixable" | "pending">("all");
  const [blastFilter, setBlastFilter] = useState<"all" | "high" | "leaf">("all");
  const [searchQuery, setSearchQuery] = useState("");
  // Risk ordering is the default: it is the ordering the KEV and EPSS signals
  // were collected to make possible, and a CVSS-sorted list buries the
  // findings that are actually being exploited.
  const [riskOrdered, setRiskOrdered] = useState(true);
  const [viewMode, setViewMode] = useState<"cve" | "package" | "tree">("cve");
  const [currentPage, setCurrentPage] = useState(1);
  const [pageSize, setPageSize] = useState(25);
  const [expandedPkg, setExpandedPkg] = useState<string | null>(null);
  const [selectedFinding, setSelectedFinding] = useState<CveFinding | null>(null);
  const toast = useToast();
  // One clipboard implementation with an execCommand fallback. The async
  // Clipboard API is undefined on plain-http origins -- which is how a LAN
  // deployment is reached -- and the previous code silently did nothing there.
  const pkgClipboard = useClipboard(toast.error, 2000);
  const actionClipboard = useClipboard(toast.error, 2500);
  const copiedPkg = pkgClipboard.copiedKey;
  const copiedAction = actionClipboard.copiedKey;
  const copyPkg = (text: string, key: string) => void pkgClipboard.copy(text, key);
  const copyAction = (text: string, key: string) =>
    void actionClipboard.copy(text, key);

  // Summary counts for this machine
  const counts = useMemo(() => {
    const tally = {
      critical: 0,
      unscored: 0,
      high: 0,
      medium: 0,
      low: 0,
      total: findings.length,
    };
    for (const f of findings) {
      if (f.severity in tally) {
        tally[f.severity]++;
      }
    }
    return tally;
  }, [findings]);

  /** Share of this host's findings, as a percentage. Zero-safe. */
  const pct = useCallback(
    (n: number) => (counts.total > 0 ? (n / counts.total) * 100 : 0),
    [counts.total],
  );

  // Patch availability breakdown
  const patchCounts = useMemo(() => {
    let fixable = 0;
    let pending = 0;
    // Findings a package upgrade cannot clear because only a newer release has
    // the fix, by release -- surfaced on its own, since re-running the fix plan
    // and re-scanning would otherwise look like the plan failed (Req 14.8).
    const newerRelease = new Map<string, number>();
    for (const f of findings) {
      if (findingHasFix(f)) {
        fixable++;
      } else {
        pending++;
        const fix = findingFix(f);
        if (fix.status === "newer_release" && fix.release) {
          newerRelease.set(fix.release, (newerRelease.get(fix.release) ?? 0) + 1);
        }
      }
    }
    return { fixable, pending, newerRelease, total: findings.length };
  }, [findings]);

  // Remediation posture summary
  // Derived from the findings rather than threaded down as a prop: a finding
  // carries its own enrichment state, so this screen can tell "checked and
  // clear" from "never checked" without also being handed feed health.
  const exploitedCount = useMemo(
    () => findings.filter(isKnownExploited).length,
    [findings],
  );

  // A zero is a claim; the absence of one is not. `hostExploitSummary` owns
  // the distinction so this screen and the findings table below it cannot
  // disagree -- they did, and the headline was the one that was wrong: it
  // asked whether *any* finding had been checked, so one checked finding among
  // forty unchecked ones printed "None actively exploited" over a table full
  // of unknowns.
  const exploit = useMemo(() => hostExploitSummary(findings), [findings]);
  const exploitState = exploit.state;

  const remediationCounts = useMemo(() => {
    let remediated = 0;
    let inProgress = 0;
    let open = 0;
    for (const f of findings) {
      if (f.remediationStatus === "remediated") remediated++;
      else if (f.remediationStatus === "in_progress") inProgress++;
      else open++;
    }
    return { remediated, inProgress, open };
  }, [findings]);

  const newCount = useMemo(() => findings.filter((f) => f.isNew).length, [findings]);

  // Filter by severity (Requirement 3.3), and to what the last scan found new
  // (Req 18.6).
  const severityFilteredFindings = useMemo(() => {
    const bySeverity =
      severityFilter === "all" ? findings : filterBySeverity(findings, severityFilter);
    return newOnly ? bySeverity.filter((f) => f.isNew) : bySeverity;
  }, [findings, severityFilter, newOnly]);

  // Filter by patch readiness
  const patchFilteredFindings = useMemo(() => {
    if (patchFilter === "fixable") {
      return severityFilteredFindings.filter(findingHasFix);
    }
    if (patchFilter === "pending") {
      return severityFilteredFindings.filter((f) => !findingHasFix(f));
    }
    return severityFilteredFindings;
  }, [severityFilteredFindings, patchFilter]);

  // Filter by search query
  const searchedFindings = useMemo(() => {
    const q = searchQuery.toLowerCase().trim();
    if (!q) return patchFilteredFindings;
    return patchFilteredFindings.filter(
      (f) =>
        f.cveId.toLowerCase().includes(q) ||
        (f.packageIdentifier && f.packageIdentifier.toLowerCase().includes(q)) ||
        (f.remediationStatus && f.remediationStatus.toLowerCase().includes(q)) ||
        (f.remediationNote && f.remediationNote.toLowerCase().includes(q)) ||
        (f.dependencies && f.dependencies.some((d) => d.toLowerCase().includes(q))) ||
        (f.dependedOnBy && f.dependedOnBy.some((d) => d.toLowerCase().includes(q))),
    );
  }, [patchFilteredFindings, searchQuery]);

  // Order by real-world urgency by default: KEV-listed first, then EPSS, then
  // CVSS. A CVSS 6.5 that attackers are using today matters more than a CVSS
  // 9.8 nobody has touched, and a list sorted by score alone cannot say so.
  // The toggle exists because CVSS order is what a compliance report expects.
  const visibleFindings = useMemo(
    () => (riskOrdered ? sortByRisk(searchedFindings) : searchedFindings),
    [searchedFindings, riskOrdered],
  );

  // Group findings by package for the "By Package" mode and top hotspot insight
  const packageGroups = useMemo(() => {
    const groups = new Map<
      string,
      {
        packageName: string;
        packageIdentifier: string;
        findings: CveFinding[];
        /** Worst score in the group, or null if none of its findings has one. */
        maxScore: number | null;
        highestSeverity: Severity;
        dependencies: string[];
        dependedOnBy: string[];
        blastRadius: "low" | "medium" | "high" | null;
      }
    >();

    for (const f of findings) {
      const pkgName = findingPackageName(f) ?? "OS / System";
      const existing = groups.get(pkgName);
      if (!existing) {
        groups.set(pkgName, {
          packageName: pkgName,
          packageIdentifier: f.packageIdentifier ?? pkgName,
          findings: [f],
          maxScore: f.cvssScore,
          highestSeverity: f.severity,
          dependencies: f.dependencies ?? [],
          dependedOnBy: f.dependedOnBy ?? [],
          blastRadius: f.blastRadius ?? null,
        });
      } else {
        existing.findings.push(f);
        // Rank by severity band first: a finding with a published band and no
        // score must be able to win, and comparing the scores directly would
        // make every comparison against a null false (Req 10.11).
        if (
          compareBySeverity(f, {
            severity: existing.highestSeverity,
            cvssScore: existing.maxScore,
          }) < 0
        ) {
          existing.maxScore = f.cvssScore;
          existing.highestSeverity = f.severity;
        }
        if (f.dependencies && f.dependencies.length > existing.dependencies.length) {
          existing.dependencies = f.dependencies;
        }
        if (f.dependedOnBy && f.dependedOnBy.length > existing.dependedOnBy.length) {
          existing.dependedOnBy = f.dependedOnBy;
        }
        if (f.blastRadius) {
          existing.blastRadius = f.blastRadius;
        }
      }
    }

    return Array.from(groups.values()).sort((a, b) =>
      compareBySeverity(
        { severity: a.highestSeverity, cvssScore: a.maxScore },
        { severity: b.highestSeverity, cvssScore: b.maxScore },
      ),
    );
  }, [findings]);

  // Filter package groups by patch readiness and severity
  const visiblePackageGroups = useMemo(() => {
    let groups = packageGroups;
    if (patchFilter === "fixable") {
      groups = groups.filter(groupHasFix);
    } else if (patchFilter === "pending") {
      groups = groups.filter((g) => !groupHasFix(g));
    }
    if (severityFilter !== "all") {
      groups = groups.filter((g) => g.findings.some((f) => f.severity === severityFilter));
    }
    const q = searchQuery.toLowerCase().trim();
    if (!q) return groups;
    return groups.filter(
      (g) =>
        g.packageName.toLowerCase().includes(q) ||
        g.packageIdentifier.toLowerCase().includes(q) ||
        g.dependencies.some((d) => d.toLowerCase().includes(q)) ||
        g.dependedOnBy.some((d) => d.toLowerCase().includes(q)) ||
        g.findings.some((f) => f.cveId.toLowerCase().includes(q)),
    );
  }, [packageGroups, patchFilter, severityFilter, searchQuery]);

  // Reset page when filters change
  useEffect(() => {
    setCurrentPage(1);
  }, [severityFilter, patchFilter, searchQuery, viewMode]);

  // Pagination for CVEs
  const totalCvePages = Math.ceil(visibleFindings.length / pageSize) || 1;
  const safeCvePage = Math.min(Math.max(1, currentPage), totalCvePages);
  const paginatedFindings = useMemo(() => {
    const start = (safeCvePage - 1) * pageSize;
    return visibleFindings.slice(start, start + pageSize);
  }, [visibleFindings, safeCvePage, pageSize]);

  // Pagination for Packages
  const totalPkgPages = Math.ceil(visiblePackageGroups.length / pageSize) || 1;
  const safePkgPage = Math.min(Math.max(1, currentPage), totalPkgPages);
  const paginatedPackageGroups = useMemo(() => {
    const start = (safePkgPage - 1) * pageSize;
    return visiblePackageGroups.slice(start, start + pageSize);
  }, [visiblePackageGroups, safePkgPage, pageSize]);

  // Dependency Tree Blast Radius Groups
  const treePackageGroups = useMemo(() => {
    let list = visiblePackageGroups;
    if (blastFilter === "high") {
      list = list.filter((g) => g.dependedOnBy.length > 0);
    } else if (blastFilter === "leaf") {
      list = list.filter((g) => g.dependedOnBy.length === 0);
    }
    return list;
  }, [visiblePackageGroups, blastFilter]);

  const totalTreePages = Math.ceil(treePackageGroups.length / pageSize) || 1;
  const safeTreePage = Math.min(Math.max(1, currentPage), totalTreePages);
  const paginatedTreeGroups = useMemo(() => {
    const start = (safeTreePage - 1) * pageSize;
    return treePackageGroups.slice(start, start + pageSize);
  }, [treePackageGroups, safeTreePage, pageSize]);

  const inspectorTooling = useMemo(
    () => getDistroTooling(platform, osName, null),
    [platform, osName],
  );

  // One script upgrading every fixable package on this host, deduplicated: a
  // host commonly has a dozen CVEs against a single openssl.
  const bulkFixScript = useMemo(
    () => buildBulkFixScript(findings, platform, osName),
    [findings, platform, osName],
  );
  const fixableCount = useMemo(() => findings.filter(findingHasFix).length, [findings]);

  const handleSave = useCallback(
    (finding: CveFinding, status: RemediationStatus, note: string) => {
      if (onSaveRemediation) {
        onSaveRemediation(finding, status, note);
      }
    },
    [onSaveRemediation],
  );

  return (
    <section aria-label="Machine CVE drill-down" className="view-container">
      {/* Copy confirmations are otherwise a purely visual checkmark swap, which
          assistive technology never reports. */}
      <div className="visually-hidden" aria-live="polite">
        {pkgClipboard.announcement || actionClipboard.announcement}
      </div>
      <div className="view-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem" }}>
        <div style={{ display: "flex", alignItems: "center", gap: "1rem" }}>
          {onBack && (
            <button
              type="button"
              className="back-button"
              onClick={onBack}
              aria-label="Back to machines"
            >
              <Icon name="arrow-left" /> Back to machines
            </button>
          )}
          <div>
            <h2 className="view-title">
              CVE Findings for {hostname ?? machineId}
            </h2>
            <span className="view-subtitle">
              {findings.length} {findings.length === 1 ? "vulnerability" : "vulnerabilities"} detected across installed components
            </span>
            {delta && (
              <span className="scan-delta-line" data-testid="scan-delta">
                {delta.long}
              </span>
            )}
          </div>
        </div>

        {fixableCount > 0 && (
          <button
            type="button"
            className="pagination-btn bulk-fix-btn"
            onClick={() => copyAction(bulkFixScript, "bulk-fix")}
            title={
              "Copy one script upgrading every package on this host that has a " +
              "published fix. Nothing is executed for you."
            }
          >
            {copiedAction === "bulk-fix"
              ? "Remediation plan copied"
              : `Copy fix plan (${fixableCount} fixable)`}
          </button>
        )}

        {findings.length > 0 && (
          <button
            type="button"
            className="pagination-btn"
            onClick={() => exportFindingsCsv(hostname ?? machineId, visibleFindings, {
              baseline: lastScanBaseline,
            })}
            style={{
              padding: "0.55rem 1rem",
              fontSize: "0.85rem",
              fontWeight: 600,
              background: "var(--surface)",
              color: "var(--text)",
              display: "flex",
              alignItems: "center",
              gap: "0.4rem",
            }}
            title="Download RFC 4180 CSV export of visible findings"
          >
            <span>
              <Icon name="file-down" /> Export Findings CSV ({visibleFindings.length})
            </span>
          </button>
        )}
      </div>

      {lastScanStatus && isHostKeyStatus(lastScanStatus) && (
        <div className="release-fix-notice" role="note" data-testid="host-key-refused">
          <Icon name="shield-alert" />
          <div>
            {lastScanStatus === "host_key_mismatch" ? (
              <>
                <strong>The last scan was refused: this host presented a different SSH host key.</strong>{" "}
                No credentials were sent. The findings below are from the last scan that
                completed. If the host was rebuilt or its keys regenerated, check the new
                key on the host and forget the pinned one.
              </>
            ) : (
              <>
                <strong>The last scan was refused: no SSH host key is pinned for this host.</strong>{" "}
                This server only scans hosts whose key is already pinned.
              </>
            )}
          </div>
        </div>
      )}

      {hostKeyFingerprint && (
        <div className="host-key-pin" data-testid="host-key-pin">
          <span className="host-key-label">
            <Icon name="key" /> SSH host key
          </span>
          <code>
            {hostKeyType ? `${hostKeyType} ` : ""}
            {hostKeyFingerprint}
          </code>
          {onForgetHostKey && (
            <button
              type="button"
              className="btn-secondary host-key-forget"
              onClick={() => {
                setForgetError(null);
                setConfirmForget(true);
              }}
            >
              Forget host key
            </button>
          )}
        </div>
      )}

      {onListHostKeys && (
        <OtherPortPins
          machineId={machineId}
          shownPort={hostKeyFingerprint ? hostKeyPort : null}
          onListHostKeys={onListHostKeys}
          onForgetHostKey={onForgetHostKeyAt}
        />
      )}

      {confirmForget && hostKeyFingerprint && (
        <Modal title="Forget this host key?" onClose={() => setConfirmForget(false)}>
          <div className="modal-body">
            <p>
              Scans of {hostname ?? machineId} are held to <code>{hostKeyFingerprint}</code>.
            </p>
            <p>
              <strong>The next scan will trust whatever key the host presents</strong>, and pin
              that one instead. Forget it only if you know why the key changed. Compare it with{" "}
              <code>ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub</code> on the host first.
            </p>
            {forgetError && <p role="alert">{forgetError}</p>}
            <div className="modal-actions">
              <button type="button" className="btn-secondary" onClick={() => setConfirmForget(false)}>
                Cancel
              </button>
              <button
                type="button"
                className="btn-primary"
                onClick={forgetHostKey}
                disabled={forgetting}
              >
                {forgetting ? "Forgetting..." : "Forget host key"}
              </button>
            </div>
          </div>
        </Modal>
      )}

      {/*
        One strip where five KPI cards and a full-width progress card used to
        sit, costing roughly 250px before the tabs -- and duplicating the tabs
        below, which already carry their own counts.

        Ordered by what to act on: whether anything here is being exploited
        right now, then severity, then how much is already handled. The
        exploitation half was previously absent from this screen entirely, so
        the host page never said the thing the fleet page had just flagged.
      */}
      <div className="host-summary">
        <div className="host-summary-exploit" data-state={exploitState}>
          {exploitState === "unknown" ? (
            <span title="No threat intel has been loaded, so exploitation status is unknown for every finding here. This is not evidence that none are exploited.">
              <Icon name="target" /> Exploitation unknown
            </span>
          ) : exploitState === "partial" ? (
            <span
              title={`${exploit.checked} of ${exploit.total} findings were checked against CISA's KEV catalogue and none are listed. The remaining ${
                exploit.total - exploit.checked
              } were never checked, so this host has not been cleared.`}
            >
              <Icon name="target" /> {exploit.checked} of {exploit.total} checked
              {" -- "}none exploited so far
            </span>
          ) : exploitedCount > 0 ? (
            <span title="Listed in CISA's Known Exploited Vulnerabilities catalogue">
              <Icon name="target" /> <strong>{exploitedCount}</strong> actively exploited
            </span>
          ) : (
            <span title="Every finding on this host was checked against CISA's KEV catalogue and none is listed.">
              <Icon name="target" /> None actively exploited
            </span>
          )}
        </div>

        {/* Same chips as the fleet view, so the two screens read as one product
            and the severity dropdown that used to sit below is unnecessary. */}
        <div className="findings-strip-chips">
          <button
            type="button"
            className={`sev-chip ${severityFilter === "all" ? "active" : ""}`}
            aria-pressed={severityFilter === "all"}
            onClick={() => setSeverityFilter("all")}
          >
            All {counts.total}
          </button>
          {(["critical", "high", "medium", "low"] as const).map((sev) => (
            <button
              key={sev}
              type="button"
              className={`sev-chip ${severityFilter === sev ? "active" : ""}`}
              data-severity={sev}
              aria-pressed={severityFilter === sev}
              onClick={() => setSeverityFilter(severityFilter === sev ? "all" : sev)}
            >
              {severityLabel(sev)} {counts[sev]}
            </button>
          ))}
          {newCount > 0 && (
            <button
              type="button"
              className={`sev-chip ${newOnly ? "active" : ""}`}
              aria-pressed={newOnly}
              onClick={() => setNewOnly(!newOnly)}
              title="Findings the latest scan found that the scan before it did not"
            >
              New {newCount}
            </button>
          )}
        </div>

        {findings.length > 0 && (
          <div className="host-summary-progress">
            <span className="host-summary-progress-label">
              {remediationCounts.remediated} of {counts.total} resolved
            </span>
            <div
              className="remediation-bar-track"
              role="img"
              aria-label={`${remediationCounts.remediated} remediated, ${remediationCounts.inProgress} in progress, ${remediationCounts.open} open`}
            >
              <div
                className="remediation-bar-segment segment-remediated"
                style={{ width: `${pct(remediationCounts.remediated)}%` }}
                title={`Remediated: ${remediationCounts.remediated}`}
              />
              <div
                className="remediation-bar-segment segment-in-progress"
                style={{ width: `${pct(remediationCounts.inProgress)}%` }}
                title={`In progress: ${remediationCounts.inProgress}`}
              />
              <div
                className="remediation-bar-segment segment-open"
                style={{ width: `${counts.total > 0 ? pct(remediationCounts.open) : 100}%` }}
                title={`Open: ${remediationCounts.open}`}
              />
            </div>
          </div>
        )}
      </div>

      {onLoadScanRuns && onLoadScanChanges && (
        <ScanHistoryPanel onLoadRuns={onLoadScanRuns} onLoadChanges={onLoadScanChanges} />
      )}

      {findings.length === 0 ? (
        <EmptyState title={emptyTitle}>{emptyDetail}</EmptyState>
      ) : (
        <>
          {patchCounts.newerRelease.size > 0 && (
            <div className="release-fix-notice" role="note" data-testid="newer-release-notice">
              <Icon name="alert" />
              <div>
                <strong>
                  {[...patchCounts.newerRelease.values()].reduce((a, b) => a + b, 0)} finding(s)
                  are fixed only in{" "}
                  {[...patchCounts.newerRelease.keys()].sort().join(", ")}, not in this
                  host&apos;s release.
                </strong>{" "}
                Upgrading packages cannot clear them, so they stay after the fix plan
                runs and the host is re-scanned. Upgrading the distribution clears them,
                or they clear once this release publishes the fix.
              </div>
            </div>
          )}

          {/* Workspace Tabs */}
          <div className="workspace-tabs">
            <button
              type="button"
              className={`workspace-tab-btn tab-fixable ${patchFilter === "fixable" && viewMode === "cve" ? "active" : ""}`}
              onClick={() => {
                setPatchFilter("fixable");
                setViewMode("cve");
              }}
            >
              <span>
                <Icon name="wrench" /> Ready to Fix ({patchCounts.fixable})
              </span>
            </button>
            <button
              type="button"
              className={`workspace-tab-btn tab-pending ${patchFilter === "pending" && viewMode === "cve" ? "active" : ""}`}
              onClick={() => {
                setPatchFilter("pending");
                setViewMode("cve");
              }}
            >
              <span>
                <Icon name="clock" /> Pending Vendor Patch ({patchCounts.pending})
              </span>
            </button>
            <button
              type="button"
              className={`workspace-tab-btn ${patchFilter === "all" && viewMode === "cve" ? "active" : ""}`}
              onClick={() => {
                setPatchFilter("all");
                setViewMode("cve");
              }}
            >
              <span>
                <Icon name="list" /> All Findings ({counts.total})
              </span>
            </button>
            <button
              type="button"
              className={`workspace-tab-btn ${viewMode === "package" ? "active" : ""}`}
              onClick={() => setViewMode("package")}
            >
              <span>
                <Icon name="package" /> By Package ({packageGroups.length})
              </span>
            </button>
            <button
              type="button"
              className={`workspace-tab-btn ${viewMode === "tree" ? "active" : ""}`}
              onClick={() => setViewMode("tree")}
            >
              <span>
                <Icon name="branch" /> Dependency Map ({packageGroups.length})
              </span>
            </button>
          </div>

          {/* Controls Bar: Instant Search, Severity Select */}
          <div className="controls-bar">
            <div className="search-box">
              <span className="search-icon">
                <Icon name="search" />
              </span>
              <input
                type="text"
                placeholder="Search CVE ID, package, status, notes, or dependencies..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                aria-label="Search CVE findings"
              />
            </div>

            {/* The severity dropdown that stood here is now the chip row in the
                host summary above -- same filter, one control. */}
          </div>

          {/* Strategic Guidance Banner when viewing pending */}
          {patchFilter === "pending" && counts.total > 0 && (
            <div className="recommendations-banner">
              <div className="recommendations-banner-header">
                <div className="recommendations-banner-title">
                  <span>
                  <Icon name="shield-alert" /> Remediation Strategies for Pending Vendor Patches ({patchCounts.pending} CVEs)</span>
                </div>
              </div>
              <div className="recommendations-grid">
                <div className="recommendation-option-card">
                  <div className="recommendation-option-title">
                    <span>1. Purge Unused Leaf Packages</span>
                    <span className="badge badge-blast-low">Zero Impact</span>
                  </div>
                  <p className="recommendation-option-desc">
                    Packages like desktop clients or unused tools (e.g. <code>thunderbird</code>, <code>snapd</code>) with 0 dependent apps can be purged to completely eliminate their CVEs.
                  </p>
                  <div style={{ marginTop: "auto", paddingTop: "0.5rem" }}>
                    <span style={{ fontSize: "0.74rem", color: "var(--text-muted)", fontFamily: "var(--font-mono)" }}>
                      {inspectorTooling.purgeCmd("PACKAGE")}
                    </span>
                  </div>
                </div>

                {/* Ubuntu Pro is Canonical-specific. This block used to render
                    on every host, so RHEL and Alpine users were told to run
                    `sudo pro enable esm-apps`, which does not exist there. */}
                {inspectorTooling.isUbuntu && (
                  <div className="recommendation-option-card">
                    <div className="recommendation-option-title">
                      <span>2. Ubuntu Pro (ESM) Security</span>
                      <span className="badge badge-high">LTS Fixes</span>
                    </div>
                    <p className="recommendation-option-desc">
                      Many universe/multiverse packages receive backported security patches through Canonical's free Ubuntu Pro (ESM) service.
                    </p>
                    <div style={{ marginTop: "auto", paddingTop: "0.5rem" }}>
                      <button
                        type="button"
                        className="copy-cmd-btn"
                        onClick={() => copyAction("sudo pro status && sudo pro enable esm-apps", "pro-check")}
                      >
                        {copiedAction === "pro-check" ? <><Icon name="check" /> Copied!</> : <><Icon name="copy" /> Copy: sudo pro status</>}
                      </button>
                    </div>
                  </div>
                )}

                <div className="recommendation-option-card">
                  <div className="recommendation-option-title">
                    <span>{inspectorTooling.isUbuntu ? "3." : "2."} OS Distribution Upgrade</span>
                    <span className="badge badge-platform">Major Update</span>
                  </div>
                  <p className="recommendation-option-desc">
                    Newer upstream releases pull updated package trees with patched code.
                  </p>
                  {inspectorTooling.isUbuntu && (
                    <div style={{ marginTop: "auto", paddingTop: "0.5rem" }}>
                      <button
                        type="button"
                        className="copy-cmd-btn"
                        onClick={() => copyAction("sudo do-release-upgrade -c", "upgrade-check")}
                      >
                        {copiedAction === "upgrade-check" ? <><Icon name="check" /> Copied!</> : <><Icon name="copy" /> Copy: do-release-upgrade -c</>}
                      </button>
                    </div>
                  )}
                </div>
              </div>
            </div>
          )}

          {visibleFindings.length === 0 ? (
            <EmptyState
              title={
                findings.length === 0
                  ? "No CVE findings recorded for this machine."
                  : "No findings match the current filters."
              }
              filters={[
                { label: "search", value: searchQuery.trim() },
                { label: "severity", value: severityFilter === "all" ? "" : severityFilter },
                { label: "new", value: newOnly ? "new only" : "" },
                { label: "patch state", value: patchFilter === "all" ? "" : patchFilter },
                { label: "blast radius", value: blastFilter === "all" ? "" : blastFilter },
              ]}
              onClearFilters={() => {
                setSearchQuery("");
                setSeverityFilter("all");
                setNewOnly(false);
                setPatchFilter("all");
                setBlastFilter("all");
                setCurrentPage(1);
              }}
            >
              {findings.length === 0
                ? "A scan that completed with no findings may also mean an advisory source was unreachable -- check the fleet view for a partial-results warning."
                : undefined}
            </EmptyState>
          ) : viewMode === "tree" ? (
            /* Dependency Map & Blast Radius Visual Explorer */
            <div>
              {/* Blast Radius Filter Bar */}
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "1rem", flexWrap: "wrap", gap: "0.75rem" }}>
                <div style={{ display: "flex", gap: "0.4rem", alignItems: "center", flexWrap: "wrap" }}>
                  <button
                    type="button"
                    className={`pagination-btn ${blastFilter === "all" ? "active" : ""}`}
                    style={{
                      padding: "0.45rem 0.85rem",
                      fontSize: "0.83rem",
                      background: blastFilter === "all" ? "var(--accent)" : "var(--surface)",
                      color: blastFilter === "all" ? "var(--accent-text)" : "var(--text)",
                      fontWeight: blastFilter === "all" ? 600 : 400,
                    }}
                    onClick={() => setBlastFilter("all")}
                  >
                    All Components ({visiblePackageGroups.length})
                  </button>
                  <button
                    type="button"
                    className={`pagination-btn ${blastFilter === "high" ? "active" : ""}`}
                    style={{
                      padding: "0.45rem 0.85rem",
                      fontSize: "0.83rem",
                      background: blastFilter === "high" ? "var(--accent)" : "var(--surface)",
                      color: blastFilter === "high" ? "var(--accent-text)" : "var(--text)",
                      fontWeight: blastFilter === "high" ? 600 : 400,
                    }}
                    onClick={() => setBlastFilter("high")}
                  >
                    <Icon name="x-circle" /> High Blast Radius ({visiblePackageGroups.filter((g) => g.dependedOnBy.length > 0).length})
                  </button>
                  <button
                    type="button"
                    className={`pagination-btn ${blastFilter === "leaf" ? "active" : ""}`}
                    style={{
                      padding: "0.45rem 0.85rem",
                      fontSize: "0.83rem",
                      background: blastFilter === "leaf" ? "var(--accent)" : "var(--surface)",
                      color: blastFilter === "leaf" ? "var(--accent-text)" : "var(--text)",
                      fontWeight: blastFilter === "leaf" ? 600 : 400,
                    }}
                    onClick={() => setBlastFilter("leaf")}
                  >
                    <Icon name="check" /> Standalone Leaf Components ({visiblePackageGroups.filter((g) => g.dependedOnBy.length === 0).length})
                  </button>
                </div>

                <div className="pagination-nav">
                  <button
                    type="button"
                    className="pagination-btn"
                    disabled={safeTreePage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  >
                    ◀ Prev
                  </button>
                  <span style={{ fontSize: "0.82rem" }}>Page {safeTreePage} of {totalTreePages}</span>
                  <button
                    type="button"
                    className="pagination-btn"
                    disabled={safeTreePage >= totalTreePages}
                    onClick={() => setCurrentPage((p) => Math.min(totalTreePages, p + 1))}
                  >
                    Next ▶
                  </button>
                </div>
              </div>

              {/* Tree Grid Cards */}
              <div className="dep-grid">
                {paginatedTreeGroups.map((group) => {
                  const pkgName = group.packageName;
                  const hasFix = groupHasFix(group);
                  // Three states, not two. With no dependency graph behind it,
                  // "nothing depends on this" is a statement about the query,
                  // and this view acts on it -- it offers a purge command
                  // (Req 10.10).
                  const dependentsKnown = group.blastRadius !== null;
                  const isLeaf = dependentsKnown && group.dependedOnBy.length === 0;
                  const isCopied = copiedPkg === pkgName;
                  const tooling = getDistroTooling(platform, osName, group.packageIdentifier);

                  return (
                    <div
                      key={pkgName}
                      className="card"
                      style={{
                        padding: "1.2rem",
                        display: "flex",
                        flexDirection: "column",
                        gap: "0.85rem",
                        borderLeft: isLeaf
                          ? "4px solid var(--ok-border)"
                          : "4px solid var(--error-border)",
                      }}
                    >
                      <div className="dep-card-head">
                        <div>
                          <div style={{ fontWeight: 600, fontSize: "1.05rem" }}>
                            <Icon name="package" /> {pkgName}
                          </div>
                          <div className="package-pill" style={{ marginTop: "0.25rem" }}>
                            {group.packageIdentifier}
                          </div>
                        </div>
                        <div className="dep-card-meta">
                          <span className={`badge badge-${group.highestSeverity}`}>
                            {severityLabel(group.highestSeverity)} •{" "}
                            {group.maxScore === null
                              ? "No published CVSS"
                              : `CVSS ${group.maxScore.toFixed(1)}`}
                          </span>
                          <span style={{ fontSize: "0.76rem", color: "var(--text-muted)" }}>
                            {group.findings.length} {group.findings.length === 1 ? "CVE" : "CVEs"}
                          </span>
                        </div>
                      </div>

                      {/* Blast Radius Assessment */}
                      {!dependentsKnown ? (
                        <div
                          className="warning-card-low"
                          style={{ padding: "0.6rem 0.8rem", margin: 0, opacity: 0.85 }}
                        >
                          <div style={{ fontWeight: 600, fontSize: "0.82rem", color: "var(--text-dim)", marginBottom: "0.2rem" }}>
                            Blast radius not assessed
                          </div>
                          <div style={{ fontSize: "0.74rem", color: "var(--text-muted)" }}>
                            No inventory has been collected for this host, so nothing
                            is known about what depends on this package. Scan the host
                            before removing it.
                          </div>
                        </div>
                      ) : !isLeaf ? (
                        (() => {
                          // The same tier the badge shows, so a "Moderate"
                          // package cannot carry a "HIGH SYSTEM IMPACT" card.
                          const tone = impactTone(group.blastRadius)!;
                          return (
                            <div className={tone.cardClass} style={{ padding: "0.6rem 0.8rem", margin: 0 }}>
                              <div style={{ fontWeight: 600, fontSize: "0.82rem", color: tone.colorVar, marginBottom: "0.3rem" }}>
                                <Icon name="x-circle" /> {tone.heading} — required by {group.dependedOnBy.length} installed {group.dependedOnBy.length === 1 ? "app" : "apps"}:
                              </div>
                              <div className="dependency-chips">
                                {group.dependedOnBy.map((app) => (
                                  <span key={app} className="dependency-chip dependent-app">
                                    {app}
                                  </span>
                                ))}
                              </div>
                              <div style={{ fontSize: "0.74rem", color: "var(--text-muted)", marginTop: "0.35rem" }}>
                                {tone.advice}
                              </div>
                            </div>
                          );
                        })()
                      ) : (
                        <div className="warning-card-low" style={{ padding: "0.6rem 0.8rem", margin: 0 }}>
                          <div style={{ fontWeight: 600, fontSize: "0.82rem", color: "var(--ok-text)", marginBottom: "0.2rem" }}>
                            <Icon name="check" /> STANDALONE COMPONENT (0 host dependencies)
                          </div>
                          <div style={{ fontSize: "0.74rem", color: "var(--text-muted)" }}>
                            If not in active use, this component can be purged safely without breaking any other installed applications.
                          </div>
                        </div>
                      )}

                      {/* Dependencies */}
                      {group.dependencies.length > 0 && (
                        <div>
                          <div style={{ fontSize: "0.76rem", fontWeight: 600, color: "var(--text-muted)", marginBottom: "0.3rem" }}>
                            <Icon name="download" /> Requires ({group.dependencies.length} packages):
                          </div>
                          <div className="dependency-chips">
                            {group.dependencies.slice(0, 8).map((req) => (
                              <span key={req} className="dependency-chip" style={{ fontSize: "0.72rem" }}>
                                {req}
                              </span>
                            ))}
                            {group.dependencies.length > 8 && (
                              <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                                +{group.dependencies.length - 8} more
                              </span>
                            )}
                          </div>
                        </div>
                      )}

                      {/* CVE Tags */}
                      <div style={{ display: "flex", gap: "0.35rem", flexWrap: "wrap", alignItems: "center" }}>
                        <span style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Linked CVEs:</span>
                        {group.findings.slice(0, 5).map((f) => (
                          <button
                            key={f.cveId}
                            type="button"
                            className="badge badge-platform"
                            style={{ cursor: "pointer", border: "none", fontSize: "0.72rem" }}
                            onClick={() => setSelectedFinding(f)}
                            title={`Inspect ${f.cveId}`}
                          >
                            {f.cveId} ↗
                          </button>
                        ))}
                        {group.findings.length > 5 && (
                          <span style={{ fontSize: "0.72rem", color: "var(--text-muted)" }}>
                            +{group.findings.length - 5} more
                          </span>
                        )}
                      </div>

                      {/* Remediation Action */}
                      <div style={{ marginTop: "auto", paddingTop: "0.5rem" }}>
                        {hasFix ? (
                          <button
                            type="button"
                            className="copy-fix-btn"
                            style={{ width: "100%", justifyContent: "center" }}
                            onClick={() => copyPkg(tooling.updateCmd(pkgName), pkgName)}
                          >
                            {isCopied ? <><Icon name="check" /> Upgrade Command Copied!</> : <><Icon name="copy" /> Copy: {tooling.updateCmd(pkgName)}</>}
                          </button>
                        ) : isLeaf ? (
                          <button
                            type="button"
                            className="copy-purge-btn"
                            style={{ width: "100%", justifyContent: "center" }}
                            onClick={() => copyPkg(tooling.purgeCmd(pkgName), pkgName)}
                          >
                            {isCopied ? <><Icon name="check" /> Purge Command Copied!</> : <><Icon name="trash" /> Copy Purge: {tooling.purgeCmd(pkgName)}</>}
                          </button>
                        ) : (
                          <div style={{ fontSize: "0.78rem", color: "var(--text-muted)", textAlign: "center", padding: "0.35rem" }}>
                            <Icon name="clock" /> Awaiting Upstream Vendor Security Build
                          </div>
                        )}
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ) : viewMode === "package" ? (
            /* By Package Aggregated View */
            <div>
              <div className="pagination-bar" style={{ marginBottom: "1rem" }}>
                <span>
                  Showing {(safePkgPage - 1) * pageSize + 1} to {Math.min(safePkgPage * pageSize, visiblePackageGroups.length)} of {visiblePackageGroups.length} packages
                </span>
                <div className="pagination-nav">
                  <button
                    type="button"
                    className="pagination-btn"
                    disabled={safePkgPage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  >
                    ◀ Prev
                  </button>
                  <span>Page {safePkgPage} of {totalPkgPages}</span>
                  <button
                    type="button"
                    className="pagination-btn"
                    disabled={safePkgPage >= totalPkgPages}
                    onClick={() => setCurrentPage((p) => Math.min(totalPkgPages, p + 1))}
                  >
                    Next ▶
                  </button>
                  <select
                    className="page-size-select"
                    value={pageSize}
                    onChange={(e) => setPageSize(Number(e.target.value))}
                    aria-label="Packages per page"
                  >
                    <option value={25}>25 / page</option>
                    <option value={50}>50 / page</option>
                    <option value={100}>100 / page</option>
                  </select>
                </div>
              </div>

              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th scope="col">Affected Package</th>
                      <th scope="col">Vulnerabilities</th>
                      <th scope="col">Max Severity</th>
                      <th scope="col">Top Score</th>
                      <th scope="col">Blast Radius (Impact)</th>
                      <th scope="col">Remediation Fix Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedPackageGroups.map((group) => {
                      const pkgName = group.packageName;
                      const tooling = getDistroTooling(
                        platform,
                        osName,
                        group.packageIdentifier,
                      );
                      const isCopied = copiedPkg === pkgName;
                      const isExpanded = expandedPkg === pkgName;
                      const hasFix = groupHasFix(group);
                      // Three states, not two. With no dependency graph behind it,
                  // "nothing depends on this" is a statement about the query,
                  // and this view acts on it -- it offers a purge command
                  // (Req 10.10).
                  const dependentsKnown = group.blastRadius !== null;
                  const isLeaf = dependentsKnown && group.dependedOnBy.length === 0;
                      return (
                        <Fragment key={pkgName}>
                          <tr>
                            <td data-label="Affected package">
                              <div style={{ fontWeight: 600, fontSize: "0.95rem" }}>
                                <Icon name="package" /> {pkgName}
                              </div>
                              <div className="package-pill">{group.packageIdentifier}</div>
                              {(group.dependencies.length > 0 || group.dependedOnBy.length > 0 || group.findings.length > 0) && (
                                <button
                                  type="button"
                                  className="drawer-toggle-btn"
                                  onClick={() => setExpandedPkg(isExpanded ? null : pkgName)}
                                >
                                  {isExpanded ? "▲ Hide Details & Dependencies" : `▼ View CVEs (${group.findings.length}) & Dependencies`}
                                </button>
                              )}
                            </td>
                            <td data-label="Vulnerabilities">
                              <button
                                type="button"
                                className="badge badge-platform"
                                style={{ cursor: "pointer", border: "none" }}
                                onClick={() => setSelectedFinding(group.findings[0])}
                                title={`Inspect ${group.findings.length} CVEs for ${pkgName}`}
                              >
                                {group.findings.length}{" "}
                                {group.findings.length === 1 ? "CVE" : "CVEs"} ↗
                              </button>
                            </td>
                            <td data-label="Max severity">
                              <span className={`badge badge-${group.highestSeverity}`}>
                                {severityLabel(group.highestSeverity)}
                              </span>
                            </td>
                            <td data-label="Top score">
                              <span
                                className="cvss-score-pill"
                                title={
                                  group.maxScore === null
                                    ? "No CVSS score published for any advisory on this package"
                                    : undefined
                                }
                              >
                                {group.maxScore ?? "—"}
                              </span>
                            </td>
                            <td data-label="Blast radius">
                              <span
                                className={
                                  impactTone(group.blastRadius)?.badgeClass ??
                                  "badge-blast-unknown"
                                }
                                title={
                                  impactTone(group.blastRadius) === null
                                    ? "No inventory has been collected for this host, so nothing is known about what depends on this package."
                                    : undefined
                                }
                              >
                                {/* Null is its own state, not the bottom of the
                                    scale: "Low (0 apps)" would answer a
                                    question nobody asked (Req 10.10). */}
                                {(() => {
                                  const tone = impactTone(group.blastRadius);
                                  return tone === null
                                    ? "Not assessed"
                                    : impactBadgeLabel(tone, group.dependedOnBy.length);
                                })()}
                              </span>
                            </td>
                            <td data-label="Remediation">
                              {hasFix ? (
                                <button
                                  type="button"
                                  className="copy-fix-btn"
                                  onClick={() => copyPkg(tooling.updateCmd(pkgName), pkgName)}
                                  title={`Copy fix command: sudo apt install --only-upgrade ${pkgName}`}
                                >
                                  {isCopied ? <><Icon name="check" /> Command Copied!</> : <><Icon name="copy" /> Copy apt upgrade command</>}
                                </button>
                              ) : isLeaf ? (
                                <div style={{ display: "flex", flexDirection: "column", gap: "0.35rem" }}>
                                  <PendingBadge group={group} />
                                  <button
                                    type="button"
                                    className="copy-purge-btn"
                                    onClick={() => copyAction(tooling.purgeCmd(pkgName), `purge-${pkgName}`)}
                                    title={`Unused leaf package: remove completely to eliminate CVEs`}
                                  >
                                    {copiedAction === `purge-${pkgName}` ? <><Icon name="check" /> Copied!</> : <><Icon name="trash" /> Purge: sudo apt purge {pkgName}</>}
                                  </button>
                                </div>
                              ) : (
                                <PendingBadge group={group} />
                              )}
                            </td>
                          </tr>
                          {isExpanded && (
                            <tr>
                              <td colSpan={6} style={{ padding: 0 }}>
                                <div className="dependency-drawer">
                                  <div className="dependency-drawer-grid">
                                    <div>
                                      <div className="dependency-section-title">
                                        <span>
                                          <Icon name="shield-alert" /> Associated Vulnerabilities ({group.findings.length})
                                        </span>
                                      </div>
                                      <div className="dependency-chips">
                                        {group.findings.map((f) => (
                                          <button
                                            key={f.cveId}
                                            type="button"
                                            className="clickable-cve-btn"
                                            style={{
                                              fontSize: "0.78rem",
                                              padding: "0.2rem 0.45rem",
                                              background: "var(--surface-muted)",
                                              borderRadius: "4px",
                                              border: "1px solid var(--border)",
                                            }}
                                            onClick={() => setSelectedFinding(f)}
                                            title={`Click to inspect details & advisories for ${f.cveId}`}
                                          >
                                            {f.cveId} ↗
                                          </button>
                                        ))}
                                      </div>
                                    </div>

                                    <div>
                                      <div className="dependency-section-title">
                                        <span><Icon name="branch" /> Depended on by Installed Apps ({group.dependedOnBy.length})</span>
                                      </div>
                                      {group.dependedOnBy.length > 0 ? (
                                        <div className="dependency-chips">
                                          {group.dependedOnBy.map((dep) => (
                                            <span key={dep} className="dependency-chip dependent-app">
                                              {dep}
                                            </span>
                                          ))}
                                        </div>
                                      ) : (
                                        <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.8rem" }}>
                                          Standalone component — no other packages on this host depend on it.
                                        </p>
                                      )}
                                    </div>

                                    <div>
                                      <div className="dependency-section-title">
                                        <span>
                                          <Icon name="download" /> Requires ({group.dependencies.length})
                                        </span>
                                      </div>
                                      {group.dependencies.length > 0 ? (
                                        <div className="dependency-chips">
                                          {group.dependencies.map((req) => (
                                            <span key={req} className="dependency-chip">
                                              {req}
                                            </span>
                                          ))}
                                        </div>
                                      ) : (
                                        <p style={{ margin: 0, color: "var(--text-muted)", fontSize: "0.8rem" }}>
                                          No explicit package dependencies listed.
                                        </p>
                                      )}
                                    </div>
                                  </div>
                                </div>
                              </td>
                            </tr>
                          )}
                        </Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            /* By CVE Full-Width Findings Table View */
            <div className="table-full-view">
              <div className="pagination-bar">
                <span>
                  Showing {(safeCvePage - 1) * pageSize + 1} to {Math.min(safeCvePage * pageSize, visibleFindings.length)} of {visibleFindings.length} findings
                </span>
                <label
                  style={{
                    display: "inline-flex",
                    alignItems: "center",
                    gap: "0.4rem",
                    fontSize: "0.8rem",
                  }}
                  title="Rank by observed and predicted exploitation (CISA KEV, then EPSS, then CVSS) instead of by CVSS score alone."
                >
                  <input
                    type="checkbox"
                    checked={riskOrdered}
                    onChange={(event) => setRiskOrdered(event.target.checked)}
                  />
                  <span>Sort by exploitation risk</span>
                </label>
                <div className="pagination-nav">
                  <button
                    type="button"
                    className="pagination-btn"
                    disabled={safeCvePage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  >
                    ◀ Prev
                  </button>
                  <span>Page {safeCvePage} of {totalCvePages}</span>
                  <button
                    type="button"
                    className="pagination-btn"
                    disabled={safeCvePage >= totalCvePages}
                    onClick={() => setCurrentPage((p) => Math.min(totalCvePages, p + 1))}
                  >
                    Next ▶
                  </button>
                  <select
                    className="page-size-select"
                    value={pageSize}
                    onChange={(e) => setPageSize(Number(e.target.value))}
                    aria-label="Findings per page"
                  >
                    <option value={25}>25 / page</option>
                    <option value={50}>50 / page</option>
                    <option value={100}>100 / page</option>
                  </select>
                </div>
              </div>

              <div className="table-container">
                <table>
                  <thead>
                    <tr>
                      <th scope="col" style={{ minWidth: "220px" }}>CVE ID &amp; Affected Component</th>
                      <th scope="col" style={{ width: "130px" }}>Exploitation</th>
                      <th scope="col" style={{ width: "110px" }}>Severity</th>
                      <th scope="col" style={{ width: "110px" }}>CVSS Score</th>
                      <th scope="col" style={{ minWidth: "160px" }}>Remediation Status</th>
                      <th scope="col" style={{ width: "100px" }}>First seen</th>
                      {onSaveRemediation && <th scope="col" style={{ minWidth: "320px" }}>Update Remediation</th>}
                    </tr>
                  </thead>
                  <tbody>
                    {paginatedFindings.map((finding) => {
                      const pkgName = findingPackageName(finding);
                      const rowTooling = getDistroTooling(
                        platform,
                        osName,
                        finding.packageIdentifier,
                      );
                      const hasFix = findingHasFix(finding);
                      const isCopied = pkgName && copiedPkg === pkgName;
                      return (
                        <tr
                          key={`${finding.cveId}:${finding.packageIdentifier}`}
                          className="master-row"
                        >
                          <td className="host-col">
                            <div className="cve-id-cell">
                              <button
                                type="button"
                                className="clickable-cve-btn"
                                onClick={() => setSelectedFinding(finding)}
                                title={`Open detailed modal for ${finding.cveId}`}
                              >
                                <span>{finding.cveId}</span>
                                <span style={{ fontSize: "0.75rem", opacity: 0.7 }}><Icon name="search" /> Inspect</span>
                              </button>
                              {finding.isNew && (
                                <span
                                  className="badge badge-new"
                                  title="Found by the latest scan, and not by the scan before it"
                                >
                                  New
                                </span>
                              )}
                            </div>
                            {finding.packageIdentifier && (
                              <div className="package-pill">
                                <span>
                                  <Icon name="package" /> {finding.packageIdentifier}
                                </span>
                                {pkgName && hasFix ? (
                                  <button
                                    type="button"
                                    className="copy-fix-btn"
                                    onClick={() => copyPkg(rowTooling.updateCmd(pkgName), pkgName)}
                                    title={`Copy: sudo apt install --only-upgrade ${pkgName}`}
                                  >
                                    {isCopied ? <><Icon name="check" /> Copied</> : <><Icon name="copy" /> Copy fix</>}
                                  </button>
                                ) : fixElsewhereLabel(findingFix(finding)) ? (
                                  <span
                                    className="fix-elsewhere"
                                    title={fixElsewhereExplanation(findingFix(finding)) ?? undefined}
                                  >
                                    <Icon name="alert" /> {fixElsewhereLabel(findingFix(finding))}
                                  </span>
                                ) : (
                                  <span style={{ opacity: 0.85, fontSize: "0.75rem", display: "inline-flex", alignItems: "center", gap: "0.3rem" }}>
                                    <Icon name="clock" /> Pending patch
                                    {finding.dependedOnBy && finding.dependedOnBy.length > 0 ? (
                                      <span style={{ color: "var(--impact-high)", fontSize: "0.7rem", fontWeight: 600 }}>
                                        (<Icon name="alert" /> Required by {finding.dependedOnBy.length} apps)
                                      </span>
                                    ) : (
                                      <span style={{ color: "var(--accent)", fontSize: "0.7rem" }}>
                                        (<Icon name="alert" /> Standalone)
                                      </span>
                                    )}
                                  </span>
                                )}
                              </div>
                            )}
                          </td>
                          {/*
                            Three visually distinct states, never two. An
                            unenriched finding shows a muted dash, not the same
                            "Not exploited" chip a checked-and-clear finding
                            gets -- collapsing them would present a feed that
                            never loaded as a clean bill of health.
                          */}
                          <td data-label="Exploitation" data-exploitation={exploitStatus(finding)}>
                            {exploitStatus(finding) === "exploited" ? (
                              <span
                                className="badge badge-exploit"
                                title={
                                  finding.kevDueDate
                                    ? `On CISA KEV. Federal remediation due ${finding.kevDueDate}.`
                                    : "Listed in CISA's Known Exploited Vulnerabilities catalogue."
                                }
                              >
                                <Icon name="target" /> Exploited
                              </span>
                            ) : exploitStatus(finding) === "not-exploited" ? (
                              <span
                                style={{ fontSize: "0.75rem", opacity: 0.7 }}
                                title="Checked against CISA KEV and not listed."
                              >
                                Not on KEV
                              </span>
                            ) : (
                              <span
                                style={{ fontSize: "0.75rem", opacity: 0.45 }}
                                title="Not checked -- threat intel has not been loaded. This is not evidence the CVE is unexploited."
                              >
                                — unknown
                              </span>
                            )}
                            <div style={{ fontSize: "0.7rem", opacity: 0.7, marginTop: "0.2rem" }}>
                              {finding.epssScore !== null && finding.epssScore !== undefined ? (
                                <span
                                  title={`EPSS: ${formatEpssScore(finding.epssScore)} probability of exploitation in the next 30 days (${formatEpssPercentile(finding.epssPercentile)} percentile).`}
                                >
                                  EPSS {formatEpssScore(finding.epssScore)}
                                  {finding.epssPercentile !== null &&
                                  finding.epssPercentile !== undefined
                                    ? ` · ${formatEpssPercentile(finding.epssPercentile)}`
                                    : ""}
                                </span>
                              ) : (
                                <span style={{ opacity: 0.6 }}>EPSS --</span>
                              )}
                            </div>
                          </td>
                          <td data-label="Severity" data-severity={finding.severity}>
                            <span className={`badge badge-${finding.severity}`}>
                              {severityLabel(finding.severity)}
                            </span>
                          </td>
                          <td data-label="CVSS">
                            <span
                              className="cvss-score-pill"
                              title={
                                finding.cvssScore === null
                                  ? "No CVSS score published for this advisory"
                                  : undefined
                              }
                            >
                              {finding.cvssScore ?? "—"}
                            </span>
                          </td>
                          <td data-label="Remediation">
                            <span
                              className={`badge ${
                                finding.remediationStatus === "remediated"
                                  ? "badge-status-success"
                                  : finding.remediationStatus === "in_progress"
                                  ? "badge-medium"
                                  : "badge-platform"
                              }`}
                            >
                              {remediationLabel(finding.remediationStatus)}
                            </span>
                          </td>
                          <td
                            data-label="First seen"
                            className="scan-age"
                            title={finding.firstSeenAt ? new Date(finding.firstSeenAt).toLocaleString() : undefined}
                          >
                            {finding.firstSeenAt ? relativeTime(finding.firstSeenAt) : "--"}
                          </td>
                          {onSaveRemediation && (
                            <td className="remediation-col" data-label="Update">
                              <RemediationCell
                                key={`${finding.cveId}:${finding.remediationRecordId ?? "new"}`}
                                finding={finding}
                                onSave={handleSave}
                              />
                            </td>
                          )}
                        </tr>
                      );
                    })}
                  </tbody>
                </table>
              </div>

              <div className="pagination-bar">
                <span>
                  Page {safeCvePage} of {totalCvePages} ({visibleFindings.length} total findings)
                </span>
                <div className="pagination-nav">
                  <button
                    type="button"
                    className="pagination-btn"
                    disabled={safeCvePage <= 1}
                    onClick={() => setCurrentPage((p) => Math.max(1, p - 1))}
                  >
                    ◀ Prev
                  </button>
                  <button
                    type="button"
                    className="pagination-btn"
                    disabled={safeCvePage >= totalCvePages}
                    onClick={() => setCurrentPage((p) => Math.min(totalCvePages, p + 1))}
                  >
                    Next ▶
                  </button>
                </div>
              </div>
            </div>
          )}
        </>
      )}

      {selectedFinding && (
        <CveDetailModal
          finding={selectedFinding}
          hostname={hostname}
          platform={platform}
          osName={osName}
          onClose={() => setSelectedFinding(null)}
          onSaveRemediation={onSaveRemediation ? handleSave : undefined}
        />
      )}
    </section>
  );
}
