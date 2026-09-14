// The CVE inspection dialog: full detail for one finding, its exploitation
// signals, the remediation command for the host it was found on, and an inline
// remediation editor.
//
// Extracted from MachineDrillDownView, which had grown to 1,761 lines holding
// four unrelated components. A dialog with its own focus management and
// clipboard handling is a component, not a section of another one.

import { useState } from "react";

import type { CveFinding, Platform, RemediationStatus } from "../types";
import { useDialogA11y } from "./Modal";
import { useToast } from "./Toast";
import { useClipboard } from "../lib/useClipboard";
import {
  findingFix,
  findingPackageName,
  fixElsewhereExplanation,
  fixElsewhereLabel,
  getDistroTooling,
  hasFix as findingHasFix,
} from "../lib/remediation";
import { severityLabel } from "../lib/labels";
import { Icon } from "./Icon";

export interface CveDetailModalProps {
  finding: CveFinding;
  hostname?: string;
  /** Platform of the machine; selects the remediation tooling family. */
  platform?: Platform;
  /** Reported OS name, when known; refines the tooling family. */
  osName?: string;
  onClose: () => void;
  onSaveRemediation?: (
    finding: CveFinding,
    status: RemediationStatus,
    note: string,
  ) => void;
}

export function CveDetailModal({
  finding,
  hostname,
  platform,
  osName,
  onClose,
  onSaveRemediation,
}: CveDetailModalProps) {
  const toast = useToast();
  const clipboard = useClipboard(toast.error, 2500);
  const copiedAction = clipboard.copiedKey;
  const copyAction = (text: string, key: string) => void clipboard.copy(text, key);
  // Escape to close, a focus trap, initial focus, and focus restoration. The
  // dialog previously had none of these, so a keyboard user could not get out.
  const { dialogRef, dialogProps, titleId } = useDialogA11y(onClose);
  const [status, setStatus] = useState<RemediationStatus>(
    (finding.remediationStatus as RemediationStatus | null) ?? "open",
  );
  const [note, setNote] = useState(finding.remediationNote ?? "");

  const cveId = finding.cveId;
  const pkgName = findingPackageName(finding) ?? "OS / Component";
  const hasFix = findingHasFix(finding);
  const fix = findingFix(finding);
  const elsewhereLabel = fixElsewhereLabel(fix);
  const dependedOnBy = finding.dependedOnBy ?? [];
  const isLeaf = dependedOnBy.length === 0;
  const tooling = getDistroTooling(platform, osName, finding.packageIdentifier);

  const nvdUrl = `https://nvd.nist.gov/vuln/detail/${cveId}`;
  const ubuntuUrl = `https://ubuntu.com/security/${cveId}`;
  const osvUrl = `https://osv.dev/vulnerability/${cveId}`;
  const mitreUrl = `https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cveId}`;

  return (
    // role="presentation" on the backdrop: the dialog role belongs on the panel,
    // not on the element whose job is to dismiss it.
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div
        ref={dialogRef}
        className="modal-container"
        {...dialogProps}
        onClick={(e) => e.stopPropagation()}
      >
        <div className="visually-hidden" aria-live="polite">
          {clipboard.announcement}
        </div>
        <div className="modal-header">
          <div className="modal-title-row">
            <h2 className="modal-title" id={titleId}>
              {cveId}
            </h2>
            <span className={`badge badge-${finding.severity}`}>
              {severityLabel(finding.severity)} • CVSS {finding.cvssScore}
            </span>
            {hasFix ? (
              <span className="badge badge-status-success"><Icon name="wrench" /> Vendor Patch Available</span>
            ) : elsewhereLabel ? (
              <span className="fix-elsewhere"><Icon name="alert" /> {elsewhereLabel}</span>
            ) : (
              <span className="badge badge-platform"><Icon name="clock" /> Awaiting Upstream Vendor Build</span>
            )}
          </div>
          <button
            type="button"
            className="modal-close-btn"
            onClick={onClose}
            aria-label="Close detail modal"
          >
            ✕
          </button>
        </div>

        <div className="modal-body">
          {/* Target Package */}
          <div className="modal-section">
            <div className="modal-section-title">
              <span>
                <Icon name="package" /> Target Package & Host State
              </span>
            </div>
            <div className="action-card">
              <div style={{ fontWeight: 600, fontSize: "0.95rem" }}>
                {finding.packageIdentifier ?? "Operating System / Base"}
              </div>
              <div style={{ fontSize: "0.8rem", color: "var(--text-muted)", marginTop: "0.25rem" }}>
                Installed on: <strong>{hostname}</strong> • Distribution: <strong>{tooling.label}</strong>
              </div>
            </div>
          </div>

          {/* Removal Safety Warning Card */}
          <div className="modal-section">
            <div className="modal-section-title">
              <span>
                <Icon name="alert" /> Removal & Dependency Impact Assessment
              </span>
            </div>
            {!isLeaf ? (
              <div className="warning-card-high">
                <div className="warning-card-title-high">
                  <span>🚫 DO NOT REMOVE THIS PACKAGE (High System Impact)</span>
                </div>
                <p style={{ margin: 0, fontSize: "0.82rem", color: "var(--text)", lineHeight: 1.45 }}>
                  This component is actively required by <strong>{dependedOnBy.length} installed applications</strong> on this machine:
                </p>
                <div className="dependency-chips" style={{ marginTop: "0.35rem" }}>
                  {dependedOnBy.map((app) => (
                    <span key={app} className="dependency-chip dependent-app">
                      {app}
                    </span>
                  ))}
                </div>
                <p style={{ margin: "0.35rem 0 0", fontSize: "0.78rem", color: "var(--text-muted)" }}>
                  Removing or purging this package will break dependent applications. Wait for an official upstream patch or upgrade the host OS.
                </p>
              </div>
            ) : (
              <div className="warning-card-low">
                <div className="warning-card-title-low">
                  <span>
                    <Icon name="alert" /> CHECK USAGE BEFORE PURGING (Standalone Component)
                  </span>
                </div>
                <p style={{ margin: 0, fontSize: "0.82rem", color: "var(--text)", lineHeight: 1.45 }}>
                  No other packages on this host declare a dependency on <strong>{pkgName}</strong>.
                </p>
                <p style={{ margin: "0.35rem 0 0", fontSize: "0.78rem", color: "var(--text-muted)" }}>
                  If your server does not actively use this service or user-facing tool (e.g. desktop client, unused daemon), you can safely remove it to completely eliminate its CVE attack surface.
                </p>
              </div>
            )}
          </div>

          {/* Recommended Remediation Actions */}
          <div className="modal-section">
            <div className="modal-section-title">
              <span>🛠️ Recommended Remediation Actions ({tooling.label})</span>
            </div>
            <div className="action-card">
              {hasFix ? (
                <div>
                  <div style={{ fontWeight: 600, color: "var(--ok-text)", fontSize: "0.88rem", marginBottom: "0.35rem" }}>
                    <Icon name="check-circle" /> Actionable Security Patch Ready
                  </div>
                  <p style={{ margin: 0, fontSize: "0.8rem", color: "var(--text-muted)", marginBottom: "0.6rem" }}>
                    Run the selective package upgrade command to install the fix:
                  </p>
                  <button
                    type="button"
                    className="copy-fix-btn"
                    onClick={() => copyAction(tooling.updateCmd(pkgName), "fix-cmd")}
                  >
                    {copiedAction === "fix-cmd" ? <><Icon name="check" /> Command Copied!</> : <><Icon name="copy" /> Copy: {tooling.updateCmd(pkgName)}</>}
                  </button>
                </div>
              ) : (
                <div style={{ display: "flex", flexDirection: "column", gap: "0.75rem" }}>
                  {elsewhereLabel ? (
                    <div className="release-fix-notice" role="note">
                      <Icon name="alert" />
                      <div>{fixElsewhereExplanation(fix)}</div>
                    </div>
                  ) : (
                    <div style={{ fontSize: "0.82rem", color: "var(--text-muted)" }}>
                      No standard package update has been published by the distribution maintainer yet. Choose an alternative mitigation:
                    </div>
                  )}

                  {isLeaf && (
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.75rem", background: "var(--surface-muted)", padding: "0.5rem 0.75rem", borderRadius: "6px" }}>
                      <div>
                        <div style={{ fontWeight: 600, fontSize: "0.82rem" }}>1. Purge If Unused</div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Remove package if not required</div>
                      </div>
                      <button
                        type="button"
                        className="copy-purge-btn"
                        onClick={() => copyAction(tooling.purgeCmd(pkgName), "purge-cmd")}
                      >
                        {copiedAction === "purge-cmd" ? <><Icon name="check" /> Copied!</> : <><Icon name="trash" /> Copy Purge</>}
                      </button>
                    </div>
                  )}

                  {tooling.isUbuntu && (
                    <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.75rem", background: "var(--surface-muted)", padding: "0.5rem 0.75rem", borderRadius: "6px" }}>
                      <div>
                        <div style={{ fontWeight: 600, fontSize: "0.82rem" }}>2. Ubuntu Pro (ESM)</div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Check for extended security backports</div>
                      </div>
                      <button
                        type="button"
                        className="copy-cmd-btn"
                        onClick={() => copyAction("sudo pro status && sudo pro enable esm-apps", "pro-cmd")}
                      >
                        {copiedAction === "pro-cmd" ? <><Icon name="check" /> Copied!</> : <><Icon name="copy" /> Check Pro</>}
                      </button>
                    </div>
                  )}

                  <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "0.75rem", background: "var(--surface-muted)", padding: "0.5rem 0.75rem", borderRadius: "6px" }}>
                    <div>
                      <div style={{ fontWeight: 600, fontSize: "0.82rem" }}>{tooling.isUbuntu ? "3. OS Distribution Upgrade" : "2. Check Distro Updates"}</div>
                      <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>Check for upstream distribution updates</div>
                    </div>
                    <button
                      type="button"
                      className="copy-cmd-btn"
                      onClick={() => copyAction(tooling.checkUpdateCmd(pkgName), "dist-cmd")}
                    >
                      {copiedAction === "dist-cmd" ? <><Icon name="check" /> Copied!</> : <><Icon name="copy" /> {tooling.checkUpdateCmd}</>}
                    </button>
                  </div>
                </div>
              )}
            </div>
          </div>

          {/* Official Security Advisory Links */}
          <div className="modal-section">
            <div className="modal-section-title">
              <span>🌐 Official Security Advisory Intelligence</span>
            </div>
            <div className="advisory-links-grid">
              <a
                href={nvdUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="advisory-link-card"
              >
                <span>🏛️ NIST NVD Database</span>
                <span>↗</span>
              </a>
              <a
                href={ubuntuUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="advisory-link-card"
              >
                <span>
                  <Icon name="shield" /> Ubuntu Security Tracker
                </span>
                <span>↗</span>
              </a>
              <a
                href={osvUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="advisory-link-card"
              >
                <span>
                  <Icon name="package" /> Open Source Vulns (OSV)
                </span>
                <span>↗</span>
              </a>
              <a
                href={mitreUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="advisory-link-card"
              >
                <span>
                  <Icon name="search" /> MITRE CVE Dictionary
                </span>
                <span>↗</span>
              </a>
            </div>
          </div>

          {/* Remediation Audit Record */}
          {onSaveRemediation && (
            <div className="modal-section">
              <div className="modal-section-title">
                <span>📝 Update Audit Record</span>
              </div>
              <div className="action-card">
                <div style={{ display: "flex", gap: "0.75rem", alignItems: "center", flexWrap: "wrap" }}>
                  <select
                    value={status}
                    onChange={(e) => setStatus(e.target.value as RemediationStatus)}
                    aria-label={`Modal remediation status for ${cveId}`}
                  >
                    <option value="open">Open</option>
                    <option value="in_progress">In Progress</option>
                    <option value="remediated">Remediated</option>
                  </select>
                  <input
                    type="text"
                    placeholder="Audit notes or remediation plan..."
                    value={note}
                    onChange={(e) => setNote(e.target.value)}
                    style={{ flex: 1, minWidth: "180px" }}
                    aria-label={`Modal remediation note for ${cveId}`}
                  />
                  <button
                    type="button"
                    className="button-primary"
                    onClick={() => {
                      onSaveRemediation(finding, status, note);
                      onClose();
                    }}
                  >
                    Save & Close
                  </button>
                </div>
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
