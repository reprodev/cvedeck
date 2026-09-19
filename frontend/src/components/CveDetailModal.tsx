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
import type { IconName } from "./Icon";
import { impactTone } from "../lib/impact";

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
  // Three states, as in the dependency map. With no graph behind it, an empty
  // list says nothing about the host, and this dialog acts on it: it offers a
  // purge command under "you can safely remove it" (Req 10.10).
  const dependentsKnown = finding.blastRadius !== null;
  const tone = impactTone(finding.blastRadius);
  const isLeaf = dependentsKnown && dependedOnBy.length === 0;
  const tooling = getDistroTooling(platform, osName, finding.packageIdentifier);

  // What can be done where no package update exists, in the order to try them.
  // Only the options that apply are built, so nothing numbers around a gap.
  const mitigations: {
    key: string;
    title: string;
    detail: string;
    command: string;
    buttonClass: string;
    buttonLabel: string;
    icon: IconName;
  }[] = [
    ...(isLeaf
      ? [
          {
            key: "purge-cmd",
            title: "Purge if unused",
            detail: "Remove the package if this host does not need it",
            command: tooling.purgeCmd(pkgName),
            buttonClass: "copy-purge-btn",
            buttonLabel: "Copy purge",
            icon: "trash" as IconName,
          },
        ]
      : []),
    ...(tooling.isUbuntu
      ? [
          {
            key: "pro-cmd",
            title: "Ubuntu Pro (ESM)",
            detail: "Check for extended security backports",
            command: "sudo pro status && sudo pro enable esm-apps",
            buttonClass: "copy-cmd-btn",
            buttonLabel: "Check Pro",
            icon: "copy" as IconName,
          },
        ]
      : []),
    {
      key: "dist-cmd",
      title: tooling.isUbuntu ? "OS distribution upgrade" : "Check distro updates",
      detail: "Check for upstream distribution updates",
      command: tooling.checkUpdateCmd(pkgName),
      buttonClass: "copy-cmd-btn",
      buttonLabel: "Copy check command",
      icon: "copy" as IconName,
    },
  ];

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
              {severityLabel(finding.severity)} •{" "}
              {/* An advisory may publish a band and no score (Req 2.6), or
                  neither (Req 2.7). Rendering the null directly leaves a
                  dangling "CVSS" with no number after it, because React
                  renders null as nothing. */}
              {finding.cvssScore === null
                ? "No published CVSS"
                : `CVSS ${finding.cvssScore.toFixed(1)}`}
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
            {!dependentsKnown ? (
              <div className="warning-card-low" style={{ opacity: 0.85 }}>
                <div className="warning-card-title-low" style={{ color: "var(--text-dim)" }}>
                  <span>Blast radius not assessed</span>
                </div>
                <p style={{ margin: 0, fontSize: "0.82rem", color: "var(--text-muted)", lineHeight: 1.45 }}>
                  No inventory has been collected for this host, so nothing is known
                  about what depends on <strong>{pkgName}</strong>. Scan the host before
                  removing it.
                </p>
              </div>
            ) : !isLeaf && tone !== null ? (
              <div className={tone.cardClass}>
                {/* The tier the badge shows, not "high" for any dependent at
                    all: three dependents is Moderate in both places. */}
                <div className="warning-card-title-high" style={{ color: tone.colorVar }}>
                  <span><Icon name="x-circle" /> {tone.heading}</span>
                </div>
                <p style={{ margin: 0, fontSize: "0.82rem", color: "var(--text)", lineHeight: 1.45 }}>
                  This component is required by{" "}
                  <strong>
                    {dependedOnBy.length} installed{" "}
                    {dependedOnBy.length === 1 ? "application" : "applications"}
                  </strong>{" "}
                  on this machine:
                </p>
                <div className="dependency-chips" style={{ marginTop: "0.35rem" }}>
                  {dependedOnBy.map((app) => (
                    <span key={app} className="dependency-chip dependent-app">
                      {app}
                    </span>
                  ))}
                </div>
                <p style={{ margin: "0.35rem 0 0", fontSize: "0.78rem", color: "var(--text-muted)" }}>
                  {tone.advice}
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
              <span><Icon name="wrench" /> Recommended Remediation Actions ({tooling.label})</span>
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

                  {/* An ordered list, so the numbers come from what actually
                      rendered. Hardcoded "1."/"2."/"3." skipped a number
                      whenever the purge option was hidden, which is every
                      package something else depends on. */}
                  <ol className="mitigation-list">
                    {mitigations.map((option) => (
                      <li key={option.key}>
                        <div>
                          <div style={{ fontWeight: 600, fontSize: "0.82rem" }}>{option.title}</div>
                          <div style={{ fontSize: "0.75rem", color: "var(--text-muted)" }}>{option.detail}</div>
                        </div>
                        <button
                          type="button"
                          className={option.buttonClass}
                          onClick={() => copyAction(option.command, option.key)}
                        >
                          {copiedAction === option.key ? (
                            <><Icon name="check" /> Copied!</>
                          ) : (
                            <><Icon name={option.icon} /> {option.buttonLabel}</>
                          )}
                        </button>
                      </li>
                    ))}
                  </ol>
                </div>
              )}
            </div>
          </div>

          {/* Official Security Advisory Links */}
          <div className="modal-section">
            <div className="modal-section-title">
              <span><Icon name="external" /> Official Security Advisory Intelligence</span>
            </div>
            <div className="advisory-links-grid">
              <a
                href={nvdUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="advisory-link-card"
              >
                <span><Icon name="list" /> NIST NVD Database</span>
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
                <span><Icon name="list" /> Update Audit Record</span>
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
