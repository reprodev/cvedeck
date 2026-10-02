// A host's kernel, apart from its userland (Req 12.5, 12.6, 12.8).
//
// One kernel source carries hundreds of CVEs, so the kernel gets its own card
// rather than burying everything else in the findings list -- but its
// findings stay in every total and export. The card says which kernel is
// running, how much of what was found is live, and the one thing that fixes
// it: a reboot when the fixed kernel is already installed, otherwise an
// upgrade and a reboot. Only known exploitation is red.

import { useEffect, useState } from "react";
import type { CveFinding, KernelInfo, Platform } from "../types";
import { kernelPlan, kernelUpgradeCommand, unfixedSummary, type UnfixedSummary } from "../lib/kernel";
import { Icon } from "./Icon";

export interface KernelCardProps {
  findings: CveFinding[];
  /** False until this machine's findings have arrived. */
  findingsLoaded: boolean;
  platform?: Platform;
  osName?: string;
  /** Load the host's kernels; resolves null when nothing was collected yet. */
  onLoad: () => Promise<KernelInfo | null>;
}

function plural(n: number, one: string, many: string = `${one}s`): string {
  return `${n.toLocaleString("en-US")} ${n === 1 ? one : many}`;
}

/** "2,187 fixed only in Debian 13, 132 with no fix yet" (Req 12.9). */
function unfixedParts(summary: UnfixedSummary): string {
  const parts = summary.elsewhere.map(([release, n]) => `${n.toLocaleString("en-US")} fixed only in ${release}`);
  if (summary.noFix > 0) parts.push(`${summary.noFix.toLocaleString("en-US")} with no fix yet`);
  return parts.join(", ");
}

export function KernelCard({ findings, findingsLoaded, platform, osName, onLoad }: KernelCardProps) {
  const [kernel, setKernel] = useState<KernelInfo | null | undefined>(undefined);
  const [error, setError] = useState<string | null>(null);

  // Reloaded with the findings: a re-scan changes both, and a card describing
  // the previous scan's kernels next to this scan's findings would be wrong.
  useEffect(() => {
    if (!findingsLoaded) return;
    let cancelled = false;
    setError(null);
    onLoad()
      .then((result) => {
        if (!cancelled) setKernel(result);
      })
      .catch((err: unknown) => {
        if (!cancelled) setError(err instanceof Error ? err.message : "The kernel could not be loaded.");
      });
    return () => {
      cancelled = true;
    };
  }, [findings, findingsLoaded, onLoad]);

  if (error) {
    return (
      <section className="kernel-card" data-testid="kernel-card" role="note">
        <Icon name="alert" /> <span>Kernel details could not be loaded: {error}</span>
      </section>
    );
  }
  // Nothing collected, or no kernel installed at all (a container).
  if (!kernel || kernel.installed.length === 0) return null;

  if (!kernel.checked) {
    // A question not asked must not look answered (Req 12.5).
    return (
      <section className="release-fix-notice kernel-card" role="note" data-testid="kernel-unchecked">
        <Icon name="alert" />
        <div>
          <strong>
            This host's kernel was not checked against advisories ({plural(kernel.installed.length, "kernel")}{" "}
            installed).
          </strong>{" "}
          CveDeck does not look up the kernel on this distribution: for some, Ubuntu among them, the
          advisory data for one kernel runs to gigabytes. The findings below say nothing about it. Keep
          the kernel updated through your distribution.
        </div>
      </section>
    );
  }

  const plan = kernelPlan(findings, kernel);
  const liveUnfixed = kernel.runningInstalled === false ? null : unfixedSummary(kernel, "live");
  const idleUnfixed = unfixedSummary(kernel, "idle");
  const sampleIdentifier = findings.find((f) => f.isKernel)?.packageIdentifier ?? null;
  const upgrade = kernelUpgradeCommand(kernel, platform, osName, sampleIdentifier);

  return (
    <section className="kernel-card" data-testid="kernel-card" aria-label="Kernel">
      <header className="kernel-card-head">
        <span className="kernel-card-title">
          <Icon name="linux" /> Kernel
        </span>
        <span className="kernel-card-release" data-testid="kernel-release">
          {kernel.release === null ? "Running kernel not reported" : `Running ${kernel.release}`}
        </span>
      </header>

      {kernel.release === null && (
        <p className="kernel-card-line">
          This host did not report which kernel it is running, so every kernel finding is treated as live.
        </p>
      )}
      {kernel.runningInstalled === false && (
        <p className="kernel-card-line" data-testid="kernel-not-installed">
          <Icon name="alert" /> The running kernel {kernel.release} is not from an installed package — a
          container's host, or a kernel built by hand — so it was not checked. Findings below are for
          the kernels installed on disk.
        </p>
      )}

      {kernel.runningInstalled !== false && (
        // Not said when the running kernel was not checked: "0 CVEs in the
        // running kernel" would read as an answer to a question never asked.
        <p className="kernel-card-line" data-testid="kernel-live">
          <strong>{plural(plan.live.length, "CVE")}</strong>{" "}
          {kernel.release === null ? "in the installed kernels" : "in the running kernel"}
          {plan.exploited > 0 && (
            <>
              {", "}
              <span className="badge badge-exploit" data-testid="kernel-exploited">
                {plan.exploited} known exploited
              </span>
            </>
          )}
          .
        </p>
      )}
      {kernel.runningInstalled !== false && (
        // Counted, not listed: CVEs this release cannot fix. Said, never hidden.
        <p className="kernel-card-line kernel-card-idle" data-testid="kernel-unfixed">
          {liveUnfixed === null
            ? "CVEs with no fix in this release were not assessed for this kernel."
            : liveUnfixed.total === 0
              ? "No CVEs without a fix in this release."
              : `${plural(liveUnfixed.total, "more CVE")} ${liveUnfixed.total === 1 ? "has" : "have"} no fix in this release and ${liveUnfixed.total === 1 ? "is" : "are"} counted, not listed: ${unfixedParts(liveUnfixed)}.`}
        </p>
      )}

      {plan.fixedByReboot.length > 0 && plan.rebootInto && (
        <p className="kernel-card-fix" data-testid="kernel-reboot">
          <Icon name="refresh" /> <strong>Reboot into {plan.rebootInto}.</strong> It is already installed,
          and it fixes{" "}
          {plan.fixedByReboot.length === plan.live.length
            ? "all of them"
            : `${plan.fixedByReboot.length} of them`}
          {kernel.rebootRequired ? "; the host also reports a reboot pending." : "."}
        </p>
      )}
      {plan.needUpgrade.length > 0 && (
        <div className="kernel-card-fix" data-testid="kernel-upgrade">
          <p>
            <Icon name="wrench" />{" "}
            <strong>
              {plan.fixedByReboot.length > 0 ? "For the rest, upgrade" : "Upgrade"} the kernel, then reboot
            </strong>{" "}
            — {plural(plan.needUpgrade.length, "CVE")} {plan.needUpgrade.length === 1 ? "has" : "have"} a
            fix in this release.
          </p>
          {upgrade ? (
            <pre className="kernel-card-command">
              <code>{upgrade}</code>
            </pre>
          ) : (
            <p className="kernel-card-line">
              Install the newer kernel through your distribution; no kernel metapackage is installed to
              upgrade.
            </p>
          )}
        </div>
      )}
      {plan.idle.length > 0 && (
        <p className="kernel-card-line kernel-card-idle" data-testid="kernel-idle">
          {plural(plan.idle.length, "CVE")} {plan.idle.length === 1 ? "is" : "are"} only in kernels installed
          but not running. They matter if one of those is booted; removing old kernels clears them.
        </p>
      )}
      {idleUnfixed !== null && idleUnfixed.total > 0 && (
        <p className="kernel-card-line kernel-card-idle" data-testid="kernel-idle-unfixed">
          The kernels not running have {plural(idleUnfixed.total, "more CVE")} with no fix in this release
          ({unfixedParts(idleUnfixed)}).
        </p>
      )}

      <ul className="kernel-card-list">
        {kernel.installed.map((k) => (
          <li key={`${k.package}@${k.version}`}>
            <code>{k.package}</code> {k.version}
            {k.running === true && <span className="badge badge-platform">running</span>}
            {k.running === null && <span className="badge badge-platform">may be running</span>}
            {k.newest && k.running !== true && <span className="badge badge-platform">newest</span>}
          </li>
        ))}
      </ul>
    </section>
  );
}
