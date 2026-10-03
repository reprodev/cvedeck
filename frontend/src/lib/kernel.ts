// A host's kernel findings, and the one action that fixes them (Req 12.6, 12.8).
//
// The kernel is the one package where installed and in use part ways. A
// kernel CVE in the running kernel is live; one in a kernel installed but not
// booted matters only if that kernel is booted again. And a host that has
// already installed the fixed kernel needs a reboot, not another upgrade --
// telling it to upgrade sends someone in a loop that never clears the finding.

import type { CveFinding, InstalledKernel, KernelInfo, Platform } from "../types";
import { isKnownExploited } from "./intel";
import { getDistroTooling, hasFix } from "./remediation";

export type KernelScope = "all" | "kernel" | "userland";

/** The findings in one part of the host: its kernels, or everything else. */
export function filterByKernel(findings: CveFinding[], scope: KernelScope): CveFinding[] {
  if (scope === "all") return findings;
  const wantKernel = scope === "kernel";
  return findings.filter((f) => (f.isKernel ?? false) === wantKernel);
}

/**
 * Whether a kernel finding should be treated as live.
 *
 * `null` -- the host did not say which kernel it runs -- counts as live: an
 * unknown is never shown as safely idle (Req 12.6).
 */
export function inRunningKernel(finding: CveFinding): boolean {
  return (finding.isKernel ?? false) && finding.kernelRunning !== false;
}

export interface KernelPlan {
  /** Kernel findings in the running kernel, or possibly in it. */
  live: CveFinding[];
  /** Kernel findings only in kernels installed and not running. */
  idle: CveFinding[];
  /** Live findings the newest installed kernel does not have: a reboot fixes them. */
  fixedByReboot: CveFinding[];
  /** The installed kernel a reboot would bring up, when it is not the running one. */
  rebootInto: string | null;
  /** Live findings with a fix in this release that a reboot alone does not bring. */
  needUpgrade: CveFinding[];
  /** Known-exploited live findings. */
  exploited: number;
}

/** The installed version a finding names: what follows the last "@", before any note. */
function identifierVersion(identifier: string | null): string | null {
  if (!identifier) return null;
  const note = identifier.indexOf(" (");
  const base = note === -1 ? identifier : identifier.slice(0, note);
  const at = base.lastIndexOf("@");
  return at > 0 && base[at - 1] !== ":" ? base.slice(at + 1).trim() || null : null;
}

/**
 * Whether a finding is in this installed kernel.
 *
 * By name and version: on RPM and SUSE every installed kernel has the same
 * name (kernel-core, kernel-default), and only the version tells the running
 * one from an old one beside it (Req 12.6).
 */
function onKernel(finding: CveFinding, kernel: InstalledKernel): boolean {
  const names = finding.affectedPackages ?? [];
  const named = names.length > 0 ? names.includes(kernel.package) : finding.packageName === kernel.package;
  if (!named) return false;
  const version = identifierVersion(finding.packageIdentifier);
  return version === null || version === kernel.version;
}

/** What the kernel findings on one host add up to, and what to do about them. */
export function kernelPlan(findings: CveFinding[], kernel: KernelInfo | null): KernelPlan {
  const kernelFindings = findings.filter((f) => f.isKernel);
  const live = kernelFindings.filter(inRunningKernel);
  const idle = kernelFindings.filter((f) => !inRunningKernel(f));

  // A reboot fixes a live finding when the kernel it would boot was checked
  // and has no finding for that CVE. Only when that kernel is not already the
  // one running, and only when the running one is known.
  const newest = kernel?.checked
    ? kernel.installed.find((k) => k.newest && k.running === false)
    : undefined;
  const newestCves = newest
    ? new Set(kernelFindings.filter((f) => onKernel(f, newest)).map((f) => f.cveId))
    : null;
  const fixedByReboot =
    newestCves !== null ? live.filter((f) => f.kernelRunning === true && !newestCves.has(f.cveId)) : [];
  const rebooted = new Set(fixedByReboot);

  return {
    live,
    idle,
    fixedByReboot,
    rebootInto: newest?.package ?? null,
    needUpgrade: live.filter((f) => !rebooted.has(f) && hasFix(f)),
    exploited: live.filter(isKnownExploited).length,
  };
}

/**
 * The command that brings a newer kernel, or null when there is none to give.
 *
 * On Debian and Ubuntu a fixed kernel arrives as a new package
 * (linux-image-6.1.0-54-amd64), so it is the metapackage that is upgraded;
 * upgrading the running image's own package does nothing. A host with no
 * metapackage gets no command rather than one that does nothing.
 */
export function kernelUpgradeCommand(
  kernel: KernelInfo,
  platform: Platform | undefined,
  osName: string | undefined,
  packageIdentifier: string | null,
): string | null {
  const tooling = getDistroTooling(platform, osName, packageIdentifier);
  if (tooling.family === "unknown" || tooling.family === "windows") return null;
  if (tooling.family === "arch") return tooling.updateCmd("");
  if (kernel.upgradePackages.length === 0) return null;
  return tooling.updateCmd(kernel.upgradePackages);
}

/**
 * Why a kernel was not checked, as the card says it (Req 12.5, 12.11).
 *
 * Every reason the server gives has words here; one it does not know falls
 * back to a plain "not checked", never to silence.
 */
export function uncheckedReasonText(reason: string | null): string {
  switch (reason) {
    case "ubuntu_feed_off":
      return "The Ubuntu kernel feed is switched off on this server (CVEDECK_UBUNTU_KERNEL_FEED).";
    case "ubuntu_feed_unavailable":
      return "Canonical's kernel feed for this Ubuntu release has not been fetched yet, or is out of date. It refreshes with the other intel feeds.";
    case "ubuntu_release_unknown":
      return "CveDeck does not know this Ubuntu release, so it has no kernel feed to check it against.";
    case "ubuntu_release_end_of_life":
      return "This Ubuntu release is out of support. Canonical's feed for it no longer changes, so newer CVEs would be missing, not fixed.";
    case "ubuntu_running_kernel_unknown":
      return "This host did not report which kernel it is running, and on Ubuntu only the running kernel can be checked.";
    case "ubuntu_running_kernel_not_installed":
      return "The running kernel is not from an installed package (a container, or a kernel built by hand), and on Ubuntu only the running kernel can be checked.";
    case "ubuntu_kernel_flavour_unknown":
      return "Canonical's feed has no entries for this kernel's flavour.";
    case "ubuntu_not_yet_scanned":
      return "The Ubuntu kernel feed is now available; scan this host again to check its kernel.";
    case "not_supported":
      return "CveDeck does not look up the kernel on this distribution.";
    default:
      return "The kernel was not checked against advisories.";
  }
}

export interface UnfixedSummary {
  total: number;
  noFix: number;
  /** Per release that has a fix, largest first. */
  elsewhere: [string, number][];
}

/**
 * Kernel CVEs that were counted rather than listed (Req 12.9), summed over the
 * running kernel ("live") or over the kernels installed and not running
 * ("idle"). When the running kernel is unknown, every kernel counts as live.
 *
 * `null` when any kernel in the sum was not assessed: a partial sum would
 * read as a complete one.
 */
export function unfixedSummary(kernel: KernelInfo, which: "live" | "idle"): UnfixedSummary | null {
  const kernels = kernel.installed.filter((k) =>
    which === "live" ? k.running !== false : k.running === false,
  );
  if (kernels.length === 0) return { total: 0, noFix: 0, elsewhere: [] };
  if (kernels.some((k) => k.noFix === null || k.fixedElsewhere === null)) return null;
  let noFix = 0;
  const elsewhere = new Map<string, number>();
  for (const k of kernels) {
    noFix += k.noFix ?? 0;
    for (const [release, n] of Object.entries(k.fixedElsewhere ?? {})) {
      elsewhere.set(release, (elsewhere.get(release) ?? 0) + n);
    }
  }
  const ordered = [...elsewhere.entries()].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
  return { total: noFix + ordered.reduce((sum, [, n]) => sum + n, 0), noFix, elsewhere: ordered };
}

/**
 * The command that removes kernels nothing runs, or null where there is none.
 *
 * Each keeps the running kernel and the newest: apt's autoremove (which also
 * offers any other package nothing depends on, so it is shown with a note to
 * review), dnf's --oldinstallonly, zypper's purge-kernels. Alpine and Arch
 * replace the kernel in place on upgrade, so there is nothing old to remove.
 */
export function oldKernelsCommand(
  platform: Platform | undefined,
  osName: string | undefined,
  packageIdentifier: string | null,
): string | null {
  switch (getDistroTooling(platform, osName, packageIdentifier).family) {
    case "debian":
      return "sudo apt autoremove --purge";
    case "rhel":
      return "sudo dnf remove --oldinstallonly";
    case "suse":
      return "sudo zypper purge-kernels";
    default:
      return null;
  }
}
