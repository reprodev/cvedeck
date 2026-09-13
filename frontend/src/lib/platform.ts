// Platform inference for a host found by network discovery (Req 8.7).
//
// This existed twice, in App.tsx and DiscoveryView.tsx, and the two copies
// disagreed:
//
//   - DiscoveryView treated port 445 as Windows. App.tsx did not consider 445
//     at all, and let an open port 22 force "linux" regardless of everything
//     else.
//
// So a Samba-on-Linux host, or a Windows box running OpenSSH, got one answer
// from the Discovery tab's Scan button and the other from typing the same IP
// into the scan form. Same host, same data, two answers.
//
// One implementation, with the precedence written down.

import type { DiscoveredHost, Platform } from "../types";

const LINUX_MARKERS = [
  "ubuntu",
  "debian",
  "linux",
  "openssh",
  "centos",
  "rhel",
  "red hat",
  "almalinux",
  "rocky",
  "alpine",
  "arch",
  "fedora",
  "suse",
  "raspbian",
  "oracle linux",
  "amazon linux",
];

const WINDOWS_MARKERS = [
  "windows",
  "microsoft",
  "iis",
  "ms-wbt-server",
  "msrpc",
];

/** Ports that only a Windows host normally exposes. */
const WINDOWS_ONLY_PORTS = [5985, 5986, 3389];

/**
 * Best-effort platform for a discovered host.
 *
 * Precedence, strongest evidence first:
 *
 *  1. An explicit banner naming an OS. A banner is a direct claim about what
 *     is running; a port number is only an inference from it.
 *  2. A Windows-only management port (WinRM, RDP) with no SSH.
 *  3. SSH, which is overwhelmingly Linux in practice but no longer *overrides*
 *     an explicit Windows banner the way the old App.tsx copy did.
 *
 * Port 445 (SMB) is deliberately NOT treated as a Windows signal: Samba is
 * ubiquitous on Linux file servers, and DiscoveryView's copy misclassified
 * every one of them.
 */
export function inferPlatform(host: DiscoveredHost): Platform {
  const haystack = [
    host.osGuess,
    ...host.services.map(
      (service) =>
        `${service.protocol} ${service.banner} ${service.product} ${service.extraInfo}`,
    ),
  ]
    .join(" ")
    .toLowerCase();

  const looksLinux = LINUX_MARKERS.some((marker) => haystack.includes(marker));
  const looksWindows = WINDOWS_MARKERS.some((marker) => haystack.includes(marker));

  // 1. Explicit banners. When both appear (a Linux host running a Windows
  //    emulator, or a mixed reverse proxy) prefer Windows: getting a Linux host
  //    wrong costs a failed SSH attempt, while getting a Windows host wrong
  //    means offering apt commands for it.
  if (looksWindows && !looksLinux) return "windows";
  if (looksLinux && !looksWindows) return "linux";
  if (looksWindows && looksLinux) return "windows";

  // 2. Management ports, when nothing was named.
  const hasSsh = host.openPorts.includes(22);
  const hasWindowsPort = WINDOWS_ONLY_PORTS.some((port) =>
    host.openPorts.includes(port),
  );
  if (hasWindowsPort && !hasSsh) return "windows";

  // 3. SSH, or the default. Linux is the safer default here: the scan is
  //    read-only either way, and the Linux collector is the mature path.
  return "linux";
}

/** Map of hostname/IP (lowercased) to platform, for auto-detect in the scan form. */
export function buildKnownHostMap(
  machines: { hostname: string; platform: Platform }[],
  discoveredHosts: DiscoveredHost[],
): Map<string, Platform> {
  const map = new Map<string, Platform>();

  // Discovery first, so a machine already in the fleet -- whose platform was
  // confirmed by an actual credentialed scan -- overrides an inference.
  for (const host of discoveredHosts) {
    const platform = inferPlatform(host);
    map.set(host.ip.toLowerCase(), platform);
    if (host.hostname) {
      map.set(host.hostname.toLowerCase(), platform);
    }
  }
  for (const machine of machines) {
    map.set(machine.hostname.toLowerCase(), machine.platform);
  }

  return map;
}

// ---------------------------------------------------------------------------
// Which platforms can actually be scanned (Req 10.8).
//
// Windows hosts can be discovered and enrolled, and the backend can collect
// their inventory over WinRM -- but it cannot yet match that inventory against
// vulnerability data. A Windows scan would therefore finish with zero findings,
// which is indistinguishable from a clean host. The backend refuses Windows
// scans outright; the dashboard does not offer them, so nobody fills in a form
// only to be told no.
//
// Kept here, beside platform inference, so every view asks one question instead
// of re-deriving the answer.

/** Whether CveDeck can scan hosts on this platform today. */
export function isScannable(platform: Platform): boolean {
  return platform === "linux";
}

/** Shown wherever a Windows scan is withheld. Matches the backend's reason. */
export const WINDOWS_SCAN_UNSUPPORTED =
  "Windows scanning is not supported yet. CveDeck can enrol Windows hosts, but " +
  "cannot match Windows software or updates against vulnerability data, so a " +
  "scan would report the host as clean without having checked it.";
