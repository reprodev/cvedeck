// Per-distribution remediation command generation (Req 14.1, 14.2, 14.3).
//
// Commands are generated for display only and are never executed against a
// target (Req 14.6, extending Req 4.5).
//
// This logic previously lived inside MachineDrillDownView and inferred the
// distribution from the *package identifier string*, with substring matching.
// That produced two classes of bug:
//
//   1. `low.includes("ol")` matched `tool`, `tools`, `console`, `symbol`,
//      `protocol`, and `golang`, so a Debian package named `python3-tools`
//      routed to `dnf`. `low.includes("arch")` matched `libarchive`, `noarch`,
//      and `search` and routed Debian packages to `pacman`.
//   2. A Windows host has no Linux ecosystem prefix at all, so every one of its
//      findings fell through to the default branch and the UI confidently
//      offered `sudo apt install --only-upgrade <pkg>`.
//
// The fix is to derive tooling from the *machine* -- its platform and reported
// OS (Req 14.1) -- and to match on the ecosystem prefix rather than anywhere
// in the
// string. The package identifier is only ever used for the package name.
//
// Nothing here executes anything. Commands are generated for the user to
// review and run themselves; remediation is manual by design (AGENTS.md).

import type { CveFinding, Platform } from "../types";

export type DistroFamily =
  | "debian"
  | "rhel"
  | "suse"
  | "alpine"
  | "arch"
  | "windows"
  | "unknown";

export interface DistroTooling {
  family: DistroFamily;
  /** Human-readable name of the package manager ("apt", "dnf", ...). */
  manager: string;
  /** Display label for the distribution family. */
  label: string;
  /** Command to upgrade a single package to its fixed version. */
  updateCmd: (pkg: string) => string;
  /** Command to remove a package outright, when no fix is available. */
  purgeCmd: (pkg: string) => string;
  /** Command to check what updates are pending for a package. */
  checkUpdateCmd: (pkg: string) => string;
  /** Whether Ubuntu-specific advice (Ubuntu Pro / ESM) applies. */
  isUbuntu: boolean;
}

const TOOLING: Record<Exclude<DistroFamily, "unknown">, DistroTooling> = {
  debian: {
    family: "debian",
    manager: "apt",
    label: "Debian / Ubuntu",
    updateCmd: (p) => `sudo apt update && sudo apt install --only-upgrade ${p}`,
    purgeCmd: (p) => `sudo apt remove --purge ${p}`,
    checkUpdateCmd: (p) => `apt list --upgradable 2>/dev/null | grep '^${p}/'`,
    isUbuntu: false,
  },
  rhel: {
    family: "rhel",
    manager: "dnf",
    label: "RHEL / Fedora / Rocky / Alma",
    updateCmd: (p) => `sudo dnf upgrade -y ${p}`,
    purgeCmd: (p) => `sudo dnf remove -y ${p}`,
    checkUpdateCmd: (p) => `dnf check-update ${p}`,
    isUbuntu: false,
  },
  suse: {
    family: "suse",
    manager: "zypper",
    label: "openSUSE / SLES",
    updateCmd: (p) => `sudo zypper update -y ${p}`,
    purgeCmd: (p) => `sudo zypper remove -y ${p}`,
    checkUpdateCmd: (p) => `zypper list-updates | grep ' ${p} '`,
    isUbuntu: false,
  },
  alpine: {
    family: "alpine",
    manager: "apk",
    label: "Alpine",
    updateCmd: (p) => `sudo apk update && sudo apk upgrade ${p}`,
    purgeCmd: (p) => `sudo apk del ${p}`,
    checkUpdateCmd: (p) => `apk version ${p}`,
    isUbuntu: false,
  },
  arch: {
    family: "arch",
    manager: "pacman",
    label: "Arch / Manjaro",
    // Arch has no supported single-package upgrade: partial upgrades are
    // explicitly unsupported upstream and routinely break the system, so the
    // correct advice is a full system upgrade.
    updateCmd: () => `sudo pacman -Syu`,
    purgeCmd: (p) => `sudo pacman -Rns ${p}`,
    checkUpdateCmd: (p) => `pacman -Qu ${p}`,
    isUbuntu: false,
  },
  windows: {
    family: "windows",
    manager: "winget",
    label: "Windows",
    updateCmd: (p) => `winget upgrade --id ${p} --accept-source-agreements`,
    purgeCmd: (p) => `winget uninstall --id ${p}`,
    checkUpdateCmd: () => `Get-HotFix | Sort-Object -Property InstalledOn -Descending`,
    isUbuntu: false,
  },
};

const UNKNOWN_TOOLING: DistroTooling = {
  family: "unknown",
  manager: "your package manager",
  label: "Unknown distribution",
  // Deliberately not a guess. Handing a user a confidently wrong command is
  // worse than telling them we do not know which one applies.
  updateCmd: (p) => `# Unknown distribution -- upgrade '${p}' with your package manager`,
  purgeCmd: (p) => `# Unknown distribution -- remove '${p}' with your package manager`,
  checkUpdateCmd: (p) => `# Unknown distribution -- check updates for '${p}'`,
  isUbuntu: false,
};

/** Ecosystem prefixes, matched at the START of an identifier, not anywhere in it. */
const ECOSYSTEM_FAMILIES: ReadonlyArray<[RegExp, DistroFamily]> = [
  [/^ubuntu\b/, "debian"],
  [/^(debian|raspbian|deb)\b/, "debian"],
  [/^(red\s?hat|rhel|centos|almalinux|rocky|fedora|oracle|amazon|rpm)\b/, "rhel"],
  [/^(opensuse|suse|sles|zypper)\b/, "suse"],
  [/^(alpine|wolfi|chainguard|apk)\b/, "alpine"],
  [/^(arch|manjaro|pacman)\b/, "arch"],
  [/^windows\b/, "windows"],
];

// OS name patterns, used when the ecosystem prefix is absent or unhelpful.
//
// Note the optional suffixes: distribution names are frequently written as one
// word ("AlmaLinux", "openSUSE Leap"), so a bare `\balma\b` never matches. The
// alternation is still anchored on word boundaries, which is what keeps a
// package called `libarchive` from being mistaken for Arch.
const OS_NAME_FAMILIES: ReadonlyArray<[RegExp, DistroFamily]> = [
  [/\bubuntu\b/, "debian"],
  [/\b(debian|raspbian|pop!?_os|linux mint)\b/, "debian"],
  [
    /\b(red\s?hat|rhel|centos|alma(linux)?|rocky(\s?linux)?|fedora|oracle\s?linux|amazon\s?linux|scientific\s?linux)\b/,
    "rhel",
  ],
  [/\b(opensuse(\s?\w+)?|suse|sles|sled)\b/, "suse"],
  [/\b(alpine(\s?linux)?|wolfi|chainguard)\b/, "alpine"],
  [/\b(arch(\s?linux)?|manjaro|endeavour\w*)\b/, "arch"],
  [/\bwindows\b/, "windows"],
];

/**
 * Identify the distribution family for a machine.
 *
 * `platform` and `osName` come from the machine; `packageIdentifier` is only
 * consulted as a last resort, and then only against its ecosystem prefix.
 */
export function detectDistroFamily(
  platform: Platform | undefined,
  osName: string | undefined,
  packageIdentifier?: string | null,
): DistroFamily {
  if (platform === "windows") return "windows";

  const os = (osName ?? "").toLowerCase();
  for (const [pattern, family] of OS_NAME_FAMILIES) {
    if (pattern.test(os)) return family;
  }

  // Fall back to the finding's ecosystem prefix. Anchored so a package *named*
  // `libarchive` or `python3-tools` cannot be mistaken for a distribution.
  const identifier = (packageIdentifier ?? "").trim().toLowerCase();
  if (identifier) {
    for (const [pattern, family] of ECOSYSTEM_FAMILIES) {
      if (pattern.test(identifier)) return family;
    }
  }

  return "unknown";
}

/** Remediation tooling for a machine. */
export function getDistroTooling(
  platform: Platform | undefined,
  osName: string | undefined,
  packageIdentifier?: string | null,
): DistroTooling {
  const family = detectDistroFamily(platform, osName, packageIdentifier);
  if (family === "unknown") return UNKNOWN_TOOLING;
  const base = TOOLING[family];
  if (family === "debian" && /\bubuntu\b/i.test(osName ?? "")) {
    return { ...base, label: "Ubuntu", isUbuntu: true };
  }
  return base;
}

/**
 * Extract the bare package name from an identifier.
 *
 * Prefer the backend's `packageName` field; this exists for findings stored
 * before that field was added.
 */
export function parsePackageName(packageIdentifier: string | null): string | null {
  if (!packageIdentifier || !packageIdentifier.trim()) return null;
  let token = packageIdentifier.trim().split(/\s+/)[0];
  if (token.includes(":")) token = token.slice(token.lastIndexOf(":") + 1);
  if (token.includes("@")) token = token.slice(0, token.indexOf("@"));
  return token.trim() || null;
}

/** The package a finding affects, preferring the structured field. */
export function findingPackageName(finding: CveFinding): string | null {
  return finding.packageName ?? parsePackageName(finding.packageIdentifier);
}

/**
 * Whether an actionable fix exists for a finding.
 *
 * Uses the backend's structured `hasFix` field rather than the wording of a
 * display string (Req 14.5), falling back to the legacy prose check only for
 * findings served by an older backend.
 */
export function hasFix(finding: CveFinding): boolean {
  if (typeof finding.hasFix === "boolean") return finding.hasFix;
  return Boolean(finding.packageIdentifier?.includes("fixed in"));
}

/**
 * Build one script upgrading every fixable package on a host.
 *
 * Packages are deduplicated: a host commonly has a dozen CVEs against one
 * `openssl`, and pasting a dozen identical upgrade lines is noise. Sorted so
 * the output is stable and diffable.
 */
export function buildBulkFixScript(
  findings: CveFinding[],
  platform: Platform | undefined,
  osName: string | undefined,
): string {
  const fixable = findings.filter(hasFix);
  const packages = [
    ...new Set(
      fixable
        .map((finding) => findingPackageName(finding))
        .filter((name): name is string => Boolean(name)),
    ),
  ].sort();

  const tooling = getDistroTooling(platform, osName, fixable[0]?.packageIdentifier);
  const header = [
    `# Remediation plan for ${osName ?? "this host"}`,
    `# ${packages.length} package(s) with published fixes, ` +
      `covering ${fixable.length} CVE(s).`,
    "# Review before running. Nothing here has been executed for you.",
    "",
  ];

  if (packages.length === 0) {
    return [
      ...header,
      "# No findings on this host have a published fix yet.",
    ].join("\n");
  }

  if (tooling.family === "arch") {
    // Partial upgrades are unsupported on Arch, so listing packages
    // individually would be actively harmful advice.
    return [...header, tooling.updateCmd(""), ""].join("\n");
  }

  if (tooling.family === "debian") {
    return [
      ...header,
      "sudo apt update",
      `sudo apt install --only-upgrade ${packages.join(" ")}`,
      "",
    ].join("\n");
  }

  return [...header, ...packages.map((pkg) => tooling.updateCmd(pkg)), ""].join("\n");
}
