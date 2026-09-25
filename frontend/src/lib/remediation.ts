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

import type { CveFinding, FixStatus, Platform } from "../types";

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
  /**
   * Command to upgrade packages to their fixed versions. A list when a finding
   * covers several binaries of one source (Req 2.8): upgrading libc-bin alone
   * leaves libc6 vulnerable.
   */
  updateCmd: (pkg: Pkgs) => string;
  /** Command to remove packages outright, when no fix is available. */
  purgeCmd: (pkg: Pkgs) => string;
  /** Command to check what updates are pending for packages. */
  checkUpdateCmd: (pkg: Pkgs) => string;
  /** Whether Ubuntu-specific advice (Ubuntu Pro / ESM) applies. */
  isUbuntu: boolean;
}

// Package names come off the scanned host, and a scanned host is not trusted
// (Req 14.10). These commands are copied into a root shell, so every name is
// quoted before it reaches one -- the same rule as Python's shlex.quote: a name
// made only of characters no shell treats specially is left bare, so an
// ordinary command reads exactly as it always has, and anything else is
// single-quoted, which a POSIX shell takes literally.
const SHELL_SAFE = /^[A-Za-z0-9@%+=:,./_-]+$/;

/** One package name, or every binary a finding covers. */
export type Pkgs = string | readonly string[];

function asList(pkgs: Pkgs): string[] {
  return typeof pkgs === "string" ? [pkgs] : [...pkgs];
}

/** Each name as its own quoted shell word, space-separated. */
function shellWords(pkgs: Pkgs): string {
  return asList(pkgs).map(shellQuote).join(" ");
}

// No package manager accepts a name containing a control character, so such a
// name is not a package -- it is an attempt. Quoted, a newline is still one
// word to a shell, but pasted into a terminal it reads as two commands, so each
// one becomes "?" and the command matches nothing.
// eslint-disable-next-line no-control-regex
const CONTROL = /[\u0000-\u001f\u007f\u2028\u2029]/g;

/** Quote `value` as one POSIX shell word. */
export function shellQuote(value: string): string {
  const printable = value.replace(CONTROL, "?");
  if (printable !== "" && SHELL_SAFE.test(printable)) return printable;
  return `'${printable.replace(/'/g, `'"'"'`)}'`;
}

/**
 * Quote `value` as one PowerShell word.
 *
 * Inside single quotes PowerShell expands nothing, and a quote is escaped by
 * doubling it -- including the typographic quotes it also accepts as quotes.
 */
export function powershellQuote(value: string): string {
  const printable = value.replace(CONTROL, "?");
  if (printable !== "" && SHELL_SAFE.test(printable)) return printable;
  return `'${printable.replace(/(['\u2018\u2019\u201a\u201b])/g, "$1$1")}'`;
}

/**
 * Make host-derived text safe to embed in a `#` comment line.
 *
 * A comment ends at a newline, so text carrying one would continue on the next
 * line as a command. Every line break and other control character becomes a
 * space.
 */
export function commentSafe(text: string): string {
  return text.replace(CONTROL, " ");
}

const TOOLING: Record<Exclude<DistroFamily, "unknown">, DistroTooling> = {
  debian: {
    family: "debian",
    manager: "apt",
    label: "Debian / Ubuntu",
    updateCmd: (p) => `sudo apt update && sudo apt install --only-upgrade ${shellWords(p)}`,
    purgeCmd: (p) => `sudo apt remove --purge ${shellWords(p)}`,
    // apt filters the listing by name itself, which leaves no grep pattern to
    // splice a name into.
    checkUpdateCmd: (p) => `apt list --upgradable ${shellWords(p)} 2>/dev/null`,
    isUbuntu: false,
  },
  rhel: {
    family: "rhel",
    manager: "dnf",
    label: "RHEL / Fedora / Rocky / Alma",
    updateCmd: (p) => `sudo dnf upgrade -y ${shellWords(p)}`,
    purgeCmd: (p) => `sudo dnf remove -y ${shellWords(p)}`,
    checkUpdateCmd: (p) => `dnf check-update ${shellWords(p)}`,
    isUbuntu: false,
  },
  suse: {
    family: "suse",
    manager: "zypper",
    label: "openSUSE / SLES",
    updateCmd: (p) => `sudo zypper update -y ${shellWords(p)}`,
    purgeCmd: (p) => `sudo zypper remove -y ${shellWords(p)}`,
    // -F: each name is a literal, never a pattern.
    checkUpdateCmd: (p) =>
      `zypper list-updates | grep -F ${asList(p).map((n) => `-e ${shellQuote(` ${n} `)}`).join(" ")}`,
    isUbuntu: false,
  },
  alpine: {
    family: "alpine",
    manager: "apk",
    label: "Alpine",
    updateCmd: (p) => `sudo apk update && sudo apk upgrade ${shellWords(p)}`,
    purgeCmd: (p) => `sudo apk del ${shellWords(p)}`,
    checkUpdateCmd: (p) => `apk version ${shellWords(p)}`,
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
    purgeCmd: (p) => `sudo pacman -Rns ${shellWords(p)}`,
    checkUpdateCmd: (p) => `pacman -Qu ${shellWords(p)}`,
    isUbuntu: false,
  },
  windows: {
    family: "windows",
    manager: "winget",
    label: "Windows",
    // winget takes one id; Windows packages have no source grouping anyway.
    updateCmd: (p) => `winget upgrade --id ${powershellQuote(asList(p)[0] ?? "")} --accept-source-agreements`,
    purgeCmd: (p) => `winget uninstall --id ${powershellQuote(asList(p)[0] ?? "")}`,
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
  updateCmd: (p) => `# Unknown distribution -- upgrade ${commentSafe(shellWords(p))} with your package manager`,
  purgeCmd: (p) => `# Unknown distribution -- remove ${commentSafe(shellWords(p))} with your package manager`,
  checkUpdateCmd: (p) => `# Unknown distribution -- check updates for ${commentSafe(shellWords(p))}`,
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
 * Prefer the backend's `packageName` field; this exists for findings served
 * by an older backend, and must agree with backend/app/package_identifier.py.
 *
 * Identifiers are `<ecosystem>:<name>@<version>`, and both the ecosystem
 * (`Debian:13`, `Ubuntu:22.04:LTS`) and the version (an epoch, `1:5.2`) can
 * contain colons, and the `Red Hat` ecosystem contains a space. So the version is removed first, from the last `@`, and the
 * name is what follows the last remaining colon. Doing either step the other
 * way round produced `13:openssl` or `5.2`, and a fix command apt rejects.
 */
export function parsePackageName(packageIdentifier: string | null): string | null {
  if (!packageIdentifier || !packageIdentifier.trim()) return null;
  let token = packageIdentifier.trim();
  // Cut the "(fixed in ...)" note at its marker, not at the first space:
  // "Red Hat" is an ecosystem, and splitting on whitespace reduced it to "Red".
  const note = token.indexOf(" (");
  if (note !== -1) token = token.slice(0, note);
  const at = token.lastIndexOf("@");
  // An "@" straight after the ecosystem's colon is an npm scope, not a version.
  if (at > 0 && token[at - 1] !== ":") token = token.slice(0, at);
  const name = token.slice(token.lastIndexOf(":") + 1).trim();
  return name || null;
}

/** The package a finding affects, preferring the structured field. */
export function findingPackageName(finding: CveFinding): string | null {
  return finding.packageName ?? parsePackageName(finding.packageIdentifier);
}

/**
 * Every installed package a fix for these findings must upgrade (Req 2.8).
 *
 * A finding is reported once per source package, against one representative
 * binary; the server lists every installed binary of that source. Falls back
 * to the representative alone for a response from before 0.8.15.
 */
export function upgradeTargets(findings: readonly CveFinding[]): string[] {
  const names = new Set<string>();
  for (const finding of findings) {
    const affected = finding.affectedPackages ?? [];
    if (affected.length > 0) {
      affected.forEach((name) => names.add(name));
    } else {
      const name = findingPackageName(finding);
      if (name) names.add(name);
    }
  }
  return [...names].sort();
}

/** Where a finding's fix is, and which release has it (Req 14.7, 14.8). */
export interface FixInfo {
  status: FixStatus;
  /** The release with the fix, for "newer_release" and "upstream". */
  release: string | null;
  version: string | null;
}

const ELSEWHERE_NOTE = /\(no fix in (.+?); fixed only in (.+): (\S+)\)\s*$/;
const UPSTREAM_NOTE = /\(not confirmed for this release; upstream fix in (.+): (\S+)\)\s*$/;
const AVAILABLE_NOTE = /\(fixed in ([^)\s]+)\)\s*$/;

/**
 * Where the fix for a finding is.
 *
 * Prefers the backend's structured fields; reads the matcher's note for findings
 * served by an older backend. Must agree with parse_fix in
 * backend/app/package_identifier.py.
 */
export function findingFix(finding: CveFinding): FixInfo {
  if (finding.fixStatus) {
    return {
      status: finding.fixStatus,
      release: finding.fixRelease ?? null,
      version:
        finding.fixStatus === "available"
          ? finding.fixedVersion ?? null
          : finding.fixReleaseVersion ?? null,
    };
  }
  const text = finding.packageIdentifier ?? "";
  let m = AVAILABLE_NOTE.exec(text);
  if (m) return { status: "available", release: null, version: m[1] };
  m = ELSEWHERE_NOTE.exec(text);
  if (m) return { status: "newer_release", release: m[2], version: m[3] };
  m = UPSTREAM_NOTE.exec(text);
  if (m) return { status: "upstream", release: m[1], version: m[2] };
  if (typeof finding.hasFix === "boolean" && finding.hasFix) {
    return { status: "available", release: null, version: finding.fixedVersion ?? null };
  }
  return { status: "none", release: null, version: null };
}

/**
 * Whether an actionable fix exists for a finding: one this host's own release
 * ships, so a package upgrade installs it.
 *
 * Uses the backend's structured fields rather than the wording of a display
 * string (Req 14.5). A fix that only a newer release has is not actionable, and
 * treating it as one is what put Debian 14 fixes into a Debian 13 host's plan.
 */
export function hasFix(finding: CveFinding): boolean {
  if (finding.fixStatus) return finding.fixStatus === "available";
  if (typeof finding.hasFix === "boolean") return finding.hasFix;
  return findingFix(finding).status === "available";
}

/** A short label for a fix that is not installable here, or null. */
export function fixElsewhereLabel(fix: FixInfo): string | null {
  if (fix.status === "newer_release" && fix.release) return `Fixed only in ${fix.release}`;
  if (fix.status === "upstream" && fix.release) return `Upstream fix in ${fix.release}`;
  return null;
}

/** The longer explanation for the same, for a tooltip or a detail view. */
export function fixElsewhereExplanation(fix: FixInfo): string | null {
  const version = fix.version ? ` (${fix.version})` : "";
  if (fix.status === "newer_release" && fix.release) {
    return (
      `${fix.release} has a fix${version}, but this host's release does not. ` +
      `No package upgrade here can install it: upgrading the distribution will, ` +
      `or a future update to this release.`
    );
  }
  if (fix.status === "upstream" && fix.release) {
    return (
      `${fix.release} has a fix${version}, but this host's release could not be ` +
      `matched to the advisory, so it is not known whether your distribution ` +
      `ships it yet. Check with your package manager, and re-scan after updating.`
    );
  }
  return null;
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
  // Every binary of every fixable source, not just each representative.
  const packages = upgradeTargets(fixable);

  const tooling = getDistroTooling(platform, osName, fixable[0]?.packageIdentifier);
  const header = [
    `# Remediation plan for ${commentSafe(osName ?? "this host")}`,
    `# ${packages.length} package(s) with fixes in this host's release, ` +
      `covering ${fixable.length} CVE(s).`,
    "# Review before running. Nothing here has been executed for you.",
    "",
  ];

  // What the plan cannot fix, said up front, so re-running it and re-scanning
  // does not look like the plan failed (Req 14.8).
  const elsewhere = elsewhereSummary(findings);
  const commands: string[] = [];
  if (packages.length === 0) {
    commands.push("# No findings on this host have a fix in its own release yet.");
  } else if (tooling.family === "arch") {
    // Partial upgrades are unsupported on Arch, so listing packages
    // individually would be actively harmful advice.
    commands.push(tooling.updateCmd(""));
  } else if (tooling.family === "debian") {
    commands.push(
      "sudo apt update",
      `sudo apt install --only-upgrade ${packages.map(shellQuote).join(" ")}`,
    );
  } else {
    commands.push(...packages.map((pkg) => tooling.updateCmd(pkg)));
  }

  return [...header, ...commands, ...elsewhere, ""].join("\n");
}

/** Comment lines describing the findings a package upgrade cannot clear. */
function elsewhereSummary(findings: CveFinding[]): string[] {
  const byRelease = (status: FixStatus) => {
    const groups = new Map<string, { cves: number; packages: Set<string> }>();
    for (const finding of findings) {
      const fix = findingFix(finding);
      if (fix.status !== status || !fix.release) continue;
      const group = groups.get(fix.release) ?? { cves: 0, packages: new Set<string>() };
      group.cves += 1;
      const pkg = findingPackageName(finding);
      if (pkg) group.packages.add(pkg);
      groups.set(fix.release, group);
    }
    return [...groups.entries()].sort(([a], [b]) => a.localeCompare(b));
  };

  const lines: string[] = [];
  const newer = byRelease("newer_release");
  if (newer.length > 0) {
    lines.push("", "# Not fixable on this release:");
    for (const [release, group] of newer) {
      lines.push(
        `# ${group.cves} CVE(s) in ${group.packages.size} package(s) are fixed only in ${commentSafe(release)}.`,
        `#   ${commentSafe([...group.packages].sort().join(" "))}`,
      );
    }
    lines.push(
      "# The commands above cannot install those fixes, and re-scanning will still",
      "# show them. Upgrading the distribution clears them, or they clear when this",
      "# release publishes the fix.",
    );
  }
  const upstream = byRelease("upstream");
  if (upstream.length > 0) {
    lines.push("", "# Fixed upstream, not confirmed for this release:");
    for (const [release, group] of upstream) {
      lines.push(
        `# ${group.cves} CVE(s) in ${group.packages.size} package(s) have a fix in ${commentSafe(release)}.`,
        `#   ${commentSafe([...group.packages].sort().join(" "))}`,
      );
    }
    lines.push(
      "# Your distribution may not ship those fixes yet. Update normally, then",
      "# re-scan to see which cleared.",
    );
  }
  return lines;
}
