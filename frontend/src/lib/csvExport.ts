/**
 * RFC 4180 compliant CSV generator and browser download utility.
 *
 * Backs the exports offered from the fleet overview, the machine drill-down
 * and the discovery view (Req 8.8).
 */

import type {
  CveFinding,
  DiscoveredHost,
  MachineSummary,
} from "../types";
import { exploitStatus } from "./intel";

/**
 * What a cell says when the system never answered the question (Req 10.10).
 *
 * A spreadsheet has no tooltip and no dimmed styling, so the dashboard's
 * quieter treatments of "unknown" do not survive the export. The word has to.
 */
const NOT_ASSESSED = "not assessed";
const NOT_CHECKED = "not checked";

/** Three states of exploitation knowledge, as a cell (Req 8.10). */
function exploitCell(finding: CveFinding): string {
  const status = exploitStatus(finding);
  if (status === "exploited") return "yes";
  if (status === "not-exploited") return "no";
  return NOT_CHECKED;
}

/** A count that may not have been assessed, as a cell (Req 18.6). */
function countCell(value: number | null | undefined): number | string {
  return value === null || value === undefined ? NOT_ASSESSED : value;
}

/**
 * Characters that make Excel, LibreOffice and Sheets treat a cell as a formula
 * rather than as text, when they lead the cell (Req 8.9).
 *
 * A tab and a carriage return are in the list because both spreadsheets and
 * this file's own quoting can leave them at the start of a parsed cell, where
 * they are stripped and whatever follows -- `=cmd|...` -- leads instead.
 */
const FORMULA_LEADS = ["=", "+", "-", "@", "\t", "\r"];

/**
 * Escape a single cell value for CSV (RFC 4180), neutralising formulas (Req 8.9).
 *
 * RFC 4180 is about parsing, not about what the parser then does with the
 * value, so quoting alone is no defence: a cell reading
 * `=HYPERLINK("http://...")` opens as a live formula. The values at risk are
 * exactly the ones the operator did not write -- a remediation note pasted from
 * a ticket, a package identifier read off a scanned host, a reverse-DNS
 * hostname from a swept subnet -- and this tool is pointed at hosts nobody
 * trusts by definition.
 *
 * A leading apostrophe is the standard neutraliser: spreadsheets read it as
 * "the rest is text" and hide it, though a plain-text viewer and some importers
 * show it. That cost is worth paying; the alternative is that opening an export
 * runs something. Numbers are exempt, so a CVSS score or a count is never
 * touched and a negative number stays negative.
 */
export function escapeCsvCell(val: unknown): string {
  if (val === null || val === undefined) {
    return "";
  }
  let str = String(val);
  if (typeof val !== "number" && FORMULA_LEADS.includes(str.charAt(0))) {
    str = `'${str}`;
  }
  if (str.includes(",") || str.includes('"') || str.includes("\n") || str.includes("\r")) {
    return `"${str.replace(/"/g, '""')}"`;
  }
  return str;
}

/** Convert a 2D array of cells into a CSV string with CRLF line endings. */
export function toCsvString(headers: string[], rows: (string | number | boolean | null | undefined)[][]): string {
  const headerLine = headers.map(escapeCsvCell).join(",");
  const rowLines = rows.map((row) => row.map(escapeCsvCell).join(","));
  return [headerLine, ...rowLines].join("\r\n");
}

/** Trigger a browser file download for a CSV string. */
export function downloadCsv(filename: string, csvContent: string): void {
  const blob = new Blob([csvContent], { type: "text/csv;charset=utf-8;" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.setAttribute("href", url);
  link.setAttribute("download", filename);
  link.style.visibility = "hidden";
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
  URL.revokeObjectURL(url);
}

/** Format a current timestamp for filenames (e.g. 2026-09-01_00-10). */
function getTimestampStr(): string {
  const now = new Date();
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${now.getFullYear()}-${pad(now.getMonth() + 1)}-${pad(now.getDate())}_${pad(now.getHours())}${pad(now.getMinutes())}`;
}

// --------------------------------------------------------------------------- //
// Specialized View Exporters
// --------------------------------------------------------------------------- //

/**
 * Export Fleet Overview machines to CSV (Req 8.8, 8.10).
 *
 * Carries when each host was scanned and whether its counts are complete. A
 * sheet of counts with neither is undatable: month-old numbers read as current,
 * and an undercount from an unreachable advisory source reads as a clean host.
 *
 * ``intelUsable`` is whether any threat-intel feed has loaded. The fleet view
 * draws a dash in the exploited column without one; the export wrote 0, which
 * in a spreadsheet with no tooltip is a claim that every host is clear.
 */
export function exportFleetCsv(
  machines: MachineSummary[],
  options: { intelUsable?: boolean } = {},
): void {
  const { intelUsable = true } = options;
  const headers = [
    "Machine ID",
    "Hostname",
    "Platform",
    "Last Scan Status",
    "Last Scanned",
    "Counts Complete",
    "Critical CVEs",
    "Unscored CVEs",
    "High CVEs",
    "Medium CVEs",
    "Low CVEs",
    "Total Findings",
    "Exploited (KEV)",
    "New Findings",
    "Resolved Findings",
  ];

  const rows = machines.map((m) => {
    const total =
      m.cveCounts.critical +
      m.cveCounts.unscored +
      m.cveCounts.high +
      m.cveCounts.medium +
      m.cveCounts.low;
    return [
      m.machineId,
      m.hostname,
      m.platform,
      // The backend always sends a status, "never_scanned" included, so there
      // is nothing to fall back to -- a default here would invent a status.
      m.lastScanStatus,
      m.lastScannedAt ?? "never",
      // False means an advisory source was unreachable, so the counts beside
      // this are a floor rather than a total (Req 10.1). A host never scanned
      // has no counts to be complete: its flag is the backend's default, not
      // an answer, and "yes" would vouch for zeros nobody measured (Req 8.10).
      m.lastScannedAt === null
        ? NOT_ASSESSED
        : m.lastScanSourcesOk
          ? "yes"
          : "no",
      // A host nobody has scanned has no counts, and a row of zeros beside
      // "never" read as a clean host rather than an unmeasured one (Req 8.10).
      ...(m.lastScannedAt === null
        ? [
            NOT_ASSESSED,
            NOT_ASSESSED,
            NOT_ASSESSED,
            NOT_ASSESSED,
            NOT_ASSESSED,
            NOT_ASSESSED,
          ]
        : [
            m.cveCounts.critical,
            m.cveCounts.unscored,
            m.cveCounts.high,
            m.cveCounts.medium,
            m.cveCounts.low,
            total,
          ]),
      // Counting only what a feed confirmed: with no feed loaded, zero is the
      // absence of an answer rather than a clean host (Req 8.10).
      intelUsable ? m.kevCount : NOT_CHECKED,
      // Null is "not assessed" -- a baseline, a partial scan, or no successful
      // scan yet -- and a zero here would be a different claim (Req 18.6).
      countCell(m.lastScanNew),
      countCell(m.lastScanResolved),
    ];
  });

  const csv = toCsvString(headers, rows);
  downloadCsv(`cvedeck-fleet-${getTimestampStr()}.csv`, csv);
}

/**
 * Export Machine Findings / Drill-Down to CSV (Req 8.8, 8.10).
 *
 * Ordered identity, severity, exploitation, fix, impact, then provenance. The
 * export is how a finding reaches the people who will patch it, and it used to
 * arrive without a single exploitation signal -- no KEV listing, no EPSS, no
 * fix availability -- which left CVSS to stand in for urgency it cannot carry.
 *
 * EPSS is exported as its raw probability rather than through
 * `formatEpssScore`, because a spreadsheet column is for sorting and filtering
 * and "0.08%" sorts as text. The dashboard keeps the formatted view.
 */
export function exportFindingsCsv(
  hostname: string,
  findings: CveFinding[],
  options: { baseline?: boolean } = {},
): void {
  const headers = [
    "CVE ID",
    "Severity",
    "CVSS Score",
    "Package Identifier",
    "Exploited (KEV)",
    "KEV Due Date",
    "EPSS Score (0-1)",
    "EPSS Percentile (0-1)",
    "Fix Status",
    "Fixed Version",
    // Every installed binary of the finding's source; a fix upgrades them all.
    "Affected Packages",
    "Blast Radius",
    "Dependencies",
    "Depended On By (Reverse Deps)",
    "Remediation Status",
    "Remediation Note",
    "New",
    "First Seen",
  ];

  const rows = findings.map((f) => [
    f.cveId,
    f.severity,
    // An empty cell reads as zero in a spreadsheet; "not assessed" does not
    // (Req 8.10, 10.11).
    f.cvssScore ?? NOT_ASSESSED,
    f.packageIdentifier ?? "",
    exploitCell(f),
    f.kevDueDate ?? "",
    f.epssScore ?? NOT_CHECKED,
    f.epssPercentile ?? NOT_CHECKED,
    f.fixStatus ?? "unknown",
    f.fixedVersion ?? "",
    (f.affectedPackages ?? []).join("; "),
    f.blastRadius ?? NOT_ASSESSED,
    (f.dependencies ?? []).join("; "),
    (f.dependedOnBy ?? []).join("; "),
    // No record is the same state the view shows as open.
    f.remediationStatus ?? "open",
    f.remediationNote ?? "",
    // A baseline compared with nothing, so its findings are neither new nor
    // not new, and the backend's false for them is a default (Req 18.6).
    options.baseline ? NOT_ASSESSED : f.isNew ? "yes" : "no",
    f.firstSeenAt ?? "",
  ]);

  const sanitizedHost = hostname.replace(/[^a-zA-Z0-9_.-]/g, "_");
  const csv = toCsvString(headers, rows);
  downloadCsv(`cvedeck-findings-${sanitizedHost}-${getTimestampStr()}.csv`, csv);
}

/** Export Discovered Network Hosts to CSV. */
export function exportDiscoveryCsv(
  cidr: string,
  hosts: DiscoveredHost[],
): void {
  const headers = [
    "IP Address",
    "Hostname",
    "OS Guess",
    "Responds to Ping",
    "Open Ports",
    "Discovered Services",
    "Service Banners",
  ];

  const rows = hosts.map((h) => {
    const portsStr = h.openPorts.join("; ");
    const servicesStr = h.services
      .map((s) => `${s.protocol.toUpperCase()}:${s.port}${s.product ? ` (${s.product}${s.version ? `/${s.version}` : ""})` : ""}`)
      .join("; ");
    const bannersStr = h.services
      .filter((s) => s.banner)
      .map((s) => `[Port ${s.port}] ${s.banner}`)
      .join(" | ");

    return [
      h.ip,
      h.hostname,
      h.osGuess,
      // Three states: a host nobody could ping is not a host that ignored one.
      h.respondsToPing === null ? NOT_CHECKED : h.respondsToPing ? "Yes" : "No",
      portsStr,
      servicesStr,
      bannersStr,
    ];
  });

  const sanitizedCidr = cidr.replace(/[^a-zA-Z0-9_.-]/g, "_");
  const csv = toCsvString(headers, rows);
  downloadCsv(`cvedeck-discovery-${sanitizedCidr}-${getTimestampStr()}.csv`, csv);
}
