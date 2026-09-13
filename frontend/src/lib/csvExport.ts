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

/** Escape a single cell value for CSV (RFC 4180). */
export function escapeCsvCell(val: unknown): string {
  if (val === null || val === undefined) {
    return "";
  }
  const str = String(val);
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

/** Export Fleet Overview machines to CSV. */
export function exportFleetCsv(machines: MachineSummary[]): void {
  const headers = [
    "Machine ID",
    "Hostname",
    "Platform",
    "Last Scan Status",
    "Critical CVEs",
    "High CVEs",
    "Medium CVEs",
    "Low CVEs",
    "Total Findings",
  ];

  const rows = machines.map((m) => {
    const total =
      m.cveCounts.critical +
      m.cveCounts.high +
      m.cveCounts.medium +
      m.cveCounts.low;
    return [
      m.machineId,
      m.hostname,
      m.platform,
      m.lastScanStatus || "discovered",
      m.cveCounts.critical,
      m.cveCounts.high,
      m.cveCounts.medium,
      m.cveCounts.low,
      total,
    ];
  });

  const csv = toCsvString(headers, rows);
  downloadCsv(`cvedeck-fleet-${getTimestampStr()}.csv`, csv);
}

/** Export Machine Findings / Drill-Down to CSV. */
export function exportFindingsCsv(
  hostname: string,
  findings: CveFinding[],
): void {
  const headers = [
    "CVE ID",
    "Severity",
    "CVSS Score",
    "Package Identifier",
    "Remediation Status",
    "Remediation Note",
    "Blast Radius",
    "Dependencies",
    "Depended On By (Reverse Deps)",
  ];

  const rows = findings.map((f) => [
    f.cveId,
    f.severity,
    f.cvssScore,
    f.packageIdentifier || "",
    f.remediationStatus || "open",
    f.remediationNote || "",
    f.blastRadius || "low",
    (f.dependencies || []).join("; "),
    (f.dependedOnBy || []).join("; "),
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
      h.hostname || "",
      h.osGuess,
      h.respondsToPing ? "Yes" : "No",
      portsStr,
      servicesStr,
      bannersStr,
    ];
  });

  const sanitizedCidr = cidr.replace(/[^a-zA-Z0-9_.-]/g, "_");
  const csv = toCsvString(headers, rows);
  downloadCsv(`cvedeck-discovery-${sanitizedCidr}-${getTimestampStr()}.csv`, csv);
}
