import { afterEach, describe, expect, it, vi } from "vitest";
import {
  escapeCsvCell,
  exportFindingsCsv,
  exportFleetCsv,
  toCsvString,
} from "./csvExport";
import { makeFinding, makeMachine } from "../test-utils/factories";

/**
 * Run an exporter and return the CSV it would have downloaded.
 *
 * The exporters end at a Blob and a click on a hidden anchor, so the only way
 * to assert on what a user actually receives is to intercept the Blob.
 */
async function capture(run: () => void): Promise<string> {
  let blob: Blob | undefined;
  const createObjectURL = vi
    .spyOn(URL, "createObjectURL")
    .mockImplementation((value: Blob | MediaSource) => {
      blob = value as Blob;
      return "blob:captured";
    });
  vi.spyOn(URL, "revokeObjectURL").mockImplementation(() => {});
  // jsdom logs "Not implemented: navigation" for the download anchor, which is
  // noise in every run rather than a result.
  vi.spyOn(HTMLAnchorElement.prototype, "click").mockImplementation(() => {});
  try {
    run();
  } finally {
    createObjectURL.mockRestore();
  }
  if (blob === undefined) throw new Error("no CSV was produced");
  return blob.text();
}

/** The first data row of an exported CSV, i.e. everything but the header. */
function dataRow(csv: string, index = 0): string {
  return csv.split("\r\n")[index + 1];
}

afterEach(() => {
  vi.restoreAllMocks();
});

describe("csvExport utility", () => {
  describe("escapeCsvCell", () => {
    it("returns empty string for null and undefined", () => {
      expect(escapeCsvCell(null)).toBe("");
      expect(escapeCsvCell(undefined)).toBe("");
    });

    it("returns plain strings as-is when no special characters exist", () => {
      expect(escapeCsvCell("CVE-2023-1234")).toBe("CVE-2023-1234");
      expect(escapeCsvCell(9.8)).toBe("9.8");
      expect(escapeCsvCell(true)).toBe("true");
    });

    it("escapes cells containing commas", () => {
      expect(escapeCsvCell("curl, git, nginx")).toBe('"curl, git, nginx"');
    });

    it("escapes cells containing quotes with double quotes", () => {
      expect(escapeCsvCell('Hello "World"')).toBe('"Hello ""World"""');
    });

    it("escapes cells containing newlines", () => {
      expect(escapeCsvCell("Line 1\nLine 2")).toBe('"Line 1\nLine 2"');
    });
  });

  // A cell a spreadsheet would evaluate is not a formatting problem: opening
  // the file runs it. The values below are the ones an operator does not
  // write -- a remediation note, a package identifier, a discovered hostname.
  describe("escapeCsvCell formula neutralisation (Req 8.9)", () => {
    it("prefixes every leading character a spreadsheet would evaluate", () => {
      expect(escapeCsvCell('=HYPERLINK("http://evil.invalid","Click")')).toBe(
        '"\'=HYPERLINK(""http://evil.invalid"",""Click"")"',
      );
      expect(escapeCsvCell("+1+cmd|' /c calc'!A0")).toBe("'+1+cmd|' /c calc'!A0");
      expect(escapeCsvCell("-2+3")).toBe("'-2+3");
      expect(escapeCsvCell("@SUM(A1:A9)")).toBe("'@SUM(A1:A9)");
      expect(escapeCsvCell("\t=1+1")).toBe("'\t=1+1");
      expect(escapeCsvCell("\r=1+1")).toBe("\"'\r=1+1\"");
    });

    it("leaves numbers alone, including negative ones", () => {
      // Typed as a number, so it is a CVSS score or a count and not attacker
      // text. Quoting these would make every numeric column import as text.
      expect(escapeCsvCell(-5)).toBe("-5");
      expect(escapeCsvCell(9.8)).toBe("9.8");
    });

    it("leaves a formula character that does not lead the cell alone", () => {
      expect(escapeCsvCell("libssl >= 3.0.2")).toBe("libssl >= 3.0.2");
      expect(escapeCsvCell("user@example.com")).toBe("user@example.com");
    });

    it("composes with RFC 4180 quoting rather than replacing it", () => {
      // The apostrophe goes inside the quotes, so the cell still parses as one
      // field and still arrives neutralised.
      expect(escapeCsvCell("=A1,B2")).toBe("\"'=A1,B2\"");
    });
  });

  describe("exportFindingsCsv", () => {
    it("writes an unassessed blast radius as unassessed, not as low", async () => {
      const csv = await capture(() =>
        exportFindingsCsv("web-01", [makeFinding({ blastRadius: null })]),
      );

      // "low" here would export an impact nobody measured, and a spreadsheet
      // carries no tooltip to say otherwise (Req 10.10).
      expect(csv).toContain("not assessed");
      expect(dataRow(csv)).not.toMatch(/,low,/);
    });

    it("writes a measured blast radius as the level it measured", async () => {
      const csv = await capture(() =>
        exportFindingsCsv("web-01", [makeFinding({ blastRadius: "high" })]),
      );

      expect(dataRow(csv)).toContain("high");
      expect(csv).not.toContain("not assessed");
    });

    it("carries the exploitation signals the view shows", async () => {
      const csv = await capture(() =>
        exportFindingsCsv("web-01", [
          makeFinding({
            kevListed: true,
            kevDueDate: "2026-10-01",
            epssScore: 0.944,
            epssPercentile: 0.99,
          }),
        ]),
      );

      const [header, row] = [csv.split("\r\n")[0], dataRow(csv)];
      expect(header).toContain("Exploited (KEV)");
      // Without this column the export left CVSS standing in for urgency, and
      // the one finding being exploited right now looked like the rest.
      expect(row).toContain("yes");
      expect(row).toContain("2026-10-01");
      expect(row).toContain("0.944");
    });

    it("distinguishes a CVE checked and absent from one never checked", async () => {
      const checked = await capture(() =>
        exportFindingsCsv("web-01", [makeFinding({ kevListed: false })]),
      );
      const unchecked = await capture(() =>
        exportFindingsCsv("web-01", [makeFinding({ kevListed: null })]),
      );

      // By column, not by substring: "no" also appears in the New column, and
      // the distinction being tested is exactly the one a loose match loses.
      const kev = (csv: string) => dataRow(csv).split(",")[4];
      expect(kev(checked)).toBe("no");
      // An unenriched finding exported as "no" would report a fleet as clear
      // on the strength of a feed that never downloaded.
      expect(kev(unchecked)).toBe("not checked");
    });

    it("writes new-ness after a baseline as unassessed, not as no", async () => {
      const header = (csv: string) => csv.split("\r\n")[0].split(",");
      const newCell = (csv: string) =>
        dataRow(csv).split(",")[header(csv).indexOf("New")];

      const baseline = await capture(() =>
        exportFindingsCsv("web-01", [makeFinding({ isNew: false })], {
          baseline: true,
        }),
      );
      const compared = await capture(() =>
        exportFindingsCsv("web-01", [makeFinding({ isNew: false })]),
      );

      expect(newCell(baseline)).toBe("not assessed");
      expect(newCell(compared)).toBe("no");
    });

    it("neutralises a formula pasted into a remediation note", async () => {
      const csv = await capture(() =>
        exportFindingsCsv("web-01", [
          makeFinding({ remediationNote: '=HYPERLINK("http://evil.invalid","Payroll")' }),
        ]),
      );

      expect(csv).toContain("'=HYPERLINK");
    });
  });

  describe("exportFleetCsv", () => {
    it("dates the counts and says whether they are complete", async () => {
      const csv = await capture(() =>
        exportFleetCsv([
          makeMachine({
            lastScannedAt: "2026-09-01T12:00:00Z",
            lastScanSourcesOk: false,
            cveCounts: { critical: 2, unscored: 0, high: 1, medium: 0, low: 0 },
          }),
        ]),
      );

      const row = dataRow(csv);
      expect(csv.split("\r\n")[0]).toContain("Counts Complete");
      expect(row).toContain("2026-09-01T12:00:00Z");
      // An undercount from an unreachable advisory source is the difference
      // between a floor and a total, and the sheet has to carry it.
      expect(row).toContain("no");
    });

    it("writes an unassessed change count as unassessed, never as zero", async () => {
      const csv = await capture(() =>
        exportFleetCsv([makeMachine({ lastScanNew: null, lastScanResolved: 3 })]),
      );

      const cells = dataRow(csv).split(",");
      expect(cells).toContain("not assessed");
      expect(cells[cells.length - 1]).toBe("3");
    });

    it("never scanned reads as never, not as an empty cell", async () => {
      const csv = await capture(() =>
        exportFleetCsv([makeMachine({ lastScannedAt: null, lastScanStatus: "never_scanned" })]),
      );

      expect(dataRow(csv)).toContain("never");
    });

    it("does not vouch for the counts of a host never scanned", async () => {
      // The backend defaults sources-ok to true, so a host with no scan at all
      // arrives looking like one scanned cleanly against every source.
      const csv = await capture(() =>
        exportFleetCsv([
          makeMachine({
            lastScannedAt: null,
            lastScanStatus: "never_scanned",
            lastScanSourcesOk: true,
          }),
        ]),
      );

      const cells = dataRow(csv).split(",");
      expect(cells[3]).toBe("never_scanned");
      expect(cells[4]).toBe("never");
      expect(cells[5]).toBe("not assessed");
    });

    it("writes no exploited count when no intel feed has loaded", async () => {
      // The fleet view draws a dash here without a feed; a spreadsheet has no
      // tooltip, so a 0 would read as "this host is clear" (Req 8.10).
      const csv = await capture(() =>
        exportFleetCsv([makeMachine({ kevCount: 0 })], { intelUsable: false }),
      );
      const withFeed = await capture(() =>
        exportFleetCsv([makeMachine({ kevCount: 0 })], { intelUsable: true }),
      );

      const header = csv.split("\r\n")[0].split(",");
      const cell = (text: string) =>
        dataRow(text).split(",")[header.indexOf("Exploited (KEV)")];
      expect(cell(csv)).toBe("not checked");
      // A feed that did load still answers zero, or the fix only moved the lie.
      expect(cell(withFeed)).toBe("0");
    });

    it("writes no counts for a host that was never scanned", async () => {
      const csv = await capture(() =>
        exportFleetCsv([
          makeMachine({
            lastScannedAt: null,
            lastScanStatus: "never_scanned",
            cveCounts: { critical: 0, unscored: 0, high: 0, medium: 0, low: 0 },
          }),
        ]),
      );

      const header = csv.split("\r\n")[0].split(",");
      const cells = dataRow(csv).split(",");
      for (const column of ["Critical CVEs", "High CVEs", "Medium CVEs", "Low CVEs", "Total Findings"]) {
        expect(cells[header.indexOf(column)]).toBe("not assessed");
      }
    });

    it("writes the status the backend sent, and invents none", async () => {
      const csv = await capture(() =>
        exportFleetCsv([makeMachine({ lastScanStatus: "auth_failure" })]),
      );

      expect(dataRow(csv).split(",")[3]).toBe("auth_failure");
      expect(csv).not.toContain("discovered");
    });
  });

  describe("toCsvString", () => {
    it("generates RFC 4180 compliant CSV string with CRLF", () => {
      const headers = ["CVE ID", "CVSS", "Description"];
      const rows = [
        ["CVE-2024-0001", 9.8, "Critical RCE"],
        ["CVE-2024-0002", 5.3, "Info leak, minor"],
      ];

      const csv = toCsvString(headers, rows);
      expect(csv).toBe(
        'CVE ID,CVSS,Description\r\nCVE-2024-0001,9.8,Critical RCE\r\nCVE-2024-0002,5.3,"Info leak, minor"',
      );
    });
  });
});
