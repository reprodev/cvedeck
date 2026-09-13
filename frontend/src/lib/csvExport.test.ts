import { describe, expect, it } from "vitest";
import {
  escapeCsvCell,
  toCsvString,
} from "./csvExport";

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
