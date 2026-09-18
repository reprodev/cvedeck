import { describe, expect, it } from "vitest";
import { filterBySeverity, groupCountsBySeverity } from "./severity";
import type { CveFinding } from "../types";

function finding(cveId: string, severity: CveFinding["severity"]): CveFinding {
  return {
    cveId,
    severity,
    cvssScore: 5,
    packageIdentifier: null,
    remediationStatus: null,
    remediationRecordId: null,
    remediationNote: null,
  };
}

const sample: CveFinding[] = [
  finding("CVE-2024-0001", "critical"),
  finding("CVE-2024-0002", "high"),
  finding("CVE-2024-0003", "high"),
  finding("CVE-2024-0004", "medium"),
  finding("CVE-2024-0005", "low"),
  finding("CVE-2024-0006", "critical"),
];

describe("filterBySeverity", () => {
  it("returns only findings matching the requested severity", () => {
    const result = filterBySeverity(sample, "high");
    expect(result).toEqual([
      finding("CVE-2024-0002", "high"),
      finding("CVE-2024-0003", "high"),
    ]);
  });

  it("returns an empty array when no finding matches", () => {
    const onlyLows = [finding("CVE-1", "low"), finding("CVE-2", "low")];
    expect(filterBySeverity(onlyLows, "critical")).toEqual([]);
  });

  it("returns an empty array for empty input", () => {
    expect(filterBySeverity([], "medium")).toEqual([]);
  });

  it("preserves the original order of matching findings", () => {
    const result = filterBySeverity(sample, "critical");
    expect(result.map((f) => f.cveId)).toEqual([
      "CVE-2024-0001",
      "CVE-2024-0006",
    ]);
  });

  it("does not mutate the input array", () => {
    const input = [...sample];
    const snapshot = [...input];
    filterBySeverity(input, "high");
    expect(input).toEqual(snapshot);
  });
});

describe("groupCountsBySeverity", () => {
  it("counts findings per severity level", () => {
    expect(groupCountsBySeverity(sample)).toEqual({
      critical: 2,
      unscored: 0,
      high: 2,
      medium: 1,
      low: 1,
    });
  });

  it("returns all-zero counts for empty input", () => {
    expect(groupCountsBySeverity([])).toEqual({
      critical: 0,
      unscored: 0,
      high: 0,
      medium: 0,
      low: 0,
    });
  });

  it("produces counts whose sum equals the total number of findings", () => {
    const counts = groupCountsBySeverity(sample);
    const total = counts.critical + counts.high + counts.medium + counts.low;
    expect(total).toBe(sample.length);
  });

  it("does not mutate the input array", () => {
    const input = [...sample];
    const snapshot = [...input];
    groupCountsBySeverity(input);
    expect(input).toEqual(snapshot);
  });
});
