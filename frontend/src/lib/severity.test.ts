import { describe, expect, it } from "vitest";
import {
  compareBySeverity,
  filterBySeverity,
  groupCountsBySeverity,
} from "./severity";
import type { CveFinding, Severity } from "../types";

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

describe("compareBySeverity and the unscored band", () => {
  const f = (severity: Severity, cvssScore: number | null) =>
    ({ severity, cvssScore }) as Pick<CveFinding, "severity" | "cvssScore">;

  it("never returns NaN, for any pair", () => {
    // Every finding in the Unscored band lacks a score, so every comparison
    // within it went through `Infinity - Infinity`. Sort coerces a NaN result
    // to 0, which is the right answer by accident -- and the docstring on this
    // very function warns against producing one.
    const samples = [
      f("critical", 9.8),
      f("unscored", null),
      f("unscored", null),
      f("high", null),
      f("high", 7.5),
      f("low", null),
    ];
    for (const a of samples) {
      for (const b of samples) {
        expect(Number.isNaN(compareBySeverity(a, b))).toBe(false);
      }
    }
  });

  it("treats two unscored findings as equal rather than unordered", () => {
    expect(compareBySeverity(f("unscored", null), f("unscored", null))).toBe(0);
  });

  it("leads a band with the finding that published no number", () => {
    // Req 10.11: a band with no number could be anywhere in that band,
    // including its top, so it keeps its place rather than falling to the
    // bottom of the list. This was the specified behaviour with no test behind
    // it -- inverting it left every suite green.
    const sorted = [f("high", 7.5), f("high", null), f("high", 8.8)].sort(
      compareBySeverity,
    );

    expect(sorted[0].cvssScore).toBeNull();
    expect(sorted.map((x) => x.cvssScore)).toEqual([null, 8.8, 7.5]);
  });

  it("puts the unscored band below critical and above high", () => {
    const sorted = [f("high", 9.9), f("unscored", null), f("critical", 9.0)].sort(
      compareBySeverity,
    );

    expect(sorted.map((x) => x.severity)).toEqual(["critical", "unscored", "high"]);
  });
});
