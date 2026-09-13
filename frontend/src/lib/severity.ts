// Pure client-side helpers for severity filtering and counting.
//
// See design.md "Frontend Interfaces":
//   filterBySeverity(findings, severity) -> CveFinding[]
//   groupCountsBySeverity(findings)      -> SeverityCounts
//
// These functions are pure: they never mutate their inputs and their output
// depends solely on their arguments.

import type { CveFinding, Severity, SeverityCounts } from "../types";

/**
 * Return exactly the findings whose severity matches the given severity.
 *
 * Sound and complete: every returned finding has the requested severity, and
 * no finding with any other severity is returned. Input order is preserved and
 * the input array is not mutated (Requirement 3.3).
 */
export function filterBySeverity(
  findings: CveFinding[],
  severity: Severity,
): CveFinding[] {
  return findings.filter((finding) => finding.severity === severity);
}

/**
 * Tally the findings by severity level.
 *
 * The returned counts equal the actual number of findings at each severity,
 * and the sum of the four counts equals the total number of findings. The
 * input array is not mutated (Requirement 3.2).
 */
export function groupCountsBySeverity(findings: CveFinding[]): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const finding of findings) {
    // finding.severity is one of SEVERITIES, which are exactly the keys of
    // SeverityCounts, so this increment is total over valid inputs.
    counts[finding.severity] += 1;
  }
  return counts;
}
