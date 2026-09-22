// Pure client-side helpers for severity filtering and counting.
//
// See design.md "Frontend Interfaces":
//   filterBySeverity(findings, severity) -> CveFinding[]
//   groupCountsBySeverity(findings)      -> SeverityCounts
//
// These functions are pure: they never mutate their inputs and their output
// depends solely on their arguments.

import { SEVERITIES } from "../types";
import type { CveFinding, Severity, SeverityCounts } from "../types";

/**
 * Triage ranking, lowest number first. Mirrors SEVERITY_RANK in the backend's
 * app/enums.py, which is the definition of record.
 *
 * "unscored" ranks below critical and above high: an unmeasured finding could
 * be either, so ranking it with the least severe would be the same silent
 * all-clear that a substituted score of 5.0 was (Req 10.11).
 */
export const SEVERITY_RANK: Readonly<Record<Severity, number>> =
  Object.fromEntries(SEVERITIES.map((s, i) => [s, i])) as Record<
    Severity,
    number
  >;

/**
 * Compare two findings for triage order: severity band first, then the score
 * within it, with an unscored finding ahead of the measured ones in its band.
 *
 * Never compares cvssScore directly — subtracting a null yields NaN, which
 * leaves the sort order unspecified (Req 10.11, 10.12).
 *
 * The two-unscored case is returned explicitly rather than falling out of the
 * arithmetic. `Infinity - Infinity` is NaN, and every finding in the Unscored
 * band lacks a score by definition, so *every* comparison within that band
 * produced one. It happened to behave: `Array.prototype.sort` coerces a NaN
 * comparison to 0, which is the right answer here. But "correct because the
 * specification rounds our mistake in our favour" is not a property to rest a
 * ranking on, and the paragraph directly above already warns against producing
 * the NaN this function then produced.
 */
export function compareBySeverity(
  a: Pick<CveFinding, "severity" | "cvssScore">,
  b: Pick<CveFinding, "severity" | "cvssScore">,
): number {
  const byBand = SEVERITY_RANK[a.severity] - SEVERITY_RANK[b.severity];
  if (byBand !== 0) return byBand;

  const aScore = a.cvssScore ?? null;
  const bScore = b.cvssScore ?? null;
  if (aScore === null && bScore === null) return 0;
  // An unscored finding leads its band: the advisory published a band and no
  // number, so it could be anywhere in that band -- including the top of it.
  if (aScore === null) return -1;
  if (bScore === null) return 1;
  return bScore - aScore;
}

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
 * and the sum of the five counts equals the total number of findings. The
 * input array is not mutated (Requirement 3.2).
 */
export function groupCountsBySeverity(findings: CveFinding[]): SeverityCounts {
  const counts: SeverityCounts = {
    critical: 0,
    unscored: 0,
    high: 0,
    medium: 0,
    low: 0,
  };
  for (const finding of findings) {
    // finding.severity is one of SEVERITIES, which are exactly the keys of
    // SeverityCounts, so this increment is total over valid inputs. Omitting
    // a key here would make its first increment NaN rather than a type error.
    counts[finding.severity] += 1;
  }
  return counts;
}
