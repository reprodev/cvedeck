// Pure helpers for presenting threat-intel signals (KEV and EPSS).
//
// The rule these helpers exist to enforce, in one place rather than at every
// call site:
//
//   null  ->  "we did not check"
//   false ->  "we checked, and this CVE is not in CISA's catalogue"
//
// Rendering null as "not exploited" would tell a user their fleet is clear on
// the basis of a feed that was never downloaded. Every function here keeps the
// two apart, and `isKnownExploited` is deliberately strict (`=== true`) so a
// null can never sneak through a truthiness check.

import { compareBySeverity } from "./severity";
import type { CveFinding, FeedHealth } from "../types";

/** How a CVE's exploitation status should be presented. */
export type ExploitStatus = "exploited" | "not-exploited" | "unknown";

/**
 * Whether a finding is confirmed as actively exploited.
 *
 * Strict equality on purpose: `if (finding.kevListed)` would read null as
 * false, quietly collapsing "unknown" into "safe".
 */
export function isKnownExploited(finding: CveFinding): boolean {
  return finding.kevListed === true;
}

/** Classify a finding's exploitation status into the three real states. */
export function exploitStatus(finding: CveFinding): ExploitStatus {
  if (finding.kevListed === true) return "exploited";
  if (finding.kevListed === false) return "not-exploited";
  return "unknown";
}

/** Count the findings confirmed as actively exploited. */
export function countKnownExploited(findings: CveFinding[]): number {
  return findings.filter(isKnownExploited).length;
}

/**
 * Format an EPSS score as a percentage string, or a dash when unknown.
 *
 * Two decimal places below 1%: the EPSS distribution is heavily skewed and the
 * majority of CVEs sit under 0.01, so rounding to whole percents would render
 * most of the corpus as an indistinguishable "0%".
 */
export function formatEpssScore(score: number | null | undefined): string {
  if (score === null || score === undefined) return "--";
  const percent = score * 100;
  if (percent < 1) return `${percent.toFixed(2)}%`;
  return `${percent.toFixed(1)}%`;
}

/**
 * Format an EPSS percentile as an ordinal rank string.
 *
 * The percentile is what makes the raw score legible: 0.08 reads as negligible
 * until you know it ranks above 94% of every scored CVE.
 */
export function formatEpssPercentile(
  percentile: number | null | undefined,
): string {
  if (percentile === null || percentile === undefined) return "--";
  return `${Math.round(percentile * 100)}th`;
}

/**
 * Rank findings by real-world urgency rather than by CVSS alone.
 *
 * The ordering, highest priority first:
 *   1. KEV-listed  -- being exploited right now, regardless of CVSS
 *   2. EPSS score  -- likely to be exploited soon
 *   3. CVSS score  -- would be bad if it were
 *   4. CVE id      -- a stable tiebreak so the order never flickers
 *
 * The CVSS tier ranks by severity band first and then by score, so a finding
 * whose advisory published a band but no number keeps its place instead of
 * falling to the bottom of the list (Req 10.11).
 *
 * A CVSS 6.5 on the KEV list outranks a CVSS 9.8 that nobody is exploiting,
 * which is the whole point of collecting these signals. Findings with no EPSS
 * score sort below any that have one rather than being treated as zero: an
 * unscored CVE has not been assessed, and sorting it alongside genuinely
 * near-zero probabilities would misrepresent that.
 *
 * Pure: returns a new array and never mutates its input.
 */
export function sortByRisk(findings: CveFinding[]): CveFinding[] {
  return [...findings].sort((a, b) => {
    const aKev = isKnownExploited(a) ? 1 : 0;
    const bKev = isKnownExploited(b) ? 1 : 0;
    if (aKev !== bKev) return bKev - aKev;

    const aEpss = a.epssScore ?? -1;
    const bEpss = b.epssScore ?? -1;
    if (aEpss !== bEpss) return bEpss - aEpss;

    // Severity band, then magnitude within it. Subtracting the scores
    // directly yields NaN against a null, which leaves the comparator
    // inconsistent and the sort order unspecified. The band is the
    // authoritative signal now in any case: a finding can carry a published
    // band with no score at all (Req 2.6, 10.11).
    const bySeverity = compareBySeverity(a, b);
    if (bySeverity !== 0) return bySeverity;
    return a.cveId.localeCompare(b.cveId);
  });
}

/** Human-readable label for a feed name. */
export function feedLabel(feedName: string): string {
  if (feedName === "kev") return "CISA KEV";
  if (feedName === "epss") return "EPSS";
  return feedName;
}

/**
 * A one-line warning about degraded enrichment, or null when all is well.
 *
 * Returns a message whenever any feed is unusable or stale, because both
 * states change how the KEV and EPSS columns should be read. Silence here
 * means the signals on screen can be trusted at face value.
 */
export function enrichmentWarning(feeds: FeedHealth[]): string | null {
  if (feeds.length === 0) return null;

  const unusable = feeds.filter((feed) => !feed.usable);
  if (unusable.length === feeds.length) {
    return (
      "Threat intelligence has never been loaded. Findings are ranked by CVSS " +
      "only -- no exploitation data is available. Refresh the intel feeds to " +
      "see which findings are actively exploited."
    );
  }
  if (unusable.length > 0) {
    const names = unusable.map((feed) => feedLabel(feed.feedName)).join(" and ");
    return `${names} data is unavailable, so those columns show no value rather than a negative result.`;
  }

  const stale = feeds.filter((feed) => feed.stale);
  if (stale.length > 0) {
    const names = stale.map((feed) => feedLabel(feed.feedName)).join(" and ");
    return `${names} data is out of date. Newly exploited vulnerabilities may not be flagged yet.`;
  }
  return null;
}

/**
 * Relative age of a feed's data, for display beside the warning.
 *
 * Reports the age of the *data*, not of the last attempt, so a feed that has
 * been failing for a week reads as a week old rather than as just-checked.
 */
export function formatFeedAge(
  lastRefreshedAt: string | null,
  now: Date = new Date(),
): string {
  if (!lastRefreshedAt) return "never";
  const then = new Date(lastRefreshedAt);
  if (Number.isNaN(then.getTime())) return "unknown";

  const minutes = Math.floor((now.getTime() - then.getTime()) / 60000);
  if (minutes < 1) return "just now";
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}
