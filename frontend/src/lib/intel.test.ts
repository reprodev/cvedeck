// Tests for the threat-intel presentation helpers.
//
// The bulk of this file defends a single distinction: null means "not checked"
// and false means "checked and clear". Every helper that touches kevListed is
// tested against all three states, because collapsing null into false is the
// one bug here that would actively mislead a user about fleet safety.

import { describe, expect, it } from "vitest";
import fc from "fast-check";

import {
  countKnownExploited,
  enrichmentWarning,
  exploitStatus,
  feedLabel,
  formatEpssPercentile,
  formatEpssScore,
  formatFeedAge,
  hostExploitSummary,
  isKnownExploited,
  sortByRisk,
} from "./intel";
import type { CveFinding, FeedHealth } from "../types";

function finding(overrides: Partial<CveFinding> = {}): CveFinding {
  return {
    cveId: "CVE-2021-44228",
    severity: "critical",
    cvssScore: 10,
    packageIdentifier: null,
    remediationStatus: null,
    remediationRecordId: null,
    remediationNote: null,
    ...overrides,
  };
}

function feed(overrides: Partial<FeedHealth> = {}): FeedHealth {
  return {
    feedName: "kev",
    status: "ok",
    lastRefreshedAt: new Date().toISOString(),
    lastAttemptedAt: new Date().toISOString(),
    recordCount: 1200,
    errorDetail: null,
    stale: false,
    usable: true,
    ...overrides,
  };
}

describe("isKnownExploited", () => {
  it("is true only for an explicit true", () => {
    expect(isKnownExploited(finding({ kevListed: true }))).toBe(true);
  });

  it("is false for a checked-and-absent finding", () => {
    expect(isKnownExploited(finding({ kevListed: false }))).toBe(false);
  });

  it("is false for an unenriched finding, without claiming it was checked", () => {
    // isKnownExploited answers "is it confirmed exploited", so null is
    // correctly false here. exploitStatus is what preserves the distinction.
    expect(isKnownExploited(finding({ kevListed: null }))).toBe(false);
    expect(isKnownExploited(finding())).toBe(false);
  });
});

describe("exploitStatus", () => {
  it("distinguishes all three states", () => {
    expect(exploitStatus(finding({ kevListed: true }))).toBe("exploited");
    expect(exploitStatus(finding({ kevListed: false }))).toBe("not-exploited");
    expect(exploitStatus(finding({ kevListed: null }))).toBe("unknown");
  });

  it("treats a missing field as unknown, never as not-exploited", () => {
    expect(exploitStatus(finding())).toBe("unknown");
  });
});

describe("countKnownExploited", () => {
  it("counts only confirmed findings", () => {
    const findings = [
      finding({ cveId: "CVE-1", kevListed: true }),
      finding({ cveId: "CVE-2", kevListed: false }),
      finding({ cveId: "CVE-3", kevListed: null }),
      finding({ cveId: "CVE-4", kevListed: true }),
    ];
    expect(countKnownExploited(findings)).toBe(2);
  });

  it("is zero for an empty list", () => {
    expect(countKnownExploited([])).toBe(0);
  });
});

describe("formatEpssScore", () => {
  it("renders a dash when there is no score", () => {
    expect(formatEpssScore(null)).toBe("--");
    expect(formatEpssScore(undefined)).toBe("--");
  });

  it("keeps two decimals below one percent", () => {
    // Most of the EPSS corpus sits here; whole percents would render nearly
    // every CVE as an indistinguishable 0%.
    expect(formatEpssScore(0.0004)).toBe("0.04%");
    expect(formatEpssScore(0.0092)).toBe("0.92%");
  });

  it("uses one decimal at and above one percent", () => {
    expect(formatEpssScore(0.944)).toBe("94.4%");
    expect(formatEpssScore(1)).toBe("100.0%");
  });

  it("renders a genuine zero distinctly from an absent score", () => {
    expect(formatEpssScore(0)).toBe("0.00%");
    expect(formatEpssScore(0)).not.toBe(formatEpssScore(null));
  });
});

describe("formatEpssPercentile", () => {
  it("renders an ordinal rank", () => {
    expect(formatEpssPercentile(0.9995)).toBe("100th");
    expect(formatEpssPercentile(0.94)).toBe("94th");
  });

  it("renders a dash when unknown", () => {
    expect(formatEpssPercentile(null)).toBe("--");
  });
});

describe("sortByRisk", () => {
  it("puts an exploited medium above an unexploited critical", () => {
    // The central claim of the whole feature: what is happening beats what
    // could happen.
    const exploitedMedium = finding({
      cveId: "CVE-MED",
      cvssScore: 6.5,
      severity: "medium",
      kevListed: true,
    });
    const quietCritical = finding({
      cveId: "CVE-CRIT",
      cvssScore: 9.8,
      kevListed: false,
    });

    const sorted = sortByRisk([quietCritical, exploitedMedium]);

    expect(sorted.map((f) => f.cveId)).toEqual(["CVE-MED", "CVE-CRIT"]);
  });

  it("orders by EPSS when neither is KEV-listed", () => {
    const high = finding({ cveId: "CVE-A", cvssScore: 5, epssScore: 0.8 });
    const low = finding({ cveId: "CVE-B", cvssScore: 9, epssScore: 0.01 });

    expect(sortByRisk([low, high]).map((f) => f.cveId)).toEqual([
      "CVE-A",
      "CVE-B",
    ]);
  });

  it("sorts an unscored finding below any scored one", () => {
    // An unscored CVE has not been assessed. Treating it as zero would rank it
    // alongside CVEs that were genuinely measured as near-zero.
    const unscored = finding({ cveId: "CVE-NONE", cvssScore: 9 });
    const scored = finding({ cveId: "CVE-LOW", cvssScore: 1, epssScore: 0.0001 });

    expect(sortByRisk([unscored, scored]).map((f) => f.cveId)).toEqual([
      "CVE-LOW",
      "CVE-NONE",
    ]);
  });

  it("falls back to CVSS, then to CVE id, for a stable order", () => {
    const a = finding({ cveId: "CVE-2020-0002", cvssScore: 7 });
    const b = finding({ cveId: "CVE-2020-0001", cvssScore: 7 });

    expect(sortByRisk([a, b]).map((f) => f.cveId)).toEqual([
      "CVE-2020-0001",
      "CVE-2020-0002",
    ]);
  });

  it("does not mutate its input", () => {
    const findings = [
      finding({ cveId: "CVE-B", cvssScore: 1 }),
      finding({ cveId: "CVE-A", cvssScore: 9 }),
    ];
    const before = findings.map((f) => f.cveId);

    sortByRisk(findings);

    expect(findings.map((f) => f.cveId)).toEqual(before);
  });

  it("keeps every KEV-listed finding ahead of every other one", () => {
    fc.assert(
      fc.property(
        fc.array(
          fc.record({
            kev: fc.option(fc.boolean(), { nil: null }),
            cvss: fc.float({ min: 0, max: 10, noNaN: true }),
            epss: fc.option(fc.float({ min: 0, max: 1, noNaN: true }), {
              nil: null,
            }),
          }),
          { maxLength: 40 },
        ),
        (specs) => {
          const findings = specs.map((spec, index) =>
            finding({
              cveId: `CVE-2020-${String(index).padStart(5, "0")}`,
              cvssScore: spec.cvss,
              kevListed: spec.kev,
              epssScore: spec.epss,
            }),
          );

          const sorted = sortByRisk(findings);
          const lastExploited = sorted.reduce(
            (acc, f, i) => (isKnownExploited(f) ? i : acc),
            -1,
          );
          const firstQuiet = sorted.findIndex((f) => !isKnownExploited(f));

          if (lastExploited >= 0 && firstQuiet >= 0) {
            expect(lastExploited).toBeLessThan(firstQuiet);
          }
          expect(sorted).toHaveLength(findings.length);
        },
      ),
      { numRuns: 100 },
    );
  });
});

describe("enrichmentWarning", () => {
  it("is silent when every feed is fresh and usable", () => {
    expect(
      enrichmentWarning([feed({ feedName: "kev" }), feed({ feedName: "epss" })]),
    ).toBeNull();
  });

  it("says intel was never loaded when no feed is usable", () => {
    const warning = enrichmentWarning([
      feed({ feedName: "kev", usable: false, status: "never_refreshed" }),
      feed({ feedName: "epss", usable: false, status: "never_refreshed" }),
    ]);

    expect(warning).toMatch(/never been loaded/i);
    expect(warning).toMatch(/CVSS only/i);
  });

  it("names the specific feed when only one is unusable", () => {
    const warning = enrichmentWarning([
      feed({ feedName: "kev", usable: false }),
      feed({ feedName: "epss" }),
    ]);

    expect(warning).toContain("CISA KEV");
    expect(warning).not.toContain("EPSS");
  });

  it("explains that an unusable feed shows no value, not a negative", () => {
    // This is the sentence that stops a user reading a blank KEV column as
    // "nothing here is exploited".
    const warning = enrichmentWarning([
      feed({ feedName: "kev", usable: false }),
      feed({ feedName: "epss" }),
    ]);
    expect(warning).toMatch(/rather than a negative/i);
  });

  it("warns about a stale but usable feed", () => {
    const warning = enrichmentWarning([feed({ stale: true })]);

    expect(warning).toMatch(/out of date/i);
    expect(warning).toMatch(/may not be flagged/i);
  });

  it("prioritises unusable over merely stale", () => {
    const warning = enrichmentWarning([
      feed({ feedName: "kev", usable: false, stale: true }),
      feed({ feedName: "epss", stale: true }),
    ]);

    expect(warning).toMatch(/unavailable/i);
  });

  it("is silent when there are no feeds to report on", () => {
    expect(enrichmentWarning([])).toBeNull();
  });
});

describe("formatFeedAge", () => {
  const now = new Date("2026-09-02T12:00:00Z");

  it("reports never for a feed that has not refreshed", () => {
    expect(formatFeedAge(null, now)).toBe("never");
  });

  it("reports minutes, hours, and days", () => {
    expect(formatFeedAge("2026-09-02T11:30:00Z", now)).toBe("30m ago");
    expect(formatFeedAge("2026-09-02T06:00:00Z", now)).toBe("6h ago");
    expect(formatFeedAge("2026-08-30T12:00:00Z", now)).toBe("3d ago");
  });

  it("reports just now for a fresh refresh", () => {
    expect(formatFeedAge("2026-09-02T11:59:40Z", now)).toBe("just now");
  });

  it("degrades to unknown on an unparseable timestamp", () => {
    expect(formatFeedAge("not-a-date", now)).toBe("unknown");
  });
});

describe("feedLabel", () => {
  it("maps known feed names to display labels", () => {
    expect(feedLabel("kev")).toBe("CISA KEV");
    expect(feedLabel("epss")).toBe("EPSS");
  });

  it("passes an unknown name through unchanged", () => {
    expect(feedLabel("something-new")).toBe("something-new");
  });
});

describe("hostExploitSummary", () => {
  it("reports exploited when anything is confirmed", () => {
    expect(
      hostExploitSummary([
        finding({ kevListed: true }),
        finding({ kevListed: null }),
      ]).state,
    ).toBe("exploited");
  });

  it("clears a host only when every finding was checked", () => {
    expect(
      hostExploitSummary([
        finding({ kevListed: false }),
        finding({ kevListed: false }),
      ]).state,
    ).toBe("clear");
  });

  it("reports partial when some findings were never checked", () => {
    // The whole reason this helper exists. Computed as "was anything
    // checked?", this case returned clear -- a confident all-clear resting on
    // one answered question out of three.
    const summary = hostExploitSummary([
      finding({ kevListed: false }),
      finding({ kevListed: null }),
      finding({ kevListed: null }),
    ]);

    expect(summary.state).toBe("partial");
    expect(summary.checked).toBe(1);
    expect(summary.total).toBe(3);
  });

  it("reports unknown when nothing was checked", () => {
    expect(
      hostExploitSummary([finding({ kevListed: null })]).state,
    ).toBe("unknown");
  });

  it("never reports clear for a host with no findings at all", () => {
    // Zero findings is not a clean bill of health: it is a host nothing has
    // been established about.
    expect(hostExploitSummary([]).state).toBe("unknown");
  });
});

describe("enrichmentWarning", () => {
  const dead = (name: string) => ({
    feedName: name,
    status: "never_refreshed" as const,
    lastRefreshedAt: null,
    lastAttemptedAt: null,
    recordCount: 0,
    errorDetail: null,
    stale: true,
    usable: false,
  });

  it("tells a user who can refresh to do so", () => {
    expect(enrichmentWarning([dead("kev"), dead("epss")], true)).toMatch(
      /Refresh the intel feeds/,
    );
  });

  it("withholds the instruction where there is no control to follow it with", () => {
    // A demo refuses the refresh route and offers no button, so the sentence
    // sent anyone who took it seriously looking for something that is not
    // there.
    const message = enrichmentWarning([dead("kev"), dead("epss")], false);

    expect(message).toMatch(/never been loaded/);
    expect(message).not.toMatch(/Refresh the intel feeds/);
  });
});
