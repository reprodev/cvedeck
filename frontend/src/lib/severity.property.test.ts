// Property-based tests for the cvedeck feature.
//
// Property 6: Severity-grouped counts are accurate
// For any set of findings for a machine, the severity-grouped counts SHALL
// equal the actual tally of findings per severity level, and the sum of the
// four counts SHALL equal the total number of findings.
//
// **Validates: Requirements 3.2**

import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { groupCountsBySeverity } from "./severity";
import { SEVERITIES } from "../types";
import type { CveFinding, Severity } from "../types";

/** Arbitrary Severity drawn from the canonical severity levels. */
const severityArb: fc.Arbitrary<Severity> = fc.constantFrom(...SEVERITIES);

/** Arbitrary CveFinding with an arbitrary severity. */
const findingArb: fc.Arbitrary<CveFinding> = fc.record({
  cveId: fc.string(),
  severity: severityArb,
  cvssScore: fc.double({ min: 0, max: 10, noNaN: true }),
  packageIdentifier: fc.option(fc.string(), { nil: null }),
  remediationStatus: fc.option(fc.string(), { nil: null }),
  remediationRecordId: fc.option(fc.string(), { nil: null }),
  remediationNote: fc.option(fc.string(), { nil: null }),
});

/** Arbitrary array of CveFinding for a machine. */
const findingsArb: fc.Arbitrary<CveFinding[]> = fc.array(findingArb);

describe("groupCountsBySeverity (Property 6: Severity-grouped counts are accurate)", () => {
  it("each severity count equals the actual tally and the four counts sum to the total", () => {
    fc.assert(
      fc.property(findingsArb, (findings) => {
        const counts = groupCountsBySeverity(findings);

        // Each severity count equals the actual tally of findings at that level.
        for (const severity of SEVERITIES) {
          const actual = findings.filter(
            (finding) => finding.severity === severity,
          ).length;
          expect(counts[severity]).toBe(actual);
        }

        // The sum of the four counts equals the total number of findings.
        const sum =
          counts.critical + counts.high + counts.medium + counts.low;
        expect(sum).toBe(findings.length);
      }),
      { numRuns: 100 },
    );
  });
});
