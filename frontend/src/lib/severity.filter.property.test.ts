// Property-based tests for the cvedeck feature.
//
// Property 7: Severity filtering is sound and complete
// For any set of findings and any selected Severity_Level, filtering (whether
// applied in the dashboard or via the API) SHALL return every finding with
// that severity and no finding with any other severity.
//
// **Validates: Requirements 3.3, 6.3**

import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { filterBySeverity } from "./severity";
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

describe("filterBySeverity (Property 7: Severity filtering is sound and complete)", () => {
  it("returns every finding of the selected severity and no finding of any other severity", () => {
    fc.assert(
      fc.property(findingsArb, severityArb, (findings, selected) => {
        const result = filterBySeverity(findings, selected);

        // Soundness: no returned finding has a severity other than the
        // selected one.
        for (const finding of result) {
          expect(finding.severity).toBe(selected);
        }

        // Completeness: every finding of the selected severity in the input is
        // present in the result. Comparing the counts of matching findings on
        // both sides establishes that none were dropped (and, combined with
        // soundness above, that none were spuriously added).
        const expectedMatches = findings.filter(
          (finding) => finding.severity === selected,
        );
        expect(result.length).toBe(expectedMatches.length);

        // Every input finding of the selected severity is referenced in the
        // result (identity preserved, nothing fabricated).
        for (const finding of expectedMatches) {
          expect(result).toContain(finding);
        }
      }),
      { numRuns: 100 },
    );
  });
});
