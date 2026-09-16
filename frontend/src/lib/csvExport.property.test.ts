// Property-based tests for the cvedeck feature.
//
// Property 14: An exported cell survives the round trip and never becomes a formula
// For any cell value, parsing the generated CSV back SHALL yield that value,
// or that value behind a single leading apostrophe when a spreadsheet would
// otherwise have evaluated it; and no parsed cell other than a number SHALL
// begin with a character a spreadsheet evaluates.
//
// The round trip is the half that keeps the fix honest. Neutralising a cell is
// easy to do by mangling it -- stripping the character, or quoting in a way
// that loses the value -- and an export that quietly alters a remediation note
// is a different bug, not a fix.
//
// **Validates: Requirements 8.8, 8.9**

import { describe, expect, it } from "vitest";
import fc from "fast-check";
import { escapeCsvCell, toCsvString } from "./csvExport";

/** The characters a spreadsheet evaluates when they lead a cell (Req 8.9). */
const FORMULA_LEADS = ["=", "+", "-", "@", "\t", "\r"];

/**
 * Parse an RFC 4180 CSV back into rows of cells.
 *
 * Deliberately written here rather than imported: a round-trip property proved
 * with the generator's own inverse proves only that the two agree.
 */
function parseCsv(csv: string): string[][] {
  const rows: string[][] = [];
  let row: string[] = [];
  let cell = "";
  let quoted = false;

  for (let i = 0; i < csv.length; i += 1) {
    const ch = csv[i];
    if (quoted) {
      if (ch === '"') {
        if (csv[i + 1] === '"') {
          cell += '"';
          i += 1;
        } else {
          quoted = false;
        }
      } else {
        cell += ch;
      }
    } else if (ch === '"' && cell === "") {
      quoted = true;
    } else if (ch === ",") {
      row.push(cell);
      cell = "";
    } else if (ch === "\r" && csv[i + 1] === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      i += 1;
    } else {
      cell += ch;
    }
  }
  row.push(cell);
  rows.push(row);
  return rows;
}

/**
 * Arbitrary cell values, weighted towards the shapes that matter: free text
 * that may open with a formula character, and numbers.
 */
const cellArb = fc.oneof(
  fc.string(),
  fc.tuple(fc.constantFrom(...FORMULA_LEADS), fc.string()).map(([lead, rest]) => lead + rest),
  fc.double({ noNaN: true }),
  fc.integer(),
  fc.boolean(),
);

describe("csvExport (Property 14: cells round-trip and never become formulas)", () => {
  it("parses back to the original value, or to it behind one apostrophe", () => {
    fc.assert(
      fc.property(fc.array(cellArb, { minLength: 1, maxLength: 6 }), (cells) => {
        const csv = toCsvString(
          cells.map((_, i) => `col${i}`),
          [cells as (string | number | boolean)[]],
        );
        const parsed = parseCsv(csv);

        expect(parsed).toHaveLength(2);
        expect(parsed[1]).toHaveLength(cells.length);

        parsed[1].forEach((got, i) => {
          const original = String(cells[i]);
          // Either untouched, or the same value behind exactly one apostrophe.
          expect(got === original || got === `'${original}`).toBe(true);
          // And unless the value is a number, nothing a spreadsheet would
          // evaluate leads it. A number is exempt because -1 leading with "-"
          // is the point: it is meant to arrive as the number minus one, and
          // quoting it would import every numeric column as text.
          if (typeof cells[i] !== "number") {
            expect(FORMULA_LEADS.includes(got.charAt(0))).toBe(false);
          }
        });
      }),
      { numRuns: 100 },
    );
  });

  it("neutralises exactly when the value leads with a formula character", () => {
    fc.assert(
      fc.property(fc.string(), (text) => {
        const escaped = escapeCsvCell(text);
        const wasFormula = FORMULA_LEADS.includes(text.charAt(0));
        // The apostrophe is added for those values and for no others, so a note
        // that reads as text keeps reading as text.
        expect(escaped.replace(/^"/, "").startsWith("'")).toBe(
          wasFormula || text.startsWith("'"),
        );
      }),
      { numRuns: 100 },
    );
  });
});
