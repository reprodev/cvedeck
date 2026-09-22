/// <reference types="vite/client" />
// The palette carries the ranking: red is exploitation, and nothing else.
//
// Both rules below were broken in shipped code without a test noticing. A
// "high blast radius" badge, a purge button and a close-button hover all used
// --exploit, and a blast-radius cell still led with a red-circle emoji after
// the sweep that replaced every emoji with an icon -- so a package with many
// dependents sat beside a CVE CISA says is being exploited, at the same volume.

import { beforeAll, describe, expect, it } from "vitest";

// Not an import: Vitest hands a stylesheet's `?raw` import back as an empty
// string, which would make the CSS check pass vacuously. The specifier is built
// so TypeScript does not need Node's types for a test-only read.
const nodeModule = (name: string) => import(/* @vite-ignore */ `node:${name}`);
let css = "";
beforeAll(async () => {
  // Under jsdom import.meta.url is not a file URL, so resolve from the project
  // root, which is where Vitest runs.
  const [fs, path, proc] = await Promise.all(
    ["fs", "path", "process"].map(nodeModule),
  );
  css = fs.readFileSync(path.join(proc.cwd(), "src", "index.css"), "utf8");
});

const sources = import.meta.glob<string>(
  ["./**/*.{ts,tsx}", "!./**/*.test.{ts,tsx}"],
  { query: "?raw", import: "default", eager: true },
);

/** Each rule's selector paired with its declarations, comments stripped. */
function rules(stylesheet: string): { selector: string; body: string }[] {
  const plain = stylesheet.replace(/\/\*[\s\S]*?\*\//g, "");
  return [...plain.matchAll(/([^{}]+)\{([^{}]*)\}/g)].map((m) => ({
    selector: m[1].trim(),
    body: m[2],
  }));
}

// A pictograph renders in colour whatever the stylesheet says, so it bypasses
// the palette entirely. Glyphs that render as text without a variation
// selector -- the close cross, the external-link arrow, the pager arrows -- stay.
const EMOJI = /\p{Extended_Pictographic}/u;
const TEXT_GLYPHS = new Set(["✕", "↗", "◀", "▶"]);

describe("design language", () => {
  it("reads the sources it guards", () => {
    // An empty glob would make every check below pass vacuously.
    expect(Object.keys(sources)).toContain("./views/MachineDrillDownView.tsx");
    expect(css).toContain("--exploit:");
  });

  it("uses the exploitation red only on exploitation", () => {
    const offenders = rules(css)
      .filter((r) => /var\(--exploit\)/.test(r.body))
      .map((r) => r.selector)
      .filter((selector) => !/exploit/.test(selector));

    expect(offenders).toEqual([]);
  });

  it("uses the exploitation red inline only for exploitation", () => {
    const offenders = Object.entries(sources)
      .filter(([, text]) => text.includes("var(--exploit)"))
      .map(([path]) => path);

    expect(offenders).toEqual([]);
  });

  it("labels every table cell that reflows into a card", () => {
    // At phone width `.table-container` tables become cards: the header row is
    // visually hidden and each cell prints `attr(data-label)` instead. A cell
    // without one renders as an unlabelled value under no heading at all.
    //
    // Scoped by `<table`, not by the presence of the string "table-container".
    // Keying on the class name meant a table was in scope only once it was
    // already inside the card system, so every table left out of it was exempt
    // precisely because it was the offender -- the discovery sweep's and both
    // of Settings', all three carrying correct data-labels that nothing read.
    // A guard that selects its subjects by whether they already comply is not
    // a guard.
    const offenders: string[] = [];
    for (const [path, text] of Object.entries(sources)) {
      if (!/<table[\s>]/.test(text)) continue;
      // Body cells only: `<td` inside a row, not the `<th>` header cells.
      const cells = text.match(/<td(\s[^>]*)?>/g) ?? [];
      for (const cell of cells) {
        // `host-col`, `select-col` and `token-actions` are exempt in the
        // stylesheet itself: the hostname is the card's title, and neither a
        // checkbox nor a row of buttons wants a label in front of it, so all
        // three have `::before { display: none }`. A cell spanning the row is
        // the expanded drawer, which carries its own heading.
        const exempt =
          /className="(host-col|select-col|token-actions)"/.test(cell) ||
          cell.includes("colSpan");
        if (!cell.includes("data-label") && !exempt) {
          offenders.push(`${path} ${cell}`);
        }
      }
    }

    expect(offenders).toEqual([]);
  });

  it("puts every table in the card system", () => {
    // The labels above only do anything inside `.table-container`, which is
    // what prints `attr(data-label)` at phone width. A table outside it keeps
    // its header row and scrolls sideways instead, so its labels are inert --
    // which is what the discovery sweep's table and both of Settings' did,
    // correctly labelled and never reflowing, for as long as the check above
    // could not see them.
    const offenders = Object.entries(sources)
      .filter(([, text]) => /<table[\s>]/.test(text))
      .filter(([, text]) => !text.includes("table-container"))
      .map(([path]) => path);

    expect(offenders).toEqual([]);
  });

  it("renders no emoji", () => {
    const offenders: string[] = [];
    // The stylesheet is scanned alongside the sources: `content: "..."` can
    // inject a pictograph, and a pictograph renders in its own colour whatever
    // the palette says -- the very reason this rule exists. Scanning only the
    // components left the one file that can bypass the palette by construction
    // unexamined.
    for (const [path, text] of [...Object.entries(sources), ["src/index.css", css]] as [
      string,
      string,
    ][]) {
      text.split("\n").forEach((line, i) => {
        const found = [...line].filter(
          (ch) => EMOJI.test(ch) && !TEXT_GLYPHS.has(ch),
        );
        if (found.length > 0) offenders.push(`${path}:${i + 1} ${found.join("")}`);
      });
    }

    expect(offenders).toEqual([]);
  });
});
