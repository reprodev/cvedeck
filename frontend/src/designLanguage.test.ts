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

  it("renders no emoji", () => {
    const offenders: string[] = [];
    for (const [path, text] of Object.entries(sources)) {
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
