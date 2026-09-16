import "@testing-library/jest-dom/vitest";
import { configure } from "@testing-library/react";

// How long `findBy*` and `waitFor` keep retrying before giving up.
//
// Testing-library's default is 1000ms, which is a claim about how fast a
// machine is rather than about the code. A push was refused when the first
// render in App.e2e.test.tsx took 2135ms on a loaded machine -- every later
// test in that same file passed, because only the first pays the cold cost.
//
// 5000ms is roughly 2.3x the slowest render anyone has measured here, rather
// than a number set just above the one failure we happened to see. It stays
// well under `testTimeout: 20_000` in vite.config.ts, and that gap is the
// point: a query that will never match still fails as testing-library's
// "Unable to find an element..." with the rendered DOM printed, which is
// diagnosable, instead of as a bare test timeout, which is not. Raising this
// to the test timeout would trade every useful failure message for that one.
configure({ asyncUtilTimeout: 5000 });
