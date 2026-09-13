// Tests for URL-backed navigation.
//
// The parsing half is pure and gets the bulk of the coverage, including the
// hand-edited and truncated URLs that a shareable link invites. The hook half
// covers the two behaviours that make a link worth sharing at all: a route
// survives a reload, and back returns to where you were.

import { act, renderHook } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import {
  DEFAULT_ROUTE,
  formatHash,
  parseHash,
  useUrlState,
} from "./useUrlState";

beforeEach(() => {
  window.location.hash = "";
});

describe("parseHash", () => {
  it("treats an empty hash as the default route", () => {
    expect(parseHash("")).toEqual(DEFAULT_ROUTE);
    expect(parseHash("#")).toEqual(DEFAULT_ROUTE);
    expect(parseHash("#/")).toEqual(DEFAULT_ROUTE);
  });

  it("parses each workspace", () => {
    expect(parseHash("#/fleet")).toEqual({ workspace: "fleet", machineId: null });
    expect(parseHash("#/scan")).toEqual({ workspace: "scan", machineId: null });
    expect(parseHash("#/discovery")).toEqual({
      workspace: "discovery",
      machineId: null,
    });
  });

  it("parses a machine drill-down", () => {
    expect(parseHash("#/machines/web-01")).toEqual({
      workspace: "fleet",
      machineId: "web-01",
    });
  });

  it("decodes a machine id containing reserved characters", () => {
    // Machine ids are hostnames or IPs, and a hostname can legitimately carry
    // characters that must be escaped in a fragment.
    expect(parseHash("#/machines/host%20one.lan").machineId).toBe("host one.lan");
    expect(parseHash("#/machines/10.0.0.1").machineId).toBe("10.0.0.1");
  });

  it("falls back to the default for an unknown route", () => {
    // A shared link invites hand-editing and truncation. Landing somewhere
    // useful beats rendering nothing.
    expect(parseHash("#/nonsense")).toEqual(DEFAULT_ROUTE);
    expect(parseHash("#/machines")).toEqual(DEFAULT_ROUTE);
    expect(parseHash("#/machines/")).toEqual(DEFAULT_ROUTE);
  });

  it("tolerates a missing leading slash", () => {
    expect(parseHash("#scan")).toEqual({ workspace: "scan", machineId: null });
  });

  it("never throws on arbitrary input", () => {
    for (const hash of ["#/%", "#///", "#/machines/%E0%A4%A", "#/a/b/c/d"]) {
      expect(() => parseHash(hash)).not.toThrow();
    }
  });
});

describe("formatHash", () => {
  it("round-trips every workspace", () => {
    for (const workspace of ["fleet", "scan", "discovery"] as const) {
      const route = { workspace, machineId: null };
      expect(parseHash(formatHash(route))).toEqual(route);
    }
  });

  it("round-trips a machine id needing encoding", () => {
    const route = { workspace: "fleet" as const, machineId: "host one.lan" };
    expect(parseHash(formatHash(route))).toEqual(route);
  });

  it("encodes rather than emitting a raw space", () => {
    expect(formatHash({ workspace: "fleet", machineId: "a b" })).toBe(
      "#/machines/a%20b",
    );
  });
});

describe("useUrlState", () => {
  it("reads the initial route from the URL", () => {
    // The point of the whole module: a pasted link opens that host.
    window.location.hash = "#/machines/db-primary";

    const { result } = renderHook(() => useUrlState());

    expect(result.current.route).toEqual({
      workspace: "fleet",
      machineId: "db-primary",
    });
  });

  it("writes the route to the URL when navigating", () => {
    const { result } = renderHook(() => useUrlState());

    act(() => result.current.navigate({ workspace: "scan", machineId: null }));

    expect(window.location.hash).toBe("#/scan");
    expect(result.current.route.workspace).toBe("scan");
  });

  it("responds to a hash change from outside", () => {
    // This is what makes browser back work: the button changes the hash, and
    // the app follows.
    const { result } = renderHook(() => useUrlState());

    act(() => {
      window.location.hash = "#/machines/web-01";
      window.dispatchEvent(new HashChangeEvent("hashchange"));
    });

    expect(result.current.route.machineId).toBe("web-01");
  });

  it("does not re-push a route already in the URL", () => {
    // A duplicate entry makes the first back press appear to do nothing.
    window.location.hash = "#/scan";
    const before = window.history.length;

    const { result } = renderHook(() => useUrlState());
    act(() => result.current.navigate({ workspace: "scan", machineId: null }));

    expect(window.history.length).toBe(before);
  });

  it("replaces without adding a history entry", () => {
    const { result } = renderHook(() => useUrlState());
    const before = window.history.length;

    act(() => result.current.replace({ workspace: "discovery", machineId: null }));

    expect(window.location.hash).toBe("#/discovery");
    expect(window.history.length).toBe(before);
  });
});
