import { act, renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { sortIndicator, useSort } from "./useSort";

interface Row {
  name: string;
  criticals: number;
  scannedAt: number | null;
}

const rows: Row[] = [
  { name: "web-02", criticals: 3, scannedAt: 200 },
  { name: "db-01", criticals: 12, scannedAt: 100 },
  { name: "app-10", criticals: 0, scannedAt: null },
];

const accessors = {
  name: (r: Row) => r.name,
  criticals: (r: Row) => r.criticals,
  scannedAt: (r: Row) => r.scannedAt,
};

function setup(initial?: keyof typeof accessors) {
  return renderHook(() => useSort(rows, accessors, initial));
}

describe("useSort", () => {
  it("leaves rows untouched until a column is chosen", () => {
    const { result } = setup();
    expect(result.current.sorted).toEqual(rows);
  });

  it("sorts descending on first toggle", () => {
    // Every sortable column here answers a "worst first" question, so the
    // first click should show the worst rows.
    const { result } = setup();
    act(() => result.current.toggle("criticals"));
    expect(result.current.sorted.map((r) => r.criticals)).toEqual([12, 3, 0]);
  });

  it("reverses on a second toggle of the same column", () => {
    const { result } = setup();
    act(() => result.current.toggle("criticals"));
    act(() => result.current.toggle("criticals"));
    expect(result.current.sorted.map((r) => r.criticals)).toEqual([0, 3, 12]);
  });

  it("restarts descending when switching columns", () => {
    const { result } = setup();
    act(() => result.current.toggle("criticals"));
    act(() => result.current.toggle("criticals")); // now ascending
    act(() => result.current.toggle("name"));
    expect(result.current.sort).toEqual({ key: "name", direction: "desc" });
  });

  it("sorts nulls last in both directions", () => {
    // "Never scanned" is not meaningfully older or newer than a real
    // timestamp, so burying it under real data in one direction only would be
    // surprising.
    const { result } = setup();
    const last = () => result.current.sorted[result.current.sorted.length - 1];
    act(() => result.current.toggle("scannedAt"));
    expect(last().scannedAt).toBeNull();
    act(() => result.current.toggle("scannedAt"));
    expect(last().scannedAt).toBeNull();
  });

  it("sorts strings naturally, so app-10 follows app-9", () => {
    const natural = renderHook(() =>
      useSort(
        [{ name: "app-9" }, { name: "app-10" }, { name: "app-1" }],
        { name: (r: { name: string }) => r.name },
      ),
    );
    act(() => natural.result.current.toggle("name"));
    expect(natural.result.current.sorted.map((r) => r.name)).toEqual([
      "app-10",
      "app-9",
      "app-1",
    ]);
  });

  it("does not mutate the input array", () => {
    // `rows` is typically a memo shared with other consumers.
    const snapshot = [...rows];
    const { result } = setup();
    act(() => result.current.toggle("criticals"));
    expect(rows).toEqual(snapshot);
  });

  it("exposes aria-sort reflecting the current column and direction", () => {
    const { result } = setup();
    expect(result.current.headerProps("name")["aria-sort"]).toBe("none");
    act(() => result.current.toggle("name"));
    expect(result.current.headerProps("name")["aria-sort"]).toBe("descending");
    expect(result.current.headerProps("criticals")["aria-sort"]).toBe("none");
    act(() => result.current.toggle("name"));
    expect(result.current.headerProps("name")["aria-sort"]).toBe("ascending");
  });

  it("activates on Enter and Space", () => {
    const { result } = setup();
    const preventDefault = () => undefined;
    act(() => result.current.headerProps("name").onKeyDown({ key: "Enter", preventDefault }));
    expect(result.current.sort.key).toBe("name");
    act(() => result.current.headerProps("criticals").onKeyDown({ key: " ", preventDefault }));
    expect(result.current.sort.key).toBe("criticals");
  });

  it("ignores other keys", () => {
    const { result } = setup();
    act(() =>
      result.current.headerProps("name").onKeyDown({ key: "a", preventDefault: () => undefined }),
    );
    expect(result.current.sort.key).toBeNull();
  });
});

describe("sortIndicator", () => {
  it("marks only the sorted column", () => {
    expect(sortIndicator({ key: "name", direction: "desc" }, "name")).toBe(" ▼");
    expect(sortIndicator({ key: "name", direction: "asc" }, "name")).toBe(" ▲");
    expect(sortIndicator({ key: "name", direction: "asc" }, "other")).toBe("");
  });
});
