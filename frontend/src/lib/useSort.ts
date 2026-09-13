// Sortable table state, shared by every fleet and finding table (Req 13.4).
//
// No table in the app was sortable. On a fleet view, "which hosts have the most
// criticals" is the first question anyone asks, and the answer was whatever
// order the backend happened to return.

import { useCallback, useMemo, useState } from "react";

export type SortDirection = "asc" | "desc";

export interface SortState<K extends string> {
  key: K | null;
  direction: SortDirection;
}

export interface SortApi<K extends string, T> {
  sort: SortState<K>;
  /** Toggle sorting by `key`: first click descending, second ascending. */
  toggle: (key: K) => void;
  /** Props for a sortable `<th>`, including `aria-sort` and keyboard support. */
  headerProps: (key: K) => {
    "aria-sort": "ascending" | "descending" | "none";
    onClick: () => void;
    onKeyDown: (event: { key: string; preventDefault: () => void }) => void;
    tabIndex: 0;
    role: "columnheader button";
    className: string;
  };
  /** `rows` ordered by the current sort, or unchanged when nothing is sorted. */
  sorted: T[];
}

/**
 * @param rows Rows to sort.
 * @param accessors Comparable value per sort key.
 * @param initial Key sorted on first render, if any.
 *
 * Descending is the first direction because every sortable column here answers
 * a "worst first" question -- most criticals, oldest scan, highest CVSS.
 */
export function useSort<K extends string, T>(
  rows: T[],
  accessors: Record<K, (row: T) => string | number | null | undefined>,
  initial?: K,
): SortApi<K, T> {
  const [sort, setSort] = useState<SortState<K>>({
    key: initial ?? null,
    direction: "desc",
  });

  const toggle = useCallback((key: K) => {
    setSort((current) =>
      current.key === key
        ? { key, direction: current.direction === "desc" ? "asc" : "desc" }
        : { key, direction: "desc" },
    );
  }, []);

  const sorted = useMemo(() => {
    if (!sort.key) return rows;
    const accessor = accessors[sort.key];
    if (!accessor) return rows;

    const factor = sort.direction === "asc" ? 1 : -1;
    // Copy first: Array.prototype.sort mutates, and `rows` is usually a memo
    // shared with other consumers.
    return [...rows].sort((a, b) => {
      const left = accessor(a);
      const right = accessor(b);

      // Nulls sort last regardless of direction: "never scanned" is not
      // meaningfully older or newer than a real timestamp, and burying it under
      // real data in one direction only would be surprising.
      if (left == null && right == null) return 0;
      if (left == null) return 1;
      if (right == null) return -1;

      if (typeof left === "number" && typeof right === "number") {
        return (left - right) * factor;
      }
      return String(left).localeCompare(String(right), undefined, {
        numeric: true,
        sensitivity: "base",
      }) * factor;
    });
  }, [rows, sort, accessors]);

  const headerProps = useCallback(
    (key: K) => ({
      "aria-sort": (sort.key === key
        ? sort.direction === "asc"
          ? "ascending"
          : "descending"
        : "none") as "ascending" | "descending" | "none",
      onClick: () => toggle(key),
      onKeyDown: (event: { key: string; preventDefault: () => void }) => {
        if (event.key === "Enter" || event.key === " ") {
          event.preventDefault();
          toggle(key);
        }
      },
      tabIndex: 0 as const,
      role: "columnheader button" as const,
      className: sort.key === key ? `sortable sorted-${sort.direction}` : "sortable",
    }),
    [sort, toggle],
  );

  return { sort, toggle, headerProps, sorted };
}

/** Arrow indicating a column's sort state, for rendering inside a header. */
export function sortIndicator<K extends string>(
  sort: SortState<K>,
  key: K,
): string {
  if (sort.key !== key) return "";
  return sort.direction === "asc" ? " ▲" : " ▼";
}
