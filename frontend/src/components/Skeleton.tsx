/* Loading placeholders.
 *
 * The fleet list previously had no loading affordance at all: the initial fetch
 * rendered an empty table, so the first thing a new user saw was a screen that
 * looks identical to "you have no machines" and to "the backend is down". On a
 * cold container -- which is exactly when someone is evaluating the thing --
 * that gap is long enough to read as broken.
 *
 * A skeleton is used rather than a spinner because the shape of what is coming
 * is known, and showing that shape makes the wait feel shorter than a spinner
 * that says only "something is happening".
 *
 * The pulse is defined in index.css and is disabled under
 * prefers-reduced-motion, where these degrade to static blocks.
 */

export interface SkeletonProps {
  /** CSS width, e.g. "60%" or "4rem". Defaults to filling its container. */
  width?: string;
  className?: string;
}

/** One shimmering block, sized to the text it stands in for. */
export function Skeleton({ width, className }: SkeletonProps) {
  return (
    <span
      className={className ? `skeleton ${className}` : "skeleton"}
      style={width ? { width } : undefined}
      aria-hidden="true"
    />
  );
}

export interface SkeletonRowsProps {
  /** How many placeholder rows to draw. */
  rows?: number;
  /** How many cells per row. Should match the real table's column count. */
  columns: number;
}

/**
 * Placeholder rows for a table body.
 *
 * Widths are deliberately uneven and deterministic: a column of identical bars
 * reads as a rendering bug, and a random width per render makes the skeleton
 * flicker on every re-render while loading.
 */
export function SkeletonRows({ rows = 5, columns }: SkeletonRowsProps) {
  const widths = ["70%", "45%", "60%", "35%", "55%", "40%", "65%", "50%"];

  return (
    <>
      {Array.from({ length: rows }, (_, r) => (
        <tr key={r} className="skeleton-row">
          {Array.from({ length: columns }, (_, c) => (
            <td key={c}>
              <Skeleton width={widths[(r * columns + c) % widths.length]} />
            </td>
          ))}
        </tr>
      ))}
    </>
  );
}
