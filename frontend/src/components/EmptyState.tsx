// Empty states that name the actual reason a list is empty, and offer to clear
// the filters responsible (Req 13.5).
//
// The previous messages guessed, and guessed wrong. The fleet view rendered
// `No machines match ""` whenever the *platform* filter was what excluded the
// rows, because it assumed the search box was responsible. The drill-down said
// "No CVEs match the selected severity" even when the exclusion came from the
// search box or the patch filter. A user reading either one would go and adjust
// the wrong control.

import type { ReactNode } from "react";

export interface ActiveFilter {
  /** Human-readable name of the filter, e.g. "platform". */
  label: string;
  /** Its current value, shown so the user can see what to undo. */
  value: string;
}

export interface EmptyStateProps {
  title: string;
  /** Filters currently excluding rows, named so the user knows what to clear. */
  filters?: ActiveFilter[];
  /** Clears every active filter. Omitted when there is nothing to clear. */
  onClearFilters?: () => void;
  /** A primary action for the genuinely-empty (not filtered) case. */
  action?: ReactNode;
  children?: ReactNode;
}

export function EmptyState({
  title,
  filters = [],
  onClearFilters,
  action,
  children,
}: EmptyStateProps) {
  const active = filters.filter((filter) => filter.value);

  return (
    <div className="empty-state" role="status">
      <p className="empty-state-title">{title}</p>

      {active.length > 0 && (
        <p className="empty-state-detail">
          Active {active.length === 1 ? "filter" : "filters"}:{" "}
          {active.map((filter, index) => (
            <span key={filter.label}>
              {index > 0 ? ", " : ""}
              {filter.label} = <strong>{filter.value}</strong>
            </span>
          ))}
        </p>
      )}

      {children && <p className="empty-state-detail">{children}</p>}

      <div className="empty-state-actions">
        {active.length > 0 && onClearFilters && (
          <button type="button" className="pagination-btn" onClick={onClearFilters}>
            Clear filters
          </button>
        )}
        {action}
      </div>
    </div>
  );
}
