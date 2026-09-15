// What a host's latest successful scan changed, in words (Req 18.6).
//
// One home for the wording, because the fleet view and the host page must not
// disagree about it -- and because the rule that matters is easy to break in
// two places: a count the scan did not assess is null, and null is never
// rendered as zero. "0 resolved" after a partial scan would say an unreachable
// advisory source proved nothing was patched, which is the opposite of true.

export interface ScanDeltaInput {
  lastScanNew: number | null;
  lastScanResolved: number | null;
  lastScanBaseline: boolean;
}

export interface ScanDelta {
  /** Compact form for the fleet table, or null when there is nothing to flag. */
  short: string | null;
  /** Full sentence for the host page and for tooltips. */
  long: string;
}

/** "1 new finding" / "3 new findings". The unit is the point. */
function findings(n: number, adjective: string): string {
  return `${n} ${adjective} finding${n === 1 ? "" : "s"}`;
}

/** Describe a host's latest successful scan, or null when it has none. */
export function scanDelta(machine: ScanDeltaInput): ScanDelta | null {
  const { lastScanNew: added, lastScanResolved: resolved, lastScanBaseline } = machine;

  if (lastScanBaseline) {
    return { short: null, long: "Baseline scan: nothing earlier to compare with yet." };
  }
  if (added === null) return null;

  if (resolved === null) {
    return {
      short: `+${added} new`,
      long:
        `Partial scan: ${findings(added, "new")}. Resolved findings were not ` +
        "assessed, because an advisory source did not answer.",
    };
  }

  if (added === 0 && resolved === 0) {
    return { short: null, long: "No change since the previous scan." };
  }
  return {
    short: `+${added} new / −${resolved} resolved`,
    long: `Since the previous scan: ${findings(added, "new")}, ${findings(resolved, "resolved")}.`,
  };
}
