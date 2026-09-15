// Wording for what a host's last scan changed (Req 18.6).

import { describe, expect, it } from "vitest";
import { scanDelta } from "./scanDelta";

describe("scanDelta", () => {
  it("says nothing for a host with no successful scan", () => {
    expect(scanDelta({ lastScanNew: null, lastScanResolved: null, lastScanBaseline: false })).toBeNull();
  });

  it("calls a baseline a baseline, with nothing to flag in the fleet view", () => {
    const delta = scanDelta({ lastScanNew: null, lastScanResolved: null, lastScanBaseline: true });
    expect(delta?.short).toBeNull();
    expect(delta?.long).toMatch(/baseline/i);
  });

  it("never turns a partial scan's unassessed resolved count into zero (Req 18.3)", () => {
    const delta = scanDelta({ lastScanNew: 2, lastScanResolved: null, lastScanBaseline: false });
    expect(delta?.short).toBe("+2 new");
    expect(delta?.long).toMatch(/not assessed/);
    expect(delta?.long).not.toMatch(/0 resolved/);
  });

  it("states units, singular and plural", () => {
    const delta = scanDelta({ lastScanNew: 1, lastScanResolved: 5, lastScanBaseline: false });
    expect(delta?.short).toBe("+1 new / −5 resolved");
    expect(delta?.long).toBe("Since the previous scan: 1 new finding, 5 resolved findings.");
  });

  it("reports an unchanged host plainly, without a fleet-view badge", () => {
    const delta = scanDelta({ lastScanNew: 0, lastScanResolved: 0, lastScanBaseline: false });
    expect(delta?.short).toBeNull();
    expect(delta?.long).toBe("No change since the previous scan.");
  });
});
