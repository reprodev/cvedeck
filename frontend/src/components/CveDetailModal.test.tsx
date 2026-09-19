// Tests for the CVE detail modal's header badge, and its dialog contract.
//
// 0.8.6 made cvssScore nullable and added the Unscored band, but this file did
// not exist and the modal's badge rendered `CVSS {finding.cvssScore}` with no
// guard. React renders null as nothing, so an unscored finding displayed
// "Unscored • CVSS" -- a label with no number after it. Neither `tsc` nor the
// property tests can see JSX text, so nothing failed.
//
// These tests therefore assert the rendered STRING, not just that the component
// mounts. That is the only check that would have caught it.

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { CveDetailModal } from "./CveDetailModal";
import type { CveFinding } from "../types";

function finding(overrides: Partial<CveFinding> = {}): CveFinding {
  return {
    cveId: "CVE-2024-1000",
    severity: "critical",
    cvssScore: 9.8,
    packageIdentifier: "Ubuntu:22.04:openssl@3.0.2",
    remediationStatus: null,
    remediationRecordId: null,
    remediationNote: null,
    dependencies: [],
    dependedOnBy: [],
    ...overrides,
  };
}

function openModal(f: CveFinding, onClose: () => void = () => {}) {
  return render(
    <CveDetailModal
      finding={f}
      platform="linux"
      osName="Ubuntu"
      hostname="web-01"
      onClose={onClose}
    />,
  );
}

/** The severity/score badge in the modal header. */
function severityBadge(severity: string): HTMLElement {
  const badge = document.querySelector(`.badge-${severity}`);
  expect(badge).not.toBeNull();
  return badge as HTMLElement;
}

describe("CveDetailModal header badge", () => {
  it("says no score was published rather than leaving a dangling CVSS label", () => {
    // The regression: an advisory nobody scored (Req 2.7).
    openModal(finding({ severity: "unscored", cvssScore: null }));

    const badge = severityBadge("unscored");
    expect(badge.textContent).toBe("Unscored • No published CVSS");
    // The shape of the bug, stated as itself: "• CVSS" with nothing after it.
    expect(badge.textContent).not.toMatch(/•\s*CVSS\s*$/);
  });

  it("keeps a published band while reporting no score (Req 2.6)", () => {
    // A feed that publishes the word "HIGH" and no vector. The band is real;
    // the number was never published. Severity and score are independent.
    openModal(finding({ severity: "high", cvssScore: null }));

    expect(severityBadge("high").textContent).toBe("High • No published CVSS");
  });

  it("still renders a measured score", () => {
    openModal(finding({ severity: "critical", cvssScore: 9.8 }));

    expect(severityBadge("critical").textContent).toBe("Critical • CVSS 9.8");
  });

  it("renders a whole-number score to one decimal", () => {
    // Consistent with ScanHistoryPanel, which has always used toFixed(1).
    openModal(finding({ severity: "high", cvssScore: 7 }));

    expect(severityBadge("high").textContent).toBe("High • CVSS 7.0");
  });
});

describe("CveDetailModal dialog contract", () => {
  it("is a dialog named after the CVE it describes", () => {
    openModal(finding({ cveId: "CVE-2024-3094" }));

    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveAccessibleName(/CVE-2024-3094/);
  });

  it("closes on Escape", async () => {
    const user = userEvent.setup();
    const onClose = vi.fn();
    openModal(finding(), onClose);

    await user.keyboard("{Escape}");

    expect(onClose).toHaveBeenCalled();
  });
});
