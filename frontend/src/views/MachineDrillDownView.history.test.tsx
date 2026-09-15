// Scan history on the host page (Req 18.6, 18.9).

import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MachineDrillDownView } from "./MachineDrillDownView";
import { makeFinding } from "../test-utils/factories";
import type { FindingChangeRow, ScanRun } from "../types";

const findings = [
  makeFinding({ cveId: "CVE-2026-0001", severity: "high", packageIdentifier: "Debian:13:openssl@3.0.2", isNew: true, firstSeenAt: "2026-09-15T10:00:00Z" }),
  makeFinding({ cveId: "CVE-2026-0002", severity: "high", packageIdentifier: "Debian:13:curl@8.0", isNew: false, firstSeenAt: "2026-08-01T10:00:00Z" }),
];

const runs: ScanRun[] = [
  { runId: "r3", scannedAt: "2026-09-15T10:00:00Z", status: "success", sourcesOk: false, findingCount: 2, newCount: 1, resolvedCount: null, baseline: false },
  { runId: "r2", scannedAt: "2026-09-14T10:00:00Z", status: "connection_failure", sourcesOk: true, findingCount: 0, newCount: null, resolvedCount: null, baseline: false },
  { runId: "r1", scannedAt: "2026-09-10T10:00:00Z", status: "success", sourcesOk: true, findingCount: 1, newCount: null, resolvedCount: null, baseline: true },
];

const changes: FindingChangeRow[] = [
  { change: "new", cveId: "CVE-2026-0001", packageIdentifier: "Debian:13:openssl@3.0.2", packageName: "openssl", severity: "high", cvssScore: 7.5, kevListed: false, remediationStatus: null },
  { change: "resolved", cveId: "CVE-2026-0009", packageIdentifier: "Debian:13:glibc@2.36", packageName: "glibc", severity: "critical", cvssScore: 9.8, kevListed: true, remediationStatus: "in_progress" },
];

describe("what the last scan changed", () => {
  it("states the partial scan's counts without inventing a resolved zero", () => {
    render(<MachineDrillDownView machineId="m1" findings={findings} lastScanNew={1} lastScanResolved={null} />);

    expect(screen.getByTestId("scan-delta")).toHaveTextContent(/1 new finding.*not assessed/);
  });

  it("marks new findings and filters to them", async () => {
    const user = userEvent.setup();
    render(<MachineDrillDownView machineId="m1" findings={findings} lastScanNew={1} lastScanResolved={0} />);

    const newRow = screen.getByText("CVE-2026-0001").closest("tr")!;
    expect(within(newRow as HTMLElement).getByText("New")).toHaveClass("badge-new");
    expect(screen.getByRole("columnheader", { name: "First seen" })).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: "New 1" }));
    expect(screen.getByText("CVE-2026-0001")).toBeInTheDocument();
    expect(screen.queryByText("CVE-2026-0002")).not.toBeInTheDocument();
  });
});

describe("scan history panel", () => {
  it("loads on first open, and shows unassessed counts as a dash with a reason", async () => {
    const user = userEvent.setup();
    const onLoadScanRuns = vi.fn().mockResolvedValue(runs);
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={findings}
        onLoadScanRuns={onLoadScanRuns}
        onLoadScanChanges={vi.fn()}
      />,
    );
    expect(onLoadScanRuns).not.toHaveBeenCalled();

    await user.click(screen.getByText("Scan history"));
    const table = await within(screen.getByTestId("scan-history")).findByRole("table");
    const rows = within(table).getAllByRole("row").slice(1);

    expect(onLoadScanRuns).toHaveBeenCalledTimes(1);
    expect(rows[0]).toHaveTextContent("Partial");
    expect(within(rows[0]).getAllByRole("cell")[4]).toHaveTextContent("—");
    expect(within(within(rows[0]).getAllByRole("cell")[4]).getByTitle(/source did not answer/)).toBeInTheDocument();
    expect(rows[1]).toHaveTextContent("Could not connect");
    expect(rows[2]).toHaveTextContent("Baseline");
    expect(within(rows[2]).queryByRole("button")).not.toBeInTheDocument();
  });

  it("expands a run's changes, and flags a cleared finding whose record is still open (Req 18.9)", async () => {
    const user = userEvent.setup();
    const onLoadScanChanges = vi.fn().mockResolvedValue(changes);
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={findings}
        onLoadScanRuns={vi.fn().mockResolvedValue(runs)}
        onLoadScanChanges={onLoadScanChanges}
      />,
    );

    await user.click(screen.getByText("Scan history"));
    await user.click(await screen.findByRole("button", { name: "Show changes" }));

    expect(onLoadScanChanges).toHaveBeenCalledWith("r3");
    const resolved = (await screen.findByText("CVE-2026-0009")).closest("li")!;
    expect(resolved).toHaveAttribute("data-change", "resolved");
    expect(resolved).toHaveTextContent("Cleared by this scan; its remediation record is still In Progress.");
  });
});
