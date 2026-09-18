// Example-based rendering tests for MachineListView.
//
// Requirements covered:
//   3.1 - the dashboard displays a list of scanned machines
//   3.2 - each machine shows its CVE counts grouped by severity
//   10.8 - Windows hosts are never sent for scanning
//
// These are example tests (per design.md "Testing Strategy": dashboard list
// rendering, 3.1). Pure filter/count logic is covered separately by the
// property tests in src/lib.

import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MachineListView } from "./MachineListView";
import type { MachineSummary } from "../types";
import { makeMachine } from "../test-utils/factories";

const machines: MachineSummary[] = [
  makeMachine({
    machineId: "m1",
    hostname: "web-01",
    platform: "linux",
    lastScanStatus: "success",
    cveCounts: { critical: 2, unscored: 0, high: 3, medium: 1, low: 4 },
  }),
  makeMachine({
    machineId: "m2",
    hostname: "db-01",
    platform: "windows",
    lastScanStatus: "connection_failure",
    cveCounts: { critical: 0, unscored: 0, high: 1, medium: 5, low: 0 },
  }),
];

describe("MachineListView", () => {
  it("renders a row for each scanned machine (Req 3.1)", () => {
    render(<MachineListView machines={machines} />);

    // Each machine's hostname is rendered as a selectable row.
    expect(
      screen.getByRole("button", { name: "web-01" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "db-01" })).toBeInTheDocument();

    // Two data rows, one per machine (header row excluded).
    const rows = screen.getAllByRole("row");
    expect(rows).toHaveLength(machines.length + 1);
  });

  it("shows severity-grouped CVE counts for each machine (Req 3.2)", () => {
    render(<MachineListView machines={machines} />);

    const webRow = screen.getByRole("button", { name: "web-01" }).closest("tr");
    expect(webRow).not.toBeNull();
    const webCells = within(webRow as HTMLElement).getAllByRole("cell");
    // Cells: hostname, platform, status, last scanned, exploited, critical,
    // unscored, high, medium, low — unscored sits between critical and high,
    // which is the triage rank (Req 10.11).
    expect(webCells[1]).toHaveTextContent("linux");
    // The status column renders a human label, not the raw enum value.
    expect(webCells[2]).toHaveTextContent("Success");
    expect(webCells[5]).toHaveTextContent("2"); // critical
    expect(webCells[6]).toHaveTextContent("0"); // unscored
    expect(webCells[7]).toHaveTextContent("3"); // high
    expect(webCells[8]).toHaveTextContent("1"); // medium
    expect(webCells[9]).toHaveTextContent("4"); // low
  });

  it("renders a header column for each severity level (Req 3.2)", () => {
    render(<MachineListView machines={machines} />);

    for (const label of ["Critical", "High", "Medium", "Low"]) {
      expect(
        screen.getByRole("columnheader", { name: label }),
      ).toBeInTheDocument();
    }
  });

  it("shows an empty-state message when there are no machines (Req 3.1)", () => {
    render(<MachineListView machines={[]} />);

    expect(screen.getByText("No machines yet.")).toBeInTheDocument();
    // The first-run state points somewhere rather than just reporting emptiness.
    expect(screen.getByText(/network discovery sweep/i)).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("invokes onSelectMachine with the machine id when a row is chosen (Req 3.4)", async () => {
    const onSelectMachine = vi.fn();
    render(
      <MachineListView machines={machines} onSelectMachine={onSelectMachine} />,
    );

    await userEvent.click(screen.getByRole("button", { name: "db-01" }));

    expect(onSelectMachine).toHaveBeenCalledWith("m2");
  });
});

describe("MachineListView loading state", () => {
  // The bug this guards: an empty fleet and an in-flight first fetch used to
  // render identically, so a cold start looked like "you have no machines" --
  // a reassuring answer presented before the real one was known.
  it("shows placeholder rows, not the empty state, while loading", () => {
    const { container } = render(<MachineListView machines={[]} loading />);

    expect(screen.queryByText(/no machines yet/i)).not.toBeInTheDocument();
    expect(container.querySelectorAll(".skeleton-row").length).toBeGreaterThan(0);
  });

  it("shows the empty state once loading finishes with no machines", () => {
    const { container } = render(<MachineListView machines={[]} loading={false} />);

    expect(screen.getByText(/no machines yet/i)).toBeInTheDocument();
    expect(container.querySelectorAll(".skeleton-row")).toHaveLength(0);
  });

  it("shows real rows rather than placeholders once machines arrive", () => {
    const { container } = render(<MachineListView machines={machines} loading />);

    expect(container.querySelectorAll(".skeleton-row")).toHaveLength(0);
    expect(screen.getByText("web-01")).toBeInTheDocument();
  });

  it("leaves Windows hosts out of 'Re-scan all shown' and says so (Req 10.8, 13.2)", async () => {
    const onRescan = vi.fn();
    render(<MachineListView machines={machines} onRescan={onRescan} />);

    const button = screen.getByRole("button", { name: /Re-scan all shown/ });
    expect(button).toHaveTextContent("Re-scan all shown (1)");
    expect(screen.getByTestId("rescan-skipped")).toHaveTextContent("1 Windows host not");

    await userEvent.click(button);

    expect(onRescan).toHaveBeenCalledTimes(1);
    const sent = onRescan.mock.calls[0][0] as MachineSummary[];
    expect(sent.map((m) => m.hostname)).toEqual(["web-01"]);
  });

  it("does not re-scan a selection made up only of Windows hosts (Req 10.8)", async () => {
    const onRescan = vi.fn();
    render(<MachineListView machines={machines} onRescan={onRescan} />);

    await userEvent.click(screen.getByLabelText("Select db-01"));

    expect(screen.getByRole("button", { name: /Re-scan selected/ })).toBeDisabled();
    expect(onRescan).not.toHaveBeenCalled();
  });

  it("disables the quick scan for a Windows host (Req 10.8)", () => {
    render(<MachineListView machines={machines} onQuickScan={vi.fn()} />);

    const scanButtons = screen.getAllByRole("button", { name: /Scan$/ });
    const byTitle = (text: string) => scanButtons.find((b) => b.getAttribute("title")?.includes(text));
    expect(byTitle("Quick scan web-01")).toBeEnabled();
    expect(byTitle("Windows scanning is not supported yet")).toBeDisabled();
  });
});

describe("MachineListView scan delta (Req 18.6)", () => {
  it("shows what the last scan changed, with units in its accessible name", () => {
    render(
      <MachineListView
        machines={[
          makeMachine({ machineId: "a", hostname: "web-01", lastScanNew: 3, lastScanResolved: 5 }),
          makeMachine({ machineId: "b", hostname: "db-01", lastScanBaseline: true }),
        ]}
      />,
    );

    const delta = screen.getByText("+3 new / −5 resolved");
    expect(delta).toHaveAttribute("aria-label", "Since the previous scan: 3 new findings, 5 resolved findings.");
    expect(screen.queryByText(/Baseline/)).not.toBeInTheDocument();
  });
});
