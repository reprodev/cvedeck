// Example-based rendering tests for MachineDrillDownView.
//
// Requirements covered:
//   3.4 - drill-down view lists the CVEs identified for the selected machine
//   3.5 - each CVE shows its identifier, severity, and CVSS score
//   4.2 - a remediation status value is captured/displayed per finding
//   4.4 - the drill-down displays the current remediation status of each CVE
//
// These are example tests (per design.md "Testing Strategy": drill-down
// rendering and remediation status display, 3.4/4.4, and remediation field
// capture, 4.2). Because the implemented view is a display component, the
// remediation "field capture" (4.2) is exercised here by confirming the
// remediation status value supplied on each finding is rendered, and that a
// finding with no record renders a clear no-record placeholder.

import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MachineDrillDownView } from "./MachineDrillDownView";
import type { CveFinding } from "../types";

const findings: CveFinding[] = [
  {
    cveId: "CVE-2024-1000",
    severity: "critical",
    cvssScore: 9.8,
    packageIdentifier: "openssl",
    remediationStatus: "in_progress",
    remediationRecordId: "rec-1",
    remediationNote: "patch scheduled",
  },
  {
    cveId: "CVE-2024-2000",
    severity: "medium",
    cvssScore: 5.4,
    packageIdentifier: null,
    remediationStatus: null,
    remediationRecordId: null,
    remediationNote: null,
  },
];

/** Locate the table row that contains the given CVE id. */
function rowForCve(cveId: string): HTMLElement {
  const cell = screen.getByText(cveId);
  const row = cell.closest("tr");
  expect(row).not.toBeNull();
  return row as HTMLElement;
}

describe("MachineDrillDownView", () => {
  it("lists a row for each CVE finding (Req 3.4)", () => {
    render(<MachineDrillDownView machineId="m1" findings={findings} />);

    expect(screen.getByText("CVE-2024-1000")).toBeInTheDocument();
    expect(screen.getByText("CVE-2024-2000")).toBeInTheDocument();

    // Two data rows, one per finding (header row excluded).
    expect(screen.getAllByRole("row")).toHaveLength(findings.length + 1);
  });

  it("renders each CVE's id, severity, and CVSS score (Req 3.5)", () => {
    render(<MachineDrillDownView machineId="m1" findings={findings} />);

    const criticalRow = rowForCve("CVE-2024-1000");
    const cells = within(criticalRow).getAllByRole("cell");
    // Cells: CVE id, exploitation, severity, CVSS score, remediation status.
    expect(cells[0]).toHaveTextContent("CVE-2024-1000");
    expect(cells[2]).toHaveTextContent("Critical");
    expect(cells[3]).toHaveTextContent("9.8");
  });

  it("displays the current remediation status for each CVE (Req 4.2, 4.4)", () => {
    render(<MachineDrillDownView machineId="m1" findings={findings} />);

    // A finding with a recorded status shows that status value (field capture),
    // presented as a readable label rather than the raw enum value.
    const criticalRow = rowForCve("CVE-2024-1000");
    expect(within(criticalRow).getAllByRole("cell")[4]).toHaveTextContent(
      "In Progress",
    );

    // A finding with no remediation record shows an explicit placeholder.
    const mediumRow = rowForCve("CVE-2024-2000");
    expect(within(mediumRow).getAllByRole("cell")[4]).toHaveTextContent(
      "No remediation record",
    );
  });

  it("renders a Remediation Status column header (Req 4.4)", () => {
    render(<MachineDrillDownView machineId="m1" findings={findings} />);

    expect(
      screen.getByRole("columnheader", { name: "Remediation Status" }),
    ).toBeInTheDocument();
  });

  it("uses the hostname in the heading when provided (Req 3.4)", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={findings}
      />,
    );

    expect(
      screen.getByRole("heading", { name: "CVE Findings for web-01" }),
    ).toBeInTheDocument();
  });

  it("shows an empty-state message when the machine has no CVEs (Req 3.4)", () => {
    render(<MachineDrillDownView machineId="m1" findings={[]} />);

    expect(
      screen.getByText("No CVEs identified for this machine."),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("filters the CVE rows by severity (Req 3.3)", async () => {
    render(<MachineDrillDownView machineId="m1" findings={findings} />);

    // Severity filtering moved from a <select> to the chip row in the host
    // summary, which replaced a dropdown that duplicated it.
    await userEvent.click(screen.getByRole("button", { name: /^Critical \d+$/ }));

    expect(screen.getByText("CVE-2024-1000")).toBeInTheDocument();
    expect(screen.queryByText("CVE-2024-2000")).not.toBeInTheDocument();
  });

  it("reports when no CVE matches the selected severity (Req 3.3)", async () => {
    render(<MachineDrillDownView machineId="m1" findings={findings} />);

    await userEvent.click(screen.getByRole("button", { name: /^Low \d+$/ }));

    // The message names the filters actually excluding rows, rather than
    // blaming severity when the search box or patch filter was responsible.
    expect(
      screen.getByText("No findings match the current filters."),
    ).toBeInTheDocument();
    // Scoped to the empty state: "severity" also appears in the filter control.
    const emptyState = screen.getByRole("status");
    expect(emptyState).toHaveTextContent(/severity = low/);
    expect(
      screen.getByRole("button", { name: "Clear filters" }),
    ).toBeInTheDocument();
    expect(screen.queryByRole("table")).not.toBeInTheDocument();
  });

  it("saves a remediation status and note for a finding (Req 4.1, 4.2)", async () => {
    const onSaveRemediation = vi.fn();
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={findings}
        onSaveRemediation={onSaveRemediation}
      />,
    );

    // The finding with no existing record defaults to "open" and an empty note.
    await userEvent.selectOptions(
      screen.getByLabelText("Remediation status for CVE-2024-2000"),
      "remediated",
    );
    await userEvent.type(
      screen.getByLabelText("Remediation note for CVE-2024-2000"),
      "upgraded package",
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Save remediation for CVE-2024-2000" }),
    );

    expect(onSaveRemediation).toHaveBeenCalledTimes(1);
    expect(onSaveRemediation).toHaveBeenCalledWith(
      findings[1],
      "remediated",
      "upgraded package",
    );
  });

  it("seeds the remediation controls from an existing record (Req 4.3, 4.4)", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={findings}
        onSaveRemediation={vi.fn()}
      />,
    );

    expect(
      screen.getByLabelText("Remediation status for CVE-2024-1000"),
    ).toHaveValue("in_progress");
    expect(
      screen.getByLabelText("Remediation note for CVE-2024-1000"),
    ).toHaveValue("patch scheduled");
  });

  it("omits the remediation editor when no save handler is supplied", () => {
    render(<MachineDrillDownView machineId="m1" findings={findings} />);

    expect(
      screen.queryByRole("button", { name: /Save remediation/ }),
    ).not.toBeInTheDocument();
  });

  it("invokes onBack when the back control is used (Req 3.4)", async () => {
    const onBack = vi.fn();
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={findings}
        onBack={onBack}
      />,
    );

    await userEvent.click(
      screen.getByRole("button", { name: "Back to machines" }),
    );

    expect(onBack).toHaveBeenCalledTimes(1);
  });
});
