// Drill-down tests for the exploitation column and risk ordering.
//
// The column renders three visually distinct states, and keeping them distinct
// is the point: an unenriched finding must not look like one that was checked
// and found clear. A user who reads "— unknown" as "Not on KEV" has been told
// their fleet is safer than anyone actually knows.

import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { MachineDrillDownView } from "./MachineDrillDownView";
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
    ...overrides,
  };
}

function rowFor(cveId: string): HTMLElement {
  return screen.getByText(cveId).closest("tr") as HTMLElement;
}

describe("MachineDrillDownView exploitation column", () => {
  it("flags a KEV-listed finding as exploited", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[finding({ kevListed: true, kevDueDate: "2024-04-19" })]}
      />,
    );

    expect(within(rowFor("CVE-2024-1000")).getByText(/Exploited/)).toBeInTheDocument();
  });

  it("surfaces the CISA remediation due date on the badge", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[finding({ kevListed: true, kevDueDate: "2024-04-19" })]}
      />,
    );

    expect(
      within(rowFor("CVE-2024-1000")).getByTitle(/due 2024-04-19/i),
    ).toBeInTheDocument();
  });

  it("shows a checked-and-clear finding as not on KEV", () => {
    render(
      <MachineDrillDownView machineId="m1" findings={[finding({ kevListed: false })]} />,
    );

    const row = rowFor("CVE-2024-1000");
    expect(within(row).getByText("Not on KEV")).toBeInTheDocument();
    expect(within(row).queryByText(/unknown/i)).not.toBeInTheDocument();
  });

  it("shows an unenriched finding as unknown, never as not-on-KEV", () => {
    // The distinction this whole column exists to preserve.
    render(<MachineDrillDownView machineId="m1" findings={[finding()]} />);

    const row = rowFor("CVE-2024-1000");
    expect(within(row).getByText(/unknown/i)).toBeInTheDocument();
    expect(within(row).queryByText("Not on KEV")).not.toBeInTheDocument();
  });

  it("explains in the tooltip that unknown is not evidence of safety", () => {
    render(<MachineDrillDownView machineId="m1" findings={[finding()]} />);

    expect(
      within(rowFor("CVE-2024-1000")).getByTitle(/not evidence/i),
    ).toBeInTheDocument();
  });

  it("renders the three states as distinct cell values", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[
          finding({ cveId: "CVE-A", kevListed: true }),
          finding({ cveId: "CVE-B", kevListed: false }),
          finding({ cveId: "CVE-C", kevListed: null }),
        ]}
      />,
    );

    const texts = ["CVE-A", "CVE-B", "CVE-C"].map((id) => {
      const cells = within(rowFor(id)).getAllByRole("cell");
      return cells[1].textContent;
    });

    expect(new Set(texts).size).toBe(3);
  });

  it("shows the EPSS score and percentile when both are known", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[finding({ epssScore: 0.944, epssPercentile: 0.999 })]}
      />,
    );

    const row = rowFor("CVE-2024-1000");
    expect(within(row).getByText(/EPSS 94\.4%/)).toBeInTheDocument();
    expect(within(row).getByText(/100th/)).toBeInTheDocument();
  });

  it("shows a dash rather than a zero when EPSS is unknown", () => {
    // A rendered 0% would be indistinguishable from a measured near-zero.
    render(<MachineDrillDownView machineId="m1" findings={[finding()]} />);

    expect(within(rowFor("CVE-2024-1000")).getByText("EPSS --")).toBeInTheDocument();
  });
});

describe("MachineDrillDownView risk ordering", () => {
  const findings = [
    finding({ cveId: "CVE-QUIET-CRIT", cvssScore: 9.8, kevListed: false }),
    finding({
      cveId: "CVE-EXPLOITED-MED",
      cvssScore: 6.5,
      severity: "medium",
      kevListed: true,
    }),
  ];

  function orderedIds(): string[] {
    return screen
      .getAllByRole("row")
      .slice(1)
      .map((row) => within(row).getAllByRole("cell")[0].textContent ?? "")
      .map((text) => (text.includes("CVE-EXPLOITED-MED") ? "CVE-EXPLOITED-MED" : "CVE-QUIET-CRIT"));
  }

  it("ranks an exploited medium above a quiet critical by default", () => {
    // Risk ordering is on by default because it is the ordering the KEV and
    // EPSS signals were collected to make possible.
    render(<MachineDrillDownView machineId="m1" findings={findings} />);

    expect(orderedIds()[0]).toBe("CVE-EXPLOITED-MED");
  });

  // The toggle exists because compliance reporting still expects CVSS order;
  // this is the test that proves switching it off actually restores that.
  it("offers a toggle labelled by what it actually sorts on", async () => {
    const user = userEvent.setup();
    render(<MachineDrillDownView machineId="m1" findings={findings} />);

    const toggle = screen.getByRole("checkbox", {
      name: /sort by exploitation risk/i,
    });
    expect(toggle).toBeChecked();

    await user.click(toggle);

    expect(toggle).not.toBeChecked();
    expect(orderedIds()[0]).toBe("CVE-QUIET-CRIT");
  });
});

describe("MachineDrillDownView host summary", () => {
  function summary(): HTMLElement {
    return document.querySelector(".host-summary") as HTMLElement;
  }

  it("counts the actively exploited findings on this host", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[
          finding({ cveId: "CVE-A", kevListed: true }),
          finding({ cveId: "CVE-B", kevListed: true }),
          finding({ cveId: "CVE-C", kevListed: false }),
        ]}
      />,
    );

    expect(within(summary()).getByText(/actively exploited/)).toHaveTextContent("2");
  });

  it("says none are exploited when the findings were checked and clear", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[finding({ kevListed: false })]}
      />,
    );

    expect(within(summary()).getByText(/None actively exploited/)).toBeInTheDocument();
  });

  it("says exploitation is unknown when nothing here was ever checked", () => {
    // Distinct from "none": a zero is a claim, and this is the absence of one.
    // The host page must not imply safety the intel feeds never established.
    render(
      <MachineDrillDownView machineId="m1" findings={[finding()]} />,
    );

    expect(within(summary()).getByText(/Exploitation unknown/)).toBeInTheDocument();
    expect(within(summary()).queryByText(/None actively exploited/)).not.toBeInTheDocument();
  });

  it("does not clear a host whose findings were only partly checked", () => {
    // The regression this pins: the summary asked whether *any* finding had
    // been checked, so one checked-and-absent finding among many unchecked
    // ones printed a confident "None actively exploited" -- directly
    // contradicting the table below it, which showed the rest as unknown.
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[
          finding({ cveId: "CVE-A", kevListed: false }),
          finding({ cveId: "CVE-B" }),
          finding({ cveId: "CVE-C" }),
        ]}
      />,
    );

    expect(
      within(summary()).queryByText(/None actively exploited/),
    ).not.toBeInTheDocument();
    expect(within(summary()).getByText(/1 of 3 checked/)).toBeInTheDocument();
  });

  it("says what it does not know, rather than blaming a feed that did load", () => {
    // "No threat intel has been loaded" is false on a partially-checked host,
    // and a message that is wrong about the reason is not a safe way to say
    // "I don't know".
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[
          finding({ cveId: "CVE-A", kevListed: false }),
          finding({ cveId: "CVE-B" }),
        ]}
      />,
    );

    expect(
      within(summary()).getByTitle(/never checked, so this host has not been cleared/i),
    ).toBeInTheDocument();
  });

  it("explains in the tooltip that unknown is not evidence of safety", () => {
    render(<MachineDrillDownView machineId="m1" findings={[finding()]} />);

    expect(within(summary()).getByTitle(/not evidence/i)).toBeInTheDocument();
  });

  it("renders the three exploitation states as distinct markers", () => {
    const cases = [
      [finding({ kevListed: true })],
      [finding({ kevListed: false })],
      [finding()],
    ];
    const states = cases.map((f) => {
      const { unmount } = render(
        <MachineDrillDownView machineId="m1" findings={f} />,
      );
      const state = summary()
        .querySelector(".host-summary-exploit")
        ?.getAttribute("data-state");
      unmount();
      return state;
    });

    expect(new Set(states).size).toBe(3);
  });

  it("reports remediation progress", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[
          finding({ cveId: "CVE-A", remediationStatus: "remediated" }),
          finding({ cveId: "CVE-B", remediationStatus: "open" }),
        ]}
      />,
    );

    expect(within(summary()).getByText(/1 of 2 resolved/)).toBeInTheDocument();
  });

  it("replaces the KPI cards rather than sitting alongside them", () => {
    // The five-card grid duplicated counts the workspace tabs already carry.
    render(<MachineDrillDownView machineId="m1" findings={[finding()]} />);

    expect(document.querySelector(".severity-kpi-grid")).toBeNull();
  });
});
