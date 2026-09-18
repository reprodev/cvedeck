// Tests for the restructured fleet summary.
//
// The layout this replaced stacked two five-card grids of identical visual
// weight where one counted hosts and the other counted findings, with nothing
// on screen to say which was which. Several tests here exist purely to keep
// those units distinguishable, because the failure is silent: a reader simply
// misreads a number and never finds out.

import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { MachineListView } from "./MachineListView";
import { makeMachine } from "../test-utils/factories";
import type { FeedHealth, MachineSummary } from "../types";

const USABLE_FEEDS: FeedHealth[] = ["kev", "epss"].map((feedName) => ({
  feedName,
  status: "ok" as const,
  lastRefreshedAt: new Date().toISOString(),
  lastAttemptedAt: new Date().toISOString(),
  recordCount: 1200,
  errorDetail: null,
  stale: false,
  usable: true,
}));

const NO_FEEDS: FeedHealth[] = USABLE_FEEDS.map((f) => ({
  ...f,
  status: "never_refreshed" as const,
  usable: false,
  recordCount: 0,
  lastRefreshedAt: null,
}));

function daysAgo(n: number): string {
  return new Date(Date.now() - n * 86400 * 1000).toISOString();
}

/** A fleet exercising every state the summary distinguishes. */
function fleet(): MachineSummary[] {
  return [
    makeMachine({
      machineId: "exploited",
      hostname: "db-primary",
      kevCount: 2,
      cveCounts: { critical: 5, unscored: 0, high: 3, medium: 0, low: 0 },
      lastScannedAt: daysAgo(1),
    }),
    makeMachine({
      machineId: "critical-only",
      hostname: "app-01",
      kevCount: 0,
      cveCounts: { critical: 4, unscored: 0, high: 2, medium: 0, low: 0 },
      lastScannedAt: daysAgo(1),
    }),
    makeMachine({
      machineId: "high-only",
      hostname: "cache-01",
      kevCount: 0,
      cveCounts: { critical: 0, unscored: 0, high: 3, medium: 0, low: 0 },
      lastScannedAt: daysAgo(1),
    }),
    makeMachine({
      machineId: "stale",
      hostname: "nas-01",
      lastScannedAt: daysAgo(30),
      cveCounts: { critical: 1, unscored: 0, high: 0, medium: 0, low: 0 },
    }),
    makeMachine({
      machineId: "failed",
      hostname: "rdp-gw",
      lastScanStatus: "connection_failure",
      lastScannedAt: daysAgo(1),
    }),
    makeMachine({
      machineId: "never",
      hostname: "new-host",
      lastScanStatus: "never_scanned",
      lastScannedAt: null,
    }),
  ];
}

function card(label: string): HTMLElement {
  return screen.getByText(label).closest(".triage-card") as HTMLElement;
}

function visibleHostnames(): string[] {
  return screen
    .getAllByRole("row")
    .slice(1)
    .map((row) => within(row).getAllByRole("cell")[0].textContent ?? "")
    // The per-row scan button sits in the same cell as the hostname. Its
    // label lost its emoji when the icons went in, so this anchors to the end
    // of the cell instead of matching a bare "Scan" that a hostname could
    // legitimately contain.
    .map((t) => t.replace(/\s*Scan\s*$/, "").trim());
}

describe("fleet summary units", () => {
  it("states the unit on every triage card", () => {
    // The whole row counts hosts. Saying so on each card is what stops it
    // being read as a finding count, which is what the row below reports.
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    expect(within(card("Critical findings")).getByText(/hosts? ·/)).toBeInTheDocument();
    expect(within(card("High findings")).getByText(/hosts? ·/)).toBeInTheDocument();
  });

  it("distinguishes the host count from the finding count on one card", () => {
    // 2 hosts have critical findings; there are 10 critical findings between
    // them. Both numbers appear, and they are labelled differently.
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    const criticalCard = card("Critical findings");
    expect(within(criticalCard).getByText("3")).toBeInTheDocument(); // hosts
    expect(within(criticalCard).getByText(/3 hosts · 10 findings/)).toBeInTheDocument();
  });

  it("reports findings totals separately from the host cards", () => {
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    expect(screen.getByText(/findings across/)).toBeInTheDocument();
  });

  it("uses a singular unit for a single host", () => {
    render(
      <MachineListView
        machines={[makeMachine({ kevCount: 1, cveCounts: { critical: 1, unscored: 0, high: 0, medium: 0, low: 0 } })]}
        feeds={USABLE_FEEDS}
      />,
    );

    expect(within(card("Actively exploited")).getByText(/1 host ·/)).toBeInTheDocument();
  });
});

describe("needs-attention grouping", () => {
  it("counts hosts whose data cannot be trusted as current", () => {
    // stale + failed + never scanned = 3.
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    expect(within(card("Needs attention")).getByText("3")).toBeInTheDocument();
  });

  it("breaks the group down rather than only totalling it", () => {
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    expect(
      within(card("Needs attention")).getByText(/1 failed · 1 stale · 1 never scanned/),
    ).toBeInTheDocument();
  });

  it("says so plainly when nothing needs attention", () => {
    render(
      <MachineListView
        machines={[makeMachine({ lastScannedAt: daysAgo(1) })]}
        feeds={USABLE_FEEDS}
      />,
    );

    expect(
      within(card("Needs attention")).getByText(/all hosts scanned recently/i),
    ).toBeInTheDocument();
  });

  it("filters to exactly those hosts when activated", async () => {
    const user = userEvent.setup();
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    await user.click(card("Needs attention"));

    expect(visibleHostnames().sort()).toEqual(["nas-01", "new-host", "rdp-gw"]);
  });
});

describe("risk ordering", () => {
  it("puts actively exploited hosts first by default", () => {
    // Alphabetical is a filing order, not a triage order -- it previously
    // buried an exploited host eleventh of twelve.
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    expect(visibleHostnames()[0]).toBe("db-primary");
  });

  it("ranks an exploited host above one with more critical findings", () => {
    const machines = [
      makeMachine({
        machineId: "many-crit",
        hostname: "aaa-noisy",
        kevCount: 0,
        cveCounts: { critical: 99, unscored: 0, high: 0, medium: 0, low: 0 },
      }),
      makeMachine({
        machineId: "one-kev",
        hostname: "zzz-exploited",
        kevCount: 1,
        cveCounts: { critical: 1, unscored: 0, high: 0, medium: 0, low: 0 },
      }),
    ];

    render(<MachineListView machines={machines} feeds={USABLE_FEEDS} />);

    expect(visibleHostnames()[0]).toBe("zzz-exploited");
  });

  it("falls back to critical count between unexploited hosts", () => {
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    const order = visibleHostnames();
    expect(order.indexOf("app-01")).toBeLessThan(order.indexOf("cache-01"));
  });
});

describe("exploitation column", () => {
  it("shows a badge for an exploited host", () => {
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    const row = screen.getByText("db-primary").closest("tr") as HTMLElement;
    expect(within(row).getAllByRole("cell")[4]).toHaveTextContent("2");
  });

  it("shows zero for a host checked and found clear", () => {
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    const row = screen.getByText("app-01").closest("tr") as HTMLElement;
    const cell = within(row).getAllByRole("cell")[4];
    expect(cell).toHaveTextContent("0");
    expect(cell.querySelector(".kev-none")).not.toBeNull();
  });

  it("shows a dash, not a zero, when intel has never loaded", () => {
    // The distinction the whole enrichment feature turns on. A zero here would
    // report the host clear on the authority of a feed nobody downloaded.
    render(<MachineListView machines={fleet()} feeds={NO_FEEDS} />);

    const row = screen.getByText("app-01").closest("tr") as HTMLElement;
    const cell = within(row).getAllByRole("cell")[4];
    expect(cell).not.toHaveTextContent("0");
    expect(cell.querySelector(".kev-unknown")).not.toBeNull();
  });

  it("explains in the tooltip that unknown is not evidence of safety", () => {
    render(<MachineListView machines={fleet()} feeds={NO_FEEDS} />);

    const row = screen.getByText("app-01").closest("tr") as HTMLElement;
    expect(within(row).getByTitle(/not evidence/i)).toBeInTheDocument();
  });
});

describe("severity chips", () => {
  it("replaces the old dropdown as the single severity control", () => {
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    expect(screen.queryByLabelText(/filter by severity/i)).not.toBeInTheDocument();
    expect(screen.getByRole("button", { name: /^Critical \d+$/ })).toBeInTheDocument();
  });

  it("narrows the visible severity columns when a chip is selected", async () => {
    const user = userEvent.setup();
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    await user.click(screen.getByRole("button", { name: /^Critical \d+$/ }));

    expect(screen.getByRole("columnheader", { name: /Critical/ })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: /^High/ })).not.toBeInTheDocument();
  });

  it("toggles back to all severities on a second click", async () => {
    const user = userEvent.setup();
    render(<MachineListView machines={fleet()} feeds={USABLE_FEEDS} />);

    const chip = screen.getByRole("button", { name: /^Critical \d+$/ });
    await user.click(chip);
    await user.click(chip);

    expect(screen.getByRole("columnheader", { name: /^High/ })).toBeInTheDocument();
  });
});

describe("refused host keys (Req 17.3)", () => {
  it("groups them on their own rather than as ordinary failures", async () => {
    const user = userEvent.setup();
    render(
      <MachineListView
        machines={[
          makeMachine({ machineId: "a", hostname: "web-01", lastScannedAt: daysAgo(1) }),
          makeMachine({
            machineId: "b",
            hostname: "rebuilt-01",
            lastScanStatus: "host_key_mismatch",
            lastScannedAt: daysAgo(1),
          }),
        ]}
        feeds={USABLE_FEEDS}
      />,
    );

    expect(
      within(card("Needs attention")).getByText(/1 host refused on host key/),
    ).toBeInTheDocument();
    const badge = screen.getByText("Host key changed");
    expect(badge).toHaveClass("badge-status-warn");

    await user.click(card("Needs attention"));
    expect(visibleHostnames()).toEqual(["rebuilt-01"]);
  });
});

describe("the new-findings filter (Req 18.6)", () => {
  const fleetWithNew = () => [
    makeMachine({ machineId: "a", hostname: "web-01", lastScanNew: 3, lastScanResolved: 0, lastScannedAt: daysAgo(1) }),
    makeMachine({ machineId: "b", hostname: "db-01", lastScanNew: 0, lastScanResolved: 0, lastScannedAt: daysAgo(1) }),
    // Never successfully scanned, so "new" is not assessed -- not zero.
    makeMachine({ machineId: "c", hostname: "new-host", lastScanNew: null, lastScannedAt: daysAgo(1) }),
  ];

  it("counts hosts, states the findings, and filters to them", async () => {
    const user = userEvent.setup();
    render(<MachineListView machines={fleetWithNew()} feeds={USABLE_FEEDS} />);

    const filter = screen.getByRole("button", { name: /New findings \(1\)/ });
    expect(filter).toHaveAttribute(
      "title",
      "3 findings these hosts' latest scans found that the scan before did not",
    );

    await user.click(filter);
    expect(visibleHostnames()).toEqual(["web-01"]);
  });

  it("stays out of the way when the last round of scanning found nothing new", () => {
    render(
      <MachineListView
        machines={[makeMachine({ lastScanNew: 0, lastScannedAt: daysAgo(1) })]}
        feeds={USABLE_FEEDS}
      />,
    );

    expect(screen.queryByRole("button", { name: /New findings/ })).not.toBeInTheDocument();
  });

  it("leaves the triage row at four cards", () => {
    // The fifth card was removed from this row once already; see .triage-row.
    render(<MachineListView machines={fleetWithNew()} feeds={USABLE_FEEDS} />);

    expect(document.querySelectorAll(".triage-card")).toHaveLength(4);
  });
});
