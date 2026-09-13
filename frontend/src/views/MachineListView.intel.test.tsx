// Fleet-view tests for the threat-intel surface.
//
// The recurring concern: a zero in the "Actively Exploited" card is only
// reassuring if the catalogue was actually consulted. These tests pin that the
// view never presents an unloaded feed as an all-clear, and that the warning
// banner appears exactly when the numbers on screen cannot be taken at face
// value.

import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { MachineListView } from "./MachineListView";
import { makeMachine } from "../test-utils/factories";
import type { FeedHealth } from "../types";

function feed(overrides: Partial<FeedHealth> = {}): FeedHealth {
  return {
    feedName: "kev",
    status: "ok",
    lastRefreshedAt: new Date().toISOString(),
    lastAttemptedAt: new Date().toISOString(),
    recordCount: 1200,
    errorDetail: null,
    stale: false,
    usable: true,
    ...overrides,
  };
}

const HEALTHY_FEEDS: FeedHealth[] = [
  feed({ feedName: "kev" }),
  feed({ feedName: "epss" }),
];

const UNLOADED_FEEDS: FeedHealth[] = [
  feed({ feedName: "kev", usable: false, status: "never_refreshed", recordCount: 0, lastRefreshedAt: null }),
  feed({ feedName: "epss", usable: false, status: "never_refreshed", recordCount: 0, lastRefreshedAt: null }),
];

function cardByTitle(title: string): HTMLElement {
  return screen.getByText(title).closest(".triage-card") as HTMLElement;
}

describe("MachineListView threat-intel surface", () => {
  it("counts hosts with confirmed exploited findings", () => {
    render(
      <MachineListView
        machines={[
          makeMachine({ machineId: "m1", hostname: "a", kevCount: 3 }),
          makeMachine({ machineId: "m2", hostname: "b", kevCount: 0 }),
          makeMachine({ machineId: "m3", hostname: "c", kevCount: 1 }),
        ]}
        feeds={HEALTHY_FEEDS}
      />,
    );

    const card = cardByTitle("Actively exploited");
    expect(within(card).getByText("2")).toBeInTheDocument();
    expect(within(card).getByText(/2 hosts · 4 on CISA KEV/i)).toBeInTheDocument();
  });

  it("says no exploit data is loaded rather than implying the fleet is clear", () => {
    // The single most important assertion in this file. With no usable feed,
    // every host reports kevCount 0 -- and rendering that as "0 findings on
    // CISA KEV" would be a factual statement that reads as an all-clear.
    render(
      <MachineListView
        machines={[makeMachine({ kevCount: 0 })]}
        feeds={UNLOADED_FEEDS}
      />,
    );

    const card = cardByTitle("Actively exploited");
    expect(within(card).getByText(/no exploit data loaded/i)).toBeInTheDocument();
    expect(within(card).queryByText(/on CISA KEV/i)).not.toBeInTheDocument();
  });

  it("leads the triage row with exploitation, ahead of CVSS-based cards", () => {
    // Ordering is the argument: what is being exploited outranks what merely
    // scores highly.
    render(
      <MachineListView machines={[makeMachine()]} feeds={HEALTHY_FEEDS} />,
    );

    const titles = screen
      .getAllByText(/Actively exploited|Critical findings|High findings/)
      // textContent, unlike getByText, is not whitespace-normalised, and the
      // label now leads with an aria-hidden icon element.
      .map((node) => node.textContent?.trim());

    expect(titles[0]).toBe("Actively exploited");
  });

  it("filters the fleet to exploited hosts when the card is activated", async () => {
    const user = userEvent.setup();
    render(
      <MachineListView
        machines={[
          makeMachine({ machineId: "m1", hostname: "exploited-host", kevCount: 2 }),
          makeMachine({ machineId: "m2", hostname: "quiet-host", kevCount: 0 }),
        ]}
        feeds={HEALTHY_FEEDS}
      />,
    );

    expect(screen.getByText("quiet-host")).toBeInTheDocument();

    await user.click(cardByTitle("Actively exploited"));

    expect(screen.getByText("exploited-host")).toBeInTheDocument();
    expect(screen.queryByText("quiet-host")).not.toBeInTheDocument();
  });

  it("shows no warning banner when every feed is fresh", () => {
    render(
      <MachineListView machines={[makeMachine()]} feeds={HEALTHY_FEEDS} />,
    );

    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });

  it("warns when intel has never been loaded", () => {
    render(
      <MachineListView machines={[makeMachine()]} feeds={UNLOADED_FEEDS} />,
    );

    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent(/never been loaded/i);
    expect(banner).toHaveTextContent(/CVSS only/i);
  });

  it("warns when a feed is stale and reports how old the data is", () => {
    const threeDaysAgo = new Date(Date.now() - 3 * 86400 * 1000).toISOString();
    render(
      <MachineListView
        machines={[makeMachine()]}
        feeds={[
          feed({ feedName: "kev", stale: true, lastRefreshedAt: threeDaysAgo }),
          feed({ feedName: "epss" }),
        ]}
      />,
    );

    const banner = screen.getByRole("status");
    expect(banner).toHaveTextContent(/out of date/i);
    // The age shown is the age of the data, not of the last attempt.
    expect(banner).toHaveTextContent(/CISA KEV: 3d ago/);
  });

  it("offers a refresh control that calls back", async () => {
    const user = userEvent.setup();
    const onRefreshFeeds = vi.fn();
    render(
      <MachineListView
        machines={[makeMachine()]}
        feeds={UNLOADED_FEEDS}
        onRefreshFeeds={onRefreshFeeds}
      />,
    );

    await user.click(screen.getByRole("button", { name: /refresh intel/i }));

    expect(onRefreshFeeds).toHaveBeenCalledTimes(1);
  });

  it("disables the refresh control while a refresh is running", () => {
    render(
      <MachineListView
        machines={[makeMachine()]}
        feeds={UNLOADED_FEEDS}
        onRefreshFeeds={vi.fn()}
        refreshingFeeds
      />,
    );

    expect(screen.getByRole("button", { name: /refreshing/i })).toBeDisabled();
  });

  it("hides the refresh control when the caller cannot refresh", () => {
    render(
      <MachineListView machines={[makeMachine()]} feeds={UNLOADED_FEEDS} />,
    );

    expect(
      screen.queryByRole("button", { name: /refresh intel/i }),
    ).not.toBeInTheDocument();
  });

  it("stays silent when feed health could not be fetched at all", () => {
    // An empty feeds array means the health request failed. Inventing a
    // warning would be as wrong as inventing an all-clear.
    render(<MachineListView machines={[makeMachine()]} feeds={[]} />);

    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});

describe("exploitation is the only thing painted red", () => {
  // The palette carries the ranking: severity is a single amber ramp, and red
  // is reserved for exploitation, so a CVSS 9.8 nobody has touched cannot
  // out-shout a 6.5 being used today. The exploited card previously shared
  // data-tone="critical" with the Critical findings card beside it, which threw
  // that distinction away on the one screen where it matters most.
  function tone(label: string): string | null {
    const card = screen.getByText(label).closest(".triage-card");
    return card?.getAttribute("data-tone") ?? null;
  }

  it("gives the exploited card its own tone, distinct from severity", () => {
    render(
      <MachineListView
        machines={[makeMachine({ kevCount: 2 })]}
        feeds={HEALTHY_FEEDS}
      />,
    );

    expect(tone("Actively exploited")).toBe("exploit");
    expect(tone("Critical findings")).toBe("critical");
    expect(tone("High findings")).toBe("high");
  });

  it("drops the red when the exploitation data never loaded", () => {
    // Zero exploited hosts on a deployment whose KEV feed has never loaded is
    // an absence of an answer, not an all-clear and not an alarm.
    render(
      <MachineListView
        machines={[makeMachine({ kevCount: 0 })]}
        feeds={UNLOADED_FEEDS}
      />,
    );

    expect(tone("Actively exploited")).toBeNull();
  });
});
