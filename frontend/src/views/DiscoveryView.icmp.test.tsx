// A sweep that could not send ICMP says so, rather than reporting every host
// as filtered and an empty subnet as clear (Req 8.11).
//
// The shipped image had no ping binary for several releases, so every probe
// failed and every discovered host showed "Filtered" -- a claim about the
// host's ICMP posture derived from a missing program on the scanner.

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { DiscoveryView } from "./DiscoveryView";
import type { DiscoveredHost, DiscoverySweepResult } from "../types";

function host(overrides: Partial<DiscoveredHost> = {}): DiscoveredHost {
  return {
    ip: "192.0.2.10",
    hostname: "host.example",
    respondsToPing: null,
    openPorts: [22],
    services: [{ port: 22, protocol: "ssh", banner: "", product: "", version: "", extraInfo: "" }],
    osGuess: "Linux / Unix (inferred from SSH)",
    ...overrides,
  };
}

function result(overrides: Partial<DiscoverySweepResult> = {}): DiscoverySweepResult {
  return {
    cidr: "192.0.2.0/24",
    totalHostsScanned: 254,
    totalHostsDiscovered: 1,
    icmpChecked: true,
    probeErrors: 0,
    hosts: [host()],
    ...overrides,
  };
}

const renderView = (initialResult: DiscoverySweepResult) =>
  render(
    <DiscoveryView
      onSweep={vi.fn().mockResolvedValue(initialResult)}
      initialResult={initialResult}
      initialCidr="192.0.2.0/24"
    />,
  );

describe("ping reachability (Req 8.11)", () => {
  it("says a host's ping state is unchecked rather than filtered", async () => {
    const user = userEvent.setup();
    renderView(result({ icmpChecked: false, hosts: [host({ respondsToPing: null })] }));

    await user.click(screen.getByText("192.0.2.10"));

    expect(screen.getByText("Not checked")).toBeInTheDocument();
    expect(screen.queryByText("Filtered")).not.toBeInTheDocument();
  });

  it("still calls a host that ignored a ping filtered", async () => {
    const user = userEvent.setup();
    renderView(result({ hosts: [host({ respondsToPing: false })] }));

    await user.click(screen.getByText("192.0.2.10"));

    // A real answer must keep reading as one, or the fix has only moved the lie.
    expect(screen.getByText("Filtered")).toBeInTheDocument();
  });

  it("qualifies an empty sweep when ICMP could not be sent", () => {
    renderView(result({ icmpChecked: false, hosts: [], totalHostsDiscovered: 0 }));

    // Without ICMP a host answering only a ping is invisible to the sweep, so
    // "nothing here" is not a claim this sweep can make.
    expect(screen.getByText(/answer only a ping were not visible/i)).toBeInTheDocument();
  });

  it("does not qualify an empty sweep that did send ICMP", () => {
    renderView(result({ icmpChecked: true, hosts: [], totalHostsDiscovered: 0 }));

    expect(screen.queryByText(/not visible to this sweep/i)).not.toBeInTheDocument();
    expect(screen.getByText(/No host on 192.0.2.0\/24 answered/)).toBeInTheDocument();
  });
});

describe("addresses that could not be probed (Req 8.12)", () => {
  it("says how many, rather than counting them as nothing there", () => {
    renderView(result({ probeErrors: 7 }));

    // The sweep states a count; without this the count reads as complete.
    // The count and its noun sit in one badge, split across text nodes.
    const badge = screen.getByTitle(/could not be probed/i);
    expect(badge.textContent).toMatch(/7 addresses not probed/i);
  });

  it("says nothing when every address was probed", () => {
    renderView(result({ probeErrors: 0 }));

    expect(screen.queryByText(/not probed/i)).not.toBeInTheDocument();
  });
});

