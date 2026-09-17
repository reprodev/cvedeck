// The pinned SSH host key in the drill-down (Req 17.3, 17.7, 17.8).

import { describe, expect, it, vi } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MachineDrillDownView } from "./MachineDrillDownView";
import type { HostKeyPin } from "../types";

const FINGERPRINT = "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8";

describe("pinned host key", () => {
  it("shows the fingerprint so it can be compared with ssh-keygen (Req 17.8)", () => {
    render(
      <MachineDrillDownView machineId="m1" hostname="web-01" findings={[]} hostKeyFingerprint={FINGERPRINT} />,
    );

    expect(screen.getByTestId("host-key-pin")).toHaveTextContent(FINGERPRINT);
  });

  it("offers no forget action where forgetting is not allowed", () => {
    render(
      <MachineDrillDownView machineId="m1" hostname="web-01" findings={[]} hostKeyFingerprint={FINGERPRINT} />,
    );

    expect(screen.queryByRole("button", { name: "Forget host key" })).not.toBeInTheDocument();
  });

  it("forgets only after confirming, and says what the next scan will trust (Req 17.7)", async () => {
    const user = userEvent.setup();
    const onForget = vi.fn().mockResolvedValue(undefined);
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={[]}
        hostKeyFingerprint={FINGERPRINT}
        onForgetHostKey={onForget}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Forget host key" }));
    const dialog = screen.getByRole("dialog");
    expect(dialog).toHaveTextContent(/next scan will trust whatever key the host presents/i);
    expect(onForget).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
    expect(onForget).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Forget host key" }));
    const confirm = screen
      .getAllByRole("button", { name: "Forget host key" })
      .find((button) => screen.getByRole("dialog").contains(button))!;
    await user.click(confirm);

    expect(onForget).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("dialog")).not.toBeInTheDocument();
  });

  it("keeps the dialog open and reports a failure to forget", async () => {
    const user = userEvent.setup();
    const onForget = vi.fn().mockRejectedValue(new Error("No host key is pinned for that address"));
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={[]}
        hostKeyFingerprint={FINGERPRINT}
        onForgetHostKey={onForget}
      />,
    );

    await user.click(screen.getByRole("button", { name: "Forget host key" }));
    const dialog = screen.getByRole("dialog");
    const confirm = screen
      .getAllByRole("button", { name: "Forget host key" })
      .find((button) => dialog.contains(button))!;
    await user.click(confirm);

    expect(await screen.findByRole("alert")).toHaveTextContent("No host key is pinned");
    expect(screen.getByRole("dialog")).toBeInTheDocument();
  });

  it("explains a refused scan (Req 17.3)", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={[]}
        lastScanStatus="host_key_mismatch"
        hostKeyFingerprint={FINGERPRINT}
      />,
    );

    expect(screen.getByTestId("host-key-refused")).toHaveTextContent(
      /presented a different SSH host key.*No credentials were sent/,
    );
  });
});

describe("the pinned key's type", () => {
  it("names the key type beside the fingerprint (Req 17.8)", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={[]}
        hostKeyFingerprint={FINGERPRINT}
        hostKeyType="ssh-ed25519"
      />,
    );

    // The type is what tells an operator which /etc/ssh/ssh_host_*.pub to check.
    expect(screen.getByTestId("host-key-pin")).toHaveTextContent(
      `ssh-ed25519 ${FINGERPRINT}`,
    );
  });

  it("still renders a pin whose type is unknown", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={[]}
        hostKeyFingerprint={FINGERPRINT}
      />,
    );

    expect(screen.getByTestId("host-key-pin")).toHaveTextContent(FINGERPRINT);
  });
});

describe("pins on other ports (Req 17.11)", () => {
  const pin = (overrides: Partial<HostKeyPin>): HostKeyPin => ({
    hostname: "web-01",
    port: 22,
    keyType: "ssh-ed25519",
    fingerprint: FINGERPRINT,
    firstSeenAt: "2026-09-01T00:00:00Z",
    lastSeenAt: "2026-09-02T00:00:00Z",
    machineId: "m1",
    ...overrides,
  });

  // The same key on 22 and 2222, as one sshd listening twice presents it, so
  // only the port can tell the page's own pin from the other one.
  const PINS = [
    pin({}),
    pin({ port: 2222 }),
    pin({ hostname: "db-01", port: 2200, machineId: "m2" }),
    pin({ hostname: "lab-99", port: 2201, machineId: null }),
  ];

  it("lists this machine's pins on other ports, and only those", async () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={[]}
        hostKeyFingerprint={FINGERPRINT}
        hostKeyPort={22}
        onListHostKeys={vi.fn().mockResolvedValue(PINS)}
      />,
    );

    const list = await screen.findByTestId("other-port-pins");
    expect(list).toHaveTextContent("Also pinned on other ports");
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(1);
    expect(rows[0]).toHaveTextContent(`port 2222`);
    expect(rows[0]).toHaveTextContent(`ssh-ed25519 ${FINGERPRINT}`);
  });

  it("lists every pin for the machine when none is on the configured port", async () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={[]}
        onListHostKeys={vi.fn().mockResolvedValue(PINS)}
      />,
    );

    const list = await screen.findByTestId("other-port-pins");
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
  });

  it("forgets a pin on another port only after confirming, with its port", async () => {
    const user = userEvent.setup();
    const onForgetAt = vi.fn().mockResolvedValue(undefined);
    const onList = vi
      .fn()
      .mockResolvedValueOnce(PINS)
      .mockResolvedValueOnce(PINS.filter((p) => p.port !== 2222));
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={[]}
        hostKeyFingerprint={FINGERPRINT}
        hostKeyPort={22}
        onListHostKeys={onList}
        onForgetHostKeyAt={onForgetAt}
      />,
    );

    await user.click(
      await screen.findByRole("button", { name: "Forget host key for web-01:2222" }),
    );
    expect(onForgetAt).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Forget web-01:2222" }));

    expect(onForgetAt).toHaveBeenCalledWith("web-01", 2222);
    // Reloaded, and nothing is left on another port.
    await vi.waitFor(() =>
      expect(screen.queryByTestId("other-port-pins")).not.toBeInTheDocument(),
    );
  });

  it("offers no forget action where forgetting is not allowed", async () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={[]}
        hostKeyFingerprint={FINGERPRINT}
        hostKeyPort={22}
        onListHostKeys={vi.fn().mockResolvedValue(PINS)}
      />,
    );

    const list = await screen.findByTestId("other-port-pins");
    expect(within(list).queryByRole("button")).not.toBeInTheDocument();
  });

  it("says it does not know, rather than showing nothing, when the list fails", async () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        hostname="web-01"
        findings={[]}
        onListHostKeys={vi.fn().mockRejectedValue(new Error("offline"))}
      />,
    );

    expect(await screen.findByTestId("other-port-pins-unknown")).toHaveTextContent(
      /could not be loaded/,
    );
  });
});
