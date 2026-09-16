// The pinned SSH host key in the drill-down (Req 17.3, 17.7, 17.8).

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MachineDrillDownView } from "./MachineDrillDownView";

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
