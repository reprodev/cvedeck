// Example-based tests for ScanFormView.
//
// Requirements covered:
//   1.1 - manually initiate a scan of a target machine
//   1.2 - platform selection; Windows is deferred
//   10.8 - a platform that cannot be assessed is refused, not scanned
//
// These are example tests (per design.md "Testing Strategy": the view is an
// I/O-boundary component, not pure logic). The view is a display + capture
// component, so the assertions here are about what it hands to its callback.

import { describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ScanFormView } from "./ScanFormView";
import { makeScanOutcome } from "../test-utils/factories";

/** Fill the form and submit it. */
async function submitScan(options: {
  hostname: string;
  platform?: "Linux (SSH)" | "Windows (WinRM) — not yet supported";
  username?: string;
  password?: string;
}) {
  await userEvent.type(screen.getByLabelText("Hostname"), options.hostname);
  if (options.platform) {
    await userEvent.selectOptions(
      screen.getByLabelText("Platform"),
      screen.getByRole("option", { name: options.platform }),
    );
  }
  await userEvent.type(
    screen.getByLabelText("Username"),
    options.username ?? "scanner",
  );
  await userEvent.type(
    screen.getByLabelText("Password"),
    options.password ?? "secret",
  );
  await userEvent.click(screen.getByRole("button", { name: "Start scan" }));
}

describe("ScanFormView", () => {
  it("submits the entered target, defaulting to Linux (Req 1.1, 1.2)", async () => {
    const onScan = vi.fn();
    render(<ScanFormView onScan={onScan} />);

    await submitScan({ hostname: "web-01.example.com" });

    expect(onScan).toHaveBeenCalledTimes(1);
    expect(onScan).toHaveBeenCalledWith({
      // The hostname doubles as the machine id, so a re-scan updates the same
      // machine row rather than creating a duplicate.
      id: "web-01.example.com",
      hostname: "web-01.example.com",
      platform: "linux",
      username: "scanner",
      password: "secret",
    });
  });

  it("does not submit a Windows target, and says why (Req 10.8)", async () => {
    const onScan = vi.fn();
    render(<ScanFormView onScan={onScan} />);

    await submitScan({
      hostname: "win-01",
      platform: "Windows (WinRM) — not yet supported",
    });

    expect(onScan).not.toHaveBeenCalled();
    expect(screen.getByRole("button", { name: "Start scan" })).toBeDisabled();
    expect(screen.getByTestId("platform-unsupported")).toHaveTextContent(
      "Windows scanning is not supported yet",
    );
  });

  it("explains the refusal when auto-detection lands on Windows (Req 8.7, 10.8)", () => {
    render(
      <ScanFormView
        onScan={vi.fn()}
        initialTarget={{ hostname: "dc-01", platform: "windows" }}
      />,
    );

    expect(screen.getByLabelText("Platform")).toHaveValue("windows");
    expect(screen.getByRole("button", { name: "Start scan" })).toBeDisabled();
    expect(screen.getByTestId("platform-unsupported")).toBeInTheDocument();
  });

  it("offers the scan again once the platform is switched back to Linux (Req 10.8)", async () => {
    const onScan = vi.fn();
    render(
      <ScanFormView
        onScan={onScan}
        initialTarget={{ hostname: "web-01", platform: "windows" }}
      />,
    );

    await userEvent.selectOptions(
      screen.getByLabelText("Platform"),
      screen.getByRole("option", { name: "Linux (SSH)" }),
    );
    await userEvent.type(screen.getByLabelText("Username"), "scanner");
    await userEvent.type(screen.getByLabelText("Password"), "secret");
    await userEvent.click(screen.getByRole("button", { name: "Start scan" }));

    expect(screen.queryByTestId("platform-unsupported")).not.toBeInTheDocument();
    expect(onScan).toHaveBeenCalledWith(
      expect.objectContaining({ hostname: "web-01", platform: "linux" }),
    );
  });

  it("clears the password once the scan has been handed off", async () => {
    render(<ScanFormView onScan={vi.fn()} />);

    await submitScan({ hostname: "web-01" });

    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("trims surrounding whitespace from the hostname", async () => {
    const onScan = vi.fn();
    render(<ScanFormView onScan={onScan} />);

    await submitScan({ hostname: "  web-01  " });

    expect(onScan).toHaveBeenCalledWith(
      expect.objectContaining({ id: "web-01", hostname: "web-01" }),
    );
  });

  it("disables submission while a scan is in flight", () => {
    render(<ScanFormView onScan={vi.fn()} scanning />);

    expect(screen.getByRole("button", { name: "Scanning..." })).toBeDisabled();
  });

  it("reports the per-target outcome of the last scan (Req 1.4, 1.5)", () => {
    render(
      <ScanFormView
        onScan={vi.fn()}
        outcomes={[
          makeScanOutcome({ machineId: "web-01", status: "success", findingCount: 3 }),
          makeScanOutcome({
            machineId: "db-01",
            status: "auth_failure",
            findingCount: 0,
            message: "authentication failed for root@db-01",
          }),
        ]}
      />,
    );

    const result = screen.getByRole("status");
    expect(result).toHaveTextContent("web-01");
    expect(result).toHaveTextContent("Success");
    expect(result).toHaveTextContent("3 findings");
    // A failed target is reported as an outcome, not raised as an error.
    expect(result).toHaveTextContent("db-01");
    expect(result).toHaveTextContent("Authentication failed");
  });

  it("uses the singular noun for a single finding", () => {
    render(
      <ScanFormView
        onScan={vi.fn()}
        outcomes={[
          makeScanOutcome({ machineId: "web-01", status: "success", findingCount: 1 }),
        ]}
      />,
    );

    expect(screen.getByRole("status")).toHaveTextContent("1 finding");
  });

  it("shows no result panel before the first scan", () => {
    render(<ScanFormView onScan={vi.fn()} />);

    expect(screen.queryByRole("status")).not.toBeInTheDocument();
  });
});

describe("ScanFormView authentication modes", () => {
  it("offers only a password field by default", () => {
    render(<ScanFormView onScan={vi.fn()} />);

    expect(screen.getByLabelText("Password")).toBeInTheDocument();
    expect(screen.queryByLabelText("Private key")).not.toBeInTheDocument();
  });

  it("swaps in the key fields when SSH key auth is selected", async () => {
    render(<ScanFormView onScan={vi.fn()} />);

    await userEvent.selectOptions(
      screen.getByLabelText("Authentication"),
      "key",
    );

    expect(screen.getByLabelText("Private key")).toBeInTheDocument();
    expect(screen.getByLabelText("Passphrase (optional)")).toBeInTheDocument();
    // Mutually exclusive: the backend rejects both being supplied.
    expect(screen.queryByLabelText("Password")).not.toBeInTheDocument();
  });

  it("submits the private key instead of a password", async () => {
    const onScan = vi.fn();
    render(<ScanFormView onScan={onScan} />);

    await userEvent.type(screen.getByLabelText("Hostname"), "web-01");
    await userEvent.type(screen.getByLabelText("Username"), "root");
    await userEvent.selectOptions(screen.getByLabelText("Authentication"), "key");
    await userEvent.type(screen.getByLabelText("Private key"), "KEY-MATERIAL");
    await userEvent.click(screen.getByRole("button", { name: "Start scan" }));

    expect(onScan).toHaveBeenCalledWith(
      expect.objectContaining({
        hostname: "web-01",
        privateKey: "KEY-MATERIAL",
      }),
    );
    expect(onScan.mock.calls[0][0]).not.toHaveProperty("password");
  });

  it("clears the key material once the scan is handed off", async () => {
    render(<ScanFormView onScan={vi.fn()} />);

    await userEvent.type(screen.getByLabelText("Hostname"), "web-01");
    await userEvent.type(screen.getByLabelText("Username"), "root");
    await userEvent.selectOptions(screen.getByLabelText("Authentication"), "key");
    const keyField = screen.getByLabelText("Private key");
    await userEvent.type(keyField, "KEY-MATERIAL");
    await userEvent.click(screen.getByRole("button", { name: "Start scan" }));

    expect(keyField).toHaveValue("");
  });

  it("hides the server-key option unless the deployment has one", async () => {
    const { rerender } = render(<ScanFormView onScan={vi.fn()} />);
    expect(
      screen.queryByRole("option", { name: "Server-managed key" }),
    ).not.toBeInTheDocument();

    rerender(<ScanFormView onScan={vi.fn()} serverKeyAvailable />);
    expect(
      screen.getByRole("option", { name: "Server-managed key" }),
    ).toBeInTheDocument();
  });

  it("sends no credentials at all in server-key mode", async () => {
    const onScan = vi.fn();
    render(<ScanFormView onScan={onScan} serverKeyAvailable />);

    await userEvent.type(screen.getByLabelText("Hostname"), "web-01");
    await userEvent.selectOptions(screen.getByLabelText("Authentication"), "server");
    await userEvent.click(screen.getByRole("button", { name: "Start scan" }));

    const target = onScan.mock.calls[0][0];
    expect(target).not.toHaveProperty("password");
    expect(target).not.toHaveProperty("privateKey");
  });

  it("does not offer key auth for a Windows target", async () => {
    // WinRM has no SSH-key equivalent, so the backend rejects it outright.
    render(<ScanFormView onScan={vi.fn()} />);

    await userEvent.selectOptions(screen.getByLabelText("Platform"), "windows");

    expect(screen.queryByLabelText("Authentication")).not.toBeInTheDocument();
    expect(screen.getByLabelText("Password")).toBeInTheDocument();
  });
});
