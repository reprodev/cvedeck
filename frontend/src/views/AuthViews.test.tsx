// Sign-in, setup and account settings pages (Req 16.2, 16.3, 16.6, 16.7, 16.8).

import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { ApiError } from "../api/client";
import type { ApiToken, CreatedApiToken, HostKeyPin } from "../types";
import { LoginView } from "./LoginView";
import { SettingsView } from "./SettingsView";
import { SetupView } from "./SetupView";

describe("LoginView", () => {
  it("uses the autocomplete names password managers look for", () => {
    render(<LoginView onLogin={vi.fn()} onSignedIn={vi.fn()} />);

    expect(screen.getByLabelText("Username")).toHaveAttribute("autocomplete", "username");
    expect(screen.getByLabelText("Password")).toHaveAttribute("autocomplete", "current-password");
    expect(screen.getByLabelText("Password")).toHaveAttribute("type", "password");
  });

  it("shows the server's reason and clears the password after a failure", async () => {
    const user = userEvent.setup();
    const onLogin = vi
      .fn()
      .mockRejectedValue(new ApiError(401, "Incorrect username or password."));
    render(<LoginView onLogin={onLogin} onSignedIn={vi.fn()} />);

    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "wrong password");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Incorrect username or password.");
    expect(screen.getByLabelText("Password")).toHaveValue("");
  });

  it("tells the user how long to wait when throttled", async () => {
    const user = userEvent.setup();
    const onLogin = vi
      .fn()
      .mockRejectedValue(new ApiError(429, "Too many failed attempts. Try again in 30 seconds."));
    render(<LoginView onLogin={onLogin} onSignedIn={vi.fn()} />);

    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "whatever");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("Try again in 30 seconds");
  });

  it("hands the new state up on success", async () => {
    const user = userEvent.setup();
    const state = { state: "signed_in" as const, username: "admin" };
    const onSignedIn = vi.fn();
    render(<LoginView onLogin={vi.fn().mockResolvedValue(state)} onSignedIn={onSignedIn} />);

    await user.type(screen.getByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "correct horse battery");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    await waitFor(() => expect(onSignedIn).toHaveBeenCalledWith(state));
  });
});

describe("SetupView", () => {
  async function fill(code: string, password: string, confirm = password) {
    const user = userEvent.setup();
    await user.type(screen.getByLabelText("Setup code"), code);
    await user.type(screen.getByLabelText("Password"), password);
    await user.type(screen.getByLabelText("Repeat password"), confirm);
    await user.click(screen.getByRole("button", { name: /Create account/ }));
  }

  it("does not send mismatched passwords", async () => {
    const onSetup = vi.fn();
    render(<SetupView onSetup={onSetup} onSignedIn={vi.fn()} />);

    await fill("7KQ4-M2XD-9HPA", "correct horse battery", "correct horse batterY");

    expect(await screen.findByRole("alert")).toHaveTextContent("do not match");
    expect(onSetup).not.toHaveBeenCalled();
  });

  it("does not send a password the server would refuse for length", async () => {
    const onSetup = vi.fn();
    render(<SetupView onSetup={onSetup} onSignedIn={vi.fn()} />);

    await fill("7KQ4-M2XD-9HPA", "short");

    expect(await screen.findByRole("alert")).toHaveTextContent("at least 12");
    expect(onSetup).not.toHaveBeenCalled();
  });

  it("sends the code, username and password, and shows a refused code", async () => {
    const onSetup = vi
      .fn()
      .mockRejectedValue(new ApiError(400, "That setup code is not valid."));
    render(<SetupView onSetup={onSetup} onSignedIn={vi.fn()} />);

    await fill("7KQ4-M2XD-9HPA", "correct horse battery");

    expect(onSetup).toHaveBeenCalledWith("7KQ4-M2XD-9HPA", "admin", "correct horse battery");
    expect(await screen.findByRole("alert")).toHaveTextContent("setup code is not valid");
  });
});

describe("SettingsView", () => {
  const existing: ApiToken = {
    tokenId: "t1",
    name: "cron",
    prefix: "cvd_AbCdEf",
    createdAt: "2026-09-14T10:00:00Z",
    lastUsedAt: null,
    revokedAt: null,
  };

  function renderSettings(overrides: Partial<Parameters<typeof SettingsView>[0]> = {}) {
    const props = {
      username: "admin",
      onChangePassword: vi.fn().mockResolvedValue(undefined),
      onListTokens: vi.fn().mockResolvedValue([existing]),
      onCreateToken: vi.fn(),
      onRevokeToken: vi.fn().mockResolvedValue(undefined),
      onBack: vi.fn(),
      ...overrides,
    };
    render(<SettingsView {...props} />);
    return props;
  }

  it("lists tokens by name and prefix, never the token", async () => {
    renderSettings();

    const table = await screen.findByRole("table");
    expect(within(table).getByText("cron")).toBeInTheDocument();
    expect(within(table).getByText("cvd_AbCdEf…")).toBeInTheDocument();
    expect(within(table).getByText("Never")).toBeInTheDocument();
  });

  it("shows a new token once, with a warning and a copy button", async () => {
    const user = userEvent.setup();
    const created: CreatedApiToken = {
      ...existing,
      tokenId: "t2",
      name: "script",
      prefix: "cvd_ZyXwVu",
      token: "cvd_ZyXwVuFULLSECRETVALUE",
    };
    const props = renderSettings({ onCreateToken: vi.fn().mockResolvedValue(created) });
    await screen.findByRole("table");

    await user.type(screen.getByLabelText("New token name"), "script");
    await user.click(screen.getByRole("button", { name: /Create token/ }));

    expect(props.onCreateToken).toHaveBeenCalledWith("script");
    expect(await screen.findByTestId("created-token")).toHaveTextContent(created.token);
    expect(screen.getByText(/will not be shown again/)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Copy/ })).toBeInTheDocument();
  });

  it("asks before revoking, and revokes only on confirmation", async () => {
    const user = userEvent.setup();
    const props = renderSettings();
    await screen.findByRole("table");

    await user.click(screen.getByRole("button", { name: "Revoke cron" }));
    expect(props.onRevokeToken).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: 'Revoke "cron"' }));

    await waitFor(() => expect(props.onRevokeToken).toHaveBeenCalledWith("t1"));
  });

  it("does not send a password change whose new passwords differ", async () => {
    const user = userEvent.setup();
    const props = renderSettings();

    await user.type(screen.getByLabelText("Current password"), "correct horse battery");
    await user.type(screen.getByLabelText("New password"), "a brand new passphrase");
    await user.type(screen.getByLabelText("Repeat new password"), "a brand new passphrasE");
    await user.click(screen.getByRole("button", { name: "Change password" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("do not match");
    expect(props.onChangePassword).not.toHaveBeenCalled();
  });

  it("shows the server's reason when the current password is wrong", async () => {
    const user = userEvent.setup();
    renderSettings({
      onChangePassword: vi
        .fn()
        .mockRejectedValue(new ApiError(400, "Your current password is incorrect.")),
    });

    await user.type(screen.getByLabelText("Current password"), "not it at all");
    await user.type(screen.getByLabelText("New password"), "a brand new passphrase");
    await user.type(screen.getByLabelText("Repeat new password"), "a brand new passphrase");
    await user.click(screen.getByRole("button", { name: "Change password" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("current password is incorrect");
  });
});

describe("SettingsView pinned host keys (Req 17.10)", () => {
  const enrolled: HostKeyPin = {
    hostname: "web-01.lan",
    port: 22,
    keyType: "ssh-ed25519",
    fingerprint: "SHA256:nThbg6kXUpJWGl7E1IGOCspRomTxdCARLviKw6E5SY8",
    firstSeenAt: "2026-09-10T10:00:00Z",
    lastSeenAt: "2026-09-15T10:00:00Z",
    machineId: "m1",
  };
  const unenrolled: HostKeyPin = {
    ...enrolled,
    hostname: "test-only.lan",
    port: 2222,
    machineId: null,
  };

  function renderHostKeys(overrides: Record<string, unknown> = {}) {
    const props = {
      username: "admin",
      onChangePassword: vi.fn().mockResolvedValue(undefined),
      onListTokens: vi.fn().mockResolvedValue([]),
      onCreateToken: vi.fn(),
      onRevokeToken: vi.fn().mockResolvedValue(undefined),
      onListHostKeys: vi.fn().mockResolvedValue([enrolled, unenrolled]),
      onForgetHostKey: vi.fn().mockResolvedValue(undefined),
      onBack: vi.fn(),
      ...overrides,
    };
    render(<SettingsView {...props} />);
    return props;
  }

  it("lists a pin with no enrolled machine, and says so", async () => {
    renderHostKeys();

    // The pin that no machine page can show is the reason this panel exists.
    const row = (await screen.findByText("test-only.lan:2222")).closest("tr")!;
    expect(within(row).getByText("Not enrolled")).toBeInTheDocument();
    expect(within(row).getByText(/ssh-ed25519 SHA256:/)).toBeInTheDocument();
    const enrolledRow = screen.getByText("web-01.lan:22").closest("tr")!;
    expect(within(enrolledRow).getByRole("link", { name: "Open" })).toHaveAttribute(
      "href",
      "#/machines/m1",
    );
  });

  it("forgets only after confirming, and sends the port it was pinned under", async () => {
    const user = userEvent.setup();
    const props = renderHostKeys();

    await user.click(
      await screen.findByRole("button", { name: "Forget host key for test-only.lan:2222" }),
    );
    expect(props.onForgetHostKey).not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: "Cancel" }));
    expect(props.onForgetHostKey).not.toHaveBeenCalled();

    await user.click(
      screen.getByRole("button", { name: "Forget host key for test-only.lan:2222" }),
    );
    await user.click(screen.getByRole("button", { name: "Forget test-only.lan:2222" }));

    expect(props.onForgetHostKey).toHaveBeenCalledWith("test-only.lan", 2222);
    // The list is re-read, so a forgotten pin leaves the page.
    expect(props.onListHostKeys).toHaveBeenCalledTimes(2);
  });

  it("shows the server's reason when a pin cannot be forgotten", async () => {
    const user = userEvent.setup();
    renderHostKeys({
      onForgetHostKey: vi
        .fn()
        .mockRejectedValue(new ApiError(404, "No host key is pinned for that address")),
    });

    await user.click(
      await screen.findByRole("button", { name: "Forget host key for web-01.lan:22" }),
    );
    await user.click(screen.getByRole("button", { name: "Forget web-01.lan:22" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("No host key is pinned");
  });

  it("is absent when the shell does not supply the host key callbacks", () => {
    render(
      <SettingsView
        username="admin"
        onChangePassword={vi.fn()}
        onListTokens={vi.fn().mockResolvedValue([])}
        onCreateToken={vi.fn()}
        onRevokeToken={vi.fn()}
        onBack={vi.fn()}
      />,
    );

    expect(screen.queryByText("Pinned SSH host keys")).not.toBeInTheDocument();
  });
});
