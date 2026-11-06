// The Alerts panel in Settings (Req 21): what it shows, and what it cannot change.

import { describe, expect, it, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { SettingsView } from "./SettingsView";
import { makeNotificationSettings } from "../test-utils/factories";
import type { NotificationSettings } from "../types";

function renderAlerts(
  settings: NotificationSettings = makeNotificationSettings(),
  overrides: Partial<Parameters<typeof SettingsView>[0]> = {},
) {
  const props = {
    username: null as string | null,
    onChangePassword: vi.fn(),
    onListTokens: vi.fn().mockResolvedValue([]),
    onCreateToken: vi.fn(),
    onRevokeToken: vi.fn(),
    onGetNotifications: vi.fn().mockResolvedValue(settings),
    onSetNotifications: vi
      .fn()
      .mockImplementation(async (enabled: boolean, threshold: string, includeNotChecked: boolean) =>
        makeNotificationSettings({ ...settings, enabled, threshold, includeNotChecked }),
      ),
    onSendTestNotification: vi.fn().mockResolvedValue({ status: "sent", error: null }),
    onBack: vi.fn(),
    ...overrides,
  };
  render(<SettingsView {...props} />);
  return props;
}

describe("SettingsView alerts (Req 21)", () => {
  it("shows the destination by host, and what messages say", async () => {
    renderAlerts();

    const facts = await screen.findByTestId("alerts-facts");
    expect(facts).toHaveTextContent("Webhook at alerts.home.example.org");
    expect(facts).toHaveTextContent("Summary: counts only");
    expect(screen.getByLabelText("Send alerts after scheduled scans")).not.toBeChecked();
    expect(screen.getByLabelText("Alert on new findings that are")).toHaveValue("critical");
    expect(screen.getByLabelText("Also alert when a host could not be checked")).toBeChecked();
  });

  it("switches alerts on with a threshold (Req 21.1, 21.4)", async () => {
    const props = renderAlerts();

    await userEvent.click(await screen.findByLabelText("Send alerts after scheduled scans"));
    await userEvent.selectOptions(screen.getByLabelText("Alert on new findings that are"), "kev");
    await userEvent.click(screen.getByRole("button", { name: "Save alerts" }));

    await waitFor(() => expect(props.onSetNotifications).toHaveBeenCalledWith(true, "kev", true));
  });

  it("offers no control over where alerts go or how much they say (Req 21.10)", async () => {
    renderAlerts();
    await screen.findByTestId("alerts-facts");

    // Three controls, none of them a destination, token or detail level.
    expect(screen.getAllByRole("checkbox")).toHaveLength(2);
    expect(screen.getAllByRole("combobox")).toHaveLength(1);
    expect(screen.queryByRole("textbox")).not.toBeInTheDocument();
  });

  it("explains how to configure a destination, and will not switch on without one", async () => {
    renderAlerts(makeNotificationSettings({ configured: false, destinationHost: null }));

    expect(await screen.findByTestId("alerts-not-configured")).toHaveTextContent("CVEDECK_NOTIFY_URL");
    expect(screen.getByLabelText("Send alerts after scheduled scans")).toBeDisabled();
    expect(screen.getByRole("button", { name: "Send a test alert" })).toBeDisabled();
  });

  it("says why a detailed configuration sends summaries (Req 21.14)", async () => {
    renderAlerts(
      makeNotificationSettings({
        detailReason: "Detailed alerts need an access token; sending summaries.",
      }),
    );

    expect(await screen.findByTestId("alerts-facts")).toHaveTextContent("need an access token");
  });

  it("lists configuration problems and holds back the test alert", async () => {
    renderAlerts(
      makeNotificationSettings({
        problems: ["a token is set but the URL is plain http; use https"],
      }),
    );

    expect(await screen.findByTestId("alerts-problems")).toHaveTextContent("plain http");
    expect(screen.getByRole("button", { name: "Send a test alert" })).toBeDisabled();
  });

  it("warns about each opt-in that loosens the defaults", async () => {
    renderAlerts(makeNotificationSettings({ allowPublic: true, allowHttp: true, link: true }));

    const warnings = await screen.findByTestId("alerts-warnings");
    expect(warnings).toHaveTextContent("alerts may leave your network");
    expect(warnings).toHaveTextContent("plain http");
    expect(warnings).toHaveTextContent("link to this dashboard");
  });

  it("sends a test alert and reports a refusal in words", async () => {
    const props = renderAlerts(makeNotificationSettings(), {
      onSendTestNotification: vi.fn().mockResolvedValue({
        status: "refused",
        error: "alerts.home.example.org resolves to a public address",
      }),
    });

    await userEvent.click(await screen.findByRole("button", { name: "Send a test alert" }));

    expect(await screen.findByRole("alert")).toHaveTextContent("resolves to a public address");
    expect(props.onSendTestNotification).toHaveBeenCalledTimes(1);
  });

  it("shows the last alert's result", async () => {
    renderAlerts(
      makeNotificationSettings({
        enabled: true,
        lastSentAt: "2026-11-07T03:04:12Z",
        lastStatus: "failed",
        lastError: "alerts.home.example.org: HTTP 401",
      }),
    );

    expect(await screen.findByTestId("alerts-last")).toHaveTextContent(
      "Alert failed (alerts.home.example.org: HTTP 401)",
    );
  });

  it("suggests a random ntfy topic, made in the browser (Req 21.17)", async () => {
    const props = renderAlerts(makeNotificationSettings({ kind: "ntfy" }));

    await userEvent.click(await screen.findByRole("button", { name: "Suggest a topic name" }));

    expect(screen.getByTestId("alerts-topic").textContent).toMatch(/^cvd-[a-z0-9]{24}$/);
    // Nothing about the suggestion reaches the server.
    expect(props.onSetNotifications).not.toHaveBeenCalled();
    expect(props.onSendTestNotification).not.toHaveBeenCalled();
  });

  it("does not offer a topic for a webhook", async () => {
    renderAlerts();
    await screen.findByTestId("alerts-facts");
    expect(screen.queryByRole("button", { name: "Suggest a topic name" })).not.toBeInTheDocument();
  });
});
