import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { CveScannerApiClient } from "./api/client";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/** Enough backend for the shell: health, an empty fleet, and the schedule. */
function client({ demoMode }: { demoMode: boolean }) {
  const fetchImpl = vi.fn(async (input: RequestInfo | URL): Promise<Response> => {
    const path = (typeof input === "string" ? input : input.toString()).split("?")[0];
    switch (path) {
      case "/api/health":
        return jsonResponse({
          status: "ok",
          version: "0.12.0",
          capabilities: { demo_mode: demoMode, login_required: false, server_ssh_key: true },
        });
      case "/api/machines":
      case "/api/feeds":
      case "/api/scans/jobs":
        return jsonResponse([]);
      case "/api/scan-schedule":
        return jsonResponse({
          enabled: false,
          time_of_day: "03:00",
          timezone: "UTC",
          eligible_hosts: 0,
          server_key_configured: true,
        });
      default:
        return jsonResponse({ detail: "not found" }, 404);
    }
  });
  return new CveScannerApiClient({ fetchImpl });
}

describe("Settings without sign-in (Req 20.2)", () => {
  beforeEach(() => {
    window.location.hash = "";
  });

  it("is offered when sign-in is off, so the schedule can be set", async () => {
    render(<App client={client({ demoMode: false })} />);

    await userEvent.click(await screen.findByRole("button", { name: "Settings" }));

    expect(await screen.findByLabelText("Scan every day")).toBeInTheDocument();
    expect(screen.queryByText("Change password")).not.toBeInTheDocument();
  });

  it("is not offered in a public demo, which changes nothing", async () => {
    render(<App client={client({ demoMode: true })} />);

    await screen.findByText(/demo/i);
    expect(screen.queryByRole("button", { name: "Settings" })).not.toBeInTheDocument();
  });
});
