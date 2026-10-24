import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import { CveScannerApiClient } from "./api/client";
import { ToastProvider } from "./components/Toast";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

const machine = {
  machine_id: "web-01",
  hostname: "web-01",
  platform: "linux",
  last_scan_status: "success",
  last_scanned_at: "2026-10-20T03:00:00Z",
  cve_counts: { critical: 0, unscored: 0, high: 1, medium: 0, low: 0 },
};

function job(overrides: Record<string, unknown> = {}) {
  return {
    id: "job-1",
    status: "running",
    requested_by: "schedule",
    created_at: "2026-10-24T03:00:00Z",
    started_at: "2026-10-24T03:00:00Z",
    finished_at: null,
    error_detail: null,
    cancellable: true,
    cancel_requested: false,
    targets: [
      { machine_id: "web-01", hostname: "web-01", state: "running", outcome: null },
      { machine_id: "web-02", hostname: "web-02", state: "queued", outcome: null },
    ],
    ...overrides,
  };
}

const cancelled = job({
  status: "cancelled",
  finished_at: "2026-10-24T03:01:00Z",
  error_detail: "Cancelled by admin after 1 of 2 hosts.",
  cancellable: false,
  targets: [
    {
      machine_id: "web-01",
      hostname: "web-01",
      state: "done",
      outcome: {
        machine_id: "web-01",
        status: "success",
        finding_count: 1,
        sources_ok: true,
        unavailable_sources: [],
        message: null,
        new_count: 0,
        resolved_count: 0,
        baseline: false,
      },
    },
    { machine_id: "web-02", hostname: "web-02", state: "cancelled", outcome: null },
  ],
});

/**
 * A backend with one scan already running when the page loads -- a scheduled
 * one, say -- and a cancel route answering ``cancel``.
 */
function client(active: Record<string, unknown>, cancel: () => Response) {
  let current: Record<string, unknown> = active;
  const fetchImpl = vi.fn(async (input: RequestInfo | URL, init?: RequestInit): Promise<Response> => {
    const [path, query] = (typeof input === "string" ? input : input.toString()).split("?");
    if (path === "/api/scans/jobs/job-1/cancel" && init?.method === "POST") {
      const response = cancel();
      if (response.ok) current = cancelled;
      return response;
    }
    switch (path) {
      case "/api/health":
        return jsonResponse({
          status: "ok",
          version: "0.13.0",
          capabilities: { demo_mode: false, login_required: false, server_ssh_key: true },
        });
      case "/api/machines":
        return jsonResponse([machine]);
      case "/api/feeds":
        return jsonResponse([]);
      case "/api/scans/jobs":
        return jsonResponse(query === "active=true" && current === active ? [active] : []);
      case "/api/scans/jobs/job-1":
        return jsonResponse(current);
      default:
        return jsonResponse({ detail: "not found" }, 404);
    }
  });
  return { api: new CveScannerApiClient({ fetchImpl }), fetchImpl };
}

/** As main.tsx mounts it: toasts are where cancelling reports back. */
function renderApp(api: CveScannerApiClient) {
  return render(
    <ToastProvider>
      <App client={api} />
    </ToastProvider>,
  );
}

describe("Cancelling a scan from the dashboard (Req 19.7-19.9)", () => {
  beforeEach(() => {
    window.location.hash = "";
  });

  it("cancels the running scan and reports what was scanned", async () => {
    const { api, fetchImpl } = client(job(), () => jsonResponse(job({ cancel_requested: true }), 202));
    renderApp(api);

    await userEvent.click(await screen.findByRole("button", { name: "Cancel scan" }));

    expect(fetchImpl).toHaveBeenCalledWith(
      "/api/scans/jobs/job-1/cancel",
      expect.objectContaining({ method: "POST" }),
    );
    // The job ends on the next poll, every POLL_MS.
    expect(
      await screen.findByText(/Scan cancelled: 1 of 2 host\(s\) scanned\./, {}, { timeout: 5000 }),
    ).toBeInTheDocument();
    await waitFor(() => expect(screen.queryByRole("button", { name: "Cancel scan" })).not.toBeInTheDocument());
  });

  it("offers no cancel for a scan a POST /api/scans caller is waiting on", async () => {
    const { api } = client(job({ cancellable: false }), () => jsonResponse({}, 500));
    renderApp(api);

    expect(await screen.findByText(/Scanning 1 of 2: web-01/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: "Cancel scan" })).not.toBeInTheDocument();
  });

  it("shows the backend's reason when the cancel is refused", async () => {
    const { api } = client(job(), () => jsonResponse({ detail: "This scan has already ended." }, 409));
    renderApp(api);

    await userEvent.click(await screen.findByRole("button", { name: "Cancel scan" }));

    expect(await screen.findByText(/This scan has already ended\./)).toBeInTheDocument();
  });
});

describe("The Scan history tab (Req 19.10)", () => {
  beforeEach(() => {
    window.location.hash = "";
  });

  it("opens Scan history at #/jobs, and marks a scan under way", async () => {
    const { api, fetchImpl } = client(job(), () => jsonResponse({}, 500));
    renderApp(api);

    const tab = await screen.findByRole("button", { name: /Scan history/ });
    await waitFor(() => expect(within(tab).getByText("running")).toBeInTheDocument());
    await userEvent.click(tab);

    expect(window.location.hash).toBe("#/jobs");
    expect(await screen.findByRole("heading", { name: "Scan history" })).toBeInTheDocument();
    expect(fetchImpl).toHaveBeenCalledWith("/api/scans/jobs?limit=100", expect.anything());
  });
});
