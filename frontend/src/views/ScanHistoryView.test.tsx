import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
import { ToastProvider } from "../components/Toast";
import { makeScanJob, makeScanOutcome } from "../test-utils/factories";
import type { ScanJob } from "../types";
import { HISTORY_LIMIT, HISTORY_POLL_MS, ScanHistoryView } from "./ScanHistoryView";

const finished = makeScanJob({
  id: "job-2",
  requestedBy: "schedule",
  createdAt: "2026-10-24T03:00:00",
  startedAt: "2026-10-24T03:00:00",
  finishedAt: "2026-10-24T03:02:10",
  targets: [
    {
      machineId: "web-01",
      hostname: "web-01",
      state: "done",
      outcome: makeScanOutcome({ machineId: "web-01", findingCount: 12, newCount: 2, resolvedCount: 1, baseline: false }),
    },
    {
      machineId: "db-01",
      hostname: "db-01",
      state: "done",
      outcome: makeScanOutcome({ machineId: "db-01", status: "auth_failure", message: "Permission denied" }),
    },
  ],
});

const cancelled = makeScanJob({
  id: "job-1",
  status: "cancelled",
  requestedBy: "admin",
  createdAt: "2026-10-23T09:00:00",
  startedAt: "2026-10-23T09:00:00",
  finishedAt: "2026-10-23T09:00:41",
  errorDetail: "Cancelled by admin after 1 of 2 hosts.",
  targets: [
    { machineId: "web-01", hostname: "web-01", state: "done", outcome: makeScanOutcome({ machineId: "web-01" }) },
    { machineId: "web-02", hostname: "web-02", state: "cancelled", outcome: null },
  ],
});

const running = makeScanJob({
  id: "job-3",
  status: "running",
  requestedBy: "token:ci",
  finishedAt: null,
  cancellable: true,
  targets: [{ machineId: "web-01", hostname: "web-01", state: "running", outcome: null }],
});

function api(lists: ScanJob[][], cancel = vi.fn().mockResolvedValue(running)) {
  const listScanJobs = vi.fn();
  for (const list of lists) listScanJobs.mockResolvedValueOnce(list);
  listScanJobs.mockResolvedValue(lists[lists.length - 1]);
  return { listScanJobs, cancelScanJob: cancel };
}

function renderView(client: ReturnType<typeof api>, onSelectMachine = vi.fn(), onNavigateScan = vi.fn()) {
  render(
    <ToastProvider>
      <ScanHistoryView api={client} onSelectMachine={onSelectMachine} onNavigateScan={onNavigateScan} />
    </ToastProvider>,
  );
  return { onSelectMachine, onNavigateScan };
}

afterEach(() => {
  vi.useRealTimers();
});

describe("ScanHistoryView (Req 19.10)", () => {
  it("lists every job kept, newest first, with who, outcome and duration", async () => {
    const client = api([[finished, cancelled]]);
    renderView(client);

    const rows = await screen.findAllByRole("button", { expanded: false });
    expect(client.listScanJobs).toHaveBeenCalledWith(HISTORY_LIMIT);
    expect(rows).toHaveLength(2);
    const first = rows[0].closest("tr")!;
    expect(within(first).getByText("Schedule")).toBeInTheDocument();
    expect(within(first).getByText("1 succeeded · 1 failed")).toBeInTheDocument();
    expect(within(first).getByText("2m 10s")).toBeInTheDocument();
    const second = rows[1].closest("tr")!;
    expect(within(second).getByText("Cancelled after 1 of 2")).toBeInTheDocument();
    expect(screen.getByText(/keeps the newest 100 scans/)).toBeInTheDocument();
  });

  it("opens a job in place to show each host, by click and by keyboard", async () => {
    const { onSelectMachine } = renderView(api([[finished, cancelled]]));
    const [toggle] = await screen.findAllByRole("button", { expanded: false });

    await userEvent.click(toggle);
    expect(toggle).toHaveAttribute("aria-expanded", "true");
    const hosts = document.getElementById(toggle.getAttribute("aria-controls")!)!;
    expect(within(hosts).getByText("12 (2 new, 1 resolved)")).toBeInTheDocument();
    expect(within(hosts).getByText("Authentication failed")).toBeInTheDocument();
    expect(within(hosts).getByText("Permission denied")).toBeInTheDocument();

    await userEvent.click(within(hosts).getByRole("button", { name: "db-01" }));
    expect(onSelectMachine).toHaveBeenCalledWith("db-01");

    toggle.focus();
    await userEvent.keyboard("{Enter}");
    expect(toggle).toHaveAttribute("aria-expanded", "false");
    expect(document.getElementById(toggle.getAttribute("aria-controls")!)).toBeNull();
  });

  it("shows why a cancelled job stopped and which hosts it never reached", async () => {
    renderView(api([[cancelled]]));
    await userEvent.click(await screen.findByRole("button", { expanded: false }));

    expect(screen.getByText("Cancelled by admin after 1 of 2 hosts.")).toBeInTheDocument();
    expect(screen.getByText("Cancelled -- not reached")).toBeInTheDocument();
  });

  it("offers Cancel only on a job that can be cancelled, and re-reads after", async () => {
    const client = api([[running, finished], [finished]]);
    renderView(client);

    const cancel = await screen.findByRole("button", { name: "Cancel" });
    expect(screen.getAllByRole("button", { name: "Cancel" })).toHaveLength(1);
    await userEvent.click(cancel);

    expect(client.cancelScanJob).toHaveBeenCalledWith("job-3");
    await waitFor(() => expect(client.listScanJobs).toHaveBeenCalledTimes(2));
    await waitFor(() => expect(screen.queryByRole("button", { name: "Cancel" })).not.toBeInTheDocument());
  });

  it("reports a refused cancel with the backend's reason", async () => {
    const client = api([[running]], vi.fn().mockRejectedValue(new ApiError(409, "This scan has already ended.")));
    renderView(client);

    await userEvent.click(await screen.findByRole("button", { name: "Cancel" }));
    expect(await screen.findByText("This scan has already ended.")).toBeInTheDocument();
  });

  it("polls while a job is under way, and stops once none is", async () => {
    vi.useFakeTimers();
    const client = api([[running], [finished]]);
    renderView(client);
    await act(async () => {
      await vi.advanceTimersByTimeAsync(0);
    });
    expect(client.listScanJobs).toHaveBeenCalledTimes(1);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(HISTORY_POLL_MS);
    });
    expect(client.listScanJobs).toHaveBeenCalledTimes(2);

    await act(async () => {
      await vi.advanceTimersByTimeAsync(HISTORY_POLL_MS * 3);
    });
    expect(client.listScanJobs).toHaveBeenCalledTimes(2);
  });

  it("says there are no scans yet and offers to start one", async () => {
    const { onNavigateScan } = renderView(api([[]]));

    expect(await screen.findByText("No scans yet.")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /New scan/ }));
    expect(onNavigateScan).toHaveBeenCalled();
  });

  it("pages through a long history", async () => {
    const many = Array.from({ length: 30 }, (_, i) =>
      makeScanJob({ id: `job-${i}`, requestedBy: `user${i}` }),
    );
    renderView(api([many]));

    expect(await screen.findByText("Showing 1 to 25 of 30 scans")).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /Next/ }));
    expect(screen.getByText("Showing 26 to 30 of 30 scans")).toBeInTheDocument();
    expect(within(screen.getByRole("table")).getByText("user29")).toBeInTheDocument();
  });

  it("reports a history that could not be loaded", async () => {
    const client = { listScanJobs: vi.fn().mockRejectedValue(new Error("Network down")), cancelScanJob: vi.fn() };
    renderView(client);

    expect(await screen.findByText(/Could not load scan history: Network down/)).toBeInTheDocument();
    expect(screen.getByText("No scans yet.")).toBeInTheDocument();
  });
});

describe("ScanHistoryView filters (Req 19.12)", () => {
  const partial = makeScanJob({
    id: "job-4",
    requestedBy: "token:ci",
    targets: [
      {
        machineId: "nas",
        hostname: "nas",
        state: "done",
        outcome: makeScanOutcome({ machineId: "nas", sourcesOk: false }),
      },
    ],
  });

  function startedCells() {
    return screen.queryAllByRole("button", { expanded: false }).map((b) => b.closest("tr")!);
  }

  it("narrows by host, matching any host in the job and ignoring case", async () => {
    renderView(api([[finished, cancelled, partial]]));
    await screen.findAllByRole("button", { expanded: false });

    await userEvent.type(screen.getByRole("textbox", { name: "Search scans by host" }), "WEB-02");
    expect(startedCells()).toHaveLength(1);
    expect(within(startedCells()[0]).getByText("Cancelled after 1 of 2")).toBeInTheDocument();
    expect(screen.getByText("Showing 1 to 1 of 1 scans (filtered from 3)")).toBeInTheDocument();
  });

  it("narrows by outcome, counting each, with a job listed under every outcome its hosts had", async () => {
    renderView(api([[finished, cancelled, partial]]));
    await screen.findAllByRole("button", { expanded: false });
    const outcome = screen.getByRole("combobox", { name: "Filter by outcome" });

    expect(within(outcome).getByRole("option", { name: "Failed or interrupted (1)" })).toBeInTheDocument();
    expect(within(outcome).getByRole("option", { name: "Partial (1)" })).toBeInTheDocument();
    expect(within(outcome).getByRole("option", { name: "Cancelled (1)" })).toBeInTheDocument();

    await userEvent.selectOptions(outcome, "failed");
    expect(startedCells()).toHaveLength(1);
    expect(within(startedCells()[0]).getByText("1 succeeded · 1 failed")).toBeInTheDocument();

    await userEvent.selectOptions(outcome, "partial");
    expect(within(startedCells()[0]).getByText("API token ci")).toBeInTheDocument();
  });

  it("narrows by requester, offering only who has requested a kept scan", async () => {
    renderView(api([[finished, cancelled, partial]]));
    await screen.findAllByRole("button", { expanded: false });
    const requester = screen.getByRole("combobox", { name: "Filter by requester" });

    expect(within(requester).getAllByRole("option").map((o) => o.textContent)).toEqual([
      "Anyone",
      "admin",
      "API token ci",
      "Schedule",
    ]);
    await userEvent.selectOptions(requester, "schedule");
    expect(startedCells()).toHaveLength(1);
    expect(within(startedCells()[0]).getByText("Schedule")).toBeInTheDocument();
  });

  it("names every filter excluding the rows, and clears them all", async () => {
    renderView(api([[finished, cancelled, partial]]));
    await screen.findAllByRole("button", { expanded: false });

    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Filter by requester" }), "schedule");
    await userEvent.selectOptions(screen.getByRole("combobox", { name: "Filter by outcome" }), "cancelled");

    expect(screen.getByText("No scans match the current filters.")).toBeInTheDocument();
    const status = screen.getByText("No scans match the current filters.").closest<HTMLElement>("[role=status]")!;
    expect(within(status).getByText("Cancelled")).toBeInTheDocument();
    expect(within(status).getByText("Schedule")).toBeInTheDocument();
    expect(screen.queryByText("No scans yet.")).not.toBeInTheDocument();

    await userEvent.click(screen.getByRole("button", { name: "Clear filters" }));
    expect(startedCells()).toHaveLength(3);
  });

  it("goes back to the first page when a filter changes", async () => {
    const many = Array.from({ length: 30 }, (_, i) => makeScanJob({ id: `job-${i}`, requestedBy: "schedule" }));
    renderView(api([many]));
    await userEvent.click(await screen.findByRole("button", { name: /Next/ }));
    expect(screen.getByText("Showing 26 to 30 of 30 scans")).toBeInTheDocument();

    await userEvent.type(screen.getByRole("textbox", { name: "Search scans by host" }), "web");
    expect(screen.getByText("Showing 1 to 25 of 30 scans")).toBeInTheDocument();
  });
});
