import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { ApiError } from "../api/client";
import { makeScanJob, makeScanOutcome } from "../test-utils/factories";
import type { ScanJob } from "../types";
import { POLL_MS, progressLabel, useScanJob } from "./useScanJob";

const running = (index: number): ScanJob =>
  makeScanJob({
    status: "running",
    finishedAt: null,
    targets: ["web-01", "web-02", "web-03"].map((hostname, i) => ({
      machineId: hostname,
      hostname,
      state: i < index ? "done" : i === index ? "running" : "queued",
      outcome: i < index ? makeScanOutcome({ machineId: hostname }) : null,
    })),
  });

function fakeApi(overrides: Partial<Record<"startScanJob" | "getScanJob" | "listActiveScanJobs", unknown>> = {}) {
  return {
    startScanJob: vi.fn().mockResolvedValue("job-1"),
    getScanJob: vi.fn(),
    listActiveScanJobs: vi.fn().mockResolvedValue([]),
    ...overrides,
  } as unknown as Parameters<typeof useScanJob>[0] & {
    startScanJob: ReturnType<typeof vi.fn>;
    getScanJob: ReturnType<typeof vi.fn>;
    listActiveScanJobs: ReturnType<typeof vi.fn>;
  };
}

beforeEach(() => {
  vi.useFakeTimers();
});

afterEach(() => {
  vi.useRealTimers();
});

async function tick() {
  await act(async () => {
    await vi.advanceTimersByTimeAsync(POLL_MS);
  });
}

describe("progressLabel", () => {
  it("names the host being scanned and where it is in the job (Req 19.2)", () => {
    expect(progressLabel(running(1))).toBe("Scanning 2 of 3: web-02");
  });

  it("says a queued job is waiting for another scan", () => {
    expect(progressLabel(makeScanJob({ status: "queued" }))).toMatch(/waiting for another scan/i);
  });
});

describe("useScanJob", () => {
  it("polls a job until it finishes, and reports it once (Req 19.2)", async () => {
    const api = fakeApi();
    api.getScanJob
      .mockResolvedValueOnce(running(0))
      .mockResolvedValueOnce(running(1))
      .mockResolvedValueOnce(makeScanJob())
      .mockResolvedValue(makeScanJob());
    const onFinished = vi.fn();
    const { result } = renderHook(() => useScanJob(api, onFinished, vi.fn()));

    await act(async () => {
      await result.current.start([{ id: "web-01", hostname: "web-01", platform: "linux" }]);
    });
    expect(result.current.job && progressLabel(result.current.job)).toBe("Scanning 1 of 3: web-01");

    await tick();
    expect(result.current.job && progressLabel(result.current.job)).toBe("Scanning 2 of 3: web-02");

    await tick();
    expect(result.current.job).toBeNull();
    expect(onFinished).toHaveBeenCalledTimes(1);

    await tick();
    await tick();
    expect(onFinished).toHaveBeenCalledTimes(1);
    expect(api.getScanJob).toHaveBeenCalledTimes(3);
  });

  it("picks up a scan still running after a reload (Req 19.2)", async () => {
    const api = fakeApi({ listActiveScanJobs: vi.fn().mockResolvedValue([running(2)]) });
    api.getScanJob.mockResolvedValue(makeScanJob());
    const onFinished = vi.fn();
    const { result } = renderHook(() => useScanJob(api, onFinished, vi.fn()));

    await act(async () => {
      await Promise.resolve();
    });
    expect(result.current.job?.status).toBe("running");

    await tick();
    expect(onFinished).toHaveBeenCalledTimes(1);
  });

  it("stops and says so when the job has gone", async () => {
    const api = fakeApi();
    api.getScanJob
      .mockResolvedValueOnce(running(0))
      .mockRejectedValue(new ApiError(404, "No such scan job", "No such scan job"));
    const onLost = vi.fn();
    const { result } = renderHook(() => useScanJob(api, vi.fn(), onLost));

    await act(async () => {
      await result.current.start([{ id: "web-01", hostname: "web-01", platform: "linux" }]);
    });
    await tick();
    await tick();

    expect(result.current.job).toBeNull();
    expect(onLost).toHaveBeenCalledTimes(1);
    expect(api.getScanJob).toHaveBeenCalledTimes(2);
  });

  it("keeps polling through a dropped connection", async () => {
    const api = fakeApi();
    api.getScanJob
      .mockResolvedValueOnce(running(0))
      .mockRejectedValueOnce(new TypeError("Failed to fetch"))
      .mockResolvedValue(makeScanJob());
    const onFinished = vi.fn();
    const { result } = renderHook(() => useScanJob(api, onFinished, vi.fn()));

    await act(async () => {
      await result.current.start([{ id: "web-01", hostname: "web-01", platform: "linux" }]);
    });
    await tick();
    await tick();

    expect(onFinished).toHaveBeenCalledTimes(1);
  });

  it("stops polling when the page goes away", async () => {
    const api = fakeApi();
    api.getScanJob.mockResolvedValue(running(0));
    const { result, unmount } = renderHook(() => useScanJob(api, vi.fn(), vi.fn()));

    await act(async () => {
      await result.current.start([{ id: "web-01", hostname: "web-01", platform: "linux" }]);
    });
    unmount();
    const calls = api.getScanJob.mock.calls.length;
    await tick();
    await tick();

    expect(api.getScanJob.mock.calls.length).toBe(calls);
  });
});
