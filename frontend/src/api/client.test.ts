import { describe, expect, it, vi } from "vitest";
import { ApiError, CveScannerApiClient } from "./client";
import type { MachineSummary } from "../types";
import { makeMachine } from "../test-utils/factories";

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("CveScannerApiClient", () => {
  it("requests the machine list from GET /api/machines and maps snake_case to camelCase", async () => {
    // The backend serializes MachineSummary with snake_case keys.
    const wire = [
      {
        machine_id: "m1",
        hostname: "host-1",
        platform: "linux",
        last_scan_status: "success",
        cve_counts: { critical: 1, high: 2, medium: 0, low: 3 },
      },
    ];
    const expected: MachineSummary[] = [
      makeMachine({
        machineId: "m1",
        hostname: "host-1",
        platform: "linux",
        lastScanStatus: "success",
        // Absent from the wire payload above, so the client defaults them.
        lastScannedAt: null,
        lastScanSourcesOk: false,
        cveCounts: { critical: 1, high: 2, medium: 0, low: 3 },
      }),
    ];
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(wire));
    const client = new CveScannerApiClient({ fetchImpl });

    const result = await client.listMachines();

    expect(result).toEqual(expected);
    expect(fetchImpl).toHaveBeenCalledWith(
      "/api/machines",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("reads an absent sources-ok flag as incomplete, and a sent one as sent", async () => {
    // A missing answer must never be presentable as a good one: "every
    // advisory source answered" is the claim that needs evidence.
    const base = {
      machine_id: "m1",
      hostname: "host-1",
      platform: "linux",
      last_scan_status: "success",
      cve_counts: { critical: 0, high: 0, medium: 0, low: 0 },
    };
    const fetchImpl = vi
      .fn()
      .mockResolvedValueOnce(jsonResponse([base]))
      .mockResolvedValueOnce(jsonResponse([{ ...base, last_scan_sources_ok: true }]));
    const client = new CveScannerApiClient({ fetchImpl });

    const [absent] = await client.listMachines();
    const [sent] = await client.listMachines();

    expect(absent.lastScanSourcesOk).toBe(false);
    expect(sent.lastScanSourcesOk).toBe(true);
  });

  it("calls the global fetch with the global as its receiver when none is injected", async () => {
    // Regression: the default fetch was stored unbound and then called as
    // this.fetchImpl, so the browser received the client as fetch's receiver
    // and rejected every request with "Illegal invocation". Every other test
    // injects fetchImpl, so only this one exercises the default.
    const calls: unknown[] = [];
    const globalFetch = vi.fn(function (this: unknown, ...args: unknown[]) {
      // Browsers throw a TypeError when fetch is invoked on a foreign receiver;
      // node/jsdom are lenient, so assert the receiver explicitly here.
      if (this !== globalThis && this !== undefined) {
        throw new TypeError(
          "Failed to execute 'fetch' on 'Window': Illegal invocation",
        );
      }
      calls.push(args);
      return Promise.resolve(jsonResponse([]));
    });
    const original = globalThis.fetch;
    globalThis.fetch = globalFetch as unknown as typeof fetch;
    try {
      const client = new CveScannerApiClient();

      await expect(client.listMachines()).resolves.toEqual([]);

      expect(globalFetch).toHaveBeenCalledTimes(1);
      expect(globalFetch.mock.instances[0]).toBe(globalThis);
    } finally {
      globalThis.fetch = original;
    }
  });

  it("appends the severity query param when filtering machine CVEs", async () => {
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse([]));
    const client = new CveScannerApiClient({ fetchImpl });

    await client.getMachineCves("m 1", "critical");

    expect(fetchImpl).toHaveBeenCalledWith(
      "/api/machines/m%201/cves?severity=critical",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("posts a remediation record with a JSON body and maps the response", async () => {
    // The backend serializes RemediationOut with snake_case keys.
    const wire = {
      record_id: "r1",
      machine_id: "m1",
      cve_id: "CVE-2024-0001",
      status: "in_progress",
      note: "patching",
    };
    const fetchImpl = vi.fn().mockResolvedValue(jsonResponse(wire));
    const client = new CveScannerApiClient({ fetchImpl });

    const result = await client.addRemediation("m1", "CVE-2024-0001", {
      status: "in_progress",
      note: "patching",
    });

    expect(result).toEqual({
      recordId: "r1",
      machineId: "m1",
      cveId: "CVE-2024-0001",
      status: "in_progress",
      note: "patching",
    });
    expect(fetchImpl).toHaveBeenCalledWith(
      "/api/machines/m1/cves/CVE-2024-0001/remediation",
      expect.objectContaining({
        method: "POST",
        body: JSON.stringify({ status: "in_progress", note: "patching" }),
      }),
    );
  });

  it("throws ApiError on a non-2xx response", async () => {
    const fetchImpl = vi
      .fn()
      .mockResolvedValue(jsonResponse({ detail: "not found" }, 404));
    const client = new CveScannerApiClient({ fetchImpl });

    await expect(client.getMachine("missing")).rejects.toBeInstanceOf(
      ApiError,
    );
  });
});
