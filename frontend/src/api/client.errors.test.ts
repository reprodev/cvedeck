import { describe, expect, it, vi } from "vitest";

import { ApiError, ApiTimeoutError, CveScannerApiClient } from "./client";

function respondWith(status: number, body: string, contentType = "application/json") {
  return vi.fn(async () =>
    new Response(body, { status, headers: { "Content-Type": contentType } }),
  ) as unknown as typeof fetch;
}

describe("ApiClient error reporting", () => {
  it("surfaces FastAPI's detail string instead of a bare status code", async () => {
    // Previously every failure read "failed with status 422", discarding the
    // only text that told the user what was actually wrong.
    const client = new CveScannerApiClient({
      fetchImpl: respondWith(422, JSON.stringify({ detail: "Invalid CIDR: '10.0.0'" })),
    });

    await expect(client.listMachines()).rejects.toThrow("Invalid CIDR: '10.0.0'");
  });

  it("exposes the detail separately from the message", async () => {
    const client = new CveScannerApiClient({
      fetchImpl: respondWith(404, JSON.stringify({ detail: "Machine not found" })),
    });

    const error = await client.listMachines().catch((e: unknown) => e);
    expect(error).toBeInstanceOf(ApiError);
    expect((error as ApiError).status).toBe(404);
    expect((error as ApiError).detail).toBe("Machine not found");
  });

  it("flattens a 422 validation error array into a readable message", async () => {
    const body = JSON.stringify({
      detail: [
        { loc: ["body", "cidr"], msg: "field required" },
        { loc: ["body", "ports"], msg: "value is not a valid list" },
      ],
    });
    const client = new CveScannerApiClient({ fetchImpl: respondWith(422, body) });

    const error = await client.listMachines().catch((e: unknown) => e);
    expect((error as ApiError).message).toBe(
      "cidr: field required; ports: value is not a valid list",
    );
  });

  it("falls back to the status when the body carries no usable detail", async () => {
    const client = new CveScannerApiClient({ fetchImpl: respondWith(500, "") });

    await expect(client.listMachines()).rejects.toThrow(/failed with status 500/);
  });

  it("ignores an HTML error page rather than dumping it into the UI", async () => {
    // A reverse proxy returns HTML, which is a document, not a message.
    const client = new CveScannerApiClient({
      fetchImpl: respondWith(502, "<html><body>Bad Gateway</body></html>", "text/html"),
    });

    const error = await client.listMachines().catch((e: unknown) => e);
    expect((error as ApiError).message).toMatch(/failed with status 502/);
    expect((error as ApiError).message).not.toContain("<html>");
  });

  it("uses a short plain-text body as the message", async () => {
    const client = new CveScannerApiClient({
      fetchImpl: respondWith(503, "Service temporarily unavailable", "text/plain"),
    });

    await expect(client.listMachines()).rejects.toThrow(
      "Service temporarily unavailable",
    );
  });

  it("turns a hung request into a timeout rather than hanging forever", async () => {
    // Without a deadline the UI button stays disabled with no way back but a reload.
    const never = vi.fn(
      (_url: string, init?: RequestInit) =>
        new Promise<Response>((_resolve, reject) => {
          init?.signal?.addEventListener("abort", () => {
            const error = new Error("aborted");
            error.name = "AbortError";
            reject(error);
          });
        }),
    ) as unknown as typeof fetch;

    const client = new CveScannerApiClient({ fetchImpl: never, timeoutMs: 10 });

    await expect(client.listMachines()).rejects.toBeInstanceOf(ApiTimeoutError);
  });
});
