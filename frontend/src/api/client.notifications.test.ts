// The alert settings' wire mapping (Req 21.22): the newly-exploited switch and
// what the last alert was about, in both directions.

import { describe, expect, it, vi } from "vitest";

import { CveScannerApiClient } from "./client";

const WIRE = {
  configured: true,
  kind: "webhook",
  destination_host: "alerts.home.example.org",
  problems: [],
  detail_in_effect: "summary",
  allow_http: false,
  allow_public: false,
  link: false,
  signed: true,
  enabled: true,
  threshold: "critical",
  include_not_checked: true,
};

function clientReturning(body: unknown) {
  const fetchImpl = vi.fn(
    async (_input: RequestInfo | URL, _init?: RequestInit): Promise<Response> =>
      new Response(JSON.stringify(body), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
  );
  return { api: new CveScannerApiClient({ fetchImpl }), fetchImpl };
}

describe("alert settings mapping", () => {
  it("maps the switch and the last event", async () => {
    const { api } = clientReturning({
      ...WIRE,
      include_newly_exploited: false,
      last_event: "kev_update",
    });

    const settings = await api.getNotifications();

    expect(settings.includeNewlyExploited).toBe(false);
    expect(settings.lastEvent).toBe("kev_update");
  });

  it("reads an older server's silence as off and unknown, never as on", async () => {
    const { api } = clientReturning(WIRE);

    const settings = await api.getNotifications();

    expect(settings.includeNewlyExploited).toBe(false);
    expect(settings.lastEvent).toBeNull();
  });

  it("sends the switch when saving", async () => {
    const { api, fetchImpl } = clientReturning({ ...WIRE, include_newly_exploited: false });

    await api.setNotifications(true, "kev", false, false);

    const init = fetchImpl.mock.calls[0][1] as RequestInit;
    expect(JSON.parse(String(init.body))).toEqual({
      enabled: true,
      threshold: "kev",
      include_not_checked: false,
      include_newly_exploited: false,
    });
  });
});
