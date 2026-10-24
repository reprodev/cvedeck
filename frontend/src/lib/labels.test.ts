import { afterAll, beforeAll, describe, expect, it } from "vitest";

import {
  durationLabel,
  formatServerTime,
  parseServerTime,
  requestedByLabel,
  isStale,
  relativeTime,
  severityLabel,
  statusLabel,
  statusTone,
  isHostKeyStatus,
} from "./labels";

describe("statusLabel", () => {
  it("gives every scan status a human-readable label", () => {
    // The fleet table used to render the raw enum, e.g. "connection_failure".
    expect(statusLabel("success")).toBe("Success");
    expect(statusLabel("never_scanned")).toBe("Never scanned");
    expect(statusLabel("connection_failure")).toBe("Could not connect");
    expect(statusLabel("auth_failure")).toBe("Authentication failed");
    // A host that answered but could not be inventoried: a failure of its own,
    // never a scan that found nothing (Req 1.7).
    expect(statusLabel("inventory_unavailable")).toBe("No inventory could be read");
  });

  it("passes through an unrecognized status rather than hiding it", () => {
    expect(statusLabel("something_new")).toBe("something_new");
  });
});

describe("statusTone", () => {
  it("treats never_scanned as neutral, not a failure", () => {
    // Enrollment used to stamp CONNECTION_FAILURE, so every host added from
    // discovery showed a red badge before anything had been attempted.
    expect(statusTone("never_scanned")).toBe("neutral");
    expect(statusTone("success")).toBe("success");
    expect(statusTone("connection_failure")).toBe("failure");
    expect(statusTone("auth_failure")).toBe("failure");
  });

  it("gives a refused host key the amber caveat tone, never red", () => {
    // Red is reserved for exploitation; a changed key needs a person, not a retry.
    expect(statusTone("host_key_mismatch")).toBe("warn");
    expect(statusTone("host_key_unknown")).toBe("warn");
    expect(statusLabel("host_key_mismatch")).toBe("Host key changed");
    expect(statusLabel("host_key_unknown")).toBe("Host key not pinned");
    // Test connection reports the same statuses in upper case.
    expect(isHostKeyStatus("HOST_KEY_MISMATCH")).toBe(true);
    expect(isHostKeyStatus("connection_failure")).toBe(false);
  });
});

describe("relativeTime", () => {
  const now = new Date("2026-09-01T12:00:00Z");

  it("reports a never-scanned machine as Never", () => {
    expect(relativeTime(null, now)).toBe("Never");
  });

  it("scales the unit with the age", () => {
    expect(relativeTime("2026-09-01T11:59:40Z", now)).toBe("Just now");
    expect(relativeTime("2026-09-01T11:30:00Z", now)).toBe("30m ago");
    expect(relativeTime("2026-09-01T06:00:00Z", now)).toBe("6h ago");
    expect(relativeTime("2026-08-25T12:00:00Z", now)).toBe("7d ago");
    expect(relativeTime("2026-06-01T12:00:00Z", now)).toBe("3mo ago");
    expect(relativeTime("2024-09-01T12:00:00Z", now)).toBe("2y ago");
  });

  it("does not crash on an unparseable timestamp", () => {
    expect(relativeTime("not-a-date", now)).toBe("Never");
  });
});

describe("isStale", () => {
  const now = new Date("2026-09-01T12:00:00Z");

  it("is false for a never-scanned machine", () => {
    // "Never scanned" is its own state; calling it stale would double-report it.
    expect(isStale(null, now)).toBe(false);
  });

  it("flags scans older than the threshold", () => {
    expect(isStale("2026-08-30T12:00:00Z", now)).toBe(false);
    expect(isStale("2026-08-20T12:00:00Z", now)).toBe(true);
  });
});

describe("severityLabel", () => {
  it("title-cases a severity", () => {
    expect(severityLabel("critical")).toBe("Critical");
    expect(severityLabel("low")).toBe("Low");
  });
});

describe("server timestamps (Req 19.11)", () => {
  // Node re-reads TZ when it is assigned, so this runs away from UTC on any
  // machine -- including CI, which is UTC, where the bug cannot show.
  // The tests run under Node; the app's types deliberately know nothing of it.
  const env = (globalThis as unknown as { process: { env: Record<string, string | undefined> } })
    .process.env;
  const saved = env.TZ;
  beforeAll(() => {
    env.TZ = "Asia/Kolkata"; // UTC+05:30, no daylight saving
  });
  afterAll(() => {
    env.TZ = saved;
  });

  it("reads a bare server timestamp as UTC, not the browser's local time", () => {
    expect(parseServerTime("2026-09-01T11:30:00.852917")).toBe(Date.parse("2026-09-01T11:30:00.852Z"));
    expect(parseServerTime("2026-09-01T11:30")).toBe(Date.parse("2026-09-01T11:30:00Z"));
  });

  it("takes a timestamp with an offset as written", () => {
    expect(parseServerTime("2026-09-01T11:30:00Z")).toBe(Date.parse("2026-09-01T11:30:00Z"));
    expect(parseServerTime("2026-09-01T12:30:00+01:00")).toBe(Date.parse("2026-09-01T11:30:00Z"));
  });

  it("gives NaN for garbage", () => {
    expect(parseServerTime("soon")).toBeNaN();
  });

  it("puts a scan that just finished at just now, whatever the zone", () => {
    const now = new Date("2026-09-01T12:00:00Z");
    expect(relativeTime("2026-09-01T11:59:40", now)).toBe("Just now");
    expect(relativeTime("2026-09-01T11:30:00", now)).toBe("30m ago");
  });

  it("formats in the viewer's zone", () => {
    // 11:30 UTC is 17:00 in Kolkata; the clock style is the locale's.
    expect(formatServerTime("2026-09-01T11:30:00")).toMatch(/17:00|5:00\s?PM/i);
    expect(formatServerTime(null)).toBe("–");
    expect(formatServerTime("soon")).toBe("–");
  });
});

describe("requestedByLabel", () => {
  it("names who asked for a scan", () => {
    expect(requestedByLabel("schedule")).toBe("Schedule");
    expect(requestedByLabel("open")).toBe("Sign-in off");
    expect(requestedByLabel("token:ci")).toBe("API token ci");
    expect(requestedByLabel("unknown")).toBe("Unknown");
    expect(requestedByLabel("admin")).toBe("admin");
  });
});

describe("durationLabel", () => {
  it("scales with the length of the run", () => {
    const start = "2026-09-01T11:00:00";
    expect(durationLabel(start, "2026-09-01T11:00:12")).toBe("12s");
    expect(durationLabel(start, "2026-09-01T11:02:10")).toBe("2m 10s");
    expect(durationLabel(start, "2026-09-01T12:05:00")).toBe("1h 5m");
  });

  it("counts to now while running, and shows a dash before it starts", () => {
    expect(durationLabel("2026-09-01T11:00:00", null, new Date("2026-09-01T11:00:30Z"))).toBe("30s");
    expect(durationLabel(null, null)).toBe("–");
  });
});
