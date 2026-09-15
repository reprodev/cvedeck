import { describe, expect, it } from "vitest";

import {
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
