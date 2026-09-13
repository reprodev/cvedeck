import { describe, expect, it } from "vitest";

import type { DiscoveredHost } from "../types";
import { buildKnownHostMap, inferPlatform, isScannable } from "./platform";

function host(overrides: Partial<DiscoveredHost> = {}): DiscoveredHost {
  return {
    ip: "10.0.0.5",
    hostname: "",
    respondsToPing: true,
    openPorts: [],
    services: [],
    osGuess: "",
    ...overrides,
  };
}

function service(banner: string, port = 22) {
  return { port, protocol: "tcp", banner, product: "", version: "", extraInfo: "" };
}

describe("inferPlatform", () => {
  it("trusts an explicit OS banner", () => {
    expect(inferPlatform(host({ osGuess: "Ubuntu 22.04" }))).toBe("linux");
    expect(inferPlatform(host({ osGuess: "Microsoft Windows Server 2022" }))).toBe(
      "windows",
    );
  });

  it("reads banners from services, not only the OS guess", () => {
    expect(
      inferPlatform(host({ services: [service("SSH-2.0-OpenSSH_8.9p1 Ubuntu")] })),
    ).toBe("linux");
    expect(
      inferPlatform(host({ services: [service("Microsoft-IIS/10.0", 80)] })),
    ).toBe("windows");
  });

  it("does not treat SMB as a Windows signal", () => {
    // Samba is ubiquitous on Linux file servers. DiscoveryView's old copy
    // treated port 445 as Windows and misclassified every one of them.
    expect(inferPlatform(host({ openPorts: [22, 445] }))).toBe("linux");
    expect(inferPlatform(host({ openPorts: [445] }))).toBe("linux");
  });

  it("classifies a Windows host running OpenSSH as Windows", () => {
    // App.tsx's old copy let an open port 22 force "linux" regardless of an
    // explicit Windows banner, so this host was offered apt commands.
    expect(
      inferPlatform(
        host({ osGuess: "Microsoft Windows Server 2022", openPorts: [22, 3389] }),
      ),
    ).toBe("windows");
  });

  it("uses management ports when no banner names an OS", () => {
    expect(inferPlatform(host({ openPorts: [5985] }))).toBe("windows");
    expect(inferPlatform(host({ openPorts: [3389] }))).toBe("windows");
    expect(inferPlatform(host({ openPorts: [5986] }))).toBe("windows");
    // SSH alongside them is ambiguous; SSH wins because the Linux collector is
    // the mature path and the scan is read-only either way.
    expect(inferPlatform(host({ openPorts: [22, 5985] }))).toBe("linux");
  });

  it("defaults to linux when there is nothing to go on", () => {
    expect(inferPlatform(host())).toBe("linux");
  });

  it("prefers windows when both families are named", () => {
    // Misclassifying a Linux host costs a failed SSH attempt; misclassifying a
    // Windows host means offering it apt commands.
    expect(
      inferPlatform(host({ osGuess: "Windows Subsystem for Linux" })),
    ).toBe("windows");
  });
});

describe("buildKnownHostMap", () => {
  it("indexes discovered hosts by both IP and hostname", () => {
    const map = buildKnownHostMap(
      [],
      [host({ ip: "10.0.0.5", hostname: "web-01", osGuess: "Ubuntu" })],
    );
    expect(map.get("10.0.0.5")).toBe("linux");
    expect(map.get("web-01")).toBe("linux");
  });

  it("lets a scanned machine override a discovery inference", () => {
    // A credentialed scan confirmed the platform; discovery only guessed it.
    const map = buildKnownHostMap(
      [{ hostname: "web-01", platform: "windows" }],
      [host({ ip: "10.0.0.5", hostname: "web-01", osGuess: "Ubuntu" })],
    );
    expect(map.get("web-01")).toBe("windows");
  });

  it("lowercases keys so lookup is case-insensitive", () => {
    const map = buildKnownHostMap([{ hostname: "WEB-01", platform: "linux" }], []);
    expect(map.get("web-01")).toBe("linux");
  });
});

describe("isScannable", () => {
  it("allows Linux and withholds Windows (Req 10.8)", () => {
    expect(isScannable("linux")).toBe(true);
    expect(isScannable("windows")).toBe(false);
  });
});
