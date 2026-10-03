// Kernel findings and the action that fixes them (Req 12.6, 12.8).
//
// The host in these tests was upgraded and not rebooted: it runs the old
// kernel (6.1.0-52) with the new one (6.1.0-53) installed beside it -- the
// state in which "upgrade the kernel" is the wrong advice.

import { describe, expect, it } from "vitest";

import type { CveFinding, KernelInfo } from "../types";
import { makeFinding } from "../test-utils/factories";
import { buildBulkFixScript } from "./remediation";
import { filterByKernel, inRunningKernel, kernelPlan, kernelUpgradeCommand, unfixedSummary } from "./kernel";
import { sortByRisk } from "./intel";

const OLD = "linux-image-6.1.0-52-amd64";
const NEW = "linux-image-6.1.0-53-amd64";
// The version each finding names is what ties it to an installed kernel.
const VERSIONS: Record<string, string> = { [OLD]: "6.1.180-1", [NEW]: "6.1.187-1" };

const KERNEL: KernelInfo = {
  release: "6.1.0-52-amd64",
  checked: true,
  runningInstalled: true,
  rebootRequired: true,
  installed: [
    { package: NEW, version: "6.1.187-1", running: false, newest: true, noFix: null, fixedElsewhere: null },
    { package: OLD, version: "6.1.180-1", running: true, newest: false, noFix: null, fixedElsewhere: null },
  ],
  upgradePackages: ["linux-image-amd64"],
  uncheckedReason: null,
  runningOnly: false,
};

function onKernel(cve: string, pkg: string, running: boolean | null, extra: Partial<CveFinding> = {}) {
  return makeFinding({
    cveId: cve,
    packageIdentifier: `Debian:12:${pkg}@${VERSIONS[pkg] ?? "1"} (fixed in 9)`,
    packageName: pkg,
    affectedPackages: [pkg],
    fixStatus: "available",
    fixedVersion: "9",
    hasFix: true,
    isKernel: true,
    kernelRunning: running,
    ...extra,
  });
}

const libc = makeFinding({
  cveId: "CVE-2023-4911",
  packageIdentifier: "Debian:12:libc6@2.36-9 (fixed in 2.36-9+deb12u3)",
  packageName: "libc6",
  affectedPackages: ["libc6", "libc-bin"],
  fixStatus: "available",
  fixedVersion: "2.36-9+deb12u3",
  hasFix: true,
  isKernel: false,
  kernelRunning: null,
});

describe("kernelPlan", () => {
  it("says a reboot fixes what the installed newer kernel does not have", () => {
    const findings = [
      onKernel("CVE-A", OLD, true), // fixed in the new kernel
      onKernel("CVE-B", OLD, true), // still in the new kernel too
      onKernel("CVE-B", NEW, false),
      libc,
    ];

    const plan = kernelPlan(findings, KERNEL);

    expect(plan.rebootInto).toBe(NEW);
    expect(plan.fixedByReboot.map((f) => f.cveId)).toEqual(["CVE-A"]);
    expect(plan.needUpgrade.map((f) => f.cveId)).toEqual(["CVE-B"]);
    expect(plan.live.map((f) => f.cveId)).toEqual(["CVE-A", "CVE-B"]);
    expect(plan.idle.map((f) => f.cveId)).toEqual(["CVE-B"]);
  });

  it("never offers a reboot when the newest kernel is the one running", () => {
    const booted: KernelInfo = {
      ...KERNEL,
      release: "6.1.0-53-amd64",
      installed: [
        { package: NEW, version: "6.1.187-1", running: true, newest: true, noFix: null, fixedElsewhere: null },
        { package: OLD, version: "6.1.180-1", running: false, newest: false, noFix: null, fixedElsewhere: null },
      ],
    };
    const plan = kernelPlan([onKernel("CVE-B", NEW, true), onKernel("CVE-A", OLD, false)], booted);

    expect(plan.rebootInto).toBeNull();
    expect(plan.fixedByReboot).toEqual([]);
    expect(plan.needUpgrade.map((f) => f.cveId)).toEqual(["CVE-B"]);
  });

  it("treats an unknown running kernel as live, and promises no reboot", () => {
    const unknown: KernelInfo = {
      ...KERNEL,
      release: null,
      runningInstalled: null,
      installed: KERNEL.installed.map((k) => ({ ...k, running: null })),
    };
    const findings = [onKernel("CVE-A", OLD, null)];

    const plan = kernelPlan(findings, unknown);

    expect(plan.live).toHaveLength(1);
    expect(plan.idle).toEqual([]);
    expect(plan.fixedByReboot).toEqual([]);
    expect(inRunningKernel(findings[0])).toBe(true);
  });

  it("counts known exploitation in the running kernel only", () => {
    const findings = [
      onKernel("CVE-A", OLD, true, { kevListed: true }),
      onKernel("CVE-C", NEW, false, { kevListed: true }),
    ];
    expect(kernelPlan(findings, KERNEL).exploited).toBe(1);
  });
});

describe("filterByKernel", () => {
  it("separates the kernel from userland, and all is everything", () => {
    const findings = [onKernel("CVE-A", OLD, true), libc];
    expect(filterByKernel(findings, "kernel").map((f) => f.cveId)).toEqual(["CVE-A"]);
    expect(filterByKernel(findings, "userland").map((f) => f.cveId)).toEqual(["CVE-2023-4911"]);
    expect(filterByKernel(findings, "all")).toHaveLength(2);
  });
});

describe("kernelUpgradeCommand", () => {
  it("upgrades the Debian metapackage, never the installed image", () => {
    const cmd = kernelUpgradeCommand(KERNEL, "linux", "Debian GNU/Linux 12", null);
    expect(cmd).toBe("sudo apt update && sudo apt install --only-upgrade linux-image-amd64");
  });

  it("gives no command rather than one that does nothing", () => {
    expect(kernelUpgradeCommand({ ...KERNEL, upgradePackages: [] }, "linux", "Debian GNU/Linux 12", null)).toBeNull();
  });

  it("upgrades the image package where a new kernel installs beside the old", () => {
    const rocky: KernelInfo = { ...KERNEL, upgradePackages: ["kernel-core"] };
    expect(kernelUpgradeCommand(rocky, "linux", "Rocky Linux 9.4", null)).toBe("sudo dnf upgrade -y kernel-core");
  });
});

describe("the bulk fix plan", () => {
  it("leaves the kernel out, and says where its fix is", () => {
    const script = buildBulkFixScript([onKernel("CVE-A", OLD, true), libc], "linux", "Debian GNU/Linux 12");

    expect(script).not.toContain(OLD);
    expect(script).toContain("libc-bin libc6");
    expect(script).toContain("1 kernel CVE(s) are not in this plan");
  });
});

describe("sortByRisk", () => {
  it("puts an idle kernel's findings after live ones, but exploitation still first", () => {
    const idle = onKernel("CVE-IDLE", NEW, false, { severity: "critical" });
    const idleKev = onKernel("CVE-IDLE-KEV", NEW, false, { kevListed: true });
    const live = onKernel("CVE-LIVE", OLD, true, { severity: "medium" });

    expect(sortByRisk([idle, live, idleKev]).map((f) => f.cveId)).toEqual([
      "CVE-IDLE-KEV",
      "CVE-LIVE",
      "CVE-IDLE",
    ]);
  });
});

describe("kernelPlan on an RPM host", () => {
  it("tells two kernel-core packages apart by version", () => {
    const rocky: KernelInfo = {
      release: "5.14.0-284.11.1.el9_2.x86_64",
      checked: true,
      runningInstalled: true,
      rebootRequired: null,
      installed: [
        { package: "kernel-core", version: "5.14.0-362.8.1.el9_3", running: false, newest: true, noFix: null, fixedElsewhere: null },
        { package: "kernel-core", version: "5.14.0-284.11.1.el9_2", running: true, newest: false, noFix: null, fixedElsewhere: null },
      ],
      upgradePackages: ["kernel-core"],
      uncheckedReason: null,
      runningOnly: false,
    };
    const on = (cve: string, version: string, running: boolean) =>
      makeFinding({
        cveId: cve,
        packageIdentifier: `Rocky Linux:9:kernel-core@${version} (fixed in 9)`,
        packageName: "kernel-core",
        affectedPackages: ["kernel-core", "kernel-modules-core"],
        fixStatus: "available",
        fixedVersion: "9",
        hasFix: true,
        isKernel: true,
        kernelRunning: running,
      });

    // CVE-B is in both kernels; CVE-A only in the old, running one.
    const plan = kernelPlan(
      [on("CVE-A", "5.14.0-284.11.1.el9_2", true), on("CVE-B", "5.14.0-284.11.1.el9_2", true), on("CVE-B", "5.14.0-362.8.1.el9_3", false)],
      rocky,
    );

    expect(plan.fixedByReboot.map((f) => f.cveId)).toEqual(["CVE-A"]);
    expect(plan.needUpgrade.map((f) => f.cveId)).toEqual(["CVE-B"]);
  });
});

describe("unfixedSummary (Req 12.9)", () => {
  const counted: KernelInfo = {
    ...KERNEL,
    installed: [
      { package: NEW, version: "6.1.187-1", running: false, newest: true, noFix: 2, fixedElsewhere: { "Debian 13": 10 } },
      { package: OLD, version: "6.1.180-1", running: true, newest: false, noFix: 132, fixedElsewhere: { "Debian 13": 2187 } },
    ],
  };

  it("sums the running kernel's counts and the others' separately", () => {
    expect(unfixedSummary(counted, "live")).toEqual({ total: 2319, noFix: 132, elsewhere: [["Debian 13", 2187]] });
    expect(unfixedSummary(counted, "idle")).toEqual({ total: 12, noFix: 2, elsewhere: [["Debian 13", 10]] });
  });

  it("is null, not zero, when a kernel in the sum was not assessed", () => {
    const partly: KernelInfo = {
      ...counted,
      installed: [counted.installed[0], { ...counted.installed[1], noFix: null, fixedElsewhere: null }],
    };
    expect(unfixedSummary(partly, "live")).toBeNull();
  });
});

describe("ranking an unscored kernel finding (Req 12.10)", () => {
  it("goes after every scored finding, kernel or not; userland unscored keeps its place", () => {
    const kernelUnscored = onKernel("CVE-KU", OLD, true, { severity: "unscored", cvssScore: null });
    const userlandUnscored = makeFinding({ cveId: "CVE-UU", severity: "unscored", cvssScore: null, isKernel: false });
    const low = makeFinding({ cveId: "CVE-LOW", severity: "low", cvssScore: 2.0, isKernel: false });
    const high = makeFinding({ cveId: "CVE-HIGH", severity: "high", cvssScore: 7.5, isKernel: false });
    const kernelKev = onKernel("CVE-KEV", OLD, true, { severity: "unscored", cvssScore: null, kevListed: true });

    expect(sortByRisk([kernelUnscored, low, high, userlandUnscored, kernelKev]).map((f) => f.cveId)).toEqual([
      "CVE-KEV",
      "CVE-UU",
      "CVE-HIGH",
      "CVE-LOW",
      "CVE-KU",
    ]);
  });
});

describe("the Ubuntu kernel feed is not threat intelligence (Req 12.11)", () => {
  it("is labelled by release and never counts as usable intel", async () => {
    const { feedLabel, isIntelFeed, enrichmentWarning } = await import("./intel");
    const feed = (feedName: string, usable: boolean) => ({
      feedName, status: "ok", lastRefreshedAt: usable ? "2026-10-03T00:00:00Z" : null,
      lastAttemptedAt: null, recordCount: usable ? 1 : 0, errorDetail: null, stale: !usable, usable,
    });
    expect(feedLabel("ubuntu-kernel:jammy")).toBe("Ubuntu 22.04 kernel");
    const feeds = [feed("kev", false), feed("epss", false), feed("ubuntu-kernel:jammy", true)];
    // A healthy kernel feed must not make never-loaded intel look loaded.
    expect(feeds.filter(isIntelFeed).some((f) => f.usable)).toBe(false);
    expect(enrichmentWarning(feeds.filter(isIntelFeed) as never)).toContain("never been loaded");
  });
});

describe("oldKernelsCommand", () => {
  it.each([
    ["Debian GNU/Linux 12", "sudo apt autoremove --purge"],
    ["Ubuntu 22.04.4 LTS", "sudo apt autoremove --purge"],
    ["Rocky Linux 9.4", "sudo dnf remove --oldinstallonly"],
    ["openSUSE Leap 15.5", "sudo zypper purge-kernels"],
    ["Alpine Linux v3.18", null],
    ["Arch Linux", null],
  ])("%s", async (osName, expected) => {
    const { oldKernelsCommand } = await import("./kernel");
    expect(oldKernelsCommand("linux", osName, null)).toBe(expected);
  });
});
