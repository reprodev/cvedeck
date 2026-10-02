// The kernel card's words, asserted as rendered text (Req 12.5, 12.6, 12.8).
//
// Each state here is one where the card could say something untrue: "0 CVEs"
// for a kernel nobody checked, "upgrade" to a host that only needs a reboot,
// or "idle" for a kernel nobody said was idle.

import { describe, expect, it } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

import type { CveFinding, KernelInfo } from "../types";
import { makeFinding } from "../test-utils/factories";
import { KernelCard } from "./KernelCard";

const OLD = "linux-image-6.1.0-52-amd64";
const NEW = "linux-image-6.1.0-53-amd64";
// The version each finding names is what ties it to an installed kernel.
const VERSIONS: Record<string, string> = { [OLD]: "6.1.180-1", [NEW]: "6.1.187-1" };

const UPGRADED_NOT_REBOOTED: KernelInfo = {
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

function renderCard(kernel: KernelInfo | null, findings: CveFinding[]) {
  return render(
    <KernelCard
      findings={findings}
      findingsLoaded
      platform="linux"
      osName="Debian GNU/Linux 12"
      onLoad={() => Promise.resolve(kernel)}
    />,
  );
}

describe("KernelCard", () => {
  it("tells a host that only needs a reboot to reboot, not to upgrade", async () => {
    renderCard(UPGRADED_NOT_REBOOTED, [onKernel("CVE-A", OLD, true, { kevListed: true })]);

    const reboot = await screen.findByTestId("kernel-reboot");
    expect(reboot).toHaveTextContent(`Reboot into ${NEW}.`);
    expect(reboot).toHaveTextContent("it fixes all of them; the host also reports a reboot pending.");
    expect(screen.queryByTestId("kernel-upgrade")).toBeNull();
    expect(screen.getByTestId("kernel-live")).toHaveTextContent("1 CVE in the running kernel, 1 known exploited.");
    expect(screen.getByTestId("kernel-release")).toHaveTextContent("Running 6.1.0-52-amd64");
  });

  it("states the CVEs it counted rather than listed, and never shows not-assessed as none", async () => {
    const counted: KernelInfo = {
      ...UPGRADED_NOT_REBOOTED,
      installed: [
        { ...UPGRADED_NOT_REBOOTED.installed[0], noFix: 0, fixedElsewhere: {} },
        { ...UPGRADED_NOT_REBOOTED.installed[1], noFix: 132, fixedElsewhere: { "Debian 13": 2187 } },
      ],
    };
    const { unmount } = renderCard(counted, []);
    expect(await screen.findByTestId("kernel-unfixed")).toHaveTextContent(
      "2,319 more CVEs have no fix in this release and are counted, not listed: 2,187 fixed only in Debian 13, 132 with no fix yet.",
    );
    unmount();

    renderCard(UPGRADED_NOT_REBOOTED, []);
    expect(await screen.findByTestId("kernel-unfixed")).toHaveTextContent(
      "CVEs with no fix in this release were not assessed for this kernel.",
    );
  });

  it("gives the upgrade command for what a reboot does not fix", async () => {
    renderCard(UPGRADED_NOT_REBOOTED, [onKernel("CVE-B", OLD, true), onKernel("CVE-B", NEW, false)]);

    const upgrade = await screen.findByTestId("kernel-upgrade");
    expect(upgrade).toHaveTextContent("Upgrade the kernel, then reboot");
    expect(upgrade).toHaveTextContent("sudo apt update && sudo apt install --only-upgrade linux-image-amd64");
    expect(screen.getByTestId("kernel-idle")).toHaveTextContent(
      "1 CVE is only in kernels installed but not running.",
    );
  });

  it("says a kernel that was not looked up was not checked", async () => {
    renderCard({ ...UPGRADED_NOT_REBOOTED, checked: false }, []);

    const note = await screen.findByTestId("kernel-unchecked");
    expect(note).toHaveTextContent("This host's kernel was not checked against advisories (2 kernels installed).");
    expect(screen.queryByTestId("kernel-live")).toBeNull();
  });

  it.each([
    ["ubuntu_feed_off", "The Ubuntu kernel feed is switched off on this server"],
    ["ubuntu_feed_unavailable", "has not been fetched yet, or is out of date"],
    ["ubuntu_release_end_of_life", "newer CVEs would be missing, not fixed"],
    ["ubuntu_not_yet_scanned", "scan this host again to check its kernel"],
    ["something_new", "The kernel was not checked against advisories."],
  ])("says why an Ubuntu kernel was not checked: %s", async (reason, text) => {
    renderCard({ ...UPGRADED_NOT_REBOOTED, checked: false, uncheckedReason: reason, runningOnly: true }, []);
    expect(await screen.findByTestId("kernel-unchecked-reason")).toHaveTextContent(text);
  });

  it("says that on Ubuntu only the running kernel is checked", async () => {
    renderCard({ ...UPGRADED_NOT_REBOOTED, runningOnly: true }, []);
    expect(await screen.findByTestId("kernel-running-only")).toHaveTextContent(
      "Only the running kernel is checked; kernels installed but not running are not assessed.",
    );
  });

  it("says nothing about the running kernel in a container but that it was not checked", async () => {
    renderCard(
      {
        ...UPGRADED_NOT_REBOOTED,
        release: "6.6.87.2-microsoft-standard-WSL2",
        runningInstalled: false,
        installed: UPGRADED_NOT_REBOOTED.installed.map((k) => ({ ...k, running: false })),
      },
      [onKernel("CVE-A", NEW, false)],
    );

    expect(await screen.findByTestId("kernel-not-installed")).toHaveTextContent(
      "The running kernel 6.6.87.2-microsoft-standard-WSL2 is not from an installed package",
    );
    // "0 CVEs in the running kernel" would answer a question never asked.
    expect(screen.queryByTestId("kernel-live")).toBeNull();
  });

  it("treats every kernel finding as live when the running kernel is unknown", async () => {
    renderCard(
      {
        ...UPGRADED_NOT_REBOOTED,
        release: null,
        runningInstalled: null,
        installed: UPGRADED_NOT_REBOOTED.installed.map((k) => ({ ...k, running: null })),
      },
      [onKernel("CVE-A", OLD, null)],
    );

    expect(await screen.findByTestId("kernel-live")).toHaveTextContent("1 CVE in the installed kernels.");
    expect(screen.getByTestId("kernel-release")).toHaveTextContent("Running kernel not reported");
    expect(screen.queryByTestId("kernel-reboot")).toBeNull();
  });

  it("shows nothing for a host with no kernel installed", async () => {
    const { container } = renderCard({ ...UPGRADED_NOT_REBOOTED, installed: [] }, []);
    await waitFor(() => expect(container).toBeEmptyDOMElement());
  });

  it("says when the kernel could not be loaded", async () => {
    render(
      <KernelCard
        findings={[]}
        findingsLoaded
        onLoad={() => Promise.reject(new Error("HTTP 500"))}
      />,
    );
    expect(await screen.findByTestId("kernel-card")).toHaveTextContent(
      "Kernel details could not be loaded: HTTP 500",
    );
  });
});

describe("the machine page", () => {
  it("can show the kernel or userland on their own, and loads the kernel card", async () => {
    const userEvent = (await import("@testing-library/user-event")).default;
    const { MachineDrillDownView } = await import("../views/MachineDrillDownView");
    const libc = makeFinding({
      cveId: "CVE-2023-4911",
      packageIdentifier: "Debian:12:libc6@2.36-9 (fixed in 2.36-9+deb12u3)",
      packageName: "libc6",
      isKernel: false,
    });
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[onKernel("CVE-2024-1086", OLD, true), libc]}
        onLoadKernel={() => Promise.resolve(UPGRADED_NOT_REBOOTED)}
      />,
    );

    expect(await screen.findByTestId("kernel-card")).toBeInTheDocument();
    expect(screen.getAllByText("CVE-2024-1086").length).toBeGreaterThan(0);

    await userEvent.selectOptions(screen.getByTestId("kernel-scope"), "userland");
    expect(screen.queryAllByText("CVE-2024-1086")).toHaveLength(0);
    expect(screen.getAllByText("CVE-2023-4911").length).toBeGreaterThan(0);

    await userEvent.selectOptions(screen.getByTestId("kernel-scope"), "kernel");
    expect(screen.queryAllByText("CVE-2023-4911")).toHaveLength(0);
  });
});
