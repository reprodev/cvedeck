// Fixes that live in another release are never presented as installable, and
// the dashboard says why they stay after the fix plan runs (Req 14.7, 14.8).
//
// Found on a Debian 13 host: the plan listed packages whose only fix was in
// Debian 14, apt had nothing to install, and every re-scan found them again.

import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { makeFinding } from "../test-utils/factories";
import { MachineDrillDownView } from "../views/MachineDrillDownView";
import { CveDetailModal } from "../components/CveDetailModal";
import { buildBulkFixScript, findingFix, hasFix } from "./remediation";

const FIXABLE = makeFinding({
  cveId: "CVE-2026-0001",
  packageIdentifier: "Debian:13:curl@8.14.1-2+deb13u5 (fixed in 8.14.1-2+deb13u6)",
  packageName: "curl",
  fixedVersion: "8.14.1-2+deb13u6",
  hasFix: true,
  fixStatus: "available",
});

const NEWER_ONLY = makeFinding({
  cveId: "CVE-2025-10966",
  packageIdentifier:
    "Debian:13:curl@8.14.1-2+deb13u5 (no fix in Debian 13; fixed only in Debian 14: 8.17.0~rc2-1)",
  packageName: "curl",
  hasFix: false,
  fixStatus: "newer_release",
  fixRelease: "Debian 14",
  fixReleaseVersion: "8.17.0~rc2-1",
});

const NEWER_ONLY_OTHER_PKG = makeFinding({
  cveId: "CVE-2025-59800",
  packageIdentifier:
    "Debian:13:ghostscript@10.05.1~dfsg-1+deb13u1 (no fix in Debian 13; fixed only in Debian 14: 10.06.0~dfsg-1)",
  packageName: "ghostscript",
  hasFix: false,
  fixStatus: "newer_release",
  fixRelease: "Debian 14",
  fixReleaseVersion: "10.06.0~dfsg-1",
});

describe("findingFix", () => {
  it("reads the structured fields", () => {
    expect(findingFix(NEWER_ONLY)).toEqual({
      status: "newer_release",
      release: "Debian 14",
      version: "8.17.0~rc2-1",
    });
    expect(findingFix(FIXABLE)).toEqual({
      status: "available",
      release: null,
      version: "8.14.1-2+deb13u6",
    });
  });

  it("reads the note when an older backend sends no structured fields", () => {
    const legacy = (packageIdentifier: string) => makeFinding({ packageIdentifier });

    expect(findingFix(legacy(NEWER_ONLY.packageIdentifier!))).toEqual({
      status: "newer_release",
      release: "Debian 14",
      version: "8.17.0~rc2-1",
    });
    expect(
      findingFix(
        legacy(
          "Fedora:curl@8.6.0-10.fc40 (not confirmed for this release; upstream fix in RHEL 9: 7.76.1-29.el9)",
        ),
      ),
    ).toEqual({ status: "upstream", release: "RHEL 9", version: "7.76.1-29.el9" });
    expect(findingFix(legacy("Debian:13:curl@8.14.1-2+deb13u5")).status).toBe("none");
  });

  it("never counts a fix in another release as installable", () => {
    expect(hasFix(NEWER_ONLY)).toBe(false);
    expect(hasFix(makeFinding({ packageIdentifier: NEWER_ONLY.packageIdentifier }))).toBe(false);
    expect(hasFix(FIXABLE)).toBe(true);
  });
});

describe("buildBulkFixScript", () => {
  it("upgrades only what this release fixes, and explains the rest", () => {
    const script = buildBulkFixScript(
      [FIXABLE, NEWER_ONLY, NEWER_ONLY_OTHER_PKG],
      "linux",
      "Debian GNU/Linux 13",
    );

    expect(script).toContain("sudo apt install --only-upgrade curl\n");
    expect(script).not.toContain("--only-upgrade curl ghostscript");
    expect(script).toContain("# 2 CVE(s) in 2 package(s) are fixed only in Debian 14.");
    expect(script).toContain("#   curl ghostscript");
    expect(script).toContain("Upgrading the distribution clears them");
  });

  it("explains an unconfirmed upstream fix without offering it as a command", () => {
    const upstream = makeFinding({
      packageIdentifier:
        "Fedora:curl@8.6.0-10.fc40 (not confirmed for this release; upstream fix in RHEL 9: 7.76.1-29.el9)",
      packageName: "curl",
      hasFix: false,
      fixStatus: "upstream",
      fixRelease: "RHEL 9",
      fixReleaseVersion: "7.76.1-29.el9",
    });

    const script = buildBulkFixScript([upstream], "linux", "Fedora Linux 40");

    expect(script).toContain("# No findings on this host have a fix in its own release yet.");
    expect(script).toContain("have a fix in RHEL 9");
    expect(script).not.toMatch(/^sudo dnf/m);
  });
});

describe("MachineDrillDownView", () => {
  it("says up front when findings are fixed only in a newer release", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        platform="linux"
        osName="Debian GNU/Linux 13"
        findings={[FIXABLE, NEWER_ONLY, NEWER_ONLY_OTHER_PKG]}
      />,
    );

    const notice = screen.getByTestId("newer-release-notice");
    expect(notice).toHaveTextContent("2 finding(s) are fixed only in Debian 14");
    expect(notice).toHaveTextContent("Upgrading packages cannot clear them");
    expect(screen.getByText(/Ready to Fix \(1\)/)).toBeInTheDocument();
  });

  it("labels the finding with the release that has the fix, and offers no copy", () => {
    render(
      <MachineDrillDownView machineId="m1" platform="linux" osName="Debian GNU/Linux 13" findings={[NEWER_ONLY]} />,
    );

    const row = screen.getByText("CVE-2025-10966").closest("tr") as HTMLElement;
    expect(within(row).getByText(/Fixed only in Debian 14/)).toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: /Copy fix/ })).not.toBeInTheDocument();
  });

  it("shows no notice when every fix is in this release", () => {
    render(<MachineDrillDownView machineId="m1" platform="linux" findings={[FIXABLE]} />);

    expect(screen.queryByTestId("newer-release-notice")).not.toBeInTheDocument();
  });
});

describe("CveDetailModal", () => {
  it("explains a newer-release fix instead of offering a command", () => {
    render(
      <CveDetailModal
        finding={NEWER_ONLY}
        platform="linux"
        osName="Debian GNU/Linux 13"
        hostname="host.example.com"
        onClose={() => {}}
      />,
    );

    expect(screen.getAllByText(/Fixed only in Debian 14/).length).toBeGreaterThan(0);
    expect(screen.getByText(/Debian 14 has a fix \(8.17.0~rc2-1\), but this host's release does not/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Copy: sudo apt/ })).not.toBeInTheDocument();
  });
});
