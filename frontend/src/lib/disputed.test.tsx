// A finding whose stated fix the host already has is disputed (Req 14.11): kept,
// counted and explained, never offered as an upgrade.
//
// Found in 0.17.0's upgrade check: OSV reported 6,835 kernel CVEs on a Debian
// 12 host, each "fixed in" a version older than the 6.1.187-1 installed. The
// backend marks such a finding fixStatus "disputed"; this is what the
// dashboard does with it.

import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import { makeFinding } from "../test-utils/factories";
import { MachineDrillDownView } from "../views/MachineDrillDownView";
import { CveDetailModal } from "../components/CveDetailModal";
import {
  buildBulkFixScript,
  findingFix,
  fixElsewhereExplanation,
  fixElsewhereLabel,
  hasFix,
  identifierVersion,
} from "./remediation";
import { kernelPlan } from "./kernel";

const DISPUTED = makeFinding({
  cveId: "CVE-2026-63795",
  severity: "critical",
  packageIdentifier: "Debian:12:linux-image-6.1.0-53-amd64@6.1.187-1 (fixed in 6.1.177-1)",
  packageName: "linux-image-6.1.0-53-amd64",
  fixedVersion: "6.1.177-1",
  hasFix: false,
  fixStatus: "disputed",
});

const DISPUTED_USERLAND = makeFinding({
  cveId: "CVE-2014-6271",
  packageIdentifier: "Debian:12:bash@5.2.15-2+b7 (fixed in 4.3-7)",
  packageName: "bash",
  fixedVersion: "4.3-7",
  hasFix: false,
  fixStatus: "disputed",
});

const FIXABLE = makeFinding({
  cveId: "CVE-2026-0001",
  packageIdentifier: "Debian:12:curl@7.88.1-10 (fixed in 7.88.1-10+deb12u5)",
  packageName: "curl",
  fixedVersion: "7.88.1-10+deb12u5",
  hasFix: true,
  fixStatus: "available",
});

describe("a disputed fix", () => {
  it("carries the version it names and the one installed", () => {
    expect(findingFix(DISPUTED)).toEqual({
      status: "disputed",
      release: null,
      version: "6.1.177-1",
      installed: "6.1.187-1",
    });
  });

  it("is never actionable", () => {
    expect(hasFix(DISPUTED)).toBe(false);
  });

  it("says what it names and what the host has", () => {
    const fix = findingFix(DISPUTED);
    expect(fixElsewhereLabel(fix)).toBe("Disputed fix");
    expect(fixElsewhereExplanation(fix)).toMatch(
      /names 6\.1\.177-1 as the fix, but this host already has 6\.1\.187-1/,
    );
    expect(fixElsewhereExplanation(fix)).toMatch(/never alerted on or offered as an upgrade/);
  });

  it("is left out of the fix script", () => {
    const script = buildBulkFixScript([DISPUTED_USERLAND, FIXABLE], "linux", "Debian GNU/Linux 12");
    expect(script).toContain("sudo apt install --only-upgrade curl");
    expect(script).not.toContain("bash");
    expect(script).toContain("1 CVE(s)");
  });

  it("is not a kernel upgrade, though it is still a live finding", () => {
    const live = { ...DISPUTED, isKernel: true, kernelRunning: true };
    const plan = kernelPlan([live], null);
    expect(plan.live).toEqual([live]);
    expect(plan.needUpgrade).toEqual([]);
  });
});

describe("identifierVersion", () => {
  it("reads the installed version, epoch and all", () => {
    expect(identifierVersion("Debian:12:bash@1:5.2.15-2 (fixed in 1:5.2.15-3)")).toBe("1:5.2.15-2");
    expect(identifierVersion("Red Hat:openssl@1:3.0.7-27.el9")).toBe("1:3.0.7-27.el9");
    expect(identifierVersion("npm:@scope/pkg")).toBeNull();
    expect(identifierVersion(null)).toBeNull();
  });
});

describe("MachineDrillDownView", () => {
  it("counts it, explains it, and keeps it out of Ready to Fix", () => {
    render(
      <MachineDrillDownView
        machineId="m1"
        platform="linux"
        osName="Debian GNU/Linux 12"
        findings={[DISPUTED_USERLAND, FIXABLE]}
      />,
    );

    const notice = screen.getByTestId("disputed-notice");
    expect(notice).toHaveTextContent("1 finding(s) name a fix this host already has");
    expect(notice).toHaveTextContent("never offered as an upgrade or sent as an alert");
    expect(screen.getByText(/Ready to Fix \(1\)/)).toBeInTheDocument();
    expect(screen.getByText(/Pending Vendor Patch \(1\)/)).toBeInTheDocument();

    const row = screen.getByText("CVE-2014-6271").closest("tr") as HTMLElement;
    expect(within(row).getByText(/Disputed fix/)).toBeInTheDocument();
    expect(within(row).queryByText(/Pending patch/)).not.toBeInTheDocument();
    expect(within(row).queryByRole("button", { name: /Copy fix/ })).not.toBeInTheDocument();
  });

  it("shows no notice when nothing is disputed", () => {
    render(<MachineDrillDownView machineId="m1" platform="linux" findings={[FIXABLE]} />);
    expect(screen.queryByTestId("disputed-notice")).not.toBeInTheDocument();
  });
});

describe("CveDetailModal", () => {
  it("explains the dispute instead of offering a command", () => {
    render(
      <CveDetailModal
        finding={DISPUTED_USERLAND}
        platform="linux"
        osName="Debian GNU/Linux 12"
        hostname="host.example.com"
        onClose={() => {}}
      />,
    );

    expect(screen.getAllByText(/Disputed fix/).length).toBeGreaterThan(0);
    expect(screen.getByText(/names 4\.3-7 as the fix, but this host already has 5\.2\.15-2\+b7/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Copy: sudo apt/ })).not.toBeInTheDocument();
  });
});
