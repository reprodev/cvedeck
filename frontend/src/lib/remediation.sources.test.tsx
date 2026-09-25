// A finding is reported once per source package, against one representative
// binary, and a fix must upgrade every installed binary of that source
// (Req 2.8): `apt install --only-upgrade libc-bin` leaves libc6 vulnerable.
// And kernel packages are not matched yet, which the host page must say rather
// than show a kernel that reads as clean (Req 12.5).

import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";

import { buildBulkFixScript, getDistroTooling, upgradeTargets } from "./remediation";
import { CveDetailModal } from "../components/CveDetailModal";
import { MachineDrillDownView } from "../views/MachineDrillDownView";
import { makeFinding } from "../test-utils/factories";

const glibc = makeFinding({
  cveId: "CVE-2024-2961",
  packageIdentifier: "Debian:12:libc-bin@2.36-9 (fixed in 2.36-9+deb12u7)",
  packageName: "libc-bin",
  fixStatus: "available",
  fixedVersion: "2.36-9+deb12u7",
  hasFix: true,
  affectedPackages: ["libc-bin", "libc6", "locales"],
});

describe("upgrade targets (Req 2.8)", () => {
  it("names every installed binary of the finding's source", () => {
    expect(upgradeTargets([glibc])).toEqual(["libc-bin", "libc6", "locales"]);
  });

  it("falls back to the package name for a response from before 0.8.15", () => {
    const old = makeFinding({ packageIdentifier: "Debian:12:openssl@3.0.9-1 (fixed in 3.0.11-1)" });
    expect(upgradeTargets([old])).toEqual(["openssl"]);
  });

  it("puts every binary into the upgrade command, each as one word", () => {
    const tooling = getDistroTooling("linux", "Debian GNU/Linux 12", null);
    expect(tooling.updateCmd(upgradeTargets([glibc]))).toBe(
      "sudo apt update && sudo apt install --only-upgrade libc-bin libc6 locales",
    );
    const rpm = getDistroTooling("linux", "Rocky Linux 9", null);
    expect(rpm.updateCmd(["openssl", "openssl-libs"])).toBe("sudo dnf upgrade -y openssl openssl-libs");
  });

  it("puts every binary into the host's fix plan", () => {
    const script = buildBulkFixScript([glibc], "linux", "Debian GNU/Linux 12");
    expect(script).toContain("sudo apt install --only-upgrade libc-bin libc6 locales");
  });

  it("shows the other binaries on the finding's detail", () => {
    render(<CveDetailModal finding={glibc} hostname="db-01" platform="linux"
      osName="Debian GNU/Linux 12" onClose={() => {}} />);
    expect(screen.getByTestId("also-installed")).toHaveTextContent("libc6, locales");
  });
});

describe("unchecked kernel packages (Req 12.5)", () => {
  it("says how many were not checked", () => {
    render(<MachineDrillDownView machineId="m1" findings={[glibc]} kernelPackagesUnchecked={3} />);
    expect(screen.getByTestId("kernel-unchecked")).toHaveTextContent(
      "3 kernel packages are not checked against advisories yet.",
    );
  });

  it("says nothing when there is no kernel, or no inventory to count", () => {
    const { unmount } = render(
      <MachineDrillDownView machineId="m1" findings={[glibc]} kernelPackagesUnchecked={0} />,
    );
    expect(screen.queryByTestId("kernel-unchecked")).toBeNull();
    unmount();
    render(<MachineDrillDownView machineId="m1" findings={[glibc]} kernelPackagesUnchecked={null} />);
    expect(screen.queryByTestId("kernel-unchecked")).toBeNull();
  });
});
