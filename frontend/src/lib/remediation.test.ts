import { describe, expect, it } from "vitest";

import { makeFinding } from "../test-utils/factories";
import {
  buildBulkFixScript,
  detectDistroFamily,
  findingPackageName,
  getDistroTooling,
  hasFix,
  parsePackageName,
} from "./remediation";

describe("detectDistroFamily", () => {
  it("uses the machine's platform before anything else", () => {
    // A Windows host has no Linux ecosystem prefix, so the old code fell
    // through to the default branch and offered `sudo apt`.
    expect(detectDistroFamily("windows", "Microsoft Windows Server 2022", null)).toBe(
      "windows",
    );
    expect(
      detectDistroFamily("windows", undefined, "windows:OpenSSL@3.0.2"),
    ).toBe("windows");
  });

  it("uses the reported OS name when available", () => {
    expect(detectDistroFamily("linux", "Ubuntu", null)).toBe("debian");
    expect(detectDistroFamily("linux", "AlmaLinux", null)).toBe("rhel");
    expect(detectDistroFamily("linux", "Alpine Linux", null)).toBe("alpine");
    expect(detectDistroFamily("linux", "openSUSE Leap", null)).toBe("suse");
    expect(detectDistroFamily("linux", "Arch Linux", null)).toBe("arch");
  });

  it("falls back to the ecosystem prefix of the package identifier", () => {
    expect(
      detectDistroFamily("linux", undefined, "Ubuntu:22.04:LTS:openssl@3.0.2"),
    ).toBe("debian");
    expect(
      detectDistroFamily("linux", undefined, "Rocky Linux:9:openssl@3.0.7"),
    ).toBe("rhel");
  });

  it("returns unknown rather than guessing", () => {
    // Handing a user a confidently wrong command is worse than saying we do
    // not know which package manager applies.
    expect(detectDistroFamily("linux", "Some Custom OS", null)).toBe("unknown");
    expect(detectDistroFamily(undefined, undefined, null)).toBe("unknown");
  });

  describe("substring hazards that produced real bugs", () => {
    // `low.includes("ol")` matched tool/tools/console/symbol/protocol/golang,
    // routing Debian packages to dnf. `low.includes("arch")` matched
    // libarchive/noarch/search, routing them to pacman.
    it.each([
      "deb:python3-tools@1.0",
      "deb:console-setup@1.0",
      "deb:golang-go@1.21",
      "deb:libsymbol@1.0",
      "deb:protocol-buffers@1.0",
    ])("does not route %s to rhel", (identifier) => {
      expect(detectDistroFamily("linux", undefined, identifier)).not.toBe("rhel");
    });

    it.each([
      "deb:libarchive13@3.6",
      "deb:searchd@2.0",
      "deb:architecture-properties@1.0",
    ])("does not route %s to arch", (identifier) => {
      expect(detectDistroFamily("linux", undefined, identifier)).not.toBe("arch");
    });

    it("still detects a real Oracle Linux ecosystem prefix", () => {
      expect(
        detectDistroFamily("linux", undefined, "Oracle Linux:9:openssl@3.0.7"),
      ).toBe("rhel");
    });
  });
});

describe("getDistroTooling", () => {
  it("offers the right package manager per family", () => {
    expect(getDistroTooling("linux", "Ubuntu").updateCmd("openssl")).toBe(
      "sudo apt update && sudo apt install --only-upgrade openssl",
    );
    expect(getDistroTooling("linux", "Rocky Linux").updateCmd("openssl")).toBe(
      "sudo dnf upgrade -y openssl",
    );
    expect(getDistroTooling("linux", "Alpine").updateCmd("openssl")).toBe(
      "sudo apk update && sudo apk upgrade openssl",
    );
    expect(getDistroTooling("linux", "openSUSE").updateCmd("openssl")).toBe(
      "sudo zypper update -y openssl",
    );
  });

  it("never offers apt to a Windows host", () => {
    const tooling = getDistroTooling("windows", "Windows Server 2022");
    expect(tooling.updateCmd("Git.Git")).not.toContain("apt");
    expect(tooling.updateCmd("Git.Git")).toContain("winget");
    expect(tooling.purgeCmd("Git.Git")).not.toContain("apt");
  });

  it("recommends a full system upgrade on Arch", () => {
    // Partial upgrades are explicitly unsupported upstream and routinely break
    // the system, so a single-package command would be harmful advice.
    expect(getDistroTooling("linux", "Arch Linux").updateCmd("openssl")).toBe(
      "sudo pacman -Syu",
    );
  });

  it("marks Ubuntu so Ubuntu Pro advice can be gated on it", () => {
    expect(getDistroTooling("linux", "Ubuntu 22.04").isUbuntu).toBe(true);
    expect(getDistroTooling("linux", "Debian GNU/Linux 12").isUbuntu).toBe(false);
    expect(getDistroTooling("linux", "AlmaLinux 9").isUbuntu).toBe(false);
  });

  it("emits a comment rather than a wrong command for an unknown distro", () => {
    const cmd = getDistroTooling("linux", "Mystery OS").updateCmd("openssl");
    expect(cmd.startsWith("#")).toBe(true);
    expect(cmd).not.toContain("sudo apt");
  });
});

describe("parsePackageName", () => {
  it("strips the ecosystem prefix and version suffix", () => {
    expect(parsePackageName("Ubuntu:22.04:LTS:openssl@3.0.2-0ubuntu1.10")).toBe(
      "openssl",
    );
    expect(parsePackageName("deb:curl@7.81.0")).toBe("curl");
    expect(parsePackageName("openssl")).toBe("openssl");
  });

  it("ignores the trailing fixed-in prose", () => {
    expect(
      parsePackageName("Ubuntu:openssl@3.0.2 (fixed in 3.0.2-0ubuntu1.16)"),
    ).toBe("openssl");
  });

  it("returns null for empty input", () => {
    expect(parsePackageName(null)).toBeNull();
    expect(parsePackageName("   ")).toBeNull();
  });
});

describe("hasFix", () => {
  it("prefers the backend's structured field", () => {
    expect(hasFix(makeFinding({ hasFix: true, packageIdentifier: null }))).toBe(true);
    // Structured false wins even when the prose would have said otherwise.
    expect(
      hasFix(
        makeFinding({ hasFix: false, packageIdentifier: "deb:x@1 (fixed in 2)" }),
      ),
    ).toBe(false);
  });

  it("falls back to the legacy prose check for older payloads", () => {
    expect(
      hasFix(
        makeFinding({ hasFix: undefined, packageIdentifier: "deb:x@1 (fixed in 2)" }),
      ),
    ).toBe(true);
    expect(
      hasFix(makeFinding({ hasFix: undefined, packageIdentifier: "deb:x@1" })),
    ).toBe(false);
  });
});

describe("findingPackageName", () => {
  it("prefers the structured field over parsing the identifier", () => {
    const finding = makeFinding({
      packageName: "openssl",
      packageIdentifier: "something:else@1.0",
    });
    expect(findingPackageName(finding)).toBe("openssl");
  });
});

describe("buildBulkFixScript", () => {
  const findings = [
    makeFinding({ cveId: "CVE-1", packageName: "openssl", hasFix: true }),
    makeFinding({ cveId: "CVE-2", packageName: "openssl", hasFix: true }),
    makeFinding({ cveId: "CVE-3", packageName: "curl", hasFix: true }),
    makeFinding({ cveId: "CVE-4", packageName: "linux", hasFix: false }),
  ];

  it("deduplicates packages and sorts them", () => {
    // A host commonly has a dozen CVEs against one openssl; a dozen identical
    // upgrade lines is noise.
    const script = buildBulkFixScript(findings, "linux", "Ubuntu 22.04");
    expect(script).toContain("sudo apt install --only-upgrade curl openssl");
    expect(script.match(/openssl/g)?.length).toBe(1);
  });

  it("excludes findings with no published fix", () => {
    const script = buildBulkFixScript(findings, "linux", "Ubuntu 22.04");
    expect(script).not.toContain("linux");
    expect(script).toContain("3 CVE(s)");
  });

  it("uses the right manager for the host", () => {
    expect(buildBulkFixScript(findings, "linux", "Rocky Linux 9")).toContain(
      "sudo dnf upgrade -y openssl",
    );
  });

  it("emits a single system upgrade on Arch", () => {
    const script = buildBulkFixScript(findings, "linux", "Arch Linux");
    expect(script).toContain("sudo pacman -Syu");
    expect(script).not.toContain("pacman -S openssl");
  });

  it("says so plainly when nothing is fixable", () => {
    const script = buildBulkFixScript(
      [makeFinding({ hasFix: false })],
      "linux",
      "Ubuntu",
    );
    expect(script).toContain("No findings on this host have a published fix");
  });

  it("states that nothing has been executed", () => {
    // Remediation is manual by design; the script must not imply otherwise.
    expect(buildBulkFixScript(findings, "linux", "Ubuntu")).toContain(
      "Nothing here has been executed for you",
    );
  });
});
