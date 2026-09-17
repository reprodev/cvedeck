// Drill-down tests for an unmeasured blast radius (Req 10.10).
//
// The dependency graph is built from a machine's collected inventory. Where it
// was not built, the old code rendered the bottom of the scale: "Low (0 apps)",
// and in the dependency map a green card reading "STANDALONE COMPONENT" with a
// purge command under it. That is an action recommended on no evidence -- the
// same failure the KEV column is careful to avoid, in a place where acting on
// it removes a package.

import { describe, expect, it } from "vitest";
import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";

import { MachineDrillDownView } from "./MachineDrillDownView";
import { CveDetailModal } from "../components/CveDetailModal";
import type { CveFinding } from "../types";

function finding(overrides: Partial<CveFinding> = {}): CveFinding {
  return {
    cveId: "CVE-2024-1000",
    severity: "critical",
    cvssScore: 9.8,
    packageIdentifier: "Ubuntu:22.04:openssl@3.0.2",
    remediationStatus: null,
    remediationRecordId: null,
    remediationNote: null,
    dependencies: [],
    dependedOnBy: [],
    ...overrides,
  };
}

/** Switch to the aggregated package view, where the impact column lives. */
async function openPackageView(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: /By Package/i }));
}

/** Switch to the dependency map, where the purge command is offered. */
async function openDependencyMap(user: ReturnType<typeof userEvent.setup>) {
  await user.click(screen.getByRole("button", { name: /Dependency Map/i }));
}

describe("MachineDrillDownView blast radius", () => {
  it("shows an unassessed impact as unassessed, not as low", async () => {
    const user = userEvent.setup();
    render(
      <MachineDrillDownView machineId="m1" findings={[finding({ blastRadius: null })]} />,
    );
    await openPackageView(user);

    expect(screen.getByText("Not assessed")).toBeInTheDocument();
    expect(screen.queryByText(/Low \(0 apps\)/)).not.toBeInTheDocument();
  });

  it("still reports a measured graph with no dependents as low", async () => {
    const user = userEvent.setup();
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[finding({ blastRadius: "low", dependedOnBy: [] })]}
      />,
    );
    await openPackageView(user);

    // A graph that was built and found nothing is a real answer, and must keep
    // reading as one -- otherwise the fix has only moved the lie.
    expect(screen.getByText(/Low \(0 apps\)/)).toBeInTheDocument();
    expect(screen.queryByText("Not assessed")).not.toBeInTheDocument();
  });

  it("reports a measured graph with many dependents as high", async () => {
    const user = userEvent.setup();
    render(
      <MachineDrillDownView
        machineId="m1"
        findings={[
          finding({
            blastRadius: "high",
            dependedOnBy: Array.from({ length: 11 }, (_, i) => `app${i}`),
          }),
        ]}
      />,
    );
    await openPackageView(user);

    expect(screen.getByText(/High \(11 apps\)/)).toBeInTheDocument();
  });

  it("does not offer to purge a package whose dependents were never measured", async () => {
    const user = userEvent.setup();
    render(
      <MachineDrillDownView machineId="m1" findings={[finding({ blastRadius: null })]} />,
    );
    await openDependencyMap(user);

    expect(screen.getByText(/Blast radius not assessed/i)).toBeInTheDocument();
    expect(screen.queryByText(/STANDALONE COMPONENT/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Purge/i })).not.toBeInTheDocument();
  });

  it("still offers the purge command for a measured leaf package", async () => {
    const user = userEvent.setup();
    render(
      <MachineDrillDownView
        machineId="m1"
        platform="linux"
        osName="Ubuntu"
        findings={[finding({ blastRadius: "low", dependedOnBy: [] })]}
      />,
    );
    await openDependencyMap(user);

    expect(screen.getByText(/STANDALONE COMPONENT/i)).toBeInTheDocument();
    expect(
      within(screen.getByRole("button", { name: /Purge/i })).getByText(/purge/i),
    ).toBeInTheDocument();
  });
});

// The detail dialog kept the two-state test after the dependency map was fixed:
// an empty dependents list read as "standalone", with the purge command under it.
describe("CveDetailModal blast radius", () => {
  const openModal = (f: CveFinding) =>
    render(
      <CveDetailModal
        finding={f}
        platform="linux"
        osName="Ubuntu"
        hostname="web-01"
        onClose={() => {}}
      />,
    );

  it("does not call a package standalone when its dependents were never measured", () => {
    openModal(finding({ blastRadius: null, fixStatus: "none", hasFix: false }));

    expect(screen.getByText(/Blast radius not assessed/i)).toBeInTheDocument();
    expect(screen.queryByText(/Standalone Component/i)).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Purge/i })).not.toBeInTheDocument();
  });

  it("still offers the purge command for a measured leaf package", () => {
    openModal(finding({ blastRadius: "low", fixStatus: "none", hasFix: false }));

    expect(screen.getByText(/Standalone Component/i)).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Purge/i })).toBeInTheDocument();
    expect(screen.queryByText(/Blast radius not assessed/i)).not.toBeInTheDocument();
  });

  it("warns in the tier the badge shows, not always the top one", () => {
    // Three dependents is Moderate. The card used to read "DO NOT REMOVE THIS
    // PACKAGE (High System Impact)" for any dependent at all, contradicting the
    // badge beside it.
    openModal(
      finding({ blastRadius: "medium", dependedOnBy: ["nginx", "curl", "git"] }),
    );

    expect(screen.getByText(/Moderate system impact/i)).toBeInTheDocument();
    expect(screen.queryByText(/High system impact/i)).not.toBeInTheDocument();
    expect(screen.getByText(/3 installed applications/)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Purge/i })).not.toBeInTheDocument();
  });

  it("numbers the mitigations from what actually rendered", () => {
    // Non-leaf and non-Ubuntu used to render a single option numbered "2.",
    // because the numbers were literals and the purge option above them was
    // conditional.
    openModal(
      finding({
        blastRadius: "medium",
        dependedOnBy: ["nginx", "curl", "git"],
        fixStatus: "none",
        hasFix: false,
      }),
    );

    const mitigations = screen
      .getAllByRole("listitem")
      .filter((li) => li.closest("ol") !== null);

    // Not a leaf, so the purge option that used to be "1." is absent, and what
    // remains must not start at "2.". The numbering is the list's now, so no
    // item carries a literal number at all.
    expect(mitigations.length).toBeGreaterThan(0);
    for (const item of mitigations) {
      expect(item.textContent?.trimStart()).not.toMatch(/^\d+\./);
    }
    expect(mitigations[mitigations.length - 1]).toHaveTextContent(
      /distribution upgrade|distro updates/i,
    );
  });

  it("says high only when the graph measured high", () => {
    openModal(
      finding({
        blastRadius: "high",
        dependedOnBy: Array.from({ length: 12 }, (_, i) => `app${i}`),
      }),
    );

    expect(screen.getByText(/High system impact/i)).toBeInTheDocument();
  });
});
