// End-to-end-style integration tests for the dashboard (task 10.1).
//
// These render the full <App/> with an injected CveScannerApiClient whose
// fetch is stubbed to return backend-shaped JSON. The backend serializes its
// Pydantic response models with snake_case keys (see backend/app/api/schemas.py:
// MachineSummary, CveFindingOut), while the frontend domain types use camelCase.
// By feeding the exact snake_case wire shapes through the real client mapping,
// these tests confirm the end-to-end data flow resolves against the backend
// contract.
//
// Requirements covered:
//   3.1 / 6.1 - the machine list renders from the API on load
//   3.2       - each machine shows severity-grouped CVE counts
//   3.3       - severity filtering narrows the displayed counts
//   3.4 / 6.2 - selecting a machine drills down and loads its CVEs
//   3.5 / 4.4 - each CVE shows id, severity, CVSS score, and remediation status

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { App } from "./App";
import { CveScannerApiClient } from "./api/client";

// ---- Backend-shaped (snake_case) wire fixtures -------------------------- //
// These mirror exactly what the FastAPI backend serializes.

const machinesWire = [
  {
    machine_id: "m1",
    hostname: "web-01",
    platform: "linux",
    last_scan_status: "success",
    last_scanned_at: "2026-09-16T09:00:00Z",
    cve_counts: { critical: 2, high: 3, medium: 1, low: 4 },
  },
  {
    machine_id: "m2",
    hostname: "db-01",
    platform: "windows",
    last_scan_status: "connection_failure",
    last_scanned_at: "2026-09-16T09:00:00Z",
    cve_counts: { critical: 0, high: 1, medium: 5, low: 0 },
  },
];

const cvesByMachine: Record<string, unknown[]> = {
  m1: [
    {
      cve_id: "CVE-2024-1000",
      severity: "critical",
      cvss_score: 9.8,
      package_identifier: "openssl",
      remediation_status: "in_progress",
      remediation_record_id: "rec-1",
      remediation_note: "patch scheduled",
    },
    {
      cve_id: "CVE-2024-2000",
      severity: "medium",
      cvss_score: 5.4,
      package_identifier: null,
      remediation_status: null,
      remediation_record_id: null,
      remediation_note: null,
    },
  ],
  m2: [
    {
      cve_id: "CVE-2024-3000",
      severity: "high",
      cvss_score: 7.5,
      package_identifier: null,
      remediation_status: "open",
      remediation_record_id: "rec-2",
      remediation_note: "",
    },
  ],
};

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

/**
 * Build a fetch stub that routes the dashboard's requests to the backend-shaped
 * fixtures above, honoring the ?severity= filter on the per-machine CVE route.
 */
function makeFetchStub() {
  return vi.fn(async (
    input: RequestInfo | URL,
    init?: RequestInit,
  ): Promise<Response> => {
    const url = typeof input === "string" ? input : input.toString();
    const [path, query] = url.split("?");

    if (path === "/api/scans") {
      // Mirror the backend: one outcome per requested target.
      const body = JSON.parse(String(init?.body ?? "{}")) as {
        targets?: { id: string }[];
      };
      return jsonResponse({
        machine_scans: (body.targets ?? []).map((t) => ({
          machine_id: t.id,
          status: "success",
          finding_count: 0,
        })),
      });
    }

    const addRemediationMatch = path.match(
      /^\/api\/machines\/([^/]+)\/cves\/([^/]+)\/remediation$/,
    );
    if (addRemediationMatch && init?.method === "POST") {
      const body = JSON.parse(String(init?.body ?? "{}"));
      return jsonResponse(
        {
          record_id: "rec-new",
          machine_id: decodeURIComponent(addRemediationMatch[1]),
          cve_id: decodeURIComponent(addRemediationMatch[2]),
          status: body.status,
          note: body.note,
        },
        201,
      );
    }

    const updateRemediationMatch = path.match(/^\/api\/remediation\/([^/]+)$/);
    if (updateRemediationMatch && init?.method === "PUT") {
      const body = JSON.parse(String(init?.body ?? "{}"));
      return jsonResponse({
        record_id: decodeURIComponent(updateRemediationMatch[1]),
        machine_id: "m1",
        cve_id: "CVE-2024-1000",
        status: body.status,
        note: body.note,
      });
    }

    if (path === "/api/machines") {
      return jsonResponse(machinesWire);
    }

    const cveMatch = path.match(/^\/api\/machines\/([^/]+)\/cves$/);
    if (cveMatch) {
      const machineId = decodeURIComponent(cveMatch[1]);
      let findings = cvesByMachine[machineId] ?? [];
      const severity = new URLSearchParams(query ?? "").get("severity");
      if (severity) {
        findings = findings.filter(
          (f) => (f as { severity: string }).severity === severity,
        );
      }
      return jsonResponse(findings);
    }

    const machineMatch = path.match(/^\/api\/machines\/([^/]+)$/);
    if (machineMatch) {
      const machineId = decodeURIComponent(machineMatch[1]);
      const found = machinesWire.find((m) => m.machine_id === machineId);
      return found
        ? jsonResponse(found)
        : jsonResponse({ detail: "Machine not found" }, 404);
    }

    return jsonResponse({ detail: "not found" }, 404);
  });
}

function renderApp() {
  const fetchImpl = makeFetchStub();
  const client = new CveScannerApiClient({ fetchImpl });
  render(<App client={client} />);
  return { fetchImpl };
}

describe("App end-to-end data flow", () => {
  // Navigation lives in the URL now, and jsdom keeps one window.location for
  // the whole file -- so without this, a test that drills into a host leaves
  // the next one starting on that host's page instead of the fleet list.
  beforeEach(() => {
    window.location.hash = "";
  });

  it("renders the machine list from the API on load (Req 3.1, 6.1)", async () => {
    const { fetchImpl } = renderApp();

    // Both machines resolve from the stubbed backend response.
    expect(
      await screen.findByRole("button", { name: "web-01" }),
    ).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "db-01" })).toBeInTheDocument();

    // The list was loaded via the machines endpoint.
    expect(fetchImpl).toHaveBeenCalledWith(
      "/api/machines",
      expect.objectContaining({ method: "GET" }),
    );
  });

  it("shows severity-grouped counts mapped from snake_case (Req 3.2)", async () => {
    renderApp();

    const webRow = (await screen.findByRole("button", { name: "web-01" })).closest(
      "tr",
    );
    expect(webRow).not.toBeNull();
    const cells = within(webRow as HTMLElement).getAllByRole("cell");
    // Cells: hostname, platform, status, last scanned, exploited, critical,
    // high, medium, low.
    expect(cells[1]).toHaveTextContent("linux");
    // The status column renders a human label, not the raw enum value.
    expect(cells[2]).toHaveTextContent("Success");
    expect(cells[5]).toHaveTextContent("2"); // critical
    expect(cells[6]).toHaveTextContent("3"); // high
    expect(cells[7]).toHaveTextContent("1"); // medium
    expect(cells[8]).toHaveTextContent("4"); // low
  });

  it("filters the displayed severity counts by the selected level (Req 3.3)", async () => {
    renderApp();

    await screen.findByRole("button", { name: "web-01" });

    // Only the four severity headers exist initially.
    for (const label of ["Critical", "High", "Medium", "Low"]) {
      expect(
        screen.getByRole("columnheader", { name: label }),
      ).toBeInTheDocument();
    }

    // Select the "Critical" filter. This used to be a <select> labelled
    // "Filter by severity"; it is now a chip in the findings strip, which
    // replaced a dropdown that duplicated it.
    await userEvent.click(
      screen.getByRole("button", { name: /^Critical \d+$/ }),
    );

    // Now only the Critical severity column remains.
    expect(
      screen.getByRole("columnheader", { name: "Critical" }),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("columnheader", { name: "High" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("columnheader", { name: "Medium" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("columnheader", { name: "Low" }),
    ).not.toBeInTheDocument();

    // The web-01 row still shows its critical count.
    const webRow = screen
      .getByRole("button", { name: "web-01" })
      .closest("tr");
    const cells = within(webRow as HTMLElement).getAllByRole("cell");
    expect(cells[cells.length - 1]).toHaveTextContent("2");
  });

  it("drills down into a machine and loads its CVEs from the API (Req 3.4, 6.2)", async () => {
    const { fetchImpl } = renderApp();

    await userEvent.click(
      await screen.findByRole("button", { name: "web-01" }),
    );

    // Drill-down heading uses the hostname resolved from the list.
    expect(
      await screen.findByRole("heading", { name: "CVE Findings for web-01" }),
    ).toBeInTheDocument();

    // The machine's CVEs were fetched from its cves endpoint.
    await waitFor(() =>
      expect(fetchImpl).toHaveBeenCalledWith(
        "/api/machines/m1/cves",
        expect.objectContaining({ method: "GET" }),
      ),
    );

    // Both of web-01's findings render.
    expect(screen.getByText("CVE-2024-1000")).toBeInTheDocument();
    expect(screen.getByText("CVE-2024-2000")).toBeInTheDocument();
  });

  it("shows id, severity, CVSS score, and remediation status per CVE (Req 3.5, 4.4)", async () => {
    renderApp();

    await userEvent.click(
      await screen.findByRole("button", { name: "web-01" }),
    );

    const criticalRow = (
      await screen.findByText("CVE-2024-1000")
    ).closest("tr") as HTMLElement;
    const cells = within(criticalRow).getAllByRole("cell");
    // Cells: CVE id, exploitation, severity, CVSS score, remediation status.
    expect(cells[0]).toHaveTextContent("CVE-2024-1000");
    expect(cells[2]).toHaveTextContent("Critical");
    expect(cells[3]).toHaveTextContent("9.8"); // cvss_score mapped to cvssScore
    expect(cells[4]).toHaveTextContent("In Progress"); // remediation_status mapped

    // A finding without a remediation record shows the placeholder.
    const mediumRow = screen
      .getByText("CVE-2024-2000")
      .closest("tr") as HTMLElement;
    expect(within(mediumRow).getAllByRole("cell")[4]).toHaveTextContent(
      "No remediation record",
    );
  });

  it("submits a scan and reports its outcome (Req 1.1, 1.2)", async () => {
    const { fetchImpl } = renderApp();
    await screen.findByRole("button", { name: "web-01" });

    // Navigate to dedicated New Scan page
    await userEvent.click(screen.getByRole("button", { name: "New Scan" }));

    await userEvent.type(screen.getByLabelText("Hostname"), "new-host");
    await userEvent.type(screen.getByLabelText("Username"), "scanner");
    await userEvent.type(screen.getByLabelText("Password"), "secret");
    await userEvent.click(screen.getByRole("button", { name: "Start scan" }));

    // The request carries the target and its credentials in the documented shape.
    await waitFor(() =>
      expect(fetchImpl).toHaveBeenCalledWith(
        "/api/scans",
        expect.objectContaining({
          method: "POST",
          // Credential fields are mapped explicitly to snake_case; unset ones
          // are sent as null so the backend applies its own default (the
          // server-managed SSH key).
          body: JSON.stringify({
            targets: [
              {
                id: "new-host",
                hostname: "new-host",
                platform: "linux",
                username: "scanner",
                password: "secret",
                private_key: null,
                passphrase: null,
              },
            ],
          }),
        }),
      ),
    );

    // The per-target outcome is surfaced, mapped from snake_case.
    const result = await screen.findByRole("status");
    expect(result).toHaveTextContent("new-host");
    expect(result).toHaveTextContent("Success");
    expect(result).toHaveTextContent("0 findings");
  });

  it("refreshes the machine list after a scan (Req 3.1)", async () => {
    const { fetchImpl } = renderApp();
    await screen.findByRole("button", { name: "web-01" });
    const before = fetchImpl.mock.calls.filter(
      ([url]) => url === "/api/machines",
    ).length;

    // Navigate to dedicated New Scan page
    await userEvent.click(screen.getByRole("button", { name: "New Scan" }));

    await userEvent.type(screen.getByLabelText("Hostname"), "new-host");
    await userEvent.type(screen.getByLabelText("Username"), "scanner");
    await userEvent.type(screen.getByLabelText("Password"), "secret");
    await userEvent.click(screen.getByRole("button", { name: "Start scan" }));

    // A newly scanned machine only appears if the list is re-read.
    await waitFor(() => {
      const after = fetchImpl.mock.calls.filter(
        ([url]) => url === "/api/machines",
      ).length;
      expect(after).toBeGreaterThan(before);
    });
  });

  it("adds a remediation record for a CVE that has none (Req 4.1)", async () => {
    const { fetchImpl } = renderApp();
    await userEvent.click(
      await screen.findByRole("button", { name: "web-01" }),
    );
    await screen.findByText("CVE-2024-2000");

    await userEvent.selectOptions(
      screen.getByLabelText("Remediation status for CVE-2024-2000"),
      "remediated",
    );
    await userEvent.type(
      screen.getByLabelText("Remediation note for CVE-2024-2000"),
      "upgraded",
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Save remediation for CVE-2024-2000" }),
    );

    // No existing record id, so this must take the POST (add) path.
    await waitFor(() =>
      expect(fetchImpl).toHaveBeenCalledWith(
        "/api/machines/m1/cves/CVE-2024-2000/remediation",
        expect.objectContaining({
          method: "POST",
          body: JSON.stringify({ status: "remediated", note: "upgraded" }),
        }),
      ),
    );
  });

  it("updates the existing record for a CVE that already has one (Req 4.3)", async () => {
    const { fetchImpl } = renderApp();
    await userEvent.click(
      await screen.findByRole("button", { name: "web-01" }),
    );
    await screen.findByText("CVE-2024-1000");

    await userEvent.selectOptions(
      screen.getByLabelText("Remediation status for CVE-2024-1000"),
      "remediated",
    );
    await userEvent.click(
      screen.getByRole("button", { name: "Save remediation for CVE-2024-1000" }),
    );

    // remediation_record_id was present, so this must take the PUT path
    // against that record rather than adding a second one.
    await waitFor(() =>
      expect(fetchImpl).toHaveBeenCalledWith(
        "/api/remediation/rec-1",
        expect.objectContaining({
          method: "PUT",
          body: JSON.stringify({
            status: "remediated",
            note: "patch scheduled",
          }),
        }),
      ),
    );
  });

  it("navigating back and into another machine loads that machine's CVEs (Req 3.4, 6.2)", async () => {
    renderApp();

    // Drill into web-01, then go back.
    await userEvent.click(
      await screen.findByRole("button", { name: "web-01" }),
    );
    await screen.findByText("CVE-2024-1000");
    await userEvent.click(
      screen.getByRole("button", { name: "Back to machines" }),
    );

    // Drill into db-01 and confirm its distinct CVE loads.
    await userEvent.click(
      await screen.findByRole("button", { name: "db-01" }),
    );
    expect(await screen.findByText("CVE-2024-3000")).toBeInTheDocument();
    expect(screen.queryByText("CVE-2024-1000")).not.toBeInTheDocument();
  });
});
