// Application shell. Wires the ScanFormView, MachineListView and
// MachineDrillDownView to the backend API client.
//
// Requirements:
//   1.1 / 1.2 - manually initiate a scan of a Windows or Linux target
//   3.1 - show the machine list on load
//   3.4 - selecting a machine opens its drill-down view
//   3.5 / 4.4 - drill-down shows CVE id, severity, CVSS score, remediation
//   4.1 / 4.3 - add or update a remediation record for a CVE

import { useCallback, useEffect, useMemo, useState } from "react";
import { CveScannerApiClient } from "./api/client";
import type {
  CveFinding,
  DiscoverySweepResult,
  MachineSummary,
  ServerCapabilities,
  FeedHealth,
  Platform,
  RemediationStatus,
  ScanOutcome,
  ScanTargetInput,
} from "./types";
import { DiscoveryView } from "./views/DiscoveryView";
import { MachineDrillDownView } from "./views/MachineDrillDownView";
import { MachineListView } from "./views/MachineListView";
import { Icon } from "./components/Icon";
import { themeAffordance, useTheme } from "./lib/useTheme";
import { useUrlState } from "./lib/useUrlState";
import type { Workspace } from "./lib/useUrlState";
import { ScanFormView } from "./views/ScanFormView";
import { SettingsView } from "./views/SettingsView";
import { useToast } from "./components/Toast";
import { buildKnownHostMap, isScannable } from "./lib/platform";
import { statusLabel } from "./lib/labels";

export interface AppProps {
  /** Injectable API client, primarily for testing. Defaults to a real client. */
  client?: CveScannerApiClient;
  /**
   * The signed-in account, or null when login is not required here (disabled,
   * or demo mode). The account controls only appear when there is one.
   */
  account?: { username: string } | null;
  /** Sign out. Supplied by the auth gate alongside `account`. */
  onSignOut?: () => void;
}

/** Extract a displayable message from a rejected API call. */
function errorMessage(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

export function App({ client, account = null, onSignOut }: AppProps = {}) {
  const api = useMemo(() => client ?? new CveScannerApiClient(), [client]);

  const [machines, setMachines] = useState<MachineSummary[]>([]);
  // Starts true: the first fetch is dispatched on mount, so "not yet asked"
  // and "asked and waiting" are the same frame as far as the UI is concerned.
  const [loadingMachines, setLoadingMachines] = useState(true);

  // Navigation lives in the URL rather than in component state, so a screen can
  // be linked, bookmarked, and reached with the browser back button. See
  // lib/useUrlState for why this is a fragment and not a path.
  const { route, navigate } = useUrlState();
  const selectedMachineId = route.machineId;
  const activeNav = route.workspace;
  const [findings, setFindings] = useState<CveFinding[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [capabilities, setCapabilities] = useState<ServerCapabilities | null>(null);
  const { theme, cycleTheme } = useTheme();
  const { icon: themeIcon, label: themeLabel } = themeAffordance(theme);
  const [feeds, setFeeds] = useState<FeedHealth[]>([]);
  const [refreshingFeeds, setRefreshingFeeds] = useState(false);
  const toast = useToast();
  const [scanning, setScanning] = useState(false);
  const [scanOutcomes, setScanOutcomes] = useState<ScanOutcome[] | undefined>();
  // Pre-populates the scan form when a Quick Scan is triggered from the
  // discovery or fleet view (Req 8.5).
  const [quickScanTarget, setQuickScanTarget] = useState<{
    hostname: string;
    platform: Platform;
  } | null>(null);

  // Cached discovery results and CIDR across tab switches and reloads, so
  // navigating away and back does not force a redundant re-sweep (Req 8.6).
  const [discoveryResult, setDiscoveryResult] = useState<DiscoverySweepResult | null>(() => {
    try {
      const saved = sessionStorage.getItem("cvedeck_discovery_result");
      return saved ? JSON.parse(saved) : null;
    } catch {
      return null;
    }
  });
  const [discoveryCidr, setDiscoveryCidr] = useState<string>(() => {
    try {
      return sessionStorage.getItem("cvedeck_discovery_cidr") || "";
    } catch {
      return "";
    }
  });

  const handleDiscoveryResultChange = useCallback((res: DiscoverySweepResult | null) => {
    setDiscoveryResult(res);
    try {
      if (res) {
        sessionStorage.setItem("cvedeck_discovery_result", JSON.stringify(res));
      } else {
        sessionStorage.removeItem("cvedeck_discovery_result");
      }
    } catch {}
  }, []);

  const handleDiscoveryCidrChange = useCallback((c: string) => {
    setDiscoveryCidr(c);
    try {
      sessionStorage.setItem("cvedeck_discovery_cidr", c);
    } catch {}
  }, []);

  const loadMachines = useCallback(async () => {
    setMachines(await api.listMachines());
  }, [api]);

  const handleEnrollHosts = useCallback(
    async (hosts: { hostname: string; platform: Platform }[]) => {
      await api.enrollHosts(hosts);
      await loadMachines();
    },
    [api, loadMachines],
  );

  const handleQuickScan = useCallback(
    (host: { hostname: string; platform: Platform }) => {
      setQuickScanTarget(host);
      navigate({ workspace: "scan", machineId: null });
    },
    [navigate],
  );

  // Compute all known hosts for auto-detecting platform when entering credentials
  // Platform inference lives in lib/platform.ts. It used to exist here AND in
  // DiscoveryView with different rules, so the same host got one answer from
  // the Discovery tab's Scan button and another from the scan form.
  const knownHosts = useMemo<{ hostname: string; platform: Platform }[]>(() => {
    const map = buildKnownHostMap(machines, discoveryResult?.hosts ?? []);
    return Array.from(map.entries()).map(([hostname, platform]) => ({
      hostname,
      platform,
    }));
  }, [machines, discoveryResult]);

  const loadFindings = useCallback(
    async (machineId: string) => {
      setFindings(await api.getMachineCves(machineId));
    },
    [api],
  );

  // Load the machine list on mount (Requirement 3.1).
  useEffect(() => {
    let cancelled = false;
    api
      .listMachines()
      .then((result) => {
        if (!cancelled) {
          setMachines(result);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(errorMessage(err));
        }
      })
      .finally(() => {
        // finally, not the success path: a failed load must also stop showing
        // a skeleton, or the error banner sits above a table that still looks
        // like it is about to produce something.
        if (!cancelled) {
          setLoadingMachines(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [api]);

  // Load the selected machine's CVEs for the drill-down (Requirement 3.4).
  useEffect(() => {
    if (!selectedMachineId) {
      setFindings([]);
      return;
    }
    let cancelled = false;
    api
      .getMachineCves(selectedMachineId)
      .then((result) => {
        if (!cancelled) {
          setFindings(result);
        }
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setError(errorMessage(err));
        }
      });
    return () => {
      cancelled = true;
    };
  }, [api, selectedMachineId]);

  const handleSelectMachine = useCallback(
    (machineId: string) => {
      navigate({ workspace: "fleet", machineId });
    },
    [navigate],
  );

  // Asked once: it reflects deployment configuration, which cannot change
  // without a restart. A failure here is not worth a toast -- the only
  // consequence is that the fleet re-scan controls stay hidden.
  useEffect(() => {
    let cancelled = false;
    api
      .getCapabilities()
      .then((caps) => {
        if (!cancelled) setCapabilities(caps);
      })
      .catch(() => {
        // version stays null, so the header badge is omitted rather than
        // asserting a version we could not confirm.
        if (!cancelled) {
          setCapabilities({
            serverSshKey: false,
            defaultSshUser: false,
            version: null,
            demoMode: false,
            loginRequired: false,
          });
        }
      });
    return () => {
      cancelled = true;
    };
  }, [api]);

  // Threat-intel feed health, which captions the exploited counts. Fetched
  // alongside capabilities and, like them, a failure here is not worth a toast:
  // the consequence is an empty feeds array, which the fleet view already
  // treats as "nothing to warn about" rather than as a false all-clear.
  const loadFeeds = useCallback(() => {
    return api
      .getFeeds()
      .then(setFeeds)
      .catch(() => {
        setFeeds([]);
      });
  }, [api]);

  useEffect(() => {
    void loadFeeds();
  }, [loadFeeds]);

  /**
   * Pull the KEV and EPSS feeds, then re-read their health.
   *
   * Deliberately does not re-scan afterwards. Enrichment is applied at scan
   * time, so fresh intel reaches findings on the next scan; silently kicking
   * off a fleet-wide SSH sweep because someone clicked "refresh intel" would
   * be a much larger action than the button advertises.
   */
  const handleRefreshFeeds = useCallback(async () => {
    setRefreshingFeeds(true);
    try {
      const outcome = await api.refreshFeeds();
      await loadFeeds();
      if (!outcome.ok) {
        const failed = outcome.results
          .filter((result) => result.status !== "ok")
          .map((result) => `${result.feedName}: ${result.errorDetail ?? result.status}`)
          .join("; ");
        setError(`Some intel feeds could not be refreshed (${failed}).`);
      } else {
        setError(null);
      }
    } catch (err) {
      setError(
        err instanceof Error
          ? `Intel refresh failed: ${err.message}`
          : "Intel refresh failed.",
      );
    } finally {
      setRefreshingFeeds(false);
    }
  }, [api, loadFeeds]);

  /**
   * Re-scan a batch of machines with the server-managed key.
   *
   * `startScan` has always taken an array and the backend has always batched
   * with per-target fault isolation; the UI simply never sent more than one.
   * Credentials are omitted so the backend falls back to its configured key.
   */
  const handleRescan = useCallback(
    async (requested: MachineSummary[]) => {
      // The fleet view already leaves Windows hosts out; this is the second
      // line, because the backend refuses a whole batch that contains one
      // (Req 10.8) and a single stray target would fail every host in it.
      const targets = requested.filter((machine) => isScannable(machine.platform));
      if (targets.length === 0) return;
      setScanning(true);
      setError(null);
      try {
        const outcomes = await api.startScan(
          targets.map((machine) => ({
            id: machine.machineId,
            hostname: machine.hostname,
            platform: machine.platform,
          })),
        );
        setScanOutcomes(outcomes);

        const failed = outcomes.filter((o) => o.status !== "success");
        const partial = outcomes.filter((o) => o.status === "success" && !o.sourcesOk);
        if (failed.length === 0 && partial.length === 0) {
          toast.success(`Re-scanned ${outcomes.length} host(s) successfully.`);
        } else {
          if (partial.length > 0) {
            toast.warning(
              `${partial.length} of ${outcomes.length} host(s) returned partial ` +
                "results: an advisory source was unreachable.",
            );
          }
          for (const outcome of failed) {
            toast.error(
              `${outcome.machineId}: ${statusLabel(outcome.status)}` +
                (outcome.message ? ` -- ${outcome.message}` : ""),
            );
          }
        }
        await loadMachines();
      } catch (err: unknown) {
        const message = errorMessage(err);
        setError(message);
        toast.error(message);
      } finally {
        setScanning(false);
      }
    },
    [api, loadMachines, toast],
  );

  const handleBack = useCallback(() => {
    navigate({ workspace: "fleet", machineId: null });
    setFindings([]);
    loadMachines().catch(() => {});
  }, [loadMachines, navigate]);

  const handleNavigate = useCallback(
    (nav: Workspace) => {
      navigate({ workspace: nav, machineId: null });
      setError(null);
      setScanOutcomes(undefined);
    },
    [navigate],
  );

  const handleScan = useCallback(
    async (target: ScanTargetInput) => {
      setScanning(true);
      setError(null);
      try {
        const outcomes = await api.startScan([target]);
        setScanOutcomes(outcomes);
        for (const outcome of outcomes) {
          if (outcome.status === "success" && !outcome.sourcesOk) {
            toast.warning(
              `${outcome.machineId}: ${outcome.message ?? "partial results"}`,
            );
          } else if (outcome.status !== "success") {
            toast.error(
              `${outcome.machineId}: ${statusLabel(outcome.status)}` +
                (outcome.message ? ` -- ${outcome.message}` : ""),
            );
          } else {
            toast.success(
              `Scan completed for ${target.hostname}: ${outcome.findingCount} CVEs identified.`,
            );
          }
        }
        await loadMachines();
      } catch (err: unknown) {
        const message = errorMessage(err);
        setError(message);
        toast.error(message);
      } finally {
        setScanning(false);
      }
    },
    [api, loadMachines, toast],
  );

  const handleSaveRemediation = useCallback(
    async (
      finding: CveFinding,
      status: RemediationStatus,
      note: string,
    ) => {
      if (!selectedMachineId) {
        return;
      }
      setError(null);
      try {
        if (finding.remediationRecordId) {
          await api.updateRemediation(finding.remediationRecordId, {
            status,
            note,
          });
        } else {
          await api.addRemediation(selectedMachineId, finding.cveId, {
            status,
            note,
          });
        }
        await loadFindings(selectedMachineId);
        await loadMachines();
      } catch (err: unknown) {
        const message = errorMessage(err);
        setError(message);
        toast.error(message);
      }
    },
    [api, selectedMachineId, loadFindings, loadMachines, toast],
  );

  const selectedMachine = selectedMachineId
    ? machines.find((machine) => machine.machineId === selectedMachineId)
    : undefined;

  return (
    <main>
      <div className="app-header">
        <div className="brand-title-group">
          <h1 className="brand">
            <span className="brand-shield" aria-hidden="true">
              <Icon name="shield" />
            </span>
            <span className="brand-word">
              cve<span className="brand-stamp">DECK</span>
            </span>
            {capabilities?.version && (
              <span className="brand-badge">v{capabilities.version}</span>
            )}
          </h1>
          <p className="hint brand-tagline">
            Agentless CVE Discovery &amp; Fleet Remediation{" "}
            <a
              className="source-link"
              href="https://github.com/reprodev/cvedeck"
              target="_blank"
              rel="noreferrer noopener"
            >
              AGPL-3.0 &mdash; source
            </a>
          </p>
        </div>
        {/*
          Cycles system -> light -> dark -> system rather than toggling a
          boolean, so "follow the OS" stays reachable after someone has pinned a
          value. The label carries the current state for screen readers, since
          the icon alone does not.
        */}
        <div className="header-actions">
          {account && (
            <nav className="account-menu" aria-label="Account">
              <span className="account-name">
                <Icon name="user" /> {account.username}
              </span>
              <button
                type="button"
                className={`secondary account-btn ${activeNav === "settings" ? "active" : ""}`}
                onClick={() => handleNavigate("settings")}
                aria-current={activeNav === "settings" ? "page" : undefined}
              >
                <Icon name="key" /> Settings
              </button>
              <button type="button" className="secondary account-btn" onClick={onSignOut}>
                <Icon name="log-out" /> Sign out
              </button>
            </nav>
          )}
          <button
            type="button"
            className="theme-toggle"
            onClick={cycleTheme}
            title={`${themeLabel} — click to change`}
            aria-label={`${themeLabel}. Click to change theme.`}
          >
            <Icon name={themeIcon} />
          </button>
        </div>
      </div>

      {/* A public demo has to say so. Without this the fleet reads as a real
          network, the failure states read as this person's problems, and the
          first scan attempt returns a 403 with no explanation of why. */}
      {capabilities?.demoMode && (
        <p className="demo-banner">
          <Icon name="monitor" />
          <span>
            <strong>Demo instance.</strong> This fleet is fictional and scanning
            is disabled. Everything else is the real application.
          </span>
          <a
            href="https://github.com/reprodev/cvedeck#quick-start"
            target="_blank"
            rel="noreferrer noopener"
          >
            Run your own
          </a>
        </p>
      )}

      {/* Top-level navigation */}
      {!selectedMachineId && (
        <div className="workspace-tabs top-navbar" style={{ marginBottom: "1.5rem" }}>
          <button
            type="button"
            className={`workspace-tab-btn ${activeNav === "fleet" ? "active" : ""}`}
            onClick={() => handleNavigate("fleet")}
          >
            <span>
              <Icon name="dashboard" /> Fleet Overview
            </span>
            <span className="tab-badge">{machines.length}</span>
          </button>
          <button
            type="button"
            className={`workspace-tab-btn ${activeNav === "scan" ? "active" : ""}`}
            onClick={() => handleNavigate("scan")}
          >
            <span>
              <Icon name="zap" /> New Scan
            </span>
          </button>
          <button
            type="button"
            className={`workspace-tab-btn ${activeNav === "discovery" ? "active" : ""}`}
            onClick={() => handleNavigate("discovery")}
          >
            <span>
              <Icon name="search" /> Network Discovery
            </span>
          </button>
        </div>
      )}

      {error && (
        <p role="alert" className="error-banner">
          <span>{error}</span>
          <button
            type="button"
            className="error-banner-dismiss"
            onClick={() => setError(null)}
            aria-label="Dismiss error"
          >
            ×
          </button>
        </p>
      )}

      {selectedMachineId ? (
        <MachineDrillDownView
          machineId={selectedMachineId}
          hostname={selectedMachine?.hostname}
          platform={selectedMachine?.platform}
          findings={findings}
          onBack={handleBack}
          onSaveRemediation={handleSaveRemediation}
        />
      ) : activeNav === "settings" && account ? (
        <SettingsView
          username={account.username}
          onChangePassword={(current, next) => api.changePassword(current, next)}
          onListTokens={() => api.listApiTokens()}
          onCreateToken={(name) => api.createApiToken(name)}
          onRevokeToken={(tokenId) => api.revokeApiToken(tokenId)}
          onBack={() => handleNavigate("fleet")}
        />
      ) : activeNav === "discovery" ? (
        <DiscoveryView
          onSweep={(cidr, options) => api.discoverySweep(cidr, options)}
          onEnrollHosts={handleEnrollHosts}
          onQuickScan={handleQuickScan}
          enrolledHostnames={machines.map((m) => m.hostname)}
          initialResult={discoveryResult}
          initialCidr={discoveryCidr}
          onResultChange={handleDiscoveryResultChange}
          onCidrChange={handleDiscoveryCidrChange}
        />
      ) : activeNav === "scan" ? (
        <ScanFormView
          onScan={handleScan}
          onTestConnection={(input) => api.testConnection(input)}
          scanning={scanning}
          outcomes={scanOutcomes}
          initialTarget={quickScanTarget}
          knownHosts={knownHosts}
          serverKeyAvailable={capabilities?.serverSshKey ?? false}
        />
      ) : (
        <MachineListView
          machines={machines}
          loading={loadingMachines}
          onSelectMachine={handleSelectMachine}
          onQuickScan={handleQuickScan}
          onNavigateScan={() => handleNavigate("scan")}
          onRescan={capabilities?.serverSshKey ? handleRescan : undefined}
          scanning={scanning}
          feeds={feeds}
          onRefreshFeeds={handleRefreshFeeds}
          refreshingFeeds={refreshingFeeds}
        />
      )}
    </main>
  );
}
