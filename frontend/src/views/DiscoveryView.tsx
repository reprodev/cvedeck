import { useCallback, useMemo, useState } from "react";
import { exportDiscoveryCsv } from "../lib/csvExport";
import type { DiscoveredHost, DiscoverySweepResult, Platform } from "../types";
import { inferPlatform, isScannable, WINDOWS_SCAN_UNSUPPORTED } from "../lib/platform";
import { Icon } from "../components/Icon";
import type { IconName } from "../components/Icon";

/** Port number to human-readable protocol label. */
const PORT_LABELS: Record<number, string> = {
  22: "SSH",
  80: "HTTP",
  443: "HTTPS",
  445: "SMB",
  3389: "RDP",
  5985: "WinRM",
};

/** OS guess to an icon name, for rendering through <Icon>. */
function osIcon(osGuess: string): IconName {
  const low = osGuess.toLowerCase();
  if (low.includes("windows")) return "windows";
  if (
    low.includes("linux") ||
    low.includes("ubuntu") ||
    low.includes("debian") ||
    low.includes("centos") ||
    low.includes("fedora") ||
    low.includes("rhel")
  ) {
    return "linux";
  }
  // An unrecognised banner is genuinely unknown, not "probably Linux".
  return "help";
}

interface DiscoveryViewProps {
  onSweep: (
    cidr: string,
    options?: { ports?: number[]; grabBanners?: boolean },
  ) => Promise<DiscoverySweepResult>;
  onEnrollHosts?: (
    hosts: { hostname: string; platform: Platform }[],
  ) => Promise<void>;
  onQuickScan?: (host: { hostname: string; platform: Platform }) => void;
  enrolledHostnames?: string[];
  initialResult?: DiscoverySweepResult | null;
  initialCidr?: string;
  onResultChange?: (result: DiscoverySweepResult | null) => void;
  onCidrChange?: (cidr: string) => void;
}

export function DiscoveryView({
  onSweep,
  onEnrollHosts,
  onQuickScan,
  enrolledHostnames = [],
  initialResult = null,
  initialCidr = "",
  onResultChange,
  onCidrChange,
}: DiscoveryViewProps) {
  const [cidr, setCidr] = useState(initialCidr);
  const [sweeping, setSweeping] = useState(false);
  const [enrolling, setEnrolling] = useState(false);
  const [result, setResult] = useState<DiscoverySweepResult | null>(initialResult);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);
  const [selectedHost, setSelectedHost] = useState<DiscoveredHost | null>(null);
  // Locally enrolled hosts, tracked so a row flips to "Enrolled" immediately
  // rather than waiting for the fleet to refetch.
  const [locallyEnrolled, setLocallyEnrolled] = useState<Set<string>>(new Set());

  // Union of what the server knows and what this session just enrolled. A lazy
  // initializer seeded this once and never resynced, so a host already in the
  // fleet still showed "Add" whenever the machine list resolved after this view
  // mounted -- which is the normal ordering on a fresh page load.
  const enrolledSet = useMemo(
    () => new Set([...enrolledHostnames, ...locallyEnrolled]),
    [enrolledHostnames, locallyEnrolled],
  );

  const handleCidrChange = useCallback(
    (newCidr: string) => {
      setCidr(newCidr);
      onCidrChange?.(newCidr);
    },
    [onCidrChange],
  );

  const handleSweep = useCallback(async () => {
    const trimmed = cidr.trim();
    if (!trimmed) return;
    setSweeping(true);
    setError(null);
    setSuccessMsg(null);
    setResult(null);
    setSelectedHost(null);
    onResultChange?.(null);
    try {
      const sweepResult = await onSweep(trimmed);
      setResult(sweepResult);
      onResultChange?.(sweepResult);
    } catch (err) {
      setError(err instanceof Error ? err.message : "Sweep failed");
    } finally {
      setSweeping(false);
    }
  }, [cidr, onSweep, onResultChange]);

  const handleEnrollSingle = useCallback(
    async (host: DiscoveredHost) => {
      if (!onEnrollHosts) return;
      setEnrolling(true);
      setError(null);
      try {
        const platform = inferPlatform(host);
        await onEnrollHosts([{ hostname: host.ip, platform }]);
        setLocallyEnrolled((prev) => new Set([...prev, host.ip]));
        setSuccessMsg(`Host ${host.ip} enrolled in fleet successfully!`);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Enrollment failed");
      } finally {
        setEnrolling(false);
      }
    },
    [onEnrollHosts],
  );

  const handleEnrollAll = useCallback(async () => {
    if (!onEnrollHosts || !result) return;
    setEnrolling(true);
    setError(null);
    try {
      const toEnroll = result.hosts.map((h) => ({
        hostname: h.ip,
        platform: inferPlatform(h),
      }));
      await onEnrollHosts(toEnroll);
      setLocallyEnrolled((prev) => new Set([...prev, ...result.hosts.map((h) => h.ip)]));
      setSuccessMsg(
        `All ${result.hosts.length} discovered hosts enrolled in fleet successfully!`,
      );
    } catch (err) {
      setError(err instanceof Error ? err.message : "Enrollment failed");
    } finally {
      setEnrolling(false);
    }
  }, [onEnrollHosts, result]);

  return (
    <section aria-label="Network discovery" className="view-container">
      {/* Header */}
      <div className="view-header">
        <div>
          <h2 className="view-title">
            <Icon name="radar" /> Network Discovery
          </h2>
          <span className="view-subtitle">
            Zero-touch subnet sweep — no credentials required
          </span>
        </div>
      </div>

      {/* Sweep Form */}
      <div className="card" style={{ padding: "1.25rem 1.5rem", marginBottom: "1.25rem" }}>
        <div style={{ display: "flex", gap: "1rem", alignItems: "flex-end", flexWrap: "wrap" }}>
          <div style={{ flex: "1 1 340px" }}>
            <label
              htmlFor="discovery-cidr"
              style={{
                display: "block",
                fontSize: "0.82rem",
                fontWeight: 600,
                color: "var(--text-muted)",
                textTransform: "uppercase",
                letterSpacing: "0.05em",
                marginBottom: "0.4rem",
              }}
            >
              Network CIDR
            </label>
            <input
              id="discovery-cidr"
              type="text"
              placeholder="e.g. 192.168.0.0/24"
              value={cidr}
              onChange={(e) => handleCidrChange(e.target.value)}
              onKeyDown={(e) => e.key === "Enter" && handleSweep()}
              aria-label="Network CIDR to scan"
              style={{
                width: "100%",
                padding: "0.65rem 1rem",
                background: "var(--surface)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius-sm)",
                color: "var(--text)",
                fontSize: "0.9rem",
              }}
            />
          </div>
          <button
            type="button"
            className="btn-primary"
            onClick={handleSweep}
            disabled={sweeping || !cidr.trim()}
            style={{ minWidth: "140px" }}
          >
            {sweeping ? <><Icon name="clock" /> Sweeping…</> : <><Icon name="radar" /> Start sweep</>}
          </button>
        </div>
        <p style={{ fontSize: "0.78rem", color: "var(--text-muted)", marginTop: "0.6rem" }}>
          <Icon name="lock" /> Discovery uses ICMP ping, TCP connect probes, and unauthenticated banner reads only. No credentials are sent to any host.
        </p>
      </div>

      {/* Alerts */}
      {error && (
        <div
          className="card"
          style={{
            padding: "0.9rem 1.25rem",
            borderColor: "var(--critical)",
            background: "var(--error-bg)",
            marginBottom: "1.25rem",
          }}
        >
          <span style={{ color: "var(--critical)", fontWeight: 600 }}><Icon name="alert" /> {error}</span>
        </div>
      )}

      {successMsg && (
        <div
          className="card"
          style={{
            padding: "0.9rem 1.25rem",
            borderColor: "var(--low)",
            background: "var(--ok-bg)",
            marginBottom: "1.25rem",
          }}
        >
          <span style={{ color: "var(--ok-text)", fontWeight: 600 }}><Icon name="check-circle" /> {successMsg}</span>
        </div>
      )}

      {/* Results */}
      {result && (
        <>
          {/* Summary KPIs */}
          <div className="severity-kpi-grid" style={{ gridTemplateColumns: "repeat(3, minmax(0, 1fr))" }}>
            <div className="severity-kpi-card">
              <div className="severity-kpi-header">
                <span className="severity-kpi-label">Hosts Scanned</span>
                <span className="severity-kpi-icon"><Icon name="radar" /></span>
              </div>
              <div className="severity-kpi-value">{result.totalHostsScanned}</div>
            </div>
            <div className="severity-kpi-card kpi-total active">
              <div className="severity-kpi-header">
                <span className="severity-kpi-label">Hosts Discovered</span>
                <span className="severity-kpi-icon">
                  <Icon name="check-circle" />
                </span>
              </div>
              <div className="severity-kpi-value">{result.totalHostsDiscovered}</div>
            </div>
            <div className="severity-kpi-card">
              <div className="severity-kpi-header">
                <span className="severity-kpi-label">Target Subnet</span>
                <span className="severity-kpi-icon"><Icon name="network" /></span>
              </div>
              <div className="severity-kpi-value" style={{ fontSize: "1.1rem" }}>
                {result.cidr}
              </div>
            </div>
          </div>

          {/* Action Bar for Batch Operations */}
          {result.hosts.length > 0 && onEnrollHosts && (
            <div
              style={{
                display: "flex",
                justifyContent: "space-between",
                alignItems: "center",
                marginBottom: "1rem",
                padding: "0.75rem 1.15rem",
                background: "var(--surface)",
                border: "1px solid var(--border)",
                borderRadius: "var(--radius)",
              }}
            >
              <span style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                Discovered <strong>{result.hosts.length}</strong> live endpoint
                {result.hosts.length === 1 ? "" : "s"}
              </span>
              <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <button
                  type="button"
                  className="pagination-btn"
                  onClick={() => exportDiscoveryCsv(result.cidr, result.hosts)}
                  style={{
                    fontSize: "0.84rem",
                    padding: "0.45rem 0.9rem",
                    background: "var(--surface)",
                    color: "var(--text)",
                    fontWeight: 600,
                  }}
                  title="Download RFC 4180 CSV export of discovered network assets"
                >
                  <Icon name="file-down" /> Export Discovery CSV
                </button>
                <button
                  type="button"
                  className="btn-primary"
                  onClick={handleEnrollAll}
                  disabled={enrolling}
                  style={{ fontSize: "0.84rem", padding: "0.45rem 1rem" }}
                >
                  {enrolling ? "Enrolling…" : <><Icon name="plus" /> Enroll All ({result.hosts.length})</>}
                </button>
              </div>
            </div>
          )}

          {/* Host Table + Detail */}
          {result.hosts.length === 0 ? (
            <div className="card" style={{ padding: "2rem", textAlign: "center" }}>
              <p style={{ color: "var(--text-muted)" }}>No active hosts discovered on {result.cidr}</p>
            </div>
          ) : (
            <div className="split-pane-container">
              {/* Master: Host List */}
              <div className="master-pane">
                <div style={{ overflowX: "auto" }}>
                  <table>
                    <thead>
                      <tr>
                        <th>IP Address</th>
                        <th>Hostname</th>
                        <th>OS</th>
                        <th>Open Ports</th>
                        <th>Actions</th>
                      </tr>
                    </thead>
                    <tbody>
                      {result.hosts.map((host) => {
                        const isEnrolled = enrolledSet.has(host.ip);
                        const platform = inferPlatform(host);
                        return (
                          <tr
                            key={host.ip}
                            className={`master-row ${selectedHost?.ip === host.ip ? "selected" : ""}`}
                            onClick={() => setSelectedHost(host)}
                          >
                            <td style={{ fontFamily: "var(--font-mono)", fontWeight: 600 }}>
                              {host.ip}
                            </td>
                            <td>{host.hostname || "—"}</td>
                            <td>
                              <span title={host.osGuess}>
                                <Icon name={osIcon(host.osGuess)} /> {host.osGuess}
                              </span>
                            </td>
                            <td>
                              <div style={{ display: "flex", gap: "0.35rem", flexWrap: "wrap" }}>
                                {host.openPorts.map((port) => (
                                  <span
                                    key={port}
                                    className="badge badge-low"
                                    style={{ fontSize: "0.72rem" }}
                                  >
                                    {PORT_LABELS[port] || port}
                                  </span>
                                ))}
                                {host.openPorts.length === 0 && (
                                  <span style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>
                                    Ping only
                                  </span>
                                )}
                              </div>
                            </td>
                            <td>
                              <div
                                style={{ display: "flex", gap: "0.4rem", alignItems: "center" }}
                                onClick={(e) => e.stopPropagation()}
                              >
                                {onEnrollHosts && (
                                  <button
                                    type="button"
                                    className="pagination-btn"
                                    onClick={() => handleEnrollSingle(host)}
                                    disabled={enrolling || isEnrolled}
                                    style={{
                                      fontSize: "0.75rem",
                                      padding: "0.25rem 0.6rem",
                                      color: isEnrolled ? "var(--ok-text)" : "var(--text)",
                                    }}
                                    title={isEnrolled ? "Already in fleet" : "Add to fleet list"}
                                  >
                                    {isEnrolled ? <><Icon name="check" /> Enrolled</> : <><Icon name="plus" /> Add</>}
                                  </button>
                                )}
                                {onQuickScan && (
                                  <button
                                    type="button"
                                    className="pagination-btn"
                                    onClick={() => onQuickScan({ hostname: host.ip, platform })}
                                    disabled={!isScannable(platform)}
                                    style={{
                                      fontSize: "0.75rem",
                                      padding: "0.25rem 0.6rem",
                                      background: "var(--accent-subtle)",
                                      borderColor: "var(--accent)",
                                      color: "var(--accent)",
                                    }}
                                    title={
                                      isScannable(platform)
                                        ? "Pre-fill scan form with this host"
                                        : WINDOWS_SCAN_UNSUPPORTED
                                    }
                                  >
                                    <Icon name="zap" /> Scan
                                  </button>
                                )}
                              </div>
                            </td>
                          </tr>
                        );
                      })}
                    </tbody>
                  </table>
                </div>
              </div>

              {/* Detail: Selected Host */}
              <div className="detail-inspector-pane">
                {selectedHost ? (
                  <>
                    <div>
                      <div
                        style={{
                          fontSize: "0.72rem",
                          fontWeight: 600,
                          color: "var(--text-muted)",
                          textTransform: "uppercase",
                          letterSpacing: "0.05em",
                          marginBottom: "0.3rem",
                        }}
                      >
                        Host Details
                      </div>
                      <div
                        style={{
                          fontFamily: "var(--font-mono)",
                          fontSize: "1.3rem",
                          fontWeight: 700,
                        }}
                      >
                        {selectedHost.ip}
                      </div>
                      {selectedHost.hostname && (
                        <div style={{ fontSize: "0.85rem", color: "var(--text-muted)", marginTop: "0.15rem" }}>
                          {selectedHost.hostname}
                        </div>
                      )}
                    </div>

                    <div style={{ display: "flex", gap: "0.75rem", flexWrap: "wrap" }}>
                      <div className="action-card" style={{ flex: 1 }}>
                        <div style={{ fontSize: "0.72rem", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                          OS
                        </div>
                        <div style={{ fontWeight: 600 }}>
                          <Icon name={osIcon(selectedHost.osGuess)} /> {selectedHost.osGuess}
                        </div>
                      </div>
                      <div className="action-card" style={{ flex: 1 }}>
                        <div style={{ fontSize: "0.72rem", fontWeight: 600, color: "var(--text-muted)", textTransform: "uppercase" }}>
                          Ping
                        </div>
                        <div style={{ fontWeight: 600 }}>
                          {selectedHost.respondsToPing ? <><Icon name="check-circle" /> Responds</> : <><Icon name="x-circle" /> Filtered</>}
                        </div>
                      </div>
                    </div>

                    {/* Actions Card */}
                    <div className="action-card">
                      <div
                        style={{
                          fontSize: "0.72rem",
                          fontWeight: 600,
                          color: "var(--text-muted)",
                          textTransform: "uppercase",
                          marginBottom: "0.4rem",
                        }}
                      >
                        Fleet Management
                      </div>
                      <div style={{ display: "flex", gap: "0.6rem", flexWrap: "wrap" }}>
                        {onEnrollHosts && (
                          <button
                            type="button"
                            className="btn-primary"
                            onClick={() => handleEnrollSingle(selectedHost)}
                            disabled={enrolling || enrolledSet.has(selectedHost.ip)}
                            style={{ flex: 1, fontSize: "0.82rem", padding: "0.45rem 0.8rem" }}
                          >
                            {enrolledSet.has(selectedHost.ip) ? <><Icon name="check" /> Enrolled in Fleet</> : <><Icon name="plus" /> Add to Fleet Roster</>}
                          </button>
                        )}
                        {onQuickScan && (
                          <button
                            type="button"
                            className="workspace-tab-btn active"
                            onClick={() =>
                              onQuickScan({
                                hostname: selectedHost.ip,
                                platform: inferPlatform(selectedHost),
                              })
                            }
                            disabled={!isScannable(inferPlatform(selectedHost))}
                            title={
                              isScannable(inferPlatform(selectedHost))
                                ? undefined
                                : WINDOWS_SCAN_UNSUPPORTED
                            }
                            style={{ flex: 1, fontSize: "0.82rem", padding: "0.45rem 0.8rem", justifyContent: "center" }}
                          >
                            <Icon name="zap" /> Launch Credentialed Scan
                          </button>
                        )}
                      </div>
                    </div>

                    {/* Services */}
                    <div>
                      <div
                        style={{
                          fontSize: "0.72rem",
                          fontWeight: 600,
                          color: "var(--text-muted)",
                          textTransform: "uppercase",
                          letterSpacing: "0.05em",
                          marginBottom: "0.5rem",
                        }}
                      >
                        Discovered Services ({selectedHost.services.length})
                      </div>
                      {selectedHost.services.length === 0 ? (
                        <p style={{ fontSize: "0.85rem", color: "var(--text-muted)" }}>
                          No services detected
                        </p>
                      ) : (
                        <div style={{ display: "flex", flexDirection: "column", gap: "0.5rem" }}>
                          {selectedHost.services.map((svc) => (
                            <div key={svc.port} className="action-card">
                              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
                                <span style={{ fontWeight: 600, fontSize: "0.88rem" }}>
                                  {PORT_LABELS[svc.port] || svc.protocol.toUpperCase()}{" "}
                                  <span style={{ color: "var(--text-muted)", fontWeight: 400 }}>
                                    :{svc.port}
                                  </span>
                                </span>
                                {svc.product && (
                                  <span className="badge badge-low" style={{ fontSize: "0.72rem" }}>
                                    {svc.product}
                                    {svc.version ? `/${svc.version}` : ""}
                                  </span>
                                )}
                              </div>
                              {svc.banner && (
                                <div
                                  style={{
                                    fontFamily: "var(--font-mono)",
                                    fontSize: "0.75rem",
                                    color: "var(--text-muted)",
                                    background: "var(--surface-muted)",
                                    padding: "0.4rem 0.6rem",
                                    borderRadius: "4px",
                                    marginTop: "0.3rem",
                                    wordBreak: "break-all",
                                    maxHeight: "80px",
                                    overflowY: "auto",
                                  }}
                                >
                                  {svc.banner}
                                </div>
                              )}
                              {svc.extraInfo && (
                                <div style={{ fontSize: "0.78rem", color: "var(--text-muted)" }}>
                                  {svc.extraInfo}
                                </div>
                              )}
                            </div>
                          ))}
                        </div>
                      )}
                    </div>
                  </>
                ) : (
                  <div style={{ textAlign: "center", padding: "2rem 1rem", color: "var(--text-muted)" }}>
                    <div style={{ fontSize: "2rem", marginBottom: "0.5rem" }}><Icon name="radar" /></div>
                    <p>Click a host to inspect its services and banners</p>
                  </div>
                )}
              </div>
            </div>
          )}
        </>
      )}
    </section>
  );
}
