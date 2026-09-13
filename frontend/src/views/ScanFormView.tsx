// ScanFormView collects a target machine and its credentials, then hands them
// to the app shell to initiate a scan.
//
// Requirements:
//   1.1 - manually initiate a scan of a target machine
//   1.2 - platform selects the collector; Windows is deferred, see 10.8
//   10.8 - a platform that cannot be assessed is refused, not scanned

import { useCallback, useEffect, useState } from "react";
import type {
  Platform,
  ScanOutcome,
  ScanTargetInput,
  TestConnectionInput,
  TestConnectionResult,
} from "../types";
import { statusLabel } from "../lib/labels";
import { isScannable, WINDOWS_SCAN_UNSUPPORTED } from "../lib/platform";
import { Icon } from "../components/Icon";

export interface ScanFormViewProps {
  /** Called with the target to scan. Wiring lives in the app shell. */
  onScan: (target: ScanTargetInput) => void;
  /** Optional pre-flight connection test handler. */
  onTestConnection?: (input: TestConnectionInput) => Promise<TestConnectionResult>;
  /** True while a scan request is in flight; disables the form. */
  scanning?: boolean;
  /** Per-target results of the most recent scan, if any. */
  outcomes?: ScanOutcome[];
  /** Optional pre-filled target to scan (e.g. from discovery quick scan). */
  initialTarget?: { hostname: string; platform: Platform } | null;
  /** Known hosts from fleet or discovery to auto-detect platform. */
  knownHosts?: { hostname: string; platform: Platform }[];
  /**
   * Whether a server-managed SSH key is configured. Gates the "server key"
   * auth mode: offering it without one would produce a guaranteed failure.
   */
  serverKeyAvailable?: boolean;
}

/** How the scan authenticates to the target (Req 9.5, 11.6). */
type AuthMode = "password" | "key" | "server";

/** Human-readable label for a per-target scan status. */
export function ScanFormView({
  onScan,
  onTestConnection,
  scanning = false,
  outcomes,
  initialTarget,
  knownHosts = [],
  serverKeyAvailable = false,
}: ScanFormViewProps) {
  const [hostname, setHostname] = useState(initialTarget?.hostname ?? "");
  const [platform, setPlatform] = useState<Platform>(initialTarget?.platform ?? "linux");
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [authMode, setAuthMode] = useState<AuthMode>("password");
  const [privateKey, setPrivateKey] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [autoDetected, setAutoDetected] = useState<boolean>(false);
  const [testingConnection, setTestingConnection] = useState<boolean>(false);
  const [testResult, setTestResult] = useState<TestConnectionResult | null>(null);

  // Sync initialTarget when pre-filled from quick scan
  useEffect(() => {
    if (initialTarget) {
      setHostname(initialTarget.hostname);
      setPlatform(initialTarget.platform);
      setAutoDetected(true);
    }
  }, [initialTarget]);

  // Auto-detect platform when hostname changes
  const handleHostnameChange = useCallback(
    (newHostname: string) => {
      setHostname(newHostname);
      const trimmed = newHostname.trim().toLowerCase();
      if (!trimmed) {
        setAutoDetected(false);
        return;
      }
      const match = knownHosts.find(
        (h) => h.hostname.toLowerCase() === trimmed,
      );
      if (match) {
        setPlatform(match.platform);
        setAutoDetected(true);
      } else {
        setAutoDetected(false);
      }
    },
    [knownHosts],
  );

  // WinRM has no SSH-key equivalent, so key modes apply to Linux only.
  const keyModesAvailable = platform === "linux";
  // Auto-detection can still land on Windows -- it is a real platform that
  // discovery finds -- so the form explains the refusal rather than hiding it.
  const scannable = isScannable(platform);
  const effectiveMode: AuthMode = keyModesAvailable ? authMode : "password";

  const credentialsForRequest = useCallback(() => {
    if (effectiveMode === "key") {
      return { privateKey, passphrase: passphrase || undefined };
    }
    if (effectiveMode === "server") {
      // Omitted entirely so the backend falls back to its configured key.
      return {};
    }
    return { password };
  }, [effectiveMode, password, privateKey, passphrase]);

  /** Whether the form has enough to attempt a connection. */
  const credentialsComplete =
    effectiveMode === "server"
      ? true
      : effectiveMode === "key"
        ? Boolean(privateKey.trim())
        : Boolean(password);

  const handleTestConnection = useCallback(async () => {
    if (!onTestConnection) return;
    const trimmed = hostname.trim();
    if (!trimmed || !credentialsComplete) {
      // Reported inline rather than through a blocking alert(), which was the
      // only native dialog left in the app.
      setTestResult({
        success: false,
        status: "ERROR",
        message:
          "Enter a hostname and the credentials for the selected authentication mode.",
        latencyMs: 0,
        osBanner: "",
      });
      return;
    }
    setTestingConnection(true);
    setTestResult(null);
    try {
      const res = await onTestConnection({
        hostname: trimmed,
        platform,
        username: username.trim(),
        ...credentialsForRequest(),
      });
      setTestResult(res);
    } catch (err) {
      setTestResult({
        success: false,
        status: "ERROR",
        message: err instanceof Error ? err.message : String(err),
        latencyMs: 0,
        osBanner: "",
      });
    } finally {
      setTestingConnection(false);
    }
  }, [
    hostname,
    platform,
    username,
    credentialsComplete,
    credentialsForRequest,
    onTestConnection,
  ]);

  const handleSubmit = useCallback(
    (event: React.FormEvent) => {
      event.preventDefault();
      const trimmed = hostname.trim();
      if (!trimmed || !scannable) {
        return;
      }
      onScan({
        id: trimmed,
        hostname: trimmed,
        platform,
        username: username.trim() || undefined,
        ...credentialsForRequest(),
      });
      // Never keep a secret around once it has been handed off.
      setPassword("");
      setPrivateKey("");
      setPassphrase("");
      setTestResult(null);
    },
    [hostname, platform, scannable, username, credentialsForRequest, onScan],
  );

  return (
    <section aria-label="Scan a machine" className="scan-form">
      <h2>Scan a Machine</h2>

      <form onSubmit={handleSubmit}>
        <div className="scan-form-grid">
          <div className="field-group">
            <label htmlFor="scan-hostname">Hostname</label>
            <input
              id="scan-hostname"
              type="text"
              value={hostname}
              placeholder="e.g. 192.168.1.50 or host.example.com"
              onChange={(e) => handleHostnameChange(e.target.value)}
              required
            />
          </div>

          <div className="field-group">
            <label htmlFor="scan-platform">Platform</label>
            <select
              id="scan-platform"
              value={platform}
              onChange={(e) => {
                setPlatform(e.target.value as Platform);
                setAutoDetected(false);
              }}
            >
              <option value="linux">Linux (SSH)</option>
              <option value="windows">Windows (WinRM) — not yet supported</option>
            </select>
            {autoDetected && (
              <small
                className="field-hint"
                style={{
                  fontSize: "0.74rem",
                  fontWeight: 600,
                  color: platform === "linux" ? "var(--low)" : "var(--accent)",
                  margin: "0.15rem 0 0 0",
                  display: "inline-flex",
                  alignItems: "center",
                  gap: "0.25rem",
                }}
                title="Inferred from open ports, service banners, and fleet roster"
              >
                <Icon name="zap" /> Auto-detected
              </small>
            )}
          </div>

          <div className="field-group">
            <label htmlFor="scan-username">Username</label>
            <input
              id="scan-username"
              type="text"
              value={username}
              placeholder={platform === "linux" ? "e.g. root, ubuntu, or debian (SSH)" : "e.g. Administrator or DOMAIN\\user (WinRM)"}
              onChange={(e) => setUsername(e.target.value)}
              // Optional in server-key mode only, where the backend falls back
              // to CVEDECK_DEFAULT_SSH_USER.
              required={effectiveMode !== "server"}
            />
          </div>

          {keyModesAvailable && (
            <div className="field-group">
              <label htmlFor="scan-auth-mode">Authentication</label>
              <select
                id="scan-auth-mode"
                value={authMode}
                onChange={(e) => setAuthMode(e.target.value as AuthMode)}
              >
                <option value="password">Password</option>
                <option value="key">SSH private key</option>
                {serverKeyAvailable && (
                  <option value="server">Server-managed key</option>
                )}
              </select>
            </div>
          )}

          {effectiveMode === "password" && (
            <div className="field-group">
              <label htmlFor="scan-password">Password</label>
              <input
                id="scan-password"
                type="password"
                value={password}
                placeholder={
                  platform === "linux" ? "SSH password" : "WinRM / Domain password"
                }
                onChange={(e) => setPassword(e.target.value)}
                required
              />
            </div>
          )}

          {effectiveMode === "key" && (
            <>
              <div className="field-group field-group-wide">
                <label htmlFor="scan-private-key">Private key</label>
                <textarea
                  id="scan-private-key"
                  value={privateKey}
                  rows={4}
                  spellCheck={false}
                  autoComplete="off"
                  placeholder={"-----BEGIN OPENSSH PRIVATE KEY-----\n..."}
                  onChange={(e) => setPrivateKey(e.target.value)}
                  required
                />
                <small className="field-hint">
                  Ed25519, ECDSA, or RSA in PEM or OpenSSH format. Parsed in memory
                  and never written to disk or stored.
                </small>
              </div>
              <div className="field-group">
                <label htmlFor="scan-passphrase">Passphrase (optional)</label>
                <input
                  id="scan-passphrase"
                  type="password"
                  value={passphrase}
                  autoComplete="off"
                  placeholder="Only if the key is encrypted"
                  onChange={(e) => setPassphrase(e.target.value)}
                />
              </div>
            </>
          )}

          {effectiveMode === "server" && (
            <div className="field-group field-group-wide">
              <p className="field-hint">
                Authenticating with the server-managed SSH key. Leave the username
                blank to use the configured default.
              </p>
            </div>
          )}
        </div>

        {!scannable && (
          <p className="field-hint" role="status" data-testid="platform-unsupported">
            <Icon name="help" /> {WINDOWS_SCAN_UNSUPPORTED}
          </p>
        )}

        <div style={{ display: "flex", alignItems: "center", gap: "0.75rem", marginTop: "1rem", flexWrap: "wrap" }}>
          <button type="submit" disabled={scanning || testingConnection || !scannable}>
            {scanning ? "Scanning..." : "Start scan"}
          </button>
          {onTestConnection && (
            <button
              type="button"
              className="export-btn"
              style={{ padding: "0.45rem 0.85rem", fontSize: "0.85rem" }}
              disabled={scanning || testingConnection || !hostname.trim() || !username.trim() || !password}
              onClick={handleTestConnection}
            >
              {testingConnection ? <><Icon name="plug" /> Testing…</> : <><Icon name="plug" /> Test Connection</>}
            </button>
          )}
          <span className="hint" style={{ margin: 0 }}>
            <Icon name="lock" /> Credentials are used in memory for this scan only and are never saved to disk or logs.
          </span>
        </div>

        {testResult && (
          <div
            style={{
              marginTop: "0.85rem",
              padding: "0.6rem 0.85rem",
              borderRadius: "6px",
              fontSize: "0.84rem",
              border: testResult.success
                ? "1px solid var(--ok-border)"
                : "1px solid var(--error-border)",
              background: testResult.success
                ? "var(--ok-bg)"
                : "var(--error-bg)",
              color: testResult.success ? "var(--ok-text)" : "var(--exploit)",
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              gap: "0.5rem",
              flexWrap: "wrap",
            }}
          >
            <div>
              <strong>{testResult.success ? <><Icon name="check-circle" /> Connection Verified:</> : <><Icon name="x-circle" /> Connection Test Failed:</>}</strong>{" "}
              {testResult.message}
              {testResult.osBanner && (
                <div style={{ marginTop: "0.2rem", fontSize: "0.78rem", color: "var(--text-muted)" }}>
                  Detected Host: <strong>{testResult.osBanner}</strong>
                </div>
              )}
            </div>
            <span style={{ fontSize: "0.75rem", opacity: 0.85 }}>
              <Icon name="zap" /> {testResult.latencyMs}ms
            </span>
          </div>
        )}
      </form>

      {outcomes && outcomes.length > 0 && (
        <div className="scan-outcomes" role="status">
          <h3>Scan Result</h3>
          <ul>
            {outcomes.map((outcome) => (
              <li key={outcome.machineId} data-status={outcome.status}>
                <strong>{outcome.machineId}</strong>:{" "}
                {statusLabel(outcome.status)} -- {outcome.findingCount}{" "}
                {outcome.findingCount === 1 ? "finding" : "findings"}
              </li>
            ))}
          </ul>
        </div>
      )}
    </section>
  );
}
