// Account settings: password and API tokens (Req 16.6, 16.7).
//
// Reached at #/settings from the header. A token is shown once, straight after
// it is created, with a copy button and a plain statement that it cannot be
// shown again -- the server keeps only a hash, so there is nothing to fetch
// later. Revoking asks for confirmation inline rather than through a blocking
// browser dialog.

import { useCallback, useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Icon } from "../components/Icon";
import { useToast } from "../components/Toast";
import { useClipboard } from "../lib/useClipboard";
import type { ApiToken, CreatedApiToken, HostKeyPin } from "../types";
import { MIN_PASSWORD_LENGTH } from "./SetupView";

export interface SettingsViewProps {
  username: string;
  onChangePassword: (currentPassword: string, newPassword: string) => Promise<void>;
  onListTokens: () => Promise<ApiToken[]>;
  onCreateToken: (name: string) => Promise<CreatedApiToken>;
  onRevokeToken: (tokenId: string) => Promise<void>;
  /** Every pinned SSH host key (Req 17.10). */
  onListHostKeys?: () => Promise<HostKeyPin[]>;
  /** Forget one pin. The port is part of the address it is pinned under. */
  onForgetHostKey?: (hostname: string, port: number) => Promise<void>;
  onBack: () => void;
}

function errorText(err: unknown, fallback: string): string {
  return err instanceof Error ? err.message : fallback;
}

function formatDate(value: string | null): string {
  if (!value) return "Never";
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleString();
}

export function SettingsView({
  username,
  onChangePassword,
  onListTokens,
  onCreateToken,
  onRevokeToken,
  onListHostKeys,
  onForgetHostKey,
  onBack,
}: SettingsViewProps) {
  const toast = useToast();

  return (
    <div className="settings-view">
      <div className="settings-header">
        <button type="button" className="secondary" onClick={onBack}>
          <Icon name="arrow-left" /> Back
        </button>
        <div>
          <h2>Account</h2>
          <p className="hint settings-subtitle">
            Signed in as <strong>{username}</strong>
          </p>
        </div>
      </div>
      <PasswordPanel onChangePassword={onChangePassword} onChanged={toast.success} />
      <TokensPanel
        onListTokens={onListTokens}
        onCreateToken={onCreateToken}
        onRevokeToken={onRevokeToken}
      />
      {onListHostKeys && onForgetHostKey && (
        <HostKeysPanel
          onListHostKeys={onListHostKeys}
          onForgetHostKey={onForgetHostKey}
        />
      )}
    </div>
  );
}

function PasswordPanel({
  onChangePassword,
  onChanged,
}: {
  onChangePassword: SettingsViewProps["onChangePassword"];
  onChanged: (message: string) => void;
}) {
  const [current, setCurrent] = useState("");
  const [next, setNext] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (next !== confirm) {
      setError("The new passwords do not match.");
      return;
    }
    if (next.length < MIN_PASSWORD_LENGTH) {
      setError(`Use at least ${MIN_PASSWORD_LENGTH} characters.`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      await onChangePassword(current, next);
      setCurrent("");
      setNext("");
      setConfirm("");
      onChanged("Password changed. Other devices have been signed out.");
    } catch (err) {
      setError(errorText(err, "The password could not be changed."));
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="card settings-panel" aria-labelledby="password-heading">
      <h3 id="password-heading">
        <Icon name="lock" /> Change password
      </h3>
      <p className="hint">Changing it signs out every other browser using this account.</p>
      <form className="settings-form" onSubmit={submit}>
        {error && (
          <p role="alert" className="error-banner">
            {error}
          </p>
        )}
        {/* A hidden username lets a password manager update the right entry. */}
        <input type="text" name="username" autoComplete="username" hidden readOnly />
        <div className="field-group">
          <label htmlFor="current-password">Current password</label>
          <input
            id="current-password"
            type="password"
            autoComplete="current-password"
            required
            value={current}
            onChange={(e) => setCurrent(e.target.value)}
          />
        </div>
        <div className="field-group">
          <label htmlFor="new-password">New password</label>
          <input
            id="new-password"
            type="password"
            autoComplete="new-password"
            required
            value={next}
            onChange={(e) => setNext(e.target.value)}
          />
          <span className="field-hint">At least {MIN_PASSWORD_LENGTH} characters.</span>
        </div>
        <div className="field-group">
          <label htmlFor="confirm-password">Repeat new password</label>
          <input
            id="confirm-password"
            type="password"
            autoComplete="new-password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
        <div>
          <button type="submit" disabled={busy}>
            {busy ? "Saving…" : "Change password"}
          </button>
        </div>
      </form>
    </section>
  );
}

function TokensPanel({
  onListTokens,
  onCreateToken,
  onRevokeToken,
}: Pick<SettingsViewProps, "onListTokens" | "onCreateToken" | "onRevokeToken">) {
  const toast = useToast();
  const clipboard = useClipboard(toast.error, 2500);
  const [tokens, setTokens] = useState<ApiToken[] | null>(null);
  const [name, setName] = useState("");
  const [created, setCreated] = useState<CreatedApiToken | null>(null);
  const [confirmRevoke, setConfirmRevoke] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const load = useCallback(async () => {
    try {
      setTokens(await onListTokens());
    } catch (err) {
      setTokens([]);
      setError(errorText(err, "Tokens could not be loaded."));
    }
  }, [onListTokens]);

  useEffect(() => {
    void load();
  }, [load]);

  const create = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      const token = await onCreateToken(name);
      setCreated(token);
      setName("");
      await load();
    } catch (err) {
      setError(errorText(err, "The token could not be created."));
    } finally {
      setBusy(false);
    }
  };

  const revoke = async (token: ApiToken) => {
    setError(null);
    try {
      await onRevokeToken(token.tokenId);
      setConfirmRevoke(null);
      if (created?.tokenId === token.tokenId) setCreated(null);
      toast.success(`Revoked "${token.name}". Anything using it will now be refused.`);
      await load();
    } catch (err) {
      setError(errorText(err, "The token could not be revoked."));
    }
  };

  return (
    <section className="card settings-panel" aria-labelledby="tokens-heading">
      <h3 id="tokens-heading">
        <Icon name="key" /> API tokens
      </h3>
      <p className="hint">
        For scripts and other applications, such as a scheduled intel refresh. Send
        one as <code>Authorization: Bearer &lt;token&gt;</code>. A token has the same
        access as you, except that it cannot change the password or manage tokens.
      </p>

      {error && (
        <p role="alert" className="error-banner">
          {error}
        </p>
      )}

      {created && (
        <div className="token-created" role="status">
          <p>
            <strong>Copy this token now.</strong> It will not be shown again.
          </p>
          <div className="token-created-row">
            <code className="token-value" data-testid="created-token">
              {created.token}
            </code>
            <button
              type="button"
              className="secondary"
              onClick={() => void clipboard.copy(created.token, created.tokenId)}
            >
              <Icon name={clipboard.copiedKey === created.tokenId ? "check" : "copy"} />
              {clipboard.copiedKey === created.tokenId ? "Copied" : "Copy"}
            </button>
          </div>
          <span className="visually-hidden" aria-live="polite">
            {clipboard.announcement}
          </span>
        </div>
      )}

      <form className="settings-form token-form" onSubmit={create}>
        <div className="field-group">
          <label htmlFor="token-name">New token name</label>
          <input
            id="token-name"
            placeholder="e.g. daily intel refresh"
            required
            value={name}
            onChange={(e) => setName(e.target.value)}
          />
        </div>
        <div>
          <button type="submit" disabled={busy}>
            <Icon name="plus" /> Create token
          </button>
        </div>
      </form>

      {tokens === null ? (
        <p className="hint">Loading tokens…</p>
      ) : tokens.length === 0 ? (
        <p className="hint">No tokens yet.</p>
      ) : (
        <div className="table-container">
          <table className="token-table">
            <thead>
              <tr>
                <th scope="col">Name</th>
                <th scope="col">Token</th>
                <th scope="col">Created</th>
                <th scope="col">Last used</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {tokens.map((token) => (
                <tr key={token.tokenId}>
                  <td data-label="Name">{token.name}</td>
                  <td data-label="Token">
                    <code>{token.prefix}…</code>
                  </td>
                  <td data-label="Created">{formatDate(token.createdAt)}</td>
                  <td data-label="Last used">{formatDate(token.lastUsedAt)}</td>
                  <td className="token-actions">
                    {token.revokedAt ? (
                      <span className="hint">Revoked</span>
                    ) : confirmRevoke === token.tokenId ? (
                      <span className="token-confirm">
                        <button type="button" onClick={() => void revoke(token)}>
                          Revoke "{token.name}"
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => setConfirmRevoke(null)}
                        >
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => setConfirmRevoke(token.tokenId)}
                        aria-label={`Revoke ${token.name}`}
                      >
                        <Icon name="trash" /> Revoke
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}

/**
 * Every pinned SSH host key, and a way to forget one (Req 17.10).
 *
 * A machine's page shows the pin for its own address on the configured SSH
 * port. That leaves two kinds of pin with nowhere to appear: one made by a
 * connection test to an address nobody enrolled, and one made while
 * CVEDECK_SSH_PORT was something else. Both still decide whether a future
 * connection is refused, so both are listed here.
 *
 * Forgetting confirms inline rather than in a modal, matching the revoke above
 * it: this is a list of rows each carrying one destructive action, and the
 * page should behave the same way throughout.
 */
function HostKeysPanel({
  onListHostKeys,
  onForgetHostKey,
}: {
  onListHostKeys: NonNullable<SettingsViewProps["onListHostKeys"]>;
  onForgetHostKey: NonNullable<SettingsViewProps["onForgetHostKey"]>;
}) {
  const toast = useToast();
  const [pins, setPins] = useState<HostKeyPin[] | null>(null);
  const [confirmForget, setConfirmForget] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      setPins(await onListHostKeys());
    } catch (err) {
      setPins([]);
      setError(errorText(err, "Pinned host keys could not be loaded."));
    }
  }, [onListHostKeys]);

  useEffect(() => {
    void load();
  }, [load]);

  const address = (pin: HostKeyPin) => `${pin.hostname}:${pin.port}`;

  const forget = async (pin: HostKeyPin) => {
    setError(null);
    try {
      await onForgetHostKey(pin.hostname, pin.port);
      setConfirmForget(null);
      toast.success(
        `Forgot the host key for ${address(pin)}. The next connection pins whatever key it presents.`,
      );
      await load();
    } catch (err) {
      setError(errorText(err, "The host key could not be forgotten."));
    }
  };

  return (
    <section className="card settings-panel" aria-labelledby="host-keys-heading">
      <h3 id="host-keys-heading">
        <Icon name="lock" /> Pinned SSH host keys
      </h3>
      <p className="hint">
        A host is held to the key pinned here, and refused before any credential is
        sent if it presents another. Compare a fingerprint with{" "}
        <code>ssh-keygen -lf /etc/ssh/ssh_host_&lt;type&gt;_key.pub</code> on the host
        itself. Forget one only when you know why the key changed — the next
        connection will trust whatever the host presents.
      </p>

      {error && (
        <p role="alert" className="error-banner">
          {error}
        </p>
      )}

      {pins === null ? (
        <p className="hint">Loading host keys…</p>
      ) : pins.length === 0 ? (
        <p className="hint">
          No host keys pinned yet. The first successful scan or connection test to a
          host pins its key.
        </p>
      ) : (
        <div className="table-container">
          <table className="token-table">
            <thead>
              <tr>
                <th scope="col">Address</th>
                <th scope="col">Key</th>
                <th scope="col">First seen</th>
                <th scope="col">Last seen</th>
                <th scope="col">Machine</th>
                <th scope="col">
                  <span className="visually-hidden">Actions</span>
                </th>
              </tr>
            </thead>
            <tbody>
              {pins.map((pin) => (
                <tr key={address(pin)}>
                  <td data-label="Address">{address(pin)}</td>
                  <td data-label="Key">
                    <code>
                      {pin.keyType} {pin.fingerprint}
                    </code>
                  </td>
                  <td data-label="First seen">{formatDate(pin.firstSeenAt)}</td>
                  <td data-label="Last seen">{formatDate(pin.lastSeenAt)}</td>
                  <td data-label="Machine">
                    {pin.machineId ? (
                      <a href={`#/machines/${encodeURIComponent(pin.machineId)}`}>
                        Open
                      </a>
                    ) : (
                      <span className="hint">Not enrolled</span>
                    )}
                  </td>
                  <td className="token-actions">
                    {confirmForget === address(pin) ? (
                      <span className="token-confirm">
                        <button type="button" onClick={() => void forget(pin)}>
                          Forget {address(pin)}
                        </button>
                        <button
                          type="button"
                          className="secondary"
                          onClick={() => setConfirmForget(null)}
                        >
                          Cancel
                        </button>
                      </span>
                    ) : (
                      <button
                        type="button"
                        className="secondary"
                        onClick={() => setConfirmForget(address(pin))}
                        aria-label={`Forget host key for ${address(pin)}`}
                      >
                        <Icon name="trash" /> Forget
                      </button>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
