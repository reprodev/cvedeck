// A machine's SSH host keys pinned on ports other than the one its page shows
// (Req 17.11).
//
// The page's own pin is the one on the configured SSH port. A host reached on
// another port -- by a connection test, or before CVEDECK_SSH_PORT changed --
// has a pin there too, and it still decides whether a connection to that port
// is refused. Until this, the only place to see or forget one was Settings,
// which is not where anyone looks when a machine's connection is refused.
//
// Forgetting confirms inline, like the Settings list it mirrors: each row
// carries one destructive action.

import { useCallback, useEffect, useState } from "react";

import type { HostKeyPin } from "../types";
import { Icon } from "./Icon";
import { useToast } from "./Toast";

export interface OtherPortPinsProps {
  machineId: string;
  /**
   * Port of the pin the page already shows, or null when it shows none -- in
   * which case every pin for this machine belongs here.
   */
  shownPort: number | null;
  onListHostKeys: () => Promise<HostKeyPin[]>;
  /** Omitted where forgetting is not allowed, such as demo mode (Req 17.7). */
  onForgetHostKey?: (hostname: string, port: number) => Promise<void>;
}

const address = (pin: HostKeyPin) => `${pin.hostname}:${pin.port}`;

export function OtherPortPins({
  machineId,
  shownPort,
  onListHostKeys,
  onForgetHostKey,
}: OtherPortPinsProps) {
  const toast = useToast();
  const [pins, setPins] = useState<HostKeyPin[] | null>(null);
  const [loadFailed, setLoadFailed] = useState(false);
  const [confirming, setConfirming] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    try {
      const all = await onListHostKeys();
      setPins(all.filter((pin) => pin.machineId === machineId && pin.port !== shownPort));
      setLoadFailed(false);
    } catch {
      // Not an empty list: a pin that could not be listed can still refuse a
      // connection, so the page says it does not know.
      setPins(null);
      setLoadFailed(true);
    }
  }, [machineId, shownPort, onListHostKeys]);

  useEffect(() => {
    void load();
  }, [load]);

  const forget = async (pin: HostKeyPin) => {
    if (!onForgetHostKey) return;
    setError(null);
    try {
      await onForgetHostKey(pin.hostname, pin.port);
      setConfirming(null);
      toast.success(
        `Forgot the host key for ${address(pin)}. The next connection there pins whatever key it presents.`,
      );
      await load();
    } catch (err) {
      setError(err instanceof Error ? err.message : "The host key could not be forgotten.");
    }
  };

  if (loadFailed) {
    return (
      <p className="hint" role="status" data-testid="other-port-pins-unknown">
        Host keys pinned on other ports could not be loaded.
      </p>
    );
  }
  if (!pins || pins.length === 0) return null;

  return (
    <div className="other-port-pins" data-testid="other-port-pins">
      <span className="host-key-label">
        <Icon name="key" /> {shownPort === null ? "SSH host keys" : "Also pinned on other ports"}
      </span>
      {error && <p role="alert">{error}</p>}
      <ul>
        {pins.map((pin) => (
          <li key={address(pin)} className="host-key-pin">
            <span>port {pin.port}</span>
            <code>
              {pin.keyType} {pin.fingerprint}
            </code>
            {onForgetHostKey &&
              (confirming === address(pin) ? (
                <span className="token-confirm">
                  <button type="button" className="host-key-forget" onClick={() => void forget(pin)}>
                    Forget {address(pin)}
                  </button>
                  <button
                    type="button"
                    className="secondary host-key-forget"
                    onClick={() => setConfirming(null)}
                  >
                    Cancel
                  </button>
                </span>
              ) : (
                <button
                  type="button"
                  className="btn-secondary host-key-forget"
                  onClick={() => setConfirming(address(pin))}
                  aria-label={`Forget host key for ${address(pin)}`}
                >
                  Forget
                </button>
              ))}
          </li>
        ))}
      </ul>
    </div>
  );
}
