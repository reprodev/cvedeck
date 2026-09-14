// First-run setup page (Req 16.3).
//
// Shown while no account exists. Creating one needs the setup code the server
// printed to its log, so a stranger who reaches a fresh instance first cannot
// claim it: only someone who can read the host's logs can. The page says where
// the code is, because that is the one step nobody would guess.

import { useState } from "react";
import type { FormEvent } from "react";
import { AuthCard, AuthError } from "../components/AuthCard";
import type { AuthState } from "../types";

/** Mirrors the server's policy (app/auth/passwords.py) for an early hint only. */
export const MIN_PASSWORD_LENGTH = 12;

export interface SetupViewProps {
  onSetup: (setupCode: string, username: string, password: string) => Promise<AuthState>;
  onSignedIn: (state: AuthState) => void;
}

export function SetupView({ onSetup, onSignedIn }: SetupViewProps) {
  const [code, setCode] = useState("");
  const [username, setUsername] = useState("admin");
  const [password, setPassword] = useState("");
  const [confirm, setConfirm] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    if (password !== confirm) {
      setError("The two passwords do not match.");
      return;
    }
    if (password.length < MIN_PASSWORD_LENGTH) {
      setError(`Use at least ${MIN_PASSWORD_LENGTH} characters. A passphrase of a few words works well.`);
      return;
    }
    setBusy(true);
    setError(null);
    try {
      onSignedIn(await onSetup(code, username, password));
    } catch (err) {
      setError(err instanceof Error ? err.message : "Setup failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthCard
      title="Create your account"
      intro={
        <>
          <p>
            This instance has no account yet. To create one, you need the setup
            code CveDeck printed to its log when it started:
          </p>
          <pre className="auth-command">docker logs cvedeck</pre>
          <p className="field-hint">
            Restarting the container prints a new code. To skip this page, set{" "}
            <code>CVEDECK_ADMIN_USERNAME</code> and <code>CVEDECK_ADMIN_PASSWORD</code>.
          </p>
        </>
      }
    >
      <form className="auth-form" onSubmit={submit}>
        <AuthError message={error} />
        <div className="field-group">
          <label htmlFor="setup-code">Setup code</label>
          <input
            id="setup-code"
            name="setup-code"
            autoComplete="one-time-code"
            autoCapitalize="characters"
            spellCheck={false}
            placeholder="XXXX-XXXX-XXXX"
            autoFocus
            required
            value={code}
            onChange={(e) => setCode(e.target.value)}
          />
        </div>
        <div className="field-group">
          <label htmlFor="setup-username">Username</label>
          <input
            id="setup-username"
            name="username"
            autoComplete="username"
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="field-group">
          <label htmlFor="setup-password">Password</label>
          <input
            id="setup-password"
            name="new-password"
            type="password"
            autoComplete="new-password"
            required
            aria-describedby="setup-password-hint"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
          <span id="setup-password-hint" className="field-hint">
            At least {MIN_PASSWORD_LENGTH} characters.
          </span>
        </div>
        <div className="field-group">
          <label htmlFor="setup-confirm">Repeat password</label>
          <input
            id="setup-confirm"
            name="confirm-password"
            type="password"
            autoComplete="new-password"
            required
            value={confirm}
            onChange={(e) => setConfirm(e.target.value)}
          />
        </div>
        <button type="submit" className="btn-primary auth-submit" disabled={busy}>
          {busy ? "Creating…" : "Create account and sign in"}
        </button>
      </form>
    </AuthCard>
  );
}
