// Sign-in page (Req 16.2, 16.8).
//
// A real <form> with the autocomplete names password managers look for, so a
// saved password fills in and a new one is offered for saving. The server's own
// message is shown for a failure -- including how long to wait after too many
// attempts -- rather than a generic "sign-in failed".

import { useState } from "react";
import type { FormEvent } from "react";
import { AuthCard, AuthError } from "../components/AuthCard";
import type { AuthState } from "../types";

export interface LoginViewProps {
  onLogin: (username: string, password: string) => Promise<AuthState>;
  onSignedIn: (state: AuthState) => void;
}

export function LoginView({ onLogin, onSignedIn }: LoginViewProps) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setError(null);
    try {
      onSignedIn(await onLogin(username, password));
    } catch (err) {
      setPassword("");
      setError(err instanceof Error ? err.message : "Sign-in failed.");
    } finally {
      setBusy(false);
    }
  };

  return (
    <AuthCard title="Sign in">
      <form className="auth-form" onSubmit={submit}>
        <AuthError message={error} />
        <div className="field-group">
          <label htmlFor="login-username">Username</label>
          <input
            id="login-username"
            name="username"
            autoComplete="username"
            autoFocus
            required
            value={username}
            onChange={(e) => setUsername(e.target.value)}
          />
        </div>
        <div className="field-group">
          <label htmlFor="login-password">Password</label>
          <input
            id="login-password"
            name="password"
            type="password"
            autoComplete="current-password"
            required
            value={password}
            onChange={(e) => setPassword(e.target.value)}
          />
        </div>
        <button type="submit" className="btn-primary auth-submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
        <p className="field-hint">
          Forgotten the password? Reset it from the host with{" "}
          <code>cvedeck-admin reset-password</code>.
        </p>
      </form>
    </AuthCard>
  );
}
