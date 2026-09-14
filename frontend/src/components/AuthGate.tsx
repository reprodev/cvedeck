// Decides what to render before the dashboard exists (Req 16.3, 16.5).
//
// Asks the server for the auth state once, then shows the setup page, the
// sign-in page, or the app. The API client it creates reports every 401, so a
// session that expires mid-use returns to the sign-in page with one message
// instead of leaving each panel to fail on its own.

import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { App } from "../App";
import { CveScannerApiClient } from "../api/client";
import type { AuthState } from "../types";
import { LoginView } from "../views/LoginView";
import { SetupView } from "../views/SetupView";
import { useToast } from "./Toast";

export interface AuthGateProps {
  /** Injectable fetch, for tests. */
  fetchImpl?: typeof fetch;
}

export function AuthGate({ fetchImpl }: AuthGateProps = {}) {
  const toast = useToast();
  const [auth, setAuth] = useState<AuthState | null>(null);
  const [loadError, setLoadError] = useState<string | null>(null);

  // The client outlives state changes, so the 401 handler reads current state
  // through a ref rather than capturing a stale one.
  const authRef = useRef<AuthState | null>(null);
  authRef.current = auth;
  const toastRef = useRef(toast);
  toastRef.current = toast;

  const api = useMemo(
    () =>
      new CveScannerApiClient({
        fetchImpl,
        onUnauthorized: () => {
          if (authRef.current?.state !== "signed_in") return;
          setAuth({ state: "signed_out", username: null });
          toastRef.current.warning("Your session has ended. Sign in again to continue.");
        },
      }),
    [fetchImpl],
  );

  const load = useCallback(() => {
    setLoadError(null);
    api
      .getAuthState()
      .then(setAuth)
      .catch((err: unknown) => {
        setLoadError(
          err instanceof Error ? err.message : "The CveDeck server could not be reached.",
        );
      });
  }, [api]);

  useEffect(load, [load]);

  const signOut = useCallback(async () => {
    try {
      await api.logout();
    } catch {
      // Signing out locally is still right if the request failed: the cookie
      // is HttpOnly, so the page cannot clear it, but it can stop using it.
    }
    setAuth({ state: "signed_out", username: null });
  }, [api]);

  if (loadError) {
    return (
      <main className="auth-shell">
        <section className="auth-card card">
          <p role="alert" className="error-banner">
            {loadError}
          </p>
          <button type="button" onClick={load}>
            Try again
          </button>
        </section>
      </main>
    );
  }

  if (auth === null) {
    return (
      <main className="auth-shell" aria-busy="true">
        <p className="hint">Loading…</p>
      </main>
    );
  }

  if (auth.state === "setup_required") {
    return (
      <SetupView
        onSetup={(code, username, password) => api.completeSetup(code, username, password)}
        onSignedIn={setAuth}
      />
    );
  }

  if (auth.state === "signed_out") {
    return (
      <LoginView
        onLogin={(username, password) => api.login(username, password)}
        onSignedIn={setAuth}
      />
    );
  }

  return (
    <App
      client={api}
      account={auth.state === "signed_in" && auth.username ? { username: auth.username } : null}
      onSignOut={signOut}
    />
  );
}
