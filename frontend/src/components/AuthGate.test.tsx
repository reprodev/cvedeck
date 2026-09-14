// AuthGate: what shows before the dashboard, and what happens when a session
// ends (Req 16.3, 16.5, 16.11).

import { beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { AuthGate } from "./AuthGate";
import { ToastProvider } from "./Toast";

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

type Handler = (path: string, init?: RequestInit) => Response | undefined;

/** A fetch stub with the dashboard's background reads answered, plus overrides. */
function stubFetch(auth: { state: string; username?: string | null }, handler?: Handler) {
  return vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const path = (typeof input === "string" ? input : input.toString()).split("?")[0];
    const handled = handler?.(path, init);
    if (handled) return handled;
    if (path === "/api/auth/state") return json(auth);
    if (path === "/api/machines") return json([]);
    if (path === "/api/feeds") return json([]);
    if (path === "/api/health")
      return json({ status: "ok", version: "0.7.0", capabilities: { login_required: true } });
    return json({ detail: `unexpected ${path}` }, 404);
  });
}

function renderGate(fetchImpl: typeof fetch) {
  return render(
    <ToastProvider>
      <AuthGate fetchImpl={fetchImpl} />
    </ToastProvider>,
  );
}

describe("AuthGate", () => {
  beforeEach(() => {
    window.location.hash = "";
  });

  it("shows the setup page when no account exists, and says where the code is", async () => {
    renderGate(stubFetch({ state: "setup_required" }));

    expect(await screen.findByRole("heading", { name: "Create your account" })).toBeInTheDocument();
    expect(screen.getByLabelText("Setup code")).toBeInTheDocument();
    expect(screen.getByText("docker logs cvedeck")).toBeInTheDocument();
  });

  it("shows the sign-in page when signed out", async () => {
    renderGate(stubFetch({ state: "signed_out" }));

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.queryByText("Fleet Overview")).not.toBeInTheDocument();
  });

  it("shows the dashboard with the account controls when signed in", async () => {
    renderGate(stubFetch({ state: "signed_in", username: "admin" }));

    expect(await screen.findByRole("navigation", { name: "Account" })).toBeInTheDocument();
    expect(screen.getByText("admin")).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /Sign out/ })).toBeInTheDocument();
  });

  it("shows the dashboard without account controls when login is not required", async () => {
    renderGate(stubFetch({ state: "open" }));

    expect(await screen.findByRole("button", { name: /Fleet Overview/ })).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "Account" })).not.toBeInTheDocument();
  });

  it("signs in and then shows the dashboard", async () => {
    const user = userEvent.setup();
    let signedIn = false;
    const fetchImpl = stubFetch({ state: "signed_out" }, (path, init) => {
      if (path === "/api/auth/login" && init?.method === "POST") {
        const body = JSON.parse(String(init.body));
        if (body.username === "admin" && body.password === "correct horse battery") {
          signedIn = true;
          return json({ state: "signed_in", username: "admin" });
        }
        return json({ detail: "Incorrect username or password." }, 401);
      }
      return undefined;
    });
    renderGate(fetchImpl);

    await user.type(await screen.findByLabelText("Username"), "admin");
    await user.type(screen.getByLabelText("Password"), "correct horse battery");
    await user.click(screen.getByRole("button", { name: "Sign in" }));

    expect(await screen.findByRole("navigation", { name: "Account" })).toBeInTheDocument();
    expect(signedIn).toBe(true);
  });

  it("returns to the sign-in page with one message when the session expires mid-use", async () => {
    let expired = false;
    const fetchImpl = stubFetch({ state: "signed_in", username: "admin" }, (path) =>
      expired && path === "/api/auth/tokens"
        ? json({ detail: "Sign in to use CveDeck." }, 401)
        : undefined,
    );
    const user = userEvent.setup();
    renderGate(fetchImpl);
    await screen.findByRole("navigation", { name: "Account" });

    expired = true;
    await user.click(screen.getByRole("button", { name: /Settings/ }));

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(screen.getAllByText(/session has ended/i)).toHaveLength(1);
  });

  it("signs out and shows the sign-in page", async () => {
    const user = userEvent.setup();
    const fetchImpl = stubFetch({ state: "signed_in", username: "admin" }, (path, init) =>
      path === "/api/auth/logout" && init?.method === "POST"
        ? new Response(null, { status: 204 })
        : undefined,
    );
    renderGate(fetchImpl);

    await user.click(await screen.findByRole("button", { name: /Sign out/ }));

    expect(await screen.findByRole("heading", { name: "Sign in" })).toBeInTheDocument();
    expect(fetchImpl).toHaveBeenCalledWith(
      "/api/auth/logout",
      expect.objectContaining({ method: "POST", credentials: "include" }),
    );
  });

  it("offers a retry when the server cannot be reached", async () => {
    const fetchImpl = vi.fn(async () => {
      throw new TypeError("Failed to fetch");
    });
    renderGate(fetchImpl as unknown as typeof fetch);

    expect(await screen.findByRole("alert")).toHaveTextContent("Failed to fetch");
    expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument();
  });
});
