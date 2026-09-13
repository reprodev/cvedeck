// Navigation state in the URL, so screens can be linked, bookmarked, and
// reached with the browser's back button.
//
// Until now every screen in the dashboard lived at `/`. No URL identified a
// host, browser back did nothing, and a refresh dropped you at the fleet list.
// Sharing "look at this host" meant describing where to click.
//
// **Hash routing, deliberately, not the History API.** The dashboard is served
// by FastAPI's StaticFiles mount and is routinely put behind whatever reverse
// proxy a self-hoster already runs. A path like `/machines/web-01` would 404 on
// refresh unless every one of those deployments is configured with an SPA
// fallback -- a support burden paid by users, to buy a prettier URL. A fragment
// never reaches the server, so it works everywhere with no configuration and
// cannot break behind an unusual proxy.
//
// No router library: this is two routes and a parameter.

import { useCallback, useEffect, useState } from "react";

/** Which top-level workspace is showing. */
export type Workspace = "fleet" | "scan" | "discovery";

export interface Route {
  workspace: Workspace;
  /** Machine whose drill-down is open, or null for the workspace itself. */
  machineId: string | null;
}

export const DEFAULT_ROUTE: Route = { workspace: "fleet", machineId: null };

const WORKSPACES: readonly Workspace[] = ["fleet", "scan", "discovery"];

function isWorkspace(value: string): value is Workspace {
  return (WORKSPACES as readonly string[]).includes(value);
}

/**
 * Parse a location hash into a route.
 *
 * Unrecognised input falls back to the default rather than throwing or
 * rendering nothing: a hand-edited or truncated URL should land somewhere
 * useful, not on an error.
 */
export function parseHash(hash: string): Route {
  const path = hash.replace(/^#\/?/, "").trim();
  if (!path) return DEFAULT_ROUTE;

  const [head, ...rest] = path.split("/");

  if (head === "machines" && rest.length > 0) {
    // Machine ids are hostnames or IPs and can contain characters that must be
    // escaped in a fragment, so they travel encoded. decodeURIComponent throws
    // on a malformed escape ("%E0%A4%A"), which a truncated or hand-edited
    // shared link produces easily -- and an exception here would take down the
    // whole app rather than landing on the fleet list.
    let machineId: string;
    try {
      machineId = decodeURIComponent(rest.join("/"));
    } catch {
      machineId = rest.join("/");
    }
    return machineId
      ? { workspace: "fleet", machineId }
      : DEFAULT_ROUTE;
  }

  if (isWorkspace(head)) {
    return { workspace: head, machineId: null };
  }

  return DEFAULT_ROUTE;
}

/** Serialize a route back into a location hash. */
export function formatHash(route: Route): string {
  if (route.machineId) {
    return `#/machines/${encodeURIComponent(route.machineId)}`;
  }
  return `#/${route.workspace}`;
}

/**
 * The current route, plus a setter that writes it to the URL.
 *
 * `navigate` pushes a new history entry so back returns to the previous screen;
 * `replace` swaps the current one, for corrections that should not become a
 * step a user has to press back through (such as normalising an unparseable
 * hash on first load).
 */
export function useUrlState(): {
  route: Route;
  navigate: (next: Route) => void;
  replace: (next: Route) => void;
} {
  const [route, setRoute] = useState<Route>(() =>
    parseHash(typeof window === "undefined" ? "" : window.location.hash),
  );

  // Both events: back/forward over a pushState entry fires popstate, while a
  // hash typed or pasted into the address bar fires hashchange. Listening to
  // one only would miss half of how people actually navigate.
  useEffect(() => {
    const sync = () => setRoute(parseHash(window.location.hash));
    window.addEventListener("popstate", sync);
    window.addEventListener("hashchange", sync);
    return () => {
      window.removeEventListener("popstate", sync);
      window.removeEventListener("hashchange", sync);
    };
  }, []);

  const write = useCallback((next: Route, mode: "push" | "replace") => {
    const hash = formatHash(next);
    if (window.location.hash === hash) {
      // Guard against pushing a duplicate entry, which would make back appear
      // to do nothing for one press.
      setRoute(next);
      return;
    }
    // State is set here rather than left to the listener. Assigning
    // location.hash fires hashchange asynchronously in a browser and never in
    // jsdom, so relying on it means the UI lags a frame behind the click in
    // production and does not update at all under test.
    if (mode === "replace") {
      window.history.replaceState(null, "", hash);
    } else {
      window.history.pushState(null, "", hash);
    }
    setRoute(next);
  }, []);

  const navigate = useCallback((next: Route) => write(next, "push"), [write]);
  const replace = useCallback((next: Route) => write(next, "replace"), [write]);

  return { route, navigate, replace };
}
