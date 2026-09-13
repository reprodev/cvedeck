// Tests for the theme preference hook.
//
// Two things get the attention here. First, "system" is a real third state, not
// the absence of a choice: a boolean toggle silently pins the theme the moment
// it is touched, so a laptop that switches to dark at sunset stops following
// along with no way to ask for that back. Second, localStorage genuinely throws
// in some browser configurations, and a theme preference must not be able to
// take the dashboard down with it.

import { act, renderHook } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { themeAffordance, useTheme } from "./useTheme";

const KEY = "cvedeck.theme";

beforeEach(() => {
  window.localStorage.clear();
  document.documentElement.removeAttribute("data-theme");
});

afterEach(() => {
  vi.restoreAllMocks();
});

describe("useTheme", () => {
  it("defaults to following the system", () => {
    const { result } = renderHook(() => useTheme());

    expect(result.current.theme).toBe("system");
  });

  it("leaves data-theme unset while following the system", () => {
    // Removing the attribute is what hands control back to the media query.
    // Setting it to anything at all would pin the theme.
    renderHook(() => useTheme());

    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });

  it("stamps data-theme for an explicit choice", () => {
    const { result } = renderHook(() => useTheme());

    act(() => result.current.setTheme("light"));
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");

    act(() => result.current.setTheme("dark"));
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("clears data-theme when returning to system", () => {
    const { result } = renderHook(() => useTheme());

    act(() => result.current.setTheme("dark"));
    act(() => result.current.setTheme("system"));

    expect(document.documentElement.hasAttribute("data-theme")).toBe(false);
  });

  it("persists the choice", () => {
    const { result } = renderHook(() => useTheme());

    act(() => result.current.setTheme("light"));

    expect(window.localStorage.getItem(KEY)).toBe("light");
  });

  it("restores a persisted choice on mount", () => {
    window.localStorage.setItem(KEY, "dark");

    const { result } = renderHook(() => useTheme());

    expect(result.current.theme).toBe("dark");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("ignores a corrupted stored value", () => {
    window.localStorage.setItem(KEY, "chartreuse");

    const { result } = renderHook(() => useTheme());

    expect(result.current.theme).toBe("system");
  });

  it("cycles system -> light -> dark -> system", () => {
    // The cycle returns to "system" on purpose. A two-state toggle would make
    // "follow the OS" unreachable after the first click, permanently.
    const { result } = renderHook(() => useTheme());

    expect(result.current.theme).toBe("system");
    act(() => result.current.cycleTheme());
    expect(result.current.theme).toBe("light");
    act(() => result.current.cycleTheme());
    expect(result.current.theme).toBe("dark");
    act(() => result.current.cycleTheme());
    expect(result.current.theme).toBe("system");
  });

  it("still applies the theme when localStorage cannot be written", () => {
    // Private windows and blocked-site-data settings throw on write. The
    // preference not surviving a reload is acceptable; a crash is not.
    vi.spyOn(Storage.prototype, "setItem").mockImplementation(() => {
      throw new Error("QuotaExceededError");
    });

    const { result } = renderHook(() => useTheme());

    expect(() => act(() => result.current.setTheme("dark"))).not.toThrow();
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("falls back to system when localStorage cannot be read", () => {
    vi.spyOn(Storage.prototype, "getItem").mockImplementation(() => {
      throw new Error("SecurityError");
    });

    const { result } = renderHook(() => useTheme());

    expect(result.current.theme).toBe("system");
  });
});

describe("themeAffordance", () => {
  it("gives each state a distinct icon and label", () => {
    const states = (["light", "dark", "system"] as const).map(themeAffordance);

    expect(new Set(states.map((s) => s.icon)).size).toBe(3);
    expect(new Set(states.map((s) => s.label)).size).toBe(3);
  });

  it("names the system state as following, not as a colour", () => {
    // The control is icon-only, so this label is the entire accessible name.
    // "Dark theme" would be a lie when the OS is light.
    expect(themeAffordance("system").label).toMatch(/system/i);
  });
});
