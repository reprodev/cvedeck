// Theme selection: dark, light, or follow the operating system.
//
// The CSS in index.css defines dark on bare `:root`, light under a guarded
// `prefers-color-scheme: light` query, and light again under
// `:root[data-theme="light"]`. This hook only sets or clears the `data-theme`
// attribute; all the colour work lives in CSS.
//
// Three states rather than a boolean, because "follow the OS" is a real choice
// and not the same as either fixed value. A boolean toggle silently pins the
// theme the first time it is touched, so a laptop that switches to dark at
// sunset stops following along and the user has no way to ask for that back.

import { useCallback, useEffect, useState } from "react";
import type { IconName } from "../components/Icon";

export type Theme = "light" | "dark" | "system";

const STORAGE_KEY = "cvedeck.theme";

function isTheme(value: unknown): value is Theme {
  return value === "light" || value === "dark" || value === "system";
}

/**
 * Read the stored preference, defaulting to "system".
 *
 * Wrapped in try/catch because localStorage throws outright in some contexts --
 * a browser configured to block site data, or a privacy mode that reports the
 * API as present and then refuses access. A theme preference is not worth
 * taking the whole dashboard down for.
 */
function readStoredTheme(): Theme {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    return isTheme(raw) ? raw : "system";
  } catch {
    return "system";
  }
}

function applyTheme(theme: Theme): void {
  const root = document.documentElement;
  if (theme === "system") {
    // Removing the attribute hands control back to the media query, which is
    // what "follow the OS" means. Setting data-theme to anything would pin it.
    root.removeAttribute("data-theme");
  } else {
    root.setAttribute("data-theme", theme);
  }
}

/**
 * Current theme preference plus a setter that persists and applies it.
 *
 * Returns the raw preference, not the resolved appearance: a caller rendering
 * the control needs to know the user chose "system", not merely that the result
 * currently looks dark.
 */
export function useTheme(): {
  theme: Theme;
  setTheme: (next: Theme) => void;
  cycleTheme: () => void;
} {
  const [theme, setThemeState] = useState<Theme>(readStoredTheme);

  useEffect(() => {
    applyTheme(theme);
  }, [theme]);

  const setTheme = useCallback((next: Theme) => {
    setThemeState(next);
    try {
      window.localStorage.setItem(STORAGE_KEY, next);
    } catch {
      // Preference does not survive the reload; the theme still applies now.
    }
  }, []);

  // system -> light -> dark -> system. Keeps the control a single button
  // rather than a menu, and makes "follow the OS" reachable again after
  // someone has pinned a value.
  const cycleTheme = useCallback(() => {
    setTheme(theme === "system" ? "light" : theme === "light" ? "dark" : "system");
  }, [theme, setTheme]);

  return { theme, setTheme, cycleTheme };
}

/** Icon name and label for a theme, for rendering the control.
 *
 * Returns an icon *name* rather than a glyph: the caller renders it through
 * <Icon>, so the affordance stays a plain data function with no JSX, and the
 * control gets an icon that themes and scales with everything else. These were
 * emoji, which rendered as three different drawings on three operating systems
 * and could not respond to the theme they were toggling. */
export function themeAffordance(theme: Theme): { icon: IconName; label: string } {
  if (theme === "light") return { icon: "sun", label: "Light theme" };
  if (theme === "dark") return { icon: "moon", label: "Dark theme" };
  return { icon: "monitor", label: "Theme follows your system" };
}
