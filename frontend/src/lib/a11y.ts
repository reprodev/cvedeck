// Accessibility helpers for elements that behave as controls but are not
// rendered as <button>.
//
// The fleet view's five metric cards were plain <div>s with onClick and no
// role, tabIndex, or key handler, so they were unreachable by keyboard and
// invisible to assistive technology as controls. The drill-down's equivalents
// had role/tabIndex but handled only Enter, so Space -- which the button
// pattern requires -- did nothing.

import type { KeyboardEvent as ReactKeyboardEvent } from "react";

export interface ToggleButtonProps {
  role: "button";
  tabIndex: 0;
  "aria-pressed": boolean;
  onClick: () => void;
  onKeyDown: (event: ReactKeyboardEvent<HTMLElement>) => void;
}

/**
 * Props making a non-button element behave as a toggle button.
 *
 * Handles both Enter and Space, and calls `preventDefault` on Space so the page
 * does not scroll underneath the activation.
 *
 * @param onActivate Invoked on click, Enter, or Space.
 * @param pressed Current toggle state, exposed as `aria-pressed`.
 */
export function toggleButtonProps(
  onActivate: () => void,
  pressed: boolean,
): ToggleButtonProps {
  return {
    role: "button",
    tabIndex: 0,
    "aria-pressed": pressed,
    onClick: onActivate,
    onKeyDown: (event) => {
      if (event.key === "Enter" || event.key === " " || event.key === "Spacebar") {
        event.preventDefault();
        onActivate();
      }
    },
  };
}

/** Props making a non-button element behave as a plain (non-toggle) button. */
export function clickableProps(onActivate: () => void) {
  const { "aria-pressed": _pressed, ...rest } = toggleButtonProps(onActivate, false);
  return rest;
}
