// Copy-to-clipboard with a fallback that actually works on a LAN (Req 14.4).
//
// The previous implementation guarded with `if (navigator.clipboard)` and did
// nothing at all when it was absent -- no error, no fallback, no message.
// `navigator.clipboard` is undefined in any non-secure context, which means
// every origin except HTTPS and localhost. That is exactly how this tool gets
// used: `http://192.168.1.50:8000`. So the headline "1-click fix" feature was a
// silent no-op for most real deployments, and the promise had no `.catch()`
// either, so a rejected write surfaced as an unhandled rejection.
//
// This hook tries the async API, falls back to `document.execCommand("copy")`,
// and reports success or failure rather than swallowing it -- including in the
// non-secure contexts where the asynchronous clipboard API does not exist
// (Req 14.4).

import { useCallback, useEffect, useRef, useState } from "react";

/** Copy via a temporary textarea. Deprecated, but works in non-secure contexts. */
function copyViaExecCommand(text: string): boolean {
  if (typeof document === "undefined") return false;

  const textarea = document.createElement("textarea");
  textarea.value = text;
  // Keep it off-screen and non-disruptive: `display: none` would make the
  // selection fail, so position it out of view instead.
  textarea.setAttribute("readonly", "");
  textarea.style.position = "fixed";
  textarea.style.top = "-1000px";
  textarea.style.left = "-1000px";
  textarea.style.opacity = "0";

  const selection = document.getSelection();
  const previousRange =
    selection && selection.rangeCount > 0 ? selection.getRangeAt(0) : null;

  document.body.appendChild(textarea);
  try {
    textarea.select();
    textarea.setSelectionRange(0, textarea.value.length);
    return document.execCommand("copy");
  } catch {
    return false;
  } finally {
    document.body.removeChild(textarea);
    // Restore whatever the user had selected before we hijacked it.
    if (previousRange && selection) {
      selection.removeAllRanges();
      selection.addRange(previousRange);
    }
  }
}

/** Copy `text`, resolving to whether it succeeded. Never throws. */
export async function copyText(text: string): Promise<boolean> {
  if (typeof navigator !== "undefined" && navigator.clipboard?.writeText) {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      // Permission denied, or a non-secure context that still exposes the API.
      // Fall through to the legacy path rather than giving up.
    }
  }
  return copyViaExecCommand(text);
}

export interface ClipboardApi {
  /** Key of the most recently copied item, for rendering a confirmation. */
  copiedKey: string | null;
  /** Copy `text`, marking `key` as copied. Resolves to whether it worked. */
  copy: (text: string, key: string) => Promise<boolean>;
  /**
   * Live-region text announcing the outcome. Render this in an element with
   * `aria-live="polite"`: the visual confirmation is a checkmark swap that a
   * screen reader would otherwise never report.
   */
  announcement: string;
}

/**
 * Clipboard state for a component.
 *
 * @param onError Called with a message when a copy fails, so the caller can
 *   surface it (a toast). Silence on failure is what made the original bug
 *   invisible.
 */
export function useClipboard(
  onError?: (message: string) => void,
  resetMs = 2000,
): ClipboardApi {
  const [copiedKey, setCopiedKey] = useState<string | null>(null);
  const [announcement, setAnnouncement] = useState("");
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Clear the pending reset on unmount. Copying a command and then navigating
  // away inside the reset window would otherwise fire setState on an unmounted
  // component -- which the drill-down's "Back to machines" makes easy to do.
  useEffect(
    () => () => {
      if (timer.current) clearTimeout(timer.current);
    },
    [],
  );

  const copy = useCallback(
    async (text: string, key: string) => {
      const ok = await copyText(text);

      if (!ok) {
        setAnnouncement("Copy failed. Select the command and copy it manually.");
        onError?.(
          "Could not copy to the clipboard. Browsers block clipboard access " +
            "on insecure (http://) origins -- select the command and copy it manually.",
        );
        return false;
      }

      setCopiedKey(key);
      setAnnouncement("Command copied to the clipboard.");
      if (timer.current) clearTimeout(timer.current);
      timer.current = setTimeout(() => {
        setCopiedKey(null);
        setAnnouncement("");
      }, resetMs);
      return true;
    },
    [onError, resetMs],
  );

  return { copiedKey, copy, announcement };
}
