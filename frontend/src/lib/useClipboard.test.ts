import { act, renderHook } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { copyText, useClipboard } from "./useClipboard";

const originalClipboard = Object.getOwnPropertyDescriptor(navigator, "clipboard");

function setClipboard(value: unknown) {
  Object.defineProperty(navigator, "clipboard", {
    value,
    configurable: true,
    writable: true,
  });
}

afterEach(() => {
  if (originalClipboard) {
    Object.defineProperty(navigator, "clipboard", originalClipboard);
  } else {
    setClipboard(undefined);
  }
  vi.restoreAllMocks();
});

describe("copyText", () => {
  it("uses the async Clipboard API when it is available", async () => {
    const writeText = vi.fn().mockResolvedValue(undefined);
    setClipboard({ writeText });

    await expect(copyText("sudo apt update")).resolves.toBe(true);
    expect(writeText).toHaveBeenCalledWith("sudo apt update");
  });

  it("falls back to execCommand when the Clipboard API is absent", async () => {
    // navigator.clipboard is undefined in any non-secure context, i.e. every
    // origin except https and localhost -- which is exactly how this tool is
    // reached on a LAN (http://192.168.1.50:8000). The old code checked for the
    // API and silently did nothing when it was missing, so the headline
    // "1-click fix" feature was a no-op for most real deployments.
    setClipboard(undefined);
    const execCommand = vi.fn().mockReturnValue(true);
    document.execCommand = execCommand;

    await expect(copyText("sudo dnf upgrade -y openssl")).resolves.toBe(true);
    expect(execCommand).toHaveBeenCalledWith("copy");
  });

  it("falls back when the Clipboard API rejects", async () => {
    // The API can exist and still reject on a permissions failure. The old
    // code had no .catch(), so this surfaced as an unhandled rejection.
    setClipboard({ writeText: vi.fn().mockRejectedValue(new Error("denied")) });
    const execCommand = vi.fn().mockReturnValue(true);
    document.execCommand = execCommand;

    await expect(copyText("x")).resolves.toBe(true);
    expect(execCommand).toHaveBeenCalled();
  });

  it("reports failure rather than swallowing it", async () => {
    setClipboard(undefined);
    document.execCommand = vi.fn().mockReturnValue(false);

    await expect(copyText("x")).resolves.toBe(false);
  });

  it("does not leave its scratch textarea in the document", async () => {
    setClipboard(undefined);
    document.execCommand = vi.fn().mockReturnValue(true);

    await copyText("x");

    expect(document.querySelectorAll("textarea")).toHaveLength(0);
  });

  it("never throws, whatever the environment does", async () => {
    setClipboard({
      writeText: () => {
        throw new Error("exploded");
      },
    });
    document.execCommand = () => {
      throw new Error("also exploded");
    };

    await expect(copyText("x")).resolves.toBe(false);
  });
});

describe("useClipboard lifecycle", () => {
  it("clears its reset timer on unmount", async () => {
    // Copying a command and then navigating away inside the reset window
    // previously fired setState on an unmounted component. The drill-down's
    // "Back to machines" makes that easy to hit.
    setClipboard({ writeText: vi.fn().mockResolvedValue(undefined) });
    const clearSpy = vi.spyOn(globalThis, "clearTimeout");

    const { result, unmount } = renderHook(() => useClipboard(undefined, 5000));
    await act(async () => {
      await result.current.copy("cmd", "k");
    });
    expect(result.current.copiedKey).toBe("k");

    unmount();

    expect(clearSpy).toHaveBeenCalled();
  });

  it("announces success and failure for assistive technology", async () => {
    setClipboard({ writeText: vi.fn().mockResolvedValue(undefined) });
    const { result } = renderHook(() => useClipboard());

    await act(async () => {
      await result.current.copy("cmd", "k");
    });
    expect(result.current.announcement).toMatch(/copied/i);

    setClipboard(undefined);
    document.execCommand = vi.fn().mockReturnValue(false);
    await act(async () => {
      await result.current.copy("cmd", "k2");
    });
    expect(result.current.announcement).toMatch(/failed/i);
  });
});
