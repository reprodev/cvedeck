// Dialog accessibility.
//
// The previous inline implementation put `role="dialog" aria-modal="true"` on
// the backdrop -- which was also the click-to-close target -- and had no Escape
// handler, no focus trap, no initial focus, no accessible name, and no focus
// restoration. A keyboard or screen-reader user who opened it could not get
// out, and Tab wandered into the page behind it.
//
// Exposed as a hook rather than only a component so an existing dialog can be
// made accessible without having its markup and styling restructured.

import {
  useCallback,
  useEffect,
  useId,
  useRef,
  type KeyboardEvent as ReactKeyboardEvent,
  type ReactNode,
  type RefObject,
} from "react";

const FOCUSABLE = [
  "a[href]",
  "button:not([disabled])",
  "input:not([disabled])",
  "select:not([disabled])",
  "textarea:not([disabled])",
  '[tabindex]:not([tabindex="-1"])',
].join(",");

export interface DialogA11y {
  /** Attach to the dialog element (the panel, not the backdrop). */
  dialogRef: RefObject<HTMLDivElement>;
  /** Spread onto the dialog element. */
  dialogProps: {
    role: "dialog";
    "aria-modal": true;
    "aria-labelledby": string;
    tabIndex: -1;
    onKeyDown: (event: ReactKeyboardEvent<HTMLDivElement>) => void;
  };
  /** Put on the element holding the dialog's visible title. */
  titleId: string;
}

/**
 * Wire Escape-to-close, a focus trap, initial focus, and focus restoration.
 *
 * @param onClose Called on Escape.
 */
export function useDialogA11y(onClose: () => void): DialogA11y {
  const dialogRef = useRef<HTMLDivElement>(null!);
  const titleId = useId();
  // Captured on mount so focus returns where it came from when the dialog goes.
  const previouslyFocused = useRef<HTMLElement | null>(null);

  useEffect(() => {
    previouslyFocused.current = document.activeElement as HTMLElement | null;

    const node = dialogRef.current;
    const first = node?.querySelector<HTMLElement>(FOCUSABLE);
    (first ?? node)?.focus();

    return () => {
      // Guarded: the trigger may have unmounted while the dialog was open.
      previouslyFocused.current?.focus?.();
    };
  }, []);

  // Bound to the document rather than the dialog, so Escape still works if
  // focus has somehow escaped the trap.
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.key === "Escape") {
        event.stopPropagation();
        onClose();
      }
    };
    document.addEventListener("keydown", onKeyDown);
    return () => document.removeEventListener("keydown", onKeyDown);
  }, [onClose]);

  const trapFocus = useCallback((event: ReactKeyboardEvent<HTMLDivElement>) => {
    if (event.key !== "Tab") return;
    const node = dialogRef.current;
    if (!node) return;

    const focusable = Array.from(
      node.querySelectorAll<HTMLElement>(FOCUSABLE),
    ).filter(
      (element) => element.offsetParent !== null || element === document.activeElement,
    );
    if (focusable.length === 0) {
      event.preventDefault();
      return;
    }

    const first = focusable[0];
    const last = focusable[focusable.length - 1];
    const active = document.activeElement;

    if (event.shiftKey && (active === first || active === node)) {
      event.preventDefault();
      last.focus();
    } else if (!event.shiftKey && active === last) {
      event.preventDefault();
      first.focus();
    }
  }, []);

  return {
    dialogRef,
    titleId,
    dialogProps: {
      role: "dialog",
      "aria-modal": true,
      "aria-labelledby": titleId,
      tabIndex: -1,
      onKeyDown: trapFocus,
    },
  };
}

export interface ModalProps {
  title: ReactNode;
  onClose: () => void;
  children: ReactNode;
  className?: string;
}

/** A complete accessible dialog, for new call sites. */
export function Modal({ title, onClose, children, className }: ModalProps) {
  const { dialogRef, dialogProps, titleId } = useDialogA11y(onClose);

  return (
    <div className="modal-backdrop" onClick={onClose} role="presentation">
      <div
        ref={dialogRef}
        className={className ? `modal-container ${className}` : "modal-container"}
        {...dialogProps}
        onClick={(event) => event.stopPropagation()}
      >
        <div className="modal-header">
          <h2 id={titleId} className="modal-title">
            {title}
          </h2>
          <button
            type="button"
            className="modal-close-btn"
            onClick={onClose}
            aria-label="Close dialog"
          >
            ✕
          </button>
        </div>
        {children}
      </div>
    </div>
  );
}
