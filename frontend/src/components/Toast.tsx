// A single notification surface.
//
// Four unrelated error UIs existed before this: App's banner (with no dismiss),
// DiscoveryView's red card, ScanFormView's test-result box, and a native
// blocking `alert()` for validation. They looked different, behaved
// differently, and one of them could not be dismissed at all.
//
// Toasts are announced through an aria-live region so screen-reader users learn
// about failures and copy confirmations that are otherwise purely visual.

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from "react";

export type ToastTone = "success" | "error" | "warning" | "info";

export interface Toast {
  id: number;
  tone: ToastTone;
  message: string;
  /** Milliseconds before auto-dismiss; 0 pins the toast until dismissed. */
  durationMs: number;
}

interface ToastApi {
  notify: (message: string, tone?: ToastTone, durationMs?: number) => number;
  success: (message: string) => number;
  error: (message: string) => number;
  warning: (message: string) => number;
  dismiss: (id: number) => void;
}

const ToastContext = createContext<ToastApi | null>(null);

/** Errors are pinned: a failure the user never saw is a failure they cannot act on. */
const DEFAULT_DURATIONS: Record<ToastTone, number> = {
  success: 3000,
  info: 4000,
  warning: 8000,
  error: 0,
};

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const nextId = useRef(1);
  const timers = useRef(new Map<number, ReturnType<typeof setTimeout>>());

  const dismiss = useCallback((id: number) => {
    const timer = timers.current.get(id);
    if (timer) {
      clearTimeout(timer);
      timers.current.delete(id);
    }
    setToasts((current) => current.filter((toast) => toast.id !== id));
  }, []);

  const notify = useCallback(
    (message: string, tone: ToastTone = "info", durationMs?: number) => {
      const id = nextId.current++;
      const duration = durationMs ?? DEFAULT_DURATIONS[tone];
      setToasts((current) => [...current, { id, tone, message, durationMs: duration }]);
      if (duration > 0) {
        timers.current.set(
          id,
          setTimeout(() => dismiss(id), duration),
        );
      }
      return id;
    },
    [dismiss],
  );

  // Clear pending timers on unmount so a dismissed provider cannot set state.
  useEffect(() => {
    const pending = timers.current;
    return () => {
      pending.forEach((timer) => clearTimeout(timer));
      pending.clear();
    };
  }, []);

  const api = useMemo<ToastApi>(
    () => ({
      notify,
      dismiss,
      success: (message: string) => notify(message, "success"),
      error: (message: string) => notify(message, "error"),
      warning: (message: string) => notify(message, "warning"),
    }),
    [notify, dismiss],
  );

  return (
    <ToastContext.Provider value={api}>
      {children}
      <div className="toast-region" aria-live="polite" aria-atomic="false">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.tone}`} role="status">
            <span className="toast-message">{toast.message}</span>
            <button
              type="button"
              className="toast-dismiss"
              onClick={() => dismiss(toast.id)}
              aria-label="Dismiss notification"
            >
              ×
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

/**
 * Access the toast API.
 *
 * Returns a no-op implementation when no provider is mounted so a component
 * under test does not have to be wrapped just to render.
 */
export function useToast(): ToastApi {
  const context = useContext(ToastContext);
  return context ?? NOOP_TOAST_API;
}

const NOOP_TOAST_API: ToastApi = {
  notify: () => 0,
  success: () => 0,
  error: () => 0,
  warning: () => 0,
  dismiss: () => undefined,
};
