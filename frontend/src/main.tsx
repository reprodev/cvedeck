import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import { AuthGate } from "./components/AuthGate";
import { ToastProvider } from "./components/Toast";
import "./index.css";

const rootElement = document.getElementById("root");
if (rootElement) {
  createRoot(rootElement).render(
    <StrictMode>
      <ToastProvider>
        <AuthGate />
      </ToastProvider>
    </StrictMode>,
  );
}
