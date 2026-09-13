/// <reference types="vitest/config" />
import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// https://vitejs.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    proxy: {
      // Proxy API calls to the FastAPI backend during development. Override
      // VITE_PROXY_TARGET when the backend is not on localhost (e.g. running
      // the dev server against a container). Dev only -- the production build
      // calls /api on whatever origin serves it.
      "/api": {
        target: process.env.VITE_PROXY_TARGET ?? "http://localhost:8000",
        changeOrigin: true,
      },
    },
  },
  test: {
    globals: true,
    environment: "jsdom",
    setupFiles: "./src/test/setup.ts",
    css: false,
    // Vitest defaults to 5s. userEvent simulates real typing with a delay per
    // keystroke, so the form tests legitimately take one to two seconds each,
    // and with 21 files running in parallel a loaded machine tips the slowest
    // of them over the default. That surfaced as an intermittent failure in
    // ScanFormView -- a test nobody had touched -- which is the worst kind:
    // it trains people to re-run rather than to look.
    testTimeout: 20_000,
  },
});
