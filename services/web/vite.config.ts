import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// The console is served by nginx in production and by Vite in development, and in both
// cases its API calls must be same-origin: `GET /v1/...` with no host, no scheme, and no
// port baked into the bundle. The proxy below is what makes that true during development;
// in production nginx does the same job. Hard-coding an API origin here would mean a
// rebuild for every deployment, and would put the gateway's port into front-end code.
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    host: "127.0.0.1",
    port: 5173,
    proxy: {
      "/v1": {
        target: process.env.AEGIS_GATEWAY_URL ?? "http://127.0.0.1:8100",
        changeOrigin: false,
      },
      "/health": {
        target: process.env.AEGIS_GATEWAY_URL ?? "http://127.0.0.1:8100",
        changeOrigin: false,
      },
    },
  },
});
