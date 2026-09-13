import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

/**
 * There is deliberately **no proxy** here.
 *
 * An earlier console proxied `/v1` through its own origin in both dev and production, which
 * meant the browser never had to be told where the API was -- and also meant the static bundle
 * could only ever be served from behind that proxy. The API host was unrepresentable in the
 * build, so a CDN copy or a second deployment pointing at a different gateway was impossible.
 *
 * This project instead resolves its API base at runtime (`src/api/config.ts`), so the same
 * built assets work against any gateway. Development reads `VITE_API_BASE` from
 * `.env.development` (see `.env.example`); production reads `/config.js`, which the container
 * writes at start-up from `AEGIS_API_BASE`. The request then goes straight to the gateway and
 * is a cross-origin request, which is why the gateway allows it -- see `CORSConfig`.
 */
export default defineConfig({
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    sourcemap: false,
  },
  server: {
    host: "127.0.0.1",
    port: 5174,
  },
  preview: {
    host: "127.0.0.1",
    port: 4174,
  },
});
