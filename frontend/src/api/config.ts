/**
 * Where the API is, resolved at runtime.
 *
 * Two sources, in this order:
 *
 * 1. `window.__AEGIS_CONFIG__.apiBase`, written by `/config.js`. In the container that file is
 *    generated at start-up from `AEGIS_API_BASE`, so **one built image can be pointed at any
 *    gateway** by restarting it with a different environment. This is the reason the API base
 *    is not simply a Vite variable.
 * 2. `import.meta.env.VITE_API_BASE`, baked in at build time. This is what `npm run dev` and
 *    `npm run build` use, and it is the convenience path for local work.
 *
 * An empty result means same origin: requests go to `/v1/...` with no host. That is the right
 * answer when something in front of the app already forwards `/v1`, and the wrong one when
 * nothing does -- which is why the default in this project is a real address rather than "".
 *
 * Trailing slashes are stripped so that `base + "/v1/jobs"` cannot produce `//v1/jobs`, which
 * some proxies treat as a different path.
 */

function clean(value: unknown): string | null {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (trimmed === "") return null;
  return trimmed.replace(/\/+$/, "");
}

export function apiBase(): string {
  const runtime = clean(globalThis.window?.__AEGIS_CONFIG__?.apiBase);
  if (runtime !== null) return runtime;
  return clean(import.meta.env.VITE_API_BASE) ?? "";
}

/** A full URL for an API path. `path` must start with `/`. */
export function apiUrl(path: string): string {
  if (!path.startsWith("/")) {
    throw new Error(`API paths must start with "/": ${path}`);
  }
  return `${apiBase()}${path}`;
}

/** Shown in the UI so a misconfigured deployment is visible rather than mysterious. */
export function apiBaseLabel(): string {
  const base = apiBase();
  return base === "" ? "同源" : base;
}
