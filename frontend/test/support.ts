/**
 * Shared helpers for the tests. No React, no fetch, no filesystem side effects.
 */

import { readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

export const TEST_DIR = dirname(fileURLToPath(import.meta.url));
export const PROJECT_ROOT = join(TEST_DIR, "..");

export function readProjectFile(...parts: string[]): string {
  return readFileSync(join(PROJECT_ROOT, ...parts), "utf8");
}

/**
 * Every API path `src/api/client.ts` calls, in its template form.
 *
 * The client is the only file allowed to name a path, and each path is written in one piece so
 * this regex can see it: a route that ends in `${...}` is how a path parameter is expressed.
 * Query strings are stripped because the route table describes paths, not queries.
 */
export function calledPaths(): string[] {
  const source = readProjectFile("src", "api", "client.ts");
  const found = new Set<string>();
  const pattern = /["'`](\/(?:v1|health)[^"'`]*)["'`]/g;
  for (const match of source.matchAll(pattern)) {
    const raw = match[1];
    if (raw === undefined) continue;
    const withoutQuery = raw.split("?")[0] ?? raw;
    // A path parameter is whatever the expression produced; the table calls it `{name}`.
    found.add(withoutQuery.replace(/\$\{[^}]*\}/g, "{param}"));
  }
  return [...found].sort();
}

/** `/v1/jobs/{param}` -> `/v1/jobs/{}`, so a renamed parameter is not a contract change. */
export function normalisePath(path: string): string {
  return path.replace(/\{[^}]*\}/g, "{}");
}

/** The paths the gateway published, normalised the same way. */
export function publishedPaths(document: { paths?: Record<string, unknown> }): string[] {
  return Object.keys(document.paths ?? {}).map(normalisePath).sort();
}

/** Where the API is, for the optional live check. Absent means "do not call anything". */
export function liveApiBase(): string | null {
  const value = process.env.AEGIS_API_BASE ?? process.env.API_URL ?? process.env.VITE_API_BASE;
  if (!value || value.trim() === "") return null;
  return value.trim().replace(/\/+$/, "");
}
