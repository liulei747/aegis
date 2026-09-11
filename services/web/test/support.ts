/**
 * Test support: read the API's real route table and fetch a real bundle fixture.
 *
 * The route table comes from `python -m app.cli routes`, which asks the FastAPI application
 * itself. Grepping the route decorators, or keeping a list here, would both keep passing
 * after a route is renamed -- and this test exists precisely to catch that.
 */

import { execFileSync } from "node:child_process";
import { existsSync, readdirSync, readFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), "..", "..", "..");

/** Every path the gateway serves, straight from the application. */
export function apiPaths(): string[] {
  const raw = execFileSync("python", ["-m", "app.cli", "routes"], {
    cwd: REPO_ROOT,
    encoding: "utf8",
    stdio: ["ignore", "pipe", "pipe"],
  });
  return (JSON.parse(raw) as { paths: string[] }).paths;
}

/** Every `.ts`/`.tsx` file under `src`, as absolute paths. */
export function sourceFiles(dir: string = join(REPO_ROOT, "services", "web", "src")): string[] {
  const found: string[] = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) found.push(...sourceFiles(full));
    else if (entry.name.endsWith(".ts") || entry.name.endsWith(".tsx")) found.push(full);
  }
  return found;
}

export function readSource(path: string): string {
  return readFileSync(path, "utf8");
}

/**
 * The newest finished bundle on disk, or null.
 *
 * A real bundle rather than a hand-written fixture on purpose: the render checks below must
 * run against the shapes `views.py` actually produces, and a fixture capture goes stale the
 * first time the API gains a field.
 */
export function newestBundle(): string | null {
  const packages = join(REPO_ROOT, "var", "packages");
  if (!existsSync(packages)) return null;
  const candidates = readdirSync(packages, { withFileTypes: true })
    .filter((entry) => entry.isDirectory() && entry.name.startsWith("B-"))
    .map((entry) => join(packages, entry.name))
    .filter((dir) => existsSync(join(dir, "manifest.json")));
  if (candidates.length === 0) return null;
  return candidates.sort().at(-1) ?? null;
}

export function bundleManifest(dir: string): unknown {
  return JSON.parse(readFileSync(join(dir, "manifest.json"), "utf8"));
}
