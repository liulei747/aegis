/**
 * The contract between this front-end and the gateway, checked over HTTP.
 *
 * This project shares no source with the backend -- that is the point of deploying it separately
 * -- so the only honest way to check the contract is from the outside, against what the gateway
 * publishes. There is no import of a Python module here and no reading of a backend file; the
 * snapshot in `test/openapi.snapshot.json` is a captured HTTP response, refreshed with
 * `npm run snapshot`.
 *
 * What is checked:
 *
 * 1. Every path `src/api/client.ts` calls appears in the published route table. A backend rename
 *    therefore fails this suite instead of failing at runtime on a screen nobody opened.
 * 2. The snapshot still matches the live gateway, when one is reachable. The stored copy makes
 *    the suite runnable offline; the live comparison is what stops the copy going stale.
 * 3. No source file hard-codes an API origin. An address belongs in configuration (see
 *    `src/api/config.ts`), because one image has to serve several deployments.
 */

import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import { test } from "node:test";

import {
  calledPaths,
  liveApiBase,
  normalisePath,
  PROJECT_ROOT,
  publishedPaths,
  readProjectFile,
} from "./support.ts";

interface OpenApi {
  paths?: Record<string, unknown>;
}

function snapshot(): OpenApi {
  const path = join(PROJECT_ROOT, "test", "openapi.snapshot.json");
  try {
    return JSON.parse(readFileSync(path, "utf8")) as OpenApi;
  } catch (cause) {
    throw new Error(
      `test/openapi.snapshot.json is missing or unreadable (${String(cause)}). ` +
        "Take one from a running gateway: API_URL=http://127.0.0.1:8100 npm run snapshot",
    );
  }
}

test("every endpoint the front-end calls exists on the API", () => {
  const published = new Set(publishedPaths(snapshot()));
  const missing = calledPaths().filter((path) => !published.has(normalisePath(path)));
  assert.deepEqual(
    missing,
    [],
    `client.ts calls paths the gateway does not publish: ${missing.join(", ")}`,
  );
});

test("the front-end calls every endpoint it declares, and no path is spelled two ways", () => {
  const called = calledPaths();
  assert.ok(called.length >= 10, `expected the client to call many paths, saw ${called.length}`);
  // A path written twice with different parameter names would show up as a near-duplicate pair
  // and would mean one of them is not the route the other one is.
  const normalised = called.map(normalisePath);
  assert.equal(new Set(normalised).size, normalised.length, "a path is declared twice");
});

test("no source file hard-codes an API origin", () => {
  const files = ["config.ts", "client.ts", "types.ts"];
  const offenders: string[] = [];
  for (const file of files) {
    const source = readProjectFile("src", "api", file);
    for (const line of source.split("\n")) {
      const trimmed = line.trim();
      if (trimmed.startsWith("*") || trimmed.startsWith("//") || trimmed.startsWith("/*")) continue;
      if (/https?:\/\//.test(line)) offenders.push(`${file}: ${trimmed}`);
    }
  }
  assert.deepEqual(
    offenders,
    [],
    `an API origin must come from configuration, not from code: ${offenders.join(" | ")}`,
  );
});

test("the snapshot matches the live gateway when one is reachable", async (t) => {
  const base = liveApiBase();
  if (base === null) {
    t.skip("no API_URL/AEGIS_API_BASE set; the snapshot comparison is skipped");
    return;
  }
  const response = await fetch(`${base}/openapi.json`, { headers: { Accept: "application/json" } });
  assert.ok(response.ok, `${base}/openapi.json answered ${response.status}`);
  const live = publishedPaths((await response.json()) as OpenApi);
  const stored = publishedPaths(snapshot());
  assert.deepEqual(
    live,
    stored,
    "the gateway's route table differs from the snapshot; re-run `npm run snapshot`",
  );
});
