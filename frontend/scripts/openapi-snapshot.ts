/**
 * Fetch the gateway's OpenAPI document and store it beside the tests.
 *
 * The stored copy is *data*, not backend source: it is what the gateway published, captured at
 * a moment. `test/contract.test.ts` checks the front-end against it so the suite can run with no
 * backend, and compares it against the live document when one is reachable so drift is caught.
 *
 * Usage: API_URL=http://127.0.0.1:8100 npm run snapshot
 */

import { writeFileSync } from "node:fs";
import { join } from "node:path";

import { liveApiBase, PROJECT_ROOT } from "../test/support.ts";

const base = liveApiBase();
if (base === null) {
  console.error("Set API_URL (or AEGIS_API_BASE) to the gateway before taking a snapshot.");
  process.exit(1);
}

const response = await fetch(`${base}/openapi.json`, { headers: { Accept: "application/json" } });
if (!response.ok) {
  console.error(`${base}/openapi.json answered ${response.status}`);
  process.exit(1);
}

const document = (await response.json()) as Record<string, unknown>;
const target = join(PROJECT_ROOT, "test", "openapi.snapshot.json");
writeFileSync(target, `${JSON.stringify(document, null, 2)}\n`, "utf8");

const paths = Object.keys((document.paths as Record<string, unknown>) ?? {});
console.log(`wrote ${target}`);
console.log(`${paths.length} path(s) from ${base}`);
for (const path of paths.sort()) console.log(`  ${path}`);
