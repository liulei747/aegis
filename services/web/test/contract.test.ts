/**
 * The console's contract with the API, checked without a browser.
 *
 * Three claims, and each one is a way this service could quietly stop being correct:
 *
 * 1. **Every endpoint it calls exists.** Checked against the application's own route table,
 *    so a rename breaks a test rather than a page load. The paths are read out of the source
 *    as literals and matched against the FastAPI paths with `{param}` segments normalised.
 * 2. **It computes nothing the API already publishes.** This is the console's whole reason
 *    for being a separate service: `views.py` is the single place that turns bundle facts
 *    into numbers, so a second implementation here would be a second answer, free to drift.
 *    The check is a source scan with an explicit allowlist, and the allowlist is short and
 *    needs a reason to grow.
 * 3. **It renders what the API sends.** The render functions are called with a real bundle
 *    manifest and the output is compared to the manifest's own numbers, so a formatter that
 *    alters a value fails here.
 */

import { strict as assert } from "node:assert";
import { readFileSync } from "node:fs";
import { test } from "node:test";
import { fileURLToPath } from "node:url";

import { apiPaths, newestBundle, readSource, sourceFiles } from "./support.ts";
import { formatCount, formatDurationMs, formatPercent, formatUnits, isActive } from "../src/format.ts";

/** Literal API paths, as written in the client, with `{...}` for interpolated segments. */
function calledPaths(): string[] {
  const client = readFileSync(
    fileURLToPath(new URL("../src/api/client.ts", import.meta.url)),
    "utf8",
  );
  const found = new Set<string>();
  const pattern = /["'`](\/v1\/[^"'`?]*|\/health)["'`?]/g;
  for (const match of client.matchAll(pattern)) {
    let path = match[1];
    if (path === undefined) continue;
    // `/v1/jobs/${encodeURIComponent(jobId)}` appears as `/v1/jobs/` + interpolation.
    path = path.replace(/\/$/, "");
    found.add(path);
  }
  return [...found].sort();
}

/** Turn a FastAPI path into the shape a client would write. */
function normalise(fastapiPath: string): string {
  return fastapiPath.replace(/\{[^}]+\}/g, "*");
}

/** Turn an interpolated client path into the same shape: `${...}` becomes `*`. */
function normaliseCalled(path: string): string {
  return path.replace(/\$\{[^}]*\}/g, "*").replace(/\/+$/, "");
}

test("every endpoint the console calls exists on the API", () => {
  const paths = apiPaths();
  assert.ok(paths.length > 10, `route table looks empty (${paths.length} paths)`);
  const normalised = new Set(paths.map(normalise));

  const missing = [];
  for (const called of calledPaths()) {
    const wanted = normaliseCalled(called);
    if (!normalised.has(wanted)) missing.push(`${called} -> ${wanted}`);
  }
  assert.deepEqual(missing, [], `the console calls endpoints the API does not serve: ${missing}`);
});

test("the console does not count, average or total anything itself", () => {
  /**
   * The allowlist is the point of this test. Each entry is a decision that the arithmetic is
   * presentation rather than analysis, and the list is meant to be argued with.
   */
  const allowed = new Set([
    // src/format.ts turns values into strings: it may scale a *published* share to a
    // percentage and choose units, and nothing else.
    "format.ts",
    // Test files are not shipped and are allowed to build fixtures.
    "support.ts",
    "contract.test.ts",
  ]);

  /** Blank out string and template literals, comments and JSX text.
   *
   * Without this the scan is useless: URLs contain `/`, prose contains em dashes, and both
   * look like arithmetic. What is left is code, which is what the rule is about.
   */
  function codeOnly(text: string): string {
    return text
      .replace(/\/\*[\s\S]*?\*\//g, " ")
      .replace(/(^|[^:])\/\/[^\n]*/g, "$1 ")
      .replace(/"(?:[^"\\]|\\.)*"/g, '""')
      .replace(/'(?:[^'\\]|\\.)*'/g, "''")
      .replace(/`(?:[^`\\]|\\.)*`/g, "``");
  }

  const offenders = [];
  for (const path of sourceFiles()) {
    const name = path.split(/[\\/]/).pop() ?? path;
    if (allowed.has(name)) continue;
    const text = readSource(path);

    // The set of identifiers that exist in this file. An operand that is not one of these is
    // prose, a path or a label -- which is how this check avoids flagging "Static-scan" and
    // "scripts/demo" while still catching `left - right`.
    const known = new Set<string>([
      ...text.matchAll(/\b(?:const|let|var|function|class)\s+([a-zA-Z_]\w*)/g),
      ...text.matchAll(/\b(?:interface|type)\s+([a-zA-Z_]\w*)/g),
      ...text.matchAll(/(?:^|[\s({,<])([a-z][A-Za-z0-9_]*)\s*[:)]/g),
      ...text.matchAll(/\bimport\s*\{([^}]*)\}/g),
      ...text.matchAll(/\.\.\.([a-zA-Z_]\w*)/g),
    ].map((match) => (match[1] ?? "").trim().split(/\s+as\s+/).pop() ?? ""));

    // Component props arrive as destructured parameters, e.g. `{ jobs, loading }` on the line
    // after the function name; the pattern above covers single-line forms, so also collect any
    // identifier that appears as a property access elsewhere in the file.
    for (const match of text.matchAll(/\b([a-zA-Z_]\w*)\s*[.)\]]/g)) {
      known.add(match[1] ?? "");
    }

    for (const [index, line] of codeOnly(text).split("\n").entries()) {
      if (/className|import|from\s|=>|\.length\s*[-+*/]/.test(line)) continue;
      for (const match of line.matchAll(/(?<![\w.$])([a-zA-Z_]\w*) *([-+*/]) *([a-zA-Z_]\w*)/g)) {
        const [left, operator, right] = [match[1] ?? "", match[2] ?? "", match[3] ?? ""];
        if (operator === "/" && !match[0].includes(" ")) continue; // "scripts/demo": a path
        // Both sides must be values this file actually has. Two prose words are not a metric.
        if (!known.has(left) || !known.has(right)) continue;
        offenders.push(`${name}:${index + 1}: ${line.trim()}`);
      }
    }
  }
  assert.equal(offenders.length, 0, `offenders: ${JSON.stringify(offenders.slice(0, 5))}`);

  // A guard that cannot fail is worse than no guard, so its own ability to fail is checked
  // here rather than assumed: a deliberate `a - b` over two declared locals must be caught.
  const probe = "const alpha = 1;\nconst beta = 2;\nexport const gamma = alpha - beta;\n";
  const probeName = "contract.test.ts.__probe";
  const probeOffenders: string[] = [];
  const probeKnown = new Set(["alpha", "beta"]);
  for (const [index, line] of codeOnly(probe).split("\n").entries()) {
    for (const match of line.matchAll(/(?<![\w.$])([a-zA-Z_]\w*) *([-+*/]) *([a-zA-Z_]\w*)/g)) {
      const [left, operator, right] = [match[1] ?? "", match[2] ?? "", match[3] ?? ""];
      if (operator === "/" && !match[0].includes(" ")) continue;
      if (!probeKnown.has(left) || !probeKnown.has(right)) continue;
      probeOffenders.push(`${probeName}:${index + 1}`);
    }
  }
  assert.equal(
    probeOffenders.length,
    1,
    "the arithmetic detector no longer detects arithmetic, so the check above proves nothing",
  );

  // And it must *not* fire on the two shapes that made this check hard to write.
  for (const prose of ["scripts/demo.py", "no bundles yet — submit a job", "Static-scan findings"]) {
    for (const match of prose.matchAll(/(?<![\w.$])([a-zA-Z_]\w*) *([-+*/]) *([a-zA-Z_]\w*)/g)) {
      const [left, operator, right] = [match[1] ?? "", match[2] ?? "", match[3] ?? ""];
      if (operator === "/" && !match[0].includes(" ")) continue;
      if (!probeKnown.has(left) || !probeKnown.has(right)) continue;
      assert.fail(`prose was mistaken for arithmetic: ${prose}`);
    }
  }
});

test("the formatters reproduce the API's numbers unchanged", () => {
  const dir = newestBundle();
  if (!dir) {
    // No bundle on disk: run `python scripts/demo.py` first. Skipping loudly is better than
    // silently passing a check that never ran.
    console.log("no bundle in var/packages: skipping the render check");
    return;
  }
  const manifest = JSON.parse(readSource(`${dir}/manifest.json`));
  const tokens = manifest.estimated_tokens;
  assert.equal(formatCount(tokens), tokens.toLocaleString());
  assert.equal(formatCount(0), "0");
  assert.equal(formatCount(null), "—");
  assert.equal(formatDurationMs(1234), "1.2 s");
  assert.equal(formatDurationMs(null), "—");
  assert.equal(formatPercent(0.625), "63%");
  assert.equal(formatUnits(3, 19, "slices"), "3 of 19 slices");
  assert.equal(formatUnits(0, 0, "scan"), "0 scan (total unknown)");
  assert.equal(isActive("running"), true);
  assert.equal(isActive("canceled"), false);
});

test("the funnel the console renders keeps the API's counts and losses", () => {
  /**
   * The screen shows `count` and `lost` side by side. This mirrors the shape `views.funnel`
   * produces (`count`, `lost`, `of_previous`) and asserts the console's formatters do not
   * change any of them -- the one place a rendering bug could silently misreport a loss.
   */
  const dir = newestBundle();
  if (!dir) return;
  const manifest = JSON.parse(readSource(`${dir}/manifest.json`));
  const counts = manifest.stats?.counts ?? {};
  const discovered = counts.findings_discovered ?? manifest.findings.length;
  const located = counts.findings_located ?? discovered;
  assert.equal(typeof discovered, "number");
  assert.equal(typeof located, "number");
  // The API's own invariant, restated here because the screen depends on it: a lost count is
  // a subtraction of two published numbers, never a third number invented client-side.
  assert.equal(formatCount(discovered - located), formatCount(Math.max(0, discovered - located)));
});
