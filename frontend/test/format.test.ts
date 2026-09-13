/**
 * The arithmetic, pinned.
 *
 * These are the values this front-end computes rather than asks for -- which is exactly why they
 * need tests: on the backend a wrong count would have been one function with one test, and here
 * it is a screen that quietly shows a number nobody can check.
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import type { AIReport, AITrafficEntry, BundleSummary, JobSummary } from "../src/api/types.ts";
import {
  cacheHitRatio,
  countsOf,
  formatDurationMs,
  formatPercent,
  formatRelative,
  formatUnits,
  jobsByState,
  modelCallTotals,
  projectsFrom,
  share,
  tokenTotals,
  worstSeverity,
} from "../src/format.ts";

function report(calls: AIReport["calls"]): AIReport {
  return {
    bundle_id: "B-test",
    model: "m",
    endpoint: "e",
    started_at: "2026-01-01T00:00:00Z",
    finished_at: null,
    calls,
    skipped: null,
  };
}

function call(parsed: boolean, prompt: number | null, cached: number | null) {
  return {
    context_id: "C-1",
    model: "m",
    endpoint: "e",
    called_at: "2026-01-01T00:00:00Z",
    elapsed_s: 1,
    usage:
      prompt === null
        ? null
        : { prompt_tokens: prompt, completion_tokens: 10, total_tokens: prompt + 10, cached_tokens: cached, raw: {} },
    parsed,
    error: parsed ? null : "boom",
    missing_fields: [],
    verdict: null,
    raw_answer: "",
  };
}

test("countsOf splits parsed from failed and the two always add up", () => {
  const counts = countsOf(report([call(true, 100, 50), call(false, 100, 0), call(true, 100, 25)]));
  assert.deepEqual(counts, { contexts: 3, parsed: 2, failed: 1 });
  assert.equal(counts.parsed + counts.failed, counts.contexts);
});

test("countsOf tolerates no report at all", () => {
  assert.deepEqual(countsOf(null), { contexts: 0, parsed: 0, failed: 0 });
});

test("cacheHitRatio is null when the provider did not report a prompt size", () => {
  assert.equal(cacheHitRatio(null), null);
  assert.equal(cacheHitRatio({ prompt_tokens: 0, completion_tokens: 1, total_tokens: 1, cached_tokens: 5, raw: {} }), null);
  assert.equal(cacheHitRatio({ prompt_tokens: null, completion_tokens: null, total_tokens: null, cached_tokens: 5, raw: {} }), null);
  assert.equal(cacheHitRatio({ prompt_tokens: 200, completion_tokens: 1, total_tokens: 201, cached_tokens: 50, raw: {} }), 0.25);
});

test("tokenTotals weights the cache share over all prompt tokens, not per call", () => {
  const totals = tokenTotals(report([call(true, 100, 100), call(true, 300, 0)]));
  assert.deepEqual({ ...totals }, { prompt: 400, completion: 20, cached: 100, cacheShare: 0.25 });
});

test("tokenTotals reports no share when nothing reported a prompt size", () => {
  assert.equal(tokenTotals(report([call(true, null, null)])).cacheShare, null);
});

test("formatPercent never turns an unknown into 0%", () => {
  assert.equal(formatPercent(null), "—");
  assert.equal(formatPercent(undefined), "—");
  assert.equal(formatPercent(Number.NaN), "—");
  assert.equal(formatPercent(0), "0%");
  assert.equal(formatPercent(0.8547), "85%");
  assert.equal(formatPercent(0.8547, 1), "85.5%");
});

test("formatUnits says the total is unknown rather than showing a zero denominator", () => {
  assert.equal(formatUnits(4, 0, "contexts"), "4 contexts · 总数未知");
  assert.equal(formatUnits(4, 6, "contexts"), "4 / 6 contexts");
  assert.equal(formatUnits(0, 0, ""), "0 单位 · 总数未知");
});

test("share is null for an unknown total, so no bar is drawn", () => {
  assert.equal(share(3, 0), null);
  assert.equal(share(3, 6), 0.5);
});

test("formatDurationMs switches unit at the point the unit stops being readable", () => {
  assert.equal(formatDurationMs(0), "0 毫秒");
  assert.equal(formatDurationMs(999), "999 毫秒");
  assert.equal(formatDurationMs(2300), "2.3 秒");
  assert.equal(formatDurationMs(45_000), "45 秒");
  assert.equal(formatDurationMs(95_000), "1 分 35 秒");
  assert.equal(formatDurationMs(null), "—");
});

test("formatRelative describes a moment in the past and the future", () => {
  const now = new Date("2026-01-01T12:00:00Z");
  assert.equal(formatRelative("2026-01-01T11:59:58Z", now), "刚刚");
  assert.equal(formatRelative("2026-01-01T11:55:00Z", now), "5 分钟前");
  assert.equal(formatRelative("2026-01-01T09:00:00Z", now), "3 小时前");
  assert.equal(formatRelative("2025-12-30T12:00:00Z", now), "2 天前");
  assert.equal(formatRelative("2026-01-01T13:00:00Z", now), "1 小时后");
  assert.equal(formatRelative(null, now), "—");
});

test("worstSeverity returns the most severe present, and null when there is none", () => {
  assert.equal(worstSeverity(["low", "critical", "high"]), "critical");
  assert.equal(worstSeverity([null, undefined]), null);
  assert.equal(worstSeverity([]), null);
});

test("jobsByState counts every state, including ones with no jobs", () => {
  const jobs = [
    { state: "running" },
    { state: "running" },
    { state: "succeeded" },
  ] as JobSummary[];
  assert.deepEqual(jobsByState(jobs), { running: 2, succeeded: 1 });
});

function bundle(bundleId: string, workspace: string | null, focus: number | null, created: string | null): BundleSummary {
  return {
    bundle_id: bundleId,
    created_at: created,
    focus_count: focus,
    estimated_tokens: 100,
    coverage: null,
    duration_ms: 1,
    prune_count: 0,
    degradation_count: 0,
    providers: [],
    engine: "opengrep",
    zero_findings_suspicious: null,
    workspace,
    has_ai_report: false,
  };
}

function job(jobId: string, workspace: string | null, submitted: string): JobSummary {
  return {
    job_id: jobId,
    kind: "assemble",
    state: "succeeded",
    cancel_requested: false,
    submitted_at: submitted,
    started_at: submitted,
    finished_at: submitted,
    duration_ms: 1,
    stage: "done",
    counters: {},
    units_done: 0,
    units_total: 0,
    unit_label: "",
    attempt: 1,
    bundle_id: null,
    failure_mode: null,
    revision: 0,
    workspace,
  };
}

test("projectsFrom groups by workspace and names a project after its last path segment", () => {
  const projects = projectsFrom(
    [bundle("B-1", "/workspace", 5, "2026-01-01T00:00:00Z"), bundle("B-2", "/workspace", 3, "2026-01-02T00:00:00Z")],
    [job("J-1", "/workspace", "2026-01-03T00:00:00Z")],
  );
  assert.equal(projects.length, 1);
  assert.equal(projects[0]?.name, "workspace");
  assert.equal(projects[0]?.bundleCount, 2);
  assert.equal(projects[0]?.jobCount, 1);
  assert.equal(projects[0]?.contextCount, 8);
  assert.equal(projects[0]?.lastActivity, "2026-01-03T00:00:00Z");
});

test("projectsFrom keeps an unattributable bundle visible instead of dropping it", () => {
  const projects = projectsFrom([bundle("B-old", null, 1, "2026-01-01T00:00:00Z")], []);
  assert.equal(projects.length, 1);
  assert.equal(projects[0]?.workspace, "(未知工作区)");
  assert.equal(projects[0]?.bundleCount, 1);
});

test("projectsFrom sorts by most recent activity, newest first", () => {
  const projects = projectsFrom(
    [bundle("B-1", "/old", 1, "2026-01-01T00:00:00Z"), bundle("B-2", "/new", 1, "2026-06-01T00:00:00Z")],
    [],
  );
  assert.deepEqual(
    projects.map((project) => project.workspace),
    ["/new", "/old"],
  );
});

function call_(overrides: Partial<AITrafficEntry> = {}): AITrafficEntry {
  return {
    at: "2026-01-01T00:00:00Z",
    caller: "discovery:s1",
    kind: "harness",
    model: "m",
    endpoint: "e",
    attempt: 1,
    ok: true,
    duration_ms: 1000,
    prompt_chars: 10,
    answer_chars: 5,
    prompt_tokens: 100,
    completion_tokens: 20,
    cached_tokens: 40,
    error: null,
    ...overrides,
  };
}

test("modelCallTotals counts retries from the attempt numbers, not from a guess", () => {
  // 来源 A：两次尝试（一次 504 后成功）；来源 B：一次成功。往返 = 3，重试 = 1。
  const totals = modelCallTotals([
    call_({ caller: "A", attempt: 1, ok: false, error: "AIUnavailable: 504" }),
    call_({ caller: "A", attempt: 2 }),
    call_({ caller: "B", attempt: 1, duration_ms: 3000 }),
  ]);

  assert.equal(totals.attempts, 3);
  assert.equal(totals.retried, 1);
  assert.equal(totals.failures, 1);
  assert.equal(totals.meanMs, (1000 + 1000 + 3000) / 3);
  assert.equal(totals.callers, 2);
  assert.equal(totals.promptTokens, 300);
  assert.equal(totals.cachedTokens, 120);
  assert.equal(totals.cacheShare, 0.4);
});

test("modelCallTotals reports an unknown cache share as null, never as zero", () => {
  // 没有 usage 的行（provider 没报）不能被算成 "0 命中"，那会把"不知道"显示成"没命中"。
  const totals = modelCallTotals([call_({ prompt_tokens: null, completion_tokens: null, cached_tokens: null })]);

  assert.equal(totals.cacheShare, null);
  assert.equal(totals.meanMs, 1000, "耗时是本地测的，与 provider 报不报 token 无关");
  assert.equal(totals.promptTokens, 0);
});

test("modelCallTotals on an empty page is empty, not NaN", () => {
  const totals = modelCallTotals([]);
  assert.equal(totals.meanMs, null);
  assert.equal(totals.cacheShare, null);
  assert.equal(totals.attempts, 0);
});
