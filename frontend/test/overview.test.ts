/**
 * 概览聚合的测试。
 *
 * 概览卡片是"一眼看结论"的地方，所以它算错时最难被发现：没有一个下钻页面会暴露矛盾。
 * 这里的每个断言都对着一种具体的、会静默出错的方式 —— 比如"工作区去重"漏了就会把 20 个
 * 分析包说成 20 个工作区。
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import type { AIReport, BundleSummary, JobSummary, TrafficEntry } from "../src/api/types.ts";
import {
  aiTotals,
  coverageTotals,
  providerMix,
  queueByKind,
  trafficByPath,
} from "../src/format.ts";

function bundle(overrides: Partial<BundleSummary> = {}): BundleSummary {
  return {
    bundle_id: "B-1",
    created_at: "2026-01-01T00:00:00Z",
    focus_count: 2,
    estimated_tokens: 1000,
    coverage: { discoverable: 10, bundled: 8, rejected: 1, deduped: 1 },
    duration_ms: 500,
    prune_count: 0,
    degradation_count: 0,
    providers: ["lsp_document_symbol"],
    engine: "opengrep",
    zero_findings_suspicious: false,
    workspace: "/workspace",
    has_ai_report: false,
    ...overrides,
  };
}

test("coverageTotals 把每个口径分开累加，并把工作区去重", () => {
  const totals = coverageTotals([
    bundle({ bundle_id: "B-1", workspace: "/a" }),
    bundle({
      bundle_id: "B-2",
      workspace: "/a",
      focus_count: 3,
      estimated_tokens: 500,
      duration_ms: 250,
      prune_count: 4,
      degradation_count: 1,
      coverage: { discoverable: 6, bundled: 5, rejected: 1, deduped: 0 },
      has_ai_report: true,
      zero_findings_suspicious: true,
    }),
    bundle({ bundle_id: "B-3", workspace: "/b", focus_count: 1 }),
  ]);

  assert.equal(totals.bundles, 3);
  assert.equal(totals.findings, 26);
  assert.equal(totals.bundled, 21);
  assert.equal(totals.rejected, 3);
  assert.equal(totals.deduped, 2);
  assert.equal(totals.contexts, 6);
  assert.equal(totals.tokens, 2500);
  assert.equal(totals.durationMs, 1250);
  assert.equal(totals.prunes, 4);
  assert.equal(totals.degradations, 1);
  assert.equal(totals.analysed, 1);
  assert.equal(totals.suspicious, 1);
  assert.equal(totals.workspaces, 2, "两个包在 /a，工作区数必须是 2 而不是 3");
});

test("coverageTotals 容忍缺失的 coverage 与 focus_count", () => {
  const totals = coverageTotals([
    bundle({ coverage: null, focus_count: null, estimated_tokens: null, duration_ms: null }),
  ]);
  assert.equal(totals.findings, 0);
  assert.equal(totals.contexts, 0);
  assert.equal(totals.tokens, 0);
  assert.equal(totals.bundles, 1);
});

test("providerMix 按分析包计数，同一个包里的重复来源只算一次", () => {
  const mix = providerMix([
    bundle({ bundle_id: "B-1", providers: ["lsp_call_hierarchy", "syntax_regex", "syntax_regex"] }),
    bundle({ bundle_id: "B-2", providers: ["syntax_regex"] }),
    bundle({ bundle_id: "B-3", providers: [] }),
  ]);
  assert.deepEqual(
    mix.map((entry) => [entry.provider, entry.bundles]),
    [
      ["syntax_regex", 2],
      ["lsp_call_hierarchy", 1],
    ],
  );
  assert.equal(mix[0]?.share, 2 / 3);
  assert.equal(mix[1]?.share, 1 / 3);
});

test("providerMix 空输入不产生 NaN 占比", () => {
  assert.deepEqual(providerMix([]), []);
});

function report(calls: AIReport["calls"]): AIReport {
  return {
    bundle_id: "B-1",
    model: "m",
    endpoint: "e",
    started_at: "2026-01-01T00:00:00Z",
    finished_at: null,
    calls,
    skipped: null,
  };
}

function call(
  kind: "true_positive" | "false_positive" | "needs_more_context" | null,
  options: { parsed?: boolean; prompt?: number; cached?: number; confidence?: number } = {},
) {
  const { parsed = true, prompt = 100, cached = 40, confidence = 0.5 } = options;
  return {
    context_id: "C-1",
    model: "m",
    endpoint: "e",
    called_at: "2026-01-01T00:00:00Z",
    elapsed_s: 1,
    usage: {
      prompt_tokens: prompt,
      completion_tokens: 10,
      total_tokens: prompt + 10,
      cached_tokens: cached,
      raw: {},
    },
    parsed,
    error: parsed ? null : "boom",
    missing_fields: [],
    verdict: kind
      ? {
          verdict: kind,
          severity: "high" as const,
          confidence,
          severity_qualifier: "",
          reachability: "",
          chain: [],
          data_flow: "",
          evidence: [],
          missing: [],
          fix: "",
        }
      : null,
    raw_answer: "",
  };
}

test("aiTotals 统计三类结论、可解析数与失败数", () => {
  const totals = aiTotals([
    report([call("true_positive"), call("false_positive"), call("needs_more_context")]),
    report([call(null, { parsed: false })]),
  ]);
  assert.equal(totals.bundles, 2);
  assert.equal(totals.contexts, 4);
  assert.equal(totals.parsed, 3);
  assert.equal(totals.failed, 1);
  assert.equal(totals.truePositive, 1);
  assert.equal(totals.falsePositive, 1);
  assert.equal(totals.needsContext, 1);
  // parsed 与 failed 必须刚好等于 contexts，否则卡片上的比例会自相矛盾。
  assert.equal(totals.parsed + totals.failed, totals.contexts);
});

test("aiTotals 汇总 token，并按输入总量加权算缓存命中", () => {
  const totals = aiTotals([
    report([call("true_positive", { prompt: 100, cached: 100 })]),
    report([call("true_positive", { prompt: 300, cached: 0 })]),
  ]);
  assert.equal(totals.prompt, 400);
  assert.equal(totals.completion, 20);
  assert.equal(totals.cached, 100);
  assert.equal(totals.cacheShare, 0.25, "缓存占比要按输入总量加权，不是每个包各算再平均");
});

test("aiTotals 的置信度是均值，且没有可解析项时是 null", () => {
  const totals = aiTotals([
    report([call("true_positive", { confidence: 0.8 }), call("false_positive", { confidence: 0.4 })]),
  ]);
  assert.equal(totals.meanConfidence, 0.6000000000000001);

  assert.equal(aiTotals([]).meanConfidence, null);
  assert.equal(aiTotals([]).cacheShare, null);
  assert.equal(aiTotals([report([call(null, { parsed: false })])]).meanConfidence, null);
});

test("trafficByPath 按方法+路径聚合，算出均值与失败数，并按次数排序", () => {
  const entries: TrafficEntry[] = [
    { seq: 1, at: "t", method: "GET", path: "/v1/jobs", status: 200, duration_ms: 10, client: "x" },
    { seq: 2, at: "t", method: "GET", path: "/v1/jobs", status: 200, duration_ms: 30, client: "x" },
    { seq: 3, at: "t", method: "GET", path: "/v1/jobs", status: 500, duration_ms: 20, client: "x" },
    { seq: 4, at: "t", method: "GET", path: "/v1/bundles", status: 200, duration_ms: 5, client: "x" },
  ];
  const metrics = trafficByPath(entries, 5);
  assert.equal(metrics.length, 2);
  assert.equal(metrics[0]?.label, "GET /v1/jobs");
  assert.equal(metrics[0]?.count, 3);
  assert.equal(metrics[0]?.avgMs, 20);
  assert.equal(metrics[0]?.errors, 1);
  assert.equal(metrics[1]?.label, "GET /v1/bundles");
  assert.equal(metrics[1]?.errors, 0);
});

test("trafficByPath 把不同方法视为不同条目，并遵守条数上限", () => {
  const entries: TrafficEntry[] = [
    { seq: 1, at: "t", method: "GET", path: "/v1/jobs", status: 200, duration_ms: 1, client: "" },
    { seq: 2, at: "t", method: "POST", path: "/v1/jobs", status: 202, duration_ms: 1, client: "" },
  ];
  assert.equal(trafficByPath(entries, 5).length, 2, "GET 与 POST 不是同一个条目");
  assert.equal(trafficByPath(entries, 1).length, 1, "上限必须生效");
});

function job(kind: string, state: string): JobSummary {
  return {
    job_id: `J-${kind}-${state}`,
    kind: kind as JobSummary["kind"],
    state: state as JobSummary["state"],
    cancel_requested: false,
    submitted_at: "2026-01-01T00:00:00Z",
    started_at: null,
    finished_at: null,
    duration_ms: 0,
    stage: "done",
    counters: {},
    units_done: 0,
    units_total: 0,
    unit_label: "",
    attempt: 1,
    bundle_id: null,
    failure_mode: null,
    revision: 0,
    workspace: null,
  };
}

test("queueByKind 分开统计在跑/在排/已完成，并保留零任务的任务类型", () => {
  const rows = queueByKind(
    [
      job("assemble", "running"),
      job("assemble", "queued"),
      job("assemble", "succeeded"),
      job("scan", "failed"),
    ],
    ["assemble", "scan", "ai_fanout"],
  );
  assert.deepEqual(rows, [
    { kind: "assemble", running: 1, queued: 1, finished: 1 },
    { kind: "scan", running: 0, queued: 0, finished: 1 },
    { kind: "ai_fanout", running: 0, queued: 0, finished: 0 },
  ]);
});

test("queueByKind 保留没有出现过的任务类型，顺序按传入的列表", () => {
  const rows = queueByKind([], ["assemble", "scan"]);
  assert.deepEqual(
    rows.map((row) => row.kind),
    ["assemble", "scan"],
    "类型为零时也要显示卡片，否则界面会随数据变动而改变形状",
  );
});
