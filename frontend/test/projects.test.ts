/**
 * 「选项目」这一层的测试。
 *
 * 这条链路上的每个错误都会表现成同一件事：**用户点了一个项目，跑出来的却是另一个（或者什么都
 * 跑不了）**。所以这里钉的是选择规则本身 —— 最新分析包是谁、不可用的行会不会被自动选中、
 * 同一个项目两次渲染会不会选到不同的包。
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import type { BundleSummary, JobSummary, ProjectRecord } from "../src/api/types.ts";
import { mergeProjects, projectsFrom } from "../src/format.ts";
import { choicesFrom, defaultChoice, latestBundleOf, projectChoices } from "../src/projects.ts";

function bundle(
  bundleId: string,
  workspace: string | null,
  created: string | null,
  focus = 3,
): BundleSummary {
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

function job(
  jobId: string,
  workspace: string | null,
  kind: JobSummary["kind"],
  state: JobSummary["state"],
  submitted: string,
): JobSummary {
  return {
    job_id: jobId,
    kind,
    state,
    cancel_requested: false,
    submitted_at: submitted,
    started_at: submitted,
    finished_at: state === "succeeded" ? submitted : null,
    duration_ms: 1000,
    stage: "done",
    counters: { findings: kind === "audit" ? 2 : 0 },
    units_done: 0,
    units_total: 0,
    unit_label: "",
    attempt: 1,
    bundle_id: null,
    failure_mode: null,
    revision: 1,
    workspace,
  };
}

test("latestBundleOf takes the newest by created_at, not the first in the list", () => {
  const picked = latestBundleOf([
    bundle("B-old", "/p", "2026-01-01T00:00:00Z"),
    bundle("B-mid", "/p", "2026-03-01T00:00:00Z"),
    bundle("B-new", "/p", "2026-06-01T00:00:00Z"),
  ]);
  assert.equal(picked?.bundle_id, "B-new");
  assert.equal(latestBundleOf([]), null);
});

test("a tie on created_at is broken by id, so two renders agree", () => {
  const same = "2026-06-01T00:00:00Z";
  // 不稳定的话，界面会在两个包之间跳 —— 用户会以为自己在看 A，实际刷新后是 B。
  const first = latestBundleOf([bundle("B-a", "/p", same), bundle("B-b", "/p", same)]);
  const second = latestBundleOf([bundle("B-b", "/p", same), bundle("B-a", "/p", same)]);
  assert.equal(first?.bundle_id, second?.bundle_id);
});

test("a bundle with no created_at does not win by default", () => {
  // 空字符串排在任何 ISO 时间之前；把缺失当成"最新"会让一个来历不明的包成为默认输入。
  const picked = latestBundleOf([
    bundle("B-unknown", "/p", null),
    bundle("B-real", "/p", "2026-01-01T00:00:00Z"),
  ]);
  assert.equal(picked?.bundle_id, "B-real");
});

test("choicesFrom marks a workspace-less row unusable and never defaults to it", () => {
  const choices = choicesFrom([bundle("B-orphan", null, "2026-06-01T00:00:00Z")], []);

  assert.equal(choices.length, 1);
  assert.equal(choices[0]?.usable, false, "`(未知工作区)` 不是一个能提交的路径");
  assert.equal(defaultChoice(choices), null, "没有可用项目时宁可什么都不选");
});

test("choicesFrom pairs each project with its own newest bundle", () => {
  const choices = choicesFrom(
    [
      bundle("B-a1", "/a", "2026-01-01T00:00:00Z", 2),
      bundle("B-a2", "/a", "2026-05-01T00:00:00Z", 4),
      bundle("B-b1", "/b", "2026-02-01T00:00:00Z", 7),
    ],
    [],
  );
  const byWorkspace = new Map(choices.map((choice) => [choice.workspace, choice]));

  assert.equal(byWorkspace.get("/a")?.latestBundle?.bundle_id, "B-a2");
  assert.equal(byWorkspace.get("/a")?.bundleCount, 2);
  assert.equal(byWorkspace.get("/a")?.contextCount, 6, "上下文是该项目所有包的和，不是最新那个的");
  assert.equal(byWorkspace.get("/b")?.latestBundle?.bundle_id, "B-b1");
});

test("a project with no bundle is still offered -- it has a path and can be audited", () => {
  // 刚建好、还没组装的项目必须能被深度审计选中：那是它的主要用途。
  const choices = choicesFrom([], [job("J-1", "/fresh", "scan", "succeeded", "2026-01-01T00:00:00Z")]);

  assert.equal(choices.length, 1);
  assert.equal(choices[0]?.latestBundle, null);
  assert.equal(choices[0]?.usable, true);
  assert.equal(defaultChoice(choices)?.workspace, "/fresh");
});

test("an in-flight audit is visible on the choice that owns it", () => {
  const choices = choicesFrom(
    [bundle("B-1", "/busy", "2026-01-01T00:00:00Z")],
    [
      job("J-a", "/busy", "audit", "running", "2026-06-01T10:00:00Z"),
      job("J-b", "/busy", "assemble", "running", "2026-06-01T11:00:00Z"),
    ],
  );

  assert.equal(choices[0]?.auditInFlight, true, "组装任务在跑不算审计在跑");
  assert.equal(choices[0]?.lastAuditJob?.job_id, "J-a");
});

test("the most recently active project comes first", () => {
  const choices = choiceOrder();
  assert.deepEqual(
    choices.map((choice) => choice.workspace),
    ["/new", "/old"],
  );
});

function choiceOrder() {
  return projectChoices(
    projectsFrom(
      [
        bundle("B-old", "/old", "2026-01-01T00:00:00Z"),
        bundle("B-new", "/new", "2026-06-01T00:00:00Z"),
      ],
      [],
    ),
  );
}

// ── 项目页那一层：注册表与派生数据的并集 ─────────────────────────────────────
//
// 这一段是重建的。`frontend/test/projects.test.ts` 原来的内容在一次改写里被我覆盖掉了
// （这个工程没有提交过，没有 git 可回滚），所以下面按 `mergeProjects` 的实现与它自己的注释把
// 契约重新钉一遍：两边都要在，注册表优先，派生计数不能丢。

function record(workspace: string, name: string, created: string): ProjectRecord {
  return {
    schema_version: "1",
    workspace,
    name,
    origin: "https://example.invalid/r.git",
    source: "git",
    ref: "main",
    commit: "c".repeat(40),
    created_at: created,
    files: 3,
    bytes: 100,
    languages: { java: 2 },
    job_id: "J-reg",
  };
}

test("mergeProjects keeps a registered project that has no analysis yet", () => {
  // 只看派生数据的话，刚建好的项目不显示，用户会以为自己点失败了。
  const rows = mergeProjects([record("/fresh", "fresh", "2026-06-01T00:00:00Z")], [], []);

  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.registered, true);
  assert.equal(rows[0]?.name, "fresh");
  assert.equal(rows[0]?.bundleCount, 0);
  assert.equal(rows[0]?.lastActivity, "2026-06-01T00:00:00Z");
});

test("mergeProjects keeps historical data that is not in the registry", () => {
  // 功能上线之前就存在的包与任务只在派生那一侧，藏起来等于丢数据。
  const rows = mergeProjects(
    [],
    [bundle("B-old", "/legacy", "2026-01-01T00:00:00Z")],
    [job("J-old", "/legacy", "assemble", "succeeded", "2026-02-01T00:00:00Z")],
  );

  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.registered, false);
  assert.equal(rows[0]?.origin, null, "没有注册表条目就没有来源可报，而不是编一个");
  assert.equal(rows[0]?.bundleCount, 1);
  assert.equal(rows[0]?.jobCount, 1);
  assert.equal(rows[0]?.lastActivity, "2026-02-01T00:00:00Z", "最近活动取两侧最新的那个");
});

test("mergeProjects lets the registry win on identity and keeps the derived counts", () => {
  const rows = mergeProjects(
    [record("/p", "given-name", "2026-01-15T00:00:00Z")],
    [
      bundle("B-1", "/p", "2026-01-01T00:00:00Z"),
      { ...bundle("B-2", "/p", "2026-01-02T00:00:00Z"), has_ai_report: true },
    ],
    [job("J-1", "/p", "assemble", "succeeded", "2026-01-03T00:00:00Z")],
  );

  assert.equal(rows.length, 1, "并集按 workspace 做键，同一个项目只占一行");
  assert.equal(rows[0]?.name, "given-name", "注册表的名字比路径末段准确");
  assert.equal(rows[0]?.registered, true);
  assert.equal(rows[0]?.bundleCount, 2, "计数来自派生那一侧，不能被注册表覆盖成 0");
  assert.equal(rows[0]?.jobCount, 1);
  assert.equal(rows[0]?.analysed, 1);
  assert.deepEqual(rows[0]?.languages, { java: 2 });
});
