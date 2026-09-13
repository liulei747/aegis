/**
 * 轨迹折叠的测试：一串事件怎么变成屏幕上的那几行。
 *
 * 这里钉的是**读法**，不是渲染。后端记事件，这一屏回答"刚才在干什么"。所以每条断言背后都是一
 * 个会被误读的事实：
 *
 * * 没有 `agent_end` 的 agent 是**在跑**，不是失败 —— 猜成失败会让一个正常的审计看起来正在崩。
 * * 阶段表按真实顺序排，不按事件到达顺序 —— 重派发会让同一阶段出现两次，位置随机。
 * * 对话过滤要报告"共多少条/显示多少条" —— 只显示一小截而不说被截断，读起来就是"只有这么多"。
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  agentRows,
  agentsSeen,
  candidateRows,
  coverageRows,
  dialogue,
  filterDialogue,
  findingRows,
  isClosed,
  latestCounters,
  stageRows,
} from "../src/audit.ts";
import type { AuditEvent } from "../src/api/types.ts";

function event(seq: number, kind: AuditEvent["kind"], fields: Partial<AuditEvent> = {}): AuditEvent {
  return { seq, at: `2026-01-01T00:00:${String(seq).padStart(2, "0")}Z`, kind, ...fields };
}

test("阶段表按真实顺序排，并且只保留每个阶段的最后一次", () => {
  const rows = stageRows([
    event(1, "stage", { stage: "recon", state: "start" }),
    event(2, "stage", { stage: "recon", state: "end" }),
    event(3, "stage", { stage: "discovery", state: "start", round: 0 }),
    event(4, "stage", { stage: "discovery", state: "round", round: 1 }),
    // 乱序到达：一个并发写的事件先落盘。表要按阶段顺序排，不按到达顺序。
    event(5, "stage", { stage: "plan", state: "end" }),
  ]);

  assert.deepEqual(
    rows.map((row) => [row.stage, row.state]),
    [
      ["recon", "end"],
      ["plan", "end"],
      ["discovery", "round"],
    ],
  );
  assert.equal(rows[2]?.round, 1, "最后一次的轮次才是当前轮次");
});

test("未知阶段照样显示，排在已知阶段之后", () => {
  const rows = stageRows([
    event(1, "stage", { stage: "recon", state: "end" }),
    event(2, "stage", { stage: "brand_new", state: "start" }),
  ]);
  assert.deepEqual(rows.map((row) => row.stage), ["recon", "brand_new"]);
  assert.equal(rows[1]?.label, "brand_new", "没有中文名就显示原始 id，而不是空白");
});

test("没有结束事件的 agent 是在跑，不是失败", () => {
  const rows = agentRows([
    event(1, "agent_start", { run_id: "discovery:s1", agent: "discovery", scope: "s1" }),
    event(2, "agent_step", { run_id: "discovery:s1", agent: "discovery", tool: "read", ok: true }),
    event(3, "agent_step", { run_id: "discovery:s1", agent: "discovery", tool: null, ok: true }),
    event(4, "agent_start", { run_id: "validation:C-1", agent: "validation", scope: "C-1" }),
    event(5, "agent_end", { run_id: "validation:C-1", agent: "validation", stop_reason: "budget",
                            steps: 8, parsed: false }),
  ]);

  assert.equal(rows.length, 2);
  assert.equal(rows[0]?.state, "running");
  assert.equal(rows[0]?.steps, 2);
  assert.equal(rows[0]?.toolCalls, 1, "thought-only 的一步不算工具调用");
  assert.equal(rows[1]?.state, "budget");
  assert.equal(rows[1]?.parsed, false);
});

test("每个停止原因映射到自己的状态，未知原因不假装成功", () => {
  const rows = agentRows([
    event(1, "agent_start", { run_id: "a", agent: "x", scope: "s" }),
    event(2, "agent_end", { run_id: "a", stop_reason: "finished" }),
    event(3, "agent_start", { run_id: "b", agent: "x", scope: "s" }),
    event(4, "agent_end", { run_id: "b", stop_reason: "error" }),
    event(5, "agent_start", { run_id: "c", agent: "x", scope: "s" }),
    event(6, "agent_end", { run_id: "c", stop_reason: "something_new" }),
  ]);
  assert.deepEqual(rows.map((row) => row.state), ["finished", "error", "unknown"]);
});

test("对话流带着想法、工具、参数和结果", () => {
  const rows = dialogue([
    event(1, "agent_start", { run_id: "discovery:s1", agent: "discovery", scope: "s1" }),
    event(2, "agent_step", {
      run_id: "discovery:s1",
      agent: "discovery",
      scope: "s1",
      index: 1,
      thought: "先看 mapper",
      tool: "read",
      arguments: { path: "ItemMapper.xml" },
      ok: true,
      summary: "第 1-40 行",
    }),
    event(3, "candidate", { candidate_id: "C-1" }),
  ]);

  assert.equal(rows.length, 1);
  assert.equal(rows[0]?.tool, "read");
  assert.deepEqual(rows[0]?.arguments, { path: "ItemMapper.xml" });
  assert.equal(rows[0]?.summary, "第 1-40 行");
  assert.equal(rows[0]?.thought, "先看 mapper");
});

test("过滤对话时同时报告总数和命中数", () => {
  const rows = dialogue([
    event(1, "agent_step", { run_id: "r1", agent: "discovery", scope: "s1", thought: "a", ok: true }),
    event(2, "agent_step", { run_id: "r2", agent: "validation", scope: "s1", thought: "b", ok: false,
                             error: "工具被拒" }),
    event(3, "agent_step", { run_id: "r3", agent: "discovery", scope: "s2", thought: "c", ok: true,
                             summary: "命中 sortField" }),
  ]);

  assert.equal(filterDialogue(rows, {}).total, 3);
  assert.equal(filterDialogue(rows, { agent: "discovery" }).rows.length, 2);
  assert.equal(filterDialogue(rows, { onlyProblems: true }).rows.length, 1);
  assert.equal(filterDialogue(rows, { needle: "sortfield" }).rows.length, 1, "搜索不分大小写");
  // 参数也在搜索范围内：按文件名找步骤是常见需求。
  const args = dialogue([
    event(1, "agent_step", { run_id: "r1", agent: "d", scope: "s", arguments: { path: "a/b.java" } }),
  ]);
  assert.equal(filterDialogue(args, { needle: "b.java" }).rows.length, 1);
  assert.equal(filterDialogue(rows, {}).total, rows.length, "总数始终是过滤前的");
});

test("覆盖率取每个 scope 的最后一次判定", () => {
  const rows = coverageRows([
    event(1, "coverage", { scope: "s2", state: "insufficient", reason: "有文件没读完", unread: 3, files: 6 }),
    event(2, "coverage", { scope: "s1", state: "sufficient", reason: "看过且没有命中", files: 2 }),
    event(3, "coverage", { scope: "s2", state: "sufficient", reason: "第二轮读完了", unread: 0, files: 6 }),
  ]);

  assert.deepEqual(rows.map((row) => row.scope), ["s1", "s2"], "按 scope 名排序，行不跳");
  assert.equal(rows[1]?.state, "sufficient");
  assert.equal(rows[1]?.unread, 0);
});

test("候选与它们的研判、可达性合并成一行", () => {
  const rows = candidateRows([
    event(1, "candidate", { candidate_id: "C-1", file: "a.java", line: 7, vulnerability_type: "sql_injection",
                            title: "拼接查询", scope: "s1" }),
    event(2, "verdict", { candidate_id: "C-1", verdict: "confirmed", confidence: 0.8,
                          evidence_kind: "semantic" }),
    event(3, "attack_path", { candidate_id: "C-1", reachable: true }),
    event(4, "candidate", { candidate_id: "C-2", file: "b.java", line: 3,
                            vulnerability_type: "idor", title: "无鉴权", scope: "s1" }),
  ]);

  assert.equal(rows.length, 2);
  assert.equal(rows[0]?.verdict, "confirmed");
  assert.equal(rows[0]?.confidence, 0.8);
  assert.equal(rows[0]?.reachable, true);
  assert.equal(rows[1]?.verdict, null, "还没有研判的候选显示为空，而不是默认成假阳性");
  assert.equal(rows[1]?.reachable, null);
});

test("发现、计数与收尾状态从轨迹里读出来", () => {
  const events = [
    event(1, "finding", { finding_id: "F-1", file: "a.java", line: 7, severity: "high",
                          vulnerability_type: "sql_injection", title: "t", merged_locations: 8 }),
    event(2, "summary", { closed: true, counters: { candidates: 12, findings: 1 } }),
  ];

  const findings = findingRows(events);
  assert.equal(findings[0]?.mergedLocations, 8);
  assert.deepEqual(latestCounters(events), { candidates: 12, findings: 1 });
  assert.equal(isClosed(events), true);
  assert.equal(isClosed([event(1, "finding", {})]), false);
  assert.deepEqual(latestCounters([event(1, "stage", { stage: "recon" })]), {});
});

test("agent 名单来自出现过的事件，不靠硬编码", () => {
  assert.deepEqual(
    agentsSeen([
      event(1, "agent_step", { agent: "validation" }),
      event(2, "agent_step", { agent: "discovery" }),
      event(3, "agent_step", { agent: "validation" }),
    ]),
    ["discovery", "validation"],
  );
});
