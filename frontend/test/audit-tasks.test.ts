import assert from "node:assert/strict";
import { test } from "node:test";
import { candidateRows, leadRows, taskEvidence, taskRows, taskStatusReason } from "../src/audit.ts";
import type { AuditEvent, AuditWorkItem } from "../src/api/types.ts";

const task: AuditWorkItem = {
  work_id: "W-1", scope_id: "scope-a", title: "下载权限", rationale: "外部入口",
  kind: "investigation", state: "planned", files: ["a.py"], completion_criteria: "权限证据",
  status_reason: "等待派发", candidate_ids: ["C-1"], read_files: 0, steps_used: 0,
  opened_at: "2026-09-17T00:00:00Z", closed_at: null, attempts: [],
};
function event(seq: number, fields: Partial<AuditEvent>): AuditEvent {
  return { seq, at: "2026-09-17T00:00:00Z", kind: "work_item", ...fields };
}

test("待办在 agent 启动前可见；乱序和重复事件不能回退状态", () => {
  const planned = event(1, { work: task });
  const done = event(4, { work: { ...task, state: "done" } });
  assert.equal(taskRows([planned])[0]?.state, "planned");
  assert.equal(taskRows([done, planned, done]).length, 1);
  assert.equal(taskRows([done, planned, done])[0]?.state, "done");
  assert.deepEqual(taskRows([event(2, { kind: "agent_start", scope: "scope-a" })]), []);
});

test("批量验证只关联自己的候选，且保留共享执行证据", () => {
  const current = { ...task, kind: "validation" as const, attempts: [{ run_id: "batch", agent: "validation_batch",
    started_at: task.opened_at, finished_at: null, stop_reason: "", steps: 0, error: "" }] };
  const events = [
    event(1, { kind: "verdict", candidate_id: "C-1", scope: "scope-a" }),
    event(2, { kind: "verdict", candidate_id: "C-2", scope: "scope-a" }),
    event(3, { kind: "agent_step", run_id: "batch", summary: "共享源码" }),
    event(4, { kind: "record", scope: "unrelated", text: "不相关" }),
  ];
  assert.deepEqual(taskEvidence(events, current).map(e => e.seq), [1, 3]);
});


test("线索状态取最新快照，旧 record 仍兼容", () => {
  const lead = { lead_id: "L-1", question: "对象授权", status: "pending", source_work_id: "W-1",
    linked_work_id: "", processing_reason: "", file: "a.py", line: 1 };
  assert.deepEqual(leadRows([event(1, { kind: "record", text: "旧线索" })]), []);
  const pending = event(2, { kind: "record", lead });
  const linked = event(4, { kind: "record", lead: { ...lead, status: "linked", linked_work_id: "W-2" } });
  assert.equal(leadRows([linked, pending, linked])[0]?.status, "linked");
  assert.equal(leadRows([linked, pending, linked]).length, 1);
});

test("旧任务从最后一次模型失败补全可操作的受阻原因", () => {
  const blocked = { ...task, state: "blocked" as const, status_reason: "未知执行错误", attempts: [{
    run_id: "discovery:scope-a", agent: "discovery", started_at: task.opened_at,
    finished_at: task.opened_at, stop_reason: "error", steps: 1, error: "",
  }] };
  const evidence = [event(3, { kind: "agent_step", run_id: "discovery:scope-a",
    thought: "model call failed: AIUnavailable: SSL UNEXPECTED_EOF_WHILE_READING" })];
  const reason = taskStatusReason(blocked, taskEvidence(evidence, blocked));
  assert.match(reason, /HTTPS\/TLS 连接被提前关闭/);
  assert.match(reason, /本任务可重试/);
  assert.match(reason, /UNEXPECTED_EOF_WHILE_READING/);
});

test("关键证据变化撤下旧裁决和路径，复核事件恢复当前结果", () => {
  const candidate = event(1, { kind: "candidate", candidate_id: "C-1", file: "a.py", title: "x" });
  const verdict = event(2, { kind: "verdict", candidate_id: "C-1", verdict: "confirmed", confidence: 0.9 });
  const path = event(3, { kind: "attack_path", candidate_id: "C-1", reachable: true });
  const changed = event(4, { kind: "record", record_kind: "evidence_changed", candidate_ids: ["C-1"], evidence_version: 2 });
  const rows = candidateRows([changed, candidate, path, verdict]);
  assert.equal(rows[0]?.verdict, null);
  assert.equal(rows[0]?.reachable, null);
  assert.equal(taskEvidence([changed], task).length, 1);
  const reviewed = event(5, { kind: "verdict", candidate_id: "C-1", verdict: "rejected", confidence: 0.8 });
  assert.equal(candidateRows([reviewed, changed, candidate, verdict, path])[0]?.verdict, "rejected");
});
