/**
 * 文案映射的测试。
 *
 * 这里测的不是"翻译对不对"，而是**回退行为**：整个 `labels.ts` 的设计前提是"不认识的 API 值
 * 原样显示"。这个前提一旦破了，症状是某个角标显示空白或 `undefined`，而那是要有人恰好看到
 * 那个包才会发现的。
 *
 * 另外钉住一个真实踩过的坑：严重度有**两套**词表 —— 模型研判的 critical/high/… 与 SARIF 的
 * error/warning/note/info —— 同一个 `SeverityBadge` 两种都渲染。只查一张表的版本会让扫描命中
 * 的角标一直显示英文 "error"。
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import {
  JOB_KIND,
  JOB_STATE,
  label,
  SEVERITY,
  severityLabel,
  STAGE,
  STAGE_STATE,
  TRUST,
  VERDICT,
} from "../src/labels.ts";

test("认识的 API 值给出中文", () => {
  assert.equal(label(JOB_STATE, "running"), "运行中");
  assert.equal(label(JOB_STATE, "canceled"), "已取消");
  assert.equal(label(VERDICT, "needs_more_context"), "证据不足");
  assert.equal(label(TRUST, "guess"), "猜测");
  assert.equal(label(STAGE_STATE, "skipped"), "已跳过");
  // 两个 AI 模块的名字必须能区分深浅：一个是"自己找问题"，一个是"判断已有的点"。
  assert.equal(label(JOB_KIND, "ai_fanout"), "快速研判");
  assert.equal(label(JOB_KIND, "audit"), "深度审计");
  assert.equal(label(STAGE, "expand"), "扩展调用图");
});

test("不认识的值原样显示，绝不返回 undefined", () => {
  // 后端将来新增一个状态时，读者应该看到它的原始拼写（可以据此报一个问题），
  // 而不是一格空白或 "undefined"。
  assert.equal(label(JOB_STATE, "reaped"), "reaped");
  assert.equal(label(TRUST, "vendor-claimed"), "vendor-claimed");
  assert.equal(label({}, "anything"), "anything");
});

test("缺值渲染成破折号", () => {
  assert.equal(label(JOB_STATE, null), "—");
  assert.equal(label(JOB_STATE, undefined), "—");
  assert.equal(severityLabel(null), "—");
});

test("严重度两套词表都能翻：研判等级与 SARIF 等级", () => {
  assert.equal(severityLabel("critical"), "致命");
  assert.equal(severityLabel("informational"), "提示");
  // SARIF 等级。这几个不在 SEVERITY 里，漏掉它们就是曾经那个"扫描命中角标显示英文"的 bug。
  assert.equal(severityLabel("error"), "错误");
  assert.equal(severityLabel("warning"), "警告");
  assert.equal(severityLabel("note"), "提示");
  assert.equal(severityLabel("info"), "信息");
});

test("两套严重度词表是分开的，不是同一张表", () => {
  // 合并成一张表的话，一个未来的 SARIF 等级会和研判等级静默相撞。
  // 这里用"error 不在 SEVERITY 里"把这个结构决定固定下来。
  assert.ok(!("error" in SEVERITY), "SARIF 的等级不该混进研判词表");
  assert.equal(severityLabel("nonsense-level"), "nonsense-level");
});
