/**
 * 错误体的读法。
 *
 * 钉的是一件事：**网关说的话不能被界面压成一句状态码**。用户报的"提交审计 409"就是这么来的 ——
 * 后端明明回了"上一次尝试已取消，带 ?force=true 重提交"，但 `messageFor` 只认第一层字符串，
 * 于是界面上只剩 `409 Conflict`，而且恢复所需的 `job_id` / `state` 也一起丢了。
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import { detailText, messageFor, previousAttempt, type ApiError } from "../src/api/errors.ts";

/** 网关在"任务去重拒绝"时真正返回的那个形状，逐字抄自一次实测。 */
const conflict = {
  detail: {
    detail: "previous attempt canceled: no reason recorded; resubmit with ?force=true to run it again",
    job_id: "J-5e7de89bde6365f1e1dbdeb09745aa85c90c2ff2",
    state: "canceled",
  },
};

test("a flat detail string is the message", () => {
  assert.equal(messageFor(409, "Conflict", { detail: "项目 payment-sys 已存在" }), "项目 payment-sys 已存在");
});

test("a nested detail object is unwrapped, not flattened into the status line", () => {
  // 这一条就是用户看到"409"而没有解释的原因。
  assert.equal(messageFor(409, "Conflict", conflict), conflict.detail.detail);
  assert.notEqual(messageFor(409, "Conflict", conflict), "409 Conflict");
});

test("an unreadable body still says something", () => {
  assert.equal(messageFor(502, "Bad Gateway", null), "502 Bad Gateway");
  assert.equal(messageFor(502, "Bad Gateway", "<html>"), "502 Bad Gateway");
  assert.equal(messageFor(502, "Bad Gateway", { detail: 42 }), "502 Bad Gateway");
  assert.equal(detailText(undefined), null);
});

test("previousAttempt reads the job a 409 is refusing on", () => {
  const error: ApiError = { status: 409, detail: "…", body: conflict };
  assert.deepEqual(previousAttempt(error), {
    jobId: "J-5e7de89bde6365f1e1dbdeb09745aa85c90c2ff2",
    state: "canceled",
  });
});

test("previousAttempt stays quiet when there is nothing to re-run", () => {
  // 一个普通的 409（比如项目重名）不该长出一个"重新运行"按钮。
  assert.equal(previousAttempt({ status: 409, detail: "x", body: { detail: "项目已存在" } }), null);
  // 别的状态码也不是这个意思。
  assert.equal(previousAttempt({ status: 400, detail: "x", body: conflict }), null);
  // 形状对但缺字段：宁可不给按钮，也不要给一个指向错任务的按钮。
  assert.equal(previousAttempt({ status: 409, detail: "x", body: { detail: { state: "canceled" } } }), null);
  assert.equal(previousAttempt({ status: 409, detail: "x", body: { detail: { job_id: "J-1" } } }), null);
  assert.equal(previousAttempt({ status: 409, detail: "x" }), null);
});
