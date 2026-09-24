import { test } from "node:test";
import assert from "node:assert/strict";
import { cleanAuditTuning, loadAuditTuning, saveAuditTuning } from "../src/auditTuning.ts";

test("审计参数允许服务商自行决定输出上限，并丢弃越界值", () => {
  assert.deepEqual(cleanAuditTuning({ max_tokens: 0, timeout_s: 240, concurrency: 99 }), {
    max_tokens: 0, timeout_s: 240,
  });
  assert.deepEqual(cleanAuditTuning({ max_tokens: 1024, max_rounds: 3 }), { max_rounds: 3 });
});

test("保存的浏览器默认值会被下次审计读取", () => {
  const values = new Map<string, string>();
  Object.defineProperty(globalThis, "localStorage", { configurable: true, value: {
    getItem: (key: string) => values.get(key) ?? null,
    setItem: (key: string, value: string) => values.set(key, value),
  } });
  try {
    saveAuditTuning({ max_tokens: 0, steps_per_agent: 12, temperature: 0.2 });
    assert.deepEqual(loadAuditTuning(), { max_tokens: 0, steps_per_agent: 12, temperature: 0.2 });
  } finally {
    Reflect.deleteProperty(globalThis, "localStorage");
  }
});
