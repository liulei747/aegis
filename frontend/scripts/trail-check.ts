/**
 * 用真实轨迹检查审计屏的读法。
 *
 * 这个脚本存在的原因很具体：后端写事件、前端折事件，两边是两种语言、两套类型，中间没有任何
 * 编译期检查。单元测试用的是手工造的 JSON（形状是"我以为后端会写什么"），所以真实轨迹一旦
 * 有字段名或形状的出入，屏幕上表现为**某一块永远是空的**——而空白看起来和"这次运行本来就没
 * 有这些事件"一模一样。
 *
 * 它做三件事：读文件、跑与屏幕完全相同的那几个折叠函数、报告每一块会渲染出多少行。
 * 有任何一块是 0 行而文件里明明有对应事件时，它会以非零码退出。
 *
 * 用法：
 *   python -m services.harness run --workspace <repo> --out <dir> --dry-run
 *   node --experimental-strip-types frontend/scripts/trail-check.ts <out>/<run-id>/trail.jsonl
 */

import { readFileSync } from "node:fs";

import {
  agentRows,
  candidateRows,
  coverageRows,
  dialogue,
  findingRows,
  isClosed,
  latestCounters,
  stageRows,
} from "../src/audit.ts";
import type { AuditEvent } from "../src/api/types.ts";

const target = process.argv[2];
if (!target) {
  console.error("用法：node --experimental-strip-types frontend/scripts/trail-check.ts <trail.jsonl>");
  process.exit(2);
}

const events: AuditEvent[] = [];
let damaged = 0;
for (const line of readFileSync(target, "utf8").split("\n")) {
  const trimmed = line.trim();
  if (trimmed === "") continue;
  try {
    const parsed = JSON.parse(trimmed) as AuditEvent;
    if (typeof parsed.seq === "number" && typeof parsed.kind === "string") events.push(parsed);
    else damaged += 1;
  } catch {
    damaged += 1;
  }
}

const kinds = new Map<string, number>();
for (const event of events) kinds.set(event.kind, (kinds.get(event.kind) ?? 0) + 1);

const sections: Array<[string, number, string[]]> = [
  ["阶段", stageRows(events).length, ["stage"]],
  ["agent", agentRows(events).length, ["agent_start", "agent_end"]],
  ["对话", dialogue(events).length, ["agent_step"]],
  ["覆盖率", coverageRows(events).length, ["coverage"]],
  ["候选", candidateRows(events).length, ["candidate"]],
  ["发现", findingRows(events).length, ["finding"]],
];

console.log(`${target}`);
console.log(`事件 ${events.length} 条，未解析 ${damaged} 行，收尾=${isClosed(events)}`);
console.log("事件种类：" + [...kinds].map(([kind, count]) => `${kind}=${count}`).join(" "));
console.log("计数器：" + JSON.stringify(latestCounters(events)));
console.log("");
let problems = 0;
for (const [label, rows, sources] of sections) {
  const present = sources.filter((kind) => (kinds.get(kind) ?? 0) > 0);
  const flag = rows === 0 && present.length > 0 ? "  <-- 有事件却渲染不出行" : "";
  if (flag) problems += 1;
  console.log(`${label.padEnd(6)} ${String(rows).padStart(5)} 行   （来源事件：${present.join(", ") || "无"}）${flag}`);
}

if (problems > 0) {
  console.error(`\n${problems} 个区块有事件但渲染为空：折叠逻辑与轨迹的形状对不上。`);
  process.exit(1);
}
console.log("\n每一块都能从真实轨迹里读出内容。");
