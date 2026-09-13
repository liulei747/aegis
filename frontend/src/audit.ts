/**
 * 审计轨迹的读法：把一串事件折叠成屏幕上要渲染的那几行。
 *
 * 这里全是纯函数，没有 React、没有 JSX，理由是测试：`node --test --experimental-strip-types`
 * 不走 JSX 转换，所以放在 `components.tsx` 里的东西测试碰不到（`routes.ts` 当初独立出来就是这个
 * 原因）。而轨迹的形状恰恰是最该被钉住的部分——它决定"这次审计到底做了什么"能不能被读出来。
 *
 * 一条贯穿全文件的原则：**折叠，不推断**。轨迹记的是事实，屏幕要回答的是"刚才在干什么"、
 * "哪些 agent 在跑"、"报了什么"，所以这里只做分组、取最后一次、按 seq 排序。任何需要猜的东西
 * （比如"没收到 agent_end 所以它失败了"）都不做：没有结束事件的 agent 就是**在跑**，
 * 那是事实，而猜成失败会让一个正常运行的审计看起来正在崩。
 */

import type { AuditEvent, AuditEventKind } from "./api/types.ts";

/** 编排层的阶段，按真实顺序。`prep` 是确定性预扫描（不调用模型），`close` 收尾，`findings` 汇总。 */
export const HARNESS_STAGES = [
  "prep",
  "recon",
  "threat_model",
  "plan",
  "discovery",
  "validation",
  "attack_path",
  "findings",
  "close",
] as const;

export const STAGE_LABEL: Readonly<Record<string, string>> = {
  prep: "预扫描",
  recon: "仓库勘察",
  threat_model: "威胁建模",
  plan: "范围规划",
  discovery: "探索代码",
  validation: "验证候选",
  attack_path: "攻击路径",
  findings: "汇总发现",
  close: "收尾",
};

/** 事件种类的中文名。屏幕上的过滤器用它，没有它就只能显示英文 id。 */
export const EVENT_LABEL: Readonly<Record<string, string>> = {
  stage: "阶段",
  agent_start: "开始",
  agent_step: "对话",
  agent_end: "结束",
  candidate: "候选",
  verdict: "研判",
  attack_path: "可达性",
  coverage: "覆盖",
  record: "写黑板",
  finding: "发现",
  summary: "收尾",
  error: "错误",
  unknown: "未知",
};

export interface StageRow {
  stage: string;
  label: string;
  state: string;
  round: number | null;
  seq: number;
}

/**
 * 每个阶段最后一次见到的状态，按真实阶段顺序排列（不是按出现顺序）。
 *
 * 固定的顺序是刻意的：一份"阶段表"如果按事件到达顺序排，重派发的轮次会让同一阶段出现两次、
 * 位置随机，而读者要的是"现在走到哪一步"。
 */
export function stageRows(events: AuditEvent[]): StageRow[] {
  const latest = new Map<string, StageRow>();
  for (const event of events) {
    if (event.kind !== "stage" || !event.stage) continue;
    latest.set(event.stage, {
      stage: event.stage,
      label: STAGE_LABEL[event.stage] ?? event.stage,
      state: event.state ?? "",
      round: typeof event.round === "number" ? event.round : null,
      seq: event.seq,
    });
  }
  const known = HARNESS_STAGES.filter((stage) => latest.has(stage));
  const extra = [...latest.keys()].filter(
    (stage) => !(HARNESS_STAGES as readonly string[]).includes(stage),
  );
  return [...known, ...extra].map((stage) => latest.get(stage)!);
}

export interface AgentRow {
  runId: string;
  agent: string;
  scope: string;
  /** `running` 表示还没有收到结束事件——这是事实，不是"可能失败了"。 */
  state: "running" | "finished" | "budget" | "error" | "unknown";
  steps: number;
  toolCalls: number;
  stopReason: string | null;
  startedSeq: number;
  lastSeq: number;
  parsed: boolean | null;
  error: string | null;
}

/** 所有 agent 运行，按开始顺序。这一屏的主表：14 个 scope 各自在干什么。 */
export function agentRows(events: AuditEvent[]): AgentRow[] {
  const runs = new Map<string, AgentRow>();
  const order: string[] = [];
  for (const event of events) {
    const runId = event.run_id;
    if (!runId) continue;
    if (event.kind === "agent_start") {
      if (!runs.has(runId)) order.push(runId);
      runs.set(runId, {
        runId,
        agent: event.agent ?? "",
        scope: event.scope ?? "",
        state: "running",
        steps: 0,
        toolCalls: 0,
        stopReason: null,
        startedSeq: event.seq,
        lastSeq: event.seq,
        parsed: null,
        error: null,
      });
      continue;
    }
    const row = runs.get(runId);
    if (!row) continue; // 一个没有 start 的 step：轨迹被截断过，不猜它的归属
    row.lastSeq = event.seq;
    if (event.kind === "agent_step") {
      row.steps += 1;
      if (event.tool) row.toolCalls += 1;
    }
    if (event.kind === "agent_end") {
      const reason = event.stop_reason ?? "";
      row.stopReason = reason;
      row.state =
        reason === "finished"
          ? "finished"
          : reason === "budget"
            ? "budget"
            : reason === "error"
              ? "error"
              : "unknown";
      if (typeof event.steps === "number") row.steps = event.steps;
      row.parsed = event.parsed ?? null;
      row.error = event.error ?? null;
    }
  }
  return order.map((runId) => runs.get(runId)!);
}

export interface DialogueRow {
  seq: number;
  at: string;
  agent: string;
  scope: string;
  runId: string;
  index: number | null;
  thought: string;
  tool: string | null;
  arguments: Record<string, unknown>;
  ok: boolean | null;
  summary: string;
  error: string | null;
}

/**
 * 每个 agent 的每一步：想法 + 工具调用 + 参数 + 工具回的东西。
 *
 * 这就是"全部 agent 的对话"。它只有 turn 粒度——一次模型往返是轨迹里最小的单位——因为
 * ReAct 必须等完整的一个 JSON 才能知道要调什么工具，逐字流对决策没有任何影响，只影响观感。
 */
export function dialogue(events: AuditEvent[]): DialogueRow[] {
  const rows: DialogueRow[] = [];
  for (const event of events) {
    if (event.kind !== "agent_step") continue;
    rows.push({
      seq: event.seq,
      at: event.at,
      agent: event.agent ?? "",
      scope: event.scope ?? "",
      runId: event.run_id ?? "",
      index: typeof event.index === "number" ? event.index : null,
      thought: event.thought ?? "",
      tool: event.tool ?? null,
      arguments: event.arguments ?? {},
      ok: event.ok ?? null,
      summary: event.summary ?? "",
      error: event.error ?? null,
    });
  }
  return rows;
}

export interface CoverageRow {
  scope: string;
  state: string;
  reason: string;
  files: number;
  unread: number;
  round: number | null;
  seq: number;
}

/** 每个 scope 最后一次覆盖率判定。按 scope 名排序，让重派发不会让行跳来跳去。 */
export function coverageRows(events: AuditEvent[]): CoverageRow[] {
  const latest = new Map<string, CoverageRow>();
  for (const event of events) {
    if (event.kind !== "coverage" || !event.scope) continue;
    latest.set(event.scope, {
      scope: event.scope,
      state: event.state ?? "",
      reason: event.reason ?? "",
      files: event.files ?? 0,
      unread: event.unread ?? 0,
      round: typeof event.round === "number" ? event.round : null,
      seq: event.seq,
    });
  }
  return [...latest.values()].sort((left, right) => left.scope.localeCompare(right.scope));
}

export interface FindingRow {
  findingId: string;
  candidateId: string;
  file: string;
  line: number | null;
  vulnerabilityType: string;
  severity: string;
  title: string;
  summary: string;
  mergedLocations: number;
}

export function findingRows(events: AuditEvent[]): FindingRow[] {
  return events
    .filter((event) => event.kind === "finding")
    .map((event) => ({
      findingId: event.finding_id ?? "",
      candidateId: event.candidate_id ?? "",
      file: event.file ?? "",
      line: typeof event.line === "number" ? event.line : null,
      vulnerabilityType: event.vulnerability_type ?? "",
      severity: event.severity ?? "",
      title: event.title ?? "",
      summary: event.summary ?? "",
      mergedLocations: event.merged_locations ?? 0,
    }));
}

export interface CandidateRow {
  candidateId: string;
  scope: string;
  file: string;
  line: number | null;
  vulnerabilityType: string;
  title: string;
  verdict: string | null;
  confidence: number | null;
  evidenceKind: string | null;
  reachable: boolean | null;
}

/** 候选与它们的研判/可达性，按 candidate_id 合并。轨迹里的顺序就是账本里的顺序。 */
export function candidateRows(events: AuditEvent[]): CandidateRow[] {
  const rows = new Map<string, CandidateRow>();
  const order: string[] = [];
  for (const event of events) {
    const id = event.candidate_id;
    if (!id) continue;
    if (event.kind === "candidate") {
      if (!rows.has(id)) order.push(id);
      rows.set(id, {
        candidateId: id,
        scope: event.scope ?? "",
        file: event.file ?? "",
        line: typeof event.line === "number" ? event.line : null,
        vulnerabilityType: event.vulnerability_type ?? "",
        title: event.title ?? "",
        verdict: null,
        confidence: null,
        evidenceKind: null,
        reachable: null,
      });
      continue;
    }
    const row = rows.get(id);
    if (!row) continue;
    if (event.kind === "verdict") {
      row.verdict = event.verdict ?? null;
      row.confidence = typeof event.confidence === "number" ? event.confidence : null;
      row.evidenceKind = event.evidence_kind ?? null;
    }
    if (event.kind === "attack_path") row.reachable = event.reachable ?? null;
  }
  return order.map((id) => rows.get(id)!);
}

/** 收尾事件里的计数；没有就是空的（还在跑）。 */
export function latestCounters(events: AuditEvent[]): Record<string, number> {
  for (let index = events.length - 1; index >= 0; index -= 1) {
    const counters = events[index]?.counters;
    if (counters && Object.keys(counters).length > 0) return counters;
  }
  return {};
}

export function isClosed(events: AuditEvent[]): boolean {
  return events.some((event) => event.kind === "summary");
}

export interface DialogueFilter {
  agent?: string;
  needle?: string;
  onlyProblems?: boolean;
}

/**
 * 过滤对话。`numbers` 是过滤前的总数，因为屏幕要能说"共 240 条，显示 60 条"——
 * 只显示一小截而不说被截断了，读起来就是"这次运行只有这么点东西"。
 */
export function filterDialogue(
  rows: DialogueRow[],
  filter: DialogueFilter,
): { rows: DialogueRow[]; total: number } {
  const needle = (filter.needle ?? "").trim().toLowerCase();
  const filtered = rows.filter((row) => {
    if (filter.agent && row.agent !== filter.agent) return false;
    if (filter.onlyProblems && row.error === null && row.ok !== false) return false;
    if (needle === "") return true;
    const haystack = `${row.agent} ${row.scope} ${row.tool ?? ""} ${row.thought} ${row.summary} ${
      row.error ?? ""
    } ${JSON.stringify(row.arguments)}`.toLowerCase();
    return haystack.includes(needle);
  });
  return { rows: filtered, total: rows.length };
}

/** 参与过这次运行的事件种类，用来生成过滤器（而不是列出所有种类，其中一半没出现）。 */
export function kindsSeen(events: AuditEvent[]): AuditEventKind[] {
  const seen = new Set<AuditEventKind>();
  for (const event of events) seen.add(event.kind);
  return [...seen];
}

/** 事件的 agent 名，去重后排序。 */
export function agentsSeen(events: AuditEvent[]): string[] {
  const seen = new Set<string>();
  for (const event of events) if (event.agent) seen.add(event.agent);
  return [...seen].sort();
}
