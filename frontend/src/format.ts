/**
 * Every number this front-end computes, in one file.
 *
 * The API publishes facts -- timestamps, token counts, byte counts, ratios it was told by a
 * provider -- and this layer turns them into what a screen shows. That is the deliberate half
 * of the split with the backend: nothing here re-derives a fact, and nothing the backend
 * already computed is recomputed differently.
 *
 * Kept pure and free of React so `test/format.test.ts` can pin the arithmetic directly.
 */

import type {
  AIReport,
  AITrafficEntry,
  BundleSummary,
  JobSummary,
  ProjectRecord,
  ProjectSource,
  TokenUsage,
  TrafficEntry,
} from "./api/types.ts";

export function formatCount(value: number | null | undefined): string {
  if (value === null || value === undefined || Number.isNaN(value)) return "—";
  return value.toLocaleString("zh-CN");
}

/** A share in 0..1 as a percentage. Null and NaN render as an em dash, never as "0%". */
export function formatPercent(ratio: number | null | undefined, digits = 0): string {
  if (ratio === null || ratio === undefined || Number.isNaN(ratio)) return "—";
  return `${(ratio * 100).toFixed(digits)}%`;
}

export function formatDurationMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined || Number.isNaN(ms)) return "—";
  if (ms < 1000) return `${Math.round(ms)} 毫秒`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(ms < 10_000 ? 1 : 0)} 秒`;
  const minutes = Math.floor(ms / 60_000);
  const seconds = Math.round((ms % 60_000) / 1000);
  return `${minutes} 分 ${seconds} 秒`;
}

/** Seconds, as the AI report records elapsed time. */
export function formatSeconds(seconds: number | null | undefined): string {
  if (seconds === null || seconds === undefined) return "—";
  return formatDurationMs(seconds * 1000);
}

export function formatTimestamp(iso: string | null | undefined): string {
  if (!iso) return "—";
  const date = new Date(iso);
  if (Number.isNaN(date.getTime())) return iso;
  return date.toLocaleString("zh-CN");
}

/** "3 min ago" / "in 2 h", for list views where absolute time is noise. */
export function formatRelative(iso: string | null | undefined, now: Date = new Date()): string {
  if (!iso) return "—";
  const then = new Date(iso);
  if (Number.isNaN(then.getTime())) return iso;
  const seconds = Math.round((now.getTime() - then.getTime()) / 1000);
  const future = seconds < 0;
  const magnitude = Math.abs(seconds);
  let label: string;
  if (magnitude < 5) return "刚刚";
  if (magnitude < 60) label = `${magnitude} 秒`;
  else if (magnitude < 3600) label = `${Math.round(magnitude / 60)} 分钟`;
  else if (magnitude < 86_400) label = `${Math.round(magnitude / 3600)} 小时`;
  else label = `${Math.round(magnitude / 86_400)} 天`;
  return `${label}${future ? "后" : "前"}`;
}

/** Share of a provider's input tokens that came from its cache, or null when unreported. */
export function cacheHitRatio(usage: TokenUsage | null | undefined): number | null {
  if (!usage) return null;
  if (!usage.prompt_tokens || usage.cached_tokens === null || usage.cached_tokens === undefined) {
    return null;
  }
  return usage.cached_tokens / usage.prompt_tokens;
}

/**
 * How many contexts the model answered about, and how many it did not.
 *
 * The API used to publish these; it now publishes the calls and this computes the split.
 * `failed` is `contexts - parsed` rather than a separate count so the two can never disagree.
 */
export function countsOf(report: AIReport | null | undefined): {
  contexts: number;
  parsed: number;
  failed: number;
} {
  const calls = report?.calls ?? [];
  const parsed = calls.filter((call) => call.parsed).length;
  return { contexts: calls.length, parsed, failed: calls.length - parsed };
}

/** Token totals across every call in a report, for the cost line. */
export function tokenTotals(report: AIReport | null | undefined): {
  prompt: number;
  completion: number;
  cached: number;
  /** Weighted cache share over all prompt tokens, or null when nothing reported. */
  cacheShare: number | null;
} {
  let prompt = 0;
  let completion = 0;
  let cached = 0;
  for (const call of report?.calls ?? []) {
    prompt += call.usage?.prompt_tokens ?? 0;
    completion += call.usage?.completion_tokens ?? 0;
    cached += call.usage?.cached_tokens ?? 0;
  }
  return { prompt, completion, cached, cacheShare: prompt > 0 ? cached / prompt : null };
}

export interface Project {
  /** The workspace path; uniquely identifies a project, since there is no registry. */
  workspace: string;
  name: string;
  bundles: BundleSummary[];
  jobs: JobSummary[];
  bundleCount: number;
  jobCount: number;
  /**
   * Analysis contexts across this project's bundles, summed from each bundle's `focus_count`.
   *
   * Not a finding count: the bundles *list* carries no finding total, and inventing one from
   * `coverage` would be reading a different number under this name.
   */
  contextCount: number;
  /** Newest activity across the bundles and jobs that mention this workspace. */
  lastActivity: string | null;
}

/** The last path segment, which is what a person calls the project. */
function projectName(workspace: string): string {
  const parts = workspace.replace(/[\\/]+$/, "").split(/[\\/]/).filter(Boolean);
  return parts.length > 0 ? (parts[parts.length - 1] as string) : workspace;
}

function newest(values: Array<string | null | undefined>): string | null {
  let best: string | null = null;
  for (const value of values) {
    if (!value) continue;
    if (best === null || value > best) best = value;
  }
  return best;
}

/**
 * 没有记录工作区的分析包归到这一行。
 *
 * 导出而不是各处再写一遍：这是一个**哨兵值**，不是展示文案 —— 深度审计要用它判断某个"项目"
 * 到底有没有可用的路径（`(未知工作区)` 没有），两处写法不一致会让一个不能审计的行出现在选择器
 * 里，点了才报错。
 */
export const UNKNOWN_WORKSPACE = "(未知工作区)";

/**
 * The project list, derived from what the API already returns.
 *
 * There is no project entity in the backend: a "project" is a workspace path that jobs and
 * bundles were recorded against. Grouping here rather than adding an endpoint keeps that
 * honest -- the screen cannot claim more structure than the data has -- and it is the same
 * rule the rest of this file follows, that the front-end decides how to present facts.
 *
 * Bundles with no recorded workspace (older ones) are grouped under an explicit
 * `(unknown workspace)` row rather than dropped, because a bundle that exists but cannot be
 * attributed is a finding about the data, not a row to hide.
 */
export function projectsFrom(
  bundles: BundleSummary[],
  jobs: JobSummary[],
  unknownLabel = UNKNOWN_WORKSPACE,
): Project[] {
  const byWorkspace = new Map<string, Project>();

  const ensure = (workspace: string): Project => {
    const existing = byWorkspace.get(workspace);
    if (existing) return existing;
    const created: Project = {
      workspace,
      name: workspace === unknownLabel ? unknownLabel : projectName(workspace),
      bundles: [],
      jobs: [],
      bundleCount: 0,
      jobCount: 0,
      contextCount: 0,
      lastActivity: null,
    };
    byWorkspace.set(workspace, created);
    return created;
  };

  for (const bundle of bundles) {
    ensure(bundle.workspace ?? unknownLabel).bundles.push(bundle);
  }
  for (const job of jobs) {
    ensure(job.workspace ?? unknownLabel).jobs.push(job);
  }

  for (const project of byWorkspace.values()) {
    project.bundleCount = project.bundles.length;
    project.jobCount = project.jobs.length;
    project.contextCount = project.bundles.reduce(
      (total, bundle) => total + (bundle.focus_count ?? 0),
      0,
    );
    project.lastActivity = newest([
      ...project.bundles.map((bundle) => bundle.created_at),
      ...project.jobs.map((job) => job.finished_at ?? job.started_at ?? job.submitted_at),
    ]);
  }

  return [...byWorkspace.values()].sort((left, right) => {
    const a = left.lastActivity ?? "";
    const b = right.lastActivity ?? "";
    if (a !== b) return a < b ? 1 : -1;
    return left.name.localeCompare(right.name);
  });
}

/**
 * 项目管理页的一行：注册表（新建的项目）与派生数据（任务/分析包上记录的 workspace）的并集。
 *
 * 两边都要，缺一不可：
 *
 * * 只看派生 —— 刚建好、还没分析完的项目**不显示**，用户会以为自己点失败了；
 * * 只看注册表 —— 功能上线之前就存在的那些包与任务**全部消失**，等于把历史数据藏起来。
 *
 * 所以并集按 `workspace` 路径做键，`registered` 标明这一行有没有注册表条目。
 */
export interface ProjectRow {
  workspace: string;
  name: string;
  registered: boolean;
  origin: string | null;
  source: ProjectSource | null;
  ref: string | null;
  commit: string | null;
  createdAt: string | null;
  /** 新建时自动提交的那次分析任务。 */
  jobId: string | null;
  /** 检测到的语言（仅注册表项目有；历史行是空对象）。 */
  languages: Record<string, number>;
  bundleCount: number;
  jobCount: number;
  contextCount: number;
  analysed: number;
  lastActivity: string | null;
}

export function mergeProjects(
  records: ProjectRecord[],
  bundles: BundleSummary[],
  jobs: JobSummary[],
  unknownLabel = "(未知工作区)",
): ProjectRow[] {
  const derived = projectsFrom(bundles, jobs, unknownLabel);
  const rows = new Map<string, ProjectRow>();

  for (const project of derived) {
    rows.set(project.workspace, {
      workspace: project.workspace,
      name: project.name,
      registered: false,
      origin: null,
      source: null,
      ref: null,
      commit: null,
      createdAt: null,
      jobId: null,
      languages: {},
      bundleCount: project.bundleCount,
      jobCount: project.jobCount,
      contextCount: project.contextCount,
      analysed: project.bundles.filter((bundle) => bundle.has_ai_report).length,
      lastActivity: project.lastActivity,
    });
  }

  for (const record of records) {
    const existing = rows.get(record.workspace);
    if (existing) {
      existing.registered = true;
      // 注册表里的名字是用户/仓库给的，比路径末段更准确。
      existing.name = record.name;
      existing.origin = record.origin;
      existing.source = record.source;
      existing.ref = record.ref;
      existing.commit = record.commit;
      existing.createdAt = record.created_at;
      existing.jobId = record.job_id;
      existing.languages = record.languages ?? {};
      existing.lastActivity = newest([existing.lastActivity, record.created_at]);
    } else {
      rows.set(record.workspace, {
        workspace: record.workspace,
        name: record.name,
        registered: true,
        origin: record.origin,
        source: record.source,
        ref: record.ref,
        commit: record.commit,
        createdAt: record.created_at,
        jobId: record.job_id,
        languages: record.languages ?? {},
        bundleCount: 0,
        jobCount: 0,
        contextCount: 0,
        analysed: 0,
        lastActivity: record.created_at,
      });
    }
  }

  return [...rows.values()].sort((left, right) => {
    const a = left.lastActivity ?? "";
    const b = right.lastActivity ?? "";
    if (a !== b) return a < b ? 1 : -1;
    return left.name.localeCompare(right.name);
  });
}

/**
 * 一门语言在这个部署里能分析到什么程度。
 *
 * `call_graph` 靠语言服务器（镜像里真的有二进制才算），`taint` 靠 Joern 的单一前端
 * （目前只有 Python）。所以一门语言可能"能画调用图但不能追污点"，也可能两者都不行 ——
 * 后者意味着这个项目只会得到静态规则命中，其它什么都没有。
 */
export type LanguageDepth = "full" | "call_graph" | "findings_only";

export function languageDepth(
  language: string,
  deep: { call_graph: string[]; taint: string[] } | null | undefined,
): LanguageDepth {
  if (!deep) return "full"; // 网关没报能力时不猜：宁可不说，也不要平白警告
  const taint = deep.taint.includes(language);
  const graph = deep.call_graph.includes(language);
  if (taint && graph) return "full";
  if (graph) return "call_graph";
  return "findings_only";
}

/** 项目里出现、但本部署连调用图都画不出来的语言。空数组表示没有这个顾虑。 */
export function languagesWithoutCallGraph(
  languages: Record<string, number>,
  deep: { call_graph: string[]; taint: string[] } | null | undefined,
): string[] {
  if (!deep) return [];
  return Object.keys(languages).filter(
    (language) => languageDepth(language, deep) === "findings_only",
  );
}

/** 语言占比的一行摘要，如 `java ×51 · sql ×2`。 */
export function languageSummary(languages: Record<string, number>, limit = 3): string {
  const entries = Object.entries(languages);
  if (entries.length === 0) return "";
  const shown = entries.slice(0, limit).map(([name, count]) => `${name} ×${count}`);
  if (entries.length > limit) shown.push(`等 ${entries.length} 种`);
  return shown.join(" · ");
}

/** Job counts by state, for the overview. */export function jobsByState(jobs: JobSummary[]): Record<string, number> {
  const counts: Record<string, number> = {};
  for (const job of jobs) {
    counts[job.state] = (counts[job.state] ?? 0) + 1;
  }
  return counts;
}

const SEVERITY_ORDER = ["critical", "high", "medium", "low", "informational"] as const;

/** Whether a job is still in flight, which decides if cancel is meaningful and if it counts. */
export function isActive(state: string): boolean {
  return state === "queued" || state === "running";
}

/**
 * Progress, and an honest denominator.
 *
 * `units_total` is 0 when the stage cannot know how much work there is -- the scan stage is one
 * synchronous subprocess wait. Rendering "3 / 0" or a 100%-full bar there would be a claim the
 * pipeline never made, so the total is reported as unknown instead.
 */
export function formatUnits(done: number, total: number, label: string): string {
  const noun = label || "单位";
  if (!total || total <= 0) return `${formatCount(done)} ${noun} · 总数未知`;
  return `${formatCount(done)} / ${formatCount(total)} ${noun}`;
}

/** A share of a total, as a 0..1 fraction, or null when the total is unknown. */
export function share(done: number, total: number): number | null {
  if (!total || total <= 0) return null;
  return done / total;
}

/** The worst severity present, by the order above; null when there is none. */
export function worstSeverity(severities: Array<string | null | undefined>): string | null {
  for (const candidate of SEVERITY_ORDER) {
    if (severities.includes(candidate)) return candidate;
  }
  return null;
}

// ─────────────────────────────────────── 概览页的聚合
//
// 下面这些是概览卡片上的数字。它们全部由已有的接口响应算出，**没有为概览新增端点** ——
// 否则"运行中"就会有两个定义，而两个定义迟早会不一致。聚合放在这里而不是组件里，是为了
// 能被 `test/format.test.ts` 直接钉住：概览上最容易被悄悄算错的正是这类总数。

/** 全部分析包合计。口径来自每个分析包列表里的 `coverage`（一个已经算好的漏斗摘要）。 */
export interface CoverageTotals {
  bundles: number;
  /** 扫描器产出的命中总数。 */
  findings: number;
  /** 进入分析包的命中。 */
  bundled: number;
  /** 被裁剪规则丢掉的。 */
  rejected: number;
  /** 因重复被合并的。 */
  deduped: number;
  /** 分析上下文总数（各包 `focus_count` 之和）。 */
  contexts: number;
  tokens: number;
  durationMs: number;
  workspaces: number;
  /** 来自"完全没有命中"的扫描的分析包数 —— 记为可疑，而不是干净结果。 */
  suspicious: number;
  analysed: number;
  prunes: number;
  degradations: number;
}

export function coverageTotals(bundles: BundleSummary[]): CoverageTotals {
  const totals: CoverageTotals = {
    bundles: bundles.length,
    findings: 0,
    bundled: 0,
    rejected: 0,
    deduped: 0,
    contexts: 0,
    tokens: 0,
    durationMs: 0,
    workspaces: 0,
    suspicious: 0,
    analysed: 0,
    prunes: 0,
    degradations: 0,
  };
  const workspaces = new Set<string>();
  for (const bundle of bundles) {
    totals.findings += bundle.coverage?.discoverable ?? 0;
    totals.bundled += bundle.coverage?.bundled ?? 0;
    totals.rejected += bundle.coverage?.rejected ?? 0;
    totals.deduped += bundle.coverage?.deduped ?? 0;
    totals.contexts += bundle.focus_count ?? 0;
    totals.tokens += bundle.estimated_tokens ?? 0;
    totals.durationMs += bundle.duration_ms ?? 0;
    totals.prunes += bundle.prune_count;
    totals.degradations += bundle.degradation_count;
    if (bundle.zero_findings_suspicious) totals.suspicious += 1;
    if (bundle.has_ai_report) totals.analysed += 1;
    if (bundle.workspace) workspaces.add(bundle.workspace);
  }
  totals.workspaces = workspaces.size;
  return totals;
}

export interface ProviderShare {
  provider: string;
  bundles: number;
  /** 使用该来源的分析包占比，分母是分析包总数。 */
  share: number | null;
}

/** 数据来源分布：有多少个分析包用到了每个来源。用于一眼看出多少包依赖启发式。 */
export function providerMix(bundles: BundleSummary[]): ProviderShare[] {
  const counts = new Map<string, number>();
  for (const bundle of bundles) {
    for (const provider of new Set(bundle.providers)) {
      counts.set(provider, (counts.get(provider) ?? 0) + 1);
    }
  }
  return [...counts.entries()]
    .map(([provider, count]) => ({
      provider,
      bundles: count,
      share: share(count, bundles.length),
    }))
    .sort((left, right) => right.bundles - left.bundles || left.provider.localeCompare(right.provider));
}

/** 快速研判的合计，来自各分析包的原始 `ai/report.json`（字段名是契约，不改）。 */
export interface AITotals {
  /** 参与合计的分析包数。 */
  bundles: number;
  contexts: number;
  parsed: number;
  failed: number;
  truePositive: number;
  falsePositive: number;
  needsContext: number;
  prompt: number;
  completion: number;
  cached: number;
  cacheShare: number | null;
  /** 可解析研判的置信度均值，无可解析项时为 null。 */
  meanConfidence: number | null;
}

export function aiTotals(reports: AIReport[]): AITotals {
  const totals: AITotals = {
    bundles: reports.length,
    contexts: 0,
    parsed: 0,
    failed: 0,
    truePositive: 0,
    falsePositive: 0,
    needsContext: 0,
    prompt: 0,
    completion: 0,
    cached: 0,
    cacheShare: null,
    meanConfidence: null,
  };
  let confidenceSum = 0;
  let confidenceCount = 0;
  for (const report of reports) {
    for (const call of report.calls) {
      totals.contexts += 1;
      if (call.parsed) totals.parsed += 1;
      else totals.failed += 1;
      totals.prompt += call.usage?.prompt_tokens ?? 0;
      totals.completion += call.usage?.completion_tokens ?? 0;
      totals.cached += call.usage?.cached_tokens ?? 0;
      const kind = call.verdict?.verdict;
      if (kind === "true_positive") totals.truePositive += 1;
      else if (kind === "false_positive") totals.falsePositive += 1;
      else if (kind === "needs_more_context") totals.needsContext += 1;
      if (call.verdict) {
        confidenceSum += call.verdict.confidence;
        confidenceCount += 1;
      }
    }
  }
  totals.cacheShare = share(totals.cached, totals.prompt);
  totals.meanConfidence = confidenceCount > 0 ? confidenceSum / confidenceCount : null;
  return totals;
}

export interface PathMetric {
  /** `方法 路径`，用于分组与显示。 */
  label: string;
  count: number;
  /** 平均耗时（毫秒）。 */
  avgMs: number;
  /** 其中 4xx/5xx 的条数。 */
  errors: number;
}

/** 调用指标：把环形缓冲里的请求按「方法 + 路径」聚合。 */
export function trafficByPath(entries: TrafficEntry[], limit = 6): PathMetric[] {
  const groups = new Map<string, { count: number; totalMs: number; errors: number }>();
  for (const entry of entries) {
    const label = `${entry.method} ${entry.path}`;
    const group = groups.get(label) ?? { count: 0, totalMs: 0, errors: 0 };
    group.count += 1;
    group.totalMs += entry.duration_ms;
    if (entry.status >= 400) group.errors += 1;
    groups.set(label, group);
  }
  return [...groups.entries()]
    .map(([label, group]) => ({
      label,
      count: group.count,
      avgMs: group.count > 0 ? group.totalMs / group.count : 0,
      errors: group.errors,
    }))
    .sort((left, right) => right.count - left.count)
    .slice(0, limit);
}

export interface KindQueue {
  kind: string;
  running: number;
  queued: number;
  finished: number;
}

/** 任务队列：按任务类型统计在跑 / 在排 / 已完成。 */
export function queueByKind(jobs: JobSummary[], kinds: string[]): KindQueue[] {
  const byKind = new Map<string, KindQueue>();
  for (const kind of kinds) byKind.set(kind, { kind, running: 0, queued: 0, finished: 0 });
  for (const job of jobs) {
    const entry = byKind.get(job.kind) ?? { kind: job.kind, running: 0, queued: 0, finished: 0 };
    if (job.state === "running") entry.running += 1;
    else if (job.state === "queued") entry.queued += 1;
    else entry.finished += 1;
    byKind.set(job.kind, entry);
  }
  return kinds.map((kind) => byKind.get(kind)!).filter(Boolean);
}

export interface ModelCallTotals {
  /** 这一页里的往返次数（重试各算一次）。 */
  attempts: number;
  /** 其中失败的次数。 */
  failures: number;
  /** 逻辑调用的次数估计：减去"同一次调用里的非首次尝试"。 */
  retried: number;
  meanMs: number | null;
  promptTokens: number;
  completionTokens: number;
  cachedTokens: number;
  /** 缓存 token 占输入的比例，样本里没有任何 token 数据时为 null（而不是 0）。 */
  cacheShare: number | null;
  /** 逐条聚合后的来源数，用于"几个 agent 在跟模型说话"。 */
  callers: number;
}

/**
 * 模型调用的汇总。
 *
 * `retried` 而不是"调用数"：这一页里的每一行都是一次**往返**，重试是独立的一行（那是这张表
 * 存在的意义 —— 一次调用花掉三次往返必须看得见）。所以"有几次是重试"只能数出来：
 * 尝试次数减去每个来源的首次尝试数。把它叫做"调用数"会让人以为一次调用只有一行。
 *
 * token 只统计有数据的行：把缺失当成 0 会让平均值随"有没有 usage"而不是随真实用量变化。
 */
export function modelCallTotals(entries: AITrafficEntry[]): ModelCallTotals {
  let failures = 0;
  let totalMs = 0;
  let withMs = 0;
  let promptTokens = 0;
  let completionTokens = 0;
  let cachedTokens = 0;
  let tokenRows = 0;
  const firstAttempts = new Map<string, number>();
  const callers = new Set<string>();

  for (const entry of entries) {
    if (!entry.ok) failures += 1;
    callers.add(entry.caller);
    if (typeof entry.duration_ms === "number") {
      totalMs += entry.duration_ms;
      withMs += 1;
    }
    if (typeof entry.prompt_tokens === "number") {
      promptTokens += entry.prompt_tokens;
      tokenRows += 1;
    }
    if (typeof entry.completion_tokens === "number") completionTokens += entry.completion_tokens;
    if (typeof entry.cached_tokens === "number") cachedTokens += entry.cached_tokens;
    // 每个来源在**这一页里**的最小尝试号视为它的首次尝试；分页截断可能让真正的第 1 次不在
    // 这一页里，所以这只是个估计 —— 字段名和界面文案都必须说"重试"，不能说"第几次"。
    const seen = firstAttempts.get(entry.caller);
    if (seen === undefined || entry.attempt < seen) firstAttempts.set(entry.caller, entry.attempt);
  }

  const firsts = [...firstAttempts.values()].reduce((sum, value) => sum + value, 0);
  return {
    attempts: entries.length,
    failures,
    retried: Math.max(0, entries.length - firsts),
    meanMs: withMs > 0 ? totalMs / withMs : null,
    promptTokens,
    completionTokens,
    cachedTokens,
    cacheShare: tokenRows > 0 && promptTokens > 0 ? cachedTokens / promptTokens : null,
    callers: callers.size,
  };
}
