/**
 * The API surface this front-end reads, as types.
 *
 * Hand-written rather than generated, because the generated ones describe everything the API
 * can do while a screen needs to know what *this* build actually renders. What keeps them
 * honest is `test/contract.test.ts`: it fetches the gateway's `/openapi.json` and fails if a
 * path used by `client.ts` is not in the published route table. That check goes over HTTP on
 * purpose -- this project shares no source with the backend, so a backend rename has to be
 * caught from the outside, the way a real deployment would catch it.
 *
 * **This file derives nothing.** Where an older console refused to compute anything at all and
 * had the API publish display numbers, this one computes its own counts, shares and averages
 * (see `format.ts`). The split is: the API publishes facts, the front-end decides how to show
 * them. So `AIReport` below carries no `counts` field -- `countsOf(report)` computes it.
 */

export type JobState = "queued" | "running" | "succeeded" | "failed" | "canceled";

export type JobKind = "assemble" | "scan" | "ai_fanout" | "audit";

export type JobStage =
  | "scan"
  | "setup"
  | "locate"
  | "expand"
  | "read"
  | "assemble"
  | "package"
  | "ai"
  | "done";

export type Trust = "fact" | "strong" | "weak" | "guess" | "unknown";

export interface Health {
  status: string;
  version: string;
  opengrep: string;
  capabilities?: {
    ai?: {
      enabled: boolean;
      model: string;
      endpoint_configured: boolean;
      api_key_present: boolean;
      api_key_env: string;
      concurrency: number;
    };
    projects?: {
      enabled: boolean;
      root: string;
      writable: boolean;
      allow_private_hosts: boolean;
      /** 缺省表示这个网关没报（旧版本），前端不该因此判定"什么都不能分析"。 */
      deep_analysis?: ProjectDeepAnalysis;
    };
    [key: string]: unknown;
  };
}

export interface JobAccepted {
  job_id: string;
  state: JobState;
  deduplicated: boolean;
  revision: number;
}

export interface JobSummary {
  job_id: string;
  kind: JobKind;
  state: JobState;
  cancel_requested: boolean;
  submitted_at: string;
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number;
  stage: JobStage;
  counters: Record<string, number>;
  units_done: number;
  units_total: number;
  unit_label: string;
  attempt: number;
  bundle_id: string | null;
  failure_mode: string | null;
  revision: number;
  /** The workspace this job ran against; null on jobs recorded before the field existed. */
  workspace: string | null;
}

export interface QueueStatus {
  workers_alive: number;
  pending: number;
  lag: number | null;
  stream_length: number;
  queued: number;
  degraded: boolean;
  detail: string | null;
}

export interface JobList {
  jobs: JobSummary[];
  total: number;
  queue: QueueStatus;
}

export interface StageProgress {
  stage: JobStage;
  state: "pending" | "running" | "done" | "skipped" | "failed";
  started_at: string | null;
  finished_at: string | null;
  duration_ms: number | null;
  note: string | null;
  counters: Record<string, number>;
}

export interface Job {
  schema_version: string;
  job_id: string;
  kind: JobKind;
  state: JobState;
  cancel_requested: boolean;
  cancel_requested_at: string | null;
  submission: {
    job_id: string;
    kind: string;
    request: { workspace: string; sarif_path: string | null; bundle_id?: string | null };
    fingerprint: string;
    submitted_at: string;
    submitted_by: string;
  };
  timing: {
    submitted_at: string;
    started_at: string | null;
    finished_at: string | null;
    queue_wait_ms: number;
    duration_ms: number;
  };
  progress: {
    stage: JobStage;
    stages: StageProgress[];
    counters: Record<string, number>;
    units_done: number;
    units_total: number;
    unit_label: string;
    worker_id: string | null;
    attempt: number;
    stage_started_at: string | null;
    worker_heartbeat_at: string | null;
  };
  result: {
    bundle_id: string | null;
    package_path: string | null;
    run_id: string | null;
    sarif_path?: string | null;
    warnings: string[];
  } | null;
  failure: { mode: string; message: string; detail: string | null } | null;
  revision: number;
}

/**
 * 一次深度审计的运行轨迹（`GET /v1/audit/{job}/trail`）。
 *
 * 事件是**追加写**的：`seq` 单调递增，前端记住 `last_seq` 只取新增的部分，所以一次 30 分钟、
 * 4000 次工具调用的运行也只是一秒钟一个小请求，而不是每次把整份日志重新传一遍。
 *
 * `events` 里每一项的 `kind` 决定其它字段，这里按最宽的形状声明：轨迹的用途就是把后端记下的
 * 事实原样展示，前端**不做推断**——推断出来的一律是猜测，而这一屏的价值恰好在于它不是猜测。
 */
export interface AuditLead {
  lead_id: string;
  question: string;
  status: string;
  source_work_id: string;
  linked_work_id: string;
  processing_reason: string;
  file: string;
  line: number | null;
}

export interface AuditEvent {
  lead?: AuditLead;
  work_id?: string;
  work?: AuditWorkItem;
  seq: number;
  at: string;
  kind: AuditEventKind;
  run_id?: string;
  /** 阶段事件：prep / security_inventory / recon / threat_model / plan / discovery / validation / attack_path / findings / close。 */
  stage?: string;
  state?: string;
  round?: number;
  /** agent_start / agent_step / agent_end。 */
  agent?: string;
  scope?: string;
  /** agent_step：模型这一步的想法、它调用的工具、参数、以及工具回了什么。 */
  index?: number;
  thought?: string;
  tool?: string | null;
  arguments?: Record<string, unknown>;
  ok?: boolean | null;
  summary?: string;
  error?: string | null;
  tools?: string[];
  stop_reason?: string;
  steps?: number;
  parsed?: boolean;
  /** candidate / verdict / attack_path / finding：账本上的东西。 */
  candidate_id?: string;
  finding_id?: string;
  file?: string;
  line?: number | null;
  vulnerability_type?: string;
  title?: string;
  verdict?: string;
  evidence_kind?: string;
  confidence?: number;
  reachable?: boolean;
  severity?: string;
  reason?: string;
  merged_from?: number;
  merged_locations?: number;
  impact?: string;
  entry_points?: string[];
  /** coverage：某个 scope 的覆盖率判定与理由。 */
  files?: number;
  unread?: number;
  /** summary：收尾计数。 */
  closed?: boolean;
  counters?: Record<string, number>;
  dry_run?: boolean;
  fatal?: string | null;
  closure_note?: string;
  /** record：某个 agent 往黑板上记了一条事实（note/component/entry_point/…/lead）。 */
  record_kind?: string;
  candidate_ids?: string[];
  evidence_version?: number;
  execution_budget?: Record<string, unknown>;
  revision?: number;
  text?: string;
  note?: string;
}

export type AuditEventKind =
  | "work_item"
  | "stage"
  | "agent_start"
  | "agent_step"
  | "agent_end"
  | "candidate"
  | "verdict"
  | "attack_path"
  | "coverage"
  | "record"
  | "finding"
  | "summary"
  | "error"
  | "unknown";

export interface AuditWorkItem {
  work_id: string;
  scope_id: string;
  title: string;
  rationale: string;
  kind: "file_review" | "investigation" | "validation" | "attack_path";
  state: "planned" | "running" | "done" | "blocked" | "canceled" | "abandoned";
  files: string[];
  completion_criteria: string;
  question?: string;
  priority?: number;
  merged_into?: string;
  gaps?: { gap_id: string; kind: string; question: string; file: string; line: number;
    state: "pending" | "resolved" | "blocked"; reason: string; evidence_refs: string[]; lead_id: string }[];
  status_reason: string;
  candidate_ids: string[];
  pending_updates?: string[];
  read_files: number;
  unread_ranges?: Record<string, [number, number | null][]>;
  steps_used: number;
  opened_at: string;
  closed_at: string | null;
  attempts: {
    run_id: string;
    agent: string;
    started_at: string;
    finished_at: string | null;
    stop_reason: string;
    steps: number;
    error: string;
  }[];
}

export interface AuditTrail {
  job_id: string;
  trail: string;
  events: AuditEvent[];
  last_seq: number;
  /** 文件末尾有一行写坏了（进程被杀）；是事实，不是读取失败。 */
  damaged: number;
  /** 这一页装满了，还有更多——立刻再问一次，别等下一个轮询周期。 */
  more: boolean;
  /** false 表示这次审计还没写出轨迹（排队中或刚开始），不是错误。 */
  exists: boolean;
}

export interface AuditReport {
  job_id: string;
  run_dir: string;
  report: string;
  markdown: string;
}

/**
 * 一次模型往返的元数据（`GET /v1/ai/traffic`）。
 *
 * **没有 prompt，也没有回答正文**：那是源码和模型输出，这个文件会被浏览器读。正文有更合适的
 * 家 —— 审计的对话在运行轨迹里，快速研判的原始回答在分析包的 `ai/answers/`。
 * 这里回答的是"多少次、多久、多少 token、成没成、谁在问"。
 */
export interface AITrafficEntry {
  at: string;
  /** 谁在问：`discovery:scope-x`（审计的某个 agent）或 `context.C-1`（快速研判的某个上下文）。 */
  caller: string;
  kind: string;
  model: string;
  endpoint: string;
  /** 第几次尝试。重试是独立的一行 —— 一次调用花掉三次往返必须看得见。 */
  attempt: number;
  ok: boolean;
  duration_ms: number;
  /** 输入/输出的**字符数**，与下面的 token 不同：token 要 provider 报，字符数总是有。 */
  prompt_chars: number;
  answer_chars: number;
  prompt_tokens: number | null;
  completion_tokens: number | null;
  finish_reason?: string | null;
  cached_tokens: number | null;
  error: string | null;
}

export interface AITrafficReport {
  entries: AITrafficEntry[];
  /** 文件里的总行数，与这一页取多少无关。 */
  count: number;
  /** 没写完的行数（进程被杀时留下的半行）。 */
  damaged: number;
  path: string;
  exists: boolean;
  size_bytes?: number;
  limit: number;
  note: string;
}

export interface BundleSummary {
  bundle_id: string;
  path?: string;
  created_at: string | null;
  focus_count: number | null;
  estimated_tokens: number | null;
  coverage: { discoverable: number; bundled: number; rejected: number; deduped: number } | null;
  duration_ms: number | null;
  prune_count: number;
  degradation_count: number;
  providers: string[];
  engine: string | null;
  zero_findings_suspicious: boolean | null;
  /** The workspace the bundle was built from; drives the project grouping. */
  workspace: string | null;
  /** Whether `<bundle>/ai/report.json` exists, so the AI screen knows without N requests. */
  has_ai_report: boolean;
  error?: string;
}

export interface FunnelStep {
  key: string;
  label: string;
  count: number;
  of_previous: number | null;
  of_first: number | null;
  lost: number;
  loss_reasons: string[];
  lost_items: Array<Record<string, unknown>>;
  note: string | null;
}

export interface StageTiming {
  key: string;
  label: string;
  ms: number;
  share: number;
  cached: boolean;
}

export interface ProviderStat {
  provider: string;
  label: string;
  trust: Trust;
  confidence: number;
  note: string;
  methods: number;
  edges: number;
  focus_methods: number;
}

export interface BundleOverview {
  bundle_id: string;
  run_id: string;
  created_at: string;
  workspace_root: string;
  context_count: number;
  method_count: number;
  finding_count: number;
  total_chars: number;
  estimated_tokens: number;
  duration_ms: number;
  worst_trust: Trust;
  trust_mix: Record<string, number>;
  truncated_contexts: number;
  prune_count: number;
  degradation_count: number;
  warning_flags: string[];
}

export interface ScanSummary {
  engine: string;
  engine_version: string;
  sarif_path: string | null;
  command: string[];
  command_line: string;
  returncode: number;
  configured: boolean;
  zero_findings_is_suspicious: boolean;
  failure_mode: string | null;
  stderr_tail: string;
  rule_counts: Record<string, number>;
  severity_counts: Record<string, number>;
  top_paths: Array<[string, number]>;
}

export interface Observability {
  overview: BundleOverview;
  funnel: FunnelStep[];
  timeline: StageTiming[];
  providers: ProviderStat[];
  scan: ScanSummary | null;
  degradations: Array<{ capability: string; reason: string; impact: string }>;
  prunes: Array<{ rule: string; detail: string; path?: string | null; line?: number | null }>;
  provider_legend: Record<string, { label: string; trust: Trust; confidence: number; note: string }>;
  stage_labels: Record<string, string>;
  counts: Record<string, number>;
}

export interface ContextView {
  context_id: string;
  focus_id: string;
  focus_name: string;
  focus_location: string;
  focus_provider: string;
  worst_severity: string;
  findings: Array<{
    finding_id: string;
    rule_id?: string;
    severity?: string;
    location?: string;
    message?: string;
    snippet?: string;
    missing?: boolean;
  }>;
  methods: Array<{
    method_id: string;
    name: string;
    qualified_name: string;
    location: string;
    provider: string;
    trust: Trust;
    is_focus: boolean;
    depth: number;
    direction: string | null;
    via: string | null;
    origin_chain: string[];
  }>;
  edges: Array<{
    caller_name: string;
    callee_name: string;
    direction: string;
    provider: string;
    trust: Trust;
    confidence: number;
    call_site: string | null;
    snippet: string | null;
  }>;
  estimated_tokens: number;
  total_chars: number;
  truncated: boolean;
  prunes: Array<{ rule: string; detail: string }>;
  depth_histogram: Record<string, number>;
  provider_mix: Record<string, number>;
  unreached_focus: boolean;
}

export interface MethodIndexRow {
  method_id: string;
  qualified_name: string;
  location: string;
  path: string;
  kind: string;
  language: string;
  provider: string;
  trust: Trust;
  is_focus: boolean;
  depth: number | null;
  direction: string | null;
  via: string | null;
  contexts: string[];
}

export interface BundleDiff {
  left: { bundle_id: string } & Record<string, number | string>;
  right: { bundle_id: string } & Record<string, number | string>;
  delta: Record<string, number>;
  methods: { only_left: string[]; only_right: string[]; shared: number };
  findings: { only_left: string[]; only_right: string[]; shared: number };
  stage_delta_ms: Record<string, number>;
}

// ---------------------------------------------------------------- the AI stage

export type VerdictKind = "true_positive" | "false_positive" | "needs_more_context";

export type VerdictSeverity = "critical" | "high" | "medium" | "low" | "informational";

export interface Verdict {
  verdict: VerdictKind;
  severity: VerdictSeverity;
  confidence: number;
  /** The model's own caveat, carried inside `severity` as the prompt instructs. */
  severity_qualifier: string;
  reachability: string;
  chain: string[];
  data_flow: string;
  evidence: string[];
  missing: string[];
  fix: string;
}

/** What the provider reported. `cached_tokens` over `prompt_tokens` is the cache share. */
export interface TokenUsage {
  prompt_tokens: number | null;
  completion_tokens: number | null;
  total_tokens: number | null;
  cached_tokens: number | null;
  raw: Record<string, unknown>;
}

/** One round trip, recorded whether or not it produced a verdict. */
export interface AICall {
  context_id: string | null;
  model: string;
  endpoint: string;
  called_at: string;
  elapsed_s: number;
  usage: TokenUsage | null;
  parsed: boolean;
  error: string | null;
  missing_fields: string[];
  verdict: Verdict | null;
  raw_answer: string;
}

/**
 * `GET /v1/bundles/{id}/verdicts` — the stored `ai/report.json`, exactly as written.
 *
 * No counts. An earlier API published `counts.parsed` / `counts.failed` and a
 * `cache_hit_ratio` per call; those are now computed here (`countsOf`, `cacheHitRatio`),
 * because they describe how this screen chooses to present the report rather than what
 * happened.
 */
export interface AIReport {
  bundle_id: string;
  model: string;
  endpoint: string;
  started_at: string;
  finished_at: string | null;
  calls: AICall[];
  /** Set when the stage did not run at all; distinct from "every call failed". */
  skipped: string | null;
}

// ------------------------------------------------- traffic, settings, projects

/**
 * 项目的来源。`git` 是拉取，`archive` 是上传的压缩包。
 *
 * 只支持公开仓库：私有仓库请先导出压缩包再上传，服务端因此不需要处理任何凭据 ——
 * 一个不需要 token 的接口，也就没有 token 会漏进日志或错误信息的问题。
 */
export type ProjectSource = "git" | "archive";

/** `GET /v1/projects` 里的一项，也就是项目目录下 `project.json` 的内容。 */
export interface ProjectRecord {
  schema_version: string;
  name: string;
  /** 分析用的绝对路径，可作为任务请求里的 `workspace`。 */
  workspace: string;
  source: ProjectSource;
  /** 仓库地址，或上传时的文件名。 */
  origin: string;
  ref: string | null;
  commit: string | null;
  created_at: string;
  bytes: number;
  files: number;
  /** 新建时自动提交的那次分析任务；`analyze=false` 时为 null。 */
  job_id: string | null;
  /** 每种编程语言的文件数，多的在前（如 `{"java": 51, "sql": 2}`）。 */
  languages: Record<string, number>;
}

/** 本部署能深到什么程度：调用图靠语言服务器，污点流靠 Joern。 */
export interface ProjectDeepAnalysis {
  call_graph: string[];
  taint: string[];
}

/** One recorded request, as the gateway saw it. */
export interface TrafficEntry {
  seq: number;
  at: string;
  method: string;
  path: string;
  status: number;
  duration_ms: number;
  client: string;
}

export interface TrafficReport {
  entries: TrafficEntry[];
  /** Total requests recorded since process start, not the number of entries returned. */
  count: number;
  limit: number;
  note: string;
}

/**
 * `GET /v1/settings` — the effective, redacted configuration.
 *
 * `ai.api_key_env` is the *name* of the variable holding the key; the key itself is never in
 * this payload, and `api_key_present` is how a reader learns whether one is set.
 */
export interface SettingsView {
  workspace_root: string;
  output_dir: string;
  work_dir: string;
  log_level: string;
  budget: Record<string, unknown>;
  queue: Record<string, unknown>;
  dataflow: Record<string, unknown>;
  ai: Record<string, unknown> & {
    enabled?: boolean;
    model?: string;
    base_url?: string;
    api_key_env?: string;
    api_key_present?: boolean;
    concurrency?: number;
    max_tokens?: number;
    max_contexts?: number;
    timeout_s?: number;
  };
  cors: { allow_origins: string[] };
  note: string;
}

/** GET/PUT /v1/ai/config never returns the secret value. */
export interface LLMConfig {
  enabled: boolean;
  base_url: string;
  model: string;
  timeout_s: number;
  concurrency: number;
  temperature: number;
  max_tokens: number;
  max_contexts: number;
  api_key_present: boolean;
  api_key_source: string;
  source: string;
}

export type LLMConfigUpdate = Omit<LLMConfig, "api_key_present" | "api_key_source" | "source"> & {
  api_key?: string;
  clear_api_key?: boolean;
};
