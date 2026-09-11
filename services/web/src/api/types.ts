/**
 * The API surface this console reads, as types.
 *
 * Every shape here mirrors what the gateway already computed (`aegis_contracts/views.py`
 * for bundle views, `aegis_contracts/jobs.py` for jobs). Nothing in this file derives a
 * value: if a number is not in the API response, the console does not show it, and if a
 * field is missing that is a bug in the API contract rather than something to compute
 * around. `services/web/test/renders-api-data.test.ts` is what holds that line.
 */

/** Mirrors `aegis_contracts.jobs.JobState`. */
export type JobState = "queued" | "running" | "succeeded" | "failed" | "canceled";

/** Mirrors `aegis_contracts.jobs.JobStage`, in lifecycle order. */
export type JobStage =
  | "scan"
  | "setup"
  | "locate"
  | "expand"
  | "read"
  | "assemble"
  | "package"
  | "done";

export type Trust = "fact" | "strong" | "weak" | "guess" | "unknown";

export interface JobAccepted {
  job_id: string;
  state: JobState;
  deduplicated: boolean;
  revision: number;
}

export interface JobSummary {
  job_id: string;
  kind: "assemble" | "scan" | "ai_fanout";
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
  kind: string;
  state: JobState;
  cancel_requested: boolean;
  cancel_requested_at: string | null;
  submission: {
    job_id: string;
    kind: string;
    request: { workspace: string; sarif_path: string | null };
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
    // Present on scan jobs, and on assemble jobs when the scan ran locally; absent when the
    // SARIF lives in another container's filesystem, which the API reports as a warning.
    sarif_path?: string | null;
    warnings: string[];
  } | null;
  failure: { mode: string; message: string; detail: string | null } | null;
  revision: number;
}

export interface BundleSummary {
  bundle_id: string;
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
