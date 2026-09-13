/**
 * Every request this front-end makes, and nothing else.
 *
 * Paths are relative to the configured API base (`apiUrl`), never to the page's own origin:
 * this app is deployed separately from the gateway, so "same origin" is a special case rather
 * than the assumption.
 *
 * The path literals below are read by `test/contract.test.ts` with a regular expression and
 * checked against the gateway's published `/openapi.json`. Keep each path in one piece: a
 * query string appended *inside* a template literal would hide the route from that check, so
 * queries are concatenated outside the literal.
 */

import { apiUrl } from "./config.ts";
import type {
  AIReport,
  AITrafficReport,
  AuditReport,
  AuditTrail,
  BundleDiff,
  BundleSummary,
  ContextView,
  Health,
  Job,
  JobAccepted,
  JobList,
  MethodIndexRow,
  Observability,
  ProjectRecord,
  SettingsView,
  TrafficReport,
} from "./types.ts";

export interface ApiError {
  status: number;
  detail: string;
}

function messageFor(status: number, statusText: string, body: unknown): string {
  if (typeof body === "object" && body !== null && "detail" in body) {
    const detail = (body as { detail: unknown }).detail;
    if (typeof detail === "string") return detail;
  }
  return `${status} ${statusText}`;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response;
  try {
    response = await fetch(apiUrl(path), {
      headers: { Accept: "application/json" },
      ...init,
    });
  } catch (cause) {
    // A transport failure is the common failure in a separately deployed app -- wrong base,
    // gateway down, CORS refused -- and "Failed to fetch" on its own tells the reader nothing
    // about which of those it was. The base is part of the message for that reason.
    throw {
      status: 0,
      detail: `${apiUrl(path)} 无法访问（${String(cause)}）；请检查 API 地址，以及网关是否允许此来源`,
    } satisfies ApiError;
  }
  if (!response.ok) {
    let body: unknown = null;
    try {
      body = await response.json();
    } catch {
      // A non-JSON error body is still an error; the status line is the message.
    }
    throw { status: response.status, detail: messageFor(response.status, response.statusText, body) } satisfies ApiError;
  }
  return (await response.json()) as T;
}

export const api = {
  health: () => request<Health>("/health"),

  jobs: (limit = 50) => request<JobList>(`/v1/jobs?limit=${limit}`),

  job: (jobId: string) => request<Job>(`/v1/jobs/${encodeURIComponent(jobId)}`),

  cancelJob: (jobId: string) =>
    request<Job | JobAccepted>(`/v1/jobs/${encodeURIComponent(jobId)}/cancel`, { method: "POST" }),

  submitJob: (body: unknown) =>
    request<JobAccepted | Job>(
      "/v1/jobs",
      {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(body),
      },
    ),

  bundles: () => request<{ bundles: BundleSummary[] }>("/v1/bundles"),

  observability: (bundleId: string) =>
    request<Observability>(`/v1/bundles/${encodeURIComponent(bundleId)}/observability`),

  contexts: (bundleId: string) =>
    request<{ contexts: ContextView[] }>(`/v1/bundles/${encodeURIComponent(bundleId)}/contexts`),

  methods: (bundleId: string) =>
    request<{ count: number; methods: MethodIndexRow[] }>(
      `/v1/bundles/${encodeURIComponent(bundleId)}/methods`,
    ),

  /** Raw source, for the body viewer, so it is read as text rather than parsed as JSON. */
  methodBody: async (bundleId: string, methodId: string): Promise<string> => {
    const response = await fetch(
      apiUrl(
        `/v1/bundles/${encodeURIComponent(bundleId)}/methods/${encodeURIComponent(methodId)}/body`,
      ),
      { headers: { Accept: "text/plain" } },
    );
    if (!response.ok) {
      throw { status: response.status, detail: `方法体不可用（${response.status}）` } satisfies ApiError;
    }
    return await response.text();
  },

  diff: (bundleId: string, otherId: string) =>
    request<BundleDiff>(`/v1/bundles/${encodeURIComponent(bundleId)}/diff/${encodeURIComponent(otherId)}`),

  /**
   * Ask the model to judge a finished bundle.
   *
   * `force` re-runs a bundle that already has a report. Without it the gateway deduplicates the
   * request onto the finished job and answers with the stored result, which from the reader's
   * side looks like the button doing nothing.
   */
  analyzeBundle: (bundleId: string, options: { force?: boolean } = {}) =>
    request<Job | JobAccepted | AIReport | { skipped: string }>(
      `/v1/bundles/${encodeURIComponent(bundleId)}/analyze` + (options.force ? "?force=true" : ""),
      {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify({ bundle_id: bundleId }),
      },
    ),

  /** The stored `ai/report.json` verbatim; a 404 means the bundle was never analysed. */
  verdicts: (bundleId: string) =>
    request<AIReport>(`/v1/bundles/${encodeURIComponent(bundleId)}/verdicts`),

  traffic: (limit = 200) => request<TrafficReport>(`/v1/traffic?limit=${limit}`),

  /**
   * 模型调用的流量：网关、worker、extract 谁跟 provider 说过话都记在这里。
   *
   * 和上面的 `/v1/traffic` 是**两种**记录，不是一个表的两页：那个是网关进程内的环形缓冲
   * （重启即空、多副本各记各的），这个是落盘 JSONL、重启不丢。所以界面上必须分开说。
   */
  aiTraffic: (limit = 200) => request<AITrafficReport>(`/v1/ai/traffic?limit=${limit}`),

  // ── 深度审计：智能体编排层，当作队列里的一个任务来用 ────────────────────
  //
  // 提交走的是和其它任务同一个契约（去重、`?force=true`、取消都有），所以这里只多一个路径；
  // 真正多出来的是**读**侧：一次审计要跑半小时，轨迹必须能增量地看。

  /**
   * 提交一次全自主审计。
   *
   * 只接受 workspace：审计的边界（轮数、每 agent 步数、并发）是"这次评审产出了什么"的一部分，
   * 让调用方随手改会让两个请求看起来一样、结果却不同——而任务指纹正是按请求字段算的。
   */
  submitAudit: (body: { workspace: string }) =>
    request<JobAccepted | Job>(
      "/v1/audit",
      {
        method: "POST",
        headers: { "Content-Type": "application/json", Accept: "application/json" },
        body: JSON.stringify(body),
      },
    ),

  /**
   * 增量读取运行轨迹：只要 `after_seq` 之后的事件。
   *
   * 查询串拼在字面量外面，和这个文件里其它带参数的路径一样，为的是让契约测试的正则能看见路径。
   */
  auditTrail: (jobId: string, afterSeq = 0, limit = 500) =>
    request<AuditTrail>(
      `/v1/audit/${encodeURIComponent(jobId)}/trail` +
        `?after_seq=${afterSeq}&limit=${limit}`,
    ),

  /** 跑完之后的那份 markdown 报告；404 表示还没跑完。 */
  auditReport: (jobId: string) =>
    request<AuditReport>(`/v1/audit/${encodeURIComponent(jobId)}/report`),

  settings: () => request<SettingsView>("/v1/settings"),

  // ── 项目：从仓库拉取或上传压缩包 ────────────────────────────────────────

  /** 已登记的项目（按创建时间倒序）。 */
  projects: () => request<{ projects: ProjectRecord[] }>("/v1/projects"),

  /**
   * 从公开仓库新建一个项目。
   *
   * 只接受 `https://`：服务端按白名单拒绝其它协议，并把内网/回环地址当作 SSRF 拦掉。
   * 前端先按同样的规则挡一次，是为了让读者立刻看到哪里错了，而不是提交后等一个 400。
   */
  createProject: (body: {
    git_url: string;
    ref?: string | null;
    name?: string | null;
    analyze?: boolean;
  }) =>
    request<ProjectRecord>("/v1/projects", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    }),

  /**
   * 上传压缩包新建项目。
   *
   * 这里**不设** `Content-Type`：multipart 的边界必须由浏览器生成，手写一个
   * `multipart/form-data` 头会把 boundary 漏掉，服务端解析失败而报文里看不出来。
   */
  uploadProject: (file: File, options: { name?: string | null; analyze?: boolean } = {}) => {
    const form = new FormData();
    form.append("file", file);
    if (options.name) form.append("name", options.name);
    form.append("analyze", String(options.analyze ?? true));
    return request<ProjectRecord>("/v1/projects/upload", {
      method: "POST",
      headers: { Accept: "application/json" },
      body: form,
    });
  },

  /** A link, not a fetch: the browser downloads it and the API streams the zip. */
  archiveUrl: (bundleId: string) => apiUrl(`/v1/bundles/${encodeURIComponent(bundleId)}/archive`),
};
