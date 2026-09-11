/**
 * Every request this console makes, and nothing else.
 *
 * The paths are relative on purpose. nginx (production) and the Vite dev server both proxy
 * `/v1` to the gateway, so the browser only ever talks to one origin: the one it loaded the
 * page from. That means no API host in the bundle, no CORS in production, and no rebuild to
 * point the console at a different gateway.
 *
 * `services/web/test/endpoints-exist.test.ts` checks every literal path below against the
 * gateway's real route table, so a typo here fails a test instead of a page load.
 */

import type {
  BundleDiff,
  BundleSummary,
  ContextView,
  Job,
  JobAccepted,
  JobList,
  MethodIndexRow,
  Observability,
} from "./types.ts";

export interface ApiError {
  status: number;
  detail: string;
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await fetch(path, {
    headers: { Accept: "application/json" },
    ...init,
  });
  if (!response.ok) {
    let detail = `${response.status} ${response.statusText}`;
    try {
      const body = (await response.json()) as { detail?: unknown };
      if (typeof body.detail === "string") {
        detail = body.detail;
      }
    } catch {
      // A non-JSON error body is still an error; the status line is the message.
    }
    throw { status: response.status, detail } satisfies ApiError;
  }
  return (await response.json()) as T;
}

export const api = {
  /** Health of the gateway itself, including which scanner it would use. */
  health: () => request<{ status: string; version: string; opengrep: string }>("/health"),

  /** The queue view: what is running, what is queued, what just finished. */
  jobs: (limit = 50) => request<JobList>(`/v1/jobs?limit=${limit}`),

  job: (jobId: string) => request<Job>(`/v1/jobs/${encodeURIComponent(jobId)}`),

  cancelJob: (jobId: string) =>
    request<Job | JobAccepted>(`/v1/jobs/${encodeURIComponent(jobId)}/cancel`, {
      method: "POST",
    }),

  /** Submit a job. The caller supplies exactly the request body the API documents. */
  submitAssemble: (body: unknown) =>
    request<JobAccepted | Job>("/v1/jobs", {
      method: "POST",
      headers: { "Content-Type": "application/json", Accept: "application/json" },
      body: JSON.stringify(body),
    }),

  /** Every bundle on disk, newest first. */
  bundles: () => request<{ bundles: BundleSummary[] }>("/v1/bundles"),

  /**
   * All the derived views for one bundle in a single call.
   *
   * One request rather than six because these are computed together server-side and a
   * screen renders them together. It also means the console cannot show a funnel from one
   * moment beside a method table from another.
   */
  observability: (bundleId: string) =>
    request<Observability>(`/v1/bundles/${encodeURIComponent(bundleId)}/observability`),

  contexts: (bundleId: string) =>
    request<{ contexts: ContextView[] }>(`/v1/bundles/${encodeURIComponent(bundleId)}/contexts`),

  methods: (bundleId: string) =>
    request<{ count: number; methods: MethodIndexRow[] }>(
      `/v1/bundles/${encodeURIComponent(bundleId)}/methods`,
    ),

  /** Raw text, for the inline body viewer. */
  methodBody: async (bundleId: string, methodId: string): Promise<string> => {
    const response = await fetch(
      `/v1/bundles/${encodeURIComponent(bundleId)}/methods/${encodeURIComponent(methodId)}/body`,
    );
    if (!response.ok) {
      throw { status: response.status, detail: `body unavailable (${response.status})` } satisfies ApiError;
    }
    return await response.text();
  },

  diff: (bundleId: string, otherId: string) =>
    request<BundleDiff>(
      `/v1/bundles/${encodeURIComponent(bundleId)}/diff/${encodeURIComponent(otherId)}`,
    ),
};
