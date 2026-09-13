/**
 * Jobs: the queue, and the form that adds to it.
 *
 * The progress line uses `formatUnits`, which says "total unknown" when the API reported no
 * denominator, because the scan stage genuinely cannot report progress -- it is one synchronous
 * subprocess wait. Inventing a total there would be a lie the reader could not detect.
 */

import { useState } from "react";
import { api, type ApiError } from "../api/client.ts";
import type { JobSummary } from "../api/types.ts";
import { Empty, StateBadge } from "../components.tsx";
import {
  formatCount,
  formatDurationMs,
  formatRelative,
  formatTimestamp,
  formatUnits,
  share,
} from "../format.ts";
import { JOB_KIND, JOB_STATE, label, STAGE } from "../labels.ts";

export function JobListScreen({
  jobs,
  loading,
  onOpen,
  onSubmitted,
}: {
  jobs: JobSummary[];
  loading: boolean;
  onOpen: (jobId: string) => void;
  onSubmitted: () => void;
}) {
  const [workspace, setWorkspace] = useState("");
  const [sarifPath, setSarifPath] = useState("");
  const [lsp, setLsp] = useState(false);
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState<string | null>(null);
  const [failure, setFailure] = useState<ApiError | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true);
    setFailure(null);
    setMessage(null);
    try {
      const body: Record<string, unknown> = { lsp };
      if (workspace.trim()) body.workspace = workspace.trim();
      if (sarifPath.trim()) body.sarif_path = sarifPath.trim();
      const accepted = await api.submitJob(body);
      const deduplicated = "deduplicated" in accepted && accepted.deduplicated;
      setMessage(
        deduplicated
          ? `${accepted.job_id} 已在队列中 —— 已附加到现有任务。`
          : `已受理 ${accepted.job_id}（${label(JOB_STATE, accepted.state)}）。`,
      );
      onSubmitted();
    } catch (caught) {
      setFailure(caught as ApiError);
    } finally {
      setBusy(false);
    }
  };

  return (
    <section>
      <form className="card submit" onSubmit={submit}>
        <div className="row">
          <label>
            工作区
            <input
              value={workspace}
              onChange={(event) => setWorkspace(event.target.value)}
              placeholder="留空则使用已配置的工作区根目录"
              size={36}
            />
          </label>
          <label>
            SARIF 路径
            <input
              value={sarifPath}
              onChange={(event) => setSarifPath(event.target.value)}
              placeholder="可选：从已有 SARIF 组装"
              size={36}
            />
          </label>
          <label className="inline">
            <input type="checkbox" checked={lsp} onChange={(event) => setLsp(event.target.checked)} />
            使用语言服务器
          </label>
          <button type="submit" disabled={busy}>
            {busy ? "提交中…" : "提交任务"}
          </button>
        </div>
        {message ? <p className="ok">{message}</p> : null}
        {failure ? (
          <p className="error">
            {failure.status === 503
              ? `${failure.detail} — 此部署同步执行任务。`
              : failure.detail}
          </p>
        ) : null}
      </form>

      {loading && jobs.length === 0 ? <p className="muted">加载中…</p> : null}
      {!loading && jobs.length === 0 ? <Empty>暂无任务</Empty> : null}

      <ul className="job-list">
        {jobs.map((job) => {
          const progress = share(job.units_done, job.units_total);
          return (
            <li key={job.job_id} className="card job" onClick={() => onOpen(job.job_id)}>
              <div className="job-head">
                <code>{job.job_id}</code>
                <StateBadge state={job.state} cancelRequested={job.cancel_requested} />
                <span className="muted">{label(JOB_KIND, job.kind)}</span>
                <span className="muted right" title={formatTimestamp(job.submitted_at)}>
                  {formatRelative(job.submitted_at)}
                </span>
              </div>
              <div className="job-body">
                <span>
                  阶段 <strong>{label(STAGE, job.stage)}</strong>
                </span>
                <span>{formatUnits(job.units_done, job.units_total, job.unit_label)}</span>
                <span>第 {job.attempt} 次尝试</span>
                <span>{formatDurationMs(job.duration_ms)}</span>
                {job.workspace ? <span className="muted">{job.workspace}</span> : null}
                {job.bundle_id ? <code className="bundle-id">{job.bundle_id}</code> : null}
                {job.failure_mode ? <span className="error">{job.failure_mode}</span> : null}
              </div>
              {progress === null ? null : (
                <div className="bar-track" title={`${Math.round(progress * 100)}%`}>
                  <span className="bar-fill" style={{ width: `${progress * 100}%` }} />
                </div>
              )}
              <div className="counters">
                {Object.entries(job.counters).map(([key, value]) => (
                  <span key={key} className="counter">
                    {key} <strong>{formatCount(value)}</strong>
                  </span>
                ))}
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
