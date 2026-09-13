/**
 * One job: its stages, its timings, and how to cancel it.
 *
 * The stage list is shown whole, including stages that were `skipped`, because "this job did not
 * run the AI stage" and "this job's AI stage has not started" are different facts and a screen
 * that hid empty rows would make them look the same.
 */

import { useState } from "react";
import { api, type ApiError } from "../api/client.ts";
import type { Job } from "../api/types.ts";
import { Banner, Empty, Field, StateBadge, usePolled } from "../components.tsx";
import { formatCount, formatDurationMs, formatTimestamp, formatUnits, share } from "../format.ts";
import { JOB_KIND, label, STAGE, STAGE_STATE } from "../labels.ts";

function counted(value: Record<string, number>): string {
  const entries = Object.entries(value);
  if (entries.length === 0) return "—";
  return entries.map(([key, count]) => `${key} ${formatCount(count)}`).join(", ");
}

export function JobDetailScreen({
  jobId,
  onBack,
  onOpenBundle,
}: {
  jobId: string;
  onBack: () => void;
  onOpenBundle: (bundleId: string) => void;
}) {
  const job = usePolled<Job>(() => api.job(jobId), [jobId], { pollMs: 2000 });
  const [failure, setFailure] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);

  const cancel = async () => {
    setBusy(true);
    setFailure(null);
    try {
      await api.cancelJob(jobId);
      job.reload();
    } catch (caught) {
      setFailure(caught as ApiError);
    } finally {
      setBusy(false);
    }
  };

  if (job.error && !job.data) {
    return (
      <section>
        <button type="button" onClick={onBack}>
          ← 任务
        </button>
        <Banner>{job.error.detail}</Banner>
      </section>
    );
  }
  if (!job.data) {
    return (
      <section>
        <button type="button" onClick={onBack}>
          ← 任务
        </button>
        <Empty>正在加载 {jobId}…</Empty>
      </section>
    );
  }

  const data = job.data;
  const progress = share(data.progress.units_done, data.progress.units_total);
  const running = data.state === "running" || data.state === "queued";

  return (
    <section>
      <div className="row">
        <button type="button" onClick={onBack}>
          ← 任务
        </button>
        <h1>{data.job_id}</h1>
        <StateBadge state={data.state} cancelRequested={data.cancel_requested} />
        <span className="muted">{label(JOB_KIND, data.kind)}</span>
        {running && !data.cancel_requested ? (
          <button type="button" className="right" onClick={cancel} disabled={busy}>
            {busy ? "取消中…" : "取消"}
          </button>
        ) : null}
      </div>

      {failure ? <Banner>{failure.detail}</Banner> : null}
      {job.error ? <Banner kind="warn">上次轮询失败：{job.error.detail}</Banner> : null}
      {data.failure ? (
        <Banner>
          <strong>{data.failure.mode}</strong>: {data.failure.message}
          {data.failure.detail ? <div className="muted">{data.failure.detail}</div> : null}
        </Banner>
      ) : null}

      <div className="card summary-grid">
        <Field label="工作区">
          <code>{data.submission.request.workspace}</code>
        </Field>
        <Field label="提交者">{data.submission.submitted_by}</Field>
        <Field label="指纹">
          <code>{data.submission.fingerprint.slice(0, 16)}</code>
        </Field>
        <Field label="尝试次数">{data.progress.attempt}</Field>
        <Field label="队列等待">{formatDurationMs(data.timing.queue_wait_ms)}</Field>
        <Field label="耗时">{formatDurationMs(data.timing.duration_ms)}</Field>
        <Field label="worker">
          <code>{data.progress.worker_id ?? "—"}</code>
        </Field>
        <Field label="修订号">{data.revision}</Field>
      </div>

      <h2>进度</h2>
      <p>
        {formatUnits(data.progress.units_done, data.progress.units_total, data.progress.unit_label)}
      </p>
      {progress === null ? (
        <p className="muted">
          此阶段未报告总数，因此没有进度条可画 —— 扫描器是一次同步等待。
        </p>
      ) : (
        <div className="bar-track">
          <span className="bar-fill" style={{ width: `${progress * 100}%` }} />
        </div>
      )}

      <h2>阶段</h2>
      <table className="table">
        <thead>
          <tr>
            <th>阶段</th>
            <th>状态</th>
            <th>开始时间</th>
            <th className="num">耗时</th>
            <th>备注</th>
            <th>计数</th>
          </tr>
        </thead>
        <tbody>
          {data.progress.stages.map((stage) => (
            <tr key={stage.stage} className={stage.stage === data.progress.stage ? "current" : ""}>
              <td>
                <code>{label(STAGE, stage.stage)}</code>
              </td>
              <td>{label(STAGE_STATE, stage.state)}</td>
              <td>{formatTimestamp(stage.started_at)}</td>
              <td className="num">{formatDurationMs(stage.duration_ms)}</td>
              <td className="note">{stage.note ?? ""}</td>
              <td className="note">{counted(stage.counters)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {data.result ? (
        <>
          <h2>结果</h2>
          <div className="card summary-grid">
            <Field label="分析包">
              {data.result.bundle_id ? (
                <button type="button" onClick={() => onOpenBundle(data.result!.bundle_id!)}>
                  {data.result.bundle_id}
                </button>
              ) : (
                "—"
              )}
            </Field>
            <Field label="运行">
              <code>{data.result.run_id ?? "—"}</code>
            </Field>
            <Field label="打包产物">
              <code>{data.result.package_path ?? "—"}</code>
            </Field>
            <Field label="SARIF">
              <code>{data.result.sarif_path ?? "—"}</code>
            </Field>
          </div>
          {data.result.warnings.length > 0 ? (
            <Banner kind="warn">
              <ul>
                {data.result.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </Banner>
          ) : null}
        </>
      ) : null}
    </section>
  );
}
