/**
 * One job, in full: the stage track with its timings, the funnel counts, the ledger, and the
 * cancel button.
 *
 * This is where the queue's honesty becomes visible. A stage reports `pending`, `running`,
 * `done` or `failed`, and a `failed` stage on a canceled job is how "it stopped here" is
 * shown -- with the note the worker wrote, which is the only place the reason lives. Nothing
 * on this screen is inferred: if the API did not say it, the screen does not show it.
 */

import { api } from "../api/client.ts";
import type { StageProgress } from "../api/types.ts";
import { Banner, Empty, Field, StateBadge, usePolled } from "../App.tsx";
import {
  formatDurationMs,
  formatTimestamp,
  formatUnits,
  isActive,
  shortenWorkerId,
} from "../format.ts";

export function JobDetailScreen({
  jobId,
  onBack,
  onOpenBundle,
}: {
  jobId: string;
  onBack: () => void;
  onOpenBundle: (bundleId: string) => void;
}) {
  const { data: job, error, loading, reload } = usePolled(
    () => api.job(jobId),
    [jobId],
    { pollMs: 2000 },
  );

  const cancel = async () => {
    try {
      await api.cancelJob(jobId);
      reload();
    } catch {
      // A refusal (409: already finished) is a normal outcome; the next poll shows why.
      reload();
    }
  };

  if (loading && !job) return <p className="muted">loading {jobId}…</p>;
  if (error && !job) {
    return (
      <section>
        <button type="button" onClick={onBack}>
          ← jobs
        </button>
        <Banner>
          {error.status === 404 ? `${jobId} not found or expired.` : error.detail}
        </Banner>
      </section>
    );
  }
  if (!job) return <Empty>no job</Empty>;

  const active = isActive(job.state);

  return (
    <section>
      <div className="row">
        <button type="button" onClick={onBack}>
          ← jobs
        </button>
        <h1>{job.job_id}</h1>
        <StateBadge job={job} />
        {active ? (
          <button type="button" className="danger" onClick={cancel}>
            cancel
          </button>
        ) : null}
      </div>
      {error ? <Banner>last poll failed: {error.detail}</Banner> : null}

      <div className="card summary-grid">
        <Field label="workspace">{job.submission.request.workspace}</Field>
        <Field label="submitted">{formatTimestamp(job.timing.submitted_at)}</Field>
        <Field label="started">{formatTimestamp(job.timing.started_at)}</Field>
        <Field label="finished">{formatTimestamp(job.timing.finished_at)}</Field>
        <Field label="queue wait">{formatDurationMs(job.timing.queue_wait_ms)}</Field>
        <Field label="duration">{formatDurationMs(job.timing.duration_ms)}</Field>
        <Field label="attempt">{job.progress.attempt}</Field>
        <Field label="worker">{shortenWorkerId(job.progress.worker_id)}</Field>
        <Field label="last heartbeat">{formatTimestamp(job.progress.worker_heartbeat_at)}</Field>
        <Field label="fingerprint">
          <code>{job.submission.fingerprint.slice(0, 12)}…</code>
        </Field>
      </div>

      <h2>Stages</h2>
      <table className="table">
        <thead>
          <tr>
            <th>stage</th>
            <th>state</th>
            <th className="num">duration</th>
            <th>note</th>
            <th>counters</th>
          </tr>
        </thead>
        <tbody>
          {job.progress.stages.map((stage) => (
            <tr key={stage.stage} className={stage.stage === job.progress.stage ? "current" : ""}>
              <td>{stage.stage}</td>
              <td>
                <span className={`stage stage-${stage.state}`}>{stage.state}</span>
              </td>
              <td className="num">{formatDurationMs(stage.duration_ms)}</td>
              <td className="note">{stage.note ?? ""}</td>
              <td>
                {Object.entries(stage.counters).map(([key, value]) => (
                  <span key={key} className="counter">
                    {key} <strong>{value}</strong>
                  </span>
                ))}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Progress</h2>
      <p className="muted">
        {formatUnits(job.progress.units_done, job.progress.units_total, job.progress.unit_label)}
        {job.progress.unit_label === "scan" || job.progress.units_total === 0
          ? " — the scan stage cannot report a denominator: it is one subprocess wait."
          : ""}
      </p>
      <div className="counters">
        {Object.entries(job.progress.counters).map(([key, value]) => (
          <span key={key} className="counter">
            {key} <strong>{value}</strong>
          </span>
        ))}
      </div>

      {job.failure ? (
        <>
          <h2>Failure</h2>
          <div className="card error-card">
            <Field label="mode">{job.failure.mode}</Field>
            <Field label="message">{job.failure.message}</Field>
            {job.failure.detail ? <Field label="detail">{job.failure.detail}</Field> : null}
          </div>
        </>
      ) : null}

      {job.result ? (
        <>
          <h2>Result</h2>
          <div className="card summary-grid">
            {job.result.bundle_id ? (
              <Field label="bundle">
                <button type="button" onClick={() => onOpenBundle(job.result!.bundle_id!)}>
                  {job.result.bundle_id}
                </button>
              </Field>
            ) : null}
            <Field label="package">{job.result.package_path ?? "—"}</Field>
            <Field label="run">{job.result.run_id ?? "—"}</Field>
            <Field label="sarif">{job.result.sarif_path ?? "—"}</Field>
          </div>
          {job.result.warnings.length > 0 ? (
            <>
              <h3>Warnings</h3>
              <ul>
                {job.result.warnings.map((warning) => (
                  <li key={warning}>{warning}</li>
                ))}
              </ul>
            </>
          ) : null}
        </>
      ) : null}

      {job.state === "canceled" ? (
        <Banner>
          Canceled. A cancellation is not a failure: there is no failure record, and the stage
          it stopped in is listed above.
        </Banner>
      ) : null}
    </section>
  );
}

export function StageTrack({ stages }: { stages: StageProgress[] }) {
  return (
    <ol className="stage-track">
      {stages.map((stage) => (
        <li key={stage.stage} className={`stage-${stage.state}`}>
          {stage.stage}
        </li>
      ))}
    </ol>
  );
}
