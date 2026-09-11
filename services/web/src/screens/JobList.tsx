/**
 * The queue screen: what is running, what is queued, what just finished, and how to start
 * something.
 *
 * Every number comes from `GET /v1/jobs`. The progress track is driven by `units_done` /
 * `units_total` when the API published a total, and says "total unknown" when it did not --
 * the scan stage genuinely cannot report progress (it is one synchronous subprocess wait),
 * and inventing a denominator there would be a lie the reader could not detect.
 */

import { useState } from "react";
import { api, type ApiError } from "../api/client.ts";
import type { JobSummary } from "../api/types.ts";
import { StateBadge } from "../App.tsx";
import { formatCount, formatDurationMs, formatTimestamp, formatUnits } from "../format.ts";

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
      const accepted = await api.submitAssemble(body);
      const deduplicated = "deduplicated" in accepted && accepted.deduplicated;
      setMessage(
        deduplicated
          ? `${accepted.job_id} was already queued — attached to the existing job.`
          : `Accepted ${accepted.job_id} (${accepted.state}).`,
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
      <h1>Jobs</h1>

      <form className="card submit" onSubmit={submit}>
        <div className="row">
          <label>
            workspace
            <input
              value={workspace}
              onChange={(event) => setWorkspace(event.target.value)}
              placeholder="leave empty for the configured workspace root"
              size={40}
            />
          </label>
          <label>
            SARIF path
            <input
              value={sarifPath}
              onChange={(event) => setSarifPath(event.target.value)}
              placeholder="optional: assemble from an existing SARIF"
              size={40}
            />
          </label>
          <label className="checkbox">
            <input type="checkbox" checked={lsp} onChange={(event) => setLsp(event.target.checked)} />
            use language servers
          </label>
          <button type="submit" disabled={busy}>
            {busy ? "submitting…" : "submit job"}
          </button>
        </div>
        {message ? <p className="ok">{message}</p> : null}
        {failure ? (
          <p className="error">
            {failure.status === 503
              ? `${failure.detail} — this deployment runs jobs synchronously.`
              : failure.detail}
          </p>
        ) : null}
      </form>

      {loading && jobs.length === 0 ? <p className="muted">loading…</p> : null}
      {!loading && jobs.length === 0 ? <p className="empty">no jobs yet</p> : null}

      <ul className="job-list">
        {jobs.map((job) => (
          <li key={job.job_id} className="card job" onClick={() => onOpen(job.job_id)}>
            <div className="job-head">
              <code>{job.job_id}</code>
              <StateBadge job={job} />
              <span className="muted">{job.kind}</span>
              <span className="muted right">{formatTimestamp(job.submitted_at)}</span>
            </div>
            <div className="job-body">
              <span>
                stage <strong>{job.stage}</strong>
              </span>
              <span>{formatUnits(job.units_done, job.units_total, job.unit_label)}</span>
              <span>attempt {job.attempt}</span>
              <span>{formatDurationMs(job.duration_ms)}</span>
              {job.bundle_id ? <code className="bundle-id">{job.bundle_id}</code> : null}
              {job.failure_mode ? <span className="error">{job.failure_mode}</span> : null}
            </div>
            <div className="counters">
              {Object.entries(job.counters).map(([key, value]) => (
                <span key={key} className="counter">
                  {key} <strong>{formatCount(value)}</strong>
                </span>
              ))}
            </div>
          </li>
        ))}
      </ul>
    </section>
  );
}
