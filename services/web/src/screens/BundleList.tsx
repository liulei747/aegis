/**
 * The bundle list: one card per finished analysis package.
 *
 * The trust badges and the warning flags come straight from the API. That matters for the
 * same reason it does everywhere else in this console -- a bundle whose edges are all
 * heuristics should look different from one with a real language server behind it, and that
 * judgement is the API's to make (`views.overview`). The console's job is to put it in
 * front of the reader before they open anything.
 */

import type { ApiError } from "../api/client.ts";
import type { BundleSummary } from "../api/types.ts";
import { TrustBadge } from "../App.tsx";
import { formatCount, formatDurationMs, formatTimestamp } from "../format.ts";

export function BundleListScreen({
  bundles,
  loading,
  error,
  legend,
  onOpen,
  onCompare,
}: {
  bundles: BundleSummary[];
  loading: boolean;
  error: ApiError | null;
  legend: Record<string, { label: string; trust: string; confidence: number; note: string }>;
  onOpen: (bundleId: string) => void;
  onCompare: (bundleId: string) => void;
}) {
  return (
    <section>
      <h1>Bundles</h1>
      {error ? <p className="error">could not list bundles: {error.detail}</p> : null}
      {loading && bundles.length === 0 ? <p className="muted">loading…</p> : null}
      {!loading && bundles.length === 0 ? (
        <p className="empty">
          no bundles yet — submit a job, or run <code>python scripts/demo.py</code>.
        </p>
      ) : null}

      <ul className="bundle-list">
        {bundles.map((bundle) => {
          const coverage = bundle.coverage;
          return (
            <li key={bundle.bundle_id} className="card bundle">
              <div className="job-head">
                <code className="bundle-id">{bundle.bundle_id}</code>
                <span className="muted right">{formatTimestamp(bundle.created_at)}</span>
              </div>
              <div className="job-body">
                <span>{formatCount(bundle.focus_count)} contexts</span>
                <span>{formatCount(bundle.estimated_tokens)} tokens</span>
                <span>{formatDurationMs(bundle.duration_ms)}</span>
                {coverage ? (
                  <span title="findings bundled / discoverable">
                    findings {coverage.bundled}/{coverage.discoverable}
                  </span>
                ) : null}
                {bundle.engine ? <span className="muted">engine {bundle.engine}</span> : null}
              </div>
              <div className="job-body">
                {bundle.providers.map((provider) => (
                  // The trust level is read from the published legend, not inferred from the
                  // provider's name: the mapping is the API's judgement and this is the
                  // console echoing it.
                  <TrustBadge key={provider} trust={legend[provider]?.trust ?? "unknown"} />
                ))}
                {bundle.prune_count > 0 ? (
                  <span className="badge" title="prune decisions recorded">
                    pruned {bundle.prune_count}
                  </span>
                ) : null}
                {bundle.degradation_count > 0 ? (
                  <span className="badge warn" title="recorded degradations">
                    degraded {bundle.degradation_count}
                  </span>
                ) : null}
                {bundle.zero_findings_suspicious ? (
                  <span className="badge warn">suspicious empty scan</span>
                ) : null}
                {bundle.error ? <span className="badge warn">{bundle.error}</span> : null}
                <span className="right">
                  <button type="button" onClick={() => onOpen(bundle.bundle_id)}>
                    open
                  </button>
                  <button type="button" onClick={() => onCompare(bundle.bundle_id)}>
                    compare
                  </button>
                </span>
              </div>
            </li>
          );
        })}
      </ul>
    </section>
  );
}
