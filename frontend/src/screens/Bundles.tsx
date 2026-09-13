/**
 * Bundles: everything on disk, newest first.
 *
 * The list is deliberately a table rather than a card per bundle: the useful question here is
 * comparative ("which of these is thin, which came from a suspicious scan, which has been
 * judged?"), and cards make a comparison harder to read down a column.
 *
 * Trust levels are not shown in this table even though the API can report them. Trust is a
 * per-method judgement, and this list has no per-method data; the detail screen is where the
 * provider legend lives, so the badge here would be a summarised number nobody could check.
 */

import type { ApiError } from "../api/client.ts";
import type { BundleSummary } from "../api/types.ts";
import { Banner, Empty } from "../components.tsx";
import { formatCount, formatDurationMs, formatRelative, formatTimestamp } from "../format.ts";

export function BundleListScreen({
  bundles,
  loading,
  error,
  onOpen,
  onCompare,
  onVerdicts,
}: {
  bundles: BundleSummary[];
  loading: boolean;
  error: ApiError | null;
  onOpen: (bundleId: string) => void;
  onCompare: (bundleId: string) => void;
  onVerdicts: (bundleId: string) => void;
}) {
  return (
    <section>
      {error ? <Banner>{error.detail}</Banner> : null}
      {loading && bundles.length === 0 ? <p className="muted">加载中…</p> : null}
      {!loading && bundles.length === 0 ? (
        <Empty>暂无分析包 —— 可在「任务」页面提交任务，或调用 POST /v1/assemble。</Empty>
      ) : null}

      {bundles.length > 0 ? (
        <table className="table">
          <thead>
            <tr>
              <th>分析包</th>
              <th>创建时间</th>
              <th>工作区</th>
              <th className="num">上下文</th>
              <th className="num">命中</th>
              <th className="num">token</th>
              <th>来源</th>
              <th className="num">裁剪</th>
              <th>研判</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {bundles.map((bundle) => (
              <tr key={bundle.bundle_id}>
                <td>
                  <button type="button" className="link" onClick={() => onOpen(bundle.bundle_id)}>
                    {bundle.bundle_id}
                  </button>
                  {bundle.error ? <div className="error">{bundle.error}</div> : null}
                  {bundle.zero_findings_suspicious ? (
                    <div className="warn" title="扫描完全没有命中，这很可疑">
                      ⚠ 可疑的零命中
                    </div>
                  ) : null}
                </td>
                <td title={formatTimestamp(bundle.created_at)}>
                  {formatRelative(bundle.created_at)}
                </td>
                <td className="muted">{bundle.workspace ?? "—"}</td>
                <td className="num">{formatCount(bundle.focus_count)}</td>
                <td className="num">{formatCount(bundle.coverage?.discoverable ?? null)}</td>
                <td className="num">~{formatCount(bundle.estimated_tokens)}</td>
                <td className="note">
                  {bundle.providers.length > 0 ? bundle.providers.join(", ") : "—"}
                </td>
                <td className="num">
                  {formatCount(bundle.prune_count)}
                  {bundle.degradation_count > 0 ? (
                    <span className="warn" title="已记录的降级">
                      {" "}
                      ⚠{formatCount(bundle.degradation_count)}
                    </span>
                  ) : null}
                </td>
                <td>
                  {bundle.has_ai_report ? (
                    <button type="button" className="link" onClick={() => onVerdicts(bundle.bundle_id)}>
                      已研判
                    </button>
                  ) : (
                    <span className="muted">尚未研判</span>
                  )}
                </td>
                <td className="note">
                  <span className="muted">{formatDurationMs(bundle.duration_ms)}</span>{" "}
                  <button type="button" className="link" onClick={() => onCompare(bundle.bundle_id)}>
                    对比
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </section>
  );
}
