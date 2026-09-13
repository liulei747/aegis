/**
 * Compare two bundles: what changed between them.
 *
 * The delta table lists every key the API sent, in the API's order, rather than a hand-picked
 * subset -- a comparison that silently dropped a metric would be worse than a long table, since
 * the reader cannot tell the difference between "unchanged" and "not shown".
 *
 * The two bundle selectors default to the newest pair, because the useful comparison is almost
 * always "this run against the one before it".
 */

import { useState } from "react";
import { api } from "../api/client.ts";
import type { BundleDiff, BundleSummary } from "../api/types.ts";
import { Banner, Empty, usePolled } from "../components.tsx";
import { formatCount, formatDurationMs, formatTimestamp } from "../format.ts";

function signed(value: number): string {
  if (value === 0) return "0";
  return value > 0 ? `+${formatCount(value)}` : `−${formatCount(Math.abs(value))}`;
}

function deltaClass(value: number): string {
  if (value === 0) return "muted";
  return value > 0 ? "ok" : "warn";
}

function SetDiff({ title, diff }: { title: string; diff: { only_left: string[]; only_right: string[]; shared: number } }) {
  return (
    <>
      <h2>{title}</h2>
      <div className="stats">
        <span>
          共有 <strong>{formatCount(diff.shared)}</strong>
        </span>
        <span>
          仅左侧 <strong>{formatCount(diff.only_left.length)}</strong>
        </span>
        <span>
          仅右侧 <strong>{formatCount(diff.only_right.length)}</strong>
        </span>
      </div>
      {diff.only_left.length === 0 && diff.only_right.length === 0 ? (
        <Empty>两侧集合相同</Empty>
      ) : (
        <div className="two-col">
          <div>
            <span className="field-label">仅存在于左侧分析包</span>
            <ul className="id-list">
              {diff.only_left.map((item) => (
                <li key={item}>
                  <code>{item}</code>
                </li>
              ))}
            </ul>
          </div>
          <div>
            <span className="field-label">仅存在于右侧分析包</span>
            <ul className="id-list">
              {diff.only_right.map((item) => (
                <li key={item}>
                  <code>{item}</code>
                </li>
              ))}
            </ul>
          </div>
        </div>
      )}
    </>
  );
}

export function CompareScreen({
  bundles,
  initialLeft,
  onBack,
}: {
  bundles: BundleSummary[];
  initialLeft: string | null;
  onBack: () => void;
}) {
  const ids = bundles.map((bundle) => bundle.bundle_id);
  /**
   * Stored as "what the reader chose", null meaning "not chosen yet", and the effective value is
   * derived below.
   *
   * Initialising both with `useState(ids[1])` looked equivalent and was not: on a fresh page load
   * this screen mounts *before* the shell's bundle request resolves, so `ids` is empty, the right
   * side was frozen as `""` forever, and no diff request was ever made -- the screen sat blank
   * with no error to explain it. Deriving the default means it follows the list arriving.
   */
  const [leftChoice, setLeftChoice] = useState<string | null>(initialLeft);
  const [rightChoice, setRightChoice] = useState<string | null>(null);
  const left = leftChoice ?? ids[0] ?? "";
  // Default to the first bundle that is not the left one: the useful comparison is "this run
  // against another", and defaulting to the same id would make the screen start on an error.
  const right = rightChoice ?? ids.find((id) => id !== left) ?? ids[0] ?? "";

  const diff = usePolled<BundleDiff>(
    () => api.diff(left, right),
    [left, right],
    { enabled: left !== "" && right !== "" && left !== right },
  );

  if (bundles.length < 2) {
    return (
      <section>
        <button type="button" onClick={onBack}>
          ← 分析包
        </button>
        <Empty>
          对比需要两个分析包；此部署只有 {formatCount(bundles.length)} 个。
        </Empty>
      </section>
    );
  }

  return (
    <section>
      <div className="row">
        <button type="button" onClick={onBack}>
          ← 分析包
        </button>
        <h1>对比</h1>
      </div>

      <div className="row">
        <label>
          左侧
          <select value={left} onChange={(event) => setLeftChoice(event.target.value)}>
            {ids.map((id) => (
              <option key={id} value={id}>
                {id}
              </option>
            ))}
          </select>
        </label>
        <label>
          右侧
          <select value={right} onChange={(event) => setRightChoice(event.target.value)}>
            {ids.map((id) => (
              <option key={id} value={id}>
                {id}
              </option>
            ))}
          </select>
        </label>
      </div>

      {left === right ? <Banner kind="warn">请选择两个不同的分析包。</Banner> : null}
      {diff.error ? <Banner>{diff.error.detail}</Banner> : null}
      {diff.loading && !diff.data ? <p className="muted">对比中…</p> : null}

      {diff.data ? (
        <>
          <h2>计数</h2>
          <table className="table">
            <thead>
              <tr>
                <th>指标</th>
                <th className="num">左侧</th>
                <th className="num">右侧</th>
                <th className="num">差值</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(diff.data.delta).map(([key, value]) => (
                <tr key={key}>
                  <td>
                    <code>{key}</code>
                  </td>
                  <td className="num">{String(diff.data!.left[key] ?? "—")}</td>
                  <td className="num">{String(diff.data!.right[key] ?? "—")}</td>
                  <td className={`num ${deltaClass(value)}`}>{signed(value)}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <SetDiff title="方法集合" diff={diff.data.methods} />
          <SetDiff title="命中集合" diff={diff.data.findings} />

          <h2>阶段耗时差值</h2>
          <table className="table">
            <thead>
              <tr>
                <th>阶段</th>
                <th className="num">差值</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(diff.data.stage_delta_ms).map(([stage, ms]) => (
                <tr key={stage}>
                  <td>
                    <code>{stage}</code>
                  </td>
                  <td className={`num ${deltaClass(ms)}`}>
                    {ms > 0 ? "+" : ms < 0 ? "−" : ""}
                    {formatDurationMs(Math.abs(ms))}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>

          <p className="muted">
            左 <code>{diff.data.left.bundle_id}</code>，右{" "}
            <code>{diff.data.right.bundle_id}</code>
            {bundles[0] ? ` · 此部署最新的分析包：${formatTimestamp(bundles[0].created_at)}` : ""}
          </p>
        </>
      ) : null}
    </section>
  );
}
