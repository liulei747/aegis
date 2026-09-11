/**
 * Compare two bundles: every number here is a difference the API already computed.
 *
 * `views.diff` returns `delta`, `only_left`, `only_right` and `stage_delta_ms` precisely so
 * that a client does not subtract two payloads itself. Doing it here would look harmless and
 * would be the first place this console started producing numbers of its own -- and it would
 * be the wrong numbers, because "methods only in one bundle" is a set difference over
 * content-derived ids, not an arithmetic one.
 */

import { useState } from "react";
import { api } from "../api/client.ts";
import type { BundleDiff, BundleSummary } from "../api/types.ts";
import { Banner, Empty, usePolled } from "../App.tsx";
import { formatCount, formatDelta, formatDurationMs } from "../format.ts";

export function CompareScreen({
  bundles,
  initialLeft,
  onBack,
}: {
  bundles: BundleSummary[];
  initialLeft: string | null;
  onBack: () => void;
}) {
  const [left, setLeft] = useState<string>(initialLeft ?? bundles[0]?.bundle_id ?? "");
  const [right, setRight] = useState<string>(
    bundles.find((bundle) => bundle.bundle_id !== (initialLeft ?? bundles[0]?.bundle_id))
      ?.bundle_id ?? "",
  );

  const ready = Boolean(left && right && left !== right);
  const { data, error, loading } = usePolled<BundleDiff>(
    () => api.diff(left, right),
    [left, right],
    { enabled: ready },
  );

  return (
    <section>
      <div className="row">
        <button type="button" onClick={onBack}>
          ← bundles
        </button>
        <h1>Compare</h1>
      </div>

      <div className="card row">
        <label>
          left
          <select value={left} onChange={(event) => setLeft(event.target.value)}>
            {bundles.map((bundle) => (
              <option key={bundle.bundle_id} value={bundle.bundle_id}>
                {bundle.bundle_id}
              </option>
            ))}
          </select>
        </label>
        <label>
          right
          <select value={right} onChange={(event) => setRight(event.target.value)}>
            {bundles.map((bundle) => (
              <option key={bundle.bundle_id} value={bundle.bundle_id}>
                {bundle.bundle_id}
              </option>
            ))}
          </select>
        </label>
      </div>

      {bundles.length < 2 ? (
        <Empty>two bundles are needed to compare; only one exists.</Empty>
      ) : null}
      {left === right && left ? <Banner>Pick two different bundles.</Banner> : null}
      {error ? <Banner>could not compare: {error.detail}</Banner> : null}
      {loading && !data ? <p className="muted">comparing…</p> : null}

      {data ? (
        <>
          <h2>Counters</h2>
          <table className="table">
            <thead>
              <tr>
                <th>metric</th>
                <th className="num">{data.left.bundle_id}</th>
                <th className="num">{data.right.bundle_id}</th>
                <th className="num">delta</th>
              </tr>
            </thead>
            <tbody>
              {Object.keys(data.delta).map((key) => (
                <tr key={key}>
                  <td>{key}</td>
                  <td className="num">
                    {key === "duration_ms"
                      ? formatDurationMs(Number(data.left[key] ?? 0))
                      : formatCount(Number(data.left[key] ?? 0))}
                  </td>
                  <td className="num">
                    {key === "duration_ms"
                      ? formatDurationMs(Number(data.right[key] ?? 0))
                      : formatCount(Number(data.right[key] ?? 0))}
                  </td>
                  <td className="num">{formatDelta(data.delta[key] ?? 0)}</td>
                </tr>
              ))}
            </tbody>
          </table>

          <h2>Method sets</h2>
          <p>
            shared {formatCount(data.methods.shared)} · only left{" "}
            {formatCount(data.methods.only_left.length)} · only right{" "}
            {formatCount(data.methods.only_right.length)}
          </p>
          <IdLists left={data.methods.only_left} right={data.methods.only_right} />

          <h2>Finding sets</h2>
          <p>
            shared {formatCount(data.findings.shared)} · only left{" "}
            {formatCount(data.findings.only_left.length)} · only right{" "}
            {formatCount(data.findings.only_right.length)}
          </p>
          <IdLists left={data.findings.only_left} right={data.findings.only_right} />

          <h2>Stage timing delta</h2>
          <table className="table">
            <thead>
              <tr>
                <th>stage</th>
                <th className="num">right − left</th>
              </tr>
            </thead>
            <tbody>
              {Object.entries(data.stage_delta_ms).map(([stage, delta]) => (
                <tr key={stage}>
                  <td>{stage}</td>
                  <td className="num">{formatDelta(delta)} ms</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}
    </section>
  );
}

function IdLists({ left, right }: { left: string[]; right: string[] }) {
  if (left.length === 0 && right.length === 0) return <p className="muted">identical sets</p>;
  return (
    <div className="two-col">
      <div>
        <h4>only left</h4>
        <ul className="id-list">
          {left.map((id) => (
            <li key={id}>
              <code>{id}</code>
            </li>
          ))}
        </ul>
      </div>
      <div>
        <h4>only right</h4>
        <ul className="id-list">
          {right.map((id) => (
            <li key={id}>
              <code>{id}</code>
            </li>
          ))}
        </ul>
      </div>
    </div>
  );
}
