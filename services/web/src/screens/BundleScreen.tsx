/**
 * One bundle: the funnel, the stage timings, provenance, the scan ledger, and — the screen
 * that matters most — each analysis context with its call chain and inline method bodies.
 *
 * The layout follows the prototype in `docs/VISUAL.md`, and the changes it asks for relative
 * to a flat console are all implemented here: the call chain is a tree ordered by depth with
 * the direction spelled out, the provenance chain shows *names* rather than ids, the evidence
 * snippet sits beside the node it belongs to, bodies are inline and collapsible, and the
 * reason a branch stops is attached to the branch. Every one of those is a rendering choice
 * over data the API already produced -- `views.context_views` even pre-resolves the origin
 * chain to names.
 */

import { useEffect, useState } from "react";
import { api } from "../api/client.ts";
import type { ContextView, MethodIndexRow, Observability } from "../api/types.ts";
import { Banner, Empty, Field, TrustBadge, usePolled } from "../App.tsx";
import {
  formatConfidence,
  formatCount,
  formatDurationMs,
  formatPercent,
  formatTimestamp,
  stageLabel,
} from "../format.ts";

export function BundleScreen({
  bundleId,
  onBack,
  onCompare,
}: {
  bundleId: string;
  onBack: () => void;
  onCompare: () => void;
}) {
  const views = usePolled<Observability>(() => api.observability(bundleId), [bundleId]);
  const contexts = usePolled<{ contexts: ContextView[] }>(() => api.contexts(bundleId), [bundleId]);
  const methods = usePolled<{ count: number; methods: MethodIndexRow[] }>(
    () => api.methods(bundleId),
    [bundleId],
  );

  if (views.loading && !views.data) return <p className="muted">loading {bundleId}…</p>;
  if (views.error && !views.data) {
    return (
      <section>
        <button type="button" onClick={onBack}>
          ← bundles
        </button>
        <Banner>
          {views.error.status === 404
            ? `${bundleId} not found (removed, or never written).`
            : views.error.detail}
        </Banner>
      </section>
    );
  }
  if (!views.data) return <Empty>no bundle</Empty>;

  const { overview, funnel, timeline, providers, scan, degradations, prunes, provider_legend } =
    views.data;

  return (
    <section>
      <div className="row">
        <button type="button" onClick={onBack}>
          ← bundles
        </button>
        <h1>{overview.bundle_id}</h1>
        <span className="muted">run {overview.run_id}</span>
        <button type="button" onClick={onCompare}>
          compare
        </button>
        <a className="right" href={`/v1/bundles/${overview.bundle_id}/archive`}>
          download zip
        </a>
      </div>
      {views.error ? <Banner>last poll failed: {views.error.detail}</Banner> : null}

      <div className="card summary-grid">
        <Field label="contexts">{formatCount(overview.context_count)}</Field>
        <Field label="methods">{formatCount(overview.method_count)}</Field>
        <Field label="findings">{formatCount(overview.finding_count)}</Field>
        <Field label="tokens">~{formatCount(overview.estimated_tokens)}</Field>
        <Field label="duration">{formatDurationMs(overview.duration_ms)}</Field>
        <Field label="workspace">{overview.workspace_root}</Field>
        <Field label="created">{formatTimestamp(overview.created_at)}</Field>
        <Field label="worst trust">
          <TrustBadge trust={overview.worst_trust} />
        </Field>
        <Field label="prunes">{formatCount(overview.prune_count)}</Field>
        <Field label="degradations">{formatCount(overview.degradation_count)}</Field>
        <Field label="truncated contexts">{formatCount(overview.truncated_contexts)}</Field>
      </div>

      {overview.warning_flags.length > 0 ? (
        <div className="banner warn">
          {overview.warning_flags.map((flag) => (
            <div key={flag}>⚠ {flag}</div>
          ))}
        </div>
      ) : null}

      <h2>Funnel</h2>
      <p className="muted">
        Every step is the same unit as the one before it, so a loss is always a subtraction.
      </p>
      <table className="table funnel">
        <thead>
          <tr>
            <th>step</th>
            <th className="num">count</th>
            <th className="num">of previous</th>
            <th className="num">lost</th>
            <th>why</th>
          </tr>
        </thead>
        <tbody>
          {funnel.map((step) => (
            <tr key={step.key}>
              <td title={step.label}>
                <code>{step.key}</code>
              </td>
              <td className="num">
                <Bar value={step.of_first} />
                {formatCount(step.count)}
              </td>
              <td className="num">{formatPercent(step.of_previous)}</td>
              <td className="num">{step.lost > 0 ? formatCount(step.lost) : ""}</td>
              <td className="note">
                {step.loss_reasons.length > 0 ? step.loss_reasons.join(", ") : ""}
                {step.note ? <div className="muted">{step.note}</div> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Stage timings</h2>
      <table className="table">
        <thead>
          <tr>
            <th>stage</th>
            <th className="num">time</th>
            <th className="num">share</th>
          </tr>
        </thead>
        <tbody>
          {timeline.map((stage) => (
            <tr key={stage.key}>
              <td title={stageLabel(stage.key, views.data!.stage_labels)}>{stage.label}</td>
              <td className="num">{formatDurationMs(stage.ms)}</td>
              <td className="num">{formatPercent(stage.share)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>Provenance</h2>
      <table className="table">
        <thead>
          <tr>
            <th>provider</th>
            <th>trust</th>
            <th className="num">confidence</th>
            <th className="num">methods</th>
            <th className="num">edges</th>
            <th className="num">focus</th>
            <th>meaning</th>
          </tr>
        </thead>
        <tbody>
          {providers.map((provider) => (
            <tr key={provider.provider}>
              <td>
                <code>{provider.provider}</code>
              </td>
              <td>
                <TrustBadge trust={provider.trust} />
              </td>
              <td className="num">{formatConfidence(provider.confidence)}</td>
              <td className="num">{formatCount(provider.methods)}</td>
              <td className="num">{formatCount(provider.edges)}</td>
              <td className="num">{formatCount(provider.focus_methods)}</td>
              <td className="note">{provider.note}</td>
            </tr>
          ))}
        </tbody>
      </table>

      {scan ? (
        <>
          <h2>Scanner ledger</h2>
          <div className="card summary-grid">
            <Field label="engine">
              {scan.engine} {scan.engine_version}
            </Field>
            <Field label="exit code">{scan.returncode}</Field>
            <Field label="rules">{scan.configured ? "explicit" : "auto"}</Field>
            <Field label="suspicious zero">{String(scan.zero_findings_is_suspicious)}</Field>
            {scan.failure_mode ? <Field label="failure mode">{scan.failure_mode}</Field> : null}
          </div>
          <pre className="code">{scan.command_line || "(no command recorded)"}</pre>
          {Object.keys(scan.rule_counts).length > 0 ? (
            <div className="counters">
              {Object.entries(scan.rule_counts).map(([rule, count]) => (
                <span key={rule} className="counter">
                  {rule} <strong>{count}</strong>
                </span>
              ))}
            </div>
          ) : null}
          {Object.keys(scan.severity_counts).length > 0 ? (
            <div className="counters">
              {Object.entries(scan.severity_counts).map(([severity, count]) => (
                <span key={severity} className="counter">
                  {severity} <strong>{count}</strong>
                </span>
              ))}
            </div>
          ) : null}
          {scan.stderr_tail ? <pre className="code warn">{scan.stderr_tail}</pre> : null}
        </>
      ) : null}

      {degradations.length > 0 ? (
        <>
          <h2>What this bundle could not do</h2>
          <table className="table">
            <thead>
              <tr>
                <th>capability</th>
                <th>reason</th>
                <th>impact</th>
              </tr>
            </thead>
            <tbody>
              {degradations.map((degradation) => (
                <tr key={`${degradation.capability}:${degradation.reason}`}>
                  <td>
                    <code>{degradation.capability}</code>
                  </td>
                  <td className="note">{degradation.reason}</td>
                  <td className="note">{degradation.impact}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      ) : null}

      {prunes.length > 0 ? (
        <>
          <h2>Pruned during assembly</h2>
          <ul className="prune-list">
            {prunes.map((prune, index) => (
              <li key={`${prune.rule}-${index}`}>
                <code>{prune.rule}</code> {prune.detail}
              </li>
            ))}
          </ul>
        </>
      ) : null}

      <h2>Contexts</h2>
      {contexts.error ? <Banner>could not load contexts: {contexts.error.detail}</Banner> : null}
      {(contexts.data?.contexts ?? []).map((context) => (
        <ContextCard
          key={context.context_id}
          bundleId={bundleId}
          context={context}
          legend={provider_legend}
        />
      ))}

      <h2>Methods</h2>
      {methods.error ? <Banner>could not load methods: {methods.error.detail}</Banner> : null}
      <MethodTable rows={methods.data?.methods ?? []} />
    </section>
  );
}

/** A bar whose width is a share the API computed. It scales an existing number; it does not
 * invent one, and a missing share renders as no bar rather than a full one. */
function Bar({ value }: { value: number | null }) {
  if (value === null || value === undefined) return null;
  return <span className="bar" style={{ width: `${Math.max(0, Math.min(1, value)) * 100}%` }} />;
}

function ContextCard({
  bundleId,
  context,
  legend,
}: {
  bundleId: string;
  context: ContextView;
  legend: Record<string, { label: string; trust: string }>;
}) {
  const chain = [...context.methods].sort((a, b) => a.depth - b.depth || a.name.localeCompare(b.name));
  return (
    <article className="card context">
      <header>
        <code className="context-id">{context.context_id}</code>
        <strong>{context.focus_name}</strong>
        <span className="muted">{context.focus_location}</span>
        <TrustBadge trust={legend[context.focus_provider]?.trust ?? "unknown"} />
        <span className={`severity severity-${context.worst_severity}`}>
          {context.worst_severity}
        </span>
        <span className="muted right">~{formatCount(context.estimated_tokens)} tokens</span>
      </header>

      {context.unreached_focus ? (
        <Banner>
          The focus method could not be read from the workspace; the chain shows what was found.
        </Banner>
      ) : null}

      <h3>Static-scan findings</h3>
      {context.findings.length === 0 ? (
        <p className="empty">no finding attached (context kept for graph connectivity)</p>
      ) : (
        <ul className="finding-list">
          {context.findings.map((finding) => (
            <li key={finding.finding_id}>
              <code>{finding.finding_id.slice(0, 12)}</code>
              <span className={`severity severity-${finding.severity}`}>{finding.severity}</span>
              <code>{finding.rule_id}</code>
              <span className="muted">{finding.location}</span>
              <div>{finding.message}</div>
              {finding.snippet ? <pre className="code">{finding.snippet}</pre> : null}
            </li>
          ))}
        </ul>
      )}

      <h3>Call chain</h3>
      <ul className="chain">
        {chain.map((method) => (
          <li key={method.method_id} style={{ marginLeft: `${method.depth * 1.4}rem` }}>
            <span className="arrow">{arrow(method.direction)}</span>
            <span className="depth">d{method.depth}</span>
            <button
              type="button"
              className="link"
              onClick={() => {
                window.location.hash = `#/bundle/${bundleId}`;
              }}
            >
              {method.qualified_name}
            </button>
            <TrustBadge trust={method.trust} />
            <span className="muted">{method.location}</span>
            {method.is_focus ? <span className="badge">focus</span> : null}
            {method.via ? <span className="muted">· {method.via}</span> : null}
            {method.origin_chain.length > 0 ? (
              <div className="note muted">chain: {method.origin_chain.join(" → ")}</div>
            ) : null}
            <MethodBody bundleId={bundleId} methodId={method.method_id} name={method.qualified_name} />
          </li>
        ))}
      </ul>

      <h3>Edges</h3>
      <table className="table">
        <thead>
          <tr>
            <th>caller</th>
            <th>callee</th>
            <th>direction</th>
            <th>trust</th>
            <th className="num">conf</th>
            <th>evidence</th>
          </tr>
        </thead>
        <tbody>
          {context.edges.map((edge, index) => (
            <tr key={`${edge.caller_name}-${edge.callee_name}-${index}`}>
              <td>{edge.caller_name}</td>
              <td>{edge.callee_name}</td>
              <td>{edge.direction}</td>
              <td>
                <TrustBadge trust={edge.trust} />
              </td>
              <td className="num">{formatConfidence(edge.confidence)}</td>
              <td className="note">
                {edge.call_site ? <div className="muted">{edge.call_site}</div> : null}
                {edge.snippet ? <pre className="code">{edge.snippet}</pre> : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {context.prunes.length > 0 ? (
        <>
          <h3>Why this unit stops where it does</h3>
          <ul className="prune-list">
            {context.prunes.map((prune, index) => (
              <li key={`${prune.rule}-${index}`}>
                <code>{prune.rule}</code> {prune.detail}
              </li>
            ))}
          </ul>
        </>
      ) : null}
    </article>
  );
}

/** The body is fetched on demand and shown as text: the API stores the exact bytes it read,
 * and rendering it as anything else would be this console's interpretation. */
function MethodBody({
  bundleId,
  methodId,
  name,
}: {
  bundleId: string;
  methodId: string;
  name: string;
}) {
  const [open, setOpen] = useState(false);
  const [body, setBody] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open || body !== null || error !== null) return;
    let cancelled = false;
    api
      .methodBody(bundleId, methodId)
      .then((text) => {
        if (!cancelled) setBody(text);
      })
      .catch((caught: { detail?: string }) => {
        if (!cancelled) setError(caught.detail ?? "unavailable");
      });
    return () => {
      cancelled = true;
    };
  }, [open, body, error, bundleId, methodId]);

  return (
    <div className="body-toggle">
      <button type="button" onClick={() => setOpen((value) => !value)}>
        {open ? "hide body" : `show body of ${name}`}
      </button>
      {open ? (
        error ? (
          <p className="error">{error}</p>
        ) : body === null ? (
          <p className="muted">loading…</p>
        ) : (
          <pre className="code body">{body}</pre>
        )
      ) : null}
    </div>
  );
}

function MethodTable({ rows }: { rows: MethodIndexRow[] }) {
  return (
    <table className="table">
      <thead>
        <tr>
          <th>method</th>
          <th>location</th>
          <th>kind</th>
          <th>provider</th>
          <th>trust</th>
          <th className="num">depth</th>
          <th>contexts</th>
        </tr>
      </thead>
      <tbody>
        {rows.map((row) => (
          <tr key={row.method_id}>
            <td>
              {row.qualified_name} {row.is_focus ? <span className="badge">focus</span> : null}
            </td>
            <td className="muted">{row.location}</td>
            <td>{row.kind}</td>
            <td>
              <code>{row.provider}</code>
            </td>
            <td>
              <TrustBadge trust={row.trust} />
            </td>
            <td className="num">{row.depth ?? "—"}</td>
            <td className="muted">{row.contexts.join(", ")}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
}

function arrow(direction: string | null): string {
  if (direction === "caller") return "↑";
  if (direction === "callee") return "↓";
  return "•";
}
