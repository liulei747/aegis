/**
 * One bundle: how it was built, what is in it, and what the model made of it.
 *
 * The screen follows the bundle's own order -- funnel, timings, provenance, scanner ledger,
 * contexts, verdicts, methods -- because that is the order the pipeline produces them, and a
 * loss in the funnel is explained by the stage that follows it.
 *
 * Two things are shown that a tidier screen would hide: the *prunes* and the *degradations*.
 * Both are cases where the bundle is thinner than the workspace, and a reader who cannot see
 * them cannot tell "nothing was there" from "we could not read it".
 */

import { useState } from "react";
import { api } from "../api/client.ts";
import type { ContextView, MethodIndexRow } from "../api/types.ts";
import { Banner, Empty, Field, SeverityBadge, Stat, TrustBadge, usePolled } from "../components.tsx";
import {
  formatCount,
  formatDurationMs,
  formatPercent,
  formatTimestamp,
  worstSeverity,
} from "../format.ts";
import { VerdictsPanel } from "./Verdicts.tsx";

function Bar({ value }: { value: number | null }) {
  if (value === null || value === undefined) return null;
  const width = Math.max(0, Math.min(1, value)) * 100;
  return <span className="bar" style={{ width: `${width}%` }} />;
}

function BodyViewer({ bundleId, methodId }: { bundleId: string; methodId: string }) {
  const [body, setBody] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const load = async () => {
    try {
      setBody(await api.methodBody(bundleId, methodId));
    } catch (caught) {
      setError((caught as { detail?: string }).detail ?? "不可用");
    }
  };
  if (body !== null) return <pre className="code">{body}</pre>;
  return (
    <span>
      <button type="button" className="link" onClick={load}>
        显示方法体
      </button>
      {error ? <span className="error"> {error}</span> : null}
    </span>
  );
}

function ContextCard({
  bundleId,
  context,
  legend,
}: {
  bundleId: string;
  context: ContextView;
  legend: Record<string, { label: string; trust: string; note: string }>;
}) {
  const chain = [...context.methods].sort(
    (a, b) => a.depth - b.depth || a.name.localeCompare(b.name),
  );
  return (
    <article className="card context">
      <header>
        <code className="context-id">{context.context_id}</code>
        <strong>{context.focus_name}</strong>
        <span className="muted">{context.focus_location}</span>
        <TrustBadge trust={legend[context.focus_provider]?.trust ?? "unknown"} />
        <SeverityBadge severity={context.worst_severity} />
        <span className="muted right">~{formatCount(context.estimated_tokens)} token</span>
      </header>

      {context.unreached_focus ? (
        <Banner kind="warn">
          无法从工作区读取焦点方法；调用链展示的是实际找到的内容。
        </Banner>
      ) : null}
      {context.truncated ? (
        <Banner kind="warn">
          此上下文超出预算允许的大小，已被截断，因此模型看到的内容少于下方所列。
        </Banner>
      ) : null}

      <h3>静态扫描命中</h3>
      {context.findings.length === 0 ? (
        <p className="empty">未附带命中（该上下文因调用图连通性被保留）</p>
      ) : (
        <ul className="finding-list">
          {context.findings.map((finding) => (
            <li key={finding.finding_id}>
              <code>{finding.finding_id.slice(0, 12)}</code>
              <SeverityBadge severity={finding.severity} />
              <code>{finding.rule_id}</code>
              <span className="muted">{finding.location}</span>
              <div>{finding.message}</div>
              {finding.snippet ? <pre className="code">{finding.snippet}</pre> : null}
            </li>
          ))}
        </ul>
      )}

      <h3>调用链</h3>
      <ul className="chain">
        {chain.map((method) => (
          <li key={method.method_id} className={method.is_focus ? "focus" : ""}>
            <span className={`dir dir-${method.direction ?? "focus"}`}>
              {method.direction === "caller" ? "↑" : method.direction === "callee" ? "↓" : "•"}
            </span>
            <span className="muted">d{method.depth}</span>
            <strong>{method.name}</strong>
            <TrustBadge trust={method.trust} />
            <span className="muted">{method.location}</span>
            {method.via ? <span className="note">· {method.via}</span> : null}
            <span className="right">
              <BodyViewer bundleId={bundleId} methodId={method.method_id} />
            </span>
          </li>
        ))}
      </ul>

      <h3>边</h3>
      {context.edges.length === 0 ? (
        <p className="empty">此上下文未记录任何边</p>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>调用方</th>
              <th>被调用方</th>
              <th>方向</th>
              <th>可信度</th>
              <th className="num">置信度</th>
              <th>调用点</th>
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
                <td className="num">{formatPercent(edge.confidence, 2)}</td>
                <td className="note">
                  {edge.call_site ?? "—"}
                  {edge.snippet ? <pre className="code">{edge.snippet}</pre> : null}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {context.prunes.length > 0 ? (
        <>
          <h3>此上下文内发生的裁剪</h3>
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

export function BundleDetailScreen({
  bundleId,
  onBack,
  onCompare,
  onVerdicts,
}: {
  bundleId: string;
  onBack: () => void;
  onCompare: () => void;
  onVerdicts: (bundleId: string) => void;
}) {
  const views = usePolled(() => api.observability(bundleId), [bundleId]);
  const contexts = usePolled(() => api.contexts(bundleId), [bundleId]);
  const methods = usePolled(() => api.methods(bundleId), [bundleId]);
  const [openBody, setOpenBody] = useState<string | null>(null);

  if (views.error && !views.data) {
    return (
      <section>
        <button type="button" onClick={onBack}>
          ← 分析包
        </button>
        <Banner>
          {views.error.status === 404
            ? `未找到 ${bundleId}（已被删除，或从未写入）。`
            : views.error.detail}
        </Banner>
      </section>
    );
  }
  if (!views.data) {
    return (
      <section>
        <button type="button" onClick={onBack}>
          ← 分析包
        </button>
        <Empty>正在加载 {bundleId}…</Empty>
      </section>
    );
  }

  const { overview, funnel, timeline, providers, scan, degradations, prunes, provider_legend } =
    views.data;
  const worst = worstSeverity(
    (contexts.data?.contexts ?? []).map((context) => context.worst_severity),
  );

  return (
    <section>
      <div className="row">
        <button type="button" onClick={onBack}>
          ← 分析包
        </button>
        <h1>{overview.bundle_id}</h1>
        <span className="muted">运行 {overview.run_id}</span>
        <button type="button" onClick={onCompare}>
          对比
        </button>
        <button type="button" className="right" onClick={() => onVerdicts(bundleId)}>
          快速研判
        </button>
        <a className="button" href={api.archiveUrl(bundleId)}>
          下载 zip
        </a>
      </div>

      {views.error ? <Banner kind="warn">上次轮询失败：{views.error.detail}</Banner> : null}

      <div className="card summary-grid">
        <Stat label="上下文" value={formatCount(overview.context_count)} />
        <Stat label="方法" value={formatCount(overview.method_count)} />
        <Stat label="命中" value={formatCount(overview.finding_count)} />
        <Stat label="token" value={`~${formatCount(overview.estimated_tokens)}`} />
        <Stat label="耗时" value={formatDurationMs(overview.duration_ms)} />
        <Stat label="工作区" value={<code>{overview.workspace_root}</code>} />
        <Stat label="创建时间" value={formatTimestamp(overview.created_at)} />
        <Stat label="最低可信度" value={<TrustBadge trust={overview.worst_trust} />} />
        <Stat label="最高严重度" value={<SeverityBadge severity={worst} />} />
        <Stat label="裁剪" value={formatCount(overview.prune_count)} />
        <Stat label="降级" value={formatCount(overview.degradation_count)} />
        <Stat label="被截断的上下文" value={formatCount(overview.truncated_contexts)} />
      </div>

      {overview.warning_flags.length > 0 ? (
        <Banner kind="warn">
          {overview.warning_flags.map((flag) => (
            <div key={flag}>⚠ {flag}</div>
          ))}
        </Banner>
      ) : null}

      <h2>漏斗</h2>
      <p className="muted">
        每一步都以前一步相同的单位计数，因此损失永远是一次减法。
      </p>
      <table className="table funnel">
        <thead>
          <tr>
            <th>步骤</th>
            <th className="num">计数</th>
            <th className="num">占上一步</th>
            <th className="num">损失</th>
            <th>原因</th>
          </tr>
        </thead>
        <tbody>
          {funnel.map((step) => (
            <tr key={step.key}>
              {/* 显示 `label`（中文），把 `key` 放进 tooltip。`key` 是 API 的标识符
                  （discovered / located / …），中文界面上它不该当正文，但排查问题时要能查到。 */}
              <td title={step.key}>{step.label}</td>
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

      <h2>阶段耗时</h2>
      <table className="table">
        <thead>
          <tr>
            <th>阶段</th>
            <th className="num">耗时</th>
            <th className="num">占比</th>
          </tr>
        </thead>
        <tbody>
          {timeline.map((stage) => (
            <tr key={stage.key}>
              <td>{stage.label}</td>
              <td className="num">{formatDurationMs(stage.ms)}</td>
              <td className="num">{formatPercent(stage.share)}</td>
            </tr>
          ))}
        </tbody>
      </table>

      <h2>来源与可信度</h2>
      <table className="table">
        <thead>
          <tr>
            <th>来源</th>
            <th>可信度</th>
            <th className="num">置信度</th>
            <th className="num">方法</th>
            <th className="num">边</th>
            <th className="num">焦点</th>
            <th>含义</th>
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
              <td className="num">{formatPercent(provider.confidence, 2)}</td>
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
          <h2>扫描器台账</h2>
          <div className="card summary-grid">
            <Field label="引擎">
              {scan.engine} {scan.engine_version}
            </Field>
            <Field label="退出码">{scan.returncode}</Field>
            <Field label="规则">{scan.configured ? "显式" : "自动"}</Field>
            <Field label="可疑零命中">{scan.zero_findings_is_suspicious ? "是" : "否"}</Field>
            {scan.failure_mode ? <Field label="失败模式">{scan.failure_mode}</Field> : null}
          </div>
          <pre className="code">{scan.command_line || "（未记录命令）"}</pre>
          {Object.keys(scan.rule_counts).length > 0 ? (
            <div className="counters">
              {Object.entries(scan.rule_counts).map(([rule, count]) => (
                <span key={rule} className="counter">
                  {rule} <strong>{count}</strong>
                </span>
              ))}
            </div>
          ) : null}
          {scan.stderr_tail ? <pre className="code warn">{scan.stderr_tail}</pre> : null}
        </>
      ) : null}

      {degradations.length > 0 ? (
        <>
          <h2>此分析包未能完成的部分</h2>
          <ul className="prune-list">
            {degradations.map((item, index) => (
              <li key={`${item.capability}-${index}`}>
                <code>{item.capability}</code> {item.reason}
                <div className="muted">{item.impact}</div>
              </li>
            ))}
          </ul>
        </>
      ) : null}

      {prunes.length > 0 ? (
        <>
          <h2>组装期间发生的裁剪</h2>
          <ul className="prune-list">
            {prunes.map((prune, index) => (
              <li key={`${prune.rule}-${index}`}>
                <code>{prune.rule}</code> {prune.detail}
                {prune.path ? (
                  <span className="muted">
                    {" "}
                    {prune.path}
                    {prune.line ? `:${prune.line}` : ""}
                  </span>
                ) : null}
              </li>
            ))}
          </ul>
        </>
      ) : null}

      <h2>上下文</h2>
      {contexts.error ? <Banner>无法加载上下文：{contexts.error.detail}</Banner> : null}
      {(contexts.data?.contexts ?? []).map((context) => (
        <ContextCard
          key={context.context_id}
          bundleId={bundleId}
          context={context}
          legend={provider_legend}
        />
      ))}

      {/* The model's answer *about* those contexts, after them on purpose: the reader should be
          able to check the evidence a verdict cites before reading the verdict. */}
      <VerdictsPanel bundleId={bundleId} />

      <h2>方法</h2>
      {methods.error ? <Banner>无法加载方法：{methods.error.detail}</Banner> : null}
      <table className="table">
        <thead>
          <tr>
            <th>方法</th>
            <th>位置</th>
            <th>类型</th>
            <th>来源</th>
            <th>可信度</th>
            <th className="num">深度</th>
            <th>上下文</th>
            <th />
          </tr>
        </thead>
        <tbody>
          {(methods.data?.methods ?? []).map((row: MethodIndexRow) => (
            <tr key={row.method_id} className={row.is_focus ? "current" : ""}>
              <td>
                <strong>{row.qualified_name}</strong>
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
              <td className="note">{row.contexts.join(", ")}</td>
              <td className="note">
                <button
                  type="button"
                  className="link"
                  onClick={() =>
                    setOpenBody(openBody === row.method_id ? null : row.method_id)
                  }
                >
                  {openBody === row.method_id ? "收起" : "方法体"}
                </button>
              </td>
            </tr>
          ))}
        </tbody>
      </table>

      {openBody ? (
        <div className="card">
          <h3>
            方法体 <code>{openBody}</code>
          </h3>
          <BodyViewer bundleId={bundleId} methodId={openBody} />
        </div>
      ) : null}
    </section>
  );
}
