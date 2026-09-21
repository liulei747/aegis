/**
 * AI verdicts: what the model concluded about each analysis context.
 *
 * This screen is where the front-end/back-end split is visible. The API returns the stored
 * `ai/report.json` verbatim; how many contexts were answered, what share of the input came from
 * the provider's cache, and the token totals are all computed here (`countsOf`, `tokenTotals`,
 * `cacheHitRatio`). An earlier API published those numbers pre-computed, which put a
 * presentation decision -- "show this as a share, at this precision" -- on the server.
 *
 * Two things the screen refuses to do:
 *
 * 1. **Hide a failed call.** A context the model could not answer about is not a context with
 *    nothing to say, so a failed call keeps its place in the list with its reason and a pointer
 *    at the raw answer on disk.
 * 2. **Dress up an unparsed answer.** `verdict` is null when the model's reply did not fit the
 *    prompt's contract. The screen shows the parse error rather than guessing a severity, which
 *    is why the raw answer is stored beside the bundle in the first place.
 */

import { useState } from "react";
import { api, type ApiError } from "../api/client.ts";
import type {
  AIReport,
  AICall,
  BundleSummary,
  JobSummary,
  ProjectRecord,
  TokenUsage,
  Verdict,
} from "../api/types.ts";
import {
  Banner,
  Empty,
  Field,
  SeverityBadge,
  Stat,
  usePolled,
} from "../components.tsx";
import {
  cacheHitRatio,
  countsOf,
  formatCount,
  formatPercent,
  formatSeconds,
  formatTimestamp,
  tokenTotals,
} from "../format.ts";
import { label, VERDICT } from "../labels.ts";
import { ProjectFacts, ProjectSelect, useProjectChoice } from "./ProjectPicker.tsx";

function UsageCounters({ usage }: { usage: TokenUsage | null }) {
  if (!usage) return null;
  const ratio = cacheHitRatio(usage);
  return (
    <div className="counters">
      <span className="counter">输入 {formatCount(usage.prompt_tokens)}</span>
      <span className="counter">输出 {formatCount(usage.completion_tokens)}</span>
      <span className="counter">缓存 {formatCount(usage.cached_tokens)}</span>
      {ratio === null ? null : (
        <span className="counter" title="本次调用的输入中由来源缓存提供的占比">
          前缀命中 {formatPercent(ratio)}
        </span>
      )}
    </div>
  );
}

function VerdictBody({ verdict }: { verdict: Verdict }) {
  return (
    <div className="verdict-body">
      <div className="row">
        <span className={`badge verdict-${verdict.verdict}`}>{label(VERDICT, verdict.verdict)}</span>
        <SeverityBadge severity={verdict.severity} />
        <span className="muted">置信度 {formatPercent(verdict.confidence)}</span>
      </div>
      {verdict.severity_qualifier ? (
        <p className="note">严重度理由：{verdict.severity_qualifier}</p>
      ) : null}
      {verdict.reachability ? <p>{verdict.reachability}</p> : null}
      {verdict.data_flow ? <p className="code">{verdict.data_flow}</p> : null}
      {verdict.chain.length > 0 ? (
        <ol className="chain">
          {verdict.chain.map((step, index) => (
            <li key={index}>{step}</li>
          ))}
        </ol>
      ) : null}
      {verdict.evidence.length > 0 ? (
        <div>
          <span className="field-label">证据</span>
          <ul className="id-list">
            {verdict.evidence.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {verdict.missing.length > 0 ? (
        <div>
          <span className="field-label">模型未能证实的内容</span>
          <ul className="prune-list">
            {verdict.missing.map((item, index) => (
              <li key={index}>⚠ {item}</li>
            ))}
          </ul>
        </div>
      ) : null}
      {verdict.fix ? (
        <p>
          <span className="field-label">修复建议</span> {verdict.fix}
        </p>
      ) : null}
    </div>
  );
}

function CallCard({ call }: { call: AICall }) {
  return (
    <article className={`card context${call.parsed ? "" : " error-card"}`}>
      <header>
        <span className="context-id">{call.context_id ?? "整个分析包"}</span>
        <span className="muted">
          {call.model} · {formatSeconds(call.elapsed_s)}
        </span>
      </header>

      {call.verdict ? (
        <VerdictBody verdict={call.verdict} />
      ) : (
        <div>
          <p className="error">无可用研判结果：{call.error ?? "未知原因"}</p>
          <p className="muted">
            模型的原始回答保存在分析包旁边；原因见 <code>ai/report.json</code>
          </p>
          {call.raw_answer ? <pre className="code">{call.raw_answer}</pre> : null}
        </div>
      )}

      {call.missing_fields.length > 0 ? (
        <p className="note">
          模型遗漏了：{call.missing_fields.join(", ")} —— 这是它自身回答中的缺口，不是错误
        </p>
      ) : null}

      <UsageCounters usage={call.usage} />
      <p className="muted">调用时间 {formatTimestamp(call.called_at)}</p>
    </article>
  );
}

/** One bundle's report, with the button that produces one. Used on both screens. */
export function VerdictsPanel({ bundleId }: { bundleId: string }) {
  /**
   * Polled, because the analysis runs as a queued job: without polling the screen would show
   * "not analysed" until the reader reloaded, which reads as "the button did nothing".
   */
  const verdicts = usePolled<AIReport>(() => api.verdicts(bundleId), [bundleId], { pollMs: 5000 });
  const [busy, setBusy] = useState(false);
  const [queued, setQueued] = useState<string | null>(null);
  const [failure, setFailure] = useState<ApiError | null>(null);

  /**
   * `force` when a report already exists. A model's answer is an opinion, so asking again is
   * meaningful -- and without `force` the gateway deduplicates the request onto the finished job
   * and answers with the stored result, which looks like the button doing nothing.
   */
  const analyse = async () => {
    setBusy(true);
    setFailure(null);
    try {
      const answer = await api.analyzeBundle(bundleId, { force: verdicts.data !== null });
      if (answer && typeof answer === "object" && "job_id" in answer) {
        setQueued(answer.job_id);
      }
      verdicts.reload();
    } catch (caught) {
      setFailure(caught as ApiError);
    } finally {
      setBusy(false);
    }
  };

  const report = verdicts.data;
  const never = verdicts.error?.status === 404;
  const counts = countsOf(report);
  const totals = tokenTotals(report);

  return (
    <>
      <div className="row">
        <h2>快速研判</h2>
        {report ? (
          <span className="muted">
            {report.model} · 已回答 {formatCount(counts.parsed)} / {formatCount(counts.contexts)}{" "}
            个上下文
            {counts.failed > 0 ? ` · ${formatCount(counts.failed)} 个失败` : ""}
          </span>
        ) : null}
        <button type="button" className="right" onClick={analyse} disabled={busy}>
          {busy ? "提交中…" : report ? "重新研判" : "开始快速研判"}
        </button>
      </div>

      {failure ? <Banner>{failure.detail}</Banner> : null}
      {verdicts.error && !never ? (
        <Banner kind="warn">上次轮询失败：{verdicts.error.detail}</Banner>
      ) : null}
      {queued ? (
        <p className="muted">
          已排队为 <a href={`#/job/${queued}`}>{queued}</a> —— 此列表会自动刷新。
        </p>
      ) : null}

      {never ? (
        <Empty>
          尚未研判。模型会针对每个上下文询问一次，回答以 <code>ai/verdicts.jsonl</code>{" "}
          保存在分析包旁边。
        </Empty>
      ) : null}

      {report?.skipped ? (
        <Banner kind="warn">
          该阶段未运行：{report.skipped} —— 这是配置问题，不是研判失败
        </Banner>
      ) : null}

      {report && !report.skipped && report.calls.length === 0 ? (
        <Empty>本次运行未产生任何调用</Empty>
      ) : null}

      {report && report.calls.length > 0 ? (
        <div className="stats">
          <Stat label="输入 token" value={formatCount(totals.prompt)} />
          <Stat label="输出 token" value={formatCount(totals.completion)} />
          <Stat
            label="缓存占比"
            value={totals.cacheShare === null ? "—" : formatPercent(totals.cacheShare)}
          />
          <Stat label="缓存 token" value={formatCount(totals.cached)} />
        </div>
      ) : null}

      {(report?.calls ?? []).map((call) => (
        <CallCard key={call.context_id ?? "bundle"} call={call} />
      ))}

      {report ? (
        <div className="card summary-grid">
          <Field label="端点">{report.endpoint || "—"}</Field>
          <Field label="开始时间">{formatTimestamp(report.started_at)}</Field>
          <Field label="结束时间">{formatTimestamp(report.finished_at)}</Field>
        </div>
      ) : null}
    </>
  );
}

/**
 * 快速研判的入口：**选项目 → 用它的最新分析包**。
 *
 * 这里替代了原来"从分析包列表里挑一个"的做法，理由是用户提的那个不一致：深度审计选项目、
 * 快速研判选分析包，两条入口长得不一样，于是"该从哪儿开始"没有答案。现在两个模块都从项目开始，
 * 差别只在下一步 —— 研判必须有分析包，所以：
 *
 * 1. 该项目已有分析包 → 直接用**最新那个**（同一个项目的多个包是历次扫描的重复，读者要的是最近
 *    的事实），下面就是研判面板；
 * 2. 还没有 → 给一个「先组装分析包」按钮，提交组装任务，并说清"跑完这里会自动出现"。
 *
 * 为什么不让用户手选旧包：那需要他先知道包是什么、哪次扫描更相关 —— 而这一屏要回答的是
 * "这个项目现在有没有问题"。需要指定具体某个包时，从「分析包」页进去（那个深链仍然有效）。
 */
function QuickTriagePanel({
  bundles,
  jobs,
  projects,
  onOpenBundle,
}: {
  bundles: BundleSummary[];
  jobs: JobSummary[];
  /** 项目注册表：新项目还没有任务与分析包，只靠那两份派生的话它在选择器里是隐形的。 */
  projects: ProjectRecord[];
  onOpenBundle: (bundleId: string) => void;
}) {
  const { choices, choice, select } = useProjectChoice(bundles, jobs, projects);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<ApiError | null>(null);
  const [queued, setQueued] = useState<string | null>(null);

  const bundle = choice?.latestBundle ?? null;
  const assembling = jobs.some(
    (job) =>
      job.kind === "assemble" &&
      job.workspace === choice?.workspace &&
      (job.state === "running" || job.state === "queued"),
  );

  const assemble = async () => {
    if (choice === null) return;
    setBusy(true);
    setFailure(null);
    try {
      // `force` 是必须的：assemble 的指纹就是 workspace，项目扫描过一次之后重扫永远命中同一个
      // 指纹 —— 不带 force，上一次 succeeded 的任务原样返回（点了没反应），failed/canceled 回 409。
      // 重新扫描是用户点按钮说出口的意图，这里直接带。
      const answer = await api.assemble({ workspace: choice.workspace }, { force: true });
      if (answer && typeof answer === "object" && "job_id" in answer) setQueued(answer.job_id);
    } catch (caught) {
      setFailure(caught as ApiError);
    } finally {
      setBusy(false);
    }
  };

  return (
    <>
      <h2>选择要研判的项目</h2>
      <p className="muted">
        快速研判不读代码：它把分析包里已经组装好的每个入口各问一次模型，几分钟出结果。
        要它自己读代码找问题，用「深度审计」。
      </p>

      {failure ? <Banner>{failure.detail}</Banner> : null}

      <div className="row">
        <ProjectSelect
          choices={choices}
          selected={choice?.workspace ?? null}
          onSelect={select}
          emptyHint="还没有任何项目。先去「项目管理」新建一个（从仓库拉取或上传压缩包），再回来研判。"
        />
        <button
          type="button"
          className="right"
          onClick={assemble}
          disabled={busy || choice === null || assembling}
          title="对这个项目再跑一遍 静态扫描 → 调用图组装，生成一份新的分析包"
        >
          {assembling
            ? "正在重新扫描…"
            : busy
              ? "提交中…"
              : bundle
                ? "重新扫描"
                : "先组装分析包"}
        </button>
        {bundle ? (
          <button type="button" onClick={() => onOpenBundle(bundle.bundle_id)}>
            打开分析包
          </button>
        ) : null}
      </div>

      <ProjectFacts choice={choice} />

      {queued && !bundle ? (
        <Banner kind="info">
          已提交组装任务 <a href={`#/job/${queued}`}>{queued}</a>{" "}
          —— 跑完之后这个项目的最新分析包会自动出现在下面，不必手动刷新。
        </Banner>
      ) : null}

      {choice !== null && bundle === null ? (
        <Empty>
          这个项目还没有分析包。分析包是静态扫描 + 调用图组装出来的产物，快速研判的输入就是它 ——
          点上面的「先组装分析包」，几分钟后回来即可。
        </Empty>
      ) : null}

      {bundle ? (
        <>
          <p className="muted">
            项目的最新分析包：<code>{bundle.bundle_id}</code>（
            {formatTimestamp(bundle.created_at)} 创建，{formatCount(bundle.focus_count)} 个上下文）
            —— 要研判别的分析包，从「分析包」页进入。
          </p>
          <VerdictsPanel bundleId={bundle.bundle_id} />
        </>
      ) : null}
    </>
  );
}

/**
 * The AI verdicts screen.
 *
 * Without a bundle id it starts from a project and uses that project's newest bundle. With one it is
 * the deep link from the bundles screen, which stays supported because "which of this project's five
 * bundles did you mean" is a legitimate question that only a bundle id can answer.
 */
export function VerdictsScreen({
  bundles,
  jobs,
  projects,
  bundleId,
  onOpenBundle,
}: {
  bundles: BundleSummary[];
  jobs: JobSummary[];
  projects: ProjectRecord[];
  bundleId: string | null;
  onOpenBundle: (bundleId: string) => void;
}) {
  if (bundleId !== null) {
    return (
      <section>
        <div className="row">
          <code>{bundleId}</code>
          <button type="button" className="right" onClick={() => onOpenBundle(bundleId)}>
            打开分析包
          </button>
        </div>
        <VerdictsPanel bundleId={bundleId} />
      </section>
    );
  }

  const analysed = bundles.filter((bundle) => bundle.has_ai_report);
  return (
    <section>
      <QuickTriagePanel
        bundles={bundles}
        jobs={jobs}
        projects={projects}
        onOpenBundle={onOpenBundle}
      />

      <h2>已经研判过的分析包</h2>
      <p className="muted">
        每个分析上下文对应一次模型回答。这里有记录的是跑过快速研判的包；从这一列进去看结论，
        比在上面重新跑一次更快。
      </p>

      {bundles.length === 0 ? <Empty>磁盘上暂无分析包</Empty> : null}
      {bundles.length > 0 && analysed.length === 0 ? (
        <Empty>
          {formatCount(bundles.length)} 个分析包都尚未研判。选中项目后点「开始快速研判」即可。
        </Empty>
      ) : null}

      {analysed.length > 0 ? (
        <table className="table">
          <thead>
            <tr>
              <th>分析包</th>
              <th>创建时间</th>
              <th>工作区</th>
              <th className="num">上下文</th>
              <th />
            </tr>
          </thead>
          <tbody>
            {analysed.map((bundle) => (
              <tr key={bundle.bundle_id} className="clickable" onClick={() => onOpenBundle(bundle.bundle_id)}>
                <td>
                  <code>{bundle.bundle_id}</code>
                </td>
                <td>{formatTimestamp(bundle.created_at)}</td>
                <td className="muted">{bundle.workspace ?? "—"}</td>
                <td className="num">{formatCount(bundle.focus_count)}</td>
                <td className="note">
                  <a href={`#/verdicts/${encodeURIComponent(bundle.bundle_id)}`}>查看研判</a>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
    </section>
  );
}
