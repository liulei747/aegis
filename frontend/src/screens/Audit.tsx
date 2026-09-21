/**
 * 深度审计：把智能体编排层的运行过程摊开给人看。
 *
 * 这一屏存在的理由是**一次审计要跑半小时，而在此之前它是不可见的**：轨迹只在运行结束时落盘，
 * 所以一个正在跑的审计和一个挂掉的审计从外面看一模一样，中断一次还会把已经付过钱的 236 次模型
 * 调用一起丢掉。后端现在按事件追加写轨迹（`services/harness/trail.py`），这一屏就是读它。
 *
 * 三件事按重要性排序：
 *
 * 1. **agent 网格** —— 哪个 scope 上哪个 agent 在跑、跑了多少步、有没有结论。这是"它在动吗"。
 * 2. **对话流** —— 每个 agent 每一步的想法、调用的工具、参数、以及工具回了什么。这是
 *    "它在想什么"，也是用户问的"能不能看到全部 agent 的流式对话"。粒度是 turn：一次模型往返
 *    是轨迹里最小的单位，因为 ReAct 必须等一个完整的 JSON 才知道要调什么工具。
 * 3. **覆盖与账本** —— 每个 scope 的覆盖率判定与理由、候选与研判、最终发现。
 *
 * 轮询是增量的：记住 `last_seq`，只取新增的事件。所以这一屏每秒一个**小**请求，而不是每次把
 * 整份日志重新拉一遍——后者在 4000 次工具调用的运行上会让浏览器先卡住。
 */

import { useEffect, useMemo, useRef, useState } from "react";
import { api, previousAttempt, type ApiError } from "../api/client.ts";
import type {
  AuditEvent,
  AuditReport,
  AuditTrail,
  BundleSummary,
  Job,
  JobSummary,
  ProjectRecord,
} from "../api/types.ts";
import {
  agentRows,
  agentsSeen,
  candidateRows,
  coverageRows,
  dialogue,
  filterDialogue,
  findingRows,
  isClosed,
  latestCounters,
  stageRows,
} from "../audit.ts";
import { Banner, Empty, Field, StateBadge, Stat, usePolled } from "../components.tsx";
import { formatCount, formatDurationMs, formatTimestamp } from "../format.ts";
import { JOB_KIND, label } from "../labels.ts";
import { ProjectFacts, ProjectSelect, useProjectChoice } from "./ProjectPicker.tsx";
import { AuditBlackboard, AuditTasks } from "./AuditTasks.tsx";

/** 对话流最多渲染多少条。过滤器仍然作用于全部，截断的是 DOM，不是事实。 */
const DIALOGUE_LIMIT = 300;

const STATE_CLASS: Readonly<Record<string, string>> = {
  running: "current",
  finished: "",
  budget: "warn",
  error: "error",
  unknown: "",
};

const RUN_STATE_LABEL: Readonly<Record<string, string>> = {
  running: "运行中",
  finished: "已结束",
  budget: "用完步数",
  error: "失败",
  unknown: "未知",
};

const COVERAGE_LABEL: Readonly<Record<string, string>> = {
  sufficient: "已覆盖",
  insufficient: "不充分",
  excluded: "已排除",
  unseen: "未看过",
};

/** 一次审计的轨迹，按 `after_seq` 增量累积。 */
function useAuditTrail(jobId: string | null) {
  const lastSeq = useRef(0);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [damaged, setDamaged] = useState(0);

  // 换一个 job 就是换一次运行：不清空的话上一轮的事件会混进来，而它们看起来完全合理。
  useEffect(() => {
    lastSeq.current = 0;
    setEvents([]);
    setDamaged(0);
  }, [jobId]);

  const page = usePolled<AuditTrail>(
    () => api.auditTrail(jobId ?? "", lastSeq.current),
    [jobId],
    { pollMs: 1500, enabled: jobId !== null },
  );

  useEffect(() => {
    const payload = page.data;
    if (!payload) return;
    setDamaged(payload.damaged);
    if (payload.events.length === 0) return;
    lastSeq.current = payload.last_seq;
    setEvents((previous) => [...previous, ...payload.events]);
  }, [page.data]);

  return { events, damaged, error: page.error, loading: page.loading, exists: page.data?.exists ?? null };
}

function SubmitPanel({
  jobs,
  bundles,
  projects,
  initialWorkspace,
  onSubmitted,
}: {
  jobs: JobSummary[];
  bundles: BundleSummary[];
  /** 项目注册表：新项目还没有任务与分析包，只靠那两份派生的话它在选择器里是隐形的。 */
  projects: ProjectRecord[];
  /** 从项目页带着路径跳进来时预选它。 */
  initialWorkspace: string | null;
  onSubmitted: (jobId: string) => void;
}) {
  const { choices, choice, select } = useProjectChoice(bundles, jobs, projects, initialWorkspace);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<ApiError | null>(null);
  const [accepted, setAccepted] = useState<string | null>(null);
  // 上一次尝试是 failed / canceled 时，网关会拒绝同指纹的再次提交（409），除非带 `?force=true`。
  // 那不是死胡同，所以单独记下来给一个按钮 —— 只显示一句错误的话，这个项目在界面上就永远跑不了。
  //
  // `workspace` 必须在收到 409 的那一刻记下来：这个按钮重新提交的是**被拒绝的那个项目**，
  // 不是此刻下拉框里选中的项目。`choice` 是从三份轮询数据里每次渲染重算的（recent activity 排序、
  // 选中项消失还会退回默认值），用户改一下下拉框、或某次轮询恰好把列表换了个序，
  // 「重新运行这个项目」就会带着 `?force=true` 打到**另一个**项目上 —— 而_FORCE_对一个已成功的
  // 项目意味着归档它上一次的结果再整个重跑。
  const [previous, setPrevious] = useState<{ jobId: string; state: string; workspace: string } | null>(
    null,
  );

  const recent = jobs.filter((job) => job.kind === "audit").slice(0, 10);
  const running = recent.filter((job) => job.state === "running" || job.state === "queued");

  /** 提交一次审计。409 时把**这次请求用的 workspace** 和拒绝信息一起记下，供恢复按钮原样重发。 */
  const runAudit = async (workspace: string, options: { force?: boolean } = {}) => {
    setFailure(null);
    setAccepted(null);
    setPrevious(null);
    setBusy(true);
    try {
      const result = await api.submitAudit({ workspace }, options);
      setAccepted(result.job_id);
      onSubmitted(result.job_id);
    } catch (caught) {
      const error = caught as ApiError;
      setFailure(error);
      const attempt = previousAttempt(error);
      if (attempt !== null) setPrevious({ ...attempt, workspace });
    } finally {
      setBusy(false);
    }
  };

  const submit = (event: React.SyntheticEvent) => {
    event.preventDefault();
    if (choice === null) {
      setFailure({ status: 0, detail: "先选一个项目。还没有项目就去「项目管理」新建一个。" });
      return;
    }
    void runAudit(choice.workspace);
  };

  return (
    <section>
      <h2>开始一次深度审计</h2>
      <p className="muted">
        编排层会在项目上跑完整的流程：勘察 → 威胁建模 → 范围规划 → 探索（按 scope 并发）→
        逐个验证候选 → 推导攻击路径 → 汇总发现。<strong>它自己读代码</strong>，所以能发现组装阶段
        根本没提出的问题 —— 代价是半小时量级的时间与上百次模型调用。只想判断分析包里已经有的点，
        用「快速研判」。
      </p>

      {failure ? <Banner>{failure.detail}</Banner> : null}
      {previous ? (
        <Banner kind="warn">
          上一次尝试 <code>{previous.jobId}</code> 是
          <strong>
            {previous.state === "failed"
              ? "失败的"
              : previous.state === "canceled"
                ? "被取消的"
                : previous.state}
          </strong>
          ，同一份请求不会自动重跑（"没有结果"与"结果是干净"不是一回事）。
          {" "}
          <button
            type="button"
            disabled={busy}
            onClick={() => void runAudit(previous.workspace, { force: true })}
          >
            重新运行这个项目
          </button>
          {" "}
          <span className="muted">
            （<code>{previous.workspace}</code>，带 <code>?force=true</code>）
          </span>
          {" "}
          <a href={`#/audit/${encodeURIComponent(previous.jobId)}`}>看上一次的轨迹</a>
        </Banner>
      ) : null}
      {accepted ? (
        <Banner kind="info">
          已提交，任务号 <code>{accepted}</code>。运行状态与对话见下。
        </Banner>
      ) : null}

      <form className="card" onSubmit={submit}>
        <div className="row">
          <ProjectSelect
            choices={choices}
            selected={choice?.workspace ?? null}
            onSelect={select}
            emptyHint="还没有任何项目。先去「项目管理」新建一个（从仓库拉取或上传压缩包），再回来审计。"
          />
          <button type="submit" className="right" disabled={busy || choice === null}>
            {busy ? "提交中…" : "开始审计"}
          </button>
        </div>
        <ProjectFacts choice={choice} />
        <p className="muted">
          同一个项目的重复提交会挂到已经在跑的那个任务上，不会跑第二遍。上一次是失败或被取消时，
          提交会被<strong>先拒一次</strong>并给出「重新运行」—— 那种情况下不会自动重试，
          因为"跑过但没有结果"和"跑出来是干净的"必须让人分得开。
        </p>
      </form>

      {running.length > 0 ? (
        <>
          <h2>正在运行</h2>
          <p className="muted">这些审计已经在跑，点进去看实时进度。</p>
          <ul>
            {running.map((job) => (
              <li key={job.job_id}>
                <button type="button" onClick={() => onSubmitted(job.job_id)}>
                  {job.job_id}
                </button>{" "}
                <span className="muted">{job.workspace ?? "—"}</span>
              </li>
            ))}
          </ul>
        </>
      ) : null}

      <h2>最近的深度审计</h2>
      {recent.length === 0 ? (
        <Empty>还没有跑过深度审计。</Empty>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>任务</th>
              <th>状态</th>
              <th>项目</th>
              <th>提交时间</th>
              <th className="num">耗时</th>
              <th className="num">发现</th>
              <th className="num">重跑</th>
            </tr>
          </thead>
          <tbody>
            {recent.map((job) => {
              const terminal =
                job.state === "succeeded" || job.state === "failed" || job.state === "canceled";
              return (
                <tr key={job.job_id} className="clickable" onClick={() => onSubmitted(job.job_id)}>
                  <td>
                    <code>{job.job_id}</code>
                  </td>
                  <td>
                    <StateBadge state={job.state} cancelRequested={job.cancel_requested} />
                  </td>
                  <td className="note">{job.workspace ?? "—"}</td>
                  <td>{formatTimestamp(job.submitted_at)}</td>
                  <td className="num">{formatDurationMs(job.duration_ms)}</td>
                  <td className="num">{formatCount(job.counters.findings ?? 0)}</td>
                  <td className="num">
                    {terminal && job.workspace ? (
                      <button
                        type="button"
                        disabled={busy}
                        onClick={(event) => {
                          // 行本身点击是"进详情"；这里的重跑要拦住冒泡，别两个都发生。
                          event.stopPropagation();
                          void runAudit(job.workspace as string, { force: true });
                        }}
                      >
                        重新审计
                      </button>
                    ) : null}
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      )}
    </section>
  );
}

function DialogueFeed({ events }: { events: AuditEvent[] }) {
  const rows = useMemo(() => dialogue(events), [events]);
  const [agent, setAgent] = useState("");
  const [needle, setNeedle] = useState("");
  const [onlyProblems, setOnlyProblems] = useState(false);

  const filtered = useMemo(
    () => filterDialogue(rows, { agent, needle, onlyProblems }),
    [rows, agent, needle, onlyProblems],
  );
  // 只截断 DOM：从最新一条往回取，所以正在发生的事永远在屏幕上。
  const shown = filtered.rows.slice(-DIALOGUE_LIMIT);

  if (rows.length === 0) {
    return <Empty>还没有对话。agent 开始跑之后，每一步的想法与工具调用都会出现在这里。</Empty>;
  }

  return (
    <>
      <div className="row">
        <label className="inline">
          agent
          <select value={agent} onChange={(event) => setAgent(event.target.value)}>
            <option value="">全部</option>
            {agentsSeen(events).map((name) => (
              <option key={name} value={name}>
                {name}
              </option>
            ))}
          </select>
        </label>
        <label className="inline">
          搜索
          <input
            type="search"
            value={needle}
            placeholder="think / 工具 / 参数 / 结果"
            onChange={(event) => setNeedle(event.target.value)}
          />
        </label>
        <label className="inline">
          <input
            type="checkbox"
            checked={onlyProblems}
            onChange={(event) => setOnlyProblems(event.target.checked)}
          />
          只看失败与拒绝
        </label>
        <span className="muted">
          共 {formatCount(filtered.total)} 步，符合条件 {formatCount(filtered.rows.length)} 步
          {filtered.rows.length > shown.length
            ? `，显示最近 ${formatCount(shown.length)} 步`
            : ""}
        </span>
      </div>

      <ol className="feed">
        {shown.map((row) => (
          <li key={row.seq} className={row.error ? "feed-item error" : "feed-item"}>
            <div className="feed-head">
              <span className="muted">#{row.seq}</span>{" "}
              <code>{row.agent}</code>{" "}
              <span className="muted note">{row.scope}</span>
              {row.index !== null ? <span className="muted"> · 第 {row.index} 步</span> : null}
              {row.tool ? (
                <>
                  {" → "}
                  <code>{row.tool}</code>
                </>
              ) : (
                <span className="muted"> → （本轮没有工具调用）</span>
              )}
              {row.ok === false ? <span className="severity severity-high">工具被拒或失败</span> : null}
            </div>
            {row.thought ? <div className="feed-thought">{row.thought}</div> : null}
            {Object.keys(row.arguments).length > 0 ? (
              <div className="feed-args">
                <code>{JSON.stringify(row.arguments)}</code>
              </div>
            ) : null}
            {row.summary ? <div className="feed-result">{row.summary}</div> : null}
            {row.error ? <div className="feed-error">{row.error}</div> : null}
          </li>
        ))}
      </ol>
    </>
  );
}

function RunView({ jobId, onBack, onRestart }: { jobId: string; onBack: () => void; onRestart: (jobId: string) => void }) {
  const job = usePolled<Job>(() => api.job(jobId), [jobId], { pollMs: 2000 });
  const trail = useAuditTrail(jobId);
  const [failure, setFailure] = useState<ApiError | null>(null);
  const [busy, setBusy] = useState(false);
  const [report, setReport] = useState<AuditReport | null>(null);
  const [reportError, setReportError] = useState<ApiError | null>(null);

  const events = trail.events;
  const closed = isClosed(events);
  const terminal =
    job.data !== null && ["succeeded", "failed", "canceled"].includes(job.data.state);
  const counters = useMemo(() => {
    const fromTrail = latestCounters(events);
    return Object.keys(fromTrail).length > 0 ? fromTrail : (job.data?.progress.counters ?? {});
  }, [events, job.data]);

  // 报告只在运行结束之后存在，所以只在结束时取一次；运行中每次都问会得到一个稳定的 404。
  useEffect(() => {
    if (!terminal) {
      setReport(null);
      return;
    }
    let cancelled = false;
    api
      .auditReport(jobId)
      .then((payload) => {
        if (!cancelled) setReport(payload);
      })
      .catch((caught: ApiError) => {
        if (!cancelled) setReportError(caught);
      });
    return () => {
      cancelled = true;
    };
  }, [terminal, jobId]);

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

  const restart = async () => {
    // 重跑的是**这个任务自己的** workspace（redrive 复用任务号，它是指纹），不是下拉框里的选择。
    // 全程可选链：旧记录的 `submission` 缺字段时，按钮退化为禁用，而不是在渲染/点击时抛错。
    const workspace = job.data?.submission?.request?.workspace;
    if (!workspace || busy) return;
    setBusy(true);
    setFailure(null);
    try {
      const result = await api.submitAudit({ workspace }, { force: true });
      // Redrive keeps the job id but resets the trail sequence. Remount all polling state.
      onRestart(result.job_id);
    } catch (caught) {
      setFailure(caught as ApiError);
      setBusy(false);
    }
  };

  const stages = stageRows(events);
  const agents = agentRows(events);
  const coverage = coverageRows(events);
  const candidates = candidateRows(events);
  const findings = findingRows(events);
  const runningCount = agents.filter((row) => row.state === "running").length;
  const resultWarnings = job.data?.result?.warnings ?? [];
  const closureNote = [...events]
    .reverse()
    .find((event) => event.kind === "summary")?.closure_note;
  const legacyIncomplete =
    !resultWarnings.some((warning) => warning.includes("审计结果不完整")) &&
    closureNote?.includes("仍有")
      ? closureNote
      : null;

  return (
    <section>
      <div className="row">
        <button type="button" onClick={onBack}>
          ← 审计
        </button>
        <h1>{jobId}</h1>
        {job.data ? (
          <StateBadge state={job.data.state} cancelRequested={job.data.cancel_requested} />
        ) : null}
        {runningCount > 0 ? <span className="badge">{runningCount} 个 agent 在跑</span> : null}
        {terminal ? (
          <button
            type="button"
            className="right"
            onClick={() => void restart()}
            disabled={busy || !job.data?.submission?.request?.workspace}
          >
            {busy ? "正在重新提交…" : "重新审计"}
          </button>
        ) : null}
        {!closed && !terminal ? (
          <button type="button" className="right" onClick={cancel} disabled={busy}>
            {busy ? "取消中…" : "取消"}
          </button>
        ) : null}
      </div>

      {failure ? <Banner>{failure.detail}</Banner> : null}
      {trail.error ? <Banner kind="warn">轨迹轮询失败：{trail.error.detail}</Banner> : null}
      {job.error && !job.data ? <Banner>{job.error.detail}</Banner> : null}
      {job.data?.failure ? (
        <Banner>
          <strong>{job.data.failure.mode}</strong>：{job.data.failure.message}
        </Banner>
      ) : null}
      {resultWarnings.map((warning) => (
        <Banner key={warning} kind="warn">
          {warning}
        </Banner>
      ))}
      {legacyIncomplete ? (
        <Banner kind="warn">审计结果不完整：{legacyIncomplete}</Banner>
      ) : null}
      {trail.exists === false ? (
        <Banner kind="info">
          这次审计还没有写出轨迹：任务可能在排队，或刚开始。这一页会自己刷新。
        </Banner>
      ) : null}
      {trail.damaged > 0 ? (
        <Banner kind="warn">
          轨迹里有 {trail.damaged} 行没写完（进程被杀时留下的半行）。它们被跳过了，其余记录完好。
        </Banner>
      ) : null}

      <div className="stats">
        <Stat label="事件" value={formatCount(events.length)} />
        <Stat label="候选" value={formatCount(counters.candidates ?? candidates.length)} />
        <Stat label="研判" value={formatCount(counters.verdicts ?? 0)} />
        <Stat label="确认" value={formatCount(counters.confirmed ?? 0)} />
        <Stat label="发现" value={formatCount(counters.findings ?? findings.length)} />
        <Stat label="agent run" value={formatCount(counters.agent_runs ?? agents.length)} />
        <Stat label="轮次" value={formatCount(counters.rounds ?? 0)} />
        <Stat label="scope" value={formatCount(counters.scopes ?? coverage.length)} />
        {/* 开场那对 agent（recon × 威胁建模）跑了几个来回，以及有没有留下没读的东西。
            `opening_unread > 0` 是"未收敛"：威胁建模可能是在只有目录名的地图上写出来的，
            这件事必须和"发现 0 条"一样显眼，否则读者会把两者当成同一份结论。 */}
        <Stat
          label="开场轮次"
          value={
            counters.opening_passes
              ? `${formatCount(counters.opening_passes)}${counters.opening_unread ? "⚠" : ""}`
              : "—"
          }
        />
      </div>

      <div className="card summary-grid">
        <Field label="仓库">
          <code>{job.data?.submission.request.workspace ?? "—"}</code>
        </Field>
        <Field label="类型">{label(JOB_KIND, job.data?.kind ?? "audit")}</Field>
        <Field label="提交时间">{formatTimestamp(job.data?.timing.submitted_at ?? null)}</Field>
        <Field label="耗时">{formatDurationMs(job.data?.timing.duration_ms ?? 0)}</Field>
        <Field label="worker">
          <code>{job.data?.progress.worker_id ?? "—"}</code>
        </Field>
        <Field label="心跳">
          {formatTimestamp(job.data?.progress.worker_heartbeat_at ?? null)}
        </Field>
      </div>

      <AuditTasks key={jobId} events={events} terminal={terminal || closed} />
      <AuditBlackboard events={events} />

      <h2>阶段</h2>
      {stages.length === 0 ? (
        <Empty>轨迹里还没有阶段事件。</Empty>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>阶段</th>
              <th>状态</th>
              <th className="num">轮次</th>
              <th className="num">事件序号</th>
            </tr>
          </thead>
          <tbody>
            {stages.map((row) => (
              <tr key={row.stage} className={row.state === "start" || row.state === "round" ? "current" : ""}>
                <td>{row.label}</td>
                <td>{row.state === "end" ? "已完成" : row.state === "failed" ? "中断" : "进行中"}</td>
                <td className="num">{row.round ?? "—"}</td>
                <td className="num muted">{row.seq}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>agent</h2>
      <p className="muted">
        每个 scope 一个探索 agent，每个候选一个验证 agent。这一列是识别"它在动，还是卡住了"的地方 ——
        没有结束事件的 agent 就是正在跑。
      </p>
      {agents.length === 0 ? (
        <Empty>还没有 agent 启动。</Empty>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>agent</th>
              <th>scope / 候选</th>
              <th>状态</th>
              <th className="num">步数</th>
              <th className="num">工具调用</th>
              <th>停止原因</th>
              <th>备注</th>
            </tr>
          </thead>
          <tbody>
            {agents.map((row) => (
              <tr key={row.runId} className={STATE_CLASS[row.state] ?? ""}>
                <td>
                  <code>{row.agent}</code>
                </td>
                <td className="note">{row.scope}</td>
                <td>{RUN_STATE_LABEL[row.state] ?? row.state}</td>
                <td className="num">{formatCount(row.steps)}</td>
                <td className="num">{formatCount(row.toolCalls)}</td>
                <td className="note">{row.stopReason ?? "—"}</td>
                <td className="note">{row.error ?? (row.parsed === false ? "没有产出可用结论" : "")}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>对话流</h2>
      <p className="muted">
        每个 agent 每一步：模型的想法、它调用的工具、参数、以及工具返回的内容。粒度是"一步"，
        即一次模型往返 —— ReAct 必须等一个完整的 JSON 才知道要调什么工具，所以逐字流对决策没有影响。
      </p>
      <DialogueFeed events={events} />

      <h2>覆盖率</h2>
      <p className="muted">
        「不充分」的 scope 会被重新派发 —— 覆盖率按 read 调用台账算，搜索命中不算审完。
      </p>
      {coverage.length === 0 ? (
        <Empty>还没有覆盖率判定。</Empty>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>scope</th>
              <th>判定</th>
              <th className="num">文件</th>
              <th className="num">未读完</th>
              <th>理由</th>
            </tr>
          </thead>
          <tbody>
            {coverage.map((row) => (
              <tr key={row.scope} className={row.state === "insufficient" ? "warn" : ""}>
                <td className="note">{row.scope}</td>
                <td>{COVERAGE_LABEL[row.state] ?? row.state}</td>
                <td className="num">{formatCount(row.files)}</td>
                <td className="num">{row.unread > 0 ? formatCount(row.unread) : "—"}</td>
                <td className="note">{row.reason}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>候选与研判</h2>
      {candidates.length === 0 ? (
        <Empty>还没有候选。</Empty>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>位置</th>
              <th>类型</th>
              <th>标题</th>
              <th>研判</th>
              <th className="num">置信度</th>
              <th>证据</th>
              <th>可达</th>
            </tr>
          </thead>
          <tbody>
            {candidates.map((row) => (
              <tr key={row.candidateId}>
                <td>
                  <code>{row.file}</code>
                  {row.line ? `:${row.line}` : ""}
                </td>
                <td>
                  <code>{row.vulnerabilityType}</code>
                </td>
                <td className="note">{row.title}</td>
                <td>{row.verdict ?? "—"}</td>
                <td className="num">{row.confidence === null ? "—" : row.confidence.toFixed(2)}</td>
                <td className="note">{row.evidenceKind ?? "—"}</td>
                <td>{row.reachable === null ? "—" : row.reachable ? "是" : "否"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      <h2>最终发现</h2>
      {findings.length === 0 ? (
        <Empty>
          运行还没到汇总阶段，或者这次没有确认的发现。请对照上面的覆盖率表读这一行 ——
          「没有发现」和「没有看过」是两件不同的事。
        </Empty>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>发现</th>
              <th>位置</th>
              <th>类型</th>
              <th>严重度</th>
              <th className="num">同位点实例</th>
              <th>标题</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((row) => (
              <tr key={row.findingId}>
                <td>
                  <code>{row.findingId}</code>
                </td>
                <td>
                  <code>{row.file}</code>
                  {row.line ? `:${row.line}` : ""}
                </td>
                <td>
                  <code>{row.vulnerabilityType}</code>
                </td>
                <td>{row.severity}</td>
                <td className="num">{row.mergedLocations > 1 ? formatCount(row.mergedLocations) : "—"}</td>
                <td className="note">{row.title}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {terminal ? (
        <>
          <h2>报告</h2>
          {reportError ? (
            <Banner kind="warn">报告不可读：{reportError.detail}</Banner>
          ) : report === null ? (
            <Empty>正在读取报告…</Empty>
          ) : (
            <>
              <p className="muted">
                与 <code>{report.report}</code> 同一份文本，未做任何改写。
              </p>
              <pre className="report">{report.markdown}</pre>
            </>
          )}
        </>
      ) : null}
    </section>
  );
}

export function AuditScreen({
  jobId,
  jobs,
  bundles,
  projects,
  workspace,
  onOpen,
}: {
  jobId: string | null;
  jobs: JobSummary[];
  bundles: BundleSummary[];
  projects: ProjectRecord[];
  /** `#/audit/w/<路径>` 带来的预选项目；`#/audit` 时为 null。 */
  workspace: string | null;
  onOpen: (jobId: string) => void;
}) {
  const [attemptView, setAttemptView] = useState(0);
  if (jobId === null) {
    return (
      <SubmitPanel
        jobs={jobs}
        bundles={bundles}
        projects={projects}
        initialWorkspace={workspace}
        onSubmitted={onOpen}
      />
    );
  }
  return <RunView key={`${jobId}:${attemptView}`} jobId={jobId} onBack={() => onOpen("")}
    onRestart={(id) => { setAttemptView((value) => value + 1); onOpen(id); }} />;
}
