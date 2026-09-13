/**
 * 概览：一屏看清流水线现在是什么状态。
 *
 * 版式参照的是常见的"态势概览"：顶部一排 KPI 卡（大数字 + 一行口径说明），下面是分组卡片。
 * 关键在于**每张卡的副标题都要说清这个数字是怎么来的** —— 概览最容易骗人的地方不是算错，
 * 而是没说口径：写了"误报率 40%"却不说是基于 5 条研判，读者会当成 456 条命中的结论。
 *
 * 三条自我约束：
 *
 * 1. **只用已有的接口，不为概览新增端点。** 所有数字来自 `/v1/jobs`、`/v1/bundles`、
 *    `/v1/traffic` 和分析包的 `ai/report.json`。否则"运行中"会有两个定义，迟早不一致。
 * 2. **不造没有的数据。** 参考版式里有"人工已确认"这类卡片，我们没有人工确认这个环节，
 *    所以没有这张卡 —— 一个恒为 0 的卡片比没有卡片更糟，它看起来像一个坏掉的功能。
 * 3. **聚合逻辑放在 `format.ts` 并由测试钉住**，不写在组件里。
 */

import { api } from "../api/client.ts";
import type { AIReport, BundleSummary, JobSummary, QueueStatus, TrafficEntry } from "../api/types.ts";
import { Banner, Empty, usePolled } from "../components.tsx";
import {
  aiTotals,
  coverageTotals,
  formatCount,
  formatDurationMs,
  formatPercent,
  formatRelative,
  formatTimestamp,
  jobsByState,
  providerMix,
  queueByKind,
  share,
  trafficByPath,
} from "../format.ts";
import { IconBundles, IconJobs, IconTraffic, IconVerdicts } from "../icons.tsx";
import { JOB_KIND, JOB_STATE, label, STAGE } from "../labels.ts";

/** 概览只看最近的这些分析包的研判明细。取太多会把首屏拖成 N 个请求。 */
const AI_SAMPLE = 12;

/** 队列小卡按这三种任务类型分列，与 `JobKind` 一致。 */
const KINDS = ["assemble", "scan", "ai_fanout", "audit"];

function Kpi({
  title,
  value,
  sub,
  icon,
  tone,
}: {
  title: string;
  value: React.ReactNode;
  sub: React.ReactNode;
  icon: React.ReactNode;
  tone?: "accent" | "ok" | "warn";
}) {
  return (
    <div className="kpi">
      <div className="kpi-head">
        <span className="kpi-title">{title}</span>
        <span className={`kpi-icon${tone ? ` ${tone}` : ""}`}>{icon}</span>
      </div>
      <div className="kpi-value">{value}</div>
      <div className="kpi-sub">{sub}</div>
    </div>
  );
}

/** 一个带条的比例行，用于漏斗与分布。`share` 为 null 时不画条。 */
function BarRow({
  label,
  count,
  share: ratio,
  note,
}: {
  label: React.ReactNode;
  count: React.ReactNode;
  share: number | null;
  note?: React.ReactNode;
}) {
  return (
    <li className="bar-row">
      <span className="bar-row-label">{label}</span>
      <span className="bar-track inline-track">
        {ratio === null ? null : <span className="bar-fill" style={{ width: `${Math.max(0, Math.min(1, ratio)) * 100}%` }} />}
      </span>
      <span className="bar-row-count">{count}</span>
      {note ? <span className="bar-row-note">{note}</span> : null}
    </li>
  );
}

export function OverviewScreen({
  jobs,
  queue,
  bundles,
  error,
  onOpenJob,
  onOpenBundle,
}: {
  jobs: JobSummary[];
  queue: QueueStatus | null;
  bundles: BundleSummary[];
  error: { status: number; detail: string } | null;
  onOpenJob: (jobId: string) => void;
  onOpenBundle: (bundleId: string) => void;
}) {
  const totals = coverageTotals(bundles);
  const counts = jobsByState(jobs);
  const providers = providerMix(bundles);
  const recentJobs = [...jobs]
    .sort((a, b) => (a.submitted_at < b.submitted_at ? 1 : -1))
    .slice(0, 6);
  const recentBundles = bundles.slice(0, 6);
  const running = (counts.running ?? 0) + (counts.queued ?? 0);

  // 调用指标来自网关进程内的环形缓冲：一次请求拿到，不需要逐路径统计。
  const traffic = usePolled<{ entries: TrafficEntry[]; count: number; note: string }>(
    () => api.traffic(200),
    [],
    { pollMs: 10_000 },
  );
  const paths = trafficByPath(traffic.data?.entries ?? []);

  // 研判明细要逐包取 `ai/report.json`。只取已研判的那些，并封顶 —— 这是本屏唯一的扇出，
  // 所以卡片的副标题会写明口径，避免把"最近 4 个包"的结论说成"全部"。
  const analysedIds = bundles
    .filter((bundle) => bundle.has_ai_report)
    .map((bundle) => bundle.bundle_id);
  const sampleIds = analysedIds.slice(0, AI_SAMPLE);
  const reports = usePolled<AIReport[]>(
    async () => {
      const settled = await Promise.allSettled(sampleIds.map((id) => api.verdicts(id)));
      return settled
        .filter((item): item is PromiseFulfilledResult<AIReport> => item.status === "fulfilled")
        .map((item) => item.value);
    },
    [sampleIds.join(",")],
    { pollMs: 30_000, enabled: sampleIds.length > 0 },
  );
  const ai = aiTotals(reports.data ?? []);
  const aiCoverage = share(totals.analysed, totals.bundles);
  const fpShare = share(ai.falsePositive, ai.parsed);
  const sampleCovers = sampleIds.length === analysedIds.length;

  const funnel: Array<{ key: string; label: string; count: number; note?: string }> = [
    { key: "findings", label: "扫描器命中", count: totals.findings },
    { key: "bundled", label: "进入分析包", count: totals.bundled },
    { key: "deduped", label: "因重复合并", count: totals.deduped },
    { key: "rejected", label: "被裁剪丢弃", count: totals.rejected },
    { key: "contexts", label: "构建的分析上下文", count: totals.contexts },
  ];
  const funnelBase = totals.findings > 0 ? totals.findings : null;

  return (
    <section>
      {error ? <Banner>{error.detail}</Banner> : null}

      <div className="kpi-grid">
        <Kpi
          title="分析包"
          icon={<IconBundles size={17} />}
          value={formatCount(totals.bundles)}
          sub={
            <>
              {totals.workspaces} 个工作区 · 最近{" "}
              {formatRelative(bundles[0]?.created_at ?? null)}
            </>
          }
        />
        <Kpi
          title="静态命中"
          icon={<IconTraffic size={17} />}
          value={formatCount(totals.findings)}
          sub={
            <>
              进入分析包 {formatCount(totals.bundled)} · 裁剪 {formatCount(totals.rejected)}
            </>
          }
        />
        <Kpi
          title="快速研判覆盖"
          icon={<IconVerdicts size={17} />}
          tone="accent"
          value={aiCoverage === null ? "—" : formatPercent(aiCoverage)}
          sub={
            <>
              {formatCount(totals.analysed)} / {formatCount(totals.bundles)} 个分析包已研判
            </>
          }
        />
        <Kpi
          title="判为误报"
          icon={<IconVerdicts size={17} />}
          tone="ok"
          value={fpShare === null ? "—" : formatPercent(fpShare)}
          sub={
            ai.parsed === 0 ? (
              "尚无可解析的研判"
            ) : (
              <>
                误报 {formatCount(ai.falsePositive)} 条 · 共 {formatCount(ai.parsed)} 条研判
                {sampleCovers ? "" : `（最近 ${formatCount(sampleIds.length)} 个包）`}
              </>
            )
          }
        />
      </div>

      {totals.suspicious > 0 ? (
        <Banner kind="warn">
          {formatCount(totals.suspicious)} 个分析包来自一次完全没有命中的扫描 —— 记为可疑，而不是干净结果。
        </Banner>
      ) : null}
      {reports.error ? (
        <Banner kind="warn">研判明细读取失败，本页 AI 相关数字不完整：{reports.error.detail}</Banner>
      ) : null}

      <div className="section-head">
        <h2>运行观测</h2>
        <p className="muted">请求、后台任务与队列的实时状态</p>
      </div>

      <div className="panel-grid">
        <div className="card">
          <div className="panel-title">
            <IconTraffic size={16} />
            <h3>调用指标</h3>
            <span className="muted right">
              启动以来 {formatCount(traffic.data?.count ?? 0)} 次请求
            </span>
          </div>
          {paths.length === 0 ? (
            <Empty>暂无请求记录（网关重启后缓冲从空开始）</Empty>
          ) : (
            <ul className="metric-list">
              {paths.map((metric) => (
                <li key={metric.label}>
                  <code className="metric-name">{metric.label}</code>
                  <span className="metric-count">{formatCount(metric.count)} 次</span>
                  <span className="metric-note">
                    均值 {formatDurationMs(metric.avgMs)}
                    {metric.errors > 0 ? <span className="error"> · {metric.errors} 次失败</span> : null}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="card">
          <div className="panel-title">
            <IconJobs size={16} />
            <h3>任务队列</h3>
            <span className={`right muted`}>
              {queue ? (
                <>
                  <span className={`dot${queue.degraded ? " bad" : ""}`} />
                  {queue.degraded ? "队列降级" : `worker ${queue.workers_alive} 在线`}
                </>
              ) : (
                "无队列"
              )}
            </span>
          </div>
          <div className="queue-cards">
            {queueByKind(jobs, KINDS).map((entry) => (
              <div className="queue-card" key={entry.kind}>
                <div className="queue-card-head">
                  <span className="muted">{label(JOB_KIND, entry.kind)}</span>
                </div>
                <div className="queue-card-body">
                  <span>
                    <b>{formatCount(entry.running)}</b>
                    <em>运行中</em>
                  </span>
                  <span>
                    <b>{formatCount(entry.queued)}</b>
                    <em>排队中</em>
                  </span>
                </div>
                <div className="queue-card-foot muted">
                  {entry.running + entry.queued === 0 ? "暂无任务" : `已完成 ${formatCount(entry.finished)}`}
                </div>
              </div>
            ))}
          </div>
          {queue ? (
            <div className="counters">
              <span className="counter">总排队 {formatCount(queue.queued)}</span>
              <span className="counter">待确认 {formatCount(queue.pending)}</span>
              <span className="counter">积压 {queue.lag === null ? "—" : formatCount(queue.lag)}</span>
            </div>
          ) : (
            <Banner kind="warn">无队列：网关未配置 Redis，任务在提交它的那次请求中同步执行。</Banner>
          )}
        </div>
      </div>

      <div className="section-head">
        <h2>分析收敛</h2>
        <p className="muted">从静态命中到快速研判，每一步都在缩小范围</p>
      </div>

      <div className="panel-grid three">
        <div className="card">
          <div className="panel-title">
            <h3>流水线漏斗</h3>
            <span className="muted right">{formatCount(totals.bundles)} 个分析包合计</span>
          </div>
          <ul className="bar-rows">
            {funnel.map((step) => (
              <BarRow
                key={step.key}
                label={step.label}
                count={formatCount(step.count)}
                share={share(step.count, funnelBase ?? 0)}
              />
            ))}
          </ul>
          <div className="counters">
            {/* 「裁剪记录」而不是「裁剪」：上面漏斗里的 `被裁剪丢弃` 数的是**命中**，
                这里的 `prune_count` 数的是**裁剪决策**（方法/边）。同一个词两种单位并排出现，
                读者一定会把它们相减。 */}
            <span className="counter">裁剪记录 {formatCount(totals.prunes)}</span>
            <span className="counter">降级记录 {formatCount(totals.degradations)}</span>
            <span className="counter">累计估 token 约 {formatCount(totals.tokens)}</span>
          </div>
        </div>

        <div className="card">
          <div className="panel-title">
            <h3>快速研判结果</h3>
            <span className="muted right">
              {sampleCovers ? "" : `最近 ${formatCount(sampleIds.length)} 个包 · `}
              {formatCount(ai.contexts)} 个上下文
            </span>
          </div>
          {ai.contexts === 0 ? (
            <Empty>还没有分析包被研判</Empty>
          ) : (
            <>
              <ul className="bar-rows">
                <BarRow
                  label="真阳性"
                  count={formatCount(ai.truePositive)}
                  share={share(ai.truePositive, ai.parsed)}
                />
                <BarRow
                  label="假阳性"
                  count={formatCount(ai.falsePositive)}
                  share={share(ai.falsePositive, ai.parsed)}
                />
                <BarRow
                  label="证据不足"
                  count={formatCount(ai.needsContext)}
                  share={share(ai.needsContext, ai.parsed)}
                />
                {ai.failed > 0 ? (
                  <BarRow
                    label={<span className="error">未能解析</span>}
                    count={formatCount(ai.failed)}
                    share={share(ai.failed, ai.contexts)}
                  />
                ) : null}
              </ul>
              <div className="counters">
                <span className="counter">
                  平均置信度 {ai.meanConfidence === null ? "—" : formatPercent(ai.meanConfidence)}
                </span>
                <span className="counter">
                  缓存命中 {ai.cacheShare === null ? "—" : formatPercent(ai.cacheShare)}
                </span>
                <span className="counter">
                  token 输入 {formatCount(ai.prompt)} · 输出 {formatCount(ai.completion)}
                </span>
              </div>
            </>
          )}
        </div>

        <div className="card">
          <div className="panel-title">
            <h3>数据来源分布</h3>
            <span className="muted right">按分析包计</span>
          </div>
          {providers.length === 0 ? (
            <Empty>暂无来源信息</Empty>
          ) : (
            <ul className="bar-rows">
              {providers.map((entry) => (
                <BarRow
                  key={entry.provider}
                  label={<code>{entry.provider}</code>}
                  count={formatCount(entry.bundles)}
                  share={entry.share}
                  note={formatPercent(entry.share)}
                />
              ))}
            </ul>
          )}
          <p className="note">
            语言服务器来源记 <code>fact</code>，语法启发式记 <code>guess</code>：这一列用来看有多少分析包
            只建立在启发式之上。
          </p>
        </div>
      </div>

      <div className="section-head">
        <h2>最近活动</h2>
        <p className="muted">点任意一行进入详情</p>
      </div>

      <div className="panel-grid">
        <div className="card">
          <div className="panel-title">
            <h3>最近任务</h3>
            <span className="muted right">{running > 0 ? `${running} 个在跑或排队` : "全部已结束"}</span>
          </div>
          {recentJobs.length === 0 ? (
            <Empty>暂无任务记录</Empty>
          ) : (
            <ul className="row-list">
              {recentJobs.map((job) => (
                <li key={job.job_id} className="clickable" onClick={() => onOpenJob(job.job_id)}>
                  <code>{job.job_id.slice(0, 12)}</code>
                  <span className={`badge state state-${job.state}`}>
                    {label(JOB_STATE, job.state)}
                  </span>
                  <span className="muted">{label(JOB_KIND, job.kind)}</span>
                  <span className="right muted">
                    {label(STAGE, job.stage)} · {formatRelative(job.submitted_at)} ·{" "}
                    {formatDurationMs(job.duration_ms)}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>

        <div className="card">
          <div className="panel-title">
            <h3>最近分析包</h3>
            <span className="muted right" title={formatTimestamp(bundles[0]?.created_at ?? null)}>
              共 {formatCount(totals.bundles)} 个
            </span>
          </div>
          {recentBundles.length === 0 ? (
            <Empty>磁盘上暂无分析包</Empty>
          ) : (
            <ul className="row-list">
              {recentBundles.map((bundle) => (
                <li
                  key={bundle.bundle_id}
                  className="clickable"
                  onClick={() => onOpenBundle(bundle.bundle_id)}
                >
                  <code>{bundle.bundle_id}</code>
                  <span className="muted">{formatCount(bundle.focus_count)} 上下文</span>
                  <span className="muted">~{formatCount(bundle.estimated_tokens)} token</span>
                  <span className="right">
                    {bundle.has_ai_report ? (
                      <span className="badge ok-badge">已研判</span>
                    ) : (
                      <span className="muted">未研判</span>
                    )}
                    <span className="muted"> · {formatRelative(bundle.created_at)}</span>
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      </div>
    </section>
  );
}
