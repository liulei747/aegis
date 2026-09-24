/**
 * Traffic: the requests the gateway has actually served, and the calls made to the model provider.
 *
 * Two blocks, and they are separate for a reason that is not cosmetic: they are *different kinds of
 * record*. The gateway's request log is an in-process ring -- empty after a restart, one ring per
 * replica -- while the model traffic is a JSONL file on the shared work volume, written by whichever
 * container talked to the provider, and it survives restarts. Each block shows the API's own note
 * verbatim: a reader who mistook either one for a complete audit trail would draw a wrong conclusion
 * from a short list.
 *
 * The AI block deliberately shows metadata only -- no prompts, no answers. A count that took three
 * attempts is the thing worth seeing, and the content already has a home: an audit's conversation is
 * in its run trail, a fast verdict's raw answer is in the bundle.
 */

import { useState } from "react";
import { api } from "../api/client.ts";
import type { AITrafficReport, TrafficReport } from "../api/types.ts";
import { Banner, Empty, Stat, usePolled } from "../components.tsx";
import {
  formatCount,
  formatDurationMs,
  formatPercent,
  formatTimestamp,
  modelCallTotals,
  trafficByPath,
} from "../format.ts";

function statusClass(status: number): string {
  if (status >= 500) return "error";
  if (status >= 400) return "warn";
  return "ok";
}

const AI_LIMITS = [50, 200, 1000];

/**
 * 模型调用那一块。与网关那一块共用页面的过滤框，但过滤的是自己的字段。
 */
function ModelTrafficPanel({ needle, onlyProblems }: { needle: string; onlyProblems: boolean }) {
  const [limit, setLimit] = useState(200);
  const report = usePolled<AITrafficReport>(() => api.aiTraffic(limit), [limit], { pollMs: 5000 });

  const all = report.data?.entries ?? [];
  const totals = modelCallTotals(all);
  const entries = all.filter((entry) => {
    if (onlyProblems && entry.ok) return false;
    if (needle === "") return true;
    const haystack = `${entry.caller} ${entry.model} ${entry.kind} ${entry.error ?? ""}`;
    return haystack.toLowerCase().includes(needle.toLowerCase());
  });
  const callers = [...new Set(all.map((entry) => entry.caller))].sort();

  return (
    <>
      <div className="stats">
        <Stat label="本页往返" value={formatCount(totals.attempts)} />
        <Stat label="其中重试" value={formatCount(totals.retried)} />
        <Stat label="失败" value={formatCount(totals.failures)} />
        <Stat label="平均耗时" value={formatDurationMs(totals.meanMs ?? 0)} />
        <Stat label="输入 token" value={formatCount(totals.promptTokens)} />
        <Stat label="输出 token" value={formatCount(totals.completionTokens)} />
        <Stat label="前缀命中" value={formatPercent(totals.cacheShare)} />
        <Stat label="来源数" value={formatCount(totals.callers)} />
      </div>

      {report.data ? <Banner kind="info">{report.data.note}</Banner> : null}
      {report.error ? <Banner kind="warn">AI 流量读取失败：{report.error.detail}</Banner> : null}
      {report.data && report.data.damaged > 0 ? (
        <Banner kind="warn">
          文件里有 {formatCount(report.data.damaged)} 行没写完（进程被杀时留下的半行），已跳过。
        </Banner>
      ) : null}

      <div className="row">
        <span className="muted">
          共 {formatCount(report.data?.count ?? 0)} 次往返，符合条件 {formatCount(entries.length)} 次
        </span>
        <label className="inline right">
          显示
          <select value={limit} onChange={(event) => setLimit(Number(event.target.value))}>
            {AI_LIMITS.map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
      </div>

      {all.length === 0 ? (
        <Empty>
          还没有模型调用记录。审计和快速研判一开始跟模型说话，这里就会出现 ——
          文件在共享工作目录里（<code>{report.data?.path ?? "ai-traffic.jsonl"}</code>），
          重启不会清空。
        </Empty>
      ) : entries.length === 0 ? (
        <Empty>没有调用符合过滤条件</Empty>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>时间</th>
              <th>来源</th>
              <th>类型</th>
              <th>模型</th>
              <th className="num">尝试</th>
              <th className="num">耗时</th>
              <th className="num">输入</th>
              <th className="num">输出</th>
              <th className="num">缓存</th>
              <th>停止原因</th>
              <th>结果</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry, index) => (
              <tr key={`${entry.at}-${entry.caller}-${entry.attempt}-${index}`}>
                <td title={entry.at}>{formatTimestamp(entry.at)}</td>
                <td className="note">{entry.caller}</td>
                <td className="note">{entry.kind}</td>
                <td className="note">{entry.model}</td>
                <td className="num">{entry.attempt > 1 ? `第 ${entry.attempt} 次` : "—"}</td>
                <td className="num">{formatDurationMs(entry.duration_ms)}</td>
                <td className="num">{formatCount(entry.prompt_tokens ?? 0)}</td>
                <td className="num">{formatCount(entry.completion_tokens ?? 0)}</td>
                <td className="num">{formatCount(entry.cached_tokens ?? 0)}</td>
                <td className="note">{entry.finish_reason || "—"}</td>
                <td className={entry.ok ? "ok" : "error"}>{entry.ok ? "成功" : entry.error ?? "失败"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {callers.length > 0 ? (
        <p className="muted">
          来源：{callers.slice(0, 12).join("、")}
          {callers.length > 12 ? ` 等 ${formatCount(callers.length)} 个` : ""}
        </p>
      ) : null}
    </>
  );
}

export function TrafficScreen() {
  const [limit, setLimit] = useState(200);
  const [needle, setNeedle] = useState("");
  const [onlyProblems, setOnlyProblems] = useState(false);
  const traffic = usePolled<TrafficReport>(() => api.traffic(limit), [limit], { pollMs: 5000 });

  const entries = (traffic.data?.entries ?? []).filter((entry) => {
    if (onlyProblems && entry.status < 400) return false;
    if (needle === "") return true;
    const haystack = `${entry.method} ${entry.path} ${entry.status} ${entry.client}`;
    return haystack.toLowerCase().includes(needle.toLowerCase());
  });
  const busiest = trafficByPath(traffic.data?.entries ?? []);

  const total = traffic.data?.count ?? 0;
  const shown = traffic.data?.entries.length ?? 0;

  return (
    <section>
      {traffic.error ? <Banner>{traffic.error.detail}</Banner> : null}

      <h2>网关请求</h2>
      <div className="stats">
        <Stat label="启动以来请求数" value={formatCount(total)} />
        <Stat label="本页条数" value={formatCount(shown)} />
        <Stat label="过滤后条数" value={formatCount(entries.length)} />
      </div>

      {traffic.data ? <Banner kind="info">{traffic.data.note}</Banner> : null}

      <div className="row">
        <label className="inline">
          过滤
          <input
            type="search"
            value={needle}
            placeholder="来源、路径、错误"
            onChange={(event) => setNeedle(event.target.value)}
          />
        </label>
        <label className="inline">
          <input
            type="checkbox"
            checked={onlyProblems}
            onChange={(event) => setOnlyProblems(event.target.checked)}
          />
          只看失败
        </label>
        <label className="inline">
          显示
          <select value={limit} onChange={(event) => setLimit(Number(event.target.value))}>
            {[50, 100, 200, 500].map((value) => (
              <option key={value} value={value}>
                {value}
              </option>
            ))}
          </select>
        </label>
      </div>

      {entries.length === 0 ? (
        <Empty>
          {total === 0
            ? "暂无记录 —— 缓冲区位于网关进程内，启动时为空"
            : "没有请求符合过滤条件"}
        </Empty>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th className="num">#</th>
              <th>时间</th>
              <th>方法</th>
              <th>路径</th>
              <th className="num">状态</th>
              <th className="num">耗时</th>
              <th>客户端</th>
            </tr>
          </thead>
          <tbody>
            {entries.map((entry) => (
              <tr key={entry.seq}>
                <td className="num muted">{entry.seq}</td>
                <td title={entry.at}>{formatTimestamp(entry.at)}</td>
                <td>{entry.method}</td>
                <td>
                  <code>{entry.path}</code>
                </td>
                <td className={`num status-${statusClass(entry.status)}`}>{entry.status}</td>
                <td className="num">{formatDurationMs(entry.duration_ms)}</td>
                <td className="muted">{entry.client || "—"}</td>
              </tr>
            ))}
          </tbody>
        </table>
      )}

      {busiest.length > 0 ? (
        <p className="muted">
          最忙的接口：
          {busiest
            .map((row) => `${row.label} ×${formatCount(row.count)}（均 ${formatDurationMs(row.avgMs)}）`)
            .join("；")}
        </p>
      ) : null}

      <h2>AI 对话</h2>
      <p className="muted">
        与模型 provider 的每一次往返，由网关、worker 或 extract 里真正发起调用的那个进程写入。
        重试各记一行 —— 一次调用花掉三次往返是这里最该看见的东西。
      </p>
      <ModelTrafficPanel needle={needle} onlyProblems={onlyProblems} />
    </section>
  );
}
