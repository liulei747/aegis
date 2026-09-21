import { useMemo, useState } from "react";
import type { AuditEvent } from "../api/types.ts";
import { leadRows, taskEvidence, taskRows, taskStatusReason } from "../audit.ts";
import { Empty, Field } from "../components.tsx";
import { formatTimestamp } from "../format.ts";

const STATES: Record<string, string> = {
  planned: "待办", running: "进行中", done: "已完成", blocked: "受阻",
  canceled: "已取消", abandoned: "受阻（旧记录）",
};
const KINDS: Record<string, string> = {
  file_review: "文件审查", investigation: "专题调查", validation: "候选验证", attack_path: "攻击路径",
};

export function AuditBlackboard({ events }: { events: AuditEvent[] }) {
  const leads = leadRows(events);
  const leadStates: Record<string, string> = { pending: "待规划", linked: "待执行", handled: "已处理", deferred: "已延期", dismissed: "不适用" };
  const records = events.filter((event) => event.kind === "record");
  return <details>
    <summary>共享黑板记录（{records.length}）</summary>
    <p className="muted">显示 agent 主动发布的事实、假设和线索摘要；这些记录不是已验证漏洞。候选及裁决见任务详情。</p>
    {leads.length ? <>
      <h3>线索收件箱（{leads.length}）</h3>
      <ul>{leads.map(lead => <li key={lead.lead_id}>
        <strong>{leadStates[lead.status] || lead.status}</strong> · {lead.question} · {lead.file}:{lead.line ?? ""}
        <div className="muted">来源任务：{lead.source_work_id || "旧记录"}；关联任务：{lead.linked_work_id || "待规划"}；处理理由：{lead.processing_reason || "尚未处理"}</div>
      </li>)}</ul>
    </> : null}
    {records.length === 0 ? <Empty>尚无主动发布的黑板记录。</Empty> : <>
      <p className="muted">最近 {Math.min(80, records.length)} / {records.length} 条。</p>
      <ul>{records.slice(-80).map((entry) => <li key={entry.seq}>
        <strong>{entry.record_kind || "记录"}</strong> · {entry.scope || "全局"} · {entry.text || entry.summary || "—"}
      </li>)}</ul>
    </>}
  </details>;
}

export function AuditTasks({ events, terminal }: { events: AuditEvent[]; terminal: boolean }) {
  const tasks = useMemo(() => taskRows(events), [events]);
  const [state, setState] = useState("");
  const [kind, setKind] = useState("");
  const [selected, setSelected] = useState<string | null>(null);
  const visible = tasks.filter((task) => (!state || task.state === state) && (!kind || task.kind === kind));
  const task = visible.find((item) => item.work_id === selected) ?? visible[0];
  const evidence = useMemo(() => task ? taskEvidence(events, task) : [], [events, task]);
  const reasons = useMemo(() => new Map(tasks.map(item => {
    const itemEvidence = taskEvidence(events, item);
    return [item.work_id, taskStatusReason(item, itemEvidence)];
  })), [events, tasks]);
  const latest = evidence.filter((event) => event.kind === "agent_step").at(-1);

  return <section aria-label="统一审计任务">
    <h2>审计任务</h2>
    {tasks.length === 0 ? <Empty>尚无任务记录。规划完成后会显示待办；旧版本运行不包含此清单。</Empty> : <>
      <p className="muted">文件读取和审查完成分别记录。任务完成不代表代码没有漏洞。</p>
      <div className="row">
        {["planned", "running", "done", "blocked", "canceled"].map((value) =>
          <span className="badge" key={value}>{STATES[value]} {tasks.filter((item) => item.state === value).length}</span>)}
      </div>
      {terminal && tasks.some((item) => !["done", "canceled"].includes(item.state)) ?
        <p className="warn">运行已结束，仍有未完成任务。以下保留最后记录的状态，不表示仍在执行。</p> : null}
      <div className="row">
        <label>状态 <select value={state} onChange={(event) => setState(event.target.value)}>
          <option value="">全部状态</option>
          {Object.entries(STATES).map(([value, name]) => <option key={value} value={value}>{name}</option>)}
        </select></label>
        <label>类型 <select value={kind} onChange={(event) => setKind(event.target.value)}>
          <option value="">全部类型</option>
          {Object.entries(KINDS).map(([value, name]) => <option key={value} value={value}>{name}</option>)}
        </select></label>
        <span className="muted">显示 {visible.length} / {tasks.length} 项</span>
      </div>
      {visible.length === 0 ? <Empty>没有符合筛选条件的任务。</Empty> : <table className="table">
        <thead><tr><th>任务</th><th>类型</th><th>状态</th><th>执行次数</th><th>当前情况</th></tr></thead>
        <tbody>{visible.map((item) => <tr key={item.work_id} className={task?.work_id === item.work_id ? "current" : ""}>
          <td><button type="button" onClick={() => setSelected(item.work_id)} aria-pressed={task?.work_id === item.work_id}>{item.title}</button></td>
          <td>{KINDS[item.kind]}</td><td>{STATES[item.state]}</td><td>{item.attempts.length}</td>
          <td>{reasons.get(item.work_id) || "—"}</td>
        </tr>)}</tbody>
      </table>}
      {task ? <div className="card">
        <h3>{task.title}</h3>
        <div className="summary-grid">
          <Field label="创建原因">{task.rationale || "未提供"}</Field>
          <Field label="完成条件">{task.completion_criteria || "未提供"}</Field>
          <Field label="调查问题">{task.question || task.title}</Field>
          <Field label="优先级">{task.priority ?? 2}（1 最高）</Field>
          <Field label="状态说明">{reasons.get(task.work_id) || "—"}</Field>
          <Field label="最近执行者">{task.attempts.at(-1)?.agent ?? "尚未派发"}</Field>
          <Field label="创建时间">{formatTimestamp(task.opened_at)}</Field>
          <Field label="待处理更新">{task.pending_updates?.length ?? 0} 条</Field>
          {task.merged_into ? <Field label="合并到">{task.merged_into}</Field> : null}
          <Field label="关联候选">{task.candidate_ids.length} 项</Field>
          {["file_review", "investigation"].includes(task.kind) ?
            <Field label="文件读取">{task.read_files} / {task.files.length} 完整读取（独立于检查结果）</Field> : null}
          <Field label="最近动作">{latest ? `${latest.tool || "分析"}：${latest.summary || latest.thought || ""}` : "尚无工具记录"}</Field>
        </div>
        {task.gaps?.length ? <details open><summary>具体检查缺口（{task.gaps.length}）</summary>
          <ul>{task.gaps.map(gap => <li key={gap.gap_id}>
            {gap.state === "resolved" ? "已解决" : gap.state === "blocked" ? "受阻" : "待处理"} · {gap.question}
            <small> {gap.file}:{gap.line} · {gap.reason} · 证据 {gap.evidence_refs.length} 条</small>
          </li>)}</ul>
        </details> : null}
        <details><summary>涉及文件（{task.files.length}）</summary><ul>{task.files.map((file) => <li key={file}><code>{file}</code></li>)}</ul></details>
        {Object.keys(task.unread_ranges ?? {}).length ? <details><summary>未读源码区间</summary><ul>
          {Object.entries(task.unread_ranges ?? {}).map(([file, ranges]) => <li key={file}>
            {file}：{ranges.map(([start, end]) => `${start}–${end ?? "文件末尾"}`).join("、")}
          </li>)}
        </ul></details> : null}
        <details><summary>执行历史（{task.attempts.length}）</summary>
          <ul>{task.attempts.map((attempt, index) => <li key={`${attempt.run_id}-${index}`}>
            第 {index + 1} 次 · {formatTimestamp(attempt.started_at)} · {attempt.agent} ·
            {attempt.finished_at ? `${attempt.steps} 步，${attempt.stop_reason}` : "尚无结束记录"}
            {attempt.error ? `：${attempt.error}` : ""}
          </li>)}</ul>
        </details>
        <h3>关联黑板与证据</h3>
        <p className="muted">候选是待验证判断；研判是验证结论；工具记录用于追溯。这里只显示相关记录的摘要。</p>
        {evidence.length === 0 ? <Empty>尚无关联证据。</Empty> : <>
          <p className="muted">显示最近 {Math.min(60, evidence.length)} / {evidence.length} 条；完整执行记录见下方对话流。</p>
          <ul>{evidence.slice(-60).map((entry) => <li key={entry.seq}>
            <strong>{entry.kind === "candidate" ? "候选" : entry.kind === "verdict" ? "研判" :
              entry.kind === "record" ? "黑板记录" : entry.kind === "attack_path" ? "攻击路径" : entry.kind === "finding" ? "最终发现" : "工具 / 分析"}</strong>
            {" · "}{entry.file ? `${entry.file}:${entry.line ?? ""} · ` : ""}
            {entry.verdict ? `${entry.verdict} · ` : ""}
            {entry.title || entry.reason || entry.text || entry.impact || entry.summary || entry.thought || "—"}
          </li>)}</ul>
        </>}
      </div> : null}
    </>}
  </section>;
}
