/**
 * 项目选择：两个 AI 模块共用的那一块。
 *
 * 放在自己的文件里而不是塞进 `components.tsx`，是因为它比通用 UI 多知道一件事 —— 项目怎么从
 * 任务与分析包里派生出来（`projects.ts`）。通用组件不认识业务，认识业务的这层要能被单独读。
 */

import { useEffect, useState } from "react";
import type { BundleSummary, JobSummary } from "../api/types.ts";
import { choicesFrom, defaultChoice, type ProjectChoice } from "../projects.ts";
import { Empty } from "../components.tsx";
import { formatCount, formatRelative } from "../format.ts";

/**
 * 三份列表进来，选项出去，外加一个"当前选中的 workspace"。
 *
 * 列表由页面外壳（`App.tsx`）传进来而不是各自再轮询一次：外壳本来就在轮询任务与分析包，
 * 每个屏再拉一遍就是同一份数据的三份副本，而它们会因为刷新时刻不同而互相矛盾。
 */
export function useProjectChoice(
  bundles: BundleSummary[],
  jobs: JobSummary[],
): {
  choices: ProjectChoice[];
  choice: ProjectChoice | null;
  select: (workspace: string) => void;
} {
  const choices = choicesFrom(bundles, jobs);
  const [workspace, setWorkspace] = useState<string | null>(null);

  // 默认选中第一个可用的项目；选中的项目消失了（清理掉的分析包）就退回默认。
  const current = choices.find((item) => item.workspace === workspace) ?? null;
  const effective = current !== null && current.usable ? current : defaultChoice(choices);

  // 新项目建好后（列表里多了一项）也要能看见：只在用户没有明确选择时才跟随默认。
  useEffect(() => {
    if (workspace !== null && current === null) setWorkspace(null);
  }, [workspace, current]);

  return {
    choices,
    choice: effective,
    select: (next: string) => setWorkspace(next),
  };
}

export function ProjectSelect({
  choices,
  selected,
  onSelect,
  emptyHint,
}: {
  choices: ProjectChoice[];
  selected: string | null;
  onSelect: (workspace: string) => void;
  emptyHint: string;
}) {
  if (choices.length === 0) {
    return <Empty>{emptyHint}</Empty>;
  }
  return (
    <label className="inline grow">
      项目
      <select value={selected ?? ""} onChange={(event) => onSelect(event.target.value)}>
        {choices.map((choice) => (
          <option key={choice.workspace} value={choice.workspace} disabled={!choice.usable}>
            {choice.name}
            {" — "}
            {choice.workspace}
            {choice.usable
              ? `（${formatCount(choice.bundleCount)} 个分析包）`
              : "（没有工作区，不能分析）"}
          </option>
        ))}
      </select>
    </label>
  );
}

/** 选中项目的现状摘要：回答"这个项目现在有什么"，是点按钮之前必须看到的东西。 */
export function ProjectFacts({ choice }: { choice: ProjectChoice | null }) {
  if (choice === null) return null;
  return (
    <div className="card summary-grid">
      <div className="field">
        <span className="field-label">路径</span>
        <span className="field-value">
          <code>{choice.workspace}</code>
        </span>
      </div>
      <div className="field">
        <span className="field-label">分析包</span>
        <span className="field-value">
          {formatCount(choice.bundleCount)} 个 · 共 {formatCount(choice.contextCount)} 个上下文
        </span>
      </div>
      <div className="field">
        <span className="field-label">最近活动</span>
        <span className="field-value">
          {choice.lastActivity ? formatRelative(choice.lastActivity) : "—"}
        </span>
      </div>
      <div className="field">
        <span className="field-label">上次深度审计</span>
        <span className="field-value">
          {choice.lastAuditJob ? (
            <a href={`#/audit/${encodeURIComponent(choice.lastAuditJob.job_id)}`}>
              {choice.lastAuditJob.state === "succeeded"
                ? "已完成"
                : choice.lastAuditJob.state === "running"
                  ? "运行中"
                  : choice.lastAuditJob.state}
              {" · "}
              {formatRelative(choice.lastAuditJob.submitted_at)}
            </a>
          ) : (
            "从未跑过"
          )}
        </span>
      </div>
    </div>
  );
}
