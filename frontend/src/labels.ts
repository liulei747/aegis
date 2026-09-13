/**
 * The words the API's enum values are shown as.
 *
 * The values themselves are contract: they arrive in payloads, they are compared in `format.ts`
 * and screen code, and CSS class names are built from them (`state state-${job.state}`). Only the
 * rendering half lives here, so a screen reads `label(JOB_STATE, job.state)` while the raw value
 * keeps its place in `className` and in every comparison.
 *
 * Kept pure and free of React, like `format.ts`, so a screen can use it anywhere.
 */

export const JOB_STATE: Readonly<Record<string, string>> = {
  queued: "排队中",
  running: "运行中",
  succeeded: "成功",
  failed: "失败",
  canceled: "已取消",
};

/**
 * 任务类型。
 *
 * 两个 AI 模块的名字必须一眼看出深浅，而不是靠"审计"和"研判"两个近义词去猜：
 *
 * * **深度审计**（`audit`）—— 多智能体自己读代码、自己找证据，半小时、上百次模型调用，
 *   能发现组装阶段根本没提出的问题；
 * * **快速研判**（`ai_fanout`）—— 对分析包里每个已组装好的上下文各问一次模型，几分钟，
 *   只判断已经摆到桌面上的那些点。
 *
 * 之前叫「AI 审计」和「AI 研判」，两个都以"AI"开头、都以两个字结尾，读者分不清哪个是深度。
 */
export const JOB_KIND: Readonly<Record<string, string>> = {
  assemble: "组装",
  scan: "扫描",
  ai_fanout: "快速研判",
  audit: "深度审计",
};

/** 两个 AI 模块各自的一句话说明，出现在菜单提示和页头。 */
export const JOB_KIND_HINT: Readonly<Record<string, string>> = {
  audit: "多智能体自己读代码找问题：能发现分析包里没有的点，慢且贵",
  ai_fanout: "对分析包里每个入口各问一次模型：快，只判断已有的点",
  assemble: "静态扫描 + 调用图 + 打包成分析包",
  scan: "只跑静态扫描，不组装",
};

export const STAGE: Readonly<Record<string, string>> = {
  scan: "扫描",
  setup: "环境准备",
  locate: "定位方法",
  expand: "扩展调用图",
  read: "读取方法体",
  assemble: "组装上下文",
  package: "打包",
  ai: "快速研判",
  done: "完成",
};

export const STAGE_STATE: Readonly<Record<string, string>> = {
  pending: "待执行",
  running: "进行中",
  done: "已完成",
  skipped: "已跳过",
  failed: "失败",
};

export const VERDICT: Readonly<Record<string, string>> = {
  true_positive: "真阳性",
  false_positive: "假阳性",
  needs_more_context: "证据不足",
};

export const SEVERITY: Readonly<Record<string, string>> = {
  critical: "致命",
  high: "高",
  medium: "中",
  low: "低",
  informational: "提示",
};

export const TRUST: Readonly<Record<string, string>> = {
  fact: "事实",
  strong: "强",
  weak: "弱",
  guess: "猜测",
  unknown: "未知",
};

/**
 * The Chinese word for an API value, or the value itself when this build has not been taught it.
 *
 * Never returns `undefined`: a value the backend adds later shows up as its raw spelling, which a
 * reader can report, rather than as a blank cell nobody can explain. A missing value renders as
 * the em dash this console uses everywhere else for "the API did not say".
 */
export function label(
  map: Readonly<Record<string, string>>,
  value: string | null | undefined,
): string {
  if (value === null || value === undefined) return "—";
  return map[value] ?? value;
}

/**
 * SARIF 的等级。扫描命中的严重度用的是这一套，不是上面 `SEVERITY` 那套研判等级。
 *
 * 两套词表并存是事实，不是遗漏：模型研判回答的是 critical/high/medium/low/informational，
 * 而 SARIF（以及 `aegis_contracts/views.py` 里按它排序的"最严重命中"）用的是
 * error/warning/note/info。同一个 `SeverityBadge` 两种都要渲染，所以这里不能只留一张表 ——
 * 合并的话，将来某个 SARIF 等级会和研判等级静默相撞，而症状只是"某个角标显示英文"。
 */
export const SARIF_LEVEL: Readonly<Record<string, string>> = {
  error: "错误",
  warning: "警告",
  note: "提示",
  info: "信息",
  none: "无",
};

/** 严重度的中文：先按研判等级查，再按 SARIF 等级查，都不是就原样显示。 */
export function severityLabel(value: string | null | undefined): string {
  if (value === null || value === undefined) return "—";
  return SEVERITY[value] ?? SARIF_LEVEL[value] ?? value;
}
