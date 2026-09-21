/**
 * 「选一个项目」在两个 AI 模块里的同一套逻辑。
 *
 * 这一层存在的理由是用户提的那个问题：深度审计原来手填路径、快速研判原来从分析包进入，两条
 * 路的"来源"长得完全不一样，于是没人说得清该从哪儿开始。现在两个模块都从**项目**开始
 * （`projectsFrom` 的产物），差别只在下一步：
 *
 * * 深度审计只需要路径 —— 项目选中就能跑；
 * * 快速研判需要该项目的分析包 —— 没有就先生成一个，有就直接用**最新的那个**。
 *
 * 纯函数，不碰 React：`node --test` 不走 JSX 转换，所以任何想被测试的规则都必须住在这种文件里
 * （`routes.ts`、`audit.ts` 都是这个原因）。
 */

import type { BundleSummary, JobSummary, ProjectRecord } from "./api/types.ts";
import { byRecentActivity, projectsFrom, UNKNOWN_WORKSPACE, type Project } from "./format.ts";

export interface ProjectChoice {
  /** 提交给后端的路径。深度审计与组装任务都用它。 */
  workspace: string;
  /** 给人看的名字（路径最后一段）。 */
  name: string;
  /**
   * 这个"项目"有没有真实路径。
   *
   * `(未知工作区)` 是历史分析包归到的一行，它不是一个能审计的目录：留着它可见是对的（数据在
   * 那里），但必须标出来不能选，而不是让用户点了之后等一个 400。
   */
  usable: boolean;
  bundleCount: number;
  contextCount: number;
  /** 最新一个分析包，快速研判的默认输入；没有就是 null。 */
  latestBundle: BundleSummary | null;
  /** 最近一次活动时间，用来排序。 */
  lastActivity: string | null;
  /** 这个项目最近一次深度审计任务（跑过就用它做入口）。 */
  lastAuditJob: JobSummary | null;
  /** 有没有正在排队 / 在跑的深度审计。 */
  auditInFlight: boolean;
}

/**
 * 最新的分析包。
 *
 * 按 `created_at` 比较字符串而不是 `Date`：API 给的是 ISO-8601 UTC，字典序与时间序一致，
 * 而 `new Date()` 会把一个格式意外的值变成 `Invalid Date`（NaN 比较永远为 false），
 * 于是"最新"悄悄变成"第一个"。
 *
 * 同一时刻的并列用 `bundle_id` 兜底，纯粹为了让结果**稳定**：同一个项目两次渲染选到不同的包，
 * 会让人以为界面在随机跳。
 */
export function latestBundleOf(bundles: BundleSummary[]): BundleSummary | null {
  let best: BundleSummary | null = null;
  for (const bundle of bundles) {
    if (best === null) {
      best = bundle;
      continue;
    }
    const left = bundle.created_at ?? "";
    const right = best.created_at ?? "";
    if (left > right || (left === right && bundle.bundle_id > best.bundle_id)) best = bundle;
  }
  return best;
}

/**
 * 项目选择器的选项：`projectsFrom` 的产物加上"下一步要用什么"。
 *
 * 排序沿用它（最近活动在前），因为选择器的第一项就是用户最可能想要的那个 —— 一个新项目排到
 * 列表末尾会让人以为没建成功。
 */
export function projectChoices(projects: Project[]): ProjectChoice[] {
  return projects.map((project) => {
    const audits = project.jobs.filter((job) => job.kind === "audit");
    const lastAudit = audits
      .slice()
      .sort((left, right) => (right.submitted_at ?? "").localeCompare(left.submitted_at ?? ""))[0];
    return {
      workspace: project.workspace,
      name: project.name,
      usable: project.workspace !== UNKNOWN_WORKSPACE,
      bundleCount: project.bundleCount,
      contextCount: project.contextCount,
      latestBundle: latestBundleOf(project.bundles),
      lastActivity: project.lastActivity,
      lastAuditJob: lastAudit ?? null,
      auditInFlight: audits.some((job) => job.state === "running" || job.state === "queued"),
    };
  });
}

/**
 * 从 API 已经返回的**三份**列表算出选项。选择器与项目页共用这一个入口。
 *
 * 第三份（注册表，`GET /v1/projects`）不是可选的。`projectsFrom` 是从**分析包与任务上记录的
 * workspace** 反推项目的，所以一个刚建好、上传完文件、还没跑过任何东西的项目在那份派生数据里
 * **根本不存在** —— 于是深度审计的项目下拉里选不到它，用户只能以为项目建失败了。
 *
 * 这正是 `format.ts::mergeProjects` 的注释早就点名的那个坑（「只看派生 —— 刚建好、还没分析完的
 * 项目不显示」）；项目页补了注册表，两个 AI 模块的选择器当时漏了。两边现在都从注册表并一次。
 */
export function choicesFrom(
  bundles: BundleSummary[],
  jobs: JobSummary[],
  records: ProjectRecord[] = [],
): ProjectChoice[] {
  const derived = projectsFrom(bundles, jobs);
  const registry = new Map(
    records.filter((record) => record.workspace).map((record) => [record.workspace, record] as const),
  );
  const known = new Set(derived.map((project) => project.workspace));

  // 只有注册表条目、没有包也没有任务的项目：它们是一个**可以审计的目录**，而这正是选择器要的。
  // `lastActivity` 取注册时间，这样刚建的项目排在最前 —— 用户刚刚建完它，那多半就是他想要的那个。
  const fresh: Project[] = [...registry.values()]
    .filter((record) => !known.has(record.workspace))
    .map((record) => ({
      workspace: record.workspace,
      name: record.name,
      bundles: [],
      jobs: [],
      bundleCount: 0,
      jobCount: 0,
      contextCount: 0,
      lastActivity: record.created_at ?? null,
    }));

  // 注册表里的名字是用户/仓库给的，比路径末段准 —— 已有的项目也一起改名，与
  // `format.ts::mergeProjects` 保持同一条规则，否则同一个项目在项目页与选择器里叫两个名字。
  const merged = [...derived, ...fresh].map((project) => {
    const record = registry.get(project.workspace);
    return record ? { ...project, name: record.name } : project;
  });

  return projectChoices(byRecentActivity(merged));
}

/** 默认选谁：第一个可用的项目。不可用的行留在列表里，但不会被自动选中。 */
export function defaultChoice(choices: ProjectChoice[]): ProjectChoice | null {
  return choices.find((choice) => choice.usable) ?? null;
}
