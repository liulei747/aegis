/**
 * 项目管理：新建项目（从仓库拉取 / 上传压缩包），以及每个项目被分析到什么程度。
 *
 * 这一屏现在有两个数据来源，缺一不可：
 *
 * * **注册表**（`GET /v1/projects`）—— 新建出来的项目，带来源地址、分支、commit、时间。
 * * **派生数据** —— 任务与分析包上记录的 workspace。功能上线之前就存在的包只有这一边有。
 *
 * 只看注册表会把历史数据藏起来；只看派生则刚建好、还没分析完的项目不显示，用户会以为自己
 * 点失败了。所以两边按 workspace 合并（`mergeProjects`），并用「来源」一列区分。
 *
 * 拉取是**服务端**做的事：前端只给一个 https 地址。这个区别很重要 —— 仓库克隆由网关执行，
 * 不需要把任何凭据放进浏览器，代价是只支持公开仓库。
 */

import { useState } from "react";
import { api, type ApiError } from "../api/client.ts";
import type { BundleSummary, Health, JobSummary, ProjectDeepAnalysis, ProjectRecord } from "../api/types.ts";
import { Banner, Empty, usePolled } from "../components.tsx";
import {
  formatCount,
  formatRelative,
  formatTimestamp,
  languageDepth,
  languageSummary,
  languagesWithoutCallGraph,
  mergeProjects,
  type ProjectRow,
} from "../format.ts";
import { IconProjects } from "../icons.tsx";

/** 深不了一门语言时，说清楚"还能拿到什么、拿不到什么"，而不是一句"不支持"。 */
function depthNote(depth: ReturnType<typeof languageDepth>): string {
  if (depth === "full") return "调用图 + 污点流";
  if (depth === "call_graph") return "调用图（无污点流）";
  return "只有静态规则命中";
}

/** 前端先挡一次协议，让读者立刻看到问题，而不是提交后等一个 400。服务端仍会再挡。 */
function urlProblem(url: string): string | null {
  const trimmed = url.trim();
  if (trimmed === "") return "请输入仓库地址";
  if (!trimmed.startsWith("https://")) {
    return "只支持 https:// 开头的公开仓库地址（服务端按白名单拒绝其它协议）";
  }
  if (trimmed.length < "https://a.b".length) return "这不像一个仓库地址";
  return null;
}

function NewProjectPanel({
  onCreated,
  deep,
}: {
  onCreated: (record: ProjectRecord) => void;
  deep: ProjectDeepAnalysis | undefined;
}) {
  const [tab, setTab] = useState<"git" | "archive">("git");
  const [url, setUrl] = useState("");
  const [ref, setRef] = useState("");
  const [name, setName] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [busy, setBusy] = useState(false);
  const [failure, setFailure] = useState<ApiError | null>(null);
  const [created, setCreated] = useState<ProjectRecord | null>(null);

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setFailure(null);
    setCreated(null);

    if (tab === "git") {
      const problem = urlProblem(url);
      if (problem) {
        setFailure({ status: 0, detail: problem });
        return;
      }
    } else if (!file) {
      setFailure({ status: 0, detail: "请选择一个 .zip 压缩包" });
      return;
    }

    setBusy(true);
    try {
      // `analyze: false` 是有意的：创建项目与分析是两件事，这一屏只管前者。
      // 之前这里有一个"建好后立即分析"的复选框，它让"从哪开始"有两个互相矛盾的答案
      // （项目页能开分析，审计页又能手填路径），也让人以为不勾就不会有任何后续步骤。
      // 现在创建完只给两个去处：深度审计、快速研判。
      const record =
        tab === "git"
          ? await api.createProject({
              git_url: url.trim(),
              ref: ref.trim() || null,
              name: name.trim() || null,
              analyze: false,
            })
          : await api.uploadProject(file!, {
              name: name.trim() || null,
              analyze: false,
            });
      setCreated(record);
      setUrl("");
      setRef("");
      setName("");
      setFile(null);
      onCreated(record);
    } catch (caught) {
      setFailure(caught as ApiError);
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="card">
      <div className="panel-title">
        <IconProjects size={16} />
        <h3>新建项目</h3>
        <div className="tabs right">
          <button
            type="button"
            className={tab === "git" ? "on" : ""}
            onClick={() => setTab("git")}
          >
            从仓库拉取
          </button>
          <button
            type="button"
            className={tab === "archive" ? "on" : ""}
            onClick={() => setTab("archive")}
          >
            上传压缩包
          </button>
        </div>
      </div>

      <form onSubmit={submit}>
        <div className="row">
          {tab === "git" ? (
            <>
              <label className="grow">
                仓库地址（仅公开仓库）
                <input
                  value={url}
                  onChange={(event) => setUrl(event.target.value)}
                  placeholder="https://github.com/owner/repo.git"
                  size={44}
                />
              </label>
              <label>
                分支 / 标签
                <input
                  value={ref}
                  onChange={(event) => setRef(event.target.value)}
                  placeholder="留空用默认分支"
                  size={16}
                />
              </label>
            </>
          ) : (
            <label className="grow">
              源码压缩包（.zip）
              <input
                type="file"
                accept=".zip,application/zip"
                onChange={(event) => setFile(event.target.files?.[0] ?? null)}
              />
            </label>
          )}
          <label>
            项目名
            <input
              value={name}
              onChange={(event) => setName(event.target.value)}
              placeholder="留空自动取"
              size={18}
            />
          </label>
          <button type="submit" disabled={busy}>
            {busy ? "处理中…" : "创建"}
          </button>
        </div>
      </form>

      <p className="note">
        {tab === "git"
          ? "克隆由网关执行（浅克隆，只取默认分支），源码落在服务器的项目目录里。私有仓库请先导出压缩包再上传 —— 这个接口不接受任何凭据，因此也没有凭据会进日志。"
          : "压缩包会被解压到服务器的项目目录。会拒绝含 ../ 路径、绝对路径或符号链接的条目，并限制解压后的总大小与文件数。"}
      </p>

      {failure ? (
        <Banner>
          {failure.detail}
          {failure.status === 409 ? " —— 换一个项目名，或先删掉同名项目。" : ""}
          {failure.status === 503 ? " —— 这个部署关闭了项目功能。" : ""}
        </Banner>
      ) : null}

      {created ? (
        <Banner kind="info">
          已创建 <code>{created.name}</code>（{formatCount(created.files)} 个文件，
          {formatBytes(created.bytes)}）
          {created.languages && Object.keys(created.languages).length > 0 ? (
            <> · 识别到 {languageSummary(created.languages)}</>
          ) : null}
          {created.commit ? (
            <>
              {" "}
              · commit <code>{created.commit.slice(0, 12)}</code>
            </>
          ) : null}
          {" "}
          · 接下来：<a href="#/audit">深度审计</a> 或 <a href="#/verdicts">快速研判</a>
        </Banner>
      ) : null}

      {/* 语言识别最有用的地方就是这里：在等一次几分钟的分析之前，先说清这个项目能拿到多少。
          之前只有分析完之后、从几十条降级里才能推断出来。 */}
      {created && languagesWithoutCallGraph(created.languages ?? {}, deep).length > 0 ? (
        <Banner kind="warn">
          {languagesWithoutCallGraph(created.languages ?? {}, deep).join("、")} 在本部署里
          <strong>画不出调用图</strong>（镜像没装对应的语言服务器），也追不了污点流
          （污点分析目前只支持 Python）。这个项目只会得到 opengrep 的静态规则命中 ——
          规则本身是跨语言有效的，但不会给出可达性和数据流。
        </Banner>
      ) : null}
    </div>
  );
}

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(0)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

/** 「来源」一列：注册表项目给地址与分支，派生项目说明它是历史数据。 */
function OriginCell({ row }: { row: ProjectRow }) {
  if (!row.registered) {
    return (
      <span className="muted" title="没有注册表条目：这个项目只在任务或分析包上出现过">
        —
      </span>
    );
  }
  return (
    <span title={row.origin ?? ""}>
      <span className="badge quiet">{row.source === "git" ? "仓库" : "压缩包"}</span>{" "}
      <code className="truncate">{row.origin}</code>
      {row.ref ? <span className="muted"> @{row.ref}</span> : null}
    </span>
  );
}

export function ProjectsScreen({
  bundles,
  jobs,
  workspace,
  onOpenAudit,
  onOpenVerdicts,
}: {
  bundles: BundleSummary[];
  jobs: JobSummary[];
  workspace: string | null;
  onOpenAudit: () => void;
  onOpenVerdicts: () => void;
}) {
  // 轮询：新建项目后注册表里马上有它，而分析包要等任务跑完才出现。
  const registry = usePolled<{ projects: ProjectRecord[] }>(() => api.projects(), [], {
    pollMs: 10_000,
  });
  // 这个部署能深到什么程度。取一次即可，但跟着注册表一起轮询也无妨。
  const health = usePolled<Health>(() => api.health(), [], { pollMs: 60_000 });
  const deep: ProjectDeepAnalysis | undefined = health.data?.capabilities?.projects?.deep_analysis;
  const rows = mergeProjects(registry.data?.projects ?? [], bundles, jobs);

  if (workspace !== null) {
    const project = rows.find((candidate) => candidate.workspace === workspace);
    if (!project) {
      return (
        <section>
          <Banner kind="warn">
            没有任何任务或分析包记录工作区 <code>{workspace}</code>。这里没有注册表，因此项目只在被引用时存在。
          </Banner>
        </section>
      );
    }
    return (
      <section>
        <div className="row">
          <h1>{project.name}</h1>
          {/* 从项目页去分析，只做导航，不在这里开跑：这一屏只管理项目本身。 */}
          <button type="button" className="right" onClick={onOpenAudit}>
            去深度审计
          </button>
          <button type="button" onClick={onOpenVerdicts}>
            去快速研判
          </button>
        </div>
        <p className="muted">
          <code>{project.workspace}</code>
        </p>
        <div className="stats">
          <span>
            分析包 <strong>{formatCount(project.bundleCount)}</strong>
          </span>
          <span>
            任务 <strong>{formatCount(project.jobCount)}</strong>
          </span>
          <span>
            上下文 <strong>{formatCount(project.contextCount)}</strong>
          </span>
          <span>
            最近活动 <strong>{formatRelative(project.lastActivity)}</strong>
          </span>
        </div>
        {project.registered ? (
          <div className="card summary-grid">
            <div className="field">
              <span className="field-label">来源</span>
              <span className="field-value">
                <OriginCell row={project} />
              </span>
            </div>
            <div className="field">
              <span className="field-label">commit</span>
              <span className="field-value">
                <code>{project.commit ? project.commit.slice(0, 12) : "—"}</code>
              </span>
            </div>
            <div className="field">
              <span className="field-label">创建时间</span>
              <span className="field-value">{formatTimestamp(project.createdAt)}</span>
            </div>
          </div>
        ) : null}

        <p className="muted">
          这个项目的分析包在「分析包」页，任务在「任务」页，审计过程与发现在「深度审计」页 ——
          这里只回答"它是什么、从哪来"。
        </p>
      </section>
    );
  }

  return (
    <section>
      {registry.error ? (
        <Banner kind="warn">
          读取项目注册表失败，下面只显示任务与分析包里出现过的项目：{registry.error.detail}
        </Banner>
      ) : null}

      <NewProjectPanel onCreated={() => registry.reload()} deep={deep} />

      <div className="section-head">
        <h2>全部项目</h2>
        <p className="muted">
          注册表与任务/分析包上记录的工作区的并集。没有注册表条目的行是功能上线之前的数据。
          <strong>分析在「深度审计」与「快速研判」里跑</strong>，这一屏只管理项目本身。
        </p>
      </div>

      {rows.length === 0 ? (
        <Empty>还没有任何项目 —— 用上面的表单从仓库拉取或上传一个压缩包。</Empty>
      ) : (
        <table className="table">
          <thead>
            <tr>
              <th>项目</th>
              <th>语言</th>
              <th>来源</th>
              <th>工作区</th>
              <th className="num">分析包</th>
              <th className="num">任务</th>
              <th>最近活动</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((row) => (
              <tr
                key={row.workspace}
                className="clickable"
                onClick={() => {
                  window.location.hash = `/projects/${encodeURIComponent(row.workspace)}`;
                }}
              >
                <td className="nowrap">
                  <strong>{row.name}</strong>
                  {row.registered ? null : (
                    <span className="muted" title="没有注册表条目">
                      {" "}
                      · 历史
                    </span>
                  )}
                </td>
                <td className="nowrap">
                  {Object.keys(row.languages).length === 0 ? (
                    <span className="muted">—</span>
                  ) : (
                    Object.entries(row.languages)
                      .slice(0, 2)
                      .map(([language, files]) => (
                        <span
                          key={language}
                          className={`badge ${
                            languageDepth(language, deep) === "findings_only" ? "warn-badge" : "quiet"
                          }`}
                          title={`${language} ×${files} —— ${depthNote(languageDepth(language, deep))}`}
                        >
                          {language} ×{files}
                        </span>
                      ))
                  )}
                </td>
                <td>
                  <OriginCell row={row} />
                </td>
                <td>
                  <code className="truncate">{row.workspace}</code>
                </td>
                <td className="num">{formatCount(row.bundleCount)}</td>
                <td className="num">{formatCount(row.jobCount)}</td>
                <td className="nowrap" title={formatTimestamp(row.lastActivity)}>
                  {formatRelative(row.lastActivity)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      )}
    </section>
  );
}
