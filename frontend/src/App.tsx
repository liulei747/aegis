/**
 * 应用外壳：左侧菜单、顶栏状态、路由分发。
 *
 * 这一版把导航从顶部挪到了左侧。原因是信息层级，不是审美：原来的顶栏一行里塞了品牌、7 个
 * 菜单、4 个队列指标和 API 地址，窗口一窄就换行，换行后品牌和状态各占一行。现在三类东西
 * 各归其位 —— 导航在左侧（还会继续加），当前页标题和队列状态在顶栏，部署信息（API 地址）
 * 在侧栏底部，因为它是"这个部署连着哪儿"，不是每次都要看的东西。
 *
 * 主题（暗/亮）默认跟随系统，用户手动切过之后记住选择。首屏之前的取值由 `index.html` 里
 * 一段内联脚本完成，这里的 `useEffect` 只负责之后保持一致 —— 否则会先闪一下默认主题。
 */

import { useCallback, useEffect, useState } from "react";
import { api } from "./api/client.ts";
import { apiBase, apiBaseLabel } from "./api/config.ts";
import type { BundleSummary, JobList, ProjectRecord } from "./api/types.ts";
import { Banner, usePolled, useRoute, type Route } from "./components.tsx";
import { isActive } from "./format.ts";
import {
  IconAudit,
  IconBundles,
  IconJobs,
  IconOverview,
  IconProjects,
  IconSettings,
  IconTheme,
  IconTraffic,
  IconVerdicts,
} from "./icons.tsx";
import { AuditScreen } from "./screens/Audit.tsx";
import { BundleListScreen } from "./screens/Bundles.tsx";
import { BundleDetailScreen } from "./screens/BundleDetail.tsx";
import { CompareScreen } from "./screens/Compare.tsx";
import { JobDetailScreen } from "./screens/JobDetail.tsx";
import { JobListScreen } from "./screens/Jobs.tsx";
import { OverviewScreen } from "./screens/Overview.tsx";
import { ProjectsScreen } from "./screens/Projects.tsx";
import { SettingsScreen } from "./screens/Settings.tsx";
import { TrafficScreen } from "./screens/Traffic.tsx";
import { VerdictsScreen } from "./screens/Verdicts.tsx";
import { JOB_KIND_HINT } from "./labels.ts";
import { applyTheme, resolveTheme, setStoredTheme, watchSystemTheme, type Theme } from "./theme.ts";

const POLL_MS = 3000;
const SLOW_POLL_MS = 15_000;

interface MenuItem {
  /** 稳定标识。徽标与选中态都按它判断 —— 不能拿 `label` 判断，那是给人看的文案。 */
  key: string;
  label: string;
  to: string;
  icon: (props: { size?: number }) => React.ReactElement;
  /** 哪些路由算"在这一屏里"（列表屏与它的详情屏）。 */
  screens: Route["screen"][];
  /** 悬停提示。两个 AI 模块靠它说清深浅，省得靠名字猜。 */
  hint?: string;
}

/**
 * 菜单顺序是有主张的：**建项目 → 深度审计 / 快速研判**。
 *
 * 项目管理排第二，因为它是入口：没有项目就没有路径，两个分析模块都无事可做。之前它排在中间，
 * 而审计页又允许手填路径，于是"从哪开始"有两个互相矛盾的答案。
 *
 * 分析包排在两个分析模块之后：它是快速研判的输入，读者先知道有这两个模块、再去看它们的中间产物，
 * 比反过来顺。
 */
const MENU: MenuItem[] = [
  { key: "overview", label: "总览", to: "/overview", icon: IconOverview, screens: ["overview"] },
  {
    key: "projects",
    label: "项目管理",
    to: "/projects",
    icon: IconProjects,
    screens: ["projects"],
    hint: "新建与查看项目。分析在下面两个模块里跑。",
  },
  {
    key: "audit",
    label: "深度审计",
    to: "/audit",
    icon: IconAudit,
    screens: ["audit"],
    hint: JOB_KIND_HINT.audit,
  },
  {
    key: "verdicts",
    label: "快速研判",
    to: "/verdicts",
    icon: IconVerdicts,
    screens: ["verdicts"],
    hint: JOB_KIND_HINT.ai_fanout,
  },
  {
    key: "bundles",
    label: "分析包",
    to: "/bundles",
    icon: IconBundles,
    screens: ["bundles", "bundle", "compare"],
    hint: "静态扫描与调用图组装出的产物，快速研判的输入",
  },
  { key: "jobs", label: "任务", to: "/jobs", icon: IconJobs, screens: ["jobs", "job"] },
  { key: "traffic", label: "流量日志", to: "/traffic", icon: IconTraffic, screens: ["traffic"] },
  { key: "settings", label: "参数设置", to: "/settings", icon: IconSettings, screens: ["settings"] },
];

export function App() {
  const [route, navigate] = useRoute();
  const [theme, setTheme] = useState<Theme>(() => resolveTheme());

  // `index.html` 已经把首屏主题写好，这里只处理此后的变化：手动切换，以及用户没有手动
  // 选择时跟随系统。
  useEffect(() => {
    applyTheme(theme);
  }, [theme]);
  useEffect(() => watchSystemTheme(setTheme), []);

  const toggleTheme = useCallback(() => {
    const next: Theme = theme === "dark" ? "light" : "dark";
    setStoredTheme(next);
    setTheme(next);
  }, [theme]);

  // 在 shell 里轮询，而不是每个屏各自轮询：菜单徽标与队列状态是全局的，否则每个需要任务的
  // 屏都会再取一遍。
  const jobs = usePolled<JobList>(() => api.jobs(), [], { pollMs: POLL_MS });
  const bundles = usePolled<{ bundles: BundleSummary[] }>(() => api.bundles(), [], {
    pollMs: SLOW_POLL_MS,
  });
  // 项目注册表也要轮询。两个 AI 模块的选择器**必须**能看见刚建好、还没有任何任务与分析包的
  // 项目 —— 只从包与任务派生的话，用户建完项目、上传完文件，到深度审计页会发现选不到它。
  const projects = usePolled<{ projects: ProjectRecord[] }>(() => api.projects(), [], {
    pollMs: SLOW_POLL_MS,
  });

  const active = (jobs.data?.jobs ?? []).filter((job) => isActive(job.state)).length;
  const queue = jobs.data?.queue ?? null;
  const withVerdicts = (bundles.data?.bundles ?? []).filter((b) => b.has_ai_report).length;
  const here = MENU.find((item) => item.screens.includes(route.screen)) ?? MENU[0]!;

  const badgeFor = (key: string): React.ReactNode => {
    if (key === "jobs" && active > 0) return <span className="badge">{active}</span>;
    if (key === "verdicts" && withVerdicts > 0) return <span className="badge quiet">{withVerdicts}</span>;
    return null;
  };

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <strong>Aegis</strong>
          <span className="muted">分析控制台</span>
        </div>

        {MENU.map((item) => {
          const Icon = item.icon;
          const on = item.screens.includes(route.screen);
          return (
            <button
              key={item.key}
              type="button"
              className={`nav-item${on ? " active" : ""}`}
              aria-current={on ? "page" : undefined}
              title={item.hint ?? item.label}
              onClick={() => navigate(item.to)}
            >
              <span className="ico">
                <Icon />
              </span>
              {item.label}
              {badgeFor(item.key)}
            </button>
          );
        })}

        <div className="sidebar-foot">
          <span>v0.1.0 · 本地环境</span>
          {/* 部署信息放在这里，不占顶栏：它回答的是"这个前端连着哪个网关"，不是每隔几秒
              要盯一眼的东西 —— 而连着错的网关曾经看起来就像"没有数据"。 */}
          <span className="muted" title={apiBase() || "同源"}>
            API {apiBaseLabel()}
          </span>
        </div>
      </aside>

      <div className="main">
        <header className="topbar">
          <h1>{here.label}</h1>
          <div className="status">
            {queue ? (
              <>
                <span title="网关是否正常应答工作进程的心跳">
                  <span className={`dot${queue.degraded ? " bad" : ""}`} />
                  {queue.degraded ? "队列降级" : "队列正常"}
                </span>
                <span title="等待被领取的任务">
                  排队 <b>{queue.queued}</b>
                </span>
                <span title="已投递但尚未确认的条目">
                  待确认 <b>{queue.pending}</b>
                </span>
                <span title="从未投递的条目">
                  积压 <b>{queue.lag ?? "—"}</b>
                </span>
                <span title="最近写入过心跳的 worker">
                  worker <b>{queue.workers_alive}</b>
                </span>
              </>
            ) : (
              <span className="muted">队列不可用</span>
            )}
          </div>
          <button
            type="button"
            className="theme-toggle"
            onClick={toggleTheme}
            title={theme === "dark" ? "切换到亮色主题" : "切换到暗色主题"}
            aria-label={theme === "dark" ? "切换到亮色主题" : "切换到暗色主题"}
          >
            <IconTheme size={16} />
          </button>
        </header>

        {jobs.error ? (
          <div style={{ padding: "0 20px" }}>
            <Banner>
              无法读取任务队列：{jobs.error.detail}
              {jobs.error.status === 503 ? " — 网关未配置 Redis，任务将同步执行。" : ""}
            </Banner>
            {jobs.error.status === 0 ? (
              <Banner kind="warn">
                在 API 有响应之前，本页面上的任何功能都无法工作。前端当前调用的地址是{" "}
                <code>{apiBaseLabel()}</code>；如果这是错误的网关，请设置{" "}
                <code>AEGIS_API_BASE</code>（容器）或 <code>VITE_API_BASE</code>（构建）。
              </Banner>
            ) : null}
          </div>
        ) : null}

        <main>
          {route.screen === "overview" ? (
            <OverviewScreen
              jobs={jobs.data?.jobs ?? []}
              queue={queue}
              bundles={bundles.data?.bundles ?? []}
              error={bundles.error}
              onOpenJob={(jobId) => navigate(`/job/${jobId}`)}
              onOpenBundle={(bundleId) => navigate(`/bundle/${bundleId}`)}
            />
          ) : null}

          {route.screen === "jobs" ? (
            <JobListScreen
              jobs={jobs.data?.jobs ?? []}
              loading={jobs.loading}
              onOpen={(jobId) => navigate(`/job/${jobId}`)}
              onSubmitted={jobs.reload}
            />
          ) : null}

          {route.screen === "job" ? (
            <JobDetailScreen
              jobId={route.jobId}
              onBack={() => navigate("/jobs")}
              onOpenBundle={(bundleId) => navigate(`/bundle/${bundleId}`)}
            />
          ) : null}

          {route.screen === "bundles" ? (
            <BundleListScreen
              bundles={bundles.data?.bundles ?? []}
              loading={bundles.loading}
              error={bundles.error}
              onOpen={(bundleId) => navigate(`/bundle/${bundleId}`)}
              onCompare={(bundleId) => navigate(`/compare/${bundleId}`)}
              onVerdicts={(bundleId) => navigate(`/verdicts/${bundleId}`)}
            />
          ) : null}

          {route.screen === "bundle" ? (
            <BundleDetailScreen
              bundleId={route.bundleId}
              onBack={() => navigate("/bundles")}
              onCompare={() => navigate(`/compare/${route.bundleId}`)}
              onVerdicts={(bundleId) => navigate(`/verdicts/${bundleId}`)}
            />
          ) : null}

          {route.screen === "compare" ? (
            <CompareScreen
              bundles={bundles.data?.bundles ?? []}
              initialLeft={route.bundleId}
              onBack={() => navigate("/bundles")}
            />
          ) : null}

          {route.screen === "verdicts" ? (
            <VerdictsScreen
              bundles={bundles.data?.bundles ?? []}
              jobs={jobs.data?.jobs ?? []}
              projects={projects.data?.projects ?? []}
              bundleId={route.bundleId}
              onOpenBundle={(bundleId) => navigate(`/bundle/${bundleId}`)}
            />
          ) : null}

          {route.screen === "projects" ? (
            <ProjectsScreen
              bundles={bundles.data?.bundles ?? []}
              jobs={jobs.data?.jobs ?? []}
              workspace={route.workspace}
              onOpenAudit={() => navigate("/audit")}
              onOpenVerdicts={() => navigate("/verdicts")}
              onOpenJob={(jobId) => navigate(`/job/${jobId}`)}
            />
          ) : null}

          {route.screen === "traffic" ? <TrafficScreen /> : null}

          {route.screen === "audit" ? (
            <AuditScreen
              jobId={route.jobId}
              jobs={jobs.data?.jobs ?? []}
              bundles={bundles.data?.bundles ?? []}
              projects={projects.data?.projects ?? []}
              workspace={route.workspace}
              onOpen={(jobId) => navigate(jobId ? `/audit/${jobId}` : "/audit")}
            />
          ) : null}

          {route.screen === "settings" ? <SettingsScreen /> : null}
        </main>
      </div>
    </div>
  );
}
