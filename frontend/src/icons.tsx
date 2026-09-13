/**
 * 菜单图标。
 *
 * 内联 SVG 而不是图标库或 emoji：库会为了 8 个图标拉进几十 KB，emoji 的显示完全由系统
 * 字体决定（同一份代码在 Windows、macOS、Linux 上是三种粗细和颜色）。这里每个图标都是
 * 一条 `currentColor` 描边路径，所以它跟着菜单项的配色走 —— 选中态变强调色，图标也变。
 */

interface IconProps {
  size?: number;
}

function Svg({ size = 16, children }: IconProps & { children: React.ReactNode }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.7"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {children}
    </svg>
  );
}

/** 总览：四宫格 */
export function IconOverview(props: IconProps) {
  return (
    <Svg {...props}>
      <rect x="3" y="3" width="7.5" height="7.5" rx="1.5" />
      <rect x="13.5" y="3" width="7.5" height="7.5" rx="1.5" />
      <rect x="3" y="13.5" width="7.5" height="7.5" rx="1.5" />
      <rect x="13.5" y="13.5" width="7.5" height="7.5" rx="1.5" />
    </Svg>
  );
}

/** 任务：队列里的条目 */
export function IconJobs(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3 6h18M3 12h18M3 18h11" />
    </Svg>
  );
}

/** 分析包：打包好的盒子 */
export function IconBundles(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M21 8.5 12 13 3 8.5l9-4.5 9 4.5Z" />
      <path d="M3 8.5v7L12 20l9-4.5v-7" />
      <path d="M12 13v7" />
    </Svg>
  );
}

/** 快速研判：一个"判定"的勾 */
export function IconVerdicts(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 3l2.2 5.2L20 9.4l-4.2 3.7 1.1 5.6L12 16l-4.9 2.7 1.1-5.6L4 9.4l5.8-1.2L12 3Z" />
    </Svg>
  );
}

/** 项目管理：文件夹 */
export function IconProjects(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3 7.5A1.5 1.5 0 0 1 4.5 6h4l2 2.5h6.5A1.5 1.5 0 0 1 18.5 10v7A1.5 1.5 0 0 1 17 18.5H4.5A1.5 1.5 0 0 1 3 17V7.5Z" />
    </Svg>
  );
}

/** 流量日志：脉冲 */
export function IconTraffic(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M3 12h4l2.5-6 4 12L16 12h5" />
    </Svg>
  );
}

/** 参数设置：滑杆（比齿轮更能表达"可调项"） */
export function IconSettings(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M4 8h10M18 8h2M4 16h4M12 16h8" />
      <circle cx="16" cy="8" r="2.2" />
      <circle cx="10" cy="16" r="2.2" />
    </Svg>
  );
}

/** 深度审计：盾牌 + 检查（自主评审，不是单条判定） */
export function IconAudit(props: IconProps) {
  return (
    <Svg {...props}>
      <path d="M12 3l7 3v6c0 4.2-2.9 7.6-7 9-4.1-1.4-7-4.8-7-9V6l7-3Z" />
      <path d="M8.8 12.2l2.2 2.2 4.2-4.4" />
    </Svg>
  );
}

/** 主题切换：半明半暗的圆 */
export function IconTheme(props: IconProps) {
  return (
    <Svg {...props}>
      <circle cx="12" cy="12" r="8.5" />
      <path d="M12 3.5v17a8.5 8.5 0 0 0 0-17Z" fill="currentColor" stroke="none" />
    </Svg>
  );
}
