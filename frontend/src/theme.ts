/**
 * 主题：暗色 / 亮色，默认跟随系统。
 *
 * 真实值写在 `<html data-theme>` 上 —— CSS 只认这个属性，不认识"用户偏好"这件事（见
 * `styles.css` 顶部的说明）。首屏之前就把它设好的是 `index.html` 里一段内联脚本，
 * 因为等这个模块加载完再设，会先闪一下默认主题。
 *
 * 因此键名与"跟随系统"的判定规则在这里和 `index.html` 里各有一份。那是**故意的重复**：
 * 内联脚本必须自包含才来得及，它不可能 import 这个文件。改键名要同时改两处，
 * `test/theme.test.ts` 会盯住这一点。
 */

export type Theme = "dark" | "light";

/** localStorage 的键。`index.html` 里那份内联脚本用的是同一个字面量。 */
export const THEME_KEY = "aegis-theme";

const THEMES: Theme[] = ["dark", "light"];

function isTheme(value: unknown): value is Theme {
  return typeof value === "string" && (THEMES as string[]).includes(value);
}

/** 用户上次手动选择，没选过则是 null。读取失败（隐私模式）也当成没选过。 */
export function storedTheme(): Theme | null {
  try {
    const value = globalThis.localStorage?.getItem(THEME_KEY);
    return isTheme(value) ? value : null;
  } catch {
    return null;
  }
}

export function setStoredTheme(theme: Theme | null): void {
  try {
    if (theme === null) globalThis.localStorage?.removeItem(THEME_KEY);
    else globalThis.localStorage?.setItem(THEME_KEY, theme);
  } catch {
    // 存不下就算了：这次会话仍然按选择显示，只是下次打开回到跟随系统。
  }
}

export function systemTheme(): Theme {
  const query = globalThis.matchMedia?.("(prefers-color-scheme: dark)");
  return query?.matches ? "dark" : "light";
}

/** 按"手动选择优先，否则跟随系统"解析出当前该用的主题。 */
export function resolveTheme(): Theme {
  return storedTheme() ?? systemTheme();
}

/** 写到 `<html>` 上，CSS 从这里取值。 */
export function applyTheme(theme: Theme): void {
  globalThis.document?.documentElement.setAttribute("data-theme", theme);
}

/**
 * 订阅系统主题变化，返回取消订阅的函数。
 *
 * 只在用户**没有**手动选择时才需要响应 —— 有手动选择时系统怎么变都不该动。
 * `addEventListener` 与已废弃的 `addListener` 都试一遍：后者是为了兼容旧 Chromium，
 * 缺了它表现为"系统切了主题但页面不动"，且不会报错。
 */
export function watchSystemTheme(onChange: (theme: Theme) => void): () => void {
  const query = globalThis.matchMedia?.("(prefers-color-scheme: dark)");
  if (!query) return () => {};

  const listener = () => {
    if (storedTheme() === null) onChange(systemTheme());
  };

  if (typeof query.addEventListener === "function") {
    query.addEventListener("change", listener);
    return () => query.removeEventListener("change", listener);
  }
  // 老 API：没有 addEventListener 的 MediaQueryList。
  const legacy = query as MediaQueryList & {
    addListener?: (cb: () => void) => void;
    removeListener?: (cb: () => void) => void;
  };
  legacy.addListener?.(listener);
  return () => legacy.removeListener?.(listener);
}
