/**
 * 主题解析的测试。
 *
 * 这块值得测，因为它的失败方式全都是"看起来能用"：跟随系统的那条在开发机上永远为真，
 * 而 index.html 里那份内联脚本与 `theme.ts` 的键名一旦不一致，症状是"刷新后主题跳回去"，
 * 没人会想到去比对两个文件里的字符串。
 */

import assert from "node:assert/strict";
import { afterEach, beforeEach, test } from "node:test";

import { readProjectFile } from "./support.ts";
import {
  applyTheme,
  resolveTheme,
  setStoredTheme,
  storedTheme,
  systemTheme,
  THEME_KEY,
  watchSystemTheme,
} from "../src/theme.ts";

/** 最小可用的 localStorage：够 theme.ts 用，不需要模拟 QuotaExceeded。 */
function fakeStorage(): Storage {
  const map = new Map<string, string>();
  return {
    get length() {
      return map.size;
    },
    clear: () => map.clear(),
    getItem: (key: string) => map.get(key) ?? null,
    key: (index: number) => [...map.keys()][index] ?? null,
    removeItem: (key: string) => void map.delete(key),
    setItem: (key: string, value: string) => void map.set(key, value),
  } as Storage;
}

let darkPreferred = false;
const listeners: Array<() => void> = [];

function stubGlobals(): void {
  Object.defineProperty(globalThis, "localStorage", {
    value: fakeStorage(),
    configurable: true,
    writable: true,
  });
  Object.defineProperty(globalThis, "matchMedia", {
    value: (query: string) => ({
      matches: query.includes("dark") ? darkPreferred : false,
      media: query,
      addEventListener: (_: string, cb: () => void) => void listeners.push(cb),
      removeEventListener: (_: string, cb: () => void) => {
        const index = listeners.indexOf(cb);
        if (index >= 0) listeners.splice(index, 1);
      },
    }),
    configurable: true,
    writable: true,
  });
  Object.defineProperty(globalThis, "document", {
    value: {
      documentElement: {
        attrs: {} as Record<string, string>,
        setAttribute(this: { attrs: Record<string, string> }, key: string, value: string) {
          this.attrs[key] = value;
        },
      },
    },
    configurable: true,
    writable: true,
  });
}

beforeEach(() => {
  darkPreferred = false;
  listeners.length = 0;
  stubGlobals();
});

afterEach(() => {
  for (const key of ["localStorage", "matchMedia", "document"]) {
    Reflect.deleteProperty(globalThis, key);
  }
});

test("没存过偏好时返回 null，包括存了非法值", () => {
  assert.equal(storedTheme(), null);
  globalThis.localStorage.setItem(THEME_KEY, "chartreuse");
  assert.equal(storedTheme(), null, "非法值必须当成没选过，而不是原样返回");
});

test("存取偏好是往返的", () => {
  setStoredTheme("dark");
  assert.equal(storedTheme(), "dark");
  setStoredTheme("light");
  assert.equal(storedTheme(), "light");
  setStoredTheme(null);
  assert.equal(storedTheme(), null);
});

test("没有手动选择时跟随系统", () => {
  darkPreferred = true;
  assert.equal(systemTheme(), "dark");
  assert.equal(resolveTheme(), "dark");

  darkPreferred = false;
  assert.equal(systemTheme(), "light");
  assert.equal(resolveTheme(), "light");
});

test("手动选择压过系统设置", () => {
  darkPreferred = true;
  setStoredTheme("light");
  assert.equal(resolveTheme(), "light", "系统是暗、用户选了亮，就该是亮");

  darkPreferred = false;
  setStoredTheme("dark");
  assert.equal(resolveTheme(), "dark");
});

test("系统主题变化只影响没有手动选择的用户", () => {
  const seen: string[] = [];
  const stop = watchSystemTheme((theme) => seen.push(theme));

  darkPreferred = true;
  for (const notify of [...listeners]) notify();
  assert.deepEqual(seen, ["dark"], "没选过的用户应该跟着系统走");

  setStoredTheme("light");
  darkPreferred = false;
  for (const notify of [...listeners]) notify();
  assert.deepEqual(seen, ["dark"], "选了亮的用户不该被系统变动推走");

  stop();
  assert.equal(listeners.length, 0, "取消订阅必须真的摘掉监听");
});

test("applyTheme 把主题写到 <html data-theme> 上", () => {
  applyTheme("dark");
  const element = (globalThis.document as unknown as { documentElement: { attrs: Record<string, string> } })
    .documentElement;
  assert.equal(element.attrs["data-theme"], "dark");
  applyTheme("light");
  assert.equal(element.attrs["data-theme"], "light");
});

test("index.html 里的内联脚本与 theme.ts 用同一个键名", () => {
  // 这份重复是必要的（内联脚本要赶在 bundle 之前跑，没法 import），所以只能靠测试盯住。
  const html = readProjectFile("index.html");
  assert.ok(
    html.includes(`"${THEME_KEY}"`),
    `index.html 里必须出现 ${THEME_KEY}；改了键名要同时改 index.html 与 src/theme.ts`,
  );
  assert.ok(
    html.includes("prefers-color-scheme: dark"),
    "index.html 必须自己解析系统主题，否则首屏会闪一下默认主题",
  );
  assert.ok(
    html.includes("data-theme"),
    "index.html 必须把解析结果写到 data-theme 上，CSS 只认这个属性",
  );
});
