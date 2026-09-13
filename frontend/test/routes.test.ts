/**
 * 路由解析的测试。
 *
 * 这个文件存在的原因是一个真实 bug：参数本身是**路径**时，先把整条 hash 解码再按 `/` 切分，
 * 会把一个参数切成多个 —— 项目的工作区 `/data/projects/x` 编码成 `%2Fdata%2Fprojects%2Fx`，
 * 解码后变成三段，路由读到 `data` 当工作区，于是对"页面上明明列着"的项目报"没有这个工作区"。
 *
 * 所以下面的用例里，凡是参数可能含 `/` 的，都必须带编码后的路径。
 */

import assert from "node:assert/strict";
import { test } from "node:test";

import { parseRoute, routeSegments } from "../src/routes.ts";

test("项目工作区是一条路径：编码后仍要完整还原", () => {
  const workspace = "/data/projects/my-repo";
  const route = parseRoute(`#/projects/${encodeURIComponent(workspace)}`);
  assert.deepEqual(route, { screen: "projects", workspace });
});

test("含反斜杠的 Windows 路径也要还原", () => {
  const workspace = "E:\\vib coding\\aegis\\demo\\repo";
  assert.deepEqual(parseRoute(`#/projects/${encodeURIComponent(workspace)}`), {
    screen: "projects",
    workspace,
  });
});

test("项目列表页的工作区是 null，不是空字符串", () => {
  assert.deepEqual(parseRoute("#/projects"), { screen: "projects", workspace: null });
  assert.deepEqual(parseRoute(""), { screen: "overview" });
});

test("普通 id 参数照常解析", () => {
  assert.deepEqual(parseRoute("#/job/J-abc"), { screen: "job", jobId: "J-abc" });
  assert.deepEqual(parseRoute("#/bundle/B-abc"), { screen: "bundle", bundleId: "B-abc" });
  assert.deepEqual(parseRoute("#/verdicts/B-abc"), { screen: "verdicts", bundleId: "B-abc" });
  assert.deepEqual(parseRoute("#/compare/B-abc"), { screen: "compare", bundleId: "B-abc" });
  assert.deepEqual(parseRoute("#/verdicts"), { screen: "verdicts", bundleId: null });
});

test("详情页少了 id 就退回列表页，而不是渲染一个没有主键的屏", () => {
  assert.deepEqual(parseRoute("#/job"), { screen: "jobs" });
  assert.deepEqual(parseRoute("#/bundle"), { screen: "bundles" });
});

test("固定页面不依赖于路径段", () => {
  assert.deepEqual(parseRoute("#/traffic"), { screen: "traffic" });
  assert.deepEqual(parseRoute("#/settings"), { screen: "settings" });
  assert.deepEqual(parseRoute("#/jobs"), { screen: "jobs" });
  assert.deepEqual(parseRoute("#/bundles"), { screen: "bundles" });
});

test("审计页有 id 看运行，没有 id 就是提交页", () => {
  // 和 `job`/`bundle` 不同：那两屏少了 id 会退回列表页，因为一个没有主键的详情屏没法渲染。
  // 审计没有 id 时是一个完整可用的屏（提交表单 + 最近运行列表），所以它保留为 `jobId: null`。
  assert.deepEqual(parseRoute("#/audit"), { screen: "audit", jobId: null });
  assert.deepEqual(parseRoute("#/audit/J-abc"), { screen: "audit", jobId: "J-abc" });
  assert.deepEqual(parseRoute("#/audit/"), { screen: "audit", jobId: null });
});

test("无法识别的路由落在总览，而不是空白页", () => {
  assert.deepEqual(parseRoute("#/nonsense"), { screen: "overview" });
  assert.deepEqual(parseRoute("#/"), { screen: "overview" });
});

test("畸形的转义序列不抛异常", () => {
  // `decodeURIComponent('%zz')` 会抛。一个手输的 URL 不该让整页白屏。
  assert.doesNotThrow(() => parseRoute("#/projects/%zz"));
  assert.deepEqual(routeSegments("#/projects/%zz"), ["projects", "%zz"]);
});
