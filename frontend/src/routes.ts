/**
 * The hash router, on its own so it can be tested.
 *
 * It lives outside `components.tsx` for one reason: that file contains JSX, and the test runner
 * strips types without transforming JSX, so anything defined there is unreachable from a test.
 * Routing is exactly the kind of pure logic worth pinning -- see the comment in `parseRoute`
 * for the bug that made this file exist.
 */

export type Route =
  | { screen: "overview" }
  | { screen: "jobs" }
  | { screen: "job"; jobId: string }
  | { screen: "bundles" }
  | { screen: "bundle"; bundleId: string }
  | { screen: "compare"; bundleId: string | null }
  | { screen: "verdicts"; bundleId: string | null }
  | { screen: "projects"; workspace: string | null }
  | { screen: "audit"; jobId: string | null; workspace: string | null }
  | { screen: "traffic" }
  | { screen: "settings" };

/** Split the hash into decoded segments, or the best effort at it. */
export function routeSegments(hash: string): string[] {
  // Split first, then decode each segment -- not the other way round.
  //
  // Decoding the whole path first and splitting afterwards destroys any parameter that *is*
  // itself a path: a project's workspace is `/data/projects/x`, which a link encodes to
  // `%2Fdata%2Fprojects%2Fx`, and decoding before splitting turned that one segment into three
  // (`data`, `projects`, `x`). The route then read `data` as the workspace, found no such
  // project, and told the reader that the project did not exist -- for a project that was
  // plainly listed on the page they had just clicked.
  return hash
    .replace(/^#\/?/, "")
    .split("/")
    .filter(Boolean)
    .map((segment) => {
      try {
        return decodeURIComponent(segment);
      } catch {
        // A malformed escape (`%zz`) is not worth a blank screen; the raw text is what the
        // reader will recognise anyway.
        return segment;
      }
    });
}

export function parseRoute(hash: string): Route {
  const parts = routeSegments(hash);
  switch (parts[0]) {
    case "jobs":
      return { screen: "jobs" };
    case "job":
      return parts[1] ? { screen: "job", jobId: parts[1] } : { screen: "jobs" };
    case "bundles":
      return { screen: "bundles" };
    case "bundle":
      return parts[1] ? { screen: "bundle", bundleId: parts[1] } : { screen: "bundles" };
    case "compare":
      return { screen: "compare", bundleId: parts[1] ?? null };
    case "verdicts":
      return { screen: "verdicts", bundleId: parts[1] ?? null };
    case "projects":
      return { screen: "projects", workspace: parts[1] ?? null };
    // `#/audit` without an id is the submit screen: the list of audits and the form are the same
    // screen, because a reader who has no run open is a reader about to start one.
    //
    // `#/audit/w/<workspace>` 是**预选项目**的提交页（从「项目管理」每行的按钮跳进来）。
    // 用 `w` 作前缀段而不是把 workspace 放进第二段：第二段历史上就是 job id，而一个 job id 与
    // 一个 workspace 路径在形状上无法区分 —— 靠 `J-` 前缀去猜，就是把两个概念绑在一个位置上，
    // 下次改 job id 的格式就会静默地把路径读成 id。
    case "audit":
      if (parts[1] === "w") return { screen: "audit", jobId: null, workspace: parts[2] ?? null };
      return { screen: "audit", jobId: parts[1] ?? null, workspace: null };
    case "traffic":
      return { screen: "traffic" };
    case "settings":
      return { screen: "settings" };
    default:
      return { screen: "overview" };
  }
}
