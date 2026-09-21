/**
 * 错误体的读法，单独一个模块，因为**这是要测的规则**。
 *
 * `client.ts` 里放不下：那个文件 import 了 `config.ts`（要读 `window`），而 `node --test` 里没有
 * `window`。任何想被测试的纯逻辑都得住在不碰运行时的文件里 —— 和 `routes.ts`、`projects.ts`
 * 是同一个理由。
 */

export interface ApiError {
  status: number;
  detail: string;
  /**
   * 网关返回的原始错误体（能解析出来时）。
   *
   * 留着它是因为**有些错误是可恢复的，而恢复需要结构化字段**：提交一个失败/取消过的项目时，网关
   * 回 409 并在体里给出上一次尝试的 `job_id` 与 `state`，界面要靠它们才能给出「重新运行」。
   * 把错误压成一句话之后，那个出路就没了。
   */
  body?: unknown;
}

/** `{detail: "..."}` 里那句话，或者再往下钻一层。 */
export function messageFor(status: number, statusText: string, body: unknown): string {
  const text = detailText(body);
  return text ?? `${status} ${statusText}`;
}

/**
 * 从错误体里取出**给人看的那句话**，两层都认。
 *
 * 为什么要两层：网关有两种错误形状。
 *
 * * 简单错误是 `{"detail": "项目 X 已存在"}` —— `detail` 就是字符串；
 * * 需要**结构化信息**的错误（任务去重、取消终态）是
 *   `{"detail": {"detail": "previous attempt canceled…", "job_id": "J-…", "state": "canceled"}}`
 *   —— 多包一层是为了同时带上 `job_id` 与 `state`，让调用方不只读到一句话。
 *
 * 只认第一层字符串的时候，第二种会掉进 `${status} ${statusText}`，于是界面上**只剩一个"409"**，
 * 而那句"resubmit with ?force=true"以及上一次尝试的任务号全被丢掉。用户看到的就是一个没头没尾的
 * 状态码。
 */
export function detailText(body: unknown): string | null {
  if (typeof body !== "object" || body === null) return null;
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail === "string") return detail;
  if (typeof detail === "object" && detail !== null) {
    const nested = (detail as { detail?: unknown }).detail;
    if (typeof nested === "string") return nested;
  }
  return null;
}

/**
 * 这次 409 拒绝的是哪一次尝试 —— 有的话。
 *
 * 网关只在"上一次尝试是 failed / canceled"时回这个形状：同一份请求已经跑过并且没有结果，
 * 它不会自动重试，需要调用方明说 `?force=true`。界面拿到 `job_id` 才能把上一次尝试链出来，
 * 拿到 `state` 才能把话说准（"上次失败了"与"上次被取消了"不是同一件事）。
 *
 * 取不到就返回 null —— 那时这就是一个普通的错误，不该长出一个"重新运行"按钮。
 */
export function previousAttempt(error: ApiError): { jobId: string; state: string } | null {
  if (error.status !== 409) return null;
  const body = error.body;
  if (typeof body !== "object" || body === null) return null;
  const detail = (body as { detail?: unknown }).detail;
  if (typeof detail !== "object" || detail === null) return null;
  const { job_id: jobId, state } = detail as { job_id?: unknown; state?: unknown };
  if (typeof jobId !== "string" || jobId.length === 0) return null;
  if (typeof state !== "string" || state.length === 0) return null;
  return { jobId, state };
}
