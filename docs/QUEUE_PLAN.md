# 异步任务队列实施方案（可评审）

> ## ⚠️ 实施状态（2026-09-11 更新：**步骤 0–6 全部完成**）
>
> | 步骤 | 状态 | 证据 |
> |---|---|---|
> | 0 迁移 `app/` → `services/extraction/` | ✅ | `services -> app` 边数 0（AST 断言）；`aegis_contracts/views.py` |
> | 1 契约与指纹 | ✅ | `aegis_contracts/jobs.py`、`tests/test_jobs_contract.py` |
> | 2 配置 + Redis 状态层 | ✅ | `services/queue/{keys,jobs,streams}.py`、`tests/test_queue_{store,streams}.py` |
> | 3 pipeline 钩子 + 真取消资源层 | ✅ | `aegis_core/cancel.py`、`observer/abort/teardown`、扫描 `Popen` + `scan_aborted`、staging 写入 |
> | 4 worker + reaper + 启动自检 | ✅ | `services/queue/{worker,reaper,cancel}.py`、`tests/test_queue_worker.py` |
> | 5 `202`/`GET /v1/jobs` + 幂等边界 | ✅ | `app/api/jobs.py`、`tests/test_jobs_api.py`、`tests/test_queue_end_to_end.py` |
> | 6 compose（`redis`/`worker`）+ 端口策略断言 | ✅ | `docker/docker-compose.yml`、`tests/test_compose_policy.py` |
>
> **基线：`309 collected`**。没有 Redis：`297 passed, 12 skipped`；
> 起一个 Redis（`docker run --rm -d -p 127.0.0.1:6379:6379 redis:7-alpine`）：**307 passed, 2 skipped**。
> 本文所有 `124 passed` 的说法都是**迁移前的历史基线**，判据仍有效（"迁移/改造本身不改行为"）。
>
> **另有一条实测覆盖了本文的旧承诺**：§6.5.3 曾写「取消本端 ≤2s、对端继续跑完」，
> 而第一版实现实测是 **131 秒**（`httpx.post` 是阻塞调用，worker 在整段扫描里回不到主循环）。
> 后来改成**可轮询的扫描作业**（`POST /v1/scan/jobs` → 202 + `GET` 轮询 + `DELETE` 取消，
> `services/scan/jobs.py`），实测 **0.85 秒**且**对端进程真的死了**（0 残留、CPU 0.12%）。
> 所以 §6.5.3 那段关于"2 秒"的描述读作**已经过时的设计意图**；现状见 HANDOVER §10.18。
>
> 实施中与本文不同的决定，都是实读代码/实测之后的修正，已写进对应实现：
> 1. **`CanceledAbort` 与 `TeardownHandle` 定义在 `aegis_core/cancel.py`**，不是
>    `services/queue/cancel.py`——否则 pipeline 要 import 队列包，违反 §5.5。
>    `services/queue/cancel.py` 放的是 `Teardown`（协议的具体实现，worker 用它）。
> 2. **`_looks_killed()` 只认 `-15/-9/-1`**：opengrep 遇到不认识的参数会 `rc=2`，
>    把它标成 `scan_aborted` 会把"配置错了"伪装成"有人取消了"。
> 3. **`READ` 阶段的 `inlined` 用 `len(c.bodies)`**（`AssembledContext` 没有 `.methods`）。
> 4. **cjson 的空容器是双向丢失的，且两个 Redis 实现方向相反**（fakeredis `{}`→`[]`，
>    真服务器 `[]`→`{}`）。所以归一化必须同时知道哪些字段是 list、哪些是 dict；
>    这条只有跑真 Redis 才会发现，见 `tests/test_queue_real_redis.py`。
> 5. **worker 没有 health 端点**（§5.9 曾计划 `expose: 8104` + HTTP 健康检查）。
>    实现改为 `python -m services.queue.healthcheck`：探针检查「Redis 可达 + 心跳新鲜」，
>    这正是 reaper 用来区分"慢"与"死"的信号。一个只为了探针而开的端口不值得开。
> 6. **`/v1/assemble` 的异步入口是 `POST /v1/jobs`**，而不是给 `/v1/assemble` 加分支后
>    返回两种形状。同步路径因此**逐字段不变**（有守门测试）。

> **步骤 0（物理迁移）已经落地**，也就是说本文以下内容里凡是写着
> `app/pipeline/…`、`app/assembler/…`、`app/lsp/…`、`app/observability/…` 的路径，
> 都已经变成 `services/extraction/<同名>/…`，`observability/views.py` 则进一步下沉到了
> `aegis_contracts/views.py`。阅读时请做一次心智替换。
>
> 另外两处与现状不符，其余内容仍然有效：
> * `probe_lsp` 最终落在 `services/extraction/lsp/probe.py`（不是 §5.14 写的
>   `services/extraction/probe.py`）；
> * `resolve_workspace` 的**策略**下沉到了 `aegis_core/workspace.py`（§5.14 未预料到这一层，
>   因为原方案以为 extraction 可以继续 import `app.api.deps`）。

> 适用仓库状态：**本文开写时**工作树实测 `124 passed, 2 skipped`（`python -m pytest -q -rs`）。
> 本文开写时的基线是 `117 passed, 2 skipped`，
> 差的 7 个用例来自工作树里并行进行的夹具/prompt 前缀工作（见 §0 事实 (4)）。
> `docs/HANDOVER.md` §11.1「待决策 A：任务队列选型」尚未落地。
> 本文是**方案**，不是实现记录；所有行号对应当前工作树的真实文件。
> 术语：**漏斗 9 步** 指 `docs/ARCHITECTURE.md` §9「The funnel contract」的计数序列
> （`discovered → located → focus_methods → contexts → slices → proposed → kept → read → inlined`）；
> **流水线阶段** 指 `services/extraction/pipeline/assemble.py::AssemblyPipeline.run()` 里的计时分段（`stats.stage_ms`）。
> **引用约定**：光秃秃的 `§5.4` 指向**本文**的小节；
> 带文档名前缀的（`HANDOVER §10.2`、`HANDOVER §10.6`、`HANDOVER §10.11`、`HANDOVER §11.1`、
> `HANDOVER §11.4`、`ARCHITECTURE §5`、`ARCHITECTURE §6`、`ARCHITECTURE §7`、`ARCHITECTURE §9`）
> 指向那篇文档。裸行号（如「L124」「`assemble.py:124`」）一律指当前工作树的真实文件。

## 0. 三处需要先知道的既成事实

**(1) 那两个 skip 是什么。** `python -m pytest -q -rs` 显示两者都是
`tests/test_scanner_command.py:86: {opengrep,semgrep} not installed` ——
即「用真实二进制校验我们拼出来的 argv」的两个参数化用例，本机没装 opengrep/semgrep 才跳过。
与队列无关，但**本文 §6.5.4 要改 `OpengrepRunner.scan()`**，而这条路径的回归测试在本地永远不跑：
改完之后要么在 CI 上跑，要么本机装一个二进制，否则「argv 组装 + 子进程终止」两块只能靠单测的假进程覆盖。

**(2) `demo/` 目录在跑过 `scripts/demo.py` 之前不存在。** `.gitignore:17` 整条忽略 `demo/`，
而 `demo/repo/` 是 `scripts/demo.py:50` 调 `tests/fixtures.py::write_fixture()` **生成**的。
于是 `docker compose up` 会把 `${AEGIS_SCAN_TARGET:-../demo/repo}` 挂成一个不存在的目录，
**静默扫出 0 命中**（没有任何报错，bundle 是空的）。这是 §9 步骤 6/7 要修的问题（决策 3）。

**(3) `.env.example` 的新增项是空占位符。** 工作树里 `.env.example` 末尾有未提交的
`API_URL=` / `API_KEY=`（**两个都是空值**）、`MODEL=glm-5.3-flash` 与两条注释
（`git diff -- .env.example` 可复核）。**真实密钥只在被 `.gitignore:18` 忽略的 `.env` 里，
不要把它写进 `.env.example`，也不要在文档或 issue 里贴出来。** 本方案 §5.7 会往同一个文件追加队列段落，
追加时请保持这个约定。

**(4) 工作树在本文写作期间已经前进。** 引用行号时工作树里已有 10 个文件被改动
（`README.md`、`aegis_contracts/domain.py`、`app/assembler/package.py`、`app/assembler/render.py`、
`tests/fixtures.py`、`pyproject.toml`、`.gitignore`、`.env.example`、`docs/ARCHITECTURE.md`、
`docs/HANDOVER.md`），另新增了 `demo/`、`tests/test_demo_fixture.py`、`tests/test_prompt_prefix.py`。
**其中 `app/pipeline/assemble.py` 与 `services/scan/opengrep.py` 未被改动**，
所以本文对这两个文件的行号引用（§5.5 的插入点表、§6.5.4 的两个改造点）**仍然逐条有效**。
**但开工前请重跑一次行号核对**（§5.5 给了核对方法：把 `stats.stage_ms[...]` 的赋值行打出来比对）。
另外注意 `app/assembler/package.py` **已经被改过**（+45 行），
§5.5 里 `BundlePackager.write()` 的 patch 需要以改动后的版本为基线重新对一遍。

---

## 1. 决策摘要

### 1.1 做什么

| # | 决策 | 一句话理由 |
|---|---|---|
| 1 | 队列技术：**Redis 7 + 自研轻量 worker**，Redis Streams（`XADD` + consumer group + `XACK`） | 只有一个生产者、一类任务；Celery 的抽象面积（broker / result backend / serializer / beat）远大于需求，而且会把「阶段级进度」塞进自定义 `Task.update_state` 里 |
| 2 | 新增 `aegis_contracts/jobs.py`：Job 契约（纯 pydantic，无 I/O） | 契约要被 gateway 与 worker 同时 import；`tests/test_contracts.py:40` 已经禁止 `aegis_contracts` 碰 `app`/`services`，所以契约只能长在这一层 |
| 3 | **阶段的权威源是 Redis 里的 job 记录**（String + JSON），pub/sub 只做加速 | 轮询与推送读同一份数据，否则前端会看到两个互相矛盾的进度 |
| 4 | 进度带**阶段名 + 每阶段计时**，阶段词汇与漏斗 9 步对齐（§3 给映射与理由） | 用户拍板；且漏斗 9 步与执行阶段**不是一一对应**，必须显式定义映射而不是硬套 |
| 5 | worker **进程内**执行：复用 `run_scan_anywhere()` 与 `AssemblyPipeline.run()`；**`worker` 容器不设 `AEGIS_EXTRACTION_SERVICE_URL`** | 只有进程内执行才同时拿得到阶段进度与可中断句柄（§5.4.1 给了三条互相独立的推翻理由） |
| 6 | 落盘产物不变：仍写 `var/packages/<bundle_id>/`；Redis 只存活状态 | bundle 契约是已验收的资产（`docs/SERVICE_TOPOLOGY.md`「What does not change」） |
| 7 | 幂等：`request_fingerprint = sha1(workspace, sarif_path\|rule_config, budget, rules)`，重复提交返回已在排队/运行的那个 `job_id` | 与 `bundle_id` 内容派生同源；同一输入永远同一 job、同一 bundle |
| 8 | 取消：**真取消**。worker 持有 `TeardownHandle`（扫描子进程句柄 + 语言服务器管理器 + staging 目录），用「阻塞等待里 50ms 轮询 + terminate→kill 升级」打断进行中的扫描与 LSP 调用。**扫描可中断是它的硬前提**：`OpengrepRunner.scan()` 必须从 `subprocess.run` 改成 `Popen`（§6.5.4b）——否则占比最长的扫描阶段根本无句柄可注册 | 用户拍板；进程内执行（决策 5）是它的前提，扫描改造是它的前置条件 |
| 9 | **先迁移 `app/` → `services/extraction/`，再落地队列**（决策 4） | 用户拍板。迁移是纯目录整理，一次做完之后队列才能长在最终位置上；顺序与 `HANDOVER §11.4` 的"先迁移更省事"一致（§5.14） |
| 10 | 保持既有同步入口可用（`AEGIS_QUEUE__REDIS_URL` 未设置时完全走老路径） | 现有 124 个用例、`scripts/demo.py`、`app/cli.py` 都不需要 Redis 就能继续跑 |

### 1.2 不做什么（本轮）

* **不做 SSE / WebSocket 推送**：pub/sub 通道会建、会写，但本轮前端轮询（§8）。
* **不做 AI fan-out**：`JobSubmission.children` 与 `JobProgress.fanout` 先留好字段，将来不用改契约（§2.6）。
* **不做跨机扩展**：共享卷约束照旧（`/workspace`、`/data/packages`、`/data/work` 路径必须一致）。
* **不做 job 结果的 manifest 内嵌**：Redis 里只存 `bundle_id` + `package_path` 引用（§2.5）。
* **不做定时清理守护进程**：靠 Redis TTL（§4.6）。
* **不改 `/v1/assemble/upload` 的同步语义**（§5.2 留 TODO），**不改 `/v1/scan` 的响应契约**（新增异步端点，§5.3）。
* **不做「取消即零延迟」的强承诺**：`terminate()→kill()` 的窗口最长 `cancel_terminate_grace_s`（默认 1s），
  另有 2s 的 abort 轮询缓存（§6.5.6），且**两段同步代码不可中断**（§3.4）。
* **迁移只搬目录、不改行为**（决策 4）：步骤 0 是 `git mv` + 导入重写 + 构建配置同步。
  硬边界：**不拆服务、不动 `services/scan/`、不动 gateway 的路由集合、不动
  `aegis_contracts/domain.py`**。唯一"动内容"的地方是把 `observability/views.py`
  下沉到 `aegis_contracts/views.py`——理由是它**已经只依赖 `aegis_contracts.domain`**
  （实读 `app/observability/views.py:22-33`），搬运后逐字节不变，见 §5.14。
  注意 `tests/test_contracts.py` 里那条用**文本方式**盯着 `app/api/routes.py` 的用例
  （`test_no_module_reads_static_assets_through_the_api_anymore`）要同步换路径。
* **不把 `AEGIS_SCAN_SERVICE_URL` 之外的东西委托出去**：扫描器继续远程、提取继续进程内（§5.4.1）。
* **不做进程树级终止**：只终止 Aegis 直接 spawn 的子进程，**不保证清掉语言服务器派生的孙进程**
  （Windows 上 `pyright-langserver` 会派 `node`）。理由与折中见 §6.5.4 与 §6.5.7。
* **不做「取消对端容器的远程扫描」**：worker 委托 `http://scan:8101` 时打断不了对端（§6.5.3）。

### 1.3 一屏数据流

```
POST /v1/assemble ──► gateway: resolve_workspace() 校验（400 留在这一层）
                        ├─ fingerprint = sha1(...)          ← 幂等键
                        ├─ SET aegis:job:{id} NX (queued)   ← 权威状态首次写入
                        └─ XADD aegis:q:jobs * job_id=… kind=assemble attempt=1
                        ◄─ 202 {job_id, state, deduplicated}

worker（consumer group aegis-workers）—— 与 extract 共用镜像，但**进程内**执行
   XREADGROUP BLOCK 1000 COUNT 1 ──► job_id
   queued → running；每个阶段边界写 progress + XADD aegis:events:{id}
   写一次 stage=scan 快照（扫描阶段"开始即静默"，见 §3.4）
   构造 TeardownHandle（扫描子进程槽 + LanguageServerManager + staging 目录）
   AssemblyPipeline.run(observer=…, abort=…, teardown=…)
        ├─ run_scan_anywhere() ──HTTP──► aegis-scan:8101   （扫描器仍是独立小镜像）
        └─ LSP 语言服务器：**由 worker 自己 spawn、自己杀**
   staging 目录 → os.replace 改名 → var/packages/<bundle_id>/
   写 succeeded + result{bundle_id, package_path} → XACK

取消路径（POST /v1/jobs/{id}/cancel）
   gateway: CAS 写 cancel_requested=True ──► state 仍是 running（不新造 state）
   worker:  abort() 变真 → 阻塞等待 ≤50ms 内抛 CanceledAbort
            → terminate/kill 扫描子进程与 LSP 进程 → 删 staging 目录 → 写 canceled

GET /v1/jobs/{id} ──► GET aegis:job:{id} ──► 完整 Job（与推送同一份数据）
```

---

## 2. Job 契约（字段级）

新增文件：**`aegis_contracts/jobs.py`**。约束（由
`tests/test_contracts.py::test_contracts_forbid_io_and_web_frameworks` 强制，
该用例的 `banned` 集合已经包含 `redis`）：只允许 `pydantic` + 标准库
（`datetime` / `enum` / `hashlib` / `json` / `pathlib` / `typing`）。
**不 import `app`、不 import `services`、不 import `redis`、不 import `httpx`。**

### 2.1 枚举

```python
class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"

TERMINAL_STATES = frozenset({JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELED})


class JobStage(str, Enum):
    """执行阶段。顺序即生命周期顺序；DONE 是终态标记，不参与计时。"""
    SCAN = "scan"            # 静态扫描（或读入给定 SARIF）
    SETUP = "setup"          # 工作区 + 语言服务器装配
    LOCATE = "locate"        # 命中点 → 所属方法
    EXPAND = "expand"        # 双向走调用图
    READ = "read"            # 读取完整方法体
    ASSEMBLE = "assemble"    # 去重 + 聚合上下文 + 渲染
    PACKAGE = "package"      # 落盘 + manifest.json
    DONE = "done"            # 伪阶段


class JobKind(str, Enum):
    ASSEMBLE = "assemble"
    SCAN = "scan"
    AI_FANOUT = "ai_fanout"  # 本轮不产生，契约先接受（§2.6）


class FailureMode(str, Enum):
    """具名失败。硬规则（HANDOVER §10.2）：绝不静默留在 running。

    注意这里没有 `canceled_by_request`：**取消不是失败**。
    `state=canceled` 的 job 的 `failure` 恒为 None。把「用户要的」和「系统坏的」
    塞进同一个枚举，会逼前端再用 state 判一次，而 state 已经是权威答案。
    """
    WORKSPACE_MISSING = "workspace_missing"
    SARIF_MISSING = "sarif_missing"
    SARIF_UNREADABLE = "sarif_unreadable"
    SCAN_FAILED = "scan_failed"
    SCAN_ABORTED = "scan_aborted"          # 扫描子进程被终止（**两个落点，见下**）
    EXTRACTION_UNAVAILABLE = "extraction_unavailable"
    PIPELINE_EXCEPTION = "pipeline_exception"
    WORKER_LOST = "worker_lost"            # reaper 判定：认领后心跳超时
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"
    INTERNAL_ERROR = "internal_error"
```

**`SCAN_ABORTED` 的落点：两个地方都写，但含义不同**（用户已拍板，这是刻意的）：

| 落点 | 值 | 什么时候写 | 语义 |
|---|---|---|---|
| `ScanRecord.failure_mode`（进 `manifest.json` / `summary.md`） | `"scan_aborted"` | 扫描子进程被终止（`rc` 是 `-15`/`-9`（POSIX）或 `1`/`-1`（Windows 强杀）这类"非扫描器自身失败"的码） | **台账诚实**：这份 bundle 之所以是空的，是因为扫描**被中断**，不是因为它崩了 |
| `JobFailure.mode`（进 Redis 里的 job 记录） | `SCAN_ABORTED` | **只在"被终止但不是用户取消"时**（`aborted()` 为 False） | 系统性的中断 = 失败 |

**为什么不是"都只写一个地方"**：两个落点的**可见性条件不同**，必须都写。

* **用户取消时，job 终态是 `state=canceled` + `failure=None`**（§2.4）——
  用户点了取消不该看到一条红色失败。所以"被终止"这件事只能落在**台账**里。
* **但台账只在 bundle 落盘时才存在**：`ScanRecord` 是在 `BundlePackager.write()`
  （`assemble.py:293`）那一刻写进 `manifest.json` 的；如果扫描阶段就被取消，
  pipeline 根本走不到 package 阶段，**磁盘上不会有任何 bundle**，
  也就"没有台账可写"。这是上一版方案的漏洞：它假设台账总是存在的。
* **所以补一条硬要求**：`_collect_findings()` 在把 `CanceledAbort` 往上抛之前，
  **必须把那一份 `ScanOutcome.scan_record` 挂到 `CanceledAbort` 上**
  （`CanceledAbort.scan_record: ScanRecord | None`），由 worker 写进
  `JobFailure.scan_record` / `JobResult.scan_record`（§2.4 新增字段）。
  **这是"取消也留痕"的唯一落点**，因为那一刻没有别的持久化目标。
  同时，若取消发生在扫描**之后**（bundle 已落盘），`manifest.json` 里那份
  `ScanRecord.failure_mode` 就自然是 `"scan_aborted"`——**两条路都留痕**。

**完整映射（四条，别合并）**：

```
子进程 rc 异常 + teardown.aborted() == True
      → run_scan() 返回 ScanOutcome(failure_mode="scan_aborted")，**不抛**
      → _collect_findings() 把它挂到 CanceledAbort 上再抛
      → job: state=canceled, failure=None（若需要细节则 JobResult.scan_record 里有台账）
      → 若 pipeline 已走到 package：manifest.json 的 ScanRecord.failure_mode == "scan_aborted"

子进程 rc 异常 + teardown.aborted() == False（OOM killer、运维手动 kill）
      → run_scan() 返回具名 ScanOutcome(failure_mode="scan_aborted")
      → job: state=failed, JobFailure.mode=SCAN_ABORTED

扫描器自己失败（rc not in (0,1)、SARIF 缺失/为空/不可解析）
      → 既有四种模式完全不变（scan_failed 等），run_scan() 永不抛（HANDOVER §10.2/§10.3）
```

**`SCAN_ABORTED` 与「取消」为什么必须分开**：真取消会把扫描子进程杀掉，
而 `OpengrepRunner.scan()` 对「子进程非正常结束」的处理与「扫描器自己失败」共用一段代码。
如果不在那里区分「是我们杀的」和「它自己崩的」，一次**用户取消**会显示成 `failed(scan_failed)`——
用户点了取消却看到一条红色失败，这是真取消最容易引入的错误。
判据是 `TeardownHandle.aborted()`：谁置位谁负责（§6.5.2）。

### 2.2 `JobTiming` / `JobStageProgress` / `JobProgress`

```python
class JobTiming(BaseModel):
    submitted_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    queue_wait_ms: int = 0        # started_at - submitted_at
    duration_ms: int = 0          # finished_at - started_at（终态才有意义）


class JobStageProgress(BaseModel):
    stage: JobStage
    state: str                    # "pending" | "running" | "done" | "skipped" | "failed"
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None   # 只在该阶段结束时由 perf_counter 差值写入
    note: str | None = None          # 降级/事实说明，例如 "scan_transport=remote"
    counters: dict[str, int] = {}    # 该阶段结束了哪些漏斗步骤（§3）


class JobProgress(BaseModel):
    stage: JobStage = JobStage.SCAN   # 当前阶段（终态时是最后完成的阶段）
    stages: list[JobStageProgress] = []   # 7 项，按 JobStage 顺序，始终齐全
    counters: dict[str, int] = {}     # 全 job 累计的漏斗计数（就地覆盖，不重复计）
    units_done: int = 0               # 天然并发的阶段用：已完成单元数
    units_total: int = 0              # 0 表示"总量未知"
    unit_label: str = ""              # "slices" | "bodies" | "scan"（不确定进度）
    worker_id: str | None = None
    attempt: int = 1
    stage_started_at: datetime | None = None     # 心跳刷新（reaper 判活用）
    worker_heartbeat_at: datetime | None = None  # 心跳刷新（每 heartbeat_interval_s）
```

**计时语义（必须与实现一致）**：

* `duration_ms` 只在阶段**真正结束**时写；数值由 worker 侧 `time.perf_counter()` 差值得出，
  与 `RunStats.stage_ms` 的算法相同（`app/pipeline/assemble.py:606 _ms()` 同款）。
* `stage_started_at` / `worker_heartbeat_at` **频繁刷新**，因此它们**不是计时**，只是活性证据。
  前端不得把它们当作阶段耗时。
* 心跳只更新这两个字段（+ `EXPIRE`），**不重写整个 job JSON**：
  心跳每 15 秒一次，为了它把几十 KB 的 JSON 反复序列化是纯粹的浪费。
  实现上心跳走 §4.5 的同一个 Lua 脚本（读-改-写），只是不改 `revision`。

### 2.3 `JobRequest` / `JobSubmission`

```python
class JobRequest(BaseModel):
    """提交内容。字段是 AssembleRequest 的镜像，但不 import app.schemas（契约不许向上依赖）。"""
    workspace: str
    sarif_path: str | None = None
    rules: list[str] = []
    rule_config: str | None = None
    include_globs: list[str] = []
    exclude_globs: list[str] = []
    budget: dict[str, Any] | None = None   # BudgetConfig.model_dump()，见下
    max_findings: int | None = None
    lsp: bool = True
    package_name: str | None = None


class JobSubmission(BaseModel):
    schema_version: str = "1.0"
    job_id: str
    kind: JobKind = JobKind.ASSEMBLE
    request: JobRequest
    fingerprint: str                 # sha1，40 hex
    submitted_at: datetime
    submitted_by: str = "gateway"    # 将来多入口（CLI / web）可区分
    children: list[JobChild] = []    # §2.6
```

**为什么 `budget` 是 `dict` 而不是 `BudgetConfig`**：`BudgetConfig` 住在 `aegis_core`，
`tests/test_contracts.py` 只禁止 `aegis_core → aegis_contracts` 这个方向，反向没禁；
但把 `BudgetConfig` 放进契约会让「契约的输入形状」随 `aegis_core` 漂移。
用 `dict` + worker 侧 `BudgetConfig(**request.budget)` 还原——`app/api/routes.py:226-233`
已经是这个写法，直接沿用同一风格。**这是对既定约束的一处细化，不是反建议。**

### 2.4 `Job`（`GET /v1/jobs/{id}` 的响应体）

```python
class JobResult(BaseModel):
    bundle_id: str | None = None
    package_path: str | None = None      # 引用，不是内容（§2.5）
    run_id: str | None = None
    sarif_path: str | None = None        # scan job 用
    scan_record: ScanRecord | None = None  # ★ 取消/失败时也留台账（§2.1）
    warnings: list[str] = []
    artifacts: dict[str, ArtifactRef] = {}   # AI fan-out 复用位（§2.6）


class ArtifactRef(BaseModel):
    kind: str            # "bundle" | "sarif" | "child_bundle"
    ref: str             # bundle_id 或路径
    path: str | None = None
    available: bool = True   # 读取时按磁盘实况计算，不是落库值


class JobFailure(BaseModel):
    mode: FailureMode
    message: str                 # 人话，可直接显示
    detail: str | None = None    # 异常 repr / stderr 尾
    attempt: int = 1
    recoverable: bool = False    # True = 重建 worker 后可再试
    scan_record: ScanRecord | None = None  # ★ 被取消/中断的那次扫描的台账（§2.1）


class Job(BaseModel):
    schema_version: str = "1.0"
    job_id: str
    kind: JobKind
    state: JobState
    cancel_requested: bool = False            # 语义见下表
    cancel_requested_at: datetime | None = None
    submission: JobSubmission
    timing: JobTiming
    progress: JobProgress
    result: JobResult | None = None           # 仅 succeeded
    failure: JobFailure | None = None         # 仅 failed（canceled 时恒为 None）
    revision: int = 0                         # 单调递增；前端丢弃乱序推送用
```

**取消的三态（不新造 state，用 `state` + `cancel_requested` 表达）**

| 用户点取消后的状态 | `state` | `cancel_requested` | 前端渲染 |
|---|---|---|---|
| 已受理，任务还在跑、尚未到达可中断点 | `running` | `true` | 「正在取消…」（进度条继续走） |
| worker 已打断并收拾干净 | `canceled` | `true` | 「已取消」（灰色终态，`failure` 为 `null`） |
| 请求取消时任务恰好已成功 | `succeeded` | `true` | 「已完成（取消未生效）」，`result` 可用 |
| 请求取消时任务恰好已失败 | `failed` | `true` | 「失败（取消未生效）」，`failure` 正常显示 |

**前端如何区分：只看 `state`。** `cancel_requested=true` 且 `state=running` 是**唯一的中间态**，
含义是「已受理、正在收尾」；一旦 `state` 进入终态集合，`cancel_requested` 就只是审计信息
（它记录「用户当时确实点过取消」），不再影响渲染。
**不新造 `canceling` state 的理由**：多一个状态就要多一套
「canceling → canceled / succeeded」的转移规则，而它携带的信息量恰好是
`state` + `cancel_requested` 两个已有字段的组合。这条也让 `JobState` 保持 5 个成员。

### 2.5 真实 JSON 样例

**(a) `running` 中途** —— `GET /v1/jobs/J-…` 在 expand 阶段返回的完整内容。
注意 `read` / `assemble` / `package` 仍是 `pending`；`expand` 有 `units_done/units_total`
因为它是并发的；`counters` 里只有**已经算得出来**的漏斗步骤。

```json
{
  "schema_version": "1.0",
  "job_id": "J-3f9a1c2b7d4e50618293a4b5c6d7e8f901234567",
  "kind": "assemble",
  "state": "running",
  "cancel_requested": false,
  "cancel_requested_at": null,
  "submission": {
    "schema_version": "1.0",
    "job_id": "J-3f9a1c2b7d4e50618293a4b5c6d7e8f901234567",
    "kind": "assemble",
    "request": {
      "workspace": "/workspace",
      "sarif_path": null,
      "rules": [],
      "rule_config": "p/default",
      "include_globs": [],
      "exclude_globs": [],
      "budget": {"max_depth": 2, "max_nodes": 60, "max_contexts": 20, "expand_concurrency": 6},
      "max_findings": null,
      "lsp": true,
      "package_name": null
    },
    "fingerprint": "8b1d0f2c9a7e4b3d5c6f8a90b1c2d3e4f5061728",
    "submitted_at": "2025-01-14T09:12:03.114000Z",
    "submitted_by": "gateway",
    "children": []
  },
  "timing": {
    "submitted_at": "2025-01-14T09:12:03.114000Z",
    "started_at": "2025-01-14T09:12:04.882000Z",
    "finished_at": null,
    "queue_wait_ms": 1768,
    "duration_ms": 0
  },
  "progress": {
    "stage": "expand",
    "stages": [
      {"stage": "scan", "state": "done", "started_at": "2025-01-14T09:12:04.882000Z",
       "finished_at": "2025-01-14T09:12:14.310000Z", "duration_ms": 9428,
       "note": "scan_transport=remote", "counters": {"discovered": 37}},
      {"stage": "setup", "state": "done", "started_at": "2025-01-14T09:12:14.310000Z",
       "finished_at": "2025-01-14T09:12:15.977000Z", "duration_ms": 1667,
       "note": "lsp=python", "counters": {}},
      {"stage": "locate", "state": "done", "started_at": "2025-01-14T09:12:15.977000Z",
       "finished_at": "2025-01-14T09:12:16.402000Z", "duration_ms": 425,
       "note": null, "counters": {"located": 34, "focus_methods": 19}},
      {"stage": "expand", "state": "running", "started_at": "2025-01-14T09:12:16.402000Z",
       "finished_at": null, "duration_ms": null, "note": null,
       "counters": {"contexts": 19}},
      {"stage": "read", "state": "pending", "started_at": null, "finished_at": null,
       "duration_ms": null, "note": null, "counters": {}},
      {"stage": "assemble", "state": "pending", "started_at": null, "finished_at": null,
       "duration_ms": null, "note": null, "counters": {}},
      {"stage": "package", "state": "pending", "started_at": null, "finished_at": null,
       "duration_ms": null, "note": null, "counters": {}}
    ],
    "counters": {"discovered": 37, "located": 34, "focus_methods": 19,
                 "contexts": 19, "slices": 18},
    "units_done": 11,
    "units_total": 19,
    "unit_label": "slices",
    "worker_id": "aegis-worker:4711:0f2a",
    "attempt": 1,
    "stage_started_at": "2025-01-14T09:12:16.402000Z",
    "worker_heartbeat_at": "2025-01-14T09:12:31.006000Z"
  },
  "result": null,
  "failure": null,
  "revision": 14
}
```

**(b) `succeeded` 终态** —— `stages` 全部 `done`，漏斗 9 步齐全，`result` 里只有引用、没有 manifest：

```json
{
  "schema_version": "1.0",
  "job_id": "J-3f9a1c2b7d4e50618293a4b5c6d7e8f901234567",
  "kind": "assemble",
  "state": "succeeded",
  "cancel_requested": false,
  "cancel_requested_at": null,
  "submission": {
    "schema_version": "1.0",
    "job_id": "J-3f9a1c2b7d4e50618293a4b5c6d7e8f901234567",
    "kind": "assemble",
    "request": {
      "workspace": "/workspace",
      "sarif_path": null,
      "rules": [],
      "rule_config": "p/default",
      "include_globs": [],
      "exclude_globs": [],
      "budget": {"max_depth": 2, "max_nodes": 60, "max_contexts": 20, "expand_concurrency": 6},
      "max_findings": null,
      "lsp": true,
      "package_name": null
    },
    "fingerprint": "8b1d0f2c9a7e4b3d5c6f8a90b1c2d3e4f5061728",
    "submitted_at": "2025-01-14T09:12:03.114000Z",
    "submitted_by": "gateway",
    "children": []
  },
  "timing": {
    "submitted_at": "2025-01-14T09:12:03.114000Z",
    "started_at": "2025-01-14T09:12:04.882000Z",
    "finished_at": "2025-01-14T09:12:26.540000Z",
    "queue_wait_ms": 1768,
    "duration_ms": 21658
  },
  "progress": {
    "stage": "package",
    "stages": [
      {"stage": "scan", "state": "done", "duration_ms": 9428,
       "note": "scan_transport=remote", "counters": {"discovered": 37}},
      {"stage": "setup", "state": "done", "duration_ms": 1667,
       "note": "lsp=python", "counters": {}},
      {"stage": "locate", "state": "done", "duration_ms": 425,
       "counters": {"located": 34, "focus_methods": 19}},
      {"stage": "expand", "state": "done", "duration_ms": 4310,
       "note": "18/19 slices expanded; 1 failed and was recorded as a warning",
       "counters": {"contexts": 19, "slices": 18}},
      {"stage": "read", "state": "done", "duration_ms": 2288,
       "counters": {"proposed": 143, "kept": 121, "read": 118}},
      {"stage": "assemble", "state": "done", "duration_ms": 3011,
       "counters": {"inlined": 176}},
      {"stage": "package", "state": "done", "duration_ms": 529, "counters": {}}
    ],
    "counters": {"discovered": 37, "located": 34, "focus_methods": 19, "contexts": 19,
                 "slices": 18, "proposed": 143, "kept": 121, "read": 118, "inlined": 176},
    "units_done": 118,
    "units_total": 121,
    "unit_label": "bodies",
    "worker_id": "aegis-worker:4711:0f2a",
    "attempt": 1,
    "stage_started_at": "2025-01-14T09:12:26.011000Z",
    "worker_heartbeat_at": "2025-01-14T09:12:26.011000Z"
  },
  "result": {
    "bundle_id": "B-c7f830954f",
    "package_path": "/data/packages/B-c7f830954f",
    "run_id": "R-1a2b3c4d5e",
    "sarif_path": "/data/work/R-1a2b3c4d5e/opengrep.sarif",
    "warnings": ["scan ran in the scan service: its raw SARIF is not in this filesystem"],
    "artifacts": {
      "bundle": {"kind": "bundle", "ref": "B-c7f830954f",
                 "path": "/data/packages/B-c7f830954f", "available": true}
    }
  },
  "failure": null,
  "revision": 41
}
```

**(c) `running` + `cancel_requested`（已受理、正在收尾）**

```json
{
  "state": "running",
  "cancel_requested": true,
  "cancel_requested_at": "2025-01-14T09:13:02.550000Z",
  "progress": {
    "stage": "expand",
    "stages": [ "... expand 仍是 running，其前的阶段计时全部保留 ..." ],
    "counters": {"discovered": 37, "located": 34, "focus_methods": 19,
                 "contexts": 19, "slices": 11},
    "units_done": 11, "units_total": 19, "unit_label": "slices"
  },
  "result": null,
  "failure": null,
  "revision": 22
}
```

**(d) `canceled` 终态** —— 注意 `failure` 是 `null`，`progress.stage` 停在被打断的阶段：

```json
{
  "state": "canceled",
  "cancel_requested": true,
  "cancel_requested_at": "2025-01-14T09:13:02.550000Z",
  "timing": {
    "submitted_at": "2025-01-14T09:12:03.114000Z",
    "started_at": "2025-01-14T09:12:04.882000Z",
    "finished_at": "2025-01-14T09:13:03.180000Z",
    "queue_wait_ms": 1768,
    "duration_ms": 58298
  },
  "progress": {
    "stage": "expand",
    "stages": [
      "... scan / setup / locate 均为 done，计时保留 ...",
      {"stage": "expand", "state": "failed", "duration_ms": 46800,
       "note": "canceled at slice 11/19; 2 LSP processes terminated",
       "counters": {"contexts": 19, "slices": 11}},
      {"stage": "read", "state": "pending", "counters": {}},
      "..."
    ],
    "counters": {"discovered": 37, "located": 34, "focus_methods": 19,
                 "contexts": 19, "slices": 11}
  },
  "result": null,
  "failure": null,
  "revision": 24
}
```

**失败时同样不回填未执行的阶段**（`failed` 的 job 里 `progress.stage` 停在死亡点）——
前端据此能显示「跑到哪一步死的」。这是「绝不静默」在 UI 上的兑现。

### 2.6 为 AI fan-out 预留（本轮不实现，契约不变）

用户已定：AI 阶段本轮不做，但 job 契约要能被将来复用。留三处，**都不需要改 `Job` 的顶层形状**：

```python
class JobChild(BaseModel):
    child_id: str                 # 通常是 context_id（C-…，内容派生，见 ARCHITECTURE §5）
    label: str                    # "context.C-1a2b3c4d5e6f"
    state: JobState = JobState.QUEUED
    stage: JobStage | None = None
    duration_ms: int | None = None
    result_ref: str | None = None # ArtifactRef 的 key
```

1. `JobSubmission.children`：一个 assemble job 之后追加 N 个 `ai_fanout` 子任务，
   gateway 在**同一个 job_id** 下登记，不改 URL。
2. `JobProgress.fanout: dict[str, JobChildProgress]`：stage 级进度对子任务同样成立，
   因为 `context.<id>` 块是自包含的（ARCHITECTURE §5），子任务之间没有依赖。
3. `JobResult.artifacts`：子任务产物用 `kind="child_bundle"` 登记，与主 bundle 共用 `ArtifactRef`。

`kind=AI_FANOUT` 本轮只存在于枚举里，worker 收到它会以
`failure.mode=internal_error`（消息 "ai fanout not implemented in this build"）**显式拒绝**——
宁可明确拒绝，也不要静默接受后不执行。

---

## 3. 阶段 ↔ 漏斗 9 步的映射

### 3.1 先明确：这不是一一对应

漏斗 9 步（`docs/ARCHITECTURE.md` §9，实现见 `app/observability/views.py::funnel`，L230–375）
是**计数步骤**——每一步记录「数量在同一单位上如何变化」。
流水线阶段（`stats.stage_ms`，标签见 `app/observability/views.py:98-106 STAGE_LABELS`）是**计时分段**。
两者形状不同，三处证据：

* 9 步里有两处**单位不变但口径变化**：`proposed` 是 gross（走到过的方法数含被丢弃的）、
  `kept` 是 net（去重后真正留下的），同一批方法的两次口径。
* `kept` / `read` / `inlined` 三步在 `run()` 里**跨阶段计算**：
  `views.funnel` L249 取 `counts["methods_kept"]`（在 read 段之后才写入，`assemble.py:224-228`）、
  L250 取 `counts["bodies_read"]`（`assemble.py:219`）、而 `inlined` 是
  `sum(len(context.methods) for context in manifest.contexts)`——**只有 assemble 段结束才有**。
* 反过来，`package` 阶段在漏斗里**没有对应步骤**（写盘不改变任何计数）。

所以映射必须声明「哪个阶段结束时，哪几步才有权威数字」，而不是把 9 步切成 7 段。

### 3.2 映射表

| 流水线阶段（`JobStage`） | 该阶段结束时产出/上报的漏斗步骤 | 计时语义 | 并发性 | 上报钩子（`assemble.py` 实读行号） |
|---|---|---|---|---|
| `scan` | `discovered` | 独占计时：`_collect_findings()`，一次扫描子进程或一次 SARIF 解析 | 串行（一次同步调用） | 第 124 行（`stats.stage_ms["scan"]`）之后 |
| `setup` | —（无数） | 独占计时：`Workspace` / `LanguageServerManager` / `SymbolIndex` / `CallGraphResolver` 构造 | 串行 | 第 162 行（`stage_ms["setup"]`）之后 |
| `locate` | `located`、`focus_methods` | 独占计时：`_locate()`，逐 finding 查 `documentSymbol` | 串行（for 循环） | 第 187 行（`stage_ms["locate"]`）之后 |
| `expand` | `contexts`（预判）、`slices` | **整体计时**：`asyncio.gather` + 信号量（`budget.expand_concurrency`，默认 6） | 并发，有界 | 第 206 行（`stage_ms["expand"]`）之后 |
| `read` | `proposed`、`kept`、`read` | **整体计时**：`MethodReader.read_slices()` 在同一信号量下并发读 | 并发，有界 | 第 **231** 行之后（不是 218，见下） |
| `assemble` | `inlined` | 独占计时：`ContextAssembler.assemble()` + `BundleRenderer.render()` + `recompute_totals()` | 串行 | 第 286 行（`stage_ms["assemble"]`）之后 |
| `package` | —（无数） | 独占计时：`BundlePackager.write()` + `manifest.json` 落盘 | 串行 | 第 296–297 行（`stage_ms["package"]`）之后，rename 完成之后 |
| `done` | — | 无计时（伪阶段） | — | `run()` 返回之后，worker 写终态 |

### 3.3 为什么这么映射（四条必须写下来的理由）

**(1) `contexts` 在 `expand` 阶段"预判"上报，因为它的定义是 `len(assembly.contexts)` 而不是 `len(slices)`。**
`views.funnel` L243 是 `contexts_built = len(manifest.contexts)`，
而 `distinct_focus`（L242）是定位阶段的方法数。正常路径上二者相等
（每个 focus 方法恰好产出一个 context），但 `_expand` 有切片失败时
（`assemble.py:453-456` 吞掉异常返回 `None`）`slices < contexts`。
所以 `contexts` 的权威值只能在 expand 阶段结束时按 `len(located)` 预判，
并在 `note` 里写明失败数，等 assemble 段结束后以 manifest 实际值覆盖。
**代价：`contexts` 这个数在 job 生命周期内可能被改小一次。**
前端不应把它当作单调递增的进度条基准——进度条的基准是 `slices`。

**(2) `proposed`（gross）与 `kept`（net）落在 `read` 阶段，而不是 `expand`。**
`proposed = methods_collected + methods_dropped_at_expand`（`assemble.py:225-227`），
两项在 expand 结束时已知；而 `kept` 需要
`{ref.method.method_id for s in slices for ref in s.methods.values()}` 去重后的
`net_methods`（第 224 行）——它在 read 段之后才算，因为要等所有切片的方法集合稳定。
把 `kept` 提前到 expand 会得到偏大的未去重数字，那就是 HANDOVER §10.11
「漏斗每一步必须同单位」的反面：**宁可晚报，不可错报。**

**(3) `read` 这个漏斗步骤 ≠ `read` 这个流水线阶段。**
漏斗的 `read` = `counts["bodies_read"]`（`assemble.py:219`，读过的方法体数）；
流水线的 `read` = 读方法体这一段的时间。同名不同物，
所以 `read` 阶段结束时**同时**带上 `kept`、`read`、`proposed` 三个漏斗计数。
文档、代码注释、以及 `tests/test_jobs_contract.py` 的断言都要写死这条。

**(4) `read` 的上报点必须在第 231 行，不是第 218 行。**
第 218 行只是 `stats.stage_ms["read"] = _ms(started)`；
`net_methods`（L224）与 `methods_proposed`（L225）在它之后才算出来，
`methods_dropped_by_caps`（L229-231）更晚。
**插入判据是「所需变量都已就绪」，不是「计时刚写完」。**
同理 `stage_ms["expand"]` 在 **206**（不是 208）、`stage_ms["package"]` 在 **296**
（`write_text(manifest.json)` 在 298）。

### 3.4 上报不了的情况（诚实清单）

| 情况 | 上报什么 | 用户看到什么 |
|---|---|---|
| `lsp=false` | `setup` 阶段 `note="lsp disabled by configuration"`，`counters={}` | 阶段条正常走完，但来源全是 `syntax_regex` |
| LSP 不可用（无服务器） | `setup.note="no usable language server for scanned files"` | 同上；降级在 bundle 的 `degradations` 里 |
| 远程扫描（`AEGIS_SCAN_SERVICE_URL`） | `scan.note="scan_transport=remote"` | 扫描阶段很长但没有细分——**远程扫描器不给进度** |
| **扫描阶段「开始即静默」** | worker 在调用 pipeline **之前**写一次 `stage=scan, state=running, note="scanning"` 快照；此后直到该调用返回**没有任何事件** | 见下方专条 |

**扫描阶段是整个流水线里唯一「开始即静默」的阶段**，原因是结构性的，不是疏忽：

* `AssemblyPipeline.run()` 是 `async def`，但 `_collect_findings()`（`assemble.py:321`）是
  **同步阻塞**调用：`run_scan_anywhere()` → `run_scan()` → `subprocess.run(...)`
  （`services/scan/opengrep.py:164`）。
* 同步调用期间**事件循环一次 `await` 都不让出**，所以
  「在 `assemble.py:115` 之后发一个 `('scan','start')`」这类设计**根本不成立**：
  事件要等 `_collect_findings()` 返回才可能被处理，等于没发。
  **早先草案里有这一条，已删除。**
* 这个阶段最长可以到 `AEGIS_SCAN_TIMEOUT_S=900` 秒（默认），远程扫描还要加 HTTP 往返。

**结论（必须写进前端契约）**：`JobStage.SCAN` 的进度事件**只在它开始前与结束后各有一条**，
中间 0 条。前端在扫描阶段只能显示**不确定进度条（indeterminate）+ 已耗时**，
用 `timing.started_at` / `progress.stage_started_at` 对表计时，
**不能**期待 `units_done/units_total`（此时 `unit_label="scan"`、`units_total=0`）。

两个缓解手段，按成本排序：

| | 做法 | 状态 |
|---|---|---|
| a | **worker 在调用 pipeline 之前写一次 `stage=scan, state=running, note="scanning"` 快照** | **本轮做**。前端至少能确定「在扫描」而不是「没反应」，且 `stage_started_at` 让「已扫描 4 分 12 秒」这个数字真实、来自服务端 |
| b | 把 opengrep 的输出（`--quiet` 之外可用 `--verbose`）流式解析成进度 | **未来工作**。它要改 `OpengrepRunner.scan()` 的返回形状与 `ScanRecord.stderr_tail` 的语义 |

注意手段 (b) 与 §6.5.4 的 `Popen` 改造**共用同一个 `Popen`**：真取消已经把
`subprocess.run` 换成 `Popen` + 轮询，所以将来做 (b) 的边际成本只有
「把轮询循环里读到的行转成事件」——**这是把真取消提前做掉之后顺带买到的东西**。

---

## 4. Redis 键与数据结构

### 4.1 键清单

所有键统一前缀 `aegis:`（`QueueKeys` 集中构造，`services/queue/keys.py`）。

| 键 | 类型 | 内容 | TTL | 谁写 |
|---|---|---|---|---|
| `aegis:job:{job_id}` | String（JSON） | 整个 `Job.model_dump_json()` | 运行中：**不设 TTL**，靠心跳 `EXPIRE` 刷新为 `job_ttl_s`；终态：`EXPIRE job_ttl_s`（默认 604800 = 7d） | gateway 建、worker 改 |
| `aegis:job-fp:{fingerprint}` | String | `job_id` | 与 job 同寿（同步 `EXPIRE`） | gateway 建 |
| `aegis:jobs` | Sorted Set | member=`job_id`，score=`submitted_at` 的 epoch ms | 无（惰性 `ZREMRANGEBYSCORE`） | gateway 建 |
| `aegis:q:jobs` | Stream | 任务条目（§4.2） | `MAXLEN ~ stream_maxlen`（默认 10000）近似裁剪 | gateway `XADD` |
| `aegis:q:jobs` 的 consumer group `aegis-workers` | — | PEL 保存 in-flight | 随 stream | worker `XREADGROUP` / `XACK` |
| `aegis:q:seen` | String（JSON 或 SET） | 近期 `XADD` 过的 job_id（用于 §4.6 的孤儿检测） | `EXPIRE 2 × job_ttl_s` | gateway / worker |
| `aegis:events:{job_id}` | Pub/Sub channel | `{job_id, revision, state, stage}` | 无（pub/sub 不存储） | worker |
| `aegis:queue:heartbeat` | String | `{worker_id, at, current_job}` | `EXPIRE 60`，每 20s 刷新 | worker |

**为什么不用 Hash 存 job**：`Job` 是**带嵌套**的（`progress.stages` 是列表、
`result.artifacts` 是字典）。用 Hash 就得把 `progress` / `result` / `submission`
各序列化成一个字段里的 JSON，既没省下序列化，又把「一次 `HGETALL` 拿全」
退化成「拿回来再解一层」。String + 整体 JSON 的额外好处：
**读路径与写路径共用同一个 pydantic 模型**（`Job.model_validate_json`），
字段漂移会当场报错而不是静默少一个键。

**为什么 TTL 只在终态设**：运行中的 job 记录一旦过期，`GET /v1/jobs/{id}` 会 404
而 worker 还在写——那正是「静默状态丢失」。代价是：worker 崩溃且 reaper 也挂了
（Redis 里没有 TTL 兜底）会留下永久孤儿键，由 §6.3 的重启自检兜底。

### 4.2 Stream 条目字段

```python
# services/queue/streams.py::enqueue
stream.add(
    keys.queue,
    {
        "job_id": job_id,          # str，唯一的业务键
        "kind": kind.value,        # "assemble" | "scan"
        "fingerprint": fingerprint,
        "attempt": "1",            # Redis Stream 字段只能是 str/bytes
        "submitted_at": iso,       # ISO-8601 UTC
    },
    maxlen=settings.queue.stream_maxlen,
    approximate=True,
)
```

**`XADD` 只放路由信息，不放请求体**：请求体在 `aegis:job:{job_id}` 里，worker 用 `job_id` 取回。理由：
(a) Stream 条目会被 `MAXLEN` 裁掉，而 job 记录不会被裁——把请求体放在会被裁的地方是错的；
(b) 重投（reaper）只需再 `XADD` 同样 5 个字段，不必重新序列化整个请求。

**consumer group 名**：`aegis-workers`，固定字面量，不随部署环境变化。
consumer 名 = `{hostname}:{pid}:{4位随机}`（`services/queue/streams.py::consumer_name()`），
保证同一容器内多进程不互相覆盖 PEL。

**`XGROUP CREATE` 必须幂等且用 `id="0"`**：

```python
try:
    stream.xgroup_create(keys.queue, CONSUMER_GROUP, id="0", mkstream=True)
except redis.ResponseError as exc:
    if "BUSYGROUP" not in str(exc):
        raise
```

`id="0"` 而不是 `"$"` 是硬要求：进程重启后必须能看到**未 ACK 的历史条目**，
否则崩溃瞬间的那条消息永远不会被任何 consumer 读到（`"$"` 只读新消息），
`XAUTOCLAIM` 的兜底也随之失效。测试要断言这一点。

### 4.3 消费与 ACK

```python
entries = stream.xreadgroup(
    CONSUMER_GROUP, consumer, {keys.queue: ">"}, count=1, block=settings.queue.block_ms
)
for _stream, messages in entries or []:
    for message_id, fields in messages:
        try:
            handle(message_id, fields)
        finally:
            stream.xack(keys.queue, CONSUMER_GROUP, message_id)
```

* **`block` 必须是有限值**（默认 1000 ms）：`block=0` 会让 `XREADGROUP` 在 Redis 连接上无限等待，
  SIGTERM 到达时主循环还在 `recv` 里，graceful shutdown 会退化成「等一个任务跑完 + 被 SIGKILL」。
  用 `block=1000` + 每圈判断 `stop_event`。
* **`XACK` 的唯一正确位置是 `finally`**：无论成功、失败、取消都 ACK。
  理由：worker 已经把终态写进 job 记录，留 PEL 只会让 reaper 重复处理一个已终结的 job。
  而「worker 在写终态前崩溃」这种情况，消息仍在 PEL、job 仍是 `running`——
  那正是 reaper 要处理的输入。
* `handle()` **开头必须判终态**：重投的条目可能对应一个已 `succeeded`/`canceled` 的 job
  （§4.4 的认领、§4.6 的自愈重投都会产生重复）。判到终态直接 `XACK` 返回，不执行。

### 4.4 Pending 条目回收（`XPENDING` / `XAUTOCLAIM`）

reaper 是 worker 主循环的一个**周期任务**（不是独立进程），每
`reaper_interval_s`（默认 30s）跑一次：

```python
# services/queue/reaper.py::reap_once
result = stream.xautoclaim(
    keys.queue, CONSUMER_GROUP, consumer,
    min_idle_time=settings.queue.visibility_timeout_s * 1000,   # 毫秒
    start_id="0-0", count=settings.queue.reap_batch,
)
# redis-py >= 5: (next_start_id, [(id, fields), ...], deleted_ids)
next_id, claimed = result[0], result[1]
while next_id != "0-0" and claimed:
    result = stream.xautoclaim(keys.queue, CONSUMER_GROUP, consumer,
                               min_idle_time=..., start_id=next_id, count=...)
    next_id, more = result[0], result[1]
    claimed += more
```

对每个被认领的条目（`services/queue/reaper.py::_adjudicate`）：

1. 读 `aegis:job:{job_id}`。
2. **job 已终态** → 只 `XACK`，什么都不改（最常见的正常情况：worker 写完终态、ACK 前被杀）。
3. **`progress.worker_heartbeat_at` 距今 < `visibility_timeout_s`** → 说明活着的 worker 只是慢。
   `XACK` 并用当前 attempt 重新 `XADD`（防止消息丢失），**不写任何状态**。
   这是「慢 ≠ 死」的唯一防线，`tests/test_queue_reaper.py` 必须有用例。
4. **产物其实已落盘**（`result.package_path` 或按内容重算的 `bundle_id` 目录下 `manifest.json` 可解析）
   → 写 `succeeded`（`note="recovered"`），`XACK`。这是「能靠已有产物续跑的就续」。
5. **否则 `attempt < max_attempts`** → CAS 写入 `progress.attempt += 1` 且保留 `running`，
   `XACK` 旧条目，`XADD` 新条目。
6. **否则** → CAS 写 `failed`，`failure.mode=WORKER_LOST` / `ATTEMPTS_EXHAUSTED`，
   `recoverable=true`，`XACK`。

第 3 步与第 5 步的区别是**判据不同**：第 3 步看的是心跳（活性），第 5 步看的是尝试次数。
一个 job 可能心跳很旧（worker 真死了）但重投多次仍未成功——两条都要有。

### 4.5 状态写入的 CAS（并发正确性的关键）

三种写者会碰同一个 job：**worker**（进度/终态）、**reaper**（判死/重投）、**gateway**（取消标志）。
唯一真正危险的竞争是「reaper 判死」与「worker 正在写进度」同时发生：
reaper 会把一个健康 job 写成 `failed`，用户看到假失败。

防护：**比较并交换（CAS）**，用 Lua 保证「读-判-写」原子
（`services/queue/jobs.py::compare_and_set`）：

```lua
-- KEYS[1]=aegis:job:{id}
-- ARGV[1]=expected_state  ARGV[2]=expected_revision  ARGV[3]=new_job_json
-- ARGV[4]=ttl_s（<=0 表示不设）  ARGV[5]=bump_revision（"1"/"0"）
local raw = redis.call('GET', KEYS[1])
if not raw then return 0 end
local cur = cjson.decode(raw)
if ARGV[1] ~= '' and cur['state'] ~= ARGV[1] then return -1 end
if tonumber(ARGV[2]) >= 0 and cur['revision'] ~= tonumber(ARGV[2]) then return -2 end
local new = cjson.decode(ARGV[3])
if ARGV[5] == '1' then new['revision'] = cur['revision'] + 1
else new['revision'] = cur['revision'] end
redis.call('SET', KEYS[1], cjson.encode(new))
if tonumber(ARGV[4]) > 0 then redis.call('EXPIRE', KEYS[1], ARGV[4]) end
return new['revision']
```

返回 `revision`（>0 成功）、`-1` 状态不符、`-2` revision 被推进（有人先写了）。
reaper 在步骤 5/6 用 `expected_state="running"` + `expected_revision=<读到的值>`；
被拒就丢弃本次裁决（下一轮再看），**绝不覆盖**。
心跳走同一个脚本，但 `ARGV[5]="0"`（不改 revision，因为心跳不是状态变化）。

**为什么必须用 Lua 而不是 `WATCH/MULTI/EXEC`**：`redis-py` 的事务需要同一连接上
先 `WATCH` 再 `GET` 再 `MULTI`，在「worker 主循环 + reaper 周期任务 + 心跳」
共享连接池的场景里容易踩连接切换；Lua 是单命令、单往返、语义无歧义。
**代价**：`fakeredis` 的 Lua 需要 `lupa`（§7.1）。
**退路（写下来以防评审拒绝 `lupa`）**：改成 `WATCH/MULTI/EXEC`，
则 §4.5 这一整段（含 Lua 源码）需要同步改写为 pipeline 事务版本，
并且 `fakeredis` 的 TRANSACTIONS 支持是纯 Python 的，无需 lupa。

`revision` 单调递增是给前端的：轮询与推送可能乱序到达，前端只接受 `revision` 更大的那份。

### 4.6 TTL 与清理策略

| 对象 | TTL | 过期后的用户可见行为 |
|---|---|---|
| job 记录（终态） | `job_ttl_s=604800`（7d） | `GET /v1/jobs/{id}` → 404 `{"detail": "job not found or expired"}` |
| fingerprint 映射 | 同 job | 过期后同一输入会被当作新提交，`job_id` 相同（内容派生），幂等性天然保持 |
| `aegis:jobs` ZSET 成员 | 无 TTL；列表接口惰性剔除「job 键已不存在」的成员 | 列表不再出现 |
| `aegis:q:seen` | `2 × job_ttl_s` | 孤儿检测退化成「不知道」，见下 |
| Stream 条目 | `MAXLEN ~ 10000` | 已被 ACK 的旧条目被裁；**未被 ACK 的条目也可能被裁** |

**`stream_maxlen=10000` 与 `queued_warn_threshold=200` 是初值，不是结论。**
两个数都必须在上线后按真实 job 频率复核。观测点：
`XLEN aegis:q:jobs`、`XINFO GROUPS aegis:q:jobs` 的 `lag`/`pending`、
`GET /v1/jobs?state=queued` 的 `total`。复核方法：记录「最长的一次消费者全停时长」`T_stop`
与「峰值 job 速率」`R_peak`，要求 `stream_maxlen ≫ T_stop × R_peak`。

> **被 `MAXLEN` 裁掉未 ACK 条目的后果与检测方法**
>
> **机制**：`XADD ... MAXLEN ~ N` 的裁剪只按「最旧」删，**不区分是否已被 ACK**。
> 若 `T_stop × R_peak > N`，老条目会在被任何 consumer 读到之前消失。
>
> **后果（最坏的一种，因为它是静默的）**：那条 job 会永远停在 `queued`——
> 既不在 stream 里（没人会再派发它），也不在 PEL 里（从未被认领，`XAUTOCLAIM` 看不见它）。
> 也就是说：**`MAXLEN` 是唯一能绕过 §6.3 三层兜底的漏洞**，
> 因为「重启自检」只看 `state=running`、「reaper」只看 PEL，两者都看不见 `queued` 的孤儿。
>
> **检测方法（三条都要有，成本从低到高）**：
> 1. **`queued` 数量告警**：`GET /v1/jobs?state=queued` 的 `total > queued_warn_threshold`（200）
>    → worker 与 gateway 的 `/health` 报 `degraded`，`reason` 带数字。
> 2. **队列长度比对**：worker 每 `reaper_interval_s` 比较 `count(state=queued)`（来自 `aegis:jobs`
>    扫描）与 `XLEN aegis:q:jobs`。正常时前者 ≤ 后者（stream 里还有已 ACK 未裁的历史条目）；
>    **前者显著大于后者**就说明有条目被裁。这条比对进 `/health` 的 `queue` 字段。
> 3. **兜底自愈（本轮做）**：`reconcile_startup()` 除扫 `running`，**也扫 `queued`**：
>    对每个 `queued` 的 job 查 `aegis:q:seen`（`XADD` 时同步 `SADD`/`SET`），
>    若「已提交但近期没有对应 stream 条目」则重新 `XADD`。
>    **重投是安全的**：`job_id` 相同，`handle()` 开头判终态（§4.3），重复条目是幂等的。
>
> 有了第 3 条，`MAXLEN` 的后果从「静默丢失」降级为「延迟最多一个 worker 重启周期」。
> **第 3 条同时是「worker 全停期间提交的 job 不会丢」的保证**，值得单独一个测试用例（§7.2 用例 52）。

**Redis 内存上限**：compose 里给 `--maxmemory 256mb --maxmemory-policy noeviction`。
`noeviction` 是刻意的：`allkeys-lru` 会在内存压力下悄悄删掉 job 状态，
那等于「静默丢弃进度」。宁可 `XADD` 报 `OOM command not allowed` 让 gateway 返回 503。

---

## 5. 逐文件改动清单

### 5.1 新增

| 文件 | 内容 | 关键约束 |
|---|---|---|
| `aegis_contracts/jobs.py` | §2 的全部模型 + 两个纯函数 `request_fingerprint(request, *, lsp_config_fingerprint="")`、`job_id_for(fingerprint)` | 只 import `pydantic` + 标准库。该文件**会被 `tests/test_contracts.py:49` 的 `banned` 集合扫描**，`redis`/`httpx`/`socket` 都不许出现 |
| `services/queue/__init__.py` | 包文档 + 导出 `JobStore`、`enqueue`、`serve_forever` | — |
| `services/queue/keys.py` | `QueueKeys`：`job` / `job_fp` / `jobs_index` / `queue` / `seen` / `events` / `heartbeat` | 前缀常量 `PREFIX = "aegis:"` |
| `services/queue/jobs.py` | `JobStore`：`create` / `get` / `list` / `set_running` / `stage_started` / `stage_finished` / `heartbeat` / `succeed` / `fail` / `mark_canceled` / `request_cancel` / `compare_and_set` | 唯一的 Redis 状态读写口；所有写入走 §4.5 的 `EVAL` |
| `services/queue/streams.py` | `ensure_group` / `enqueue` / `claim` / `ack` / `consumer_name` / `publish_event` | §4.2、§4.3 |
| `services/queue/reaper.py` | `reap_once(store, stream, settings)`、`_adjudicate()` | §4.4 的 6 步 |
| `services/queue/cancel.py` | `TeardownHandle` 实现、`CanceledAbort`、`CancelWatch` | §6.5。**独立成文件**：它同时被 `worker`、`pipeline`、`OpengrepRunner` 引用，塞进 `observer.py` 会形成循环 import |
| `services/queue/observer.py` | `ProgressObserver`：把 `StageEvent` 翻译成 `JobStore` 写入（含节流与 `cancel_requested` 缓存失效） | §5.5 |
| `services/queue/worker.py` | `Worker`：`serve_forever` / `_handle` / `_shutdown` / `_kill_deadline` / `_poisoned`；`main()` 供 `aegis-worker` 调用 | §6 |
| `app/api/jobs.py` | 新 router：`GET /v1/jobs`、`GET /v1/jobs/{job_id}`、`POST /v1/jobs/{job_id}/cancel` | 取消端点**只写标志、不杀进程**（§5.3） |
| `tests/test_jobs_contract.py` | 契约与指纹 | 无 Redis 依赖 |
| `tests/test_queue_store.py` | `JobStore` 行为 | fakeredis |
| `tests/test_queue_streams.py` | Stream / consumer group / 幂等入队 | fakeredis |
| `tests/test_queue_worker.py` | worker 消费、阶段上报、终态、优雅退出 | fakeredis + 假 pipeline |
| `tests/test_queue_reaper.py` | §4.4 六个分支，尤其「慢 ≠ 死」 | fakeredis |
| `tests/test_queue_cancel.py` | 真取消：句柄登记、`Popen` 终止、`CanceledAbort` 穿透、`canceled ≠ failed` | 假子进程 + fakeredis |
| `tests/test_jobs_api.py` | 202/200/409/503 边界、`GET /v1/jobs`、`force`、取消三态 | fakeredis + TestClient |
| `tests/test_compose_policy.py` | compose 端口策略与健康检查的机器断言 | 解析 YAML，不需要 docker |

### 5.2 修改：`app/api/routes.py`

| 函数 / 行（实读） | 现状 | 改法 |
|---|---|---|
| `assemble()` L133–169 | 直接 `await pipeline.run(...)` 同步返回 | **分两条路径**：`if queue_enabled(): return await _enqueue_assemble(payload)` → `JobAcceptedResponse`（202）；否则**现有代码一字不改**（本地/测试/CLI 兼容） |
| 新增 `_enqueue_assemble()` | — | `resolve_workspace()`（复用 L138，**校验留在 gateway**，400 语义不变）→ 校验 `sarif_path.exists()`（复用 L140–141）→ 构造 `JobRequest` → `request_fingerprint()` → 查 `aegis:job-fp:{fp}` → 命中就按 §5.3 返回既有 job；未命中则 `JobStore.create()` + `enqueue()` |
| `assemble_upload()` L206–252 | 同步 multipart | **本轮不改**（TODO 见下） |
| `scan()` L110–130 | 同步 | 保留；另加 `@router.post("/v1/scan/jobs")` → 202（§5.3） |
| `list_bundles()` L255–295 | 遍历 `output_dir` 的所有子目录 | 加一行 `if entry.name.startswith("."): continue`，跳过 §5.5 的 `.staging-*` 目录 |
| 新增 include | — | `app/main.py:49` 之后加 `app.include_router(jobs_router)` |
| 新增 `JobAcceptedResponse` | — | 放 `aegis_contracts/jobs.py`（`{job_id, state, deduplicated, revision}`），因为 worker 与前端都要读 |

**为什么不改 `/v1/assemble/upload`**：它是**同步 multipart 上传 + 立即组装**。
异步化需要先落盘上传文件（`var/work/uploads/<job_id>/scan.sarif`）再入队，
于是产生新的「上传产物生命周期」问题（谁清理、失败的上传留不留、
`AEGIS_OUTPUT_DIR` 与 `work_dir` 的卷一致性是否要扩展到上传目录），
而它当前**没有超时压力**（上传是流式的，组装本身仍受 `scan_timeout_s` 约束）。

**TODO（明确留给后续，不要在本轮顺手做）**：`/v1/assemble/upload` 的异步化 =
「上传产物的保留与清理策略」这个独立决策 + 一个新端点。
**在这些问题有答案之前，异步化上传只会把「同步阻塞」换成「磁盘上无人清理的垃圾」。**

### 5.3 接口边界：202 / 200 / 409 / 404 / 503

`POST /v1/assemble`（以及 `/v1/scan/jobs`）：

| 场景 | 状态码 | 响应体 | 说明 |
|---|---|---|---|
| 请求非法（workspace 不存在、sarif 不存在、budget 不合法） | **400** | `{"detail": ...}` | 与今天完全一致。**校验发生在入队前**，绝不把一个注定失败的请求塞进队列让用户等 10 秒才看到 400 |
| 新任务入队 | **202** | `{job_id, state:"queued", deduplicated:false, revision}` + `Location: /v1/jobs/{job_id}` | |
| 同 fingerprint 已在 `queued`/`running` | **202** | `{job_id:<既有>, state:<既有>, deduplicated:true, revision}` | **幂等提交返回那个正在排队/运行的 job_id**（用户拍板项） |
| 同 fingerprint 已 `succeeded` 且 `package_path` 仍在磁盘 | **200** | 完整 `Job` | **202 与 200 的边界：202 = 「还会变」；200 = 「已经是最终答案」** |
| 同 fingerprint 已 `succeeded` 但产物已被清理 | **202** | 新 attempt（同 `job_id`，`attempt+1`） | 「结果不可用 = 需要重跑」 |
| 同 fingerprint 已 `failed`/`canceled` | **409** | `{"detail":"previous attempt failed: …","failure":{…}}` | **不自动重跑**：自动重跑会让「同一输入永远同一答案」失效，并把确定性失败变成无限重试。重跑必须显式 `?force=true`（→ 202） |
| Redis 不可达 | **503** | `{"detail":"queue unavailable: …"}` | 与 `routes.py:192-195` 的 503 语义一致：请求没问题，依赖挂了 |

`GET /v1/jobs/{job_id}`：存在 → **200** 完整 `Job`（**即使 state 是 failed/canceled**——
终态也是正常答案，用 200 表达，细节放 body）；不存在/已过期 → **404**；Redis 不可达 → **503**。

`GET /v1/jobs?state=&kind=&workspace=&limit=&since=`：**200**
`{"jobs":[<JobSummary>], "total":n, "queue":{"workers_alive":n,"pending":n,"lag":n,"degraded":bool}}`。
`JobSummary` 是 `Job` 去掉 `progress.stages` 与 `result.artifacts` 的轻量视图
（列表页不需要每个 job 的 7 段计时）。**前端首屏就用它**：一次请求拿到「排队中/运行中/最近完成」。

`POST /v1/jobs/{job_id}/cancel`（**真取消**，语义见 §6.5）：

| 请求时的 job 状态 | 状态码 | 响应体 | 含义 |
|---|---|---|---|
| `queued` | **202** | `{job_id, state:"canceled", cancel_requested:true, revision}` | 还没被认领 → 直接置 `canceled`。worker 之后即使认领，也会在 `handle()` 开头判终态并直接 `XACK`（不会执行） |
| `running` | **202** | `{job_id, state:"running", cancel_requested:true, revision}` | **受理了，但还在收尾**。前端按 §2.4 的三态表渲染成「正在取消…」并继续轮询 |
| 已是 `canceled` | **200** | 完整 `Job` | 幂等：重复点取消不是错误 |
| `succeeded` / `failed` | **409** | `{detail:"job already finished (succeeded)", state:"succeeded"}` | 不允许改历史；`cancel_requested` **也不会被置位** |
| Redis 不可达 | **503** | — | 同其它端点 |

**「已请求但仍在收尾」用 `state=running` + `cancel_requested=true` 表达，不新造 `canceling` state**
（理由见 §2.4）。端点**只写标志、绝不杀进程**：终止只能由持有句柄的那个 worker 做
（gateway 没有句柄，也不该有）。写入走 §4.5 的 CAS（`expected_state` 为读到的当前状态），
避免与「同一瞬间任务完成」竞争——CAS 返回 `-1` 时重读一次 job，按上表落到 202 或 409。

### 5.4 修改 / 复用：扫描与提取入口（worker 侧）——**worker 进程内提取**

**结论：worker 完全复用既有入口，不新增执行路径；并且 `worker` 容器【不设】`AEGIS_EXTRACTION_SERVICE_URL`。**

| 需要做的事 | 复用的入口 | 位置 | 用法 |
|---|---|---|---|
| assemble job 的扫描阶段 | `run_scan_anywhere(ScanRequest(...))` | `services/scan/client.py:59` | 与 `AssemblyPipeline._collect_findings` 的调用**逐字段一致**（`assemble.py:354-366`：`out_dir=self.settings.work_dir / run_id`、`binary`、`fallback_binary`、`timeout_s`）。**保留这一跳**：扫描器是独立小镜像（625 MB）、CPU 密集，委托仍然正确 |
| assemble job 的组装 | `AssemblyPipeline.run(request, observer=…, abort=…, teardown=…)` | `app/pipeline/assemble.py:109` | worker **进程内**构造 `PipelineRequest`，与 `routes.py:149-160` 同参 |
| scan job | `ScanOnlyPipeline.run(request)` | `app/pipeline/assemble.py:86` | 走它而不是裸调 `run_scan`，才能拿到 `run_id`/`sarif_path`/`warnings` 的既有语义 |
| SARIF 只需解析 | `parse_sarif(path, workspace=…)` | `services/scan/runner.py:69` | 当 `request.sarif_path` 给了时走这条 |
| ~~远程组装~~ | ~~`request_extraction(body)`~~ | — | **worker 不用它**。它仍是 gateway 同步路径（`routes.py:145-146`）的入口，保留不动 |

**不新增入口的理由**：`services/scan/client.py` 的文件头写着「两个传输一个契约，
调用者永远不需要知道用的是哪个」。如果 worker 绕开 `run_scan_anywhere` 直接
`httpx.post(scan_service)`，那么 `ScanRecord.location="remote"`、
「远程 SARIF 读不到要挂 warning」（`assemble.py:127-134`）这些行为就会在 worker 路径上缺失。
**worker 是 `AssemblyPipeline` 的又一个调用者，不是第二个实现。**

#### 5.4.1 为什么 worker 必须进程内提取（三条独立理由，每条都足以推翻环境变量方案）

早先的草案给 `worker` 设了 `AEGIS_EXTRACTION_SERVICE_URL: http://extract:8103`。**这是错的。**

1. **它会打死心跳。** `request_extraction()`（`services/extraction/client.py:38-42`）走的是
   `httpx.post(..., timeout_s=1800.0)`——一次**阻塞等待**，最长 30 分钟。
   worker 在这段时间里**回不到主循环**，写不了 `worker_heartbeat_at`。
   而 §6.3 的 reaper 恰好靠心跳新鲜度区分「慢」与「死」：
   于是**一个健康的、正在正常远程提取的 worker 会被自己的 reaper 判死**。
   这等于用一行环境变量把「风险 1」直接制造出来。
2. **它让真取消变成不可实现。** 实读 `services/extraction/routes.py:92-105`：
   `await pipeline.run(PipelineRequest(...))` **没有 observer、没有 cancel 回调、没有句柄**。
   worker 手上只有一条 HTTP 连接，没有任何东西能终止对端容器里的语言服务器。
   给 extraction 加进度/取消通道意味着把 HTTP 契约改成双向流（SSE 或轮询子资源），
   那是另一块工作（§5.4.3 列出全部接口点）。
3. **进度粒度会掉到 2 个粗阶段**，而 §3 的映射表是按 7 个阶段设计的——两处自相矛盾。
   更糟的是「阶段计时」会退化成「一次 HTTP 往返的耗时」，那已经不是阶段计时而是一个黑盒数字。

**因此**：`worker` 进程内跑 `AssemblyPipeline`——与 `extract` 共用同一镜像这件事
正好让它有这个能力（镜像里已经有 pyright/clangd/Node 与 `/opt/aegis/lsp.yaml`）。
**worker 自己拥有语言服务器进程、扫描子进程句柄与落盘目录**，真取消与阶段进度才同时成立。

#### 5.4.2 职责划分（写进文档，避免后来人再改回去）

| | `extract` 容器 | `worker` 容器 |
|---|---|---|
| 触发方式 | 被 HTTP 调用（同步请求/响应） | 被 Redis Stream 触发（队列） |
| 语言服务器 | **自己 spawn、自己持有** | **自己 spawn、自己持有** |
| 取消语义 | 只能靠 HTTP 客户端断开（对端**收不到**，进程继续跑到结束） | **真取消**：句柄在手，可 terminate/kill（§6.5） |
| 进度 | 无（响应里只有最终 manifest） | 7 阶段 + 漏斗计数（§3） |
| 面向谁 | 外部调用者 / gateway 的同步路径 | 队列负载 |
| 复用 `app/` 代码 | 是 | 是（同一镜像，不同 entrypoint） |

**一句话**：`extract` 是「同步 / 外部调用者的提取入口」，`worker` 是「队列负载的执行者」；
**代码共用，资源所有权与取消语义不同。**

> ⚠️ **不要让 worker 与 extract 同时持有语言服务器**。它们在两个容器里各自持有一套，
> 互不影响——但这意味着**内存占用翻倍**：`typescript-language-server`（Node，约 300–500 MB）
> + `clangd`（约 200–400 MB）会分别在两个容器里各起一份。
> 基数评估与配置建议（`shm_size`、worker 并发数）见 §5.9.3。
> 另：**不要把 `AEGIS_EXTRACTION_SERVICE_URL` 设给 worker**（§5.9.2 的清单里显式留空并注明理由），
> 否则上面这套全塌回粗粒度模式。

#### 5.4.3 远程提取模式的限制现在只影响同步路径

`AEGIS_EXTRACTION_SERVICE_URL` 仍然存在、仍被 gateway 的同步 `/v1/assemble` 使用
（`routes.py:145-146`）。它的粗粒度限制**不再适用于队列路径**：队列路径永远走进程内，
所以永远是 7 阶段。

**未来工作（明确记录，不在本轮）**：如果将来有第三方需要「异步 + 远程提取」，
需要给 extraction 加进度与取消通道。**需要改的接口点，逐条列出**：

1. `POST /v1/extract` 的请求体加 `progress_callback_url: str | None` 与 `job_token: str | None`；
   或在同一路由上按 `Accept: text/event-stream` 返回 SSE。
2. `services/extraction/routes.py:92` 的 `await pipeline.run(...)` 要传
   `observer=<把 StageEvent 发出去的适配器>`。
3. 取消需要**反向通道**：extraction 提供 `POST /v1/extract/{job_token}/cancel`，
   或在 SSE 连接断开时（`await request.is_disconnected()`）触发 abort。
4. `services/extraction/client.py:38` 的 `request_extraction()` 要从「一次 POST」变成
   「开流 + 逐事件转写进 `JobStore`」——**它现在是一个纯同步函数，这是最大的改动点**。
5. 两侧的测试：`tests/test_scan_transport.py` 的「两个传输一个行为」寓言要扩展到 extraction，
   且**取消与进度必须在两种传输下行为一致**——这才是这项工作的真正成本，
   不是那 4 行接口签名。

### 5.5 修改：`app/pipeline/assemble.py`（不改行为）

只加**三个可选关键字参数**与若干次回调调用，不移动任何既有语句、不改任何 ID 计算：

```python
@dataclass
class StageEvent:
    stage: str            # 与 stats.stage_ms 的键同名：scan/setup/locate/expand/read/assemble/package
    phase: str            # "start" | "end"
    ms: int | None = None
    counters: dict[str, int] = field(default_factory=dict)
    units_done: int = 0
    units_total: int = 0
    unit_label: str = ""
    note: str | None = None


Observer = Callable[[StageEvent], None]
AbortCheck = Callable[[], bool]


class AssemblyPipeline:
    async def run(
        self,
        request: PipelineRequest,
        *,
        observer: Observer | None = None,          # 新增：阶段进度
        abort: AbortCheck | None = None,           # 新增：可中断的等待
        teardown: TeardownHandle | None = None,    # 新增：可终止的资源句柄
    ) -> PipelineResult:
```

`TeardownHandle` 是**协议**（`typing.Protocol`），只声明行为、不实现：

```python
class TeardownHandle(Protocol):
    def aborted(self) -> bool: ...                                    # 判据，不是动作
    def register_process(self, name: str, proc: subprocess.Popen) -> None: ...
    def unregister_process(self, name: str) -> None: ...
    def register_lsp(self, manager: LanguageServerManager) -> None: ...
    def register_artifact_dir(self, path: Path) -> None: ...           # staging 目录，取消时删
```

**关键设计：`TeardownHandle` 由 worker 创建并传入，pipeline 只往里注册、不读它的内部状态。**
这保住了「pipeline 不依赖 queue 包」——`assemble.py` 里只有 `Protocol` 与三个可选参数，
`services.queue` 一个 import 都不出现。`tests/test_pipeline_observer.py` 有一条用例
用 AST 断言 `assemble.py` 的 import 集合里没有 `services.queue`。

#### 插入点（**已按实读行号逐条核对**）

`run()` 从 L109 开始。下表行号为当前工作树的实读值：

| 行号（实读） | 该行是什么 | 插入内容 |
|---|---|---|
| L115 | `run_id = "R-" + sha1(...)` | **不发 `scan.start`**：`_collect_findings()` 同步阻塞，此刻的事件要等它返回才被处理，等于没发（§3.4） |
| **L124** | `stats.stage_ms["scan"] = _ms(started)` | `_emit("scan", "end", ms=…, counters={"discovered": len(findings)}, note=f"scan_transport={scan_record.location}")` |
| **L162** | `stats.stage_ms["setup"] = _ms(started)` | `("setup", "end", note=…)`；同一处 `teardown.register_lsp(lsp)`（`lsp is not None` 时）与 `lsp.bind_run(abort=…, stage="setup")` |
| **L187** | `stats.stage_ms["locate"] = _ms(started)` | `("locate", "end", counters={"located": located_findings, "focus_methods": len(located)})` |
| **L206** | `stats.stage_ms["expand"] = _ms(started)` | `("expand", "end", counters={"contexts": len(located), "slices": len(slices)}, units_done=len(slices), units_total=len(located), unit_label="slices")`。**注意 `proposed` 此刻还算不出来**（在 L225），放到 read 事件里 |
| **L231** | `stats.counts["methods_dropped_by_caps"] = …`（read 段结束） | `("read", "end", ms=stats.stage_ms["read"], counters={"proposed": stats.counts["methods_proposed"], "kept": net_methods, "read": len(body_set.bodies)}, units_done=len(body_set.bodies), units_total=net_methods, unit_label="bodies")` |
| **L286** | `stats.stage_ms["assemble"] = _ms(started)` | `("assemble", "end", counters={"inlined": sum(len(c.methods) for c in assembly.contexts)})` |
| **L292 之前** | `packager.write(...)` 调用点 | `teardown.register_artifact_dir(staging_dir)`；`packager.write(..., staging=True)` |
| **L296–297** | `stats.stage_ms["package"] = _ms(started)` / `stats.duration_ms = sum(...)` | `("package", "end", ms=stats.stage_ms["package"])`——**必须在 rename 成功之后**，否则用户会看到「package done」但目录还没就位 |

> **三个与"行号直觉"相反的坑，写在这里免得实现时踩**：
> 1. `stage_ms["expand"]` 在 **206**（不是 208），`stage_ms["read"]` 在 **218**，
>    `stage_ms["package"]` 在 **296**（`write_text(manifest.json)` 在 298）。
> 2. **`read` 的 end 事件不能在 L218 发出**：L218 只写计时，`net_methods`（L224）、
>    `methods_proposed`（L225）、`methods_dropped_by_caps`（L229-231）都在它之后。
>    插入判据是「所需变量都已就绪」，不是「计时刚写完」。
> 3. **`proposed` 只能在 `read` 事件里上报**，因为 `methods_proposed` 在 L225 才写入
>    `stats.counts`；在 `expand` 事件里读它会拿到 `None`。

#### 取消 / 终止检查点

两级，**都必须有**：

1. **阶段边界（协作式）**：在 L124 / L162 / L187 / L206 / L231 / L286 之后各加 `_check_abort()`：
   ```python
   def _check_abort() -> None:
       if abort is not None and abort():
           raise CanceledAbort(stage=current_stage, resource="stage_boundary")
   ```
   **`package` 阶段例外**：进入 `packager.write()` **之前**检查一次，进入之后**不再检查**——
   它只有几百毫秒，半途而废会留下残缺目录（§6.5.3 的"不可中断段"）。
2. **阻塞等待内部（抢占式）**：仅靠阶段边界**不足以打断扫描**（第 1 阶段一跑就是 15 分钟）。
   `abort` 会被**继续传下去**：`_collect_findings` → `OpengrepRunner.scan(abort=…)`（§6.5.4）
   与 `LspClient.request(abort=…)`（§6.5.4）。**这是真取消与「标志位取消」的全部区别。**

`CanceledAbort` **定义在 `services/queue/cancel.py`**，继承 **`BaseException`**（理由见 §6.5.5）。

> **为什么不在 `_expand` 内部按切片上报/中断**：`_expand` 的 `asyncio.gather`（L458）
> 返回的是一个整体，中途上报要么改成 `as_completed`（改并发语义与失败处理），
> 要么在 `one()` 里回调（引入跨线程写 Redis）。前者是行为改动，后者是并发隐患，
> **两者都不该为了进度条去动一个已验收的并发模型。**
> 所以 expand/read 只给「整体计时 + 完成数/总数」。
> **真取消同样不为它改并发模型**：本轮 expand/read 的可中断点是**阶段边界的 `_check_abort()`**，
> 粒度是单切片。`tests/test_pipeline_observer.py` 里有一条用例断言
> `_expand` 的 `asyncio.gather(..., return_exceptions=False)` 语义未被改动。

**`bundle_id` 与 `run_id` 的两条设计必须保住**（实测确认）：

* `run_id`（L115）= `"R-" + sha1(workspace, time)`，**只进 manifest 元数据，不参与任何 ID 计算**
  （HANDOVER §5.1 的历史坑）。worker 每次 attempt 都会产生新的 `run_id`，这是对的：
  它标识「这一次尝试」，而 job_id/bundle_id 标识「这一份输入」。
* `bundle_id`（L167–177）= `request.package_name or "B-" + sha1(workspace_root, 排序后的 finding_id 集合,
  budget.model_dump_json(), rule_config, rules)`，**内容派生**。队列设计直接吃这个红利：
  - 同输入 → 同 `bundle_id` → 同目录 → 重跑**覆盖**而不是堆积；
  - `JobResult.bundle_id` 与 `request_fingerprint` 同源（同一组输入派生），
    所以「幂等提交返回既有 job」与「重跑得到同一个 bundle」互相印证；
  - **`package_name` 必须进 fingerprint**（§5.6），否则两次不同请求会被误判成同一个 job。
* **`BundlePackager.write()` 直接写最终目录，没有 temp+rename**（`package.py:81-95`：
  `root = output_dir / bundle_id` → `if root.exists(): shutil.rmtree(root)` → `root.mkdir(...)`），
  `zip_dir`（`package.py:178`）也是直接写 `<bundle_id>.zip`。
  **早先草案里"（原子 rename）"那句话是错的。** 后果两条，都必须处理：
  1. **半成品会被当成成品**：`canceled`/`failed` 的任务会留下一个真实存在的目录
     （可能缺 `manifest.json`，因为有 6 处 `write_text` 在它之后），还有一个残缺的 `.zip`，
     `GET /v1/bundles` 会把它列出来。
  2. **「已 succeeded」与「目录还在被写」之间有窗口**，而 `result.package_path` 会写进 Redis
     并被用户立刻读取。

  **修法（本轮做；`BundlePackager.write` 加一个可选参数，默认行为不变）**：
  ```python
  def write(self, bundle, result, *, staging: bool = False, ...) -> Path:
      final = self.output_dir / manifest.bundle_id
      root = self.output_dir / f".staging-{manifest.bundle_id}" if staging else final
      if root.exists():
          shutil.rmtree(root)
      ...                                   # 全部写 root
      if make_zip:
          zip_dir(root, target=root.with_suffix(".zip"))
      if staging:
          if final.exists():
              shutil.rmtree(final)
          os.replace(root, final)           # 同卷 rename，原子
          os.replace(root.with_suffix(".zip"), final.with_suffix(".zip"))
      bundle.package_path = str(final)
  ```
  调用方：worker 传 `staging=True`（并把 `.staging-<id>` 目录 `register_artifact_dir`，
  取消时整目录删掉）；gateway / CLI / 现有测试**不传**（`False`），
  所以 `bundle.package_path` 与磁盘布局对它们**逐字节不变**。
  `.staging-` 目录同时被两处忽略：`GET /v1/bundles`（§5.2 的 `startswith(".")` 那一行）
  与 `reconcile_startup()` 的产物判据（只认 `manifest.json` 可解析的目录）。
  **`os.replace` 要求同卷**：staging 目录必须建在 `output_dir` 内（不是 `tempfile.gettempdir()`），
  否则跨设备会退化成 copy+delete 甚至直接 `OSError`。

### 5.6 修改：`aegis_contracts/jobs.py` 里的指纹公式（对给定约束的细化）

用户给定：`request_fingerprint = sha1(workspace, sarif_path|rule_config, budget, rules)`。
**采纳，并补三项**（不改前四项，只追加），否则会出现「两个不同请求判为同一个 job」：

```python
def request_fingerprint(request: JobRequest, *, lsp_config_fingerprint: str = "") -> str:
    workspace = Path(request.workspace).expanduser().resolve().as_posix()
    if request.sarif_path:
        sarif = Path(request.sarif_path).expanduser().resolve()
        stat = sarif.stat() if sarif.exists() else None
        # 路径 + 大小 + mtime：仅路径不足以区分「同路径不同内容」
        artifact = (f"sarif:{sarif.as_posix()}:"
                    f"{stat.st_size if stat else -1}:{int(stat.st_mtime) if stat else -1}")
    else:
        artifact = f"rule_config:{request.rule_config or ''}"
    extra = [
        f"include:{','.join(sorted(request.include_globs))}",     # 补充 1
        f"exclude:{','.join(sorted(request.exclude_globs))}",     # 补充 1
        f"lsp:{int(request.lsp)}",                                # 补充 2
        f"max_findings:{request.max_findings if request.max_findings is not None else ''}",  # 补充 2
        f"package_name:{request.package_name or ''}",             # 补充 3
        f"lsp_config:{lsp_config_fingerprint}",                   # 补充 3
    ]
    return sha1(workspace, artifact, canonical_json(request.budget or {}),
                ",".join(sorted(request.rules)), *extra)
```

* **补充 1（include/exclude globs）**：直接改变命中的 finding 集合，因而改变 bundle。
* **补充 2（`lsp` / `max_findings`）**：一个关掉 LSP，一个截断 finding。
  漏掉它们会让「同一 workspace 全量跑」与「同一 workspace 只跑 5 条」共用一个 job id。
* **补充 3（`package_name` / LSP 目录指纹）**：`package_name` 直接决定落盘目录；
  `lsp_config_file` 决定用哪个语言服务器（`docker/lsp.yaml` vs 运维本地覆盖）。
  LSP 指纹用**文件内容的 sha1**（缺省空串），不是路径——路径相同内容不同必须区分。
* `canonical_json` 是 `aegis_contracts/jobs.py` 里的一个小工具（`json.dumps(..., sort_keys=True,
  separators=(",", ":"))`），保证字典顺序不影响指纹。

`job_id` 的派生：`job_id = "J-" + sha1(fingerprint, length=40)`。
用完整 40 位而不是 10 位：`job_id` 同时是「幂等键」与「用户可复制的标识」，
碰撞概率不是可以用「反正有 fingerprint 兜底」搪塞的地方。
它落在 `aegis:job:` 键名与日志里，40 位 hex 无自定义字符，`QueueKeys` 不需要转义。

### 5.7 修改：`aegis_core/config.py`

在 `Settings` 里新增一个嵌套模型（**沿用 `env_prefix="AEGIS_"` + `env_nested_delimiter="__"`**，
即 `AEGIS_QUEUE__REDIS_URL`），插在 `budget` 字段（L70）**之前**，并加注释说明
「未设置 `redis_url` 时队列关闭」——与 `AEGIS_SCAN_SERVICE_URL` 的既有约定同构：

```python
class QueueConfig(BaseModel):
    """Job queue. Absent `redis_url` = the queue is off and every route stays synchronous.

    Same convention as AEGIS_SCAN_SERVICE_URL / AEGIS_EXTRACTION_SERVICE_URL: the
    presence of a URL is what switches behaviour, so local development and the whole
    test-suite keep working with no Redis at all.
    """

    redis_url: str | None = Field(default=None,
        description="e.g. redis://redis:6379/0. Unset -> in-process, no queue.")
    stream: str = "aegis:q:jobs"
    group: str = "aegis-workers"
    visibility_timeout_s: int = Field(1800, ge=60)
    reaper_interval_s: int = Field(30, ge=5)
    heartbeat_interval_s: int = Field(15, ge=5)
    block_ms: int = Field(1000, ge=100, le=5000)
    max_attempts: int = Field(3, ge=1, le=10)
    job_ttl_s: int = Field(604_800, ge=300)
    list_limit: int = Field(100, ge=1, le=500)
    stream_maxlen: int = Field(10_000, ge=100)          # 初值，上线后按真实负载复核（§4.6）
    reap_batch: int = Field(32, ge=1, le=256)
    queued_warn_threshold: int = Field(200, ge=1)        # 初值，同上

    # --- 真取消（§6.5）-----------------------------------------------
    cancel_poll_ms: int = Field(50, ge=10, le=500)
    """阻塞等待里检查 abort 的间隔。决定取消响应时间的下限（§6.5.3）。"""
    cancel_terminate_grace_s: float = Field(1.0, ge=0.1, le=10.0)
    """terminate() 之后等多久升级到 kill()。"""
    cancel_kill_grace_s: float = Field(3.0, ge=0.5, le=30.0)
    """worker 从发出 abort 到「强制 kill 全部登记进程 + 清 staging 目录」的硬上限。
    超过它仍未收到 CanceledAbort，worker 自行完成终止并写 canceled（不依赖 pipeline 配合）。"""
    cancel_lsp_graceful: bool = Field(False)
    """True = 先走 LSP 的 shutdown/exit 协议（礼貌，慢 1–6s）；False（默认）= 直接 terminate/kill。
    取消路径默认选快。"""
```

`Settings` 里加 `queue: QueueConfig = Field(default_factory=QueueConfig)`，
`Settings.resolve()`（L72–79）**无需改动**（没有路径字段）。

`.env.example`（L27 之后）加（**保持第 0 节的事实 (3)：只放空占位符与注释，不放真实值**）：

```bash
# --- queue (unset AEGIS_QUEUE__REDIS_URL -> routes stay synchronous) -----
# AEGIS_QUEUE__REDIS_URL=redis://127.0.0.1:6379/0
AEGIS_QUEUE__VISIBILITY_TIMEOUT_S=1800
AEGIS_QUEUE__MAX_ATTEMPTS=3
AEGIS_QUEUE__JOB_TTL_S=604800
AEGIS_QUEUE__CANCEL_KILL_GRACE_S=3
```

**为什么不做成 `enabled: bool`**：两个开关（`enabled` 与 `redis_url`）会产生
「enabled=true 但 URL 为空」这种需要额外校验的状态。URL 有/无本身就是开关，
`services/scan/client.py:55` 与 `services/extraction/client.py:34` 已经是这个约定。

### 5.8 修改：`pyproject.toml`

```toml
dependencies = [
    "pydantic>=2.7",
    "pydantic-settings>=2.3",
    "httpx>=0.27",
    "pyyaml>=6.0",
    "redis>=5.0",                 # 新增（core，理由见下）
]

[project.optional-dependencies]
dev = [
    ...
    "fakeredis[lua]>=2.23",       # 新增：lua extra 提供 CAS 脚本所需的最小 Lua 解释器
]

[project.scripts]
aegis = "app.cli:main"
aegis-worker = "services.queue.worker:main"    # 新增
```

**`redis` 放 `dependencies`（core）而不是新 extra——已定（待确认第 1 项已采纳建议）**：
生产者是 gateway（`.[all]`），消费者是 worker（`.[all]`），而 `.[api]` 是 scan 服务在用的。
选择 (a) 放 core：scan 镜像多约 150 KB，零条件导入；
(b) 新建 `queue` extra：三个 Dockerfile 与 compose 都要记得加。
**选 (a)**：`redis-py` 无 C 扩展、纯 Python、约 150 KB，
不值得为它引入第三个 extra 和「某个镜像忘了加 extra，import 才炸」的失败模式
（这正是 HANDOVER §10.6 的教训）。

`redis` 导入**惰性化**（在 `services/queue/*` 内部 import，不在 `app/api/routes.py` 顶部）：
即使依赖树里没有 redis，未启用队列的部署也能起服务。这与 `routes.py:98`
把 `import httpx` 写在函数内是同一风格。

### 5.9 修改：Docker

**`docker/docker-compose.yml`** —— 新增 `redis` 与 `worker` 两个服务，`gateway` 增加
`AEGIS_QUEUE__REDIS_URL`。**方向性要点（§5.4.1）：`worker` 的
`AEGIS_EXTRACTION_SERVICE_URL` 必须为空**——这一行决定真取消能否成立、
以及 worker 会不会被自己的 reaper 判死。

```yaml
services:
  redis:
    image: redis:7-alpine
    container_name: aegis-redis
    command: ["redis-server", "--save", "", "--appendonly", "no",
              "--maxmemory", "256mb", "--maxmemory-policy", "noeviction"]
    expose: ["6379"]                 # 端口策略：不发布，只有 gateway/web 用 ports:
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 10s
      timeout: 3s
      retries: 5
      start_period: 5s
    restart: unless-stopped

  worker:
    image: aegis:0.1.0               # 与 extract 同一镜像，不同 entrypoint（决策 2/B）
    container_name: aegis-worker
    depends_on:
      redis: {condition: service_healthy}
      scan:  {condition: service_healthy}
      # 注意：**不依赖 extract**。worker 进程内提取，extract 的健康与它无关；
      # 把 extract 写进依赖会让「extract 挂了」连带阻塞 worker 启动，纯属错误耦合。
    expose: ["8104"]
    environment:
      AEGIS_LOG_LEVEL: INFO
      AEGIS_WORKSPACE_ROOT: /workspace
      AEGIS_OUTPUT_DIR: /data/packages
      AEGIS_WORK_DIR: /data/work
      AEGIS_LSP_CONFIG_FILE: /opt/aegis/lsp.yaml
      AEGIS_QUEUE__REDIS_URL: redis://redis:6379/0
      AEGIS_WORKER_PORT: "8104"
      # 只保留扫描这一跳：扫描器是独立小镜像（625 MB）、CPU 密集，委托是对的。
      AEGIS_SCAN_SERVICE_URL: http://scan:8101
      # ▼▼ 故意为空，不要"顺手补上"（三条理由见 §5.4.1）▼▼
      AEGIS_EXTRACTION_SERVICE_URL: ""
    entrypoint: ["aegis-worker"]
    volumes:                          # 与 extract 完全一致（逐条对齐 extract 的 L88-92）
      - ${AEGIS_SCAN_TARGET:-../demo/repo}:/workspace:ro   # 读：仓库（只读，Aegis 从不写仓库）
      - ../var/packages:/data/packages                     # 写：bundle 落盘 + staging 目录
      - ../var/work:/data/work                             # 写：SARIF 等中间件（run_id 子目录）
      - ./lsp.local.yaml:/opt/aegis/lsp.yaml:ro             # 读：LSP 目录（worker 自己 spawn 服务器）
    healthcheck:
      test: ["CMD", "python", "-c", "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8104/health', timeout=5).status == 200 else 1)"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 20s
    restart: unless-stopped
    shm_size: "512m"                  # 与 extract 一致，理由见 §5.9.3
    stop_grace_period: 30s            # 给 §6.2 的 drain 留时间（默认 10s 不够一个阶段边界）
```

#### 5.9.1 compose 变更后的服务清单

| 服务 | 端口 | 镜像 | 角色 | depends_on |
|---|---|---|---|---|
| `redis` | `expose 6379` | `redis:7-alpine` | 队列 + 状态权威源 | — |
| `scan` | `expose 8101` | `services/scan/Dockerfile` | 扫描器（不变） | — |
| `extract` | `expose 8103` | `docker/Dockerfile` | 同步 / 外部调用者的提取入口（不变） | `scan` |
| `worker` | **`expose 8104`（新增）** | `docker/Dockerfile`（**同镜像、不同 entrypoint**） | 队列负载的执行者；**进程内提取** | `redis`, `scan` |
| `gateway` | `ports 127.0.0.1:8100` | `docker/Dockerfile` | 唯一对外 API | `redis`, `scan`, `extract` |
| `web` | `ports 127.0.0.1:8102` | 待建 | 控制台 | — |

对既有服务的最小改动：

* `gateway`：`depends_on` 加 `redis: {condition: service_healthy}`；环境加
  `AEGIS_QUEUE__REDIS_URL: redis://redis:6379/0`。**不加 `worker`**（§5.9.4）。
* `extract`：**不加** `AEGIS_QUEUE__REDIS_URL`（它不经队列）。加了会让它误以为自己该消费。
* 文件头注释块（`docker-compose.yml` L1–34）现在写「Three services today」，改成五个，
  并把端口表补上 `redis`（internal，无端口）与 `worker`（`expose: 8104`）。

> **端口策略复核（硬规则）**：`redis` 与 `worker` 都只用 `expose:`；
> 只有 `gateway`（`127.0.0.1:${AEGIS_GATEWAY_PORT:-8100}:8000`）与将来的
> `web`（`127.0.0.1:8102`）使用 `ports:`。`tests/test_compose_policy.py` 把这条变成机器断言：
> 「拥有 `ports:` 的服务集合 ⊆ {gateway, web}」且每个 `ports:` 项以 `127.0.0.1:` 开头。

#### 5.9.2 环境变量清单（照抄即可）

| 变量 | worker | gateway | extract | scan |
|---|---|---|---|---|
| `AEGIS_QUEUE__REDIS_URL` | `redis://redis:6379/0` | `redis://redis:6379/0` | — | — |
| `AEGIS_EXTRACTION_SERVICE_URL` | **`""`（故意为空）** | `http://extract:8103` | — | — |
| `AEGIS_SCAN_SERVICE_URL` | `http://scan:8101` | `http://scan:8101` | `http://scan:8101` | — |
| `AEGIS_WORKER_PORT` | `8104` | — | — | — |
| `AEGIS_LSP_CONFIG_FILE` | `/opt/aegis/lsp.yaml` | — | `/opt/aegis/lsp.yaml` | — |

**为什么 worker 要扫描那一跳、不要提取那一跳**：
扫描是**一次性子进程**（无状态、无共享内存、委托只花一次 HTTP 往返），
委托给 625 MB 的小镜像既省内存又保留 CPU 隔离；
提取是**长驻语言服务器 + 需要进度与取消句柄**，委托出去就两头都拿不到。
**一句话判据：可以被一次性调用、不需要中途控制的，委托；需要持有句柄的，进程内。**

#### 5.9.3 `shm_size`、并发 worker 数与内存基数（决策 2 的补充 (b)）

**`worker.shm_size: "512m"`，与 `extract` 的 L101 逐字一致。** 理由：
两边跑同一套代码、同一批语言服务器，容器默认的 64 MB `/dev/shm` 对 Node 系语言服务器
（`typescript-language-server`）历来不够，会以 `SIGBUS`/`bus error` 的形式随机崩溃——
**那是最难查的一类失败**（表现为「LSP 时好时坏」）。`extract` 已经为它付过教训，worker 没有理由再踩。

`volumes` 与 `extract` **完全一致**（`/workspace:ro`、`/data/packages`、`/data/work`、
`/opt/aegis/lsp.yaml:ro`），见上面 compose 片段里的逐行注释。

**内存基数（写进容量规划）**：

| 容器 | 常驻语言服务器 | 估算 |
|---|---|---|
| `extract` | pyright / clangd / typescript-language-server（各一份） | 0.5–1.5 GB（有 job 时） |
| `worker` | **同样各一份**（owner 不同，互不影响） | 0.5–1.5 GB（有 job 时） |

**结论：镜像可以共用，语言服务器进程不能共用；启用队列后按 `worker 数 × 1.5 GB` 预留内存，
并保持 `worker` 副本数为 1。** 多副本时每份都会各起一套语言服务器，
且 §8「多 worker 并发抢占同一 bundle 目录」与「LSP 冷启动 × N」的成本会同时出现。
**真正的降本手段是将来把 worker 与 extract 合并成一个「执行者」角色**
（队列 + 同步共用一套语言服务器池），但那需要先解决「同步请求与队列任务争抢 LSP 并发」
的调度问题——不在本轮范围。

#### 5.9.4 为什么 `gateway` 的 `depends_on` 不包含 `worker`（决策 2 的补充 (a)）

**不加，而且这是一条应当刻意保持的边界。** 三条理由：

1. **`depends_on: condition: service_healthy` 是启动阻塞。** 若 gateway 等 worker 健康，
   那么「worker 崩了 → 重启中」会连带让**整个 API 无法启动**，包括与队列毫无关系的只读端点
   （`GET /v1/bundles*`、`GET /v1/lsp/probe`、`GET /health`）。
   这是把「一个消费者不健康」升级成「全站不可用」。
2. **worker 不健康时 gateway 仍有正确行为**：入队照旧成功（只写 Redis），
   job 停在 `queued`（前端显示「排队中」）。这正是队列存在的意义——**生产与消费解耦**。
   把它接回启动依赖，等于把解耦又缝上。
3. **`depends_on` 表达的是「启动顺序」，不是「健康依赖」。** gateway 确实需要 Redis
   （`condition: service_healthy`），因为它写状态；但它**不需要 worker 存在**才能工作。

**要观测「worker 不在」，应该用别的机制**：

* `GET /health` 的 `capabilities.queue` 加 `workers_alive`（读 `aegis:queue:heartbeat`
  与 `XINFO GROUPS` 的 `consumers`）+ `pending` + `lag`；
  没有任何 worker 心跳时 `status="degraded"`，`reason="no worker has heartbeated in N s"`。
* 编排层（`restart: unless-stopped` + 外部监控）负责把 worker 拉起来。
* 前端在列表页显示「队列有 N 个任务在排队，最近一次 worker 心跳 X 秒前」。

#### 5.9.5 `worker` 镜像与 `docker/Dockerfile`

**`docker/Dockerfile`：不需要改。** 逐条核对：

* `aegis_contracts/`、`aegis_core/`、`services/`、`app/` 已在 `COPY` 列表（L151–154），
  `services/queue/` 与 `services/extraction/` 随 `services/` 一起进去（迁移后 `app/` 只剩网关外壳，仍在 COPY 列表里）；
* 构建期 import 断言（L161）**顺手加** `services.queue.worker` 与 `services.extraction.pipeline.assemble`，
  让「queue 包漏了依赖」在构建期暴露，而不是在容器启动 `aegis-worker` 时暴露；
* `pip install ".[all]"`（L144–145）会带上新的 `redis` 依赖，无需改；
* `USER aegis` + `/data` 可写（L169–172）已满足 worker 写 `/data/packages` 与 staging 目录；
* `ENTRYPOINT` 是 `aegis-entrypoint`（L181），`docker/entrypoint.sh:18` 的
  `exec aegis "$@"` 会把未知子命令交给 `app.cli`。**worker 的 compose
  `entrypoint: ["aegis-worker"]` 直接绕过 aegis-entrypoint**，这是有意的：
  worker 不是「serve」也不是「aegis 子命令」，它有自己的 CLI 与信号处理（§6.1）。
  所以 `entrypoint.sh` **不需要改**。
* **worker 需要语言服务器工具链 → 必须用 `docker/Dockerfile` 那个 1.9 GB 镜像，
  不能用 `services/scan/Dockerfile`。** 这正是「与 extract 共用镜像」的实质内容：
  不是省一次构建，而是**worker 必须有能力自己 spawn 语言服务器**（§5.4.1 的结论）。

**`services/scan/Dockerfile`：不需要改**（scan 不参与队列，也不 import `services.queue`）。

### 5.10 修改：`app/main.py`

`create_app()`（L31–50）里 `app.include_router(router)` 之后加
`app.include_router(jobs_router)`；`lifespan`（L19–28）**不改**——
gateway 不消费队列，不需要在启动时建 consumer group（那是 worker 的事，见 §6.1）。

### 5.11 修改：`app/cli.py`（**已定：加**）

新增子命令 `aegis enqueue --workspace … [--rule-config …] [--follow]`：
提交到队列并打印 `job_id`；`--follow` 时每 1s 轮询 `GET /v1/jobs/{id}`，
按行打印「阶段 + 耗时 + 漏斗计数」直到终态，退出码 0（succeeded）/ 1（failed）/ 2（canceled）。
约 30 行，用现成的 `httpx`。**价值**：本地不依赖前端就能看阶段进度，
这是调试队列本身（而不是调试流水线）最省事的路径。

### 5.12 修改：`.gitignore` + `demo/` 夹具进仓库（**决策 3：已定，且已落地**）

> **状态更新（写方案期间仓库已前进）**：这一节的三件事**已经在工作树里做好了**
> （`.gitignore` 的 `demo/*` + `!demo/repo/`、`demo/repo/` 的 4 个文件、
> `tests/fixtures.py` 的幂等化、`pyproject.toml` 的 `extend-exclude = ["demo"]`、
> `tests/test_demo_fixture.py`）。本节保留**判据与验证命令**，
> 目的是让评审能核对「做对了没有」，以及让后来人知道**为什么是这个写法**。
> 与本文其余章节不同，这一节不是 TODO 而是验收清单。

**问题（`§0` 事实 (2)）**：原先 `.gitignore:17` 整条 `demo/` 被忽略，
而 `demo/repo/` 是 `scripts/demo.py:50` 调 `tests/fixtures.py::write_fixture()` **生成**的。
于是从干净克隆开始，`docker compose up` 把 `${AEGIS_SCAN_TARGET:-../demo/repo}`
挂成**不存在的目录**，Docker 会创建一个空目录，**静默扫出 0 命中**
（没有任何报错，bundle 看起来正常但是空的）。

**`.gitignore` 的正确写法**（Git 的规则：**父目录被忽略后，子文件无法用 `!` 救回**，
所以必须先放开父目录本身，再逐级取反）：

```gitignore
# --- local runtime state -------------------------------------------------
var/
workspace/
# The demo workspace is checked in on purpose: docker-compose.yml mounts
# ../demo/repo, and while that directory is ignored Docker creates an *empty* one
# and scans it, producing a normal-looking empty bundle with no error at all.
# Everything else under demo/ is generated by scripts/demo.py and stays ignored:
# lsp.yaml holds this machine's interpreter path, scan.sarif is a build product.
# Note the form: ignoring `demo/` as a whole would make the negation impossible,
# because git never descends into an excluded directory.
demo/*
!demo/repo/
demo/repo/__pycache__/
.env
docker/lsp.local.yaml
```

`demo/*` 只忽略 `demo/` 的**直接子项**（`repo`、`lsp.yaml`、`scan.sarif`…），
`!demo/repo/` 把 `repo` 目录本身取回来，于是 `demo/repo/*.py` 自然被跟踪
（因为 `demo/` 与 `demo/repo/` 都不再是被忽略的父目录）。
`demo/lsp.yaml` 与 `demo/scan.sarif` **不需要**额外的具名忽略行——
它们留在 `demo/*` 的忽略范围里，永远救不回来；
**不要**把 `!demo/repo/` 写成 `!demo/`，那会把这两个生成物一起放进来。

**验证命令**（改完 `.gitignore` 之后必须跑，任何人重构这段注释前也要跑）：

```powershell
git check-ignore -v demo/repo/handler.py     # 期望：无输出（= 不被忽略）
git check-ignore -v demo/lsp.yaml            # 期望：.gitignore:NN:demo/*（= 仍被忽略）
git check-ignore -v demo/scan.sarif          # 期望：.gitignore:NN:demo/*（= 仍被忽略）
git status --porcelain demo/                 # 期望：只列 demo/repo/ 下的 4 个 .py
```

**`demo/lsp.yaml` 为什么不进仓库**：它由 `scripts/demo.py:28-38 build_lsp_config()` 生成，
内容是 `command: ['<sys.executable 的绝对路径>', '<仓库绝对路径>/tests/fake_lsp_server.py', …]`
（实测当前内容是 `C:\Users\74768\…\python.exe` + `E:/vib coding/aegis/tests/fake_lsp_server.py`）。
**它是本机路径，进仓库对别人不但无用还有害**（会在 CI 上指向不存在的解释器，
表现为「demo 突然没有 LSP 了」）。

**`demo/scan.sarif` 为什么不进仓库**：它是 `write_sarif()` 的生成物，
且 SARIF 里含**绝对 URI**（`tests/fixtures.py` 用 `workspace.resolve().as_uri()`）。
进仓库会把某台机器的路径固化下来，同时制造一个「看着像输入其实是输出」的文件。

**`scripts/demo.py` 覆盖生成物会不会造成漂移？** 会发生，但**方向是安全的**。
仓库里已经落地的处置是「**只在内容不同时才写**」，逐条核对如下：

* `scripts/demo.py:50` 是 `workspace = write_fixture(demo / "repo")`；
  `tests/fixtures.py::write_fixture`（当前 L84–97）**逐文件比较内容，相同就 `continue`**，
  不同才 `write_text`。所以重复跑 demo **不会 churn mtime**，
  `git status` 保持干净，也就不会让「仓库里的夹具」和「demo 生成的夹具」漂移。
* **安全的原因**：那 4 个文件的内容是同一个模块里的常量
  （`tests/fixtures.py` 的 `FILES` / `HANDLER` / `SERVICE` / `REPO` / `UTIL`）。
  只要没人手改 `demo/repo/`，重写就是**逐字节幂等**的。
* **残留的风险（必须知道）**：有人为了试一个想法手改了 `demo/repo/repo.py`，
  下一次跑 demo 时会被**静默覆盖**（幂等化只避免无谓重写，不保护真实差异）。
  缓解是行为性的而非代码性的：**`demo/repo/` 现在是受版本控制的文件，
  改它要在 git 里看得见**——想试想法请改 `tests/fixtures.py` 的常量，
  或复制一份到别处用 `--demo-dir` 指向。
* **为什么不用「差异就抛错」**：那会让「刷新夹具」变成两步操作
  （先 `git checkout` 再跑），而 demo 的主要用途恰恰是生成夹具。
  **如果评审更在意保护性**，把它改成「差异时 `raise SystemExit` 并提示
  `git checkout -- <path>`」只需 4 行，`tests/test_demo_fixture.py` 里加一条用例即可。
  **我倾向保留现状**（幂等写入），因为它同时满足两个目标：
  demo 可重复运行，且仓库夹具不会被无声改坏——因为任何**真实**差异在
  `git status` 里都是可见的。

### 5.14 迁移 `app/` → `services/extraction/`（**决策 4：先做迁移，再落地队列**）

早先的草案建议「先建队列、后迁移」。**用户选了相反的顺序，本节按迁移在前重写**，
并给出迁移后的最终包结构、`observability` 的归属判定、以及一份**机械可验证**的检查清单。
（`HANDOVER §11.4` 的顺序提醒也是「先迁移更省事」，与本决策一致。）

#### 5.14.1 迁移后的最终包结构

**为什么必须先看清顶层依赖图**：迁移不只是"挪目录"——它**顺带解掉一个真实的顶层环**。
以下是用 AST 扫全仓库实测的顶层包边（脚本只读、已删；与用户独立扫出的数字一致）：

```
aegis_contracts -> aegis_core          1     ← 见 §5.14.7（一处漂移）
app             -> aegis_contracts    13
app             -> aegis_core         31
app             -> services            6     ┐ 双向环
services        -> aegis_contracts     6     │
services        -> aegis_core         10     │
services        -> app                 3     ┘ ← app -> services 与它是环
scripts         -> app 2 / aegis_core 2 / aegis_contracts 1 / tests 1
tests           -> app 31 / services 19 / aegis_core 12 / aegis_contracts 5
```

`app -> services` 的 6 处与 `services -> app` 的 3 处，逐行如下（实测）：

| 方向 | 行 |
|---|---|
| `app -> services` | `app/api/routes.py:43` `services.extraction.client`、`:48` `services.scan.opengrep`、`:70` `services.scan.client`；`app/pipeline/assemble.py:46` `services.scan.client`、`:47` `services.scan.runner`、`:48` `services.scan.scanrecord` |
| `services -> app` | `services/extraction/routes.py:17` `app.pipeline.assemble`、`:124` 与 `:125` `app.api.deps`（`probe_lsp` 与 `resolve_workspace`） |

**这个环是这次迁移真正的收益**：迁移完成后，
`app/pipeline` → `services/extraction/pipeline` 的那两条边变成包内边，
`services/extraction/routes.py:17` 从"反向 import 一个叫 `app` 的包"变成正常的同级 import，
顶层图里 **`services -> app` 归零**（见 §5.14.5 第 11 条的机器断言）。
「目录整洁」是附带效果，**「顶层包图无环」才是可验证的设计产出**。

迁移后的最终结构：

```
aegis_contracts/          ← 共享数据形状（+ 本方案新增 jobs.py、下沉的 views.py）
  domain.py  jobs.py  views.py
aegis_core/               ← config / logging / utils（不变）
services/
  scan/                   ← 不变（独立小镜像；与队列无关）
  extraction/             ← 原 app/ 的能力部分 + 它自己的 HTTP 入口
    __init__.py  app.py  routes.py  client.py      ← 三者已有
    pipeline/  graph/  lsp/  parsers/  assembler/  ← 从 app/ 搬来
  queue/                  ← ★ 本方案新增，独立于 extraction（理由见 §5.14.3）
    __init__.py  keys.py  jobs.py  streams.py  reaper.py  cancel.py
    observer.py  worker.py
  web/                    ← 不变（待建）
app/                      ← gateway 外壳，只剩 5 项
  __init__.py             ← 只留 __version__
  main.py                 ← gateway 的 ASGI 入口（uvicorn app.main:app 不变）
  api/routes.py           ← gateway 的路由
  api/deps.py             ← gateway 的依赖装配
  schemas/api.py          ← ★ 留在网关：实测**只有** app/api/routes.py:35 在用它，
                            而 extraction 的 HTTP 契约是它自己的 ExtractBody/ExtractResult
                            （services/extraction/routes.py:27-52）。搬进 extraction 只会让
                            网关反向依赖它。见 §5.14.8
  cli.py                  ← 本地 CLI
```

**`app/` 迁移后只剩这 5 项**，它们全部属于 **gateway 侧**（对外 API + 查询），
外加 `app/cli.py` 这个本地开发入口。**这个"剩下什么"就是这次迁移真正的设计产出**：
`app/` 从"业务逻辑本体"缩小成"网关外壳"。

**`app/` 内部边也是无环的一条链**（实测，这决定了"整体搬运"是安全的机械操作）：

```
app.api       -> app.lsp 1, app.observability 1, app.pipeline 2, app.schemas 1
app.pipeline  -> app.assembler 4, app.graph 3, app.lsp 1
app.assembler -> app.graph 3
app.graph     -> app.lsp 6, app.parsers 2
app.lsp       -> （只 import 自己）
app.parsers   -> （只 import 自己）
```

即 `pipeline → assembler → graph → {lsp, parsers}` **没有反向边**，
所以 `git mv app/{pipeline,graph,lsp,parsers,assembler} services/extraction/` 之后
包内 import 只需改前缀。**唯一的跨界边是 `app.api -> app.observability`**，
它就是 §5.14.2 要判的那一条。

#### 5.14.2 `observability` 归属判定（迁移里唯一的设计问题）

> **状态更新（实测：写方案期间迁移已经落地）**：工作树里的迁移把 `views.py` 放到了
> **`services/extraction/observability/views.py`**（即下面的**方案 (a)**），
> 而 `app/api/routes.py:33` 现在是
> `from services.extraction.observability import views`。
> 也就是说 **gateway 的只读查询视图已经依赖 extraction 包**。
> **本轮不改**（迁移刚落地、测试基线还在动，此刻再动它只会让 diff 更乱），
> 但**必须记一条跟进项**——理由见下方"为什么 (a) 是错的"。
> **判据没有变**：`views.py` 仍然只 import `aegis_contracts.domain`
> （实测 `services/extraction/observability/views.py:22-33`），
> 所以搬到 `aegis_contracts/views.py` 依然是**纯搬运 + 改 4 个 import**，
> 成本没有因为迁移落地而上升。
>
> **跟进项（独立提交，不要混进队列 PR）**：
> `git mv services/extraction/observability/views.py aegis_contracts/views.py`，
> 改 4 处消费方 import（`app/api/routes.py:33`、`tests/test_observability.py`、
> `tests/test_scan_stage.py`、`scripts/observe.py`）；
> 验收 = `git diff --find-renames` 显示 `R100` + `python -m pytest -q` 计数不变 +
> `services -> app` 仍为 0。

**实读事实**：`views.py` 的 import 只有 `collections` / `dataclasses` / `typing` 与
**`aegis_contracts.domain`**——没有 I/O、没有 pipeline / graph / lsp。
也就是说它**已经是一个纯函数模块**，搬到哪里都不改变行为。

**消费方（实读，四个）**：

| 消费方 | 位置 | 它需要什么 |
|---|---|---|
| gateway 路由 | `app/api/routes.py:33` `from app.observability import views`，用到 `views.overview/funnel/timeline/providers/scan_summary/context_views/method_index/diff`（L306–347）、`views.PROVIDER_NOTES`、`views.STAGE_LABELS` | 在**本进程**把 manifest 变成 JSON |
| 测试 | `tests/test_observability.py:20`、`tests/test_scan_stage.py:371` | 直接调函数做断言 |
| CLI 脚本 | `scripts/observe.py:15` | 在**本进程**打印视图 |
| 控制台服务 | `frontend/` | 只消费 HTTP JSON，不需要这个模块 |

**四个候选，逐个判**：

| 方案 | 判 |
|---|---|
| (a) 留在 `app/observability/`（gateway） | 可行，但 `app/` 迁移后 gateway 侧还挂着一个"业务视图"目录，而 §5.14.1 的意图是让 `app/` 只剩网关外壳 |
| (b) 移进 `services/extraction/observability/` | **最差**。它就是 `app/api/routes.py` 调用的东西，而 `observability` **不是 extraction 的能力**（extraction 不 import 它，实读确认）。搬进去要么让 gateway 远程调 extraction 拿视图（**把一次纯函数调用变成一次网络调用 + 让只读查询依赖重活服务**），要么让 gateway 依赖 extraction 包（**跨服务 import，正是部署边界要禁止的**） |
| **(c) 下沉到 `aegis_contracts/views.py`** | **建议**。四个消费方里有两个（gateway 路由、测试/脚本）需要**同进程**调用；契约层是唯一同时被它们依赖、且已被 `tests/test_contracts.py` 把守的地方。搬运是 `git mv` + 改一行 import，**内容逐字节不变** |
| (d) 新建一个 `aegis_views/` 包 | 多一个包、多一套打包配置，且它需要 `aegis_contracts`——比 (c) 多一层，收益为零 |

**选 (c)。五条理由：**

1. **它是"合同的派生视图"，不是"某个服务的功能"**：输入是 `AnalysisBundleManifest`
   （已在 `aegis_contracts`），输出是纯 dataclass。这正是契约层该放的东西。
2. **它实测只 import `aegis_contracts`**（不 import pipeline / graph / lsp），
   所以搬运是 `git mv` + 改一行 import，**内容逐字节不变**（`git diff` 应显示 `R100`）。
3. **下沉到 `aegis_contracts` 不会被 `tests/test_contracts.py` 误伤**：
   该文件的 `banned` 集合是
   `{fastapi, uvicorn, starlette, httpx, requests, subprocess, socket, redis}`
   ——**不含 `json` / `pathlib` / `dataclasses`**；而 `views.py` 连这些都不用
   （只有 `collections` / `dataclasses` / `typing` / `aegis_contracts.domain`）。
   它禁的是「反向依赖 `app`/`services`」与「I/O 框架」，**不禁止把纯视图放进契约层**。
   （另注：`aegis_contracts -> aegis_core` 那条边已经存在，见 §5.14.7，
   所以"契约层只能依赖 pydantic"本来就不是当前的既成事实。）
4. **保住了 `ARCHITECTURE §9` 的性质**：「observability 是视图层，不是第二个真相源。
   删掉这个模块或控制台都不能改变一个 bundle」——下沉后这句话更强：
   它连"属于哪个服务"都没有了。
5. **保住了端口策略与"gateway 不做重活"原则**：`GET /v1/bundles/{id}/observability`
   仍在 gateway **本进程**从磁盘读 manifest + 算视图（读文件 + 纯计算，
   和 `GET /v1/bundles/{id}/manifest` 一样轻）。**不影响端口策略**（没有新端口），
   **不违反"不做重活"**（重活 = 语言服务器/扫描/组装，视图计算是微秒级）。

**方案 (a) 为什么是错的（这是本条最值得评审的一点）**：把 `observability` 搬进
`services/extraction/` 之后，`app/api/routes.py` 要么
(i) `from services.extraction.observability import …` —— 于是**网关的只读查询依赖 worker 的能力包**，
两个容器共用镜像这一点掩盖了它，但依赖方向已经错了；
要么 (ii) 改成远程调 extraction 拿视图 —— **把一次纯函数调用变成一次网络调用**，
并且让「查一个已经存在的 bundle」这件事**依赖 extract 容器活着**。
后者直接违反 `SERVICE_TOPOLOGY.md` 的分工表（api 是"orchestrate, store, serve queries"，
它自己就该能回答查询）。**方案 (b)**（留在 `app/observability/`）可行但让
`app/` 不是薄层，与 §5.14.1 的意图冲突。**方案 (d)**（新建 `aegis_views/` 包）
需要自己依赖 `aegis_contracts`，比 (c) 多一个包与一套打包配置，收益为零。

**`tests/test_contracts.py` 里要跟着改的一处（机械改动，不是语义改动）**：

```python
def test_no_module_reads_static_assets_through_the_api_anymore() -> None:
    routing = (ROOT / "app" / "api" / "routes.py").read_text(encoding="utf-8")
    # 断言一个字都不改：迁移不改路由内容，只改它的 import 来源
```

**同一个 PR 里不要顺手做的事**：不要借机把 `views.py` 里的 dataclass 改成 pydantic
（那会改变 JSON 序列化的字段集合，属于契约变更，不是迁移）。

#### 5.14.3 `services/queue/` 为什么不能挂在 extraction 下

队列是 **gateway 与 worker 共用**的：gateway 要读写 `JobStore`（建 job、查 job、写
`cancel_requested`），worker 要消费 Stream。所以：

* 放 `services/extraction/queue/` → **gateway 必须 import extraction 包**才能入队。
  gateway 镜像里于是又有整套提取代码，"gateway 不做重活"从"不调用"退化成"不调用但带着"，
  且将来 gateway 想瘦身也瘦不掉。
* 放 `app/queue/`（迁移前草案的写法）→ migration 后 `app/` 只剩网关外壳，
  把一个**跨服务**的包挂在网关外壳下，同样错。
* **放 `services/queue/`（建议）**：与 `services/scan/`、`services/extraction/` 平级，
  语义是「一个能力包，不是必须独立部署的服务」。**注意 `services/` 下本来就有两个不同的东西**：
  `services/scan/` 与 `services/extraction/` 是"能力包 + 各自的服务入口"，
  `services/queue/` 是"能力包 + 一个 CLI 入口（`aegis-worker`）+ 一组给 gateway 用的读函数"。
  **没有 `services/queue/Dockerfile`**，也没有独立的 queue 容器——
  worker 容器用的仍是 `docker/Dockerfile`（§5.9.5）。这一点要在 `SERVICE_TOPOLOGY.md` 里写清楚，
  否则"services/ 下有 4 个目录、compose 里只有 3 个服务"会让人困惑。

`aegis-worker` 入口：`services/queue/worker.py::main` →
`pyproject.toml` 的 `aegis-worker = "services.queue.worker:main"`。
`Worker` 需要 `AssemblyPipeline`，所以它 import `services.extraction.pipeline.assemble`——
**这是允许的方向**（两者都在 `services/` 内，且 worker 与 extract 共用镜像，§5.9.5），
但要有一条测试把它钉住（§7.2 用例 63 的等价物）。

#### 5.14.4 迁移后的导入路径对照表

| 原路径 | 迁移后 | 备注 |
|---|---|---|
| `from app.pipeline.assemble import AssemblyPipeline, PipelineRequest` | `from services.extraction.pipeline.assemble import …` | 出现在 `app/api/routes.py:34`、`app/api/deps.py:14`、`app/cli.py:17`、`scripts/demo.py:24`、`services/extraction/routes.py:17`、5 个测试文件 |
| `from app.observability import views` | `from aegis_contracts import views` | `app/api/routes.py:33`、`scripts/observe.py:15`、2 个测试文件 |
| `from app.lsp.manager import LanguageServerManager, load_catalog` | `from services.extraction.lsp.manager import …` | `app/api/deps.py:13`、`app/lsp/*` 内部、测试 |
| `from app.assembler.* / app.graph.* / app.lsp.* / app.parsers.*` | `from services.extraction.<同名>` | **包内相对导入保持原样**（`app/assembler/render.py:40` 的 `from app.assembler.contexts import …` → `from services.extraction.assembler.contexts import …`；或改成 `from .contexts import …`，两者都可以，**但不要混用风格**) |
| `from app.schemas.api import …` | `from services.extraction.schemas.api import …` | `app/api/routes.py:35` |
| `from app.main import create_app` | **不变**（`app/main.py` 留在 gateway） | `tests/test_api.py:9` |
| `from app.api.deps import clear_pipeline_cache / probe_lsp / resolve_workspace` | **不变**（路径不变，但它内部 import 的 `app.lsp.manager` / `app.pipeline.*` 要改） | `tests/test_observability.py:18`、`services/extraction/routes.py:124-125` |
| `services/extraction/routes.py:17` 的 `from app.pipeline.assemble import …` | `from services.extraction.pipeline.assemble import AssemblyPipeline, PipelineRequest` | **这次迁移最实质的收益**：extraction 的 HTTP 入口终于不再反向 import 一个叫 `app` 的包 |
| `uvicorn app.main:app`（`docker/entrypoint.sh:9`） | **不变** | 条目名不变 → entrypoint、compose、healthcheck 全都不用动 |
| `uvicorn services.extraction.app:app`（compose `extract` 的 entrypoint） | **不变** | |

**`services/extraction/routes.py:124-125` 那个 `from app.api.deps import probe_lsp`（函数内导入）
是一个跨边界的反向依赖**，迁移后它变成
`from app.api.deps import probe_lsp`（路径不变但语义更刺眼了：**extraction 的 HTTP 入口
import 网关的依赖装配模块**）。**迁移后它必须改**：把 `probe_lsp` 的实现搬进
`services/extraction/lsp/probe.py`，gateway 的 `/v1/lsp/probe` 与 extraction 的
`/v1/lsp/probe` 各自 import 它自己那侧的路径。
**这条不改的话，`app/` 迁移后的"网关外壳"仍然被 extraction 反向依赖，边界是假的。**
`tests/test_contracts.py` 的 `test_every_service_dependency_is_satisfiable_from_shared_packages`
目前对这条**没有约束力**（它只对 `services/*` 的 import 做了一次 `isidentifier()` 检查），
所以迁移时顺手加一条真断言（§5.14.5 第 4 条）。

#### 5.14.5 机械可验证的迁移检查清单

迁移的验收不能靠"我看了一遍"。以下命令**逐条可执行**，全绿才算迁完。
（路径按仓库根目录；PowerShell 版本，`grep -rn` 用 `Select-String` 的等价写法。）

| # | 断言 | 命令 | 期望 |
|---|---|---|---|
| 1 | **没有代码再 import `app.`** | `Select-String -Path (Get-ChildItem -Recurse -Filter *.py -Path app,services,tests,scripts).FullName -Pattern "^\s*(from\|import) app\."` | 只允许剩 `app/main.py` 的 `from app.api.routes import router`、`app/api/*` 的内部互引、`app/cli.py`、`app/api/routes.py` 的内部互引。**`services/` 与 `tests/` 下必须为空** |
| 2 | **`services/` 不 import `app.`** | `Select-String -Path (Get-ChildItem -Recurse -Filter *.py -Path services).FullName -Pattern "from app\.\|import app\."` | **0 命中**（这是"部署边界是真的"的唯一可执行证据） |
| 11 | **顶层包图无环（`services -> app` 归零）** | 把下面那段 12 行的 AST 脚本跑一遍（或加进 `tests/test_contracts.py`，见下） | `services -> app` **必须是 0**；`aegis_contracts -> aegis_core` 必须**恰好是 1**（§5.14.7 的既有漂移，防止它长大） |

**第 11 条建议直接做成测试**（加进 `tests/test_contracts.py`，与既有的 AST 扫法同风格）。
它比"目录整洁"更能守住这次迁移的收益：

```python
def test_no_service_depends_on_the_gateway_shell() -> None:
    """After the move, `services/` must not import `app` at all.

    Before the move this was a real cycle: app -> services (6 edges) and
    services -> app (3 edges: app.pipeline.assemble, and app.api.deps twice for
    probe_lsp / resolve_workspace). Breaking it is the point of the migration.
    """
    offenders = [
        f"{path.relative_to(ROOT)}: {module}"
        for path in (ROOT / "services").rglob("*.py")
        for module in _imports(path)
        if module.split(".")[0] == "app"
    ]
    assert not offenders, "services reached back into the gateway shell: " + "; ".join(offenders)


def test_the_contract_layer_only_reaches_core_once() -> None:
    """`aegis_contracts -> aegis_core` is an existing, deliberate exception (see
    docs/QUEUE_PLAN.md §5.14.7). Pin it at exactly one so it cannot grow."""
    edges = [
        (path, module)
        for path in (ROOT / "aegis_contracts").rglob("*.py")
        for module in _imports(path)
        if module.split(".")[0] == "aegis_core"
    ]
    assert len(edges) == 1, f"contract->core edges grew: {edges}"
```
| 3 | **`app/` 只剩 5 项** | `Get-ChildItem app -Force \| Select-Object Name` | `__init__.py`、`api/`、`cli.py`、`main.py`（+ `__pycache__`）。**没有** `pipeline/ graph/ lsp/ parsers/ assembler/ schemas/ observability/` |
| 4 | **共享层不反向依赖** | `Select-String -Path (Get-ChildItem -Recurse -Filter *.py -Path aegis_contracts,aegis_core).FullName -Pattern "^\s*(from\|import) (app\|services)\."` | **0 命中**（既有 `tests/test_contracts.py` 已覆盖，这里给出等价的 shell 版便于人工核对） |
| 5 | **`observability` 已下沉且内容未变** | `git diff --stat app/observability/views.py aegis_contracts/views.py` | 显示的是**重命名**（`R100`，即 100% 相似度）；若有内容差异，必须解释 |
| 6 | **打包配置同步** | `python -c "import services.extraction.pipeline.assemble, services.queue, aegis_contracts.views; print('ok')"` | `ok`（`pyproject.toml` 的 `packages.find` 也要能发现它们） |
| 7 | **入口名未变** | `Select-String -Path docker\entrypoint.sh -Pattern "uvicorn"`、`docker compose -f docker/docker-compose.yml config --services` | 仍 `app.main:app`；服务清单仍是 `scan/extract/gateway` |
| 8 | **测试全绿 + 计数不变** | `python -m pytest -q -rs` | `124 passed, 2 skipped`（**迁移不改行为，计数必须一样**） |
| 9 | **构建期 import 断言同步** | `Select-String -Path docker\Dockerfile -Pattern "python -c"` | 断言里出现的是 `services.extraction.*` 而不再是 `app.pipeline.*`（两个 Dockerfile 都要看） |
| 10 | **`pip install -e .` 之后仍可导入** | `pip install -e ".[dev]" && python -c "import app.main, services.extraction.app, services.queue"` | 三个都成功（本地是 editable 安装，最容易漏掉 `packages.find` 没更新） |

**`pyproject.toml` 的确切改动**：

```toml
[tool.setuptools.packages.find]
include = [
    "app*",                      # gateway 外壳（迁移后只剩 5 项）
    "aegis_contracts*",
    "aegis_core*",
    "services*",                 # scan / extraction / queue / web 都在这一条下
]
```

`services*` 这一条本来就覆盖 `services.extraction.*` 与 `services.queue.*`，
所以**迁移本身不需要改 `packages.find`**——但要在验收里跑第 6、10 条，
因为"不需要改"正是最容易假设错的地方。

#### 5.14.6 一处需要记录的既有漂移：`aegis_contracts -> aegis_core`

**结论一句话**：那 1 处是
**`aegis_contracts/domain.py:22` 的 `from aegis_core.utils import estimate_tokens`**
（用在 `AnalysisBundle.recompute_totals()`，`domain.py:307`），
**不是新引入的环，但确实与 `docs/SERVICE_TOPOLOGY.md` 的措辞冲突**——
那里写「`aegis_contracts` 是依赖图的最底层」，而它实际依赖了 `aegis_core`。

判据：`estimate_tokens` 是**纯函数**（`aegis_core/utils.py`，无 I/O），
所以这不是架构灾难，而是**分层措辞不准**。两种可能的读法：

| 读法 | 评价 |
|---|---|
| 有意：契约层可以依赖"纯工具" | 合理，但 `aegis_core` 还含 `config.py`（pydantic-settings）与 `logging.py`，把它们一起拖进契约层的依赖闭包 |
| 漂移：`estimate_tokens` 该属于契约层 | 更可能。`AnalysisBundle` 是契约模型，它算 token 估算用的是纯函数，放进 `aegis_contracts/utils.py` 更自洽 |

**本轮不修**（用户明确：如果是漂移，不要在本轮修，但要写明）。理由：
(a) 它不在本次迁移的路径上，修它会扩大 diff；(b) 把 `estimate_tokens` 搬到
`aegis_contracts` 会与 `aegis_core.utils` 形成重复（两个同名函数）或强迫 `aegis_core`
反向依赖契约层——**那是另一个决策**。
**要做的是把它钉住**：§5.14.5 第 11 条的
`test_the_contract_layer_only_reaches_core_once` 断言这条边**恰好 1 个**，
这样它既不会悄悄长大，也不会被人"顺手"删掉而没人知道。
**建议在 `SERVICE_TOPOLOGY.md` 的"共享契约"一节补一句**：
「`aegis_contracts` 目前对 `aegis_core.utils` 有一处纯函数依赖（`estimate_tokens`），
是已知例外，见 `docs/QUEUE_PLAN.md` §5.14.7」——**改措辞，不改代码**。

**`docker/Dockerfile` 的确切改动**：`COPY` 列表（`aegis_contracts`、`aegis_core`、`services`、`app`）
**四个都在，不用加也不用减**（迁移是 `app/` 内部搬家，不是新增顶层目录）。
唯一要改的是构建期 import 断言（L161 附近）里的模块名：
`app.api.routes`（不变）+ 把 `services.scan.client` 换成/补上
`services.extraction.pipeline.assemble` 与（步骤 4 之后）`services.queue.worker`。
**`services/scan/Dockerfile` 不受影响**（它只 COPY `services/`，而 `services/scan/` 没动）。

**`tests/` 的改动面（实测）**：`grep` 出**28 个文件**含 `from app.` / `import app.`
（4 个在 `app/assembler`、4 个在 `app/lsp`、3 个在 `app/graph`、2 个在 `app/api`、
1 个在 `app/pipeline`，其余在 `tests/`、`scripts/`、`services/extraction/`，加上 `app/main.py` 与 `app/cli.py`）。
其中**包内引用**（`app/assembler/render.py` 这类）随目录一起搬、只需改前缀；
**真正要人判的是 9 个测试文件 + 2 个脚本 + 1 个 `services/extraction/routes.py`**。
**建议的机械做法**：先 `git mv app/<sub> services/extraction/<sub>`，
再对**包内**文件做一次
`(Get-ChildItem -Recurse services/extraction -Filter *.py) | ForEach-Object { (Get-Content $_ -Raw) -replace 'from app\.', 'from services.extraction.' | Set-Content $_ }`
——**但这一行 PowerShell 会改变文件编码，不要直接用**（本文档的作者踩过：
它把 UTF-8 中文注释写坏过一次）。用 `python -c` 或 ruff/IDE 的"重命名模块"功能，
或者干脆逐个文件手改并用第 1、2 条断言兜底。**改完必须跑第 8 条（测试计数不变）。**

#### 5.14.7 迁移与队列的先后：为什么必须先迁移

用户已定「先迁移、再落地队列」，理由在实读之后更充分：

1. **队列要 import 的能力全在被迁移的目录里**：`AssemblyPipeline`
   （`app/pipeline/` → `services/extraction/pipeline/`）、`ScanOnlyPipeline`、
   `run_scan_anywhere`（`services/scan`，不动）。
   先建队列意味着写一遍 `from app.pipeline…`，迁移时再改一遍。
2. **队列自己的落点依赖迁移结果**：`services/queue/` 这个位置只有在
   `services/extraction/` 已经成型、`app/` 已经缩成网关外壳之后才"看起来自然"；
   先建队列会先落一个 `app/queue/`，然后在迁移里被迫再搬一次（本文早先草案建议的"先建队列、后迁移"正是这个成本，已被决策 4 推翻）。
3. **迁移顺手解掉顶层环**（§5.14.1）：`services -> app` 归零之后，
   worker 从一开始就写正确的路径，而不是先写错的再改。
4. **迁移的验收标准是"测试计数不变"（第 8 条）**，这是一个极强的"行为未变"证据；
   有了它，后面所有队列改动都站在一个干净的基线上。

**迁移时的纪律（来自 `docs/SERVICE_TOPOLOGY.md` 迁移表）**：**一次只搬一层**，
每步 `python -m pytest -q` 全绿，**不要**把 `observability` 下沉、`probe_lsp` 搬家、
队列新增混进同一个提交。建议提交序列：
① 纯 `git mv` + 导入重写（计数不变）；
② `observability` 下沉到 `aegis_contracts/views.py`（计数不变，`git diff` 显示 R100）；
③ `probe_lsp` 从 `app/api/deps.py` 搬到 `services/extraction/lsp/probe.py`（计数不变，`services -> app` 归零）；
④ `.gitignore`/`demo` 与迁移无关，**不要**塞进这个 PR。

#### 5.14.8 `app/schemas/api.py` 留在网关（已实测确认）

**实测**：`app/schemas/api.py` 的**唯一**消费者是 `app/api/routes.py:35`；
而 extraction 的 HTTP 契约是它**自己**的 `ExtractBody` / `ExtractResult`
（`services/extraction/routes.py:27-52`），**不 import `app.schemas`**。

**结论：留在 `app/schemas/api.py`**（即 gateway 侧）。三条理由：

1. 它描述的是 **gateway 的对外请求/响应形状**（`AssembleRequest` / `AssembleResponse` /
   `ScanRequest` / `HealthResponse` / `LspProbeResponse`），不是提取能力的一部分。
2. 搬进 `services/extraction/schemas/` 会让 **gateway 反向依赖 extraction 包**
   （`app/api/routes.py` 要用 `AssembleRequest` 做请求校验），
   正好与迁移要达成的"`services -> app` 归零"对称地制造一条 `app -> services` 的**能力依赖**
   （而现在 `app -> services` 只有 `services.extraction.client` 与 `services.scan.*` 这些**叶子**模块）。
3. 数据契约本身在 `aegis_contracts/domain.py`（`manifest` 字段就是它），
   `app/schemas/api.py` 只是 HTTP 外壳 —— **外壳跟着网关走**。

**唯一要动的**：`app/schemas/api.py` 自己的 import 不用改（它只 import
`aegis_contracts.domain` 与 `aegis_core.config`）。**所以这个文件在迁移里是"零改动"**，
这本身就是"它属于 gateway"的一个佐证。

---

## 6. worker 生命周期与四个失败场景

### 6.1 正常生命周期

```
main()
  setup_logging()
  settings = get_settings()
  if settings.queue.redis_url is None: exit(2) with a clear message   # 别静默什么都不做
  stream.ensure_group()            # XGROUP CREATE … id="0" MKSTREAM，BUSYGROUP 容忍
  store.reconcile_startup()        # 见 §6.3 第 1 层
  worker = Worker(store, stream, settings)
  for sig in (SIGTERM, SIGINT): signal.signal(sig, worker.request_stop)
  worker.serve_forever()
```

主循环每一圈：

```
while not stop_event.is_set() and not self._poisoned:
    maybe_reap()                  # 每 reaper_interval_s
    heartbeat()                   # 每 heartbeat_interval_s（写 aegis:queue:heartbeat + 当前 job 的 worker_heartbeat_at）
    entries = claim(block_ms)     # XREADGROUP … ">" COUNT 1 BLOCK 1000
    if not entries: continue
    message_id, fields = …
    try:
        handle(message_id, fields)
    except CanceledAbort as exc:                                  # 必须在 Exception 之前
        store.mark_canceled(job_id, stage=exc.stage, detail=exc.detail)
    except Exception as exc:                                      # 其它一切 = 失败
        store.fail(job_id, mode=_mode_for(exc), message=str(exc), detail=repr(exc))
    finally:
        ack(message_id)                                           # §4.3：无论成败都 ACK
```

`exit(2)` 那一条是刻意的：**worker 在没有 `redis_url` 时不能"安静地什么都不做"**，
否则运维会以为它在工作。一个明确的启动失败比一个健康的空转进程好得多。

### 6.2 场景 A：graceful shutdown（`docker compose stop worker` / SIGTERM）

1. 信号处理器**只做一件事**：`stop_event.set()`（信号处理器里不做 I/O）。
2. 主循环在 `XREADGROUP` 的 `block=1000` 窗口内返回并检查 `stop_event`。
3. 若当前有任务在执行：
   * **不 XACK、不写失败**——消息留在 PEL 里；
   * 进入 `_drain()`：`teardown.abort(reason="shutdown")`，
     传给 pipeline 的 `abort` 回调在**下一个可中断点**生效（与取消走同一套机制，§6.5.8）；
   * worker 捕获 `CanceledAbort` 后写 **`state=queued`**（**不是 canceled**）
     + `progress.note="worker restarting; job returned to the queue"`，
     然后 **XACK**，再 `XADD` 一次（attempt 不变）。
   * 为什么是 `queued` 而不是 `canceled`：用户没要求取消，
     **把系统重启记成用户取消是撒谎**（`cancel_requested` 保持 `false`，两者可区分）。
4. `SIGKILL` 兜底：compose 的 `stop_grace_period: 30s`；超时被 `SIGKILL` 时走场景 B。

**用户看到什么**：`GET /v1/jobs/{id}` 从 `running` 短暂回到 `queued`
（`progress` 保留已完成的阶段计时，`revision` 递增），随后变回 `running`，
`progress.attempt` 不变。**阶段计时不会丢**——这是把权威状态放 Redis 的直接收益。

### 6.3 场景 B：worker 崩溃（OOM / `docker kill` / 宿主断电）

处置分三层，**每一层都必须能把 job 带出 `running`**：

| 层 | 触发者 | 动作 | 用户看到 |
|---|---|---|---|
| 1. 重启即自检 | 新 worker 启动时的 `store.reconcile_startup()` | 扫 `aegis:jobs` 里所有 `state=running` 的成员；对每个：读 `progress.worker_heartbeat_at`；若产物已在磁盘 → 写 `succeeded`（`note="recovered"`）；否则若 `attempt < max_attempts` → 写 `queued` 并 `XADD`；否则 → 写 `failed(WORKER_LOST)`。**并扫 `state=queued` 的孤儿**（§4.6） | 崩溃后**最多一个 worker 重启周期内**状态就不再是 `running` |
| 2. reaper（`XAUTOCLAIM`） | 任何活着的 worker，每 30s | §4.4 六步裁决 | `running` 超过 `visibility_timeout_s` 且无心跳 → `failed(WORKER_LOST)` 或重投 |
| 3. Redis 侧无兜底 | — | 若**所有** worker 都死了，没人跑 reaper | 状态会停在 `running` 直到有 worker 起来。**这是本方案唯一的静默窗口**，写进 §8 已知代价 |

**第 1 层是最重要的设计**：它不依赖 `XAUTOCLAIM` 的 `min_idle_time` 时钟，
只依赖「谁是 running 但没人认领」这一事实，所以即使崩溃后 5 秒就重启
（远小于 `visibility_timeout_s`），状态也会立刻被带出 `running`。

**续跑 vs 标死的判据（用户要求「能靠已有产物续跑的就续」）**：

```python
def _recoverable(job: Job, settings: Settings) -> Path | None:
    """产物是否已经落盘且可用？可用则不必重跑。"""
    if job.result and job.result.package_path:                       # 1) 显式记录过路径
        candidate = Path(job.result.package_path)
        if (candidate / "manifest.json").is_file():
            return candidate
    bundle_id = compute_bundle_id(job.submission.request)            # 2) 内容派生，重算
    candidate = settings.output_dir / bundle_id
    if (candidate / "manifest.json").is_file():
        return candidate
    return None
```

**注意**：`compute_bundle_id()` 要**同时**被 `AssemblyPipeline.run()`（L167–177）
和这里使用，所以抽成纯函数放进 `app/pipeline/ids.py`，`assemble.py` 改为调用它
（**纯抽取，不改变 L167–177 的计算内容**）。不抽的话两处公式迟早漂移，
而漂移的表现是「明明跑完了却被判成孤儿的 job」——最难查的那类静默错误。

### 6.4 场景 C：Redis 不可用

| 时点 | 谁 | 行为 | 用户看到 |
|---|---|---|---|
| gateway 启动时 | `create_app()` / `lifespan` | **不阻塞启动**。不建连接、不 ping（惰性连接，与 `routes.py:98` 同风格） | 服务正常起来 |
| `POST /v1/assemble` | gateway | `redis.ConnectionError` → **503** `{"detail":"queue unavailable: …"}` | 明确的可重试错误，而不是 500 |
| `GET /v1/jobs/{id}` / `/v1/jobs` | gateway | **503**，不猜、不降级读磁盘 | 明确「状态服务不可用」 |
| `GET /v1/bundles*`（既有只读接口） | gateway | **完全不受影响**（读 `output_dir`，不碰 Redis） | 产物仍可查看：**Redis 挂了不影响已落盘的 bundle** |
| worker 运行中 Redis 断连 | worker | `redis.ConnectionError` → 记日志 → **指数退避重连**（1s→2s→…→30s 封顶）；**当前任务的执行不中断**（pipeline 照跑，只是进度写不进去） | 进度条冻结在最后一个成功写入的阶段；任务本身仍可能成功 |
| worker 恢复后发现终态没写进去 | worker | 重试写终态（最多 5 次）；仍失败则**打印一条 ERROR 并继续**（不因此退出） | 进度停在 `running`；恢复后由 §6.3 第 1 层把它带出 `running` |

**为什么 `GET /v1/jobs/{id}` 在 Redis 挂掉时返回 503 而不是「读磁盘拼一个状态」**：
那会制造第二个真相源，直接违反用户拍板的「进度权威源是 Redis」。
更实际的后果是：磁盘上没有 job_id 与阶段计时的对应关系（只有 `manifest.json`），
拼出来的状态**必然比 Redis 少信息**，而且会与推送不一致。

### 6.5 场景 D：取消（**真取消**，用户已拍板）

一句话：**取消 = 把「一个标志」升级成「一个句柄」。**
标志只能让 pipeline 在阶段边界自己停下；句柄能让 worker 从外面**打断正在阻塞的调用**。

```
POST /v1/jobs/{id}/cancel
   gateway: CAS 写 cancel_requested=True（+ cancel_requested_at）
   worker（每 cancel_poll_ms=50ms 检查一次，带 2s 缓存见下）:
       1. abort() 变 True
       2. 正在阻塞的等待立刻发现（§6.5.4），抛 CanceledAbort
       3. terminate/kill 全部登记进程 + 删 staging 目录
       4. 写 state=canceled, failure=None，XACK
```

#### 6.5.1 需要哪种能力：四个资源，一个句柄

实读结论（**本节的全部依据**）：

| 资源 | 现在怎么起的 | 有没有句柄 | 真取消需要什么 |
|---|---|---|---|
| 扫描子进程 | `services/scan/opengrep.py:164` `subprocess.run(cmd, capture_output=True, text=True, timeout=…)` | **没有**。`subprocess.run` 把 `Popen` 关在内部，只返回 `returncode/stdout/stderr` | 改成 `Popen` + 轮询等待，把 `proc` 登记进 `TeardownHandle`（§6.5.4） |
| 语言服务器进程 | `app/lsp/client.py:96` `subprocess.Popen(...)`，句柄存在 `self._proc`（L72） | **有**。且 `stop()`（L159–182）已实现 `shutdown → exit → wait(2) → terminate() → wait(2) → kill()` 的完整升级链 | 加一条**快路径** `kill()`（跳过协议礼貌），把 manager 登记进句柄；`stop_all()`（`manager.py:212`）本来就有、且能重建 |
| 正在阻塞的 LSP 请求 | `LspClient.request()`（L310–341）在 `pending.event.wait(timeout)` 上阻塞（L329）；调用方 `manager._call`（L254），再往上经 `asyncio.to_thread` 进入 `_expand` / `MethodReader` | **没有中断入口**。`threading.Event.wait()` 只能等它自己超时（`lsp_timeout_s=20s` 默认） | 把 `wait()` 换成「短轮询 + abort 检查」（§6.5.4）。**Python 没有可中断的 `Event.wait`**，只能轮询 |
| staging 目录 | `BundlePackager.write()`（`package.py:81-95`）**直接写最终目录**，没有 `.tmp` 约定 | 没有 | 加 `staging=True`（§5.5 已给出 patch），worker 登记该目录，取消时整目录删 |

```python
class TeardownHandle:
    def __init__(self, *, abort_check: Callable[[], bool], reason: str = "cancel") -> None: ...
    # 判据
    def aborted(self) -> bool: ...
    def raise_if_aborted(self, *, stage: str, resource: str = "stage_boundary") -> None: ...
    # 登记（worker 与 pipeline 都调）
    def register_process(self, name: str, proc: subprocess.Popen) -> None: ...
    def unregister_process(self, name: str) -> None: ...
    def register_lsp(self, manager: LanguageServerManager) -> None: ...
    def register_artifact_dir(self, path: Path) -> None: ...
    # 终止（只由 worker 的 teardown 路径调；幂等）
    def abort(self, *, reason: str = "cancel") -> None: ...
    def kill_all(self, *, terminate_grace_s: float, kill_grace_s: float) -> None: ...
    def cleanup_partial(self) -> None: ...
```

#### 6.5.2 语义归属：**谁**把「被终止」判成 `canceled`（而不是 `failed`）

```
TeardownHandle.abort()              谁置位：worker（收到 cancel 请求，或 SIGTERM drain）
        │
        ├─► LspClient.request() 内层轮询抛 CanceledAbort   （§6.5.4a）
        ├─► OpengrepRunner.scan() 轮询循环抛 CanceledAbort  （§6.5.4b）
        └─► pipeline 阶段边界 _check_abort() 抛 CanceledAbort（§5.5）
                     │
                     ▼
        worker._handle() 捕获 CanceledAbort
                     ├── state = canceled（drain 时改为 queued，§6.2）
                     ├── failure = None            ← 取消不是失败
                     └── XACK
```

**如何同时满足 HANDOVER §10.2「失败必须具名返回，不能抛」——三条互不冲突的边界**：

1. **`run_scan()` 的契约不变**：它仍然**永不抛**（`services/scan/runner.py:74-80` 的 docstring
   与四条 `failure_mode` 路径原样保留）。**取消不从这里走。**
2. **`CanceledAbort` 继承 `BaseException`，不继承 `Exception`**（§6.5.5）。
   于是 `run_scan()` 内部的 `except Exception as exc`（`runner.py:98`）、
   `manager._call` 的（`manager.py:261`）、`_expand.one()` 的（`assemble.py:453`）
   **全部不会吞掉它**——这是有意的：取消必须能穿过四层「什么都接」的容错代码。
   它**不是失败**，所以「失败必须具名返回」这条规则对它不适用；
   它是**控制流信号**，对应的是 HANDOVER §10.2 里「任何新增的失败路径都必须走这个约定」
   所指的**失败**，而不是取消。
3. **「不是取消的异常终止」仍然具名**：如果扫描子进程是被杀的、而 `abort()` 从未被置位
   （例如 OOM killer 或运维手动 `kill`），`OpengrepRunner.scan()` **不抛**，
   而是走既有路径返回 `ScanOutcome(returncode=-9, …)`；`run_scan()` 随即产出具名
   `failure_mode`。判据只有一条：
   ```
   rc 异常 且 teardown.aborted() == True   → CanceledAbort（控制流 → canceled）
   rc 异常 且 teardown.aborted() == False  → 照旧具名返回（→ failed(scan_failed / scan_aborted)）
   ```
   **`aborted()` 只能由 worker 置位**，所以不存在「扫描器自己崩了却被当成取消」的可能。
   为把这条与普通 `scan_failed` 区分开，`FailureMode` 增加了 `SCAN_ABORTED`（§2.1）。

```python
class CanceledAbort(BaseException):
    def __init__(self, *, stage: str, resource: str, detail: str = "") -> None: ...
    # stage:    "scan" | "setup" | "locate" | "expand" | "read" | "assemble" | "package"
    # resource: "scan_process" | "lsp_request" | "stage_boundary" | "kill_deadline"
```

#### 6.5.3 响应时间承诺（替换掉旧草案那句「最长 900s」）

| 取消发生在 | 靠什么生效 | 真实量级 | 用户看到 |
|---|---|---|---|
| **扫描阶段（本地子进程）** | `OpengrepRunner` 轮询发现 `abort()` → `terminate()` → `wait(1s)` → `kill()` | **≤ 2s 发现（缓存最坏）+ ≤ 1.2s 终止 ≈ 1–3s** | 几秒内变 `canceled` |
| **扫描阶段（远程 `http://scan:8101`）** | **无法打断对端。** 只能放弃等待、本端写 `canceled`，对端容器继续把这次扫描跑完 | 本端 **≤ 2s**；对端 CPU 白跑到 `scan_timeout_s` | 前端几秒内看到 `canceled`；代价见下方"诚实说明" |
| **LSP 阶段**（locate / expand / read） | `request()` 的短轮询发现 `abort()` → 抛 `CanceledAbort` → `manager.stop_all()` → 每个 client `kill()` | **≤ 2s + 进程退出（≤1.2s）≈ 1–3s** | 几秒内变 `canceled` |
| **`expand`/`read` 的并发批次** | 阶段边界的 `_check_abort()`（§5.5 已说明不改 `asyncio.gather`） | ≤「一个切片/一个方法体的剩余时间」，实测通常几秒；最坏是一个卡住的 LSP 请求（`lsp_timeout_s=20s`） | 最坏 20 秒 |
| **纯计算 / 落盘段** | **不可中断**（见下方"两条不可中断段"） | 亚秒级 | 无感 |
| **兜底硬上限** | worker 的 `_kill_deadline()`：从 `abort()` 起 `cancel_kill_grace_s=3s` 后**无条件**自己完成终止与状态写入 | **≤ 3s**（不依赖 pipeline 是否配合） | 最坏 3 秒 |

**两条不可中断段（诚实列出）**：

1. `ContextAssembler.assemble()` + `BundleRenderer.render()`（`assemble.py:234-271`）——
   纯 Python 计算，没有 `await` 也没有子进程。**它本来就是亚秒级**，
   不打断是正确的（打断会让我们丢掉一个几乎完成的 bundle）。
2. `BundlePackager.write()`（`assemble.py:293`）——同步文件 I/O。**这是取消最不该介入的时刻**：
   半途而废会留下残缺目录。所以 `_check_abort()` 对 `package` 阶段特殊处理：
   进入之前检查一次，**进入之后不再检查**，让它写完并 rename，然后正常写 `succeeded`。
   这与「用户点取消却拿到一个完整 bundle」不矛盾——`cancel_requested` 会留在记录里作为审计。

> **诚实说明（远程扫描）**：worker 委托 `http://scan:8101` 时**打断不了对端**。
> 本端能立刻变 `canceled`，但对端容器里的 opengrep 会继续跑完（最长 `scan_timeout_s=900s`）。
> 两个可选修法：(a) 给 scan 服务加 `POST /v1/scan/{id}/cancel`
> （需要 scan 服务保存 `Popen` 句柄，即把 §6.5.4b 的改造在对端也做一遍）；
> (b) **不委托**、worker 本地跑扫描器。
> **本轮选"接受"**： (a) 是第二块工作，(b) 会让 worker 镜像背上扫描器依赖。
> **但必须诚实呈现**：取消远程扫描 = 「本端立刻响应 + 对端继续跑完」，也是 §8 的一条已知代价。
> **注意这条与 §5.4.1 理由 2 是同一个根因**：委托出去的东西就失去了句柄。
> 区别是扫描的委托只损失"对端 CPU"，而提取的委托会损失"进度 + 取消 + 心跳"三样，
> 所以取舍方向相反——**扫描委托、提取不委托**，这条不对称是有意的。

#### 6.5.4 需要改动的两个既有函数（逐行级别）

##### (a) `app/lsp/client.py::LspClient.request()`（L310–341）——把"死等"换成"短轮询"

现状（L329）：

```python
if not pending.event.wait(timeout or self.default_timeout_s):
    with self._pending_lock:
        self._pending.pop(req_id, None)
    raise TimeoutError(f"LSP {self.name}: {method} timed out")
```

改为：

```python
deadline = time.monotonic() + (timeout or self.default_timeout_s)
while True:
    if pending.event.wait(self.poll_interval_s):           # 默认 0.05s
        break
    if self._abort is not None and self._abort():           # 新增：可中断
        with self._pending_lock:
            self._pending.pop(req_id, None)
        raise CanceledAbort(stage=self._stage, resource="lsp_request",
                            detail=f"{self.name}:{method}")
    if time.monotonic() >= deadline:
        with self._pending_lock:
            self._pending.pop(req_id, None)
        raise TimeoutError(f"LSP {self.name}: {method} timed out")
```

* `self._abort` / `self._stage` 由 `LanguageServerManager` 的 `bind_run(abort, stage)` 设置，
  在 pipeline 的 `setup` 事件里由 `teardown.register_lsp(lsp)` 一并绑定。
* **默认（`_abort is None`）行为与今天完全一致**：`poll_interval_s=0.05` 只意味着
  最多多 50ms 的收尾延迟，而 `event.wait(0.05)` 在事件已置位时立即返回。
* **`CanceledAbort` 会穿过 `manager._call` 的 `except Exception`（L262）吗？会。**
  因为 `CanceledAbort` 继承 `BaseException`（§6.5.5），那里捕的是 `Exception`。
  **这正是我们要的，不需要改 `_call`。**
* 新增 `kill()` 快路径（**不改 `stop()`**——它已经是合格的多级终止）：

  ```python
  def kill(self, *, graceful: bool = False) -> None:
      """取消路径用：graceful=False 时跳过 LSP 协议寒暄，直接 terminate→kill。"""
      if graceful:
          return self.stop()
      self._stopping.set()
      proc, self._proc = self._proc, None
      self._started = False
      if proc is not None and proc.poll() is None:
          _terminate_tree(proc, grace_s=1.0)
      self._outbox.put(None)                  # 让 writer 线程退出
      self._fail_pending("canceled: server killed")   # 必须调：叫醒所有在等的请求
  ```

##### (b) `services/scan/opengrep.py::OpengrepRunner.scan()`（L133–188）——`subprocess.run` → `Popen`

**这是真取消的硬前提**：`subprocess.run(...)`（L164）**全程阻塞且不交出句柄**——
调用方拿不到 `Popen`，`teardown.register_process("scan", proc)` 无处可放，
`terminate()→kill()` 也没有对象。所以占比最长的扫描阶段（默认 `AEGIS_SCAN_TIMEOUT_S=900`）
在改造前**根本不可能可中断**。

现状（L164–170）：

```python
proc = subprocess.run(cmd, capture_output=True, text=True, timeout=self.timeout_s, check=False)
tail = "\n".join((proc.stderr or "").strip().splitlines()[-20:])
```

**句柄怎么交出去（调用链，逐层）**——`run_scan(request)` 的签名与
「永不抛异常」约定（HANDOVER §10.2、§10.3 的 `SUCCESS_CODES=(0,1)`）**都不能破**，
所以句柄**不走参数位置**，而是**加在 `ScanRequest` 上**（它是 dataclass，加可选字段不破坏调用方）：

```python
# services/scan/runner.py
@dataclass
class ScanRequest:
    workspace: Path
    ...                              # 既有字段一个不动
    # --- 可中断（全部可选；默认 None => 行为与今天逐字节相同）---
    abort: Callable[[], bool] | None = None      # 由 worker 的 CancelWatch 提供
    process_sink: Callable[[Popen], None] | None = None  # 子进程一起来就回调（交句柄）
    process_done: Callable[[], None] | None = None       # 结束时回调（注销句柄）


def run_scan(request: ScanRequest) -> ScanOutcome:      # ← 签名不变，仍然永不抛
    ...
    try:
        outcome = runner.scan(request.workspace, ..., abort=request.abort,
                              process_sink=request.process_sink,
                              process_done=request.process_done)
    except CanceledAbort:                    # ★ 新捕获，但**不向上抛**（见下）
        return ScanOutcome(
            engine=..., sarif_path=None, findings=[], warnings=["scan aborted"],
            degraded=True,
            scan_record=build_scan_record(..., failure_mode="scan_aborted", returncode=-15),
            canceled=True,                   # ★ ScanOutcome 新增字段
        )
    except Exception as exc:                 # 既有分支，一字不动
        ...
```

**为什么 `run_scan()` 要吞掉 `CanceledAbort` 而不是让它穿过**：
`HANDOVER §10.2` 要求它永不抛；而"被取消"这件事需要**同时**
(a) 到达 `ScanRecord.failure_mode`（台账）与 (b) 让上层知道该走 `canceled` 而不是 `failed`。
一个信号做不到两件事，所以拆成两步：`run_scan()` 把它转成一个
`ScanOutcome(canceled=True, scan_record.failure_mode="scan_aborted")`，
然后 **`AssemblyPipeline._collect_findings()` 检查 `outcome.canceled`**：

```python
# app/pipeline/assemble.py::_collect_findings（改 3 行）
outcome = run_scan_anywhere(ScanRequest(..., abort=abort, process_sink=teardown.register_process_slot("scan"), process_done=teardown.unregister_slot("scan")))
assert outcome.scan_record is not None
if outcome.canceled:                      # ★ 唯一新增的分支
    raise CanceledAbort(stage="scan", resource="scan_process",
                        detail=outcome.scan_record.stderr_tail[-200:],
                        scan_record=outcome.scan_record)   # ★ 台账随异常带走（§2.1）
return (outcome.findings, outcome.sarif_path, outcome.engine, outcome.warnings, outcome.scan_record)
```

**`run_scan_anywhere()` 不需要改**：它只做"URL 有就走 HTTP、没有就 `run_scan`"，
`ScanRequest` 多两个字段对它透明（HTTP 分支会忽略它们——**这也是为什么远程扫描不可取消**，
§6.5.3 的诚实说明）。

改为（`OpengrepRunner.scan()`）：

```python
def scan(self, target, *, ..., abort=None, process_sink=None, process_done=None,
         cancel_poll_s: float = 0.05) -> ScanOutcome:
    ...
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    if process_sink is not None:
        process_sink(proc)                              # ★ 句柄交出去（worker 存进 TeardownHandle）
    out = err = ""
    try:
        deadline = time.monotonic() + self.timeout_s
        while True:
            try:
                out, err = proc.communicate(timeout=min(cancel_poll_s, 1.0))
                break
            except subprocess.TimeoutExpired as expired:
                out = _as_text(expired.stdout)          # 超时也要留住已读到的输出
                err = _as_text(expired.stderr)
                if abort is not None and abort():
                    _terminate_tree(proc, grace_s=1.0)
                    raise CanceledAbort(stage="scan", resource="scan_process",
                                        detail=f"rc={proc.returncode}")
                if time.monotonic() >= deadline:
                    _terminate_tree(proc, grace_s=1.0)
                    err = (err or "") + f"\nscanner exceeded {self.timeout_s}s and was killed"
                    break
    finally:
        if process_done is not None:
            process_done()                              # ★ 注销句柄（成功/失败/取消都走）
    tail = "\n".join((err or "").strip().splitlines()[-20:])
    return ScanOutcome(engine=Path(exe).stem, returncode=proc.returncode, sarif_path=sarif_path,
                       command=cmd, stderr_tail=tail, degraded=degraded, degrade_reason=...)
```

要点（每条都是为了不破坏既有语义）：

* **argv 一个字符都不动**：`build_command()`（L94–131）与它的 8 个用例
  （`tests/test_scanner_command.py`）**完全不受影响**。这次改的是"怎么等它结束"，
  不是"怎么拼它"——其中 2 个用例（`L82-86` 的参数化）在本地会因没有二进制而 skip，
  改动后仍然 skip，语义不变。
* **`ScanOutcome` 只加一个字段**（`canceled: bool = False`），既有字段、
  `stderr_tail` 的 20 行截断、`degraded`/`degrade_reason` 全都不变。
  `run_scan()` 既有的**四条 `failure_mode` 路径**（起不来 / `rc not in (0,1)` /
  SARIF 缺失 / SARIF 为空或不可解析）**逐条保留**，新增的 `CanceledAbort` 捕获是第 5 条，
  位置放在 `except Exception` **之前**（否则被吞）。
* **超时后的文案会变**：今天 `subprocess.run(timeout=…)` 抛 `TimeoutExpired`，
  被 `run_scan()` 的 `except Exception`（`runner.py:98`）接住 →
  `failure_mode="scanner could not be started: …"`；改后走
  `rc not in (0,1)` 分支 → `failure_mode="scanner exited with rc=…"`。
  **两者的可观测结果都是「具名失败 + 0 命中」**（符合 HANDOVER §10.2），但文案变了：
  `tests/test_scan_stage.py` 里若有断言文案的用例要同步改（实现时先跑一遍确认）。
* `text=True` 保留（既有行为）；`_as_text()` 处理 `TimeoutExpired.stdout` 可能是 `bytes`/`None`。
* **`_terminate_tree(proc, grace_s)`** 是新增的模块级私有函数（**Windows 与 POSIX 分开处理**）：

  ```python
  def _terminate_tree(proc: subprocess.Popen, *, grace_s: float = 1.0) -> None:
      """terminate → 等 grace_s → kill。Windows 上优先 taskkill /T 收整棵树。绝不抛。"""
      if proc.poll() is not None:
          return
      if os.name == "nt":
          # taskkill /T 连孙进程一起收；CREATE_NO_WINDOW 避免闪一个控制台窗口。
          # 失败（例如无 taskkill 权限）就退回 terminate/kill。
          subprocess.run(["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                         capture_output=True, check=False,
                         creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
      proc.terminate()
      try:
          proc.wait(timeout=grace_s)
          return
      except subprocess.TimeoutExpired:
          pass
      proc.kill()
      try:
          proc.wait(timeout=grace_s)
      except subprocess.TimeoutExpired:      # 连 kill 都不返回：交给上层兜底，不在这里死等
          log.error("process %s did not die after kill()", proc.pid)
  ```

  **跨平台差异（写清楚，因为本机是 Windows、仓库历史也在 Windows 上）**：

  | | POSIX | Windows |
  |---|---|---|
  | `terminate()` | `SIGTERM`，**可被忽略** | `TerminateProcess`，**不可被忽略**，但只杀直接子进程 |
  | `kill()` | `SIGKILL` | 与 `terminate()` 等价（Windows 没有更强的招） |
  | 收孙进程 | 需要 `start_new_session=True` + `os.killpg(...)` | 需要 `taskkill /T /F /PID` |
  | 本方案 | 直接 `terminate→kill`（**本轮不做进程组**） | `taskkill /T /F` 优先，失败退回 `terminate→kill` |

  **`taskkill` 那段在容器里是空转**（Linux 上 `os.name != "nt"`，不进分支），
  所以生产路径不引入 `taskkill` 依赖。
  **不要给 `Popen` 加 `CREATE_NEW_PROCESS_GROUP`**：它会让 Windows 上的 `terminate()`
  从 `TerminateProcess` 变成发送 `CTRL_BREAK_EVENT`，而后者**可以被子进程忽略**——
  那会让取消在最需要它的时候失效。

#### 6.5.5 为什么 `CanceledAbort` 必须继承 `BaseException`

代码里有四处「什么都不放过」的容错：

| 位置 | 代码 | 为什么存在 |
|---|---|---|
| `services/scan/runner.py:98` | `except Exception as exc:  # no engine at all` | 扫描器起不来要降级，不能炸整个 run |
| `app/lsp/manager.py:261` | `except Exception as exc:` | 一个 LSP 查询失败要降级成空结果 |
| `app/pipeline/assemble.py:453` | `except Exception as exc:  # a single bad node must not kill the run` | 单个切片失败不能杀整个 run |
| `app/lsp/manager.py:191` | `except Exception as exc:` | 语言服务器起不来要记 `_missing` 并降级 |

这四处**都是对的**，是 ARCHITECTURE §6「Degrade, never fail」的载体。
但它们同时意味着：一个继承 `Exception` 的取消信号会被**任意一层静默吞掉**，
表现为「用户点了取消，进度条继续跑」——最难查的那种 bug。

**所以 `CanceledAbort` 继承 `BaseException`**，与 `KeyboardInterrupt` / `SystemExit` 同类：
它是**控制流**，不是**错误**。三条必须写下来的配套约束：

1. **不能有裸 `except:` 或 `except BaseException:`**（`ruff` 的 `E722` 拦裸 `except:`；
   仓库当前没有 `except BaseException`，实现时也不要加）。
2. **`worker._handle()` 必须显式捕它，并且放在 `except Exception` 之前**：
   ```python
   try:
       _run_job(...)
   except CanceledAbort as exc:                  # 必须在 Exception 之前
       store.mark_canceled(job_id, stage=exc.stage, detail=exc.detail)
   except Exception as exc:                      # 其它一切 = 失败
       store.fail(job_id, mode=_mode_for(exc), message=str(exc), detail=repr(exc))
   finally:
       ack(message_id)
   ```
   **顺序不能反**：`except Exception` 在上面会漏掉 `CanceledAbort`（它压根不是 `Exception`），
   结果是 `BaseException` 逃出 worker 主循环、进程带着一个 `running` 的 job 死掉。
   `tests/test_queue_cancel.py` 用「假 pipeline 抛 `CanceledAbort`」直接钉住这条。
3. **`asyncio.to_thread` 会把它带回来**：`to_thread` 用 `loop.run_in_executor`，
   工作线程里的异常会被 future 重新抛到 await 处；`BaseException` 子类同样被传递
   （`concurrent.futures` 用 `future.set_exception`，不筛类型）。
   `asyncio.gather`（L458）默认 `return_exceptions=False`，所以它会**立刻向 `run()` 传播**——
   这正是我们要的：一个切片的取消终止整批。

#### 6.5.6 abort 检查的缓存与代价

`abort()` 会在 50ms 的循环里被反复调用（扫描子进程一个、每个 LSP 请求一个），
每次都打 Redis 就是每秒几十次往返。实现为一个带 TTL 的闭包：

```python
class CancelWatch:
    """把『每 50ms 问一次 Redis』变成『最多每 ttl_s 问一次 Redis』。"""
    def __init__(self, store, job_id, *, ttl_s: float = 2.0):
        self._store, self._job_id, self._ttl_s = store, job_id, ttl_s
        self._checked_at, self._value = 0.0, False
    def __call__(self) -> bool:
        now = time.monotonic()
        if now - self._checked_at >= self._ttl_s:
            self._checked_at = now
            try:
                self._value = bool(self._store.get(self._job_id).cancel_requested)
            except Exception:
                pass                      # Redis 抖动不能让 abort 检查本身变成异常源
        return self._value
    def invalidate(self) -> None:
        self._checked_at = 0.0            # 每次状态写入后调用
```

**代价（必须承认）**：取消的最坏发现延迟是 `2s（缓存）+ 50ms（轮询）≈ 2s`。
**取舍**：每次状态写入（阶段边界）都**主动 `invalidate()`**，
所以在阶段边界上取消是立刻生效的；只有「一个阶段跑到一半」时才吃这 2 秒。
把 15 分钟变成 ≤2 秒，这个代价划算。
**如果评审认为 2 秒太长**，把 `ttl_s` 调到 0.2（每秒 5 次 Redis 往返，单机 Redis 无感）。

#### 6.5.7 风险：中途杀掉语言服务器，对同一 worker 进程里的后续 job 有没有影响？

**结论分三层，逐层给理由。**

**第 1 层：worker 是长驻进程，不是「每 job 一个进程」。**
理由由 §6.1 的形态决定：worker 要保留 Redis 连接池、consumer group 成员身份、
PEL 里的 in-flight 条目、reaper 的周期任务。**每 job 一个进程会让 PEL 随进程消失**，
等于把 §4.4 整套回收机制废掉。所以长驻：一个被取消的 job 之后，
同一个 worker 继续处理下一个 job。

**第 2 层：被杀掉的语言服务器不会污染后续 job，因为它的生命周期是「每次 run」。**
实读 `assemble.py:152-157`（在 `run()` 内部 `load_catalog(...)` 新建 manager）与
`assemble.py:299-301`（`finally: lsp.stop_all()`）——**manager 是 run 的局部变量，
每次 `run()` 新建、结束（正常或异常）都在 `finally` 里拆掉**。
ARCHITECTURE §7 说「spawned lazily, reused for the whole run, torn down in a finally」
正是这个意思：**per-run，不是 per-process**。

所以杀语言服务器之后：

* 本次 run 剩下的代码不会再碰它（`CanceledAbort` 已离开 `run()`，`finally` 会执行 `stop_all()`）；
* 下一个 job 会新建 manager、重新 `client.start()`（`manager.py:180-190` 的懒启动路径），
  **拿到一套干净的新进程**；
* **没有跨 job 的状态共享**：`_open_docs` / `_settled_docs` / `_pending` 都是实例字段，随实例一起死。

**第 3 层：三个真实副作用，必须明确处置。**

| 副作用 | 会不会发生 | 处置 |
|---|---|---|
| **`_missing` 黑名单误伤** | `manager.py:178-179` 与 L192：`_missing` 里的 key 会被**永久跳过**（`client_for` 直接返回 `None`）。如果杀服务器那一刻恰好有线程在 `start()` 里等 `initialize`，那个 `start()` 会因进程被杀而抛异常 → **key 进 `_missing`** | **不跨 job**：`_missing` 是 manager 实例字段，run 结束即消失。但**同一个 run 内**会误伤（表现为「这个语言的所有查询降级成 syntax_regex」）。**处置**：`manager.py:191-192` 之间插一行——`if teardown is not None and teardown.aborted(): raise CanceledAbort(...)` **放在** `self._missing.add(key)` **之前** |
| **孤儿孙进程**（Windows 上尤其真实） | `pyright-langserver`（Node）会派 `node.exe`；`clangd` 一般不派。`proc.kill()` 只杀直接子进程 | **本轮部分解决**：`_terminate_tree()`（§6.5.4b）在 Windows 上用 `taskkill /T /F`，对**扫描子进程**有效；对**语言服务器**仍只做直接 kill（`LspClient.start()` 的 `Popen` 参数不在本轮改动范围）。残留的 `node.exe` 在容器里随容器消失，在本机开发时可能残留几个。**跟进项**：给 `LspClient.start()` 加 `start_new_session=True`（POSIX）+ `os.killpg`，Windows 上同样走 `taskkill /T` |
| **端口 / 文件被占** | 语言服务器一般不开端口；pyright 会往 workspace 写 `.pyright` 缓存 | 无害。`/workspace` 是只读挂载，写失败即降级 |

**因此明确回答那个问题**：
**worker 处理完一个被取消的 job 之后，【不需要】重建语言服务器，也【不需要】退出进程。**
依据是第 2 层（manager 是 per-run 的），加上「取消路径不污染 `_missing`」那一行改动。
**一个例外**：如果这次终止**没有**走 `CanceledAbort`，而是让别的异常穿透
（例如 `LspClient` 的读线程把 `ServerExited` 注入到一个正在 `to_thread` 里跑的调用），
`run()` 的 `finally` 仍然会 `stop_all()`，下一个 job 仍会新建 manager——**同样不需要退进程**。
**例外中的例外**：如果 `stop_all()` 自己卡住（某个 client 的 `wait()` 不返回），
worker 的 `_kill_deadline()` 会强制结束该次 `handle()`，并置 **`self._poisoned = True`**，
此后 worker **拒绝领取新 job 并退出进程**（退出码 3），由 `restart: unless-stopped` 拉起来。
**这条兜底是必要的**：语言服务器的 `wait()` 卡住意味着 Python 层的线程模型已经不可信，
继续用它跑下一个 job 是赌博。「宁可重启也不带病运行」与 HANDOVER §10.2 的「绝不静默」是同一种态度。

#### 6.5.8 与 graceful shutdown（§6.2）的关系

两者共用同一套机制，只差一个字段：

| | 触发 | `abort()` 置位 | 终态 | 消息 |
|---|---|---|---|---|
| 取消 | `POST /v1/jobs/{id}/cancel` | 是（`reason="cancel"`） | `canceled` | **XACK**（不再重投） |
| 优雅停机 | SIGTERM | 是（`reason="shutdown"`） | `queued` | XACK 后**重新 XADD**（§6.2 步骤 3） |

所以 `TeardownHandle` 需要一个「终止原因」字段（`reason: "cancel" | "shutdown"`），
由 worker 在 `abort()` 时传入；`_handle()` 按它决定写 `canceled` 还是 `queued`。
**这比两套终止代码好：终止路径是危险代码，只写一遍。**

---

## 7. 测试清单

### 7.1 依赖决策：`fakeredis`，不用自研 fake

**要新依赖**：`fakeredis[lua]>=2.23`，位置 `pyproject.toml` 的
`[project.optional-dependencies].dev`（**不是** `all`/`api`/`extraction`——
运行时容器不需要它，只有测试需要）。

理由：

1. 自研 fake 要覆盖 `XADD` / `XREADGROUP` / `XACK` / `XAUTOCLAIM` / `XPENDING` /
   `XGROUP CREATE`（含 `BUSYGROUP`）/ `SET NX EX` / `ZADD` / Lua `EVAL`——
   等于重写一份 Streams 语义，而**测试要验证的恰恰是这些语义**，
   用自研 fake 测「pending 回收」是自证循环。
2. `fakeredis` 的 Streams 命令是 **25/25 全部实现**，包含 `XAUTOCLAIM`、`XPENDING`、
   `XINFO GROUPS`——本方案需要的全在里面
   （见 [fakeredis STREAM 支持列表](https://fakeredis.readthedocs.io/en/latest/supported-commands/Redis/STREAM/)）。
3. Lua：`fakeredis` 的 `EVAL` 在 [SCRIPTING 列表](https://fakeredis.readthedocs.io/en/latest/supported-commands/Redis/SCRIPTING/)里
   标为已实现，但需要 Lua 解释器（`lupa`），因此装 `fakeredis[lua]`。
   **若评审后来拒绝 `lupa`**（它有预编译 wheel，但不纯 Python），
   退路是把 `compare_and_set` 改成 `WATCH/MULTI/EXEC`——
   `fakeredis` 的 TRANSACTIONS 是纯 Python 实现，无需 lupa；
   **此时 §4.5 整段（含 Lua 源码）需要同步改写**，这是那次决策的附带成本。

**测试 fixture**（加在 `tests/conftest.py`）：

```python
@pytest.fixture()
def fake_redis():
    import fakeredis
    client = fakeredis.FakeRedis(decode_responses=True)   # 必须显式给：见下
    yield client
    client.flushall()

@pytest.fixture()
def job_store(fake_redis) -> JobStore:
    return JobStore(fake_redis, QueueConfig())

@pytest.fixture()
def queue_settings(tmp_path, workspace) -> Settings:
    return Settings(..., queue=QueueConfig(redis_url="redis://fake:6379/0")).resolve()
```

`decode_responses=True` **必须显式给**：`redis-py` 默认返回 bytes，
而 `Job.model_validate_json` 需要 str。这个默认值差异是
「本地真 Redis 正常、测试里全是 `TypeError`」的经典来源，所以 fixture 里写死。

### 7.2 测试文件 → 用例 → 断言

| # | 文件 | 用例 | 断言（关键点） |
|---|---|---|---|
| 1 | **`tests/test_jobs_contract.py`**（新） | `test_job_roundtrips_through_json` | `Job.model_validate_json(job.model_dump_json()) == job`，**用 §2.5 的四段 JSON 作字面量**（含 canceled 那段） |
| 2 | | `test_stage_order_is_the_lifecycle_order` | `list(JobStage)` == `[scan, setup, locate, expand, read, assemble, package, done]`；漏斗 9 步名集合 == 常量 `FUNNEL_STEPS` |
| 3 | | `test_progress_stages_are_complete_and_ordered` | 新建 job 的 `progress.stages` 长度 8、顺序与 `JobStage` 一致、全部 `pending` |
| 4 | | `test_canceled_has_no_failure_mode` | `FailureMode` 的成员里**没有** `canceled_by_request`；构造 `state=canceled` 的 job 时 `failure is None` |
| 5 | | `test_fingerprint_is_stable_and_normalised` | workspace 相对 vs 绝对、rules 顺序颠倒、globs 顺序颠倒 → **同一** fingerprint |
| 6 | | `test_fingerprint_separates_meaningful_differences` | 分别改 `lsp` / `max_findings` / `package_name` / `include_globs` / sarif 文件内容 → **5 个不同** fingerprint（防 §5.6 的补充 1–3 被后人删掉） |
| 7 | | `test_job_id_is_derived_from_the_fingerprint` | `job_id_for(fp)` 两次相同；长度 42（`J-`+40）；字符集 ⊆ `[0-9a-f]` |
| 8 | | `test_contracts_module_imports_no_io` | AST 扫 `aegis_contracts/jobs.py` 的 import 集合，与 `{redis, httpx, socket, subprocess, fastapi}` 无交集（防有人为了省事把 store 写进契约） |
| 9 | **`tests/test_queue_store.py`**（新） | `test_create_then_get_roundtrips` | `state=queued`、`revision=0`、`timing.submitted_at` 有值 |
| 10 | | `test_create_is_idempotent_on_the_same_job_id` | 第二次 `create()` 返回既有 job、`revision` 不变（`SET NX` 语义） |
| 11 | | `test_set_running_records_worker_and_attempt` | `progress.worker_id` / `attempt` / `stage_started_at` 写入；`timing.started_at` 有值且 `queue_wait_ms>0` |
| 12 | | `test_stage_finished_accumulates_counters` | 连续 3 个 `stage_finished` 后 `progress.counters` 是并集，且**同名键被覆盖而不是相加**（`contexts` 会上报两次，见 §3.3） |
| 13 | | `test_heartbeat_does_not_bump_revision` | `heartbeat()` 后 `worker_heartbeat_at` 变新、`revision` **不变**、`TTL` 被刷新 |
| 14 | | `test_compare_and_set_rejects_a_stale_revision` | 用旧 revision 写 → 返回 `-2`，job 内容不变（**reaper 不误杀的核心保证**） |
| 15 | | `test_compare_and_set_rejects_a_wrong_state` | `expected_state="running"` 但实际已 `succeeded` → `-1` |
| 16 | | `test_terminal_state_sets_a_ttl_and_running_does_not` | 终态后 `TTL > 0`；running 时 `TTL == -1` |
| 17 | | `test_list_jobs_is_newest_first_and_filters_by_state` | 3 个 job，`list(state="failed")` 只回 1 个，`list()` 按 `submitted_at` 倒序 |
| 18 | | `test_mark_canceled_leaves_progress_untouched` | `mark_canceled()` 后 `failure is None`、`progress.stages` 逐字段不变、`revision+1` |
| 19 | **`tests/test_queue_streams.py`**（新） | `test_ensure_group_is_idempotent_and_reads_history` | 连调两次不抛；断言用的是 `id="0"`（先 `XADD` 一条再建组，`claim()` 必须能拿到它——这条直接钉住 §4.2 的硬要求） |
| 20 | | `test_enqueue_carries_routing_fields_only` | 条目字段集合 == `{job_id, kind, fingerprint, attempt, submitted_at}`；**不含** `request`/`budget`（防有人把请求体塞进会被 MAXLEN 裁掉的地方） |
| 21 | | `test_consumer_names_are_unique_per_process` | 两次 `consumer_name()` 不同，且都以 `hostname:pid:` 开头 |
| 22 | | `test_claim_then_ack_clears_pending` | `claim()` 后 `XPENDING` 计 1；`ack()` 后计 0 |
| 23 | | `test_claim_with_small_block_returns_quickly` | `block_ms=1000` 时 `claim()` 在 ~1s 内返回（不是无限阻塞）——防 §4.3 的 `block=0` 回归 |
| 24 | **`tests/test_queue_worker.py`**（新） | `test_worker_runs_a_fake_pipeline_and_reports_every_stage` | monkeypatch `AssemblyPipeline.run` 为逐阶段调 `observer` 的假实现 → 终态 `succeeded`、7 个阶段全 `done`、每段 `duration_ms is not None`、`counters` 含 9 个漏斗键 |
| 25 | | `test_worker_marks_failed_with_a_named_mode_on_exception` | 假 pipeline 抛 `RuntimeError` → `state=failed`、`failure.mode == PIPELINE_EXCEPTION`、`detail` 含原始 repr、**`state != running`** |
| 26 | | `test_worker_refuses_missing_workspace` | 请求指向不存在的目录 → `failed(WORKSPACE_MISSING)`，且**没有调用** pipeline（断言调用计数 0） |
| 27 | | `test_worker_acks_even_when_the_job_fails` | 失败后 `XPENDING` 计 0（§4.3：绝不留 PEL） |
| 28 | | `test_worker_skips_a_terminal_job_on_redelivery` | 已 `succeeded` 的 job 重投进来 → 只 `XACK`，pipeline 调用计数 0 |
| 29 | | `test_worker_reuses_run_scan_anywhere` | monkeypatch `services.scan.client.run_scan_anywhere` 并断言**它被调用**（防有人绕开入口直连 scan 服务，§5.4） |
| 30 | | `test_graceful_shutdown_returns_the_job_to_the_queue` | `request_stop()` 在任务进行中 → `state=queued`（**不是 canceled**）、`cancel_requested is False`、`attempt` 不变、消息已 ACK 且已重投、`progress.counters` 保留 |
| 31 | **`tests/test_queue_reaper.py`**（新） | `test_reaper_acks_a_job_that_already_succeeded` | 终态 + PEL 残留 → 只 ACK，状态零变化 |
| 32 | | `test_reaper_does_not_kill_a_slow_but_heartbeating_job` | `worker_heartbeat_at` 是 5s 前、claim idle > timeout → **状态仍 `running`**，消息被重投（**本方案最重要的一条**） |
| 33 | | `test_reaper_recovers_from_a_bundle_already_on_disk` | 手工造出 `output_dir/<bundle_id>/manifest.json` → 写 `succeeded`、`package_path` 指向该目录、`note` 含 `recovered` |
| 34 | | `test_reaper_requeues_until_max_attempts` | `attempt=1`、`max_attempts=2` → 重投且 `attempt=2`；再来一次 → `failed(WORKER_LOST)` |
| 35 | | `test_reaper_never_leaves_a_job_running_forever` | 参数化 3 种起始状态，推进时间到超时后 job 一定 ∈ 终态集合 |
| 36 | | `test_reconcile_startup_fails_stale_running_jobs` | 造一个心跳很旧的 `running` job（**无 PEL 条目**）→ 启动自检后它不再是 `running` |
| 37 | | `test_reconcile_startup_requeues_a_queued_orphan` | 造一个 `queued` 但 stream 里没有条目的 job（模拟 MAXLEN 裁掉）→ 自检后 stream 里出现对应条目（§4.6 用例 52 的落点） |
| 38 | **`tests/test_queue_cancel.py`**（新） | `test_teardown_registers_and_terminates_a_fake_process` | 用一个真的短命子进程（`sys.executable -c "import time;time.sleep(30)"`）登记 → `kill_all()` 后 `proc.poll() is not None`，且耗时 < `terminate_grace_s + kill_grace_s + 1` |
| 39 | | `test_kill_all_is_idempotent` | 连调两次不抛；已退出的进程不再被碰 |
| 40 | | `test_abort_makes_a_blocked_request_raise` | 用 `tests/fake_lsp_server.py` 起一个客户端，`request()` 一个不会返回的方法 + 一个 100ms 后返回 True 的 `abort` → 抛 `CanceledAbort`，且**抛出耗时 < 0.5s**（钉住 §6.5.4a 的轮询） |
| 41 | | `test_canceled_abort_is_base_exception_not_exception` | `issubclass(CanceledAbort, BaseException) and not issubclass(CanceledAbort, Exception)`（§6.5.5） |
| 42 | | `test_canceled_abort_passes_through_the_four_swallow_sites` | 对着 `run_scan` / `manager._call` / `_expand.one` 各造一个会抛 `CanceledAbort` 的假下游，断言它**穿过去了**（这是「BaseException 不是装饰」的可执行证明） |
| 43 | | `test_worker_maps_canceled_abort_to_canceled_not_failed` | 假 pipeline 抛 `CanceledAbort` → `state=canceled`、`failure is None`、`progress.stage` == 抛出的那个 stage |
| 44 | | `test_worker_order_of_except_matters` | 若把 `except Exception` 放在前面（用一个故意写错的子类化 Worker 模拟）→ 测试必须失败；**这条用注释说明它是"回归守卫"** |
| 45 | | `test_scan_runner_reports_scan_aborted_when_not_canceled` | 手工 `proc.kill()` 一个假扫描进程（`abort()` 未置位）→ `run_scan()` 返回**具名** `failure_mode`，不抛（HANDOVER §10.2 的守卫） |
| 46 | | `test_staging_directory_is_removed_on_cancel` | `cleanup_partial()` 后 `.staging-*` 目录不存在，最终目录也不存在 |
| 47 | **`tests/test_jobs_api.py`**（新） | `test_assemble_returns_202_and_a_queued_job` | 202、body `{job_id, state:"queued", deduplicated:false}`、`Location` 头正确；**同一请求再发一次 → 202 + 同一 job_id + `deduplicated:true`**（幂等，用户拍板项） |
| 48 | | `test_invalid_request_still_returns_400_before_enqueue` | workspace 不存在 → 400；断言 stream 里**没有**新条目（校验必须在入队前） |
| 49 | | `test_duplicate_after_success_returns_200_with_the_result` | job 置 succeeded 且磁盘有包 → 重复 POST → **200**、`result.bundle_id` 一致 |
| 50 | | `test_duplicate_after_failure_returns_409_and_force_retries` | job 置 failed → POST → 409（body 含 `failure.message`）；`?force=true` → 202 且 attempt 递增 |
| 51 | | `test_get_job_is_404_when_unknown_or_expired` | 随机 id → 404，detail 含 "expired" |
| 52 | | `test_jobs_list_is_the_first_screen_payload` | 3 个 job → `GET /v1/jobs` 回 3 条、字段是 `JobSummary`（**不含** `progress.stages`）、按时间倒序、带 `queue` 汇总块 |
| 53 | | `test_cancel_queued_is_immediately_canceled` | `queued` → 202 + `state:"canceled"` |
| 54 | | `test_cancel_running_sets_the_flag_and_stays_running` | `running` → 202 + `state:"running"` + `cancel_requested:true`（**不新造 state**，§5.3） |
| 55 | | `test_cancel_a_finished_job_is_409_and_does_not_set_the_flag` | `succeeded` → 409；重新 GET 后 `cancel_requested is False` |
| 56 | | `test_cancel_twice_is_idempotent` | 第二次 → 200 完整 Job，不报错 |
| 57 | | `test_queue_unavailable_is_503_not_500` | store 抛 `redis.ConnectionError` → 503，body 含 "queue unavailable" |
| 58 | | `test_without_redis_the_old_synchronous_path_is_used` | `AEGIS_QUEUE__REDIS_URL` 未设 → `POST /v1/assemble` 返回今天那个 `AssembleResponse`（200 + `manifest`），**逐字段断言**（既有契约不许漂移的守门测试） |
| 59 | | `test_the_api_is_still_headless` | 新增路由后 `GET /` 仍 404、`/openapi.json` 仍 200（延续 `tests/test_api.py:91` 的意图） |
| 60 | **`tests/test_pipeline_observer.py`**（新） | `test_observer_is_optional_and_changes_nothing` | 同输入同 `package_name` 跑两次（带/不带 observer）→ `bundle_id`、方法数、`stats.counts`、`stats.stage_ms` 的键集合完全相同 |
| 61 | | `test_observer_events_arrive_in_stage_order` | 事件序列 == `[scan.end, setup.end, locate.end, expand.end, read.end, assemble.end, package.end]`，每个都带 `ms is not None`（**没有 `scan.start`**，§3.4） |
| 62 | | `test_observer_end_events_carry_the_funnel_counters` | `expand.end` 含 `slices`；`read.end` 含 `proposed`/`kept`/`read`；`assemble.end` 含 `inlined`——§3 的映射表变成可执行断言 |
| 63 | | `test_pipeline_module_does_not_import_the_queue_package` | AST 断言 `services/extraction/pipeline/assemble.py` 的 import 里没有 `services.queue`（§5.5 的协议隔离） |
| 64 | | `test_expand_still_gathers_without_return_exceptions` | AST 断言 `_expand` 里的 `asyncio.gather` 没被加上 `return_exceptions=True`（§5.5 的"不动并发模型"守卫） |
| 65 | **`tests/test_compose_policy.py`**（新） | `test_only_gateway_and_web_publish_ports` | 解析 `docker/docker-compose.yml`：有 `ports:` 的服务集合 ⊆ {gateway, web}，且每项以 `127.0.0.1:` 开头（HANDOVER §3 硬规则，机器可验证） |
| 66 | | `test_every_service_has_a_healthcheck_and_restart_policy` | 6 个服务全有 `healthcheck` 与 `restart`；`depends_on` 用长语法 `condition:` |
| 67 | | `test_gateway_does_not_depend_on_the_worker` | `gateway.depends_on` 里**没有** `worker`（§5.9.4 的决策变成断言，防止后来人"顺手加上"） |
| 68 | | `test_worker_has_no_extraction_url_but_has_scan_url` | `worker.environment` 里 `AEGIS_EXTRACTION_SERVICE_URL` 存在且为空串，`AEGIS_SCAN_SERVICE_URL` 非空（§5.4.1 的决策变成断言） |
| 69 | **`tests/test_scan_transport.py`**（改） | 新增 `test_worker_pipeline_calls_the_same_scan_entry_point` | 在 worker 上下文 monkeypatch `services.scan.client.run_scan_anywhere`，断言两种 transport（本地 / 伪造 httpx）下**都**经过它——延续该文件「两个传输一个行为」的主题 |
| 70 | | 新增 `test_scan_abort_raises_only_when_the_teardown_says_so` | `abort()` 未置位时子进程被杀 → 具名失败；置位时 → `CanceledAbort` |
| 71 | **`tests/test_demo_fixture.py`**（已存在，核对即可） | `test_committed_demo_fixture_matches_the_generator` | `demo/repo/` 存在，且 4 个文件内容 == `tests/fixtures.FILES` 的常量（这是 §5.12 的真正守卫：夹具与生成器不许漂移） |
| 72 | | 补一条 `test_write_fixture_is_idempotent`（若尚未有） | 连续两次 `write_fixture(root)` 后 4 个文件的 `mtime_ns` **不变**（幂等化只跳过相同内容，不重写）——这钉住「demo 可重复运行而不 churn git」这个性质 |
| 73 | **`tests/test_contracts.py`**（**改**） | `test_contracts_forbid_io_and_web_frameworks` | `banned` 集合已含 `redis`，**无需改动即覆盖新文件**；只在该用例注释里说明「`jobs.py` 也在扫描范围内」 |
| 74 | **`tests/test_contracts.py`**（**新增，步骤 0d**） | `test_no_service_depends_on_the_gateway_shell` | AST 扫 `services/`：**没有任何** import 的顶层包是 `app`。**这是决策 4 的核心验收**——迁移前它有 3 条边（§5.14.1），迁移后必须为 0 |
| 75 | **`tests/test_contracts.py`**（**新增，步骤 0d**） | `test_the_contract_layer_only_reaches_core_once` | `aegis_contracts -> aegis_core` 的边**恰好 1 条**（`domain.py:22` 的 `estimate_tokens`，§5.14.6）：既防它长大，也防它被无声删掉 |
| 76 | **`tests/test_scan_stage.py`**（**新增，步骤 3**） | `test_scan_cancel_returns_a_record_instead_of_raising` | `abort()` 立刻返回 True + 一个长命假子进程 → `run_scan()` **不抛**，返回 `ScanOutcome(canceled=True)` 且 `scan_record.failure_mode == "scan_aborted"`（HANDOVER §10.2 与真取消同时成立） |
| 77 | | `test_scan_outcome_without_cancel_keeps_the_four_failure_modes` | 参数化既有四种失败路径（起不来 / `rc=2` / SARIF 缺失 / SARIF 为空），断言 `canceled is False` 且 `failure_mode` 文案与今天一致——**锁住"改造没有顺手改掉既有语义"** |
| 78 | | `test_opengrep_scan_uses_popen_and_exposes_the_handle` | monkeypatch `subprocess.Popen` 为可观察假类 → 断言走的是 `Popen`（**不是** `subprocess.run`），`process_sink` 收到该对象，`process_done` 在成功与取消两条路径上各被调用一次 |
| 79 | | `test_scanner_argv_is_untouched` | 复用 `tests/test_scanner_command.py` 的期望 argv 逐字符比对（或直接断言那 8 个用例未改动即通过）——**这次改的是"怎么等它结束"，不是"怎么拼命令"** |

`tests/test_contracts.py` 的 `test_no_module_reads_static_assets_through_the_api_anymore`
会读 `app/api/routes.py` 的**文本**并断言 `"static" not in routing`。
本轮改动不会触发它（我们不动 static 相关字样），但改 `routes.py` 时要意识到它在用文本方式盯着那个文件。

### 7.3 端到端（手工验证）

```powershell
# 1) 起一个 Redis（不需要 compose，验证最快）
docker run --rm -d -p 127.0.0.1:6379:6379 --name aegis-redis-dev redis:7-alpine

# 2) 打开队列，起 worker（另一个终端）
$env:AEGIS_QUEUE__REDIS_URL="redis://127.0.0.1:6379/0"
python -m services.queue.worker --port 8104

# 3) 提交（gateway 也要开队列）
curl -X POST http://127.0.0.1:8100/v1/assemble -H "Content-Type: application/json" `
     -d '{\"workspace\":\"./demo/repo\",\"rule_config\":\"p/default\"}'
# → 202 {"job_id":"J-...","state":"queued","deduplicated":false}

# 4) 看阶段推进
curl http://127.0.0.1:8100/v1/jobs/J-...
# → progress.stage: scan → setup → locate → expand → read → assemble → package
# → state: succeeded, result.bundle_id = B-...

# 5) 取消演练：提交一个较大的任务，在 expand 阶段点取消
curl -X POST http://127.0.0.1:8100/v1/jobs/J-.../cancel
# → 202 {"state":"running","cancel_requested":true}
# → 期望 1-3 秒内 GET 到 state=canceled，failure=null，
#   且 var/packages/ 下没有 .staging-* 残留

# 6) 崩溃演练：worker 跑到 expand 时 kill -9，再起 worker
# → 期望：观察不到 state 长期停在 running；产物已落盘则 succeeded(recovered)，
#   否则 attempt+1 重跑，最多 3 次后 failed(worker_lost)
```

---

## 8. 不做的事与已知代价

| 不做 | 代价 / 何时该补 |
|---|---|
| **SSE / WebSocket 推送** | 前端本轮轮询（首屏 `GET /v1/jobs` + 详情页 1s 轮询，`revision` 去重）。`aegis:events:{job_id}` 通道会写但无人订阅——保留它是因为写入成本可忽略，将来加 SSE 时发布端不用改。**触发条件**：并发 job > 20，或轮询流量出现在网关日志里 |
| **跨机扩展** | worker 与 Redis、`/workspace`、`/data/packages` 必须同机（HANDOVER §3 的已知设计债）。Redis 不发布端口 → 只能同 compose 网络。**触发条件**：需要多机时，先解决共享卷（对象存储或传字节），而不是先解决队列 |
| **取消远程扫描的对端** | 见 §6.5.3 的"诚实说明"：本端立刻 `canceled`，对端 opengrep 继续跑到 `scan_timeout_s`。**触发条件**：扫描阶段动辄十几分钟且用户抱怨"取消了还在跑" |
| **进程树级终止（语言服务器）** | `pyright-langserver` 派生的 `node` 可能残留（§6.5.7 第 3 层）。扫描子进程已用 `taskkill /T` 解决；语言服务器是跟进项（要动 `LspClient.start()` 的 `Popen` 参数） |
| **abort 检查的 2s 缓存** | 「一个阶段跑到一半」时取消最多迟 2 秒生效（§6.5.6）。**触发条件**：前端反馈"点了取消没反应"→ 把 `CancelTtl` 调到 0.2s |
| **远程提取下的阶段进度与取消** | 只影响同步路径（§5.4.3 列出全部接口点）。**触发条件**：第三方需要「异步 + 远程提取」 |
| **`/v1/assemble/upload` 异步化** | 它仍是唯一会阻塞 >10s 的路由（§5.2）。**触发条件**：有前端直接上传 SARIF 的入口 |
| **AI fan-out** | 契约留位（§2.6），无实现；`kind=ai_fanout` 会被显式拒绝 |
| **job 结果内嵌 manifest** | 客户端要拿 manifest 得再发 `GET /v1/bundles/{id}/manifest`（已有接口）。Redis 内存与响应体都可控 |
| **多队列 / 优先级** | 只有一条 stream `aegis:q:jobs`，FIFO。**代价**：一个 15 分钟的扫描会挡住后面 30 秒的 bundle 任务。**触发条件**：出现交互式低延迟需求 → 拆 `aegis:q:scan` / `aegis:q:assemble`，worker 用 `XREADGROUP` 多流轮询 |
| **Redis 持久化** | `--save "" --appendonly no`：Redis 重启会丢队列与状态。**这是有意的**：产物在磁盘上不会丢，丢的是"进度记忆"，由「重启自检 + 用户重新提交（幂等 → 同一 job_id）」补偿。**触发条件**：排队时间超过 Redis 重启窗口的容忍度 → 开 AOF `everysec` |
| **worker 副本数 > 1** | 每份各起一套语言服务器（内存 × N，§5.9.3），且多个 job 可能撞同一 `bundle_id` 目录（下一条） |
| **多 worker 撞同一 bundle 目录** | 两个不同的 job 若算出同一个 `bundle_id`（例如都显式传了同一个 `package_name`），`BundlePackager` 会互相踩。**本轮不加文件锁**，只在文档里写明：`package_name` 是"我确定没有并发"时才用的逃生门 |
| **job 列表分页** | `limit` 默认 100，无游标。job 数上千时列表会慢 |
| **所有 worker 都死时的静默窗口** | §6.3 第 3 层：没人跑 reaper 时 `running` 会一直停着。**缓解**：`/health` 的 `queue.workers_alive == 0` 必须被告警；这是本方案唯一的静默窗口，**不要靠"应该会有人重启 worker"来覆盖它** |

---

## 9. 实施步骤（7 步，每步可独立提交且测试全绿）

每一步的验收都包含 `python -m pytest -q` 与 `python -m ruff check .`。
**步骤 0（迁移）必须在最前**（决策 4）；**真取消横跨步骤 3 与 4**。

### 步骤 0/7：物理迁移 `app/` → `services/extraction/`（**决策 4：用户已定，先做**）

**目标**：把 `app/` 缩成网关外壳，解掉 `services -> app` 这个顶层环（§5.14.1），
**行为零变化**（验收标准是测试计数不变）。

四个提交，每个都必须 `124 passed, 2 skipped`（`python -m pytest -q -rs`）：

| 提交 | 内容 |
|---|---|
| 0a | `git mv app/{pipeline,graph,lsp,parsers,assembler} services/extraction/`；包内与外部导入改前缀（§5.14.4 的对照表）。**不动** `app/api`、`app/main.py`、`app/cli.py`、`app/schemas/api.py` |
| 0b | `git mv app/observability/views.py aegis_contracts/views.py`；改 4 个消费方（`app/api/routes.py:33`、`tests/test_observability.py:20`、`tests/test_scan_stage.py:371`、`scripts/observe.py:15`）的导入（§5.14.2） |
| 0c | `probe_lsp` 从 `app/api/deps.py:113-141` 搬到 `services/extraction/lsp/probe.py`；gateway 与 extraction 两侧各自 import。**这一步做完 `services -> app` 才归零**（§5.14.4 末段） |
| 0d | `tests/test_contracts.py`：换掉那条读 `app/api/routes.py` 的文本断言的路径（若 0a 动了它）；**新增 §5.14.5 第 11 条的两个 AST 断言**（`test_no_service_depends_on_the_gateway_shell`、`test_the_contract_layer_only_reaches_core_once`） |

**验证（照 §5.14.5 的 11 条清单逐条跑；这里是精简版）**
```powershell
python -m pytest -q -rs                       # 124 passed, 2 skipped —— 计数必须一模一样
python -m ruff check .
# 1/2 条：没有任何 services/ 代码 import app.
Select-String -Path (Get-ChildItem -Recurse -Filter *.py -Path services).FullName -Pattern "from app\.|import app\."   # 期望 0 命中
# 3 条：app/ 只剩 5 项
Get-ChildItem app -Force | Select-Object Name   # __init__.py api cli.py main.py schemas (+__pycache__)
# 5 条：views.py 是纯重命名
git diff --stat --find-renames app/observability/views.py aegis_contracts/views.py    # 期望 R100
# 6/10 条：打包与可导入
pip install -e ".[dev]"; python -c "import app.main, services.extraction.app, services.extraction.pipeline.assemble, aegis_contracts.views; print('ok')"
# 7 条：入口名未变
Select-String -Path docker\entrypoint.sh -Pattern "uvicorn"    # 仍是 app.main:app
docker compose -f docker/docker-compose.yml config --services  # 仍是 scan/extract/gateway
```
**注意**：这一步**不新增任何功能**，所以任何测试计数或快照的变化都说明改错了——
**不要在这一步"顺手"改 `views.py` 的内容或改路由**（§5.14.2 末段）。

### 步骤 1/7：契约与指纹（纯新增，零运行时影响）

* 新增 `aegis_contracts/jobs.py`（§2 全部模型 + `request_fingerprint` + `job_id_for` + `canonical_json`）。
* 新增 `tests/test_jobs_contract.py`（用例 1–8）。
* 不改任何既有文件。

**验证**
```powershell
python -m pytest tests/test_jobs_contract.py tests/test_contracts.py -q
python -m pytest -q          # 124 passed, 2 skipped 不变
python -m ruff check .
```

### 步骤 2/7：配置 + Redis 状态层（无路由改动）

* `aegis_core/config.py` 加 `QueueConfig`（含 §5.7 的取消参数）+ `Settings.queue`；`.env.example` 加队列段落。
* `pyproject.toml`：`dependencies` 加 `redis>=5.0`，`dev` 加 `fakeredis[lua]>=2.23`（`aegis-worker` 脚本留到步骤 4）。
* 新增 `services/queue/{__init__,keys,jobs,streams}.py`（**不含 worker/reaper/cancel**）。
* `tests/conftest.py` 加 `fake_redis` / `job_store` / `queue_settings` 三个 fixture。
* 新增 `tests/test_queue_store.py`、`tests/test_queue_streams.py`（用例 9–23）。

**验证**
```powershell
pip install -e ".[dev]"
python -m pytest tests/test_queue_store.py tests/test_queue_streams.py -q
python -m pytest -q          # 本机未装 Redis 也能全绿——这正是 fakeredis 的目的
```

### 步骤 3/7：pipeline 钩子 + 真取消的资源层（**不改行为**，纯增量）

* `app/pipeline/assemble.py`：加 `StageEvent` / `Observer` / `AbortCheck` / `TeardownHandle` 协议
  与 `run(..., observer=None, abort=None, teardown=None)`，以及 §5.5 的 8 处回调与 `_check_abort()`。
* `app/pipeline/ids.py`：抽出 `compute_bundle_id()`（**纯抽取，公式逐字符不变**）。
* `app/assembler/package.py`：加 `staging: bool = False` 参数与 `os.replace` 改名。
* `app/lsp/client.py`：`request()` 的短轮询 + `kill()` 快路径；`LspClient` 加 `poll_interval_s`（默认 0.05）。
* `app/lsp/manager.py`：`bind_run(abort, stage)`；`client_for()` 的异常处理里在 `_missing.add` 之前判 `aborted()`。
* `services/scan/opengrep.py`：`scan()` 改 `Popen` + 轮询 + `_terminate_tree()`；`abort` / `teardown` 两个可选参数。
* 新增 `services/queue/cancel.py`（`TeardownHandle` / `CanceledAbort` / `CancelWatch`）。
* 新增 `tests/test_pipeline_observer.py`（用例 60–64）、`tests/test_queue_cancel.py`（用例 38–46）。

**验证**
```powershell
python -m pytest tests/test_pipeline_observer.py tests/test_queue_cancel.py -q
python -m pytest tests/test_scan_stage.py tests/test_syntax_and_lsp_types.py -q   # 受影响的既有用例
python -m pytest -q          # 既有 119 例必须一个不挂（除测试文案需同步的那几处）
python scripts/demo.py       # 人眼确认 bundle 与以前一样
git diff --stat app/pipeline/assemble.py app/assembler/package.py services/scan/opengrep.py
# 期望：只有新增行 + ids.py 抽取 + staging 参数；核心计算一行未动
```

### 步骤 4/7：worker + reaper + 自检（可独立运行，仍不改 API）

* 新增 `services/queue/{observer,worker,reaper}.py`。
* `pyproject.toml` 加 `aegis-worker = "services.queue.worker:main"`。
* `docker/Dockerfile` L161 的 import 断言加 `services.queue.worker`（一个词）。
* 新增 `tests/test_queue_worker.py`（用例 24–30）、`tests/test_queue_reaper.py`（31–37）、
  `tests/test_worker_health.py`（`/health` 的 `queue` 字段：`workers_alive`/`pending`/`lag`/`degraded`）。

**验证**
```powershell
python -m pytest tests/test_queue_worker.py tests/test_queue_reaper.py -q
python -m pytest -q
docker run --rm -d -p 127.0.0.1:6379:6379 --name aegis-redis-dev redis:7-alpine
$env:AEGIS_QUEUE__REDIS_URL="redis://127.0.0.1:6379/0"
python -m services.queue.worker --port 8104      # 另开终端；Ctrl+C 应打印 "drained, exiting"
curl http://127.0.0.1:8104/health           # 期望 queue 块里有 workers_alive=1
```

### 步骤 5/7：API 端点 + 幂等边界 + 取消端点（202/200/409/503）

* 新增 `app/api/jobs.py`（`GET /v1/jobs`、`GET /v1/jobs/{id}`、`POST /v1/jobs/{id}/cancel`）。
* `app/api/routes.py`：`assemble()` 分支、`_enqueue_assemble()`、`POST /v1/scan/jobs`、
  `list_bundles()` 的 `.staging-` 跳过；**队列关时逐字节保持原路径**。
* `app/main.py`：`include_router(jobs_router)`。
* `app/cli.py`：`aegis enqueue [--follow]`（§5.11）。
* 新增 `tests/test_jobs_api.py`（用例 47–59）。

**验证**
```powershell
python -m pytest tests/test_jobs_api.py tests/test_api.py -q
python -m pytest -q
# 端到端：§7.3 的 1→4 步（202 → 轮询到 succeeded → bundle 目录存在）
curl http://127.0.0.1:8100/v1/jobs
curl http://127.0.0.1:8100/v1/bundles/B-xxxx/manifest
# 取消：§7.3 第 5 步（期望 1-3s 内 canceled，无 .staging-* 残留）
```

### 步骤 6/7：compose + demo 夹具 + 文档收口

* `docker/docker-compose.yml`：加 `redis` 与 `worker`（§5.9 的完整片段，**含
  `AEGIS_EXTRACTION_SERVICE_URL: ""`**），`gateway` 加 `AEGIS_QUEUE__REDIS_URL` 与 `redis` 依赖，
  更新文件头注释与端口表。
* **demo 夹具部分已在工作树里落地**（§5.12 的状态更新）：`.gitignore` 的
  `demo/*` + `!demo/repo/`、`demo/repo/` 的 4 个文件、`tests/fixtures.py` 的幂等化、
  `pyproject.toml` 的 `extend-exclude = ["demo"]`、`tests/test_demo_fixture.py`。
  **本步骤只需核对与提交**（`git add demo/repo`，提交信息写明
  「committed fixture: docker compose used to mount an empty dir and silently scan nothing」）。
  **确认不要提交 `demo/lsp.yaml` 与 `demo/scan.sarif`**（§5.12 的验证命令）。
* 新增 `tests/test_compose_policy.py`（用例 65–68）；核对 `tests/test_demo_fixture.py`（71–72）。
* 文档：`docs/SERVICE_TOPOLOGY.md` 的「Job flow」（L45–60）
  **校正端点名漂移**——它写的是 `POST /v1/scans`、`POST /v1/bundles`，
  而真实路由是 `POST /v1/scan`、`POST /v1/assemble`；
  改为「`POST /v1/assemble`（异步）→ 202 + `GET /v1/jobs/{id}`」，
  并把迁移表第 7 行 status 改为 **done**。
  **这是刻意修正漂移，不是改契约**——契约从来是 `/v1/assemble`，只是文档写错了。
  另：`docs/HANDOVER.md` §2 表格「任务队列 ❌ 未做」改为已做并链接本文，
  §11.1「待决策 A」标记为已决（Redis + 轻量 worker；真取消；worker 进程内提取）。

**验证**
```powershell
python -m pytest tests/test_compose_policy.py tests/test_demo_fixture.py -q
python -m pytest -q
git check-ignore -v demo/repo/handler.py     # 期望无输出
git status --porcelain demo/                 # 期望只列 demo/repo/ 下 4 个 .py
docker compose -f docker/docker-compose.yml config --services
# 期望：redis / scan / extract / gateway / worker
docker compose -f docker/docker-compose.yml up --build
curl http://127.0.0.1:8100/health                      # queue 块无告警
curl -X POST http://127.0.0.1:8100/v1/assemble -H "Content-Type: application/json" -d '{\"workspace\":\"/workspace\"}'
# 期望 202；轮询 /v1/jobs/{id} 到 succeeded
curl http://127.0.0.1:8101/health                      # 期望连不上（端口策略未被破坏）
curl http://127.0.0.1:8104/health                      # 期望连不上（worker 只有 expose）
curl http://127.0.0.1:8103/health                      # 期望连不上（extract 只有 expose）
```

---

## 10. 已定事项与剩余待确认

**已定（用户授权，不再是待确认）**：

| # | 事项 | 结论 |
|---|---|---|
| 1 | `redis` 依赖位置 | **放 `dependencies`（core）**，理由见 §5.8 |
| 2 | CAS 实现 | **Lua + `fakeredis[lua]`**；若日后拒绝 `lupa`，退路是 `WATCH/MULTI/EXEC` 且 §4.5 需同步改写 |
| 3 | `/v1/assemble/upload` | **本轮不动**，只留 TODO（§5.2）：上传产物的保留/清理策略是独立决策 |
| 4 | `/v1/scan` | **保留同步响应**，异步走新路径 `POST /v1/scan/jobs` |
| 5 | `MAXLEN` / `queued_warn_threshold` | 用 10000 / 200，但**是初值**，上线后按真实 job 频率复核（§4.6 给了复核方法与三条检测） |
| 6 | 远程提取模式的进度 | **队列路径不再受限**（worker 进程内提取，§5.4）；「给 extraction 加进度与取消通道」已写成带接口点的未来工作（§5.4.3） |
| 7 | worker 健康端点 | **发布 `expose: 8104`**（不 `ports:`）；`tests/test_compose_policy.py` 的机器断言保留 |
| 8 | `aegis enqueue` | **加**，含 `--follow`（§5.11） |
| 9 | 取消 | **真取消**（§6.5）；早先的"低成本预留"方案作废 |
| 10 | `docs/SERVICE_TOPOLOGY.md` 端点名 | **照实修正**，放进步骤 6/7 的文档收口，并注明是修正漂移而非改契约 |
| 11 | **`app/` → `services/extraction/` 迁移顺序** | **先迁移、再落地队列**（决策 4，§5.14）。新增步骤 0（0a–0d 四个提交）、最终包结构、`observability` 下沉到 `aegis_contracts/views.py`、`probe_lsp` 搬到 `services/extraction/lsp/probe.py`、队列落在 `services/queue/`、11 条机械验收断言 |
| 12 | **扫描阶段可中断** | **必须做，且是步骤 3 的一部分**（决策 5，§6.5.4b）：`OpengrepRunner.scan()` 由 `subprocess.run` 改 `Popen` + 轮询；句柄经 `ScanRequest.process_sink/process_done` 交出（**不改 `run_scan(request)` 签名与"永不抛"约定**）；新增具名 `SCAN_ABORTED`，落在 `ScanRecord.failure_mode` 与 `JobFailure.mode` **两处**（含义不同，§2.1）；Windows 用 `taskkill /T /F`、POSIX 用 `terminate→kill`；**不给 `Popen` 加 `CREATE_NEW_PROCESS_GROUP`**（会让 `terminate()` 退化成可被忽略的 `CTRL_BREAK_EVENT`） |
| 13 | `SERVICE_TOPOLOGY.md` 的契约层措辞 | **改措辞、不改代码**：补一句 `aegis_contracts -> aegis_core.utils::estimate_tokens` 是已知例外（§5.14.6） |

**仍需确认的只有两条**（都不阻塞步骤 0 开工）：

> 说明：早先的 `CancelWatch` TTL（2.0s vs 0.2s）已经定了——**用 2.0s**
> （`QueueConfig.cancel_poll_ms=50` + `CancelWatch(ttl_s=2.0)`），
> 因为它只在"一个阶段跑到一半"时才吃这 2 秒，而阶段边界上 `invalidate()` 是立即生效的（§6.5.6）。
> 下面两条是本轮真正的开放项。

1. **语言服务器的进程树终止要不要在本轮做**（§6.5.7 第 3 层的跟进项）。
   做的话要动 `LspClient.start()` 的 `Popen` 参数（`start_new_session=True` + POSIX `killpg`，
   Windows 上同样走 `taskkill /T`），属于对既有稳定代码的侵入性改动。
   **我的倾向：不做**。理由：容器里进程随容器消失，本机开发残留几个 `node.exe` 是可接受的代价；
   而**扫描子进程**这一侧本轮已经用 `taskkill /T` 解决了（§6.5.4b），
   它是"长跑且最常被取消"的那一个，收益最大的一侧已经拿到。
2. **`worker` 副本数**（§5.9.3）。本轮按 1 副本设计（`docker compose up` 默认）。
   多副本会同时带来「语言服务器 × N」的内存与「同 `bundle_id` 撞目录」的风险；
   如果一开始就想要并发，需要先决定：加文件锁，还是给 job 分配固定 worker（一致性哈希）。
   **我的倾向：1 副本，把并发留到真的成为瓶颈时。**
   注意 `staging` + `os.replace`（§5.5）只保证"不写坏"，**不保证两个 worker 不互相覆盖**。
