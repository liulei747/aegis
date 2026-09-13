# Aegis 交接文档

> 交接对象：接手本仓库的工程师
> 交接范围：**扫描 → 调用链 → 组装分析包** 这条流水线，以及它现在的服务化拆分
> 交接日期：2025（本文件随代码演进，若与代码冲突，以代码 + `pytest` 为准）
> 阅读顺序建议：本文 → `docs/SERVICE_TOPOLOGY.md` → `docs/ARCHITECTURE.md` → `README.md`

---

## 0. 三十秒版本

**这个项目是什么**：把「静态扫描器命中一行代码」变成「AI 能直接读的一段完整分析材料」。

静态扫描器只能告诉你*哪一行匹配了规则*，它说不出这行属于哪个方法、谁调用它、它又调用了谁。
Aegis 把 **LSP（language server）当作补全这层信息的缝隙**：语言服务器的 `documentSymbol`
返回的 range 就是方法的完整范围，于是「命中点属于哪个方法」退化成纯区间包含判断，
`selectionRange` 再给出做调用层级查询所需的标识符位置。

```
opengrep 命中位置
  → LSP 定位所属方法及其范围
  → LSP 查询调用者、被调用者及实现
  → 按 LSP 返回的文件位置读取完整方法
  → 去重、限制展开范围、保留来源
  → 组装分析包交给 AI
```

**当前状态一句话**：上面这条流水线**端到端可跑、有 338 个测试、有 Docker 本地部署、有可观测台接口**；
AI 部分（威胁建模子代理、prompt 前缀缓存）**刻意没做**，但 bundle 的排版已经按「前缀可复用」设计好了。

**新人第一天该跑的三条命令**（详见 §4）：

```powershell
python -m pytest -q                                  # 395 passed, 12 skipped（见 §8 的构成说明）
python scripts/demo.py                               # 本地跑一遍完整流水线（**先跑它，见下**）
docker compose -f docker/docker-compose.yml up --build
```

---

## 1. 代码地图：谁负责什么

```
aegis/
├── aegis_contracts/        共享数据形状。纯 pydantic，无 I/O。跨服务传输的就是它。
│   ├── domain.py           Finding / MethodSymbol / CallEdge / PruneDecision /
│   │                       MethodContext / Coverage / Degradation / ScanRecord /
│   │                       RunStats / AnalysisBundle(Manifest) / PromptBlock
│   └── views.py            ★ 纯派生视图（漏斗/时间线/来源/上下文/方法/diff），只依赖 domain
├── aegis_core/             每个服务都要的基础设施，无业务。
│   ├── config.py           Settings / BudgetConfig（pydantic-settings，见 §7）
│   ├── logging.py          统一日志
│   ├── workspace.py        resolve_workspace()：两个服务共用的工作区校验（网关译成 400）
│   └── utils.py            sha1、content_hash、estimate_tokens、路径换算（to_uri/rebase_path…）
│
├── services/               ★ 服务边界在这里
│   ├── scan/               只做静态扫描。625 MB 镜像，CPU 密集。
│   │   ├── opengrep.py     引擎感知的 argv 组装（opengrep 与 semgrep 参数不同，见 §10.1）
│   │   ├── sarif.py        SARIF 2.1.0 → Finding（1-based→0-based、四级 severity 回退、路径重定位）
│   │   ├── scanrecord.py   扫描调用的存档记录
│   │   ├── runner.py       run_scan()：**永不抛异常**，失败返回 0 命中 + 具名 failure_mode
│   │   ├── client.py       run_scan_anywhere()：有 URL 走 HTTP，没 URL 就地跑
│   │   ├── app.py          FastAPI：GET /health、POST /v1/scan
│   │   └── Dockerfile      只装 .[api] + opengrep 二进制（镜像小的关键）
│   ├── extraction/         LSP + 调用图 + 组装。1.9 GB 镜像，内存密集。
│   │   ├── routes.py       POST /v1/extract、GET /v1/lsp/probe、GET /health
│   │   ├── client.py       request_extraction()：远程调用入口
│   │   ├── app.py
│   │   ├── pipeline/assemble.py   ★ AssemblyPipeline：把下面所有阶段串起来，先读这个文件
│   │   ├── graph/
│   │   │   ├── resolver.py     Workspace（读文件、按行切片、找局部方法）、SymbolIndex
│   │   │   ├── providers.py    ★ CallGraphResolver：LSP 调用链的全部细节都在这里
│   │   │   └── builder.py      CallGraphBuilder：双向 BFS + 预算裁剪
│   │   ├── lsp/                客户端、配置、进程生命周期；probe.py 探测可用服务器
│   │   ├── parsers/            语法兜底解析（LSP 不可用时退化成 syntax_regex）
│   │   └── assembler/
│   │       ├── reader.py       MethodReader：按字节范围读方法体，全局字符预算
│   │       ├── contexts.py     ContextAssembler：按 sink 聚合上下文 + 三级去重
│   │       ├── render.py       BundleRenderer：渲染成给 AI 的 prompt 块（排版顺序是契约，见 §6）
│   │       └── package.py      BundlePackager：落盘、summary.md、DOT、zip
│   └── web/                观测台前端（**待建**，见 §11）
│
├── app/                    ★ 只剩 gateway 外壳（迁移已于 2026-09-11 完成，见 §11.4）
│   ├── api/                gateway 的路由（routes.py 业务路由 / deps.py 依赖装配）
│   ├── schemas/api.py      HTTP 层的请求/响应模型（**数据契约在 aegis_contracts，不在这里**）
│   ├── main.py             FastAPI 工厂（gateway 的 ASGI 入口：app.main:app）
│   └── cli.py              本地命令行：aegis assemble|scan|probe
│
├── docker/                 Dockerfile（全家桶）、docker-compose.yml、lsp.yaml、lsp.local.yaml
├── tests/                  288 个用例，含一个零依赖的假 LSP server（见 §8）
├── docs/                   ARCHITECTURE / SERVICE_TOPOLOGY / VISUAL / 本文 / prototype.html
├── scripts/                demo.py（跑全流程）、observe.py（打印可观测视图）
└── var/                    运行时产物：packages/（bundle）、work/（SARIF 等中间件）
```

**读代码的最短路径**：`services/extraction/pipeline/assemble.py` 里 `AssemblyPipeline.run()` 是**线性**的，
并且每一段都有注释锚点，按顺序读就是流水线本身：

```
run()
  # ---- scan             → _collect_findings()   （可能远程委托给 scan 服务）
  # ---- workspace + LSP  → Workspace / SymbolIndex / CallGraphResolver
  # ---- locate           → _locate()              （命中点 → 所属方法）
  # ---- expand           → _expand()              （双向走调用图，产 FocusSlice）
  # ---- read + assemble  → MethodReader / ContextAssembler / BundleRenderer
  # ---- manifest         → _manifest()            （拼 Coverage / stats / capabilities）
```

`run()` 里还有两处容易被忽略但很重要的逻辑：远程扫描读不到 SARIF 时会**保留路径并记 warning**
（第 127–134 行），以及 `bundle_id` 用内容指纹而不是 `run_id`（第 164–177 行）。

---

## 2. 当前完成度（诚实版）

| 部分 | 状态 | 证据 |
|---|---|---|
| opengrep 扫描 + SARIF 解析 | ✅ 完成 | `tests/test_sarif.py`、`test_scanner_command.py` |
| LSP 定位方法（含 range 修正） | ✅ 完成 | `tests/test_pipeline_lsp.py`、`test_syntax_and_lsp_types.py` |
| 调用链展开（callers/callees/impl） | ✅ 完成 | 同上 + `providers.py` 的来源/置信度阶梯 |
| 读取完整方法体（字节范围） | ✅ 完成 | `tests/test_read_stage.py`（13 例） |
| 去重 + 预算裁剪 + 来源保留 | ✅ 完成 | `tests/test_assemble_stage.py`、`test_assembler.py` |
| 落盘打包 + summary + DOT | ✅ 完成 | `test_assembler.py` |
| 可观测视图（漏斗/时间线/来源） | ✅ 接口完成，**前端未建** | `aegis_contracts/views.py`（722 行）、`test_observability.py`（22 例） |
| 服务拆分（scan / extract / gateway） | ✅ 完成并验证三跳链路 | `docker/docker-compose.yml`、`docs/SERVICE_TOPOLOGY.md` |
| prompt 前缀契约（可复用前缀从哪开始） | ✅ 已修并加测试 | `ai/cache_prefix.json`、`tests/test_prompt_prefix.py`（§6.3） |
| demo 夹具（`demo/repo` 进仓库） | ✅ 已提交并加防漂移测试 | `tests/test_demo_fixture.py`（§11.5） |
| 前端观测台（`aegis-frontend`） | ✅ **已建成并重做为独立部署**：静态镜像不反代任何东西，API 地址运行期注入 | `frontend/`；`tests/test_frontend_contract.py`、`tests/test_compose_policy.py` |
| 任务队列 | ✅ **完成**（Redis Streams + worker + reaper + 真取消 + job 端点） | `docs/QUEUE_PLAN.md`；`services/queue/`、`aegis_contracts/jobs.py`、`app/api/jobs.py` |
| 队列的可中断扫描 | ✅ 完成：`subprocess.run` → `Popen` + 轮询 + 具名 `scan_aborted` | `services/scan/opengrep.py`、`services/scan/runner.py`；`CanceledAbort` 继承 `BaseException` |
| AI 分析（威胁建模子代理） | ❌ **刻意未做** | 数据流已能喂出结论（§10.20），缺口只剩"自动调用" |
| **完整数据流（Joern）** | ✅ **已接入**：Joern 提供跨文件污点路径，替掉有"方向墙"缺陷的调用链爬取 | §10.20；`services/extraction/dataflow/`、`docs/DATAFLOW_CONTRACT.md` |
| prompt 前缀缓存**真实命中率** | ✅ **已验证**：provider 计费字段证明命中 81–93%；但它只作用于输入（占总量 18–22%） | §10.21 |
| `app/` 物理迁入 `services/extraction/` | ✅ **已完成**，并顺带解掉 `app ↔ services` 顶层环 | §11.4；`tests/test_contracts.py` 用 AST 钉住边数 |

> **测试基线（本机实测，2026-09-12，前端重做后）**：`407 tests collected`。
> 没有 Redis 时：**395 passed, 12 skipped**（实测）。
> 起一个 Redis 后应为 **405 passed, 2 skipped** —— 这一行是**按跳过的 10 例推算的，本轮没有实测**，
> 因为当前栈里有一个 worker 正在消费同一个 Redis，跑那些用例会动到它。
> 另有前端自己的 19 条（`cd frontend && npm test`），由 `tests/test_frontend_contract.py`
> 转接；设了 `API_URL` 时其中一条会额外比对线上 `/openapi.json`。
>
> ```powershell
> docker run --rm -d -p 127.0.0.1:6379:6379 redis:7-alpine
> python -m pytest -q          # 405 passed, 2 skipped
> ```
>
> 其中 10 例需要真 Redis，不是冗余：**fakeredis 与真 Redis 对空容器的 cjson 行为方向相反**，
> 只跑 fakeredis 会让队列在第一次接触生产时崩掉（详见 §10.15）。
> 两个 skip 是 `test_scanner_command.py:86` 的引擎二进制探测（本机无 opengrep / semgrep），
> **不是失败**。

---

## 3. 服务拓扑与端口策略

```
                    ┌─────────────────────────────────────────┐
   host              │  docker network: aegis-net（自定义网络）  │
   127.0.0.1:8100 ──►│  gateway :8000   编排 + 查询             │
   （唯一 API 端口）   │     │                                    │
                     │     ├── HTTP ──► scan    :8101 expose     │
                     │     │            只跑 opengrep           │
                     │     └── HTTP ──► extract :8103 expose     │
                     │                  LSP + 图 + 组装          │
                     └─────────────────────────────────────────┘
   127.0.0.1:8102 ──► web（静态，尚未构建）
```

### 端口策略（**硬规则，不要放宽**）

- **只有 `gateway` 和 `web` 可以 `ports:`**，且必须绑 `127.0.0.1`，**绝不绑 `0.0.0.0`**。
- `scan` / `extract` 使用 `expose:` —— `expose` 只是文档性声明，**不会向宿主发布任何端口**。
- 服务间调用走 compose 网络的服务名：`http://scan:8101`、`http://extract:8103`。
- **理由**：能访问宿主的人如果能打到 `extract`，就得到一个「读取挂载仓库并解析」的端点，
  而这对正常功能毫无必要。少暴露一个端口就是少一个洞。

调试时不要为了图方便去发布端口，用网络内部打：

```powershell
docker compose -f docker/docker-compose.yml exec extract python -c "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8103/health').read())"
```

### 命名

服务名从 `api` 改成了 **`gateway`**，因为 `api` 说不清它是「唯一的对外入口」这个职责。
`container_name` 分别是 `aegis-scan` / `aegis-extract` / `aegis-gateway`。

### 一个契约两种传输

`services/scan/client.py` 与 `services/extraction/client.py` 是同一套逻辑：

| 环境变量 | 行为 |
|---|---|
| `AEGIS_SCAN_SERVICE_URL` 未设置 | 就地调用 `run_scan()`（**开发默认**，零网络开销，约 1 ms） |
| 设置了 | POST 到该 URL（容器里约 10.3 s，含 HTTP + 冷启动语言服务器） |

> ⚠️ **compose 里 `extract` 服务上的 `AEGIS_SCAN_SERVICE_URL` 不是可选项。**
> 漏掉它，extraction 会静默地自己扫描（`scan_transport` 变成 `in-process`），
> 于是 1.9 GB 的镜像里也跑上了扫描器——功能正常，但分层白拆了。
> 这个字段在 `capabilities.scan_transport` 里可以看到，`manifest.json` 里也留了痕。

### 共享卷约束（**已知设计债**）

gateway 与 extract 必须看到 `/workspace`、`/data/packages`、`/data/work` 位于**完全相同的路径**，
因为 SARIF 文件路径会在两个服务之间传递。两台机器部署时这条约束就会破。
**真正的修法是传字节或走对象存储**，不是继续拼卷。现在是有意为之，因为单机本地开发够用。

---

## 4. 怎么跑起来

### 4.1 本地直接跑（最快，开发用这个）

```powershell
# 装依赖（本仓库历史上用系统 Python 3.13 全局装的，.venv 未使用）
pip install -e ".[dev]"

# 扫描 + 组装（输出目录由 AEGIS_OUTPUT_DIR 决定，默认 ./var/packages；CLI 没有 --out）
python -m app.cli assemble --workspace .\demo\repo --rule-config p/default

# 复用已有 SARIF，不重新扫描
python -m app.cli assemble --workspace .\demo\repo --sarif .\var\work\scan.sarif

# 降级模式：不用语言服务器，只走语法兜底
python -m app.cli assemble --workspace .\demo\repo --sarif .\var\work\scan.sarif --no-lsp

# 只看扫描
python -m app.cli scan --workspace .\demo\repo --rule-config p/default

# 探测这个工作区能用哪些语言服务器
python -m app.cli probe --workspace .\demo\repo
```

其它可用开关：`--rule`（可重复）、`--include` / `--exclude`、`--max-findings`、
`--max-depth` / `--max-nodes` / `--max-contexts`（覆盖对应预算）、`--name`（显式指定 bundle id）、`--json`。

`scripts/demo.py` 是端到端演示（扫描 → 组装 → 打印摘要）：

```powershell
python scripts/demo.py
```

### 4.2 Docker（完整拓扑）

```powershell
copy .env.example .env        # 首次
docker compose -f docker/docker-compose.yml up --build

# 健康检查
curl http://127.0.0.1:8100/health

# 构建一个 bundle
curl -X POST http://127.0.0.1:8100/v1/assemble -H "Content-Type: application/json" -d "{\"workspace\":\"/workspace\"}"
```

`.env` 里两个关键项：
- `AEGIS_SCAN_TARGET=./demo/repo` —— 宿主上被分析代码的路径，挂到容器 `/workspace`（只读）。
- `AEGIS_GATEWAY_PORT=8100` —— 唯一对外端口。

已验证的链路日志（三个容器跑在 `aegis-net` 上）：

```
delegating extraction to http://aegis-extract:8103
  → delegating scan to http://aegis-scan:8101
    → services.scan.opengrep running static scan
    → LSP python ready (pyright-langserver)
  → bundle written        （scan_transport: remote，4 methods）
```

并且验证过：宿主**打不到** 8101/8103，只有 8100 可达；gateway 能用服务名打通两个 worker。

### 4.3 观测

```powershell
python scripts/observe.py            # 在终端打印漏斗/来源/上下文视图
```

HTTP 侧（gateway）：

```
GET /v1/bundles
GET /v1/bundles/{id}/observability      # 总览 + 漏斗 + 时间线 + 来源直方图
GET /v1/bundles/{id}/contexts
GET /v1/bundles/{id}/methods
GET /v1/bundles/{id}/methods/{mid}/body
GET /v1/bundles/{id}/diff/{other_id}    # 两个 bundle 的差异
GET /v1/bundles/{id}/manifest|summary|blocks|blocks/{block_id}|graph|archive
GET /v1/lsp/probe
GET /health                             # 委托给远程扫描器时会顺带探测远端
```

---

## 5. 数据契约：bundle 长什么样

落盘在 `AEGIS_OUTPUT_DIR/<bundle_id>/`：

```
<bundle_id>/
├── manifest.json        完整机器可读记录（下面 §5.2）
├── bundle.json          精简版
├── summary.md           人读的摘要（含 "scan ran:" 与 "## Run warnings"）
├── ai/
│   ├── prompt.md        ★ 给 AI 的完整 prompt（块按缓存友好顺序拼接）
│   ├── blocks.jsonl     每块一行
│   ├── blocks_meta.json 每块的 block_id / 标题 / token 估算 / 是否 cacheable
│   └── cache_prefix.json ★ 可复用前缀从哪一块开始（§6.2；别只看 cacheable 标志）
├── contexts/<context_id>.md    按 sink 聚合的分析单元
├── methods/<method_id>.txt     方法全文（method_id 即文件名）
├── graph/callgraph.dot         调用图
└── scan/original.sarif         原始 SARIF 副本
```

### 5.1 内容派生 ID（**关键设计**）

所有 ID 都是**内容派生的 sha1**，不是自增也不是随机。这样同一个输入永远得到同一个 ID，
可以做缓存、可以做 diff：

| ID | 形态 | 派生自 |
|---|---|---|
| `bundle_id` | `B-<10位>` | sha1(workspace, 排序后的 finding ids, budget, rule_config, rules) |
| `context_id` | `C-<12位>` | sha1(focus, 方法集合, finding ids) |
| `method_id` | `M-<12位>` | sha1(path, qualified_name, start_line, end_line) |
| `run_id` | `R-<10位>` | sha1(workspace, time) —— **只作元数据，不参与任何 ID 计算** |
| `finding_id` | sha1 | sha1(rule_id, path, start_line, start_col) |

磁盘目录名就是带前缀的 `bundle_id`（`scripts/observe.py` 按 `B-*` 找最新包）；
`M-` 前缀还被 `app/api/deps.py` 用作合法性校验，别去掉。

> 历史坑：`bundle_id` 曾经把 `run_id` 也算进去，导致每次跑都是新 ID，缓存与 diff 全废。
> 现在 `run_id` 只作为 manifest 的元数据存在，**不参与任何 ID 计算**。

`method_id` 与 `content_hash` 在不同 provider 下必须一致 —— 为此方法体做了归一化
（去掉尾部空白 + 恰好一个结尾换行）。否则同一方法经 LSP 和经语法兜底会算出两个 ID。

### 5.2 `manifest.json` 的结构（`aegis_contracts/domain.py`）

```
schema_version: "1.0"      ← 跨版本边界检查用
bundle_id / run_id / created_at / workspace_root
focus_count
methods[]        MethodSymbol（path、qualified_name、range、byte offsets、provider、confidence、origin_path、hops）
findings[]       Finding（rule_id、path、位置、severity、message、来源）
edges[]          CallEdge（caller、callee、provider、confidence、调用点位置）
contexts[]       MethodContext（focus、方法集合、finding ids、aliases）
prunes[]         PruneDecision（哪条规则裁掉了什么、在哪个文件哪一行、哪个 provider）
degradations[]   Degradation（缺了什么能力，为什么，影响是什么）
coverage         Coverage（漏斗的数字）
stats            RunStats（含 scan: ScanRecord）
capabilities     { scan_transport, warnings, ... }
total_chars / estimated_tokens
```

**`prunes` 和 `degradations` 是这套设计里最重要的两个字段。**
任何预算裁剪都必须留下 `PruneDecision`；任何「本来能查但查不了」都必须留下 `Degradation`。
理由：AI 拿到的材料如果不完整，**必须知道哪里不完整**，否则它会把「没看到」当成「不存在」。
这也是为什么 `builder.py` 的裁剪消息写的是人话，例如：

> 「X 的被调用者从未查询过，因此它们不在这份包里」

### 5.3 来源与置信度阶梯（provenance）

每一条符号与每一条边都带 `provider` + `confidence`，UI 里按 fact / strong / weak / guess 着色：

| provider | confidence | 等级 |
|---|---|---|
| `lsp_call_hierarchy` | 1.00 | fact |
| `lsp_document_symbol` | 1.00 | fact |
| `file_opengrep` / `opengrep` | 1.00 | fact |
| `lsp_definition` | 0.90 | strong |
| `lsp_implementation` | 0.80 | strong |
| `lsp_references` | 0.60 | weak |
| `syntax_regex` | 0.40 | guess |

---

## 6. Prompt 排版顺序（**这是契约，改动会使缓存全部失效**）

`services/extraction/assembler/render.py` 里 `PROMPT_VERSION = "2025-01-assemble-v1.2"`，块顺序固定为：

```
bundle.header            ← 非 cacheable（含 bundle_id 与总数），因此前缀不从这里开始
  → instructions.system  ┐
  → instructions.legend  │ 可复用前缀：前缀从这里开始
  → method_catalog       ┘
  → fanout.plan            ← 非 cacheable：它列的是**本 bundle** 的 context 表
  → context.<id>          ← 从这里开始随 bundle 变化
  → run.notes
```

**注意 `fanout.plan` 的位置**：它排在 `method_catalog` **之后**，因此不落在前缀里。
它曾经叫 `instructions.chunking`、被标成 cacheable、排在 `method_catalog` 之前 ——
那等于把一个逐 bundle 变化的表塞进"全版本稳定"的 `instructions.*` 里，前缀就成了假话。
改名的同时换了位置，也换了 `cacheable=False`；`tests/test_prompt_prefix.py` 现在用一个
**两个 sink 的工作区**来构造第二个 bundle（只差 `max_contexts` 的话 context 集合不变，
这个缺陷会继续漏过去）。

**为什么这么排**：AI 侧的 prompt 前缀缓存（用户提到的 IAI 式预填充加速）只对**完全相同的前缀**命中。
把随 bundle 变化的内容全部压到后面，前缀就能跨 bundle 复用。

### 6.1 两种稳定性，别混为一谈

| 范围 | 包含什么 | 什么时候命中 |
|---|---|---|
| **全版本稳定** | `instructions.*`（2 块：`system` / `legend`） | 任何两个 bundle 之间，只要 `PROMPT_VERSION` 没变 |
| **同输入稳定** | 上面 2 块 + `method_catalog` | 同一 workspace + 同一规则集跑出来的两个 bundle |

`method_catalog` 属于第二种：它列的是**这次跑收集到的方法体**，工作区变了它就变。
一次 fan-out（同一个包切给多个子代理）落在第二种里，所以它是真正被复用的那一层。
`fanout.plan` 两种都不属于 —— 它是本 bundle 的派发说明，只排在上面前缀之后。

### 6.2 前缀从哪里开始，现在由产物明确声明

`ai/blocks_meta.json` 每块带 `cacheable`，但这个标志**单独用会踩坑**：第 0 位的
`bundle.header` 是 volatile 的，于是「把所有 `cacheable=true` 的块拼起来」得到的是一个
**从第 0 位开始就错了的前缀**，命中率 0。

所以打包时会同时写 **`ai/cache_prefix.json`**：

```json
{
  "prefix_start": 1,
  "prefix_blocks": ["instructions.system", "instructions.legend", "method_catalog"],
  "stable_prefix_tokens": 1038,
  "note": "Blocks before cache_prefix_start are volatile and must be sent per request. ..."
}
```

**消费端的正确读法**：从 `prefix_start` 起、连续读到第一个 `cacheable=false` 为止，那就是可以
预填充/打缓存标记的部分。不要按 `order == 0` 开始拼。

实测（demo bundle `B-909bbbe468`，7 个块，1852 tokens）：

| order | 块 | tokens | cacheable |
|---|---|---|---|
| 0 | `bundle.header` | 38 | ❌ |
| 1 | `instructions.system` | 623 | ✅ |
| 2 | `instructions.legend` | 119 | ✅ |
| 3 | `method_catalog` | 296 | ✅ |
| 4 | `fanout.plan` | 149 | ❌ |
| 5 | `context.C-…` | 576 | ❌ |
| 6 | `run.notes` | 89 | ❌ |

稳定前缀 = **1038 tokens**（`prefix_start=1`），占这个小 bundle 的 **56%**；前缀大小基本恒定，
所以 bundle 越大占比越高（demo 这种小 bundle 是最差情况）。

### 6.3 这一处曾经的真实缺陷（已修，别再犯）

修之前有两个问题，任何一个都会让 AI 阶段的缓存白做：

1. **`cacheable` 标志不是渲染器声明的，而是打包器猜的** —— `package.py` 里写的是
   `block.block_id.startswith("instructions") or block.block_id == "method_catalog"`，
   即用块名硬编码反推语义。渲染器改了块名或改了稳定性，这里不会有任何提示。
   现在 `cacheable` 是 `PromptBlock` 上的字段，由 `BundleRenderer` 自己设置。
2. **没人说明前缀从哪开始** —— `order == 0` 是非 cacheable 的 header，消费端只能靠读代码猜。
   现在由 `ai/cache_prefix.json` 声明。

守住这两条的是 `tests/test_prompt_prefix.py`，它断言的不只是「cacheable 的块连续」，还有
**「前缀字节在两个只有 volatile 部分不同的 bundle 之间逐字节相同」** —— 后者才是
fan-out 真正依赖的属性。加块、改块顺序、或让某个块混进随 bundle 变化的内容时，这个测试会先红。

> 仍未做的是**真实 provider 命中率验证**：这里只证明了「前缀按契约是不变的」，
> 没有证明「provider 真的按这个前缀命中」。那一步需要真实的 API key 与一次对照实验。

---

## 7. 预算与裁剪（每个 cap 都会留下痕迹）

`aegis_core/config.py` 的 `BudgetConfig`，环境变量前缀 `AEGIS_BUDGET__`（**双下划线**表示嵌套）：

| 字段 | 默认 | 语义 |
|---|---|---|
| `max_depth` | 2 | 从 sink 出发的调用图跳数 |
| `max_nodes` | 60 | 单个 bundle 内不同方法数上限 |
| `max_callers_per_node` | 8 | 每个节点向上展开多少个调用者 |
| `max_callees_per_node` | 12 | 每个节点向下展开多少个被调用者 |
| `max_implementations` | 5 | 接口/抽象方法的实现展开数 |
| `max_lines_per_method` | 400 | 单方法行数上限 |
| `max_chars_per_method` | 24000 | 单方法字符上限 |
| `max_total_chars` | 600000 | 全 bundle 字符上限（**永不裁掉 focus 方法体**） |
| `max_contexts` | 20 | 单 bundle 的 sink 数 |
| `expand_concurrency` | 6 | 展开阶段并发度 |
| `lsp_timeout_s` | 20.0 | LSP 请求超时 |
| `read_timeout_s` | 5.0 | 读文件超时 |

> `max_total_chars` 触发时永远不会丢掉 focus（sink 所在）方法体 —— 那是分析的核心，
> 裁掉它等于交出一份没有问题的报告。它只裁上下文外围，并报 `max_total_chars_exceeded`。

---

## 8. 测试与验证

```powershell
python -m pytest -q                    # 395 passed, 12 skipped（本机无 Redis，见下面的说明）
python -m pytest -q -m slow            # 需要真实语言服务器子进程的 6 个（用假 LSP server）
python -m ruff check .                 # lint（demo/ 已排除，见下）
python -m pytest tests/test_observability.py -q
```

> **那 12 个 skip 的构成**：10 例需要真 Redis（起一个 Redis 后变成
> **336 passed, 2 skipped**），2 例是 `tests/test_scanner_command.py:86` 的**二进制探测**，
> 本机没装 opengrep 与 semgrep 就各跳一个。装上任一引擎（或跑
> `AEGIS_OPENGREP_BIN=<路径>`）那 2 例会转成 passed，跳过数归零。
>
> `ruff` 在 `pyproject.toml` 里 `extend-exclude` 掉了 `demo/`：那是**被分析的代码**，
> 不是我们的代码，它故意留着一个未使用的 import 和一处拼接 SQL。
>
> 注意仓库**没有跑 `ruff format`**（`ruff check` 的 `E501` 是 ignore 的），所以别把
> 全仓 `ruff format` 当成"顺手修一下"——那会重排 40+ 个你没碰过的文件。

测试文件分布（共 407 例；下表的例数是 `--collect-only` 实测，不是估计）：

| 文件 | 例数 | 覆盖 |
|---|---|---|
| `test_dataflow.py` | 36 | ★数据流契约 + 接入：空流是答案、流不拍平、引擎坏了要留痕降级、sink 推导取 finding 自己的行、亲缘路由、worker 的 cold 语义与路径映射、**LSP 上溯选入口与回退**（§10.20） |
| `test_queue_worker.py` | 32 | ★worker 与 reaper：阶段上报、具名失败、关停 vs 取消、**不误杀慢任务**、AI 作业按名字拒绝与"未配置仍成功"（§10.22） |
| `test_queue_store.py` | 26 | ★Job 记录、状态迁移、CAS 拒绝陈旧写入、cjson 空表归一化 |
| `test_ai.py` | 23 | ★AI 阶段：前缀/上下文切分、宽松解析（围栏/百分比/缺键）、重试策略、**失败即结果**、报告不写密钥（§10.22） |
| `test_observability.py` | 22 | 漏斗同单位、来源直方图、diff |
| `test_ai_api.py` | 4 | ★/analyze 与 /verdicts：不存在的包 404、未分析 404、关闭时如实回答、真跑一次并读回 |
| `test_scan_stage.py` | 21 | 扫描阶段 + ★取消返回台账而不抛、`Popen` 句柄、argv 未变、杀到孙进程 |
| `test_jobs_contract.py` | 20 | ★Job 契约往返、阶段↔漏斗映射、指纹稳定性与区分度 |
| `test_jobs_api.py` | 19 | ★job 端点：202/200/409/503 边界、幂等提交、取消三态、同步路径不漂移 |
| `test_queue_cancel.py` | 14 | ★Teardown 终止与幂等、`CanceledAbort` 穿过四处容错、LSP 轮询可中断 |
| `test_read_stage.py` | 13 | 方法体读取、字符预算 |
| `test_scan_jobs.py` | 13 | ★可轮询扫描作业：202 + 轮询 + `DELETE` 取消（真的杀得掉在跑的扫描） |
| `test_compose_policy.py` | 15 | ★端口策略、依赖方向、worker 不委派提取、redis 不淘汰、**dataflow 集群规模与挂载一致**（机器断言） |
| `test_dataflow.py` | 36 | ★数据流契约 + 接入：空流是答案、流不拍平、引擎坏了要留痕降级、sink 推导取 finding 自己的行、亲缘路由、worker 的 cold 语义与路径映射、**LSP 上溯选入口与回退**（§10.20） |
| `test_queue_streams.py` | 11 | ★Streams 路由字段、`id="0"` 读历史、pending 与陈旧认领 |
| `test_assemble_stage.py` | 10 | 组装阶段、裁剪（`region_line` 故意落在任何方法之外） |
| `test_contracts.py` | 10 | 数据契约 + ★AST 架构守卫（`services -> app` 边数必须为 0，见 §11.4） |
| `test_pipeline_observer.py` | 10 | ★阶段事件顺序与计数、abort 边界、staging 写入、不 import 队列包 |
| `test_sarif.py` | 10 | SARIF 解析、路径重定位、★region 必须指向它引用的那一行（§10.19 A） |
| `test_scan_transport.py` | 10 | 本地 / 远程两种传输 |
| `test_syntax_and_lsp_types.py` | 8 | 位置编码、LSP 类型 |
| `test_scanner_command.py` | 8 | argv 组装（防引擎参数混用）；其中 2 例按二进制存在与否 skip |
| `test_assembler.py` | 7 | 打包、去重 |
| `test_api.py` | 6 | 路由 |
| `test_pipeline_lsp.py` | 6 | 端到端 LSP（`slow` 标记） |
| `test_prompt_prefix.py` | 6 | ★prompt 前缀契约：连续性、起点声明、跨 bundle 逐字节稳定（§6.3） |
| `test_queue_end_to_end.py` | 6 | ★提交 → worker → 磁盘上的 bundle（真 Redis，无服务器时 5 例 skip） |
| `test_queue_real_redis.py` | 5 | ★真 Redis：Lua CAS、cjson 双向空容器、Streams 认领（无服务器时 5 例 skip） |
| `test_demo_fixture.py` | 3 | ★`demo/repo` 必须已提交、与 fixture 逐字节一致、`write_fixture` 幂等（§11.5） |
| `test_frontend_contract.py` | 3 | ★转接前端的测试（HTTP 契约 + 算术前端自算）+ 构建产物里没有 API origin |
| `test_traffic_settings.py` | 11 | ★环形缓冲（回绕/排序/count）、读日志不写日志、404 被记录、settings 形状、密钥只出现变量名、CORS 可配 |
| **合计** | **407** | 本机：无 Redis **395 passed / 12 skipped**（实测）；有 Redis 按跳过数推算 **405 / 2** |

> 12 个 skip 的构成（实测，不是"大概"）：**10 例需要真 Redis**
> （`test_queue_real_redis` 5 + `test_queue_end_to_end` 5）、**2 例是引擎探测**
> （`test_scanner_command.py:86`，本机没有 opengrep 与 semgrep）。装上任一引擎后
> 那 2 例会转成 passed。

**`tests/fake_lsp_server.py` 值得单独说**：一个**零依赖**的假语言服务器，
实现了 `documentSymbol` / `definition` / `references` / `implementation` / `callHierarchy`。
有了它，调用链逻辑可以在没有 pyright / clangd 的环境里被完整测试，CI 不需要装语言服务器。
新增 LSP 行为时，优先扩展这个假服务器，而不是让测试依赖真服务器。

---

## 9. 实测数字（用于判断改动是否退化）

| 指标 | 数值 | 备注 |
|---|---|---|
| 扫描镜像 | **625 MB** | 只装 `.[api]` + opengrep 二进制 |
| 全家桶镜像 | **1.96 GB** | 含 clangd、pyright、Node 22、可选 semgrep |
| 应用代码改动后重建 | **14.9 s** | 曾经是 **341 s**（见 §10.4） |
| 无改动重建 | ~9 s | 全部命中缓存 |
| 本地就地派发 | ~1 ms | 开发默认路径 |
| 远程 HTTP 派发 | ~10.3 s | 含语言服务器冷启动 |
| demo bundle tokens | ~1872（本机实测） | 稳定前缀 **1171** tokens → 63%，bundle 越大占比越高（见 §6） |
| `POST /v1/assemble` | ~11.5 s | **同步阻塞**，这是要做队列的直接原因 |
| 单独 `pip install semgrep` | ~230 s | 所以它被做成可选 |

---

## 10. 踩过的坑 / 不可违反的硬规则

这一节是本文最有价值的部分。每一条都对应一次真实的静默错误。

### 10.1 引擎参数不能混用
opengrep 是 semgrep 的分支，但 **`--metrics=off` 只有 semgrep 认**。
opengrep 收到它会 `rc=2` 退出，而失败被吞掉后表现为「bundle 是空的」——非常难查。
现在 argv 按引擎分别组装，并由 `test_scanner_command.py` 守住。

### 10.2 扫描失败必须具名返回，不能抛
最初扫描失败会留下一个 0 字节的 SARIF，然后解析器崩溃把整个 run 带下去。
现在 `run_scan()` **永不抛异常**：返回 0 命中 + 具名 `failure_mode`（四种模式都有测试覆盖）。
**任何新增的失败路径都必须走这个约定**，否则「静默空 bundle」会回来。

### 10.3 `run_scan` 的 returncode
`SUCCESS_CODES = (0, 1)` —— semgrep 系工具用 1 表示「跑完了且有命中」，不是错误。

### 10.4 Docker 分层顺序是承重的
**任何依赖 `app/` 的步骤都不能放在昂贵 `RUN` 之上。**
语言服务器和 semgrep 的安装要放在 `COPY app` 之前；
`pip install .` 一次然后把目录 `cp -r` 进 site-packages；用 BuildKit `--mount=type=cache` 缓存 pip/npm。
违反这条，一行 `.py` 改动就要重建 341 s。

### 10.5 `.dockerignore` 规则
**任何 Dockerfile 会 COPY 的东西都不能被 ignore。**
之前 `docker/` 被整个排除，导致 `COPY docker/lsp.yaml` 只在缓存未命中时失败——正好是最不容易遇到的情况。
现在只排除 `docker/lsp.local.yaml` 和 `docker-compose.yml`。

### 10.6 `pip install --no-deps .` 会造出一个没有 fastapi 的镜像
`--no-deps` 曾经让镜像里没有 web 框架。现在用 `.[all]`（全家桶）或 `.[api]`（scan），
并且**两个 Dockerfile 都在构建期做了一次 import 断言**，装了没装当场暴露。

### 10.7 LSP 的 symbol range 结束于下一个兄弟符号的声明行
于是读方法体会把下一个方法的 `def` 行也读进来。
修法是 `_trim_trailing_blank_lines()` 两趟处理：先剥尾部空行，
再判断「最后一行的内容是否其实是某个兄弟符号的起始行」（判据是 `sym.range.start.line == last`）。
> 第一版用「包含关系」判断，失败——因为兄弟符号自己的 range 当然包含它的首行。

### 10.8 语法兜底必须填字节偏移
语法兜底路径最初不填 byte offsets，`MethodReader` 退回按行切片，
结果**把整个文件当成了一个方法体**返回。
现在两条启发式路径都填 offset，并且 `slice_lines` 在缺少结束边界时**直接返回 None 拒绝服务**。

### 10.9 LSP 位置编码是 UTF-16 code unit
Python 字符串是 UCS-4。所有换算必须走 `LineIndex`，不能直接拿 Python 的下标当 `character`。

### 10.10 外部绝对路径要重定位
SARIF 里可能带 `/workspace/...` 或 `D:\build\...` 这种构建机路径，
直接按进程 CWD 解析会读到不存在的位置。用 `rebase_path` / `strip_foreign_prefix`，
有 3 个回归测试守着。

### 10.11 漏斗的每一步必须同单位
漏斗曾经把「切片数」从「方法数」里减掉——两个不同单位相减，`lost` 是错的。
现在 9 步全部同单位，`lost` 永远可计算：
`discovered → located → focus_methods → contexts → slices → proposed → kept → read → inlined`。
另外加了 `fanouts_skipped`，让「被截断」这件事读起来就是「被截断」。

### 10.12 `/health` 的字段名
`version` 字段曾经因为 dict 展开顺序而报出 opengrep 的版本号。
现已改名为 **`engine_version`**。

### 10.13 远程扫描会丢掉 SARIF 路径
委托给远程扫描器时，本地读不到 SARIF，于是 `sarif_path` 变 `null`、argv 是过期的本地参数。
现在保留路径、新增 `ScanRecord.location`、加一条 `warnings`，
并通过 `capabilities.scan_transport` / `capabilities.warnings` 和 `summary.md` 的
`- scan ran:` / `## Run warnings` 暴露出来。

### 10.14 跨上下文重复内联
同一个方法体既在每个 context 里内联、又出现在 `method_catalog` 里。
现在 `_mark_bundle_level_duplicates()` 做三级去重：
findings→method（context 合并）、同一 context 内相同方法体（`aliases`）、
全 bundle 相同方法体（`bundle_aliases` + `canonical_bodies`）。
渲染时替换成 `_body identical to ... ; see method_catalog_`。

### 10.15 空容器过 Lua：fakeredis 与真 Redis 的反向丢失

队列的状态写入是一个 Lua 脚本（读-判-写，原子 CAS），而 **Lua 的 `cjson` 无法忠实表示空容器**。
坑在于两个实现丢的方向相反：

| 方向 | fakeredis | 真 Redis 7 |
|---|---|---|
| `{}`（空 map）经 `cjson.encode`/`decode` | 变成 `[]` | 保持 `{}`（或反之） |
| `[]`（空 list）经 `cjson.encode`/`decode` | 保持 `[]` | **变成 `{}`** |

后果：**一个新建的 job（`counters={}`、`rules=[]`）经过一次 CAS 之后就读不回来了** ——
`Job.model_validate_json` 直接抛 `ValidationError`，而且**朴素测试完全看不出来**，因为写操作返回的是
内存里的对象、那份是正确的。坏掉的只有 Redis 里存的那一份。

修法：`JobStore.get()` 在验证失败时按**字段名**归一化（`_MAP_FIELDS` / `_LIST_FIELDS`）。
不能只按"空 list 就是 map"判 —— **双向都会发生**，所以两张表都要有，而且必须由
`tests/test_queue_store.py` 用 pydantic 反射扫全契约来保证不漏字段。

**教训**：凡是"用另一种语言/引擎序列化我们的数据形状"的地方，都必须跑一次**真引擎**的测试。
`tests/test_queue_real_redis.py` 就是为此存在的（5 例，没有 Redis 时 skip）。

### 10.16 Docker 起不来时先查这三件事（2026-09-11 实测踩过）

第一次在 Windows 上 `docker compose up --build` 时，**一个容器都没起来**。三个独立原因，
每个的报错都指向别处：

| 现象 | 真因 | 修法 |
|---|---|---|
| build 在**第 1 行**就失败，报 `failed to resolve source metadata for docker.io/docker/dockerfile:1` | `# syntax=docker/dockerfile:1` 会强制 BuildKit 先从 Docker Hub 取「前端镜像」。本仓库唯一用到的特性是 `--mount=type=cache`，那是内置前端原生的 —— 这行**没有任何好处，只增加一次联网依赖** | 已从 `docker/Dockerfile` 与 `services/scan/Dockerfile` 删除。**不要加回来** |
| `python:3.12-slim-bookworm: failed to resolve source metadata` | 默认基础镜像带 codename，很多镜像站不同步这个 tag | 默认值改为 `python:3.12-slim`；离线机器用 `--build-arg BASE_IMAGE=docker.m.daocloud.io/library/python:3.12-slim` |
| `extract`/`worker`/`gateway` 全部不起，`runc create failed: ... not a directory: Are you trying to mount a directory onto a file` | **`docker/lsp.local.yaml` 不存在**，而 Docker 对缺失的 bind-mount 源会**创建一个目录**，然后试图把目录挂到文件上 | 先 `cp docker/lsp.yaml docker/lsp.local.yaml`（README 已标注为必需） |
| `gateway` 反复重启，`exit 127`，日志 `env: 'bash\r': No such file or directory` | `docker/entrypoint.sh` 在工作区是 **CRLF**（`git ls-files --eol` 显示 `i/lf w/crlf`），`COPY` 进镜像后 shebang 变成 `#!/usr/bin/env bash\r`。**这个文件此前从未被执行过**，所以这个坑一直没被发现 | 已把工作区文件规范化为 LF，并新增 **`.gitattributes`**（`*.sh text eol=lf` 等）防止 checkout 再转换回来 |

> **教训**：`exit 127` 且日志里出现 `\r`，就是行尾问题，不是缺二进制。另外注意
> `docker compose build gateway` 会报 `No services to build` —— `gateway` 与 `worker`
> 复用 `aegis:0.1.0` 镜像，它的构建定义在 `extract` 服务上，要重建就 build `extract`。

### 10.17 实测链路日志（2026-09-11，六个容器全部 healthy）

```
GET  :8100/health                      → status ok, opengrep 1.16.0 (remote), scan_transport=remote
GET  :8101 :8103 :8104 :6379 (宿主)    → 全部不可达（端口策略正确）
GET  :8102/                            → 200，控制台；:8102/v1/bundles → 200（nginx 反代同源）
POST :8100/v1/jobs                     → 202 {"job_id":"J-8530…","state":"queued"}
GET  :8100/v1/jobs/J-8530…             → 6 秒后 succeeded
   stages: scan done 11241ms [scan_transport=remote] / setup..package 全 done
   counters: discovered 1, located 1, focus_methods 1, contexts 1, slices 1,
             proposed 2, kept 2, read 2, inlined 2      ← 漏斗 9 步齐全
   产物: /data/packages/B-834c9c206e（宿主 var/packages/ 可见）
         engine=opengrep location=remote rc=0，ai/cache_prefix.json 存在
```

`scan` 阶段 11.2 秒而本地就地扫描是 1 ms，说明**确实委托给了 scan 容器**（HTTP + 冷启动
opengrep）；这是 §3 那个环境变量生效的直接证据。

### 10.18 队列的失败/中断路径：实测数字与两个真被修掉的缺陷（2026-09-11）

四条路径在真容器里各跑了一遍，**其中两条第一次跑就发现实现是错的**。

#### 取消（缺陷，已修）

| | 修复前 | 修复后 |
|---|---|---|
| 取消 → 终态 | **131 秒** | **0.85 秒** |
| 取消后残留的 opengrep 进程 | 1 个（`opengrep-core` 在烧 CPU） | **0** |
| scan 容器 CPU | 640% | **0.12%** |

两个独立成因：

1. **`httpx.post` 是一次阻塞调用**（`services/scan/client.py`）。worker 在整段扫描里回不到
   主循环，所以既看不到自己的取消请求，也刷不了心跳。改成**可轮询的扫描作业**
   （`services/scan/jobs.py`：`POST /v1/scan/jobs` → 202 + id、`GET` 轮询、`DELETE` 取消），
   服务端持有 `Popen` 句柄，所以「后来的一个 HTTP 请求」能杀掉「已经在跑的扫描」。
   文档 §6.5.3 原本承诺的"本端 ≤2s"从未实现，现在是真做到了。
2. **只杀直接子进程，孙进程活下来**。opengrep 是个启动器，干活的是 `opengrep-core`。
   `terminate_tree` 在 POSIX 上只做 `terminate()→kill()`，`taskkill /T` 那支因为
   `os.name == "posix"` 根本不走 —— 于是**所有可观测信号都说取消成功了，CPU 还在烧**。
   修法：`Popen(start_new_session=True)` + `os.killpg()`，信号打到整个进程组。
   回归测试在 `tests/test_scan_stage.py::test_terminating_a_scan_reaches_its_grandchildren`。

#### 优雅关停（正确）

`docker compose stop worker` 中途：job 回到 **`queued`**（不是 canceled）、
`cancel_requested=false`、`attempt` 仍是 1、进度保留、对端扫描被取消（0 残留），
重启后**同一个 attempt** 被新 worker 接手。日志：`job … returned to the queue for a restart`。

#### worker 崩溃（缺陷，已修）

第一次测：`docker kill` worker 后，job **在 `running` 停留了 2 分钟以上**，而启动自检
报告 `running: 1` 却什么都没做。原因是我的 `_reconcile_running` 里写了
`if heartbeat_age < visibility_timeout_s: return` —— 而方案 §6.3 明确要求这一层
**不依赖那个时钟**（默认 1800 秒，所以它实际上永远不会触发）。

修法：把判据从「心跳多新」换成「**那个 worker 还在不在**」
（`_worker_is_alive`：查 `aegis:queue:worker:{worker_id}` 这个存活键）。
因为慢任务**不会**停止 worker 的心跳，所以这个判据不会误杀慢任务。

**实测的恢复时限**（比我原先以为的长，如实记下）：

```
worker 被杀 → 它的存活键 TTL 到期（max(heartbeat*4, 60) = 60s）
            → 下一个 worker 启动时的自检把它救回 queued（attempt 不变）
```
日志证据：`reclaimed job J-618… at startup (worker efa78cca6774:1:96ba gone, heartbeat age 162s)`。

所以第 1 层的真实语义是「**至多一个存活键 TTL**」，不是"秒级"。
注意 `docker kill` 会让容器停在那里（`Exited (137)`），**不会自动重启** ——
`restart: unless-stopped` 由编排器在容器退出时执行，`docker kill` 之后我实测到
`aegis-worker | Exited (137) 2 minutes ago`，是我手动 `up -d worker` 才回来的。
也就是说：**没有 worker 就没有 reaper**（§6.3 第 3 层那条已知静默窗口），
生产上必须有编排器保证 worker 会回来。

#### 一个部署建议

`AEGIS_QUEUE__VISIBILITY_TIMEOUT_S` 默认 1800 秒，即一个死掉的 job 最多可以被
"合法地"留在 running 半小时。它与"最长任务时长"应该同量级，建议设为**最长任务的
2–3 倍**并在 `.env` 里显式写出来，不要靠默认值。

---

### 10.19 "数据能不能直接喂给 AI"审计出的两处缺陷（2026-09-11，均已修）

为了回答"当前产物是不是已经能直接喂给模型"，逐字读了 `ai/prompt.md` 并与真实源码核对，
**两处都在"看起来完全正常"的地方**：

#### 缺陷 A：示例 SARIF 的行号与它自己引用的片段不符

`demo/scan.sarif` 里 `startLine` 是**在 `write_sarif()` 里硬编码的 5**，紧挨着一个同样硬编码的
`snippet`。夹具后来在前面加了 docstring 和两个空行，片段移到了第 6 行，**数字没动**。于是：

```
demo/scan.sarif: startLine=5, startColumn=12, snippet='sql = "SELECT ..."'
demo/repo/repo.py:5 → '    cursor = connect()'     ← 声称的位置
demo/repo/repo.py:6 → '    sql = "SELECT ..."'     ← 片段真正所在
```

**为什么一直没被发现**：`tests/test_sarif.py` 与 `tests/test_scan_stage.py` 只断言了
`region.start_line == 4`（5→4 的 base 转换），而**转换本身是对的**，所以两个数字
"互相证明"了对方。错的行号一路进到 `demo/scan.sarif` → bundle → 每一个 prompt：
模型被告知"at repo.py:5"，而片段在第 6 行。

**修法**：`tests/fixtures.py::sink_line_in_fixture()` 从夹具源码里**推导**出 sink 行，
使行号与片段不可能再分家；`write_sarif()` 的 region 默认用推导值，需要故意摆位置
（比如放在任何方法之外）的测试改用新的 `region_line=` 参数显式表达意图
（`tests/test_assemble_stage.py::_sarif_with_two_contexts` 就是这种，它靠"落在方法外"
才产生 prune 和 alias）。回归测试：`tests/test_sarif.py::test_the_sample_sarif_points_at_the_line_it_quotes`。

> 该测试断言的正是过去缺失的那件事：**region 指向的那一行必须真的包含它引用的片段。**

#### 缺陷 B：fan-out 表的 `approx tokens` 少报约 5 倍

`fanout.plan` 的表给每个 context 报一个 token 数，取值是
`AssembledContext.estimated_tokens`。而这个字段在 `contexts.py` 里只累加
**内联方法体 + 调用点片段**：

```python
context.estimated_tokens = estimate_tokens("\n".join(b.text for b in inlined.values())) \
                         + estimate_tokens("\n".join(e.call_site_snippet for e in context.edges))
```

它**不含** context 标题、`### Static-scan findings` 段、`refs` 调用链段、`### Edges` 段。
实测同一个 context：表里 **120**，真实渲染出来的块 **576 —— 4.8 倍**。而这张表存在的
全部意义就是让调用方按它给子代理分配预算，所以这是最不该出错的一个数字。

**修法**：`BundleRenderer.render()` 先把渲染好的 context 块收集成
`{context_id: tokens}` 传给 `_chunking_plan()`，表里报**真实块体积**；列名从
`approx tokens` 改成 `block tokens`。`summary.md` 里那张同源的表同样改用
`bundle.prompts` 里的块体积。`estimated_tokens` 本身保留（它是"可读载荷"的下界），
但不再冒充交付体积。

> 教训与 §6.3 同源：**同一个量有两个出处时，一定有一个是错的。** 表的数字必须来自
> 真正被打包和发送的那个对象（`PromptBlock.estimated_tokens`），不能来自渲染前的中间字段。

### 10.20 完整数据流：用 Joern 替掉有"方向墙"缺陷的调用链爬取（2026-09-11）

这是**这一轮最重要的结构性修正**，它来自一个具体缺陷，而不是"想更精确一点"。

#### 缺陷回顾：`builder.py` 的方向墙

`services/extraction/graph/builder.py` 的 BFS 从焦点出发，向上走 caller、向下走 callee，
但**节点被哪个方向发现，就只沿那个方向继续走**：

```python
# 发现节点时把方向固化
queue.append((symbol, depth + 1, direction))
# 出队时按这个方向决定问谁
if direction is EdgeDirection.CALLER:
    neighbours = self.resolver.callers(method)   # 只问"谁调用它"
else:
    neighbours = self.resolver.callees(method)   # 只问"它调用谁"
```

后果（实测，用 `var/variants3/` 四个算例 + LSP 提问日志确认）：

| `clean()` 被谁调用 | 收到了吗 | 怎么进来的 |
|---|---|---|
| sink 自己 | ✅ | `callees(sink)` |
| sink 的**直接调用者** | ❌ | `callees(handle)` **从未被问过** |
| 入口（再上一层） | ❌ | 从未被问过 |
| 兄弟分支 | ❌ | 从未被问过 |

**而且没有任何 prune 记录这件事** —— 包看起来是完整的。

最严重的实例就是 demo：`handle_request` 调用 `safe_escape`（`util.py:4`，真的在做
`'` → `''` 转义），它是决定这条 SQL 注入成不成立的**唯一**函数，却不在包里。模型因此
只能答 `needs_more_context`。

**关键证据**：同一批算例上，语言服务器**明确答得出** `callees(handle_request) ->
['safe_escape', ...]`。信息一直在，只是没人问 —— 但这不是"提问方式错了"能概括的：
**别名、动态派发、跨文件这些是能力边界，爬取怎么调参都到不了。**

#### 修法：让 Joern 给完整数据流，判断权交给模型

```
opengrep  找告警（不变）
   ↓
Joern     reachableByFlows：从不可信输入到 sink 的完整路径（跨文件）
   ↓
Aegis     把路径上每个方法的全文附进包（reader 已有）
   ↓
AI        判断"路径上的转换是否足够"
```

**为什么不让 Joern 判"清洗够不够"**：`safe_escape` 是项目自定义函数，形式化引擎默认
当普通函数 —— 实测把清洗版与未清洗版的包给 Joern，它 `reachableByFlows` **返回相同的
流**。判断"够不够"需要业务知识，是模型的活。我在这上面卡了 6 次（猜 `Semantics` /
`FlowSemantic` 的工厂方法都失败），最后放弃声明 sanitizer，改用"给流 + 给全文"。

#### 落地

| 文件 | 作用 |
|---|---|
| `docs/DATAFLOW_CONTRACT.md` | **字段级契约**（从真实输出定稿，不是设计稿） |
| `aegis_contracts/dataflow.py` | `FlowElement` / `TaintFlow` / `FlowBundle` / `FlowMethodBody` |
| `services/dataflow/worker.py` | worker 核心：常驻 Joern server（本地子进程）、CPG 缓存、流查询、sink 推导 |
| `services/dataflow/worker_app.py` | worker 的 HTTP 面：`POST /v1/query`、`GET /health` |
| `services/dataflow/router.py` | 亲缘路由：`worker_for(workspace, N)`，内容哈希取模，纯函数 |
| `services/dataflow/Dockerfile` | worker 镜像：Joern 基底 + Python 3.9 supervisor |
| `services/extraction/dataflow/client.py` | 调用方：算亲缘 → HTTP；方法正文在本地拼装 |
| `services/extraction/graph/builder.py` | `build()` 改为分发器：有 dataflow 走流，否则走爬取 |
| `docker/docker-compose.yml` | `dataflow-0` / `dataflow-1` 两个 worker 服务 |
| `aegis_core/config.py` | `DataflowConfig`（**默认关**，需要 JVM + 镜像；**没有 `sink` 旋钮**） |
| `tests/test_dataflow.py` | 23 条，用 stub 替代 JVM |

三个设计决定值得记住：

1. **空流是答案，不是失败**。参数化查询实测 `flow=0` —— 引擎**证明**了值到不了 sink。
   失败会 `raise`，空流返回 `FlowBundle(flows=[])`。把两者混起来会把"已修复"说成"分析坏了"。
2. **流不能拍平**。拍平后看起来像"一条路重复自己"，所以契约是 `flows: list[TaintFlow]`
   而不是一个元素数组。
   > 当时的证据是 demo 返回 **2 条**独立路径（16 和 20 个元素）。**2026-09-12 起不再复现**：
   > 四种锚点形式各跑一遍，全部只有一条 20 元素、跨 4 文件的流。形状仍然必须支持，但
   > "demo 有两条"已经是一段记忆 —— 见 `docs/DATAFLOW_CONTRACT.md` §4 第 1 条。
3. **引擎坏了要降级且留痕**。`dataflow_unavailable` prune 记录原因，然后回退到爬取 ——
   绝不能把"JVM 挂了"表现得像"没找到路径"。

#### 实测数字

| 项 | 值 |
|---|---|
| 建 CPG（demo，4 文件） | **2.3 秒**；查询一次 JVM 约 **8 秒**（`--server` 常驻可摊薄到 ~1 秒/次） |
| 首请求（新容器：起 server + 建图 + 推导 + 查询） | **≈16.6 s**（server 启动就占 11.3 s） |
| WARM 请求（server 与图都常驻） | **≈2.1 s**（推导 1.0 + 查询 1.0） |
| 两个 worker 并行（同项目、两查询） | **1.99× 加速**（wall 2.1 s，串行 4.2 s） |
| Python 前端 | 纯语法解析，**不需要项目能编译、不需要装依赖** |
| 参数类型 | 全是 `ANY`（无类型推断）；装饰器 / `getattr` / 动态派发看不穿 |
| 镜像 | 5.92GB，需要 JVM；每个 worker 一个常驻 JVM |

> **读数字的坑（记账）**：最初把 `elapsed_s`（只是流查询那一段）当成"请求成本"，于是
> warm 记成 1.0 s（实际 2.1 s）、首请求记成 4.4 s（实际 16.6 s）。worker 现在一次返回
> `start_s` / `load_s` / `sink_elapsed_s` / `elapsed_s` 四个数与它们的和 `total_s`。
> 这个错误也污染过 `var/joern/test_fleet.py` 的第一版 —— 它打印"wall 2.1 s，各 worker
> 报的耗时之和 2.0 s"，把"看起来串行了"当成结论，而其实是**每个 worker 的耗时少算了
> 推导那一段**。重写后它实测并行加速 1.99×，并且 verdict 会真的去比这个比值。

#### 验收结果（`var/joern/acceptance.py`）

```
methods (4): handle_request, load_user, query_user, safe_escape      ← 之前只有 3 个
Call chain slice: - d9 ^ safe_escape (util.py:4-5) [joern_dataflow]
prunes: dataflow_multiple_paths: 引擎返回 2 条独立路径，全部包含
prompt 里有 def safe_escape: True
```

> 上面这段是**当时的**输出，`prunes: dataflow_multiple_paths` 一行现在已经不会出现（那条
> 路径不再复现，原因见上）。2026-09-12 重跑，改成走集群后的实际结果：
>
> ```
> 冷启动（刚清空 cpg/ 并重启 worker）: 14.6s   methods 4 个，files 4 个  prunes 无
> 温请求（worker 常驻）              :  2.2s   methods 4 个，files 4 个  prunes 无
>   PASS  safe_escape collected / sanitizer body in prompt / transformation visible
>   PASS  joern_dataflow labeled / flow crosses files
> ```
>
> 那 2.2 s 是**穿过整条流水线**测到的，与 `test_fleet.py` 在 worker 层测到的 2.1 s 一致 ——
> 两个独立测量相互印证，说明编排本身没有额外开销。

#### 判别力验证（`var/joern/RESULTS.md`）

同一个调用链、同一个 sink，**只改清洗函数的实现**：

| 清洗函数 | verdict | severity | confidence |
|---|---|---|---|
| `return value.replace("'", "''")` | true_positive | high | 0.60（并指出取决于 DB 驱动） |
| `return v`（空操作） | true_positive | **critical** | **0.97** |
| 反斜杠+单引号都处理 | **false_positive** | informational | 0.95 |
| 参数化查询 | **无流**（Joern 直接报 flow=0，不用调用模型） | — | — |

模型从"我不知道这个清洗函数是什么"前进到"它只处理了一个字符，够不够取决于 DB 驱动"。
**这是"数据够不够"的直接证据。**

#### 锚点：sink 不必再配置（同日补做）

初版把 source/sink 都做成配置项。**这是偷懒** —— finding 自己就说了规则在哪一行命中。

**2026-09-12 又往前走了一步：`sink` 配置旋钮被删掉了**。第一版只是让"配置优先"退位，
旋钮还在，等于留了一条"把答案写进部署"的路。现在的解析顺序是：
**调用方显式给（HTTP 字段，pipeline 从不发）→ 否则从 finding 位置推导 → 都没有就如实
报告、不猜**。`derive_sink_from_finding` 这个开关也一并删了：它默认开，关掉只会让
`sink_anchor` 变空，没有第二种合理行为。

推导规则：在包含 finding 的方法里，取 **finding 行及之后第一个非 operator 调用**。
operator 必须排除，因为 finding 通常报在**构造**那行（`sql = "..." + x`），而 sink 在
**执行**那行。实测：

```
repo.py:6（真实 finding；该行只有 <operator>.addition/.assignment）
      -> 推导出 execute（第 7 行）✓
repo.py:7（sink 行本身）  -> execute ✓
service.py:7（无关行）     -> query_user ✓
```

**为什么不能直接从 opengrep 规则读 sink**：实测 demo 的 `scan/original.sarif` 里，
rule 只有 `id / shortDescription / defaultConfiguration / properties{tags}`，result 只有
`ruleId / level / message / locations{fingerprints, region}` —— **SARIF 不携带 source/sink
语义**。真正的 sink 声明在规则源文件的 `pattern-sinks:` 里，而
`services/scan/opengrep.py:189` 也注明 `--sarif` 模式下不加 `--metrics`（semgrep 专有）。
从规则读 sink 需要自己实现规则解析，属将来的事（`docs/DATAFLOW_CONTRACT.md` §9 记着）。

推导是启发式，所以契约记录 `sink_derived_from` / `sink_derivation_method` /
`sink_derivation_alternatives` —— **出处必须能复查**。

#### 两个真 bug（都是实测抓出来的）

1. **空锚点匹配一切**：`anchored("")` 让查询变成"每个调用到每个调用"而爆掉。查询里加
   `if (needle.isEmpty) Nil`，且调用方在没有 sink 时**根本不发起查询**。
2. **传错了行号**：最初把**焦点方法的起始行**（`query_user` 的第 4 行）传给推导，于是它
   选中第 5 行的 `connect` 而不是 finding 第 6 行对应的 `execute`。必须传 **finding 自己的行**。

#### 三种"没有流"必须分清

| 情形 | 表现 | 含义 |
|---|---|---|
| 引擎证明无路径 | `flows=[]` 且 `sink_anchor != ""` | 代码安全，**不要调用模型** |
| 没有 sink 可查 | `flows=[]` 且 `sink_anchor == ""` | **我们不知道要找什么** —— 配置缺口 |
| 引擎失败 | 抛异常 | 记 `dataflow_unavailable`，降级爬取 |

后两者混起来，会把**配置缺口**说成**健康报告** —— 所以 builder 产生不同的 prune：
`dataflow_sink_unresolved` vs `dataflow_no_path`，`tests/test_dataflow.py` 各有断言。

#### 仍未做

- **source 仍是配置项**（`AEGIS_DATAFLOW__SOURCE`）。它不像 sink 有位置可依：finding 说的是
  "危险发生在哪"，不是"不可信输入从哪进来"，那需要规则语义或框架知识。
- **未从规则源文件读 `pattern-sinks`**（见上）。
- **推导候选多于一个时未降级**：现在取第一个并记录其余候选，正确做法应是要求人工确认。
- **`attach_bodies` 没被流水线消费**：正文仍由 `MethodReader` 从 `MethodSymbol` 读
  （两条路读到同样的字节），属重复。
- **未接进 prompt 渲染器**：`render.py` 只多了 provider 图例行；拼装样例在
  `var/joern/ask_with_dataflow.py`（做成一个 block 是下一步）。

#### 2026-09-12 收口：从"进程内直连"改成 worker 集群

初版有三套重叠实现：`services/dataflow/{app,runner}.py`（一次性容器的 HTTP 服务）、
`services/extraction/dataflow/joern.py`（进程内直连，流水线真正走的那条）、以及
`var/joern/` 里的一堆脚本。三者都要维护，且流水线走的偏偏是最慢、最不可控的那条。
现在只剩一套：

```
extract / worker 容器                       dataflow-N 容器
  WorkerDataflowClient                        worker_app (FastAPI)
    算亲缘 worker_for(workspace, N) ──HTTP──▶   JoernWorker
    收 FlowBundle ◀──────────────────────────    └─ joern --server（本地子进程，常驻）
    方法正文在本地读（字节即源码）                 ├─ 共享 CPG 缓存 cpg/<digest>/cpg.bin
                                                  └─ 各自 scratch worker-<index>/
```

删掉的：`services/dataflow/app.py`、`services/dataflow/runner.py`、
`services/extraction/dataflow/joern.py`（拉一个容器跑 `joern --script`，每次查询一个新 JVM）。

**三个值得记住的决定**：

1. **Joern 是 worker 容器里的本地子进程，不是兄弟容器。** 曾经用 `docker run` 起一次性
   容器，必须在 worker 进程里挂 docker socket —— 那等于把宿主机 root 交给一个跑在容器里
   的进程，而且容器内的 workspace 路径和宿主路径不一致，还得做路径翻译。改成子进程后两个
   问题都消失，也少了一次容器启动（约 1 秒/次）。
2. **每次查询不再是新 JVM。** `joern --server` 常驻 + `importCpg` 让图留在会话里：查询从
   约 8 秒降到约 1 秒。代价是**同一 worker 内串行**（一个会话不能同时回答两个查询），所以
   并行靠 worker 数量。实测 2 worker 并行查询加速 **1.99×**。
3. **亲缘是算出来的，不是发现出来的**：`worker_for(workspace, N) = 内容哈希 % N`。纯函数，
   跨进程稳定，不需要注册表；代码一变哈希就变，旧 worker 下次请求时自然换项目。
   **每个 worker 挂同一个 `/workspace`**：算错只是慢一点，而不是路由到看不见路径的容器
   上 404（详见 `docs/DATAFLOW_CONTRACT.md` §8 的说明）。

**镜像**：`services/dataflow/Dockerfile` 以 Joern 官方镜像为基底（AlmaLinux 9，**自带
Python 3.9**），只补几个 wheel，不装第二个 Python。代价是项目声明的 `requires-python
>=3.10` 在容器里不成立，所以 `pip install .` 不可用，依赖按名字装、源码走 `PYTHONPATH`，
并且**必须装 `eval_type_backport`** —— 否则 pydantic 无法求值 `X | None` 注解，import 就炸。
这是全仓唯一一处这样的偏离，写在 Dockerfile 头部了。

**验收**：`var/joern/test_fleet.py`（2 容器、14 项断言全过）覆盖亲缘稳定性、cold/warm
四段耗时、并行加速比、共享 CPG + per-worker scratch。注意它的**第一版是假通过** ——
verdict 没有真的去比并行加速比，却在打印"sum of worker times"；重写后比值不过就 FAIL。

**它第一次真跑就抓出一处缺陷，而且是它自己抖出来的**：有一轮"warm 不该付载入成本"红了。
原因不是 worker 坏了，而是 `_load` 每个请求都会**重算整个工作区哈希**（4 文件夹具
0.7 ms，**本仓 107 个文件 401 ms**），于是"warm 的载入成本 ≈ 0"在真实仓库上不成立。
断言已改成与 cold 对比（要测的是"没有重新 import"），缺陷本身记进
`docs/DATAFLOW_CONTRACT.md` §9 第 4 条 —— **每次查询都要付一遍 O(项目规模) 的哈希**，
方向上给了三个可选修法，都还没做。

#### 端到端跑起来才暴露的三个集成缺陷（2026-09-12，均已修）

单元测试和 worker 级验收全绿的时候，`var/joern/acceptance.py`（流水线 → HTTP → worker）
仍然一次都没成功过。三个缺陷都是"两边各自正确、接口处错"的类型，只有端到端能看到：

1. **`health()` 要求 `status == "ok"`，而刚起来的 worker 答 `cold`。** worker 是在**收到请求
   时**才拉起 Joern server 的，所以 `cold` 的意思是"我在这儿，第一次会慢 11 秒"。探针把它
   当成"不可用"，于是流水线**静默降级到爬取** —— 包照样产出、`safe_escape` 照样缺席、只有一条
   warning。这与 compose 的 healthcheck 直接矛盾（`curl -fsS /health` 对 `cold` 是 200）。
   现在 `cold` 算可达，理由写在 `client.health()` 的 docstring 里。
2. **客户端发的是宿主路径，容器里根本没有这个路径。** 报错很干脆：`workspace not found:
   E:\vib coding\aegis\demo\repo`。compose 里两边都挂 `/workspace`，所以生产路径一直是对的 ——
   但"路径必须一致"这件事以前只是**口头契约**，任何在 compose 之外跑的调用方都会撞上。新增
   `DataflowConfig.worker_workspace`：显式声明"worker 那边这个工作区叫什么"，方法正文仍从
   本地路径读。
3. **删掉正在运行的 worker 的缓存目录会把它弄坏**。原脚本的"清空缓存"会 `rmtree` 掉
   `var/dataflow`，而它被 bind-mount 进容器，并且 `worker-<index>/` 正是 worker 里 Joern
   进程的**工作目录**。宿主删掉之后，容器里那个路径变成幽灵：`mkdir(parents=True,
   exist_ok=True)` 抛 `FileExistsError: File exists`，而 `is_dir()` 同时是 False —— 表面症状
   是一个不带原因的 HTTP 500。**正确做法是停掉 worker 再清 `cpg/`**，两个验收脚本现在都
   不碰缓存，并把原因写在原地。

**结论**：worker 级验收（`test_fleet.py`，14 项断言）证明不了插件链是通的。`acceptance.py`
这一层不可省 —— 它现在冷启动 14.6 s、温请求 2.2 s，与 worker 级测得的 2.1 s 相互印证。

---

### 10.22 AI 阶段接线：从脚本变成服务，并第一次拿到真判决（2026-09-12）

`JobKind.AI_FANOUT` 之前在 worker 里直接 `NotImplementedError`。现在它是真的：契约
（`aegis_contracts/ai.py`）、配置（`AIConfig`，`AEGIS_AI__*`，**默认关**）、服务
（`services/ai/{blocks,client,parse,runner}.py`）、队列作业、两个 HTTP 端点
（`POST /v1/bundles/{id}/analyze`、`GET /v1/bundles/{id}/verdicts`）都齐了，
`scripts/feed_ai.py` 改成服务的薄 CLI —— **同一份实现**，不是第二份。

字段级契约、决策理由、实测数字都写在 **`docs/AI_STAGE.md`**，这里只留四条最要紧的：

1. **密钥只存名字。** `api_key_env` 是"环境变量叫什么"。服务只读环境；CLI 额外支持 `.env`
   （checkout 不是容器）。用**真密钥**扫过整个包：0 次出现。
2. **模型失败是结果，不是异常。** 每次调用都记档（含原始回答到 `ai/answers/<context>.md`）。
   一个 504 不能吞掉"其他上下文答对了"这个事实，也不能看起来像"模型说没问题"。
3. **每个 context 一次调用。** 前缀（指令+图例+方法目录）作为 system，跨同工作区的包逐字节
   相同 —— 这就是 provider 端缓存能命中的前提。
4. **`concurrency` 默认 1。** 实测：某网关 ~60 s 硬顶下，6 并发只回 3 个可用答案，6 串行回 6 个。

**实测（demo 包 `B-af99db8f80`，单 context）**：

| 模型 | 结果 |
|---|---|
| `glm-5.3-flash`（`.env` 原值） | **HTTP 504，每次约 67 s，3 次全败** |
| `deepseek-v4-flash` | **33.2 s，可用判决**；`cached=2048/2320（输入的 88%）` |

两个都是推理模型，推理占了输出的大头（`completion=3848`，其中 `reasoning_tokens=2930`）。
**约 60 s 的网关硬顶因此成为选模型的约束**，调大客户端 `timeout_s` 没用（504 是网关发的）。
所以 `.env` 的 `MODEL` 换成了 `deepseek-v4-flash`，并把这条测量写在旁边。

判决本身（demo 的 SQL 注入）：`true_positive / high / 0.8`，数据流逐跳引用了
`request.args.get('id') -> safe_escape -> load_user -> query_user -> cursor.execute(sql)`。
两点值得注意：

- 它**用上了我们新加的溯源信息**：指出 `Controller.dispatch` 是 `syntax_regex` 定位的、
  不是数据流引擎给的，并在 `missing` 里要求提供"证明 dispatch 对外暴露"的路由注册 ——
  也就是我们讨论过的 dispatch/handle_request 那个问题，这次由模型自己提出来了；
- 它要求 `connect()` 的定义/import 来判断 DBMS，因为 MySQL 的反斜杠转义会让单引号双写失效。

顺带把那个从 §10.19 就记着、一直咬人的 **SARIF 外来绝对路径缺陷**修掉了：根因是
`_candidate_suffixes()` 的候选里**永远不含裸文件名**（`range(1, len(parts)-1)`），所以
"工作区根就是文件所在目录"这一最常见情形永远匹配不上；`file:///E:/.../repo.py` → 不存在的
`vib coding/...` → 每条 finding `locate_failed` → **0 方法而 run 报成功**。修法是最后才试
裸文件名、且**只在其唯一时**接受（发现第二个同名立刻放弃，扫描有预算上限）—— 宁可定位失败，
也不把 finding 挂到错误的文件上。

#### 接进运行中的栈，又抓出四个只有端到端才看得见的缺陷（同日）

代码写对了不等于接上了。第一次真调 HTTP 端点，接连四个问题：

1. `_job_request()` 直接读 `rules`/`rule_config`/globs，而 `AnalyzeRequest` 没有这些字段 →
   **500**。同步路径不经过这个函数，所以带假传输的路由测试全绿也照样漏。改成全部 `getattr`。
2. **`POST /v1/assemble` 只要配了队列就 500** —— 这是**早就存在**的线上缺陷：路由声明
   `response_model=AssembleResponse`，而队列分支返回 `JobAcceptedResponse`，FastAPI 会拿返回值
   去校验模型。compose 永远配队列，所以这个主入口一直是坏的。两个路由改为
   `response_model=None` + `responses=` 文档化（不校验）。
3. **指纹漏了 `kind` 和 `bundle_id`**：`ai_fanout` 与同一工作区早先的 `scan` 作业算出**同一个
   指纹**，于是被去重到那个作业上、沿用它 id、报 `succeeded` 而**什么都没做**。抓到的线索是
   磁盘上的报告比"写下它的作业"早 25 分钟。指纹现在含 kind 与 bundle_id。
4. **所有调用都失败时作业仍报 `succeeded`** —— 既是假成功，又让 `force=true` 无法重跑
   （它只重跑失败的作业）。现在全失败 = 具名 `ai_failed`；部分成功 = `succeeded` + warning。

第五个是**规格与解析器互相矛盾**：prompt 明确要求"severity 取决于未证实的东西就写在
severity 里"，而解析器却在等一个精确的枚举值。真调用回了
`"high — impact could be critical if Controller.dispatch is externally exposed"`，被判
`unknown severity` 丢掉。现在从前缀读类别（最长匹配 + 词边界），余下文字留在
`severity_qualifier`，模型对自己结论的限定语不再丢失。

**运维坑（值得单独记）**：**重建 `aegis:0.1.0` 不会重建容器** —— compose 比的是服务配置，
不是镜像内容，所以 `docker compose up -d` 会让旧进程继续跑内存里的旧代码。必须
`--force-recreate`。这一条让我误诊了一小时。

端到端实测（真模型、走队列）：`POST /v1/bundles/B-9a5317fb78/analyze` → 202 →
`GET .../verdicts` → `true_positive / critical / 0.85`，并且模型指出 `sql_quote` 是
**恒等函数**（p1 的 no-op 清洗）—— 正是这套 bundle 设计要区分的东西。细节见
`docs/AI_STAGE.md`。

#### 源码 → AI 研判：整条链（同日，已通）

`var/joern/source_to_ai.py` 一条命令跑完全链：`POST /v1/assemble`（opengrep 扫 → LSP + Joern
集群 → bundle）→ `POST /v1/bundles/{id}/analyze`（模型）→ `GET .../verdicts`。实测：

```
STEP 1  202 → running/scan → running/setup → running/locate → succeeded
STEP 2  methods (5): Controller.dispatch, handle_request, load_user, query_user, safe_escape
        providers: ['joern_dataflow']   ← 切片来自 Joern
        dataflow : source=dispatch(request)  warmed=4
                   walk=query_user <- load_user <- handle_request <- dispatch
STEP 4  true_positive / high / 0.75，数据流逐跳引用，并指出需要 connect() 的 DBMS
        才能判断单引号双写是否充分
```

**为此又踩掉一个"环境坑"，值得单独记**：`.env` 里 `AEGIS_SCAN_TARGET=./demo/repo` 是相对
**仓库根**写的，而 compose 把相对路径解析到**项目目录**（`docker/`）——于是挂上去的是
`docker/demo/repo`，一个**不存在、被 Docker 建成空目录**的路径。后果极隐蔽：scan 容器
（未重建，仍挂真 repo）扫出 finding，worker 容器（用 `--env-file` 重建，挂空目录）读不到文件，
**0 方法、空 bundle，而整条链报 succeeded**；dataflow 集群（在修之前起）还顺手缓存了一份
"空工作区"的 CPG。修法：`.env` 改为 `../demo/repo` 并把原因写在旁边，然后四个服务 + 两个
dataflow 容器全部 `--force-recreate`。

#### 两个遗留项的修法（已实现，同日）

1. **`succeeded` 的作业无法重跑** → `force=true` 现在也能重跑**已成功**的作业
   （`_handle_duplicate` 里 `force` 之前只走到失败分支）。指纹不变、job id 就不变，所以在此之前
   同一个请求永远拿回那份没用的结果。实测：对已分析过的包再 `?force=true` → **202**（不再是 200）
   → 报告 mtime 前移 → 新的判决（40.4s，confidence 0.65，上一次是 0.75）。
2. **AI 作业报 `stage=scan`** → 契约新增 `JobStage.AI` 与 `first_stage(kind)`
   （assemble→`scan`，ai_fanout→`ai`），`handle()` / `set_running` / `redrive` 都改用它。
   另外 `mark_succeeded` 现在**不给已经结束的阶段补 `done`**，并把这个作业种类走不到的阶段标成
   `skipped` 并写明原因 —— 于是 assemble 作业的 `ai` 行读作"not part of this job"，而不是
   永远 `pending`（读起来像"还没轮到我"）。`redrive` 的备注也从写死的 `stages[0]`（=scan）
   改到该作业种类的起始阶段。

---

### 10.21 prompt 前缀缓存：终于实测了，结论和预期不同（2026-09-11）

§6.3 一直写着"只证明了前缀按契约不变，没证明 provider 真的命中"。现在有答案了，而且
答案分两半。

#### 前半：**确实命中**

provider 的计费字段直接证明（`prompt_tokens_details.cached_tokens` 或
`prompt_cache_hit_tokens`，两个键名不同厂商各用各的）：

```
call 1: cached_tokens=0       冷
call 2: cached_tokens=896  /1046  → 86%
call 3: cached_tokens=896         → 86%
```

所以 `ai/cache_prefix.json` 那块工作**没有白做**。

#### 后半：**它打在小处，天花板约 20%**

| 形态 | 输入占总 token |
|---|---|
| 并发 ×6 | 6,139 / 33,925 = **18%** |
| 批量 | 3,706 / 17,210 = **22%** |

输入已经命中 81–93%，**剩下 78–82% 是输出（推理+答案），任何前缀缓存都碰不到**。
**所以缓存不可能成为这个负载的成本杠杆。**

#### 批量 vs 并发（6 个 finding）

token 侧（无 60s 上限的端点，3 轮中位数）：

| | 批量 | 并发 ×6 |
|---|---|---|
| 输出 token | 13,504 | **27,786（2.06×）** |
| **总计** | **17,210** | **33,925（1.97×）** |

**每一轮**并发都约为 2 倍总 token —— 因为 6 次调用各自产生一份推理。**这个差异稳定。**
墙钟差异（63.0s vs 57.5s）**落在噪声里**（批量单轮波动 36–100s），n=3~5 下不成立。

#### 一条比 token 更重要的发现：网关 60 秒硬超时

在 `tokens.store` 那个网关上实测：

| 形态 | 耗时 | 完成 |
|---|---|---|
| 批量（6 个塞一个 prompt） | 64.8s | **0/1 → HTTP 504，全军覆没** |
| 并发 ×6 | 64.9s | **3/6** |
| 顺序 ×6 | 212.3s | **6/6** |

**批量失败不是因为请求大，是因为网关在 60 秒切连接**，而批量调用在模型跑完前什么都不返回。

> **架构含义**：如果生产端点有这类上限，**批量直接被否决** —— 一次超时丢掉全部结论。
> fan-out（每个 finding 一个小请求）是唯一能跑完的形态。若无此上限，批量省约 2× token。

完整数据与测量脚本：`var/joern/BENCHMARK.md`。

---

## 11. 未完成工作与两个待决策

### 11.1 待决策 A：任务队列选型 —— **已决策，方案已成文**
`/v1/assemble` 现在是**同步阻塞**（约 11.5 s）。目标形态：

```
POST /v1/assemble  →  202 {job_id}
GET  /v1/jobs/{id} →  {status, progress, result}
```

**决策（2026-09-11）与交接时的倾向有三处不同，接手前先读 `docs/QUEUE_PLAN.md`：**

| 项 | 交接时的倾向 | 已定 |
|---|---|---|
| 队列技术 | Redis + 轻量 worker（Celery 抽象面积过大） | ✅ 同，用 **Redis Streams**（`XADD` + consumer group + `XACK`），不用 List/BLPOP |
| worker 形态 | 未定 | ✅ **新增 `worker` 容器**，与 extract 共用镜像、不同 entrypoint；**进程内**跑 `AssemblyPipeline`，**不**走 `AEGIS_EXTRACTION_SERVICE_URL` |
| 取消 | 「动手前先确认是否需要」 | ✅ **需要，且做真取消**（能打断进行中的 LSP 调用与扫描子进程），不是标志位 |
| 进度回传 | 「这决定是否必须 pub/sub」 | ✅ 要**阶段级进度（阶段名 + 计时）**，对齐漏斗 9 步；权威状态在 Redis，推送只做加速 |

> ⚠️ worker 必须**进程内**提取，这一条不是口味问题：远程提取走 `httpx.post(..., timeout=1800)`，
> worker 在那段时间回不到事件循环写心跳，reaper 会把健康 worker 判死；而且
> `services/extraction/routes.py::extract` 里的 `pipeline.run()` 没有 observer / cancel 回调，
> 远程模式下进度只剩 2 个粗阶段，真取消也不可能实现。

### 11.2 前端技术栈 —— ✅ **已决策并落地：React 18 + TypeScript + Vite**
当时倾向 Vue 3；实际选 React 是因为后端已经有一份现成的四屏实现可以直接演进，而框架偏好不值得
把已经验证过的交互重写一遍。最终形态见 §11.3（2026-09-12 重做为独立部署）。

准备工作（仍然有效）：
- `docs/VISUAL.md`：Mermaid 数据流 + 四屏信息架构 + ASCII 原型
- `docs/prototype.html`：可交互原型
- 后面这条**已被推翻**：~~`aegis_contracts/views.py`：所有视图数据已经由后端算好，前端只负责渲染，
  不做计算~~ —— 现在前端自己算展示数值（counts、cache 命中率、token 合计、project 分组），
  后端只发原始事实。`verdicts_view` 因此被删掉，见 §11.3。

> 历史提醒：上一版 console 的 `index.html` 里有个未修复的 JS 语法错误
> （`SyntaxError: missing ) after argument list`，在 `screenContext` 末尾），
> 当时控制台迁移到 `services/web/` 时那个文件被**删掉而不是修好**。
> 重建时请保留语法检查：`node --check` 已用于校验 console JS。

### 11.3 前端观测台 —— ✅ **已建成（2026-09-11），2026-09-12 重做为「独立部署」**

**第一版**（`services/web`，`aegis-web` 镜像）是 nginx 服务静态产物并**反代 `/v1`** 到 gateway，
浏览器因此永远同源：没有 CORS，产物里也没有 API 地址。代价是两样东西被焊死 —— 静态文件只能由
那一个 nginx 提供，而 API 的 host:port 成了前端部署的一部分。

**现在**的 `frontend/`（`aegis-frontend` 镜像，端口 8102）**不反代任何东西**：

* **API 地址在运行期决定。** 容器入口脚本把 `AEGIS_API_BASE` 写成 `/config.js`，nginx 启动前
  就位；构建期只剩 `VITE_API_BASE` 给 `npm run dev` 用，而且 `.dockerignore` 排除了 `.env*`，
  所以生产镜像里**不可能**带上地址。**一个镜像可以指向任意 gateway**，改地址是重启而不是重建。
  `tests/test_frontend_contract.py` 断言构建产物里不含 API origin。
* **浏览器跨域直连 gateway**，所以 `AEGIS_CORS__ALLOW_ORIGINS` 必须包含前端 origin（默认 `*`）。
  结构性证据：`GET /v1/bundles` 打在前端源站上返回的是**页面而不是 JSON**。
* **与后端零源码耦合。** 契约测试改为从 gateway 拉 `/openapi.json` 比对
  （`frontend/test/contract.test.ts`）；`frontend/test/openapi.snapshot.json` 是**抓下来的 HTTP
  响应**（数据，不是后端源码），`npm run snapshot` 刷新；设了 `API_URL`/`AEGIS_API_BASE` 时
  会同时比对线上文档，防止快照腐坏 —— 只靠快照的话，后端改名后前端仍会全绿。
* **展示数字前端自己算**（`frontend/src/format.ts`）：counts、cache 命中率、token 合计、project
  分组、进度分母。后端 `/v1/verdicts` 因此改回**原始 `ai/report.json`**，`views.verdicts_view`
  已删除（它的存在本身就是把"怎么展示"放在服务端）。

菜单：Overview / Jobs / Bundles（含单包详情）/ Compare / AI verdicts / Projects / Traffic /
Settings。其中三个值得记：

* **Projects 是派生的**：后端没有 project 实体，project 就是 job 与 bundle 上记录的 workspace
  路径，分组在 `format.ts` 里做。为它加端点等于发明一个不存在的注册表，页面就会声称比数据更多
  的结构。
* **Traffic** 读的是 gateway **进程内**的环形缓冲（500 条）：重启即空，多副本时只看得到自己那
  一路。页面把 API 自己那句 note 原样显示，因为读错这个限制会从"空的日志"推出错误结论。
* **Settings 只读**：配置来自环境变量，"改一个设置"等于改容器 env 并重启；可编辑的表单要么得
  写 env（本项目没有控制面），要么就得假装。API key 只出现**变量名**与 `api_key_present`。

`tests/test_frontend_contract.py` 把前端测试接进 `pytest`：`python -m pytest -q` 一条命令同时
覆盖 Python 与前端（Node 或 `frontend/node_modules` 不可用时自动 skip）。它只做"转发 + 检查
构建产物不含 API origin"两件事，**不读前端源码也不读后端源码**去互相比对。

> 第一版的教训，仍然成立：一条不会失败的检查比没有检查更糟。旧控制台那条"前端不做算术"的静态
> 检查自带**反向自检**（构造一个 `alpha - beta` 必须被抓到，而 `scripts/demo.py` 与
> `Static-scan findings` 必须不被抓）。现在这条规则没了 —— 展示数字本来就归前端算 —— 取而代之
> 的是 `frontend/test/format.test.ts`：把每个前端自算的值（counts、cache 比、token 合计、
> project 分组、分母未知时的进度）钉在具体数字上。自算的代价就是，算错时后端不会替你发现。

> 两条踩过的坑，写给下一个人：
> * **`npm` 在 Windows 上是 `npm.cmd`**，Python 里直接 `subprocess.run(["npm", ...])` 会
>   `FileNotFoundError`；用 `shutil.which("npm.cmd") or shutil.which("npm")`。
> * **npm/Vite 的输出是 UTF-8**，而 Windows 默认代码页解不了它，会把构建的读取线程打死并把
>   一次成功构建报成失败。`encoding="utf-8", errors="replace"` 不是可选项。
> * **`app.routes` 不再包含被 include 的 router**（FastAPI 0.115 用惰性包装），
>   列出路由必须走 `create_app().openapi()["paths"]`。

### 11.4 `app/` 物理迁入 `services/extraction/` —— ✅ **已完成（2026-09-11）**
`app/` 现在只剩 gateway 外壳（`api/`、`schemas/`、`main.py`、`cli.py`），能力层在
`services/extraction/{pipeline,graph,lsp,parsers,assembler}/`，派生视图在 `aegis_contracts/views.py`。

这次迁移的收益不是目录整洁，而是**解掉了一个真实的顶层环**：迁移前 `app → services` 有 6 处
（扫描/提取客户端），`services → app` 有 3 处（`routes.py` 的 `app.pipeline.assemble`，以及它为
复用 `probe_lsp` / `resolve_workspace` 而 import `app.api.deps`）。三条边现在都归零，做法是：
`probe_lsp` 搬到 `services/extraction/lsp/probe.py`；`resolve_workspace` 的**策略**下沉到
`aegis_core/workspace.py`，由各服务自己把 `WorkspaceNotFound` 译成自己的协议错误
（网关 → 400）。

`tests/test_contracts.py` 用 AST 把这件事钉住了，**`services -> app` 的边数必须为 0**，
所以以后没人能悄悄把它加回来。同一个文件还钉住两条：`aegis_contracts` 到 `aegis_core` 的
import **恰好 1 条**（`domain.py` 用 `estimate_tokens`，是已知的分层措辞例外，见
`SERVICE_TOPOLOGY.md`），以及 `aegis_contracts/views.py` 不得 import 任何服务。

> 顺序提醒：队列方案（§11.1）会新增 `services/queue/`——**与 `scan/`、`extraction/` 平级的
> 能力包，不是服务**。gateway 要读写 JobStore，所以它不能挂在 extraction 下（那等于 gateway
> 依赖 worker 的能力包），也不能留在迁移后的 `app/` 里。迁移已完成，队列可以直接落在最终位置。

### 11.5 demo 夹具（`demo/repo`）应当进仓库
`docker/docker-compose.yml` 默认挂 `../demo/repo`，而那个目录是 `scripts/demo.py`
用 `tests/fixtures.py::write_fixture()` **生成**的，仓库里没有 → 见 §12 第 2 步的陷阱。
已定的修法是把 `demo/repo/` 提交进仓库，`.gitignore` 里整条 `demo/` 要拆成
`demo/*` 加逐级取反（Git 的规则：父目录被忽略后，子文件无法用 `!` 单独救回；
`demo/lsp.yaml` 含本机解释器绝对路径、`demo/scan.sarif` 是生成物，都不进仓库）。

### 11.6 后续（明确不在本次范围）
威胁建模子代理、AI 侧并行 fan-out、prompt 前缀缓存的**真实 provider 命中率实测**
（§6.3 只证明了前缀按契约不变，没证明 provider 真的按它命中）。

---

## 12. 交接检查清单

接手第一天建议按顺序做这几件事，用来确认环境与理解都到位：

1. `python -m pytest -q` → 确认 **395 passed, 12 skipped**（skip 分两种：引擎探测、
   以及需要真 Redis 的用例，都不是失败）。不是这个数就先别改代码；
   `python -m pytest -q -m slow` 应额外得到 **6 passed**。
2. `python scripts/demo.py` → 看一遍完整流水线输出，读 `var/packages/<id>/summary.md`。

   > ⚠️ **这一步不能跳过**：`demo/repo` 是 `demo.py` 用 `tests/fixtures.py` **生成**的，
   > 仓库里没有它。而 `docker/docker-compose.yml` 默认就挂 `../demo/repo` ——
   > 没跑过 `demo.py` 时 Docker 会替你建一个**空目录**挂上去，扫描 0 命中，产出
   > 一个**看起来完全正常**的空 bundle，不报任何错。先跑 `demo.py`，或把
   > `AEGIS_SCAN_TARGET` 指向你自己的仓库。
3. 打开 `var/packages/<id>/ai/prompt.md` → 对照 §6 确认块顺序。
4. `python scripts/observe.py` → 看可观测视图，重点看漏斗 9 步与来源直方图。
5. `docker compose -f docker/docker-compose.yml config --services` → 应输出 `scan` / `extract` / `gateway`。
6. `docker compose -f docker/docker-compose.yml up --build` → 打通三跳，确认日志里有
   `delegating extraction` → `delegating scan` → `bundle written`，
   并且 `scan_transport` 是 **remote**（如果是 in-process，说明 §3 那个环境变量漏了）。
7. 从宿主 `curl http://127.0.0.1:8101/health` → **应该连不上**。连得上说明端口策略被破坏了。

**改代码前请先读完 §10。** 那一节里几乎每一条都对应一次「看起来正常、其实是错的」的静默故障。

---

## 13. 关键文件索引

| 想了解 | 读这个 |
|---|---|
| 流水线怎么串起来 | `services/extraction/pipeline/assemble.py` |
| LSP 调用链的全部细节 | `services/extraction/graph/providers.py` |
| 预算怎么裁、痕迹怎么留 | `services/extraction/graph/builder.py` |
| 方法体怎么读、怎么归一化 | `services/extraction/assembler/reader.py` |
| 去重与上下文聚合 | `services/extraction/assembler/contexts.py` |
| prompt 排版契约 | `services/extraction/assembler/render.py` |
| 落盘产物 | `services/extraction/assembler/package.py` |
| 可观测视图怎么算 | `aegis_contracts/views.py` |
| 数据形状 | `aegis_contracts/domain.py` |
| 配置项全集 | `aegis_core/config.py` |
| 服务拓扑与端口策略 | `docs/SERVICE_TOPOLOGY.md` |
| 架构与设计取舍 | `docs/ARCHITECTURE.md` |
| 前端信息架构与原型 | `docs/VISUAL.md`、`docs/prototype.html` |
| 假 LSP server | `tests/fake_lsp_server.py` |

---

## 附：外部依赖

- opengrep：<https://github.com/opengrep/opengrep>（release 资产名 `opengrep_manylinux_x86`，用 v1.16.0）
- 注意：`ghcr.io` 上的 opengrep 镜像**拒绝匿名拉取**（403），所以 Dockerfile 用的是 release 二进制。
- semgrep 作为可选兜底引擎（`AEGIS_OPENGREP_FALLBACK_BIN`）。
- 语言服务器：pyright（Python）、clangd（C/C++）；Node 22 来自 NodeSource，TypeScript 固定 5.9.3
  （带主版本断言，防止静默升级）。
