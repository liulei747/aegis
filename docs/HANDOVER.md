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

**当前状态一句话**：上面这条流水线**端到端可跑、有 119 个测试、有 Docker 本地部署、有可观测台接口**；
AI 部分（威胁建模子代理、prompt 前缀缓存）**刻意没做**，但 bundle 的排版已经按「前缀可复用」设计好了。

**新人第一天该跑的三条命令**（详见 §4）：

```powershell
python -m pytest -q                                  # 119 passed, 1 skipped
python scripts/demo.py                               # 本地跑一遍完整流水线
docker compose -f docker/docker-compose.yml up --build
```

---

## 1. 代码地图：谁负责什么

```
aegis/
├── aegis_contracts/        共享数据形状。纯 pydantic，无 I/O。跨服务传输的就是它。
│   └── domain.py           Finding / MethodSymbol / CallEdge / PruneDecision /
│                           MethodContext / Coverage / Degradation / ScanRecord /
│                           RunStats / AnalysisBundle(Manifest) / PromptBlock
├── aegis_core/             每个服务都要的基础设施，无业务。
│   ├── config.py           Settings / BudgetConfig（pydantic-settings，见 §7）
│   ├── logging.py          统一日志
│   └── utils.py            sha1、content_hash、estimate_tokens、路径换算（to_uri/rebase_path…）
│
├── services/               ★ 服务边界在这里，不叫 app/
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
│   │   └── app.py
│   └── web/                观测台前端（**待建**，见 §11）
│
├── app/                    ★ 业务逻辑本体（尚未物理迁入 services/extraction/，见 §11）
│   ├── pipeline/assemble.py    AssemblyPipeline：把下面所有阶段串起来的地方，先读这个文件
│   ├── graph/
│   │   ├── resolver.py     Workspace（读文件、按行切片、找局部方法）、SymbolIndex
│   │   ├── providers.py    ★ CallGraphResolver：LSP 调用链的全部细节都在这里
│   │   └── builder.py      CallGraphBuilder：双向 BFS + 预算裁剪
│   ├── lsp/                语言服务器客户端、配置、进程生命周期
│   ├── parsers/            语法兜底解析（LSP 不可用时退化成 syntax_regex）
│   ├── assembler/
│   │   ├── reader.py       MethodReader：按字节范围读方法体，全局字符预算
│   │   ├── contexts.py     ContextAssembler：按 sink 聚合上下文 + 三级去重
│   │   ├── render.py       BundleRenderer：渲染成给 AI 的 prompt 块（排版顺序是契约，见 §6）
│   │   └── package.py      BundlePackager：落盘、summary.md、DOT、zip
│   ├── observability/views.py  ★ 纯派生视图，不落盘、不改状态：漏斗/时间线/来源/上下文/方法
│   ├── api/                gateway 的路由（routes.py 业务路由 / deps.py 依赖装配）
│   ├── schemas/api.py      HTTP 层的请求/响应模型（**数据契约在 aegis_contracts，不在这里**）
│   ├── main.py             FastAPI 工厂（gateway 的 ASGI 入口：app.main:app）
│   └── cli.py              本地命令行：aegis assemble|scan|probe
│
├── docker/                 Dockerfile（全家桶）、docker-compose.yml、lsp.yaml、lsp.local.yaml
├── tests/                  119 个用例，含一个零依赖的假 LSP server（见 §8）
├── docs/                   ARCHITECTURE / SERVICE_TOPOLOGY / VISUAL / 本文 / prototype.html
├── scripts/                demo.py（跑全流程）、observe.py（打印可观测视图）
└── var/                    运行时产物：packages/（bundle）、work/（SARIF 等中间件）
```

**读代码的最短路径**：`app/pipeline/assemble.py` 里 `AssemblyPipeline.run()` 是**线性**的，
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
| 可观测视图（漏斗/时间线/来源） | ✅ 接口完成，**前端未建** | `app/observability/views.py`（722 行）、`test_observability.py`（22 例） |
| 服务拆分（scan / extract / gateway） | ✅ 完成并验证三跳链路 | `docker/docker-compose.yml`、`docs/SERVICE_TOPOLOGY.md` |
| 前端观测台（`aegis-web`） | ❌ **未建** | `services/web/` 只有 README 占位 |
| 任务队列 | ❌ **未做** | `/v1/assemble` 现在是同步阻塞（约 11.5 s） |
| AI 分析（威胁建模子代理、prompt 缓存命中） | ❌ **刻意未做** | bundle 排版已按前缀复用设计 |
| `app/` 物理迁入 `services/extraction/` | ❌ 未做（仅目录整洁问题，**部署边界已生效**） | `routes.py` 靠 `app.*` 导入 |

> 测试基线：`119 tests collected`，`python -m pytest -q` → **118 passed, 1 skipped**
> （skip 的是需要真实语言服务器子进程的 `slow` 用例）。

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
│   └── blocks_meta.json 每块的 block_id / 标题 / token 估算 / 是否 cacheable
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

`app/assembler/render.py` 里 `PROMPT_VERSION = "2025-01-assemble-v1.1"`，块顺序固定为：

```
bundle.header            ← 非 cacheable！见下面的警告
  → instructions.system
  → instructions.legend
  → instructions.chunking
  → method_catalog        ← 到 method_catalog 为止是「稳定前缀」，cacheable = true
  → context.<id>          ← 从这里开始随 bundle 变化
  → run.notes
```

**为什么这么排**：AI 侧的 prompt 前缀缓存（用户提到的 IAI 式预填充加速）只对**完全相同的前缀**命中。
把随 bundle 变化的内容全部压到后面，前缀就能跨 bundle 复用。

`ai/blocks_meta.json` 里每一块都带 `cacheable` 标志，
将来 AI 侧直接读它来决定哪些块要打缓存标记，**不需要再解析 prompt 文本**。

实测（demo bundle `B-c7f830954f`，7 个块，共 1841 tokens）：

| 块 | tokens | cacheable |
|---|---|---|
| `bundle.header` | 36 | ❌ |
| `instructions.system` | 623 | ✅ |
| `instructions.legend` | 119 | ✅ |
| `instructions.chunking` | 102 | ✅ |
| `method_catalog` | 296 | ✅ |
| `context.C-…` | 576 | ❌ |
| `run.notes` | 89 | ❌ |

稳定前缀 = **1140 tokens**，占这个小 bundle 的 **62%**；前缀大小基本恒定，
所以 bundle 越大占比越高（demo 这种小 bundle 是最差情况）。

> ⚠️ **给 AI 阶段的坑（现在就该知道）**：`bundle.header` 被排在最前（`_block_order` 里 rank 0），
> 但它**不是 cacheable** —— 因为它含 `bundle_id`、context 数和总 token 数，每个 bundle 都不同。
> 于是「标了 cacheable 的块」在 prompt 里**并不构成从第 0 位开始的连续前缀**。
> 直接照 `cacheable=true` 去拼接缓存前缀，命中率会是 0。
> 两个可选修法：消费端跳过 `bundle.header`（把前缀从 `instructions.system` 开始算），
> 或者把 header 里的变量部分挪到 `run.notes`、只留常量。**动手前先跑一次真实命中率验证。**

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
python -m pytest -q                    # 118 passed, 1 skipped
python -m pytest -q -m slow            # 需要真实语言服务器子进程的那一个
python -m ruff check .                 # lint
python -m pytest tests/test_observability.py -q
```

测试文件分布（共 119 例）：

| 文件 | 例数 | 覆盖 |
|---|---|---|
| `test_observability.py` | 22 | 漏斗同单位、来源直方图、diff |
| `test_scan_stage.py` | 14 | 扫描阶段 |
| `test_read_stage.py` | 13 | 方法体读取、字符预算 |
| `test_assemble_stage.py` | 10 | 组装阶段 |
| `test_scan_transport.py` | 9 | 本地 / 远程两种传输 |
| `test_sarif.py` | 9 | SARIF 解析、路径重定位 |
| `test_syntax_and_lsp_types.py` | 8 | 位置编码、LSP 类型 |
| `test_scanner_command.py` | 8 | argv 组装（防引擎参数混用） |
| `test_assembler.py` | 7 | 打包、去重 |
| `test_contracts.py` | 7 | 数据契约 |
| `test_api.py` | 6 | 路由 |
| `test_pipeline_lsp.py` | 6 | 端到端 LSP |
| **合计** | **119** | 其中 118 passed、1 skipped（`slow` 标记） |

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
| demo bundle tokens | 1841（实测 `B-c7f830954f`） | 稳定前缀固定 1140 tokens → 62%，bundle 越大占比越高（见 §6） |
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

---

## 11. 未完成工作与两个待决策

### 11.1 待决策 A：任务队列选型
`/v1/assemble` 现在是**同步阻塞**（约 11.5 s）。目标形态：

```
POST /v1/assemble  →  202 {job_id}
GET  /v1/jobs/{id} →  {status, progress, result}
```

候选：Redis + 轻量 worker（**当前倾向**）、Celery、RQ、Arq、Postgres 表。
倾向 Redis + 轻量 worker 的原因：这个队列只有一个生产者一类任务，
Celery 的抽象面积远大于需求；而 Postgres 表会把事务负担加到一个只读的流水线上。
**动手前先确认**：是否需要任务取消、是否需要进度回传（这决定是否必须 Redis pub/sub）。

### 11.2 待决策 B：前端技术栈
倾向 **Vite + Vue 3**；备选是纯 JS 静态页（`services/web` 现在是 nginx + 静态资源的规划）。
已完成的准备工作：
- `docs/VISUAL.md`：Mermaid 数据流 + 四屏信息架构 + ASCII 原型
- `docs/prototype.html`：可交互原型
- `app/observability/views.py`：所有视图数据已经由后端算好，**前端只负责渲染，不做计算**

> 历史提醒：上一版 console 的 `index.html` 里有个未修复的 JS 语法错误
> （`SyntaxError: missing ) after argument list`，在 `screenContext` 末尾），
> 当时控制台迁移到 `services/web/` 时那个文件被**删掉而不是修好**。
> 重建时请保留语法检查：`node --check` 已用于校验 console JS。

### 11.3 待做：`aegis-web` 服务
nginx + 静态资源，反代 `/v1` 到 gateway，端口 8102（**绑 127.0.0.1**）。
compose 文件头部注释里已经为它留好位置，但服务定义还没写。

### 11.4 待做：`app/` 物理迁入 `services/extraction/`
纯目录整洁问题——**部署边界已经生效**（三个容器各跑各的），
但 `services/extraction/routes.py` 现在还是 `from app.pipeline.assemble import ...`。
迁移时注意 `pyproject.toml` 的 `packages.find` 与两个 Dockerfile 的 `COPY` 列表要同步改。

### 11.5 后续（明确不在本次范围）
威胁建模子代理、AI 侧并行 fan-out、prompt 前缀缓存的实测命中率。

---

## 12. 交接检查清单

接手第一天建议按顺序做这几件事，用来确认环境与理解都到位：

1. `python -m pytest -q` → 确认 **118 passed, 1 skipped**。不是这个数就先别改代码。
2. `python scripts/demo.py` → 看一遍完整流水线输出，读 `var/packages/<id>/summary.md`。
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
| 流水线怎么串起来 | `app/pipeline/assemble.py` |
| LSP 调用链的全部细节 | `app/graph/providers.py` |
| 预算怎么裁、痕迹怎么留 | `app/graph/builder.py` |
| 方法体怎么读、怎么归一化 | `app/assembler/reader.py` |
| 去重与上下文聚合 | `app/assembler/contexts.py` |
| prompt 排版契约 | `app/assembler/render.py` |
| 落盘产物 | `app/assembler/package.py` |
| 可观测视图怎么算 | `app/observability/views.py` |
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
