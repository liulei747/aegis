# 数据流输入契约（Joern → bundle）

> 状态：**实测已定稿**（2026-09-11）。所有字段名、类型与语义都来自真实产出的 JSON，
> 不是设计稿。产出自 `var/joern/*.path.json`，验证记录见 `var/joern/RESULTS.md`。

## 0. 这份文档解决什么

Aegis 原来自己用 BFS 从 sink 往外爬调用图（`services/extraction/graph/builder.py`），
有一个已确认的缺陷：**节点被"哪个方向发现"后只沿那个方向继续走**，导致
`sink 的调用者所调用的函数`（如 `safe_escape`）永远进不了包，而且不留下任何 prune。
后果是 AI 只能答 `needs_more_context`。

新的分工是：

```
opengrep          找告警（不变）
   ↓
Joern             算【完整数据流】：从不可信输入到 sink 的完整路径（跨文件）
   ↓
Aegis             把路径上的方法全文附上（reader.py，已有）
   ↓
AI                判断"路径上的转换是否足够"（不让引擎判，引擎判不了自定义函数）
```

**为什么不让 Joern 判清洗是否足够**：`safe_escape` 是项目自己的函数，形式化引擎默认
把它当普通函数（实测：清洗版与未清洗版给出相同的流）。判断"够不够"需要业务知识，
是模型的活。实测三组数据的判别力见 `var/joern/RESULTS.md`：

| 清洗函数 | verdict | severity | confidence |
|---|---|---|---|
| `return value.replace("'", "''")` | true_positive | high | 0.60（并指出取决于 DB 驱动） |
| `return v`（空操作） | true_positive | critical | 0.97 |
| 反斜杠+单引号都处理 | **false_positive** | informational | 0.95 |
| 参数化查询 | **无流**（Joern `flow=0`，无需调用模型） | — | — |

## 1. 顶层结构

```json
{
  "case": "demo",
  "engine": "joern pysrc2cpg + reachableByFlows",
  "note": "…给模型看的说明…",
  "source_anchor": "request.args.get",
  "sink_anchor": "execute",
  "sink_derived_from": "repo.py:6",
  "sink_derivation_method": "query_user",
  "sink_derivation_alternatives": ["execute"],
  "source_candidates": 2,
  "sink_candidates": 2,
  "flows": [ …TaintFlow… ],
  "method_bodies": [ …MethodBody… ]
}
```

| 字段 | 类型 | 语义 |
|---|---|---|
| `case` | string | 这次分析的标识（目录名或 bundle id）。**不参与内容寻址** |
| `engine` | string | 产出引擎标识，写进 bundle 供审计 |
| `note` | string | 人读说明；**会原样进 prompt**，所以措辞面向模型 |
| `source_anchor` | string | 起点锚点（调用名） |
| `sink_anchor` | string | **实际使用**的终点锚点。**空字符串表示"没能解析出 sink"** —— 见 §5 |
| `sink_derived_from` | string \| null | sink 是从哪个 `path:line` 推导来的（非配置时为非空） |
| `sink_derivation_method` | string | 推导落到了哪个方法，供审计 |
| `sink_derivation_alternatives` | string[] | 推导时看到的其它候选调用名。**多于一个说明选择不唯一** |
| `source_candidates` / `sink_candidates` | int | 各自匹配到多少个锚点 |
| `flows` | TaintFlow[] | **每条源→汇路径一个条目**，不是拍平的元素数组 |
| `method_bodies` | MethodBody[] | 路径上方法的完整源码 |

## 1.1 锚点从哪来（**这是设计重点，不是实现细节**）

sink 不再必须配，而且**配置里已经没有 `sink` 这个旋钮了**（`aegis_core/config.py`
里写明了原因）。解析顺序：

1. **调用方显式给了锚点就用它** —— `POST /v1/query` 的 `sink` 字段还在，留给"手里已经有
   sink 名字"的调用方（例如将来从规则文件的 `pattern-sinks:` 读出来的，见 §9）；
2. 否则**从 finding 的位置推导** —— 这是 pipeline 走的唯一一条路：`WorkerDataflowClient`
   **从不发送 `sink`**，只发送 finding 的文件与行号；
3. 都没有 → **`sink_anchor` 为空**，如实报告，不猜。

**为什么把配置旋钮删掉**：在配置里写下 sink 名字，等于把分析要找的答案先写下来 ——
"看着答案做题"。而 finding 已经提供了更强的约束：规则命中的**确切文件与行号**。
所以 worker 只接受位置，自己推导，并把推导结果（`sink_derived_from`、
`sink_derivation_method`、`sink_derivation_alternatives`）随答案一起返回，让人能复查
推导错在哪一步。

推导规则：**在包含 finding 的那个方法里，取 finding 行及之后第一个非 operator 调用**。
operator（`<operator>.addition` 等）要排除，因为 finding 通常报在**构造**那一行
（`sql = "..." + x`），而 sink 是**执行**那一行。

实测（demo）：

| finding 位置 | 该行有什么 | 推导结果 |
|---|---|---|
| `repo.py:6`（真实 finding） | 只有 `<operator>.addition` / `.assignment` | **`execute`（第 7 行）** ✓ |
| `repo.py:7`（sink 行本身） | `execute` | `execute` ✓ |
| `service.py:7`（无关行） | `query_user` | `query_user` ✓ |

**为什么不能直接从 opengrep 规则里读 sink**：SARIF 里**没有** source/sink 语义。实测
demo 的 `scan/original.sarif`：

```
rule  字段只有: id, shortDescription, defaultConfiguration, properties{tags}
result 字段只有: ruleId, level, message, locations{uri, region{行/列/片段}}, fingerprints
```

真正的 sink 声明在**规则源文件**（`pattern-sinks:`）里，而 SARIF 不携带它 ——
`services/scan/opengrep.py:189` 也明确注释了 `--sarif` 模式下不加 `--metrics`（semgrep 专有）。
所以：

- **有规则源文件时**，`pattern-sinks` 里的调用名是首选锚点（将来可加，见 §9）；
- **没有时**，用 finding 位置推导（已实现，也是今天的唯一路径）；
- **API 的 `sink` 字段**是留给前者的入口，不是配置项 —— 没有旋钮可以把它写死进部署。

推导是**启发式**，所以契约把它的出处、落到的方法、以及其它候选都记下来，让人能复查。

### 1.1.1 来源锚点只有一种：`auto`（**与原实现的区别，见下**）

sink 从位置推导，而 **source 必须由调用方给出**（§6.1：`reachableByFlows` 是正向的，从 sink 端
问不出边）。这个"从哪进来"以前是在 **harness 里用 Python `ast`** 算的：点号表达式算调用锚点，
裸名字去本仓库里找同名函数，找不到就退回 `ast` 找命中行所在函数 + 第一个参数，最后退回配置默认值
`request.args.get`。**每一步都只对 Python 成立** —— 在 Java 项目上 `ast.parse` 直接 `SyntaxError`，
于是退回 `request.args.get`，而它在一张 Java 图里匹配 0 个节点（见 §5）。

现在只有一种锚点：**`anchor_kind="auto"`**，由 worker **对着图**判定（Scala 侧 `anchoredAuto`，
同一个脚本、同一次往返）：

| 调用方给了什么 | 引擎怎么锚 |
|---|---|
| 点号表达式（`request.args.get`、`os.getenv("X")`） | 按**调用**锚点匹配 |
| 裸名字，且图里有同名方法（`handle_request`） | 按该**方法的参数**锚定 |
| 裸名字，图里没有同名方法（`getenv`） | 按**调用**锚点匹配 |
| 什么都没给 | 按**命中位置所在方法的参数**锚定 —— 方法名与参数由 sink 推导的**同一次查询**带出（`PARAM` 行），不需要第二次往返 |
| 什么都没给，且该方法只有 receiver | 退回配置默认调用锚点 |

receiver（`this` / `self` / `cls`）被跳过：污点不从它进来，锚在它上面会返回一条什么也证明不了的
路径（`worker.RECEIVER_PARAMETERS`）。这是整套规则里唯一"按名字"的一处，因为它是各前端唯一一致的
东西。

**为什么必须搬到引擎里**：语言差异从此只存在于配置表（§8）里，而不在两段代码里。旧实现还有一个
Python 上也存在的隐患 —— 方法边界用的是 `ast` 的 `end_lineno`，引擎用的是 CPG 的 `lineNumberEnd`，
两套规则可以给出**不同的方法**，而调用方把其中一个当成事实发给引擎。

## 1.2 两个实测踩出来的坑

1. **`anchored("")` 会匹配程序里的每一个调用** —— 空锚点等于"从每个调用到每个调用"，
   查询会爆掉而不是返回空。所以查询里显式 `if (needle.isEmpty) Nil`，并且调用方在
   没有 sink 时**根本不发起查询**。
2. **传给推导的必须是 finding 自己的行号，不是焦点方法的起始行**。实测：传
   `query_user` 的起始行 4，推导出来是第 5 行的 `connect`；传 finding 的第 6 行，才是
   `execute`。

## 2. `FlowElement`

```json
{
  "label": "METHOD_PARAMETER_IN",
  "code": "value",
  "method": "safe_escape",
  "file": "util.py",
  "line": "4"
}
```

| 字段 | 类型 | 语义 | 实测注意 |
|---|---|---|---|
| `label` | string | Joern 的顶点类型 | 见下表 |
| `code` | string | 该顶点的源码文本（截断到 120 字符） | 可能为空 |
| `method` | string | 所属方法名 | **可能为空字符串**（见下） |
| `file` | string | 文件名（basename，非全路径） | **可能为空字符串** |
| `line` | string | 1-based 行号 | **是字符串，不是数字**；**可能为空字符串** |

`line` 为什么是字符串：Joern 的 `lineNumber` 返回 `Option[Int]`，缺省时我写成了 `""`。
**消费方必须容忍 `""`**，不要 `int()` 前先判断。

`method`/`file` 为空的情形：`BLOCK` 类顶点（如 `tmp0 = request.args`）不属于任何方法，
Joern 给不出归属。实测 demo 的 20 个元素里有 1 个是这种。**渲染时应跳过或标为 `?`，
不要假设每行都有定位信息。**

### 实测出现过的 `label` 值

| label | 含义 | 出现频次（demo 20 元素中） |
|---|---|---|
| `METHOD_PARAMETER_IN` | 进入某方法的形参 —— **方法边界就在这里** | 3 |
| `IDENTIFIER` | 变量读写 | 8 |
| `CALL` | 函数调用（含 sink 调用与清洗调用） | 5 |
| `RETURN` | 返回语句 | 1 |
| `METHOD_RETURN` | 方法返回值占位 —— **方法边界** | 1 |
| `LITERAL` | 字面量（如 `"id"`） | 1 |
| `BLOCK` | 语句块，**无归属方法** | 1 |

**不要把 label 集合写死。** 这只是实测样本；`label` 是 Joern 的顶点类型，换语言/换前端
会变。消费方应只依赖"`method` 非空"来判断归属。

## 3. `MethodBody`

```json
{
  "method": "safe_escape",
  "file": "util.py",
  "start_line": 4,
  "end_line": 5,
  "source": "def safe_escape(value):\n    return value.replace(\"'\", \"''\")"
}
```

| 字段 | 类型 | 语义 |
|---|---|---|
| `method` | string | 方法名，与流的 `methods` 对齐 |
| `file` | string | 文件名（basename） |
| `start_line` / `end_line` | int | **1-based**，闭区间。这是文档里**唯一的数字行号**（与 `FlowElement.line` 的字符串形成对比） |
| `source` | string | **完整方法体**，含 `def` 行，末尾无多余空行 |

`source` 里**不含行号**。渲染时若需要行号，用 `start_line + 偏移` 自行计算。

## 4. 消费规则（**必读，三条都是实测踩出来的**）

1. **流不能拍平**：`flows` 是**路径的列表**，每条路径内部才是有序的元素。拍平后看起来像
   "一条路重复了自己"，会误导读者。渲染时**每条路径单独呈现**。
   > 当初的证据是 demo 返回 **2 条**独立路径（16 和 20 个元素）。**这个测量已经不再复现**：
   > 2026-09-12 用四种锚点形式各跑一遍（sink 由 `repo.py:6` 推导、由 `repo.py:7` 推导、
   > 显式 `execute`、显式 `cursor.execute`），四次都只有**一条 20 元素、跨 4 个文件**的流。
   > 所以这个形状**仍然必须支持**（引擎确实会返回多条），但本仓的 demo 已经不是它的例子了 ——
   > 谁要是写一个"demo 必须有两条流"的断言，那是在断言一段记忆。`var/joern/acceptance.py`
   > 里那条检查已换成"流跨文件"（爬取做不到的那件事）。
2. **容忍空定位**：`method`/`file`/`line` 都可能是 `""`。渲染成 `?` 或跳过该行，
   不要抛异常、不要填 `0`。
3. **`method_bodies` 是给模型的判断依据**，不是可选装饰。实测：把清洗函数体从
   "真的转义"换成"空操作"，模型的 severity 从 high 变 critical、confidence 从
   0.60 变 0.97；换成"处理反斜杠"则翻成 `false_positive`。**没有函数体就没有判别力。**

## 5. "没有流"必须分清两类五种（**这是本契约最容易出错的地方**）

空流有两个来源：**关于代码的结论**，和**关于问题的陈述**。分界线是锚点有没有落在图上 ——
**没落上的一律回退到爬取，落上的不回退。**

| 情形 | 契约表现 | 含义 | builder 行为 |
|---|---|---|---|
| **引擎证明无路径** | `flows == []`，两个锚点**都落在图上**（`sink_anchor != ""`、`sink_candidates > 0`、`source_candidates > 0`） | 值到不了 sink —— **代码是安全的** | 记 `dataflow_no_path`；切片只留 focus，**不回退**（回退会把"到不了汇聚点"的噪声重新引进来） |
| **来源锚点没匹配到节点** | `flows == []` 且 `source_candidates == 0` | **问题没落在图上**（锚点写错、前端选错） | 记 `dataflow_source_unmatched`，**回退到爬取** |
| **汇聚点锚点没匹配到节点** | `flows == []` 且 `sink_candidates == 0` | 同上，发生在 sink 一侧 | 记 `dataflow_sink_unmatched`，**回退到爬取** |
| **没有 sink 可推导** | `flows == []` 且 `sink_anchor == ""` | **我们不知道要找什么** | 记 `dataflow_sink_unresolved`，**回退到爬取** |
| **引擎/建图失败** | 抛异常（`JoernError` / `JoernUnavailable`） | 分析没跑成 | 记 `dataflow_unavailable`，**回退到爬取** |

把"问题没落图"说成"健康报告"是这一节存在的理由。而**回退本身也是承重的**：四种"没落图 /
没跑成"都必须回退，因为回退不丢信息（prune 留在同一个 `slice_` 上，报告照写），不回退却会丢
东西 —— 修之前这三种"没落图"**全都返回单方法切片、不回退**，于是 LSP 已经建好的整张调用图被
一个空图悄悄换掉；其中"来源锚点匹配 0 个节点"还被叫成 `dataflow_no_path`，等于对引擎从未读过
的代码下了"值到不了汇聚点"的结论。触发它的是真实场景，不是设想：
`services/harness/tools/dataflow.py` 的 docstring 记着 `var/projects` 里那个 Java 项目上
Python 形状的来源锚点匹配 **0 个节点**（怎么修见 §9.5）。

实测 `c2-parameterized`（sink 改成参数化查询 `cursor.execute(sql, (user_id,))`）：
Joern 返回 **零条流**，因为值不再流进 SQL 文本 —— 这是第一类，是**结论**。

## 6. 成本与边界（实测，写进文档以免后续误判）

| 项 | 实测值 |
|---|---|
| 建 CPG（demo，4 文件 14 行） | **2.3 秒**（JVM 0.5s + 解析 0.17s） |
| 一次查询 = 一次 JVM 启动 + 载图 | **8 秒**（`--server` 常驻可摊薄为约 1 秒/次） |
| 首请求（新容器：起 server + 建图 + 推导 + 查询） | **≈16.6 s**（见 §8.1 的四段拆分） |
| WARM 请求（server 与图都常驻） | **≈2.1 s**（推导 1.0 + 查询 1.0） |
| 两个 worker 并行（同项目、两查询） | **1.99× 加速**（wall 2.1 s vs 串行 4.2 s） |
| Python 前端 | **纯语法**解析，不需要项目能编译、不需要装依赖 |
| **建 CPG（Java，2341 文件）** | **418 秒（≈7.0 min）/ 图 15.2 MB**。pass 分解：`AstCreationPass` 18.4s、`TypeInferencePass` 0.4s，但 `JavaConfigFileCreationPass` **47.2s**；其余时间在 JVM 启动与写盘（`tail` 截掉了开头，所以这三项加起来只有 66s） |
| Java 前端 | `javasrc2cpg` 同样是**纯语法**（不需要项目能编译，也不需要依赖 jar） |
| **Java 依赖 jar** | 选项是 **`--inference-jar-paths`**（逗号分隔的 jar 路径），说明书原文是 "extra jars used **only for type information**" —— 依赖**不进 CPG**，CPG 里只有项目自己的源码；jar 只当类型索引。**实测：它不是前提。** 三文件夹具里故意引用没有 jar 的 `HttpServletRequest`，`-o` 建图 rc=0、跨文件流照样出来（`Repo.java:2 userId → Repo.java:4 Db.execute(sql) → Db.java:3 sql`），因为 call 节点来自源码文本，与类型能否解析无关 —— 锚点是按名字匹配的。jar 带来的是**类型推断精度**（接口分发、重载），是准确度问题而不是可达性问题 |
| **依赖 jar 的代价（实测，同一份 3 文件）** | 不加：**3s**；加 1382 个 jar / 774 MB（本机 `~/.m2/repository`）：**216s（72×）**，而**图一字节没变**（43727 → 43727）、流也一模一样。索引 774 MB 约合 3.6 MB/s，成本几乎全在挨个打开 jar 上。**默认结论：不要配。** 只有在真实项目上观察到类型推断导致的具体错误（接口分发选错重载之类）时才开，而且要先量它对 `payment-sys`（2341 文件 418s 的基数）加到多少 |
| 建图内存 | 没有显式 `-Xmx`；实测 2341 文件峰值 RSS 约 **1.4 GB**，容器 `shm_size: 512m` 未成为瓶颈 |
| 解析失败面 | 2341 文件里 **1 个**失败（`ConfigContextCache.java`，Joern 的 javaparser 不认 Java 14+ 的 `yield` 受限标识符），Joern 自己报了 `Parse error` —— 不是静默丢文件 |
| 参数类型 | 全是 `ANY`（无类型推断）—— 动态派发、`getattr`、装饰器看不穿 |

> **Java 的首次查询要按分钟计，而且它会吃掉 `timeout_s` 的 70%。** 默认 `AEGIS_DATAFLOW__TIMEOUT_S=600`
> 对 2341 个文件只余 30% 余量；更大的仓库会在建图阶段超时。超时现在是**具名 `JoernError`**
> （消息里点名这个配置项并附上这组实测数字），不是 500。建图结果按
> `<workspace digest>-<frontend>` 缓存，所以这笔成本每个（内容, 前端）组合只付一次。
| 沙箱要求 | 镜像 5.92GB，需要 JVM；每个 worker 一个 JVM，常驻约 1 份图的内存 |

**已知看不穿的情形**（此时流会断，AI 会回到"证据不足"，这是诚实行为）：
装饰器包装、`getattr` 动态取函数、跨进程/跨语言的调用、字符串拼接出的函数名。

## 6.1 锚点的**方向**决定流向（**实测，最容易踩的坑**）

`reachableByFlows` 做的是**正向污点**：从 source 出发、沿数据流往下走到 sink。
**锚在哪一端，决定了它追哪个方向**：

| 锚点 | 实测路径 | 结论 |
|---|---|---|
| 从 **source 端**（`handle_request` 的参数，或 `request.args.get` 调用） | `handle_request -> safe_escape -> load_user -> query_user` | ✅ 跨文件完整 |
| 从 **sink 端**（`query_user` 自己的参数） | **只有 `query_user`** | ❌ 不跨函数回溯 |

**从 sink 端锚定不会跨函数往上爬到调用者。** 这不是配置问题、也不是深度不够 ——
"跨函数向上"是**调用图**的方向，而污点传播的边走的是**数据流**方向（调用者 → 被调用者的参数）。
所以反向查询没有边可走。

实践含义：**端点必须从 source 端锚定**。而 source 的位置由 opengrep 的 finding 给出
（`handler.py:10` + 片段），sink 的位置由规则或模式搜索给出。**Joern 只负责中间那段路。**

反例（不要这样做）：拿"sink 所在方法的参数"当锚点 —— 它会返回一条看起来合理、
但**缺失全部上游**的路径，然后你会误以为"链路就这么短"。

### 6.1.1 为什么反向不行：边是单行道（**对照实验**）

同一个节点对，只换方向，实测结果：

```
query_user.parameter -> execute.arg(1)     forward: 1   ✅
execute.arg(1)       -> query_user.parameter forward: 0  ❌
handle_request.param -> execute.arg(1)     forward: 1   ✅
execute.arg(1)       -> handle_request.param forward: 0  ❌

从 execute.arg 往上游能到达的节点数 = 0
```

**排除了"跨函数"这个干扰**：source 和 sink 放在**同一个函数体内**再测一次，结论一样：

```python
def query_user(request):
    user_id = request.args.get("id")              # ← source 锚点
    cursor = sqlite3.connect("app.db")
    sql = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(sql)                           # ← sink 锚点
```

```
FORWARD：从 request.args.get 出发 → 1 条流，路径是
    CALL        request.args.get("id")
    IDENTIFIER  user_id
    CALL        "SELECT ..." + user_id
    IDENTIFIER  sql
REVERSE：从 execute 的实参出发 → 0 条流
```

**原因直接印在节点上**：

```
param.in  -> METHOD / IDENTIFIER     ← 结构边（它属于哪个方法），不是数据流
param.out -> TYPE / IDENTIFIER       ← 数据流从这里出去
```

`reachableByFlows` 走的是 **REACHING_DEF**（可达定义）边，而这类边的方向由语言语义固定为
**「定义 → 使用」**：

```
request.args.get("id")  ──▶ 定义 user_id
user_id                 ──▶ 使用 user_id（第 8 行的拼接）
拼接结果                ──▶ 定义 sql
sql                     ──▶ 使用 sql（execute）
```

**每个节点只有"我往哪流"的出边**；反过来问"我用的值是哪来的"在图里没有边。

而**跨函数传参在数据流语义里是正向的**（实参 → 形参 是一条 REACHING_DEF 边），
所以从 `handle_request` 出发能一路顺流到 `execute` —— 这不是"反向爬调用图"。

> 一句话：**`reachableByFlows(X, Y)` 只能 X=源头、Y=汇点。**
> 反过来问没有结果，不是深度不够，是**那个方向的边不存在**。

## 7. `.sc` 脚本的硬性要求

Joern 的 Scala 脚本**不能有 BOM**。PowerShell 的 `Set-Content` 会加 BOM，
Scala 编译器直接报 `illegal character '\ufeff'`。**必须用无 BOM 的 UTF-8 写入**
（Python 的 `Path.write_text(..., encoding="utf-8")` 即可）。

另一个实测坑：**空字符串锚点会匹配程序里每一个调用**，查询变成"每个调用到每个调用"
而爆掉。查询里必须 `if (needle.isEmpty) Nil`，调用方也必须在没有 sink 时直接跳过查询。

## 8. 参考实现

| 文件 | 作用 |
|---|---|
| `services/dataflow/worker.py` | **worker 核心**：常驻 Joern server（本地子进程）、**按后缀普查选前端**（`frontend_for`）、CPG 构建与缓存、流查询、sink 推导、报告解析 |
| `services/dataflow/worker_app.py` | **HTTP 面**：`POST /v1/query`（回应里带 `frontend`）、`GET /health`（带 `frontends`） |
| `services/dataflow/router.py` | **亲缘路由**：`worker_for(workspace, N)` —— 工作区内容哈希取模，纯函数，不靠发现 |
| `services/dataflow/Dockerfile` | worker 镜像：Joern 基底 + Python 3.9 supervisor + `eval_type_backport` |
| `services/extraction/dataflow/client.py` | **调用方**：`WorkerDataflowClient`（算亲缘 → HTTP），方法正文在**本地**拼装 |
| `aegis_contracts/dataflow.py` | 契约模型（本节字段的代码形式） |
| `docker/docker-compose.yml` 的 `dataflow-0` / `dataflow-1` | 部署形态：每 worker 一个容器、**每个都挂同一个 `/workspace` 只读**、共享 CPG 缓存 + 各自 scratch |
| `var/joern/test_fleet.py` | 集群验收：亲缘稳定性、cold/warm 成本、并行加速、per-worker scratch |
| `var/joern/demo_path.py` | 完整样例：建图 → 查询 → 拼装本文档所述 JSON |
| `var/joern/ask_with_dataflow.py` | 消费方样例：读 JSON → 拼 prompt → 调用模型 → 解析 verdict |
| `var/joern/RESULTS.md` | 判别力验证（三组对照 + 一个空操作反例） |
| `var/joern/BENCHMARK.md` | 批量 vs 并发的 token/耗时对照，以及网关 60s 超时的影响 |
| `tests/test_dataflow.py` | 契约、解析、亲缘路由、缓存键（含前端维）、接入与五种"无流"的区分 |

**为什么每个 worker 挂同一个 `/workspace`**（这不是偷懒）：亲缘是**策略**（让图常驻），不是
路由的**必要条件**。如果每个 worker 挂不同的项目，哈希一旦把请求算到"错"的 worker，对方
根本看不见那个路径 → 404。挂成一样，算错只是慢一点。这也正好守住文件头写的共享卷契约：
extractor 传的就是它自己看到的路径，中间不做路径翻译。

**但"路径一致"是配置出来的，不是天生的** —— 实测在 compose 之外跑（宿主直接跑流水线）时，
客户端会发 `E:\...\demo\repo`，容器里当然没有，worker 答
`404 workspace not found`。所以有 `DataflowConfig.worker_workspace`：显式声明 worker 那边这个
工作区叫什么（宿主脚本填 `/workspace`）。**方法正文仍然从本地路径读** —— 一个路径给 worker
定位图，一个路径给本进程读字节，两者各自成立。

**`/health` 的 `cold` 算"可达"**。worker 是在收到请求时才拉起 Joern server 的，所以刚起来的
worker 答 `cold`，意思是"我在，第一次会慢 11 秒"。调用方（`WorkerDataflowClient.health()`）
必须把它当可用，否则就会把"等 11 秒"误判成"数据流不可用"，静默降级到爬取 —— 包照样产出，
只是少了清洗函数，**这是实测踩过的**。compose 的 healthcheck 也是这个语义（`curl -fsS` 对
`cold` 返回 200）。

**缓存是分开的，不是整块共享**：`/data/dataflow/cpg/<digest>-<frontend>/cpg.bin` 是**共享**的，
谁先到谁建，用 staging 文件 + `os.replace` 原子发布，其余 worker 直接复用；每个 worker 自己的
scratch 在 `/data/dataflow/worker-<index>/`，装 Joern 按工作目录物化的项目目录，不能撞。

**缓存键必须含前端，不只是工作区内容。** 同一个工作区在不同前端下是**两张不同的图**，而这份
缓存是整个 fleet 共享的。键里只有 `digest` 时，一旦存在第二个前端（Java 要 `javasrc2cpg`，
见 §9.5），项目就会被**另一个前端建的图**回答，而且两个 worker 都会这么回答。这与
`workspace_digest` 自己 docstring 里记的那次事故同族：只哈希 `.py` 时，两个无关的 Java 项目
撞在 `sha1("")` 上，第二个被第一个的图回答。会话级守卫同理，是 `(digest, frontend)` 而不是
digest —— 只比 digest 会让一个被重新配置过的进程继续用内存里的旧图。

**污点链支持哪些语言由配置决定，不是由代码决定。** `AEGIS_DATAFLOW__CPG_FRONTENDS` 是
`{后缀: 前端名}`，默认 `{".py": "pysrc2cpg", ".java": "javasrc2cpg"}`。worker 收到工作区后做一次
**后缀普查**（`aegis_core.workspace.suffix_census`，只读文件名不读字节），取占比最大的后缀，前端
可执行文件解析为 `<AEGIS_DATAFLOW__FRONTENDS_DIR>/<前端名>/bin/<前端名>`。镜像里 15 个前端全都在
（实测 `ls /opt/joern/joern-cli/frontends/`），所以**加一门语言是加一行配置，不是加一条代码路径**。

两种拒绝都是具名的，都不会退化成"建一张空图"：没有任何后缀命中配置 → `NoFrontend`；命中了但
前端没装 → `JoernUnavailable`。两者都**按工作区检查、不在启动时检查** —— 缺 Java 前端不该让
Python 分析也起不来。`AEGIS_DATAFLOW__CPG_FRONTEND_ARGS` 是 `{后缀: [argv…]}`，Java 的 classpath
从这里进去，**逐词传递**（含空格的路径不会被拆开）。

普查的平局按后缀排序决定（`dominant_suffix`），因为同一个答案还要决定缓存键，而不稳定的键等于
每次请求都重建。

### 8.1 Joern 的三种驱动方式（实测定稿）

**① `joern --script <f.sc> <cpg.bin>`（一次性容器）** —— 每次一个全新 JVM，约 **9 秒/次**。
稳定可靠，是服务初版和进程内直连用的方式。

**② `joern --server <cpg>`（把 cpg 当参数）** —— **不可用**。那个参数是**项目名**，不是
文件：Joern 会把 `workspace/<name>/cpg.bin` 加 overlays 变成一个**目录**，然后每次查询都从
**空 REPL** 回答（实测 `cpg.call.l.size` 空、流查询 `sources=0 sinks=0`），它建的目录还会
和下一次运行的普通 `cpg.bin` 冲突。

**③ `joern --server`（无 cpg 参数）+ `importCpg`（worker 用的方式）** —— **可用，最快**。
`importCpg("/w/<digest>/cpg.bin")` 让图**常驻**在会话里，之后每次查询约 **1 秒**。实测
（`var/joern/test_fleet.py`，2 worker 集群，容器内 HTTP）：

| 阶段 | 耗时 | 说明 |
|---|---|---|
| `start_s`（起 Joern server） | **11.3 s** | 只在容器起来后的**第一个**请求上付；warm 时为 `0.0` |
| `load_s`（CPG 建图 + import） | **2.3 s** | 其中建图只在 CPG 不在共享缓存时发生；第二个 worker 首次只花 **1.1 s**（纯 import） |
| `sink_elapsed_s`（推导 sink） | **1.0 s**（冷启动时 2.0 s，JIT 未热） | |
| `elapsed_s`（流查询本体） | **1.0 s** | |
| **首请求（新容器）合计** | **≈16.6 s** | 11.3 + 2.3 + 2.0 + 1.0 |
| **WARM 请求合计** | **≈2.1 s** | 1.0 + 1.0，server 与图都还在 |

> **读数字的坑**：`elapsed_s` **只是流查询那一段**。早先把它当"请求成本"记录，于是
> warm 被低估一半（2.1 s 记成 1.0 s）、首请求被低估 8 倍（16.6 s 记成 4.4 s）。现在
> worker 一次返回四个数（`start_s` / `load_s` / `sink_elapsed_s` / `elapsed_s`），
> `total_s` 是它们之和。

> **可优化项（已量到，未做）**：warm 的 2.1 s 里**推导占了整整一半**。推导与流查询各自
> 是一次 Scala 往返；把"推导 + `reachableByFlows`"合成一个 Scala 程序，warm 请求可降到
> ≈1 s。代价是推导的候选选择逻辑要在 Scala 里再写一遍（并且要保持
> `sink_derivation_*` 溯源字段），所以没有顺手做。

并行性实测（同一项目、两个 worker、同时发两个查询）：**wall 2.1 s，串行会是 4.2 s，
加速 1.99×**。单个 worker 内部是**刻意串行**的 —— 一个 Joern 会话不能同时回答两个查询，
所以项目级并行靠 worker 数量，不靠线程。

这正是 worker 集群的地基：同一项目永远路由到同一个 worker（`services/dataflow/router.py`，
工作区内容哈希取模），图常驻，JVM+载图成本每个项目只付一次。

> 之前记录的"importCpg 超时 3×120s"是**探针 bug**（shell 单行嵌套引号 + 把 404 当"未就绪"），
> 不是 Joern 的问题。用干净客户端（宿主机端口映射 + Python urllib）重测，importCpg 只需 2.1 秒。

**worker 的取结果方式**（两个实测坑）：

1. `println` 输出**不**被 server 捕获（result 只有 `success/uuid/stdout`，`println` 查询
   stdout 为空）。所以查询把报告**写进挂载目录的文件**，supervisor 读文件。串行执行让文件
   成为消息通道而不是竞态。
2. Python 字符串模板写 Scala 必须**双写反斜杠**（`"\\t"`、`"\\n"`）。单反斜杠会被 Python
   编译成真实 tab/换行，而 Scala 字符串字面量里的真实换行是语法错误（实测，
   `n.code.replace("\n", " ")` 直接让查询编译失败）。

### 8.2 两个实测踩出来的坑（会重复踩，所以写下来）

1. **`anchored()` 必须返回调用节点本身，不能返回它的参数**。写成 `.argument(1)` 时，
   `cursor.execute(sql)` 的 `argument(1)` 是**接收者 `cursor`**，锚点就落错了地方 ——
   实测 `sources=0 sinks=0 flows=0`，锚点解析出来是 `request` 和 `cursor`。
2. **子进程输出必须显式 UTF-8 解码**。Joern 用 ANSI 转义给输出上色，Windows 默认代码页
   解不了；`text=True` 会打死读取线程，错误表现为 `None` 而不是异常。这个坑本轮踩了三次。

## 9. 仍未做（**明确写下，避免误以为已覆盖**）

1. **没有从 opengrep 规则源文件读 `pattern-sinks`**。规则的调用名本可以是最精确的锚点
   （不需要跑 CPG 就能确定要找什么），但需要先实现规则解析并把它接到 `ScanRequest.rules`
   上。目前的顺序是"调用方显式给 → finding 位置推导"，**规则这一层是空的**；pipeline 走
   的是第二条，且只走第二条。
2. **推导是启发式，未做唯一性判断**。`sink_derivation_alternatives` 里多于一个候选时，
   现在仍然取第一个，只是把它记下来了。正确做法应是：候选多于一个时降级为"需人工确认"。
3. **`method_bodies` 里的正文没有被流水线消费**（正文仍由 `MethodReader` 从
   `MethodSymbol` 读）。两条路读到同样的字节，属重复。
4. **`_load` 每个请求都重算整个工作区的内容哈希**（用于判断"已载入的图还是不是当前项目"）。
   实测：4 文件夹具 **0.7 ms**，本仓 107 个 Python 文件 **401 ms**，且它随项目规模线性增长 ——
   于是每次 WARM 请求都要先付一遍全项目哈希。demo 上完全看不出来（它落进 `load_s` 的
   0.01 s 里），真实仓库上会变成每查询数百毫秒到数十秒。三个方向，都还没做：
   由调用方传入 `workspace_id` 并由 worker 廉价校验（文件数 + 最大 mtime）、按 mtime
   记忆化、或让调用方承担"项目没变"的声明。**这是已知的 O(项目规模)/查询成本。**
5. **Java：图和锚点都通了，还差一次重建与 `/health` 的声明。** 前端按后缀普查自动选
   （`.py → pysrc2cpg`、`.java → javasrc2cpg`，§8），锚点交给 `anchoredAuto` 对着图判定
   （§1.1.1），所以 Python 与 Java 从此走**同一条代码路径**；`services/harness/tools/dataflow.py`
   里那套 `ast` 推导（`_enclosing_parameter` / `_defines_function` / `_first_parameter` /
   `_looks_qualified` / `import ast`）已删除。**实测 Java 不需要依赖 jar 就能出跨文件流**
   （见 §6）—— 三文件夹具、无 classpath、引用无 jar 的 `HttpServletRequest`，`auto` 锚点
   （`PARAMS this,userId` → 跳过 receiver → 锚 `userId`）照样追到 `Db.execute(sql)`。
   所以 `--inference-jar-paths` 是**可选精度优化**，不是开关。仍未做的是：
   - `app/api/routes.py` 的 `deep_analysis.taint` 仍写死 `["python"]`。**代码路径已经通了**，
     这句话现在只是"没有人在真实 Java 项目上跑过一次"的保守表述，需要在 `payment-sys`
     上做一次对照（同一批候选，看 `evidence_kind` 里出现多少 `dataflow`）再改。
   - `services/extraction/dataflow/client.py::_find_def` 也是 Python-only（只找 `def name(`），
     但 `FlowMethodBody` 目前**没有任何流水线消费方**（§9.3），所以它对结论没有影响；真要用
     那份正文时应当让 worker 从 CPG 给出行区间、调用方按区间切本地字节。
   成本见 §6：2341 个 `.java` 首次 418s / 15.2MB，之后走缓存。
