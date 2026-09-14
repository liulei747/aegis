# PLAN: blackboard-only read reuse（执行规格）

> 这是一份**工作单**，写给执行改动的工具/工程师。它假设读者没有本次讨论的上下文，因此把
> 背景、已确认的决策、精确锚点、目标代码、测试与验收门槛都写全了。
> **不要重新讨论 §1 里已确认的决策，也不要扩大 §0 的范围。**

---

## 0. 范围

**只做一件事**：让一次 audit 运行内部，**每个文件的完整 `read` 最多从磁盘发生一次**；此后任何需要
该文件的 agent 从**黑板**拿到逐字相同的字节，不产生工具调用、不产生模型往返。

**绝对不做**（各自独立，另行评估）：

| 不做 | 理由 |
| --- | --- |
| 磁盘预读 | agent 失去"先选再读"的自由；大 scope 上撞 `budget` 后整文件跳过，白付那份 token。**本轮 `from_disk` 默认 False** |
| scope 包含关系降级（5 个重叠 scope → 1 个） | 收益更大但改的是"计划"语义，需单独的质量取舍 |
| 开场 pass 3 → 1、跳过 planner | 同上 |
| 候选按位点提前合并 | `docs/HANDOVER.md` §14.4 已定性：会让同一行上两种漏洞共享一条判决 |
| 材料包缓存 / 前缀缓存 / 符号级检索（repo map） | 分别是合约改动、provider 侧问题、小仓库零收益 |

---

## 1. 已确认的决策（**不要重新讨论**）

| # | 决策 | 定论 |
| --- | --- | --- |
| D1 | `prefetch_scope_files` 的磁盘分支 | **保留**，默认关（`from_disk: bool = False`），开关存在以便复现旧对照实验与回退 |
| D2 | planner 创建的 scope 的 `files` 为空时 | **不复用**（不传文件列表即不调用复用；绝不用"黑板上任意完整读"兜底） |
| D3 | 开场 pass ≥ 2 是否允许跨 agent 复用 | **允许**（workspace 审计期只读挂载，完整读不可能过期） |
| D4 | 可观测性放哪 | 放进 **`AgentRun`**，**不改 `report.py`**（`AgentRun` 会随 `blackboard.json` 落盘，足够核对） |

---

## 2. 背景（为什么值得做，以及为什么只值这么多）

**基线实测**：job `J-712e9f99169f44af4b88b8fa9f164bd581b4abc3`，工作区 `/data/projects/demo-taint`
（4 个 `.py` + 1 个 json）—— 22 agent run、69 次模型往返、166 步、994s 墙钟、381k 输入 + 47k 输出 token。

三条实测结论（决定了本计划的值域）：

1. **墙钟 ≈ 模型往返次数 × 单次延迟 ÷ 并发**。22 个 run 的墙钟合计 1179.4s，模型调用延迟合计
   1176.6s，**工具执行合计只有 2.8s（0.24%）**。单次往返中位 14.6s、均值 17.1s。
2. **"81 次 read" 其实只花了 20 个往返**。模型本来就在批量读（`MAX_CALLS_PER_TURN = 8`，
   `services/harness/react.py:55`；task 文本也明确要求并行读，`services/harness/agents.py:1105`）。
   实测：`recon:workspace` 一个 turn 里 5 个 `read`；4 个 discovery scope 各自一个 turn 4 个 `read`。
   所以读的代价在**往返次数**，不在 token。
3. **同一个文件被反复读**：81 次 `read` 覆盖 4 个文件 —— `service.py` 7 次、`handler.py` 6 次、
   `repo.py` 6 次、`util.py` 6 次。

**预期收益**：-9 往返 / -154s（994s → ~840s，约 15%）；上限 -12 往返 / -205s（21%）。
**候选、判决、最终发现、覆盖台账必须完全不变。**

---

## 3. 改动清单（按提交顺序）

改动集中在 3 个源文件 + 1 个测试文件。每条给出精确锚点（行号基于 HEAD `412c206`）与目标代码。

### 3.1 `aegis_contracts/harness.py` — `AgentRun` 加一个字段

锚点：`class AgentRun(BaseModel)`（`:330`），字段区 `:333-343`。

在 `steps` 与 `stop_reason` 之间插入：

```python
    #: Workspace-relative files this run did **not** read from disk because the run had already read
    #: them completely and the bytes came out of the blackboard instead (`agents.replayable_reads`).
    #: Empty for a run that fetched everything itself. Derived from the seeded `index=0` steps, not
    #: reported by the agent, for the same reason the coverage ledger is: a claim is not evidence.
    reused_files: list[str] = Field(default_factory=list)
```

> 契约是 pydantic v2 且**没有** `model_config`/`frozen`（已核对 `aegis_contracts/`），所以赋值可用。
> 该字段会随 `blackboard.json` 落盘；**不要**改 `report.py`（决策 D4）。

### 3.2 `services/harness/agents.py` — 新增 `replayable_reads`

锚点：紧接 `stored_read`（`:927-962`）之后、`prefetch_scope_files`（`:965`）之前插入。

```python
def replayable_reads(
    blackboard: Blackboard,
    files: list[str],
    *,
    budget: int,
) -> tuple[list[AgentStep], list[str], list[str]]:
    """`(steps, reused, missing)`: complete reads this run has already done, ready to be seeded.

    The sharing this harness was missing was not data, it was a reader: the blackboard already holds
    every `read` result -- 471 of them on the audit that found this, 220 KB of file text with `repo.py`
    alone stored 88 times -- and `coverage.from_runs` was the only thing that ever looked. This is the
    reader, and it is deliberately the *only* one: it never touches the tool layer and never reads the
    disk. A file with no complete read on the board is reported in `missing`, and the caller names it
    in the agent's task text so the agent reads it itself.

    Three properties make this honest rather than a trick:

    * **Real `read` results.** The replayed step carries the original call and result verbatim, so the
      coverage ledger counts it exactly as it counted the model's own read -- no new accounting rule
      and no synthetic "pretend it was read" record.
    * **Complete only.** `returned_lines == total_lines`, or nothing (see `stored_read`). Handing over
      a partial read as if it were the file is exactly the false-coverage claim the ledger exists to
      prevent.
    * **Bounded, and it skips rather than truncates.** A file is seeded only if it fits what is left of
      `budget`; anything larger is named in `missing` and the agent reads it itself. Sending half a
      file while the ledger calls it covered is the worst outcome available here.

    `files` is required, and an empty list is a no-op. It is not optional on purpose: a caller with no
    file list would be asking for "everything this run has read", and an agent handed files that are
    not its business is how one scope's context ends up being the whole repository. A planner-created
    scope can own no files at all (see `_planner_call`); those share nothing rather than everything.

    Cross-agent reuse is the point and is always allowed: the workspace is mounted read-only for an
    audit, so a complete read cannot be stale, and two agents reading one file get the same bytes.
    """
    if budget <= 0 or not files:
        return [], [], []
    steps: list[AgentStep] = []
    reused: list[str] = []
    missing: list[str] = []
    used = 0
    for name in files:
        step = stored_read(blackboard, name)
        if step is None or step.result is None:
            missing.append(name)
            continue
        size = len(step.result.summary or "")
        if used + size > budget:
            missing.append(name)
            continue
        steps.append(step)
        reused.append(name)
        used += size
    return steps, reused, missing
```

`stored_read` 本身**不改**（`verify_taint_candidate` 与既有测试用它）。

### 3.3 `services/harness/agents.py` — `prefetch_scope_files` 默认只走黑板

锚点：`:965-1066`。改签名 + 在开头插入复用分支 + 把磁盘循环限定在 `missing` 上。

新签名：

```python
def prefetch_scope_files(
    files: list[str],
    context: Any,
    *,
    budget: int,
    blackboard: Blackboard | None = None,
    from_disk: bool = False,
) -> tuple[list[AgentStep], list[str], list[str], list[str]]:
```

docstring 在原有内容上**追加**（保留原有对 88 runs / 471 reads / 5.9 vs 4.7 的记述，那是这个函数
存在的理由）：

```
    **The default is blackboard-only.** A complete read this run already performed is the same bytes, so
    the agent is *seeded* with it instead of spending a turn fetching it, and no file is read off the
    disk for a scope whose bytes are already in the run's transcript. The disk branch sits behind
    `from_disk=True` and is off by default for two reasons: it puts a full copy of the file in the
    prompt even when the agent would not have chosen to read it, and on a scope larger than `budget` it
    skips whole files *after* having read them. The switch is kept so the measurement above stays
    reproducible and the choice stays reversible.
```

函数体改为（保持返回值顺序 `steps, from_ledger, from_disk, skipped`）：

```python
    if budget <= 0 or not files:
        return [], [], [], []
    if blackboard is None:
        steps: list[AgentStep] = []
        reused: list[str] = []
        missing = list(files)
    else:
        steps, reused, missing = replayable_reads(blackboard, files, budget=budget)
    if not from_disk:
        # Blackboard only. A file with no complete read on the board is named in the last slot so the
        # agent reads it itself -- which is also what the coverage ledger wants for a re-dispatch.
        return steps, reused, [], list(missing)

    from services.harness import react

    try:
        _, _, _, invoke, _ = react.tool_layer()
    except react.ToolLayerUnavailable:
        # The reuse above needed no tool layer, so it survives; only the disk half is lost.
        return steps, reused, [], list(missing)

    used = sum(len(step.result.summary or "") for step in steps if step.result is not None)
    read: list[str] = []
    skipped: list[str] = []
    for name in missing:
        offset = 1
        pending: list[AgentStep] = []
        size = 0
        while True:
            # ---- 原样保留既有磁盘读取循环体（ToolCall / invoke / pending 累加 / next_offset）----
        if pending and used + size <= budget:
            steps.extend(pending)
            read.append(name)
            used += size
        else:
            skipped.append(name)
    return steps, reused, read, skipped
```

**注意**：`used` 必须从复用已占用的字节数起算，否则 `from_disk=True` 时预算会被重复计算。

### 3.4 `services/harness/agents.py` — `discovery_task` 文案与清单

锚点：`:1069-1128`。签名加一个参数（放在 `files` 之后）：

```python
def discovery_task(
    blackboard: Blackboard,
    item: WorkItem,
    *,
    attempt: int = 1,
    files: list[str] | None = None,
    reused: list[str] | None = None,
    prefetched: list[str] | None = None,
    skipped: list[str] | None = None,
) -> str:
```

三处改动：

**(a) `already` 块的文案分两路。** 原文案（`:1083-1093`）写死了"第二眼"，第一眼收到它会**主动压制新
发现** —— 表现为 discovery 少报候选，且不会让任何测试变红。这是本改动最容易犯的错。

```python
    already = [*(reused or []), *(prefetched or [])]
    if already:
        if attempt > 1:
            lines.append(
                "These files are already read for you and their contents are in this transcript as the "
                "first steps -- do not read them again, and do not re-report what they obviously contain. "
                "Your job is the second look: a path you have not followed, a caller you have not checked, "
                "a control whose absence matters here.\n"
                + "\n".join(f"  - {name}（已读入）" for name in already)
            )
        else:
            lines.append(
                "These files are already in this transcript as the first steps -- another scope read "
                "them completely, so do not read them again. Your job is the *first* analysis of this "
                "scope: report what is wrong with the code you can already see, and read anything else "
                "you own yourself.\n"
                + "\n".join(f"  - {name}（已读入，不要重读）" for name in already)
            )
```

**(b) `skipped` 块的措辞放宽。** 现在写的是"太大没法替你预读"（`:1094-1098`），默认路径下未命中的
原因是"黑板里还没有完整的读"：

```python
    if skipped:
        lines.append(
            "These files are not in this transcript, so read them yourself:\n"
            + "\n".join(f"  - {name}" for name in skipped)
        )
```

**(c) `files` 块只列**尚未在 transcript 里**的文件**，否则它会和 (a) 块自相矛盾（同一份 task 一边说
"每个都要读完"、一边说"这些不要重读"）：

```python
    owned = [name for name in (files or []) if name not in set(already)]
    if owned:
        lines.append(
            "Files you own -- read each one end to end, and report which of them you finished. "
            "These files are independent of one another, so put several `read` calls in ONE turn "
            "rather than one per turn: a turn is a round trip, and spending one per file is how the "
            "group fails to finish inside its budget.\n"
            + "\n".join(f"  - {name}" for name in owned)
        )
    elif files:
        lines.append(
            "Every file you own is already in this transcript (listed above). Do not read them again; "
            "report which of them you finished, based on what you have."
        )
```

### 3.5 `services/harness/coordinator.py` — `_discover` round 0 接线

锚点：`:1380-1406`（`def one(item: WorkItem) -> None:` 的开头）。

现在 `if round_index and owned:` 才预取，round 0 完全不复用。改为：

```python
        def one(item: WorkItem) -> None:
            owned = self._scope_files.get(item.scope_id) or []
            prefetched_steps: list[AgentStep] = []
            prefetched_files: list[str] = []
            skipped_files: list[str] = []
            reused_files: list[str] = []
            if round_index:
                # A re-dispatch is handed only what is still unread: starting the whole group again
                # spends the budget re-reading files the previous agent already finished.
                assigned = self._unread_in(item.scope_id) or None
            else:
                assigned = owned or None
            # Reuse happens in **every** round, round 0 included: a file another scope already read
            # completely is the same bytes, and re-fetching it costs a round trip per scope -- measured
            # on a four-file project, five scopes each spent a turn reading the same four files.
            #
            # A scope that owns no files shares nothing rather than everything (`replayable_reads`
            # treats an empty list as a no-op): a planner-created scope with no `files` has no
            # assignment to base the reuse on, and handing it the whole repository would be a scope
            # whose context is the workspace.
            if owned:
                wanted = (self._unread_in(item.scope_id) or owned) if round_index else owned
                (
                    prefetched_steps,
                    reused_files,
                    prefetched_files,
                    skipped_files,
                ) = agents.prefetch_scope_files(
                    wanted,
                    self.context,
                    budget=self.config.material_budget,
                    blackboard=self.blackboard,
                )
```

并把 `discovery_task` 调用（`:1410-1417`）改成：

```python
                task=agents.discovery_task(
                    self.blackboard,
                    item,
                    attempt=round_index + 1,
                    files=assigned,
                    reused=reused_files,
                    prefetched=prefetched_files,
                    skipped=skipped_files,
                ),
```

`initial_steps=prefetched_steps or None`（`:1423`）**保持不变**。
`_discover` 的 docstring 补一句：复用不只发生在重派发轮。

### 3.6 `services/harness/coordinator.py` — 开场 pass ≥ 2 接线

锚点：`_run_recon`（`:994-1025`）、`_run_threat_model`（`:1027-1059`）。

新增一个私有 helper（放在 `_run_recon` 之前，或与 `_opening_counts` 相邻）：

```python
    def _opening_reuse(self) -> list[AgentStep]:
        """Complete reads this run already has, to seed an opening re-dispatch with.

        Pass 1 is the reader: it is the only pass allowed to fetch from disk, and its reads are the
        evidence the coverage ledger rests on. Pass 2 onwards is a *re-read* by construction (see
        `_run_recon`), so the bytes come out of the blackboard instead -- measured on a four-file
        project, the re-dispatches re-read the same four files once per pass.
        """
        steps, _reused, _missing = agents.replayable_reads(
            self.blackboard,
            coverage.inventory(self.workspace),
            budget=self.config.material_budget,
        )
        return steps
```

两个 `self._agent(...)` 调用各加一行：

```python
            initial_steps=self._opening_reuse() if index >= 2 else None,
```

- `index >= 2` 是必须的：pass 1 是唯一允许从磁盘读的读者。
- `coverage` 已在 `:74` 导入，无需新增 import。

### 3.7 `services/harness/coordinator.py` — `_planner_call`：复用 + 回写 `_scope_files`

锚点：`:1213-1276`。两处改动。

**(a) 复用。** 在构造 `task` 之后、`outcome = self._agent(...)`（`:1242`）之前插入：

```python
        # The opening stage has already read part of this repository, and the planner's second turn is
        # otherwise spent re-fetching it (measured: one pure-read turn on the four-file project).
        reuse, _reused_files, _missing_files = agents.replayable_reads(
            self.blackboard,
            sorted({name for scope in scopes for name in scope.files}),
            budget=self.config.material_budget,
        )
```

并在 `self._agent(...)` 里加 `initial_steps=reuse or None,`。

**(b) 回写 `_scope_files`（**前置修复，必须先落地**）。** 现状：`_planner_call` 的任务文本
（`:1236`）**明确要模型返回 `files`**，构造 `WorkItem`（`:1256-1265`）时却把它丢了。实测后果：
`scope-data-access` 的 `files=0`，它的 round-1 run 预取步数是 **0**，静默空转。

在既有 `items = [...]` 列表推导（`:1256-1265`）之后追加：

```python
        # The planner is asked for each scope's `files` and used to drop them. Two things depended on
        # that list and both were silently dead for a planner-created scope: the prefetch above had
        # nothing to reuse (measured: `scope-data-access` carried `files=0` and its re-dispatch prefetch
        # seeded nothing), and `_close_coverage`'s "N files never read end to end" clause never fired
        # for it because `_unread_in` returned empty.
        #
        # Filtered against the real inventory, not trusted: the same rule as `docs/HANDOVER.md` §14.12
        # item 1 -- a path a model wrote is a string, and nobody has checked it against the workspace.
        inventory = set(coverage.inventory(self.workspace))
        for scope in planned.get("scopes", []):
            if not isinstance(scope, dict) or not scope.get("scope_id"):
                continue
            named = [
                str(name) for name in (scope.get("files") or []) if str(name) in inventory
            ]
            if named:
                self._scope_files.setdefault(str(scope["scope_id"]), named)
```

### 3.8 `services/harness/agents.py` — `run()` 写 `AgentRun.reused_files`

锚点：`run()`（`:1345-1385`），在 `run_result = run_agent(...)` 之后、`parse_output` 之前：

```python
    run_result.reused_files = _reused_files(initial_steps)
```

并在文件内新增（建议紧邻 `SCOPE_REUSE_THOUGHT`，`:1163-1166` 之后）：

```python
def _reused_files(initial_steps: list[AgentStep] | None) -> list[str]:
    """The files a run was handed out of the blackboard, read off the seeded steps.

    Derived rather than passed in as a parameter, for the same reason the coverage ledger is derived
    from real `read` calls: a separate argument is a second source of truth that can drift from the
    transcript it describes. The `thought` marker is what separates a reused read from a read the
    harness performed itself (`SCOPE_PREFETCH_THOUGHT`) or a forced dataflow trace
    (`HARNESS_PREFETCH_THOUGHT`).
    """
    found = [
        str((step.result.data or {}).get("path") or "")
        for step in (initial_steps or [])
        if step.thought == SCOPE_REUSE_THOUGHT and step.result is not None and step.result.ok
    ]
    return [name for name in dict.fromkeys(found) if name]
```

---

## 4. 测试

文件：`tests/test_harness_orchestration.py`（3537 行，基建已具备：`make_fake_tools` `:191`、
`FakeToolContext.calls` `:181`、`ScriptedClient` `:74`、`pipeline` `:733`）。

### 4.1 必须修改的既有用例（共 2 个）

| 位置 | 现在断言什么 | 怎么改 |
| --- | --- | --- |
| `:2075` `test_the_prefetch_is_off_at_budget_zero_and_skips_what_does_not_fit` | `budget=20_000` 时 `read == [service_file]` | 默认路径改成断言 `read == []` 且 `skipped == [service_file]`；**再加一条** `from_disk=True` 的调用，断言找回旧行为 `read == [service_file]` |
| `:2110` `test_a_file_the_run_already_read_is_taken_from_the_blackboard_not_the_disk` | 第一次调用（无 blackboard，`:2149`）断言 `read == [service_file] and len(module.recorded) == 1` | 第一次调用加 `from_disk=True`（它在模拟"第一次从磁盘读"）；第二次调用（有 blackboard）**不动**，`reused == [service_file]` / `read == []` / `module.recorded == []` 的断言继续成立 |

### 4.2 必须新增的用例（9 个）

| # | 名字 | 断言的核心 |
| --- | --- | --- |
| 1 | `test_replayable_reads_only_looks_at_the_blackboard` | 空黑板 + `make_fake_tools()` → `module.recorded == []`（**一次工具调用都没有**），返回值 `([], [], files)` |
| 2 | `test_replayable_reads_returns_what_the_board_has_and_names_what_it_does_not` | 黑板有一个完整读，请求两个文件 → `(1 step, [a], [b])`，且该 step 的 `thought == agents.SCOPE_REUSE_THOUGHT` |
| 3 | `test_replayable_reads_is_a_no_op_for_an_empty_file_list` | `replayable_reads(board, [], budget=10_000) == ([], [], [])`，且**不抛异常**（决策 D2 的守卫） |
| 4 | `test_a_partially_read_file_is_not_replayable` | 用 `:2172` 的 `big.py` 形状建黑板 → `replayable_reads(board, ["big.py"], budget=10_000) == ([], [], ["big.py"])` |
| 5 | `test_discovery_round_zero_reuses_a_file_another_scope_already_read` | 两个 scope 拥有同一文件；`FakeToolContext.calls` 里该文件的 `read` **只出现一次**；第二个 discovery run 的 `reused_files` 含该文件 |
| 6 | `test_opening_pass_two_does_not_re_read_what_pass_one_read` | 用**真**工具层（参照 `:1417`）或带真实 `path` 的假结果，断言 pass 2 的 run `reused_files` 非空 |
| 7 | `test_a_planner_created_scope_carries_the_files_the_planner_named` | 脚本 planner 回答里给一个新建 scope 带 `files` → `_scope_files[该 scope]` == 这些文件（且只含 inventory 内的路径） |
| 8 | `test_the_round_zero_reuse_text_asks_for_a_first_look_not_a_second` | 直接对 `agents.discovery_task(..., attempt=1, reused=[f], files=[f])` 断言含 `"*first* analysis"` 且**不含** `"second look"`；`attempt=2` 时断言相反 |
| 9 | `test_the_round_zero_reuse_text_does_not_also_demand_a_read` | 同上参数 → 断言输出里**不含** `"read each one end to end"`（即不再自相矛盾） |

### 4.3 可能需要跟着调整的用例（预期会红，**不要削弱断言**）

| 位置 | 为什么可能红 | 怎么处理 |
| --- | --- | --- |
| `:1417` `test_the_pipeline_runs_against_the_real_tool_layer_with_a_scripted_model` | `:1469` 断言 `discovery_run.steps[0]` 是模型自己读的那一步；若该 scope 命中了复用，`steps[0]` 会变成 index=0 的复用步 | 把 `steps[0]` 改成"第一个 `call is not None` 的步"，并**补一条** `assert discovery_run.reused_files == []`（该 run 是第一个读者，不该有复用）。**不要**改成"跳过断言" |
| `:1797` `test_...trail...` | `len(step events) == sum(len(run.steps))` | 这是自洽不变量：`react.run` 的 `record()` 对 seeded 步也调用 `on_step`（`react.py:369-371`），所以**不该红**。若红了说明 seeded 步没进 trail，是真 bug |

多数既有用例不受影响：它们用假工具层，`make_fake_tools` 的 stub 结果没有 `path`/`total_lines`
（`:207-212`），所以 `stored_read` 找不到完整读 → 复用不发生。

---

## 5. 文档改动

| 文件 | 改什么 |
| --- | --- |
| `services/harness/agents.py` | `prefetch_scope_files` / `replayable_reads` docstring（§3.2、§3.3 已给）；`SCOPE_PREFETCH_THOUGHT` 的注释补一句"磁盘分支现已默认关闭" |
| `services/harness/coordinator.py` | `_discover` docstring 补"复用发生在每一轮，含 round 0"；`_planner_call` docstring 补 `_scope_files` 的回写 |
| `docs/HANDOVER.md` §14.3 | 开场 pass ≥ 2 的黑板复用 |
| `docs/HANDOVER.md` §14.4 | discovery round 0 复用；`_scope_files` 修复（planner 的 `files` 不再被丢） |
| `docs/HANDOVER.md` §14.11 | **补两条实测**：`墙钟 ≈ 输出token × 20.4ms ÷ 并发`（corr(延迟, 输出)=+0.93，corr(延迟, 输入)=+0.22）；`81 次 read 只花 20 个往返（因为批量读，MAX_CALLS_PER_TURN=8）` |
| `docs/HANDOVER.md` §14.12 | 把"planner scope 无文件集"记为已修 |
| `docs/AI_STAGE.md` | **不动**（那条是 fan-out 路径，与 agent harness 无关） |
| `report.py` | **不动**（决策 D4） |

---

## 6. 验证与验收

### 6.1 每条提交都要跑（零成本）

```powershell
python -m ruff check .
python -m pytest -q
```

门槛：`ruff` 干净；`pytest` 基线 **674 passed / 13 skipped**，加上 §4.2 的 9 个新用例后应为
**683 passed / 13 skipped**（若 §4.1 的改动把某一例拆成两例，数字相应 +1）。**不允许出现 xfail 或 skip 新增用例。**

### 6.2 零成本的功能核对

```powershell
python -m services.harness.cli plan --workspace var\projects\demo-taint
```

`--dry-run` 路径不走模型也不走工具层，因此它**不**覆盖本改动；它的价值是确认 §3.7(b) 的
`_scope_files` 回写没把 `_plan` 弄崩（scope 表应当照常产出）。

### 6.3 真实运行的验收指标（只能从一次真跑读出）

对下一次 audit 的产物跑：

```powershell
python var\audit_breakdown.py <job_id>
python var\prefetch_worth.py <job_id>
```

| 指标 | 基线（`J-712e9f…`） | 门槛 |
| --- | --- | --- |
| 模型往返 | 69 | ≤ 60 |
| 墙钟 | 994s | ≤ 860s |
| `read` 工具调用 | 81 | ≤ 45 |
| 纯读 turn 数 | 20 | ≤ 11 |
| 候选 / 判决 / 最终发现 | 8 / 8 / 2 | **完全相同** |
| 覆盖台账"完整读过" | 4 / 4 | **完全相同** |

真跑会花约 25 万 token，**是否现在跑由人决定**；代码改动本身以 §6.1 为准。

---

## 7. 已知坑与禁止事项

1. **`_scope_files` 的回写（§3.7b）必须先落地。** 不修它，§3.5 的接线对 planner 拆出来的 scope
   是空转，而且**不报错**。
2. **§3.4(a) 的文案分路与 §3.5 的接线必须同一个提交。** 第一眼的 agent 收到"做第二眼"的指令会
   少报候选 —— 这个退化不会让任何测试变红。
3. **`files` 清单必须减去已读入的文件（§3.4c）。** 否则同一份 task 自相矛盾。
4. **`used` 的起算点（§3.3）。** `from_disk=True` 时预算必须扣除复用已占用的字节。
5. **不要改 `_unread_in` / `_close_coverage` 的判据。** §3.7(b) 修好 `_scope_files` 后，
   planner scope 会**自动**开始受"未读完文件"这条判据约束 —— 这是预期效果，不是回归。
6. **不要改 `report.py`**（决策 D4）。`AgentRun.reused_files` 随 `blackboard.json` 落盘即可核对；
   复用的步也已经在 `trail.jsonl` 里以 `agent_step`（index 0）出现。
7. **"完整读过的次数"会下降，百分比不会。** 同一个文件从"被读 7 次"变成"被读 1 次"，但
   `coverage.summarize` 按**文件**算覆盖率（`coverage.py:171`），`4/4 = 100%` 不变。看到 read
   次数下降不要当成覆盖退化。
