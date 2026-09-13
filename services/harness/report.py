"""The markdown report: what was found, what was dismissed, and how anyone knows.

A security report is read by someone deciding whether to act, and the questions they are actually
asking are: what did you find; *what did you consider and dismiss*; what did you not look at; and
how do you know any of it. So this is not a findings list with a header. It is, in order:

1. what the run concluded, and whether it finished;
2. the confirmed findings, with the evidence kind and the attack path that decides severity;
3. the **rejected candidates with the reason each was dismissed** -- the reader who trusts only
   confirmed findings is exactly the reader who needs to see the dismissals;
4. the coverage table with every scope's state and the stated reason, including the excluded ones;
5. the reasoning trail, one section per agent run, built from ``AgentRun.steps``;
6. the agent runs that stopped early, called out rather than buried.

The trail is generated from the recorded steps, never from a summary a model wrote about itself.
A model's account of its own reasoning is a claim; the transcript is evidence.
"""

from __future__ import annotations

from pathlib import Path

from aegis_contracts.harness import (
    AgentRun,
    Blackboard,
    CoverageState,
    EvidenceKind,
    ToolName,
)
from aegis_core.logging import get_logger
from services.harness import coverage

log = get_logger(__name__)

REPORT_FILE = "report.md"

#: The Chinese labels for coverage states. Kept explicit rather than using `.value` so the report
#: and the JSON blackboard can be worded for their different readers.
COVERAGE_LABEL = {
    CoverageState.SUFFICIENT: "充分（已按该 scope 的证据收敛）",
    CoverageState.INSUFFICIENT: "不充分（证据不足以收敛）",
    CoverageState.EXCLUDED: "已排除（有意不看，附理由）",
    CoverageState.UNSEEN: "未查看",
}

EVIDENCE_LABEL = {
    EvidenceKind.SEMANTIC: "语义证据（读代码与调用方）",
    EvidenceKind.DATAFLOW: "数据流证据（Joern 推导的源→汇聚点路径）",
}


def write_report(blackboard: Blackboard, run_dir: Path, *, notes: list[str] | None = None) -> Path:
    """Render and write `report.md`. Returns its path."""
    path = Path(run_dir) / REPORT_FILE
    path.write_text(render(blackboard, notes=notes), encoding="utf-8")
    return path


def render(blackboard: Blackboard, *, notes: list[str] | None = None) -> str:
    out: list[str] = []
    out.append(f"# Aegis harness 报告：{blackboard.run_id}")
    out.append("")
    out.append(f"- 工作区：`{blackboard.workspace}`")
    out.append(f"- 轮次：**{_rounds(blackboard)}**；blackboard revision：{blackboard.revision}")
    out.append(f"- 运行状态：{'已收敛关闭' if blackboard.closed else '未关闭（提前结束）'}")
    out.append(f"- 关闭说明：{blackboard.closure_note or '（无）'}")
    if notes:
        out.append("")
        out.append("运行备注：")
        for note in notes:
            out.append(f"- {note}")
    out.append("")

    out.append("## 1. 结论概览")
    out.append("")
    out.append("| 指标 | 数量 |")
    out.append("| --- | --- |")
    out.append(f"| scope（覆盖率条目） | {len(blackboard.coverage)} |")
    out.append(f"| 候选 candidate | {len(blackboard.candidates)} |")
    out.append(f"| 研判 verdict | {len(blackboard.verdicts)} |")
    out.append(f"| 确认 confirmed | {_count_confirmed(blackboard)} |")
    out.append(f"| 最终发现 FinalFinding | {len(blackboard.findings)} |")
    # Shown next to the finding count so the arithmetic is auditable: confirmed - merged =
    # findings, and a reader who has the old per-candidate report in mind can see where the rows
    # went instead of assuming the run simply found less.
    merged = sum(max(0, len(finding.affected_locations) - 1) for finding in blackboard.findings)
    if merged:
        out.append(f"| 同位点合并的候选（已并入上行的发现） | {merged} |")
    out.append(f"| agent run | {len(blackboard.runs)} |")
    early = _stopped_early(blackboard)
    out.append(f"| 提前结束的 agent run | {len(early)} |")
    opening = getattr(blackboard, "opening", None)
    if opening is not None:
        # In the overview as well as in section 4: whether the opening pair actually read each other
        # decides how much the threat model below is worth, and a reader who stops after the counts
        # should still see it.
        unread = sum(opening.unread.values())
        out.append(
            f"| 开场轮次（recon × 威胁建模） | {opening.passes}"
            f"{'（已收敛）' if opening.converged else f'（未收敛，{unread} 条未读）'} |"
        )
    out.append("")

    out.extend(_findings_section(blackboard))
    out.extend(_rejected_section(blackboard))
    out.extend(_coverage_section(blackboard))
    out.extend(_early_section(blackboard, early))
    out.extend(_trail_section(blackboard))
    out.extend(_where_the_rest_is(blackboard))
    return "\n".join(out).rstrip() + "\n"


# ─────────────────────────────────────────────────────────── sections


def _is_reachable(finding) -> bool:
    """Whether the attack-path stage concluded the finding is reachable.

    `None` (the stage produced nothing) is *not* the same as `False` (the stage concluded it is not
    reachable) -- and neither is the same as a bug that is not there. The report separates them
    because a reader deciding what to fix first needs exactly that distinction.
    """
    return finding.attack_path is not None and bool(finding.attack_path.reachable)


def _findings_section(blackboard: Blackboard) -> list[str]:
    """The findings: an index table for all of them, detail for the ones that are reachable.

    The shape is deliberate. A reader's first question is "how many, and which do I care about", and
    the previous version answered it by burying the list in 48 KB of prose -- every finding got a
    full block with its impact text, so ten findings could not be taken in at a glance. Now:

    * **every** finding appears in the index table. Nothing is dropped: the fix is about depth, not
      about hiding.
    * full detail goes to the findings whose attack path says *reachable*, because those are the ones
      that need fixing, and to nothing else.
    * a finding that is confirmed but not reachable is listed with its own heading and a one-line
      basis, so "we found this in the code and could not get to it" cannot be misread as "this is
      exploitable" -- nor as "we found nothing".
    """
    out = ["## 2. 确认的发现", ""]
    if not blackboard.findings:
        out.append(
            "本次运行没有产出最终发现。"
            "这不等于“没有问题”：请对照第 4 节的覆盖率表，看有多少 scope 是"
            "不充分或未查看的。"
        )
        out.append("")
        return out

    reachable = [finding for finding in blackboard.findings if _is_reachable(finding)]
    unreachable = [finding for finding in blackboard.findings if not _is_reachable(finding)]

    out.append(
        f"共 **{len(blackboard.findings)}** 条：攻击路径判定可达 **{len(reachable)}** 条，"
        f"代码中确认但判定不可达/未得出结论 **{len(unreachable)}** 条。"
    )
    out.append("")
    out.append("| # | 位置 | 类型 | 严重度 | 证据 | 可达 | 同位点实例 | 标题 |")
    out.append("| --- | --- | --- | --- | --- | --- | --- | --- |")
    for index, finding in enumerate(blackboard.findings, start=1):
        where = f"`{finding.file}`" + (f":{finding.line}" if finding.line else "")
        reach = finding.attack_path.reachable if finding.attack_path else None
        out.append(
            f"| {index} | {where} | `{finding.vulnerability_type}` | {finding.severity} | "
            f"{EVIDENCE_LABEL.get(finding.evidence_kind, finding.evidence_kind.value)} | "
            f"{'是' if reach else ('否' if reach is False else '未得出结论')} | "
            f"{len(finding.affected_locations) or 1} | {finding.title} |"
        )
    out.append("")

    if reachable:
        out.append("### 2.1 可利用的发现（攻击路径判定可达）")
        out.append("")
        for finding in reachable:
            out.extend(_finding_detail(finding, full=True))
    if unreachable:
        out.append("### 2.2 代码中确认、但判定不可达或可达性未得出结论")
        out.append("")
        out.append(
            "这些位置的问题在代码里**确实存在**（多数还有 Joern 推导出的源→汇聚点路径），"
            "但攻击路径阶段没有证明可以从入口到达。它们的严重度因此统一取 `low`，"
            "在按可利用漏洞处置之前需要人工确认可达性。完整影响描述见"
            " `blackboard.json` 的对应条目。"
        )
        out.append("")
        for finding in unreachable:
            out.extend(_finding_detail(finding, full=False))
    return out


def _bullets(label: str, values: list[str], *, limit: int = 3, width: int = 300) -> list[str]:
    """One bullet list, capped in both directions, and it says what it capped.

    The model writes these as paragraphs -- a single `入口` line ran to a kilobyte on the demo
    report -- so an uncapped list turns a finding into three pages and the reader stops reading
    findings. Capping without a count would be worse than not capping: it would look like the whole
    answer.
    """
    if not values:
        return []
    shown = "；".join(_clip(value, width) for value in values[:limit])
    more = f"（另有 {len(values) - limit} 条，见 `blackboard.json`）" if len(values) > limit else ""
    return [f"- {label}：{shown}{more}"]


def _finding_detail(finding, *, full: bool) -> list[str]:
    """One finding's block. `full` writes the impact and the attack path; otherwise a compact block
    that still names the location, the severity's basis and the evidence."""
    out = [f"#### {finding.finding_id} {finding.title}", ""]
    out.append(f"- 位置：`{finding.file}`" + (f":{finding.line}" if finding.line else ""))
    out.append(f"- 类型：`{finding.vulnerability_type}`；严重度：**{finding.severity}**")
    out.append(
        f"- 证据类型：{EVIDENCE_LABEL.get(finding.evidence_kind, finding.evidence_kind.value)}"
    )
    if finding.affected_locations:
        # Listed, not counted away. A merge the reader cannot audit is indistinguishable from a
        # finding that quietly lost five others, and the locations are often the reason two
        # candidates deserved different verdicts.
        out.append(
            f"- 同位点实例：同一位置共 {len(finding.affected_locations)} 条候选已合并为本条"
            "（下列是同一处断言的不同记录，不是额外漏洞）"
        )
        for location in finding.affected_locations:
            where = str(location.get("file") or "")
            if location.get("line"):
                where = f"{where}:{location['line']}"
            # The candidate id stays: it is what a reader greps for in `blackboard.json`, and the
            # whole point of listing the instances is that the merge can be checked.
            out.append(f"  - `{where}`（scope={location.get('scope_id')}，候选 `{location.get('candidate_id')}`）")
    if full:
        if finding.summary:
            out.append(f"- 影响：{_clip(finding.summary, 1200)}")
        out.append("")
        out.extend(_dataflow_block(finding.dataflow))
        path = finding.attack_path
        if path is None:
            out.append("- 攻击路径：**未得出结论**（attack_path 阶段没有产出）")
        else:
            out.append(f"- 可达：{'是' if path.reachable else '否'}（置信度 {path.confidence:.2f}）")
            out.extend(_bullets("入口", path.entry_points))
            out.extend(_bullets("前置条件", path.preconditions))
            out.extend(_bullets("鉴权条件", path.auth_conditions))
            out.extend(_bullets("状态条件", path.state_conditions))
            out.extend(_bullets("替代路径", path.alternative_paths))
            out.extend(_bullets("路径阶段理由", path.reasons))
    else:
        path = finding.attack_path
        basis = "; ".join((path.reasons or [])[:1]) if path is not None else "attack_path 未产出"
        out.append(f"- 判定依据：{_clip(basis, 200)}")
        if finding.dataflow is not None and finding.dataflow.derived:
            out.append(
                f"- 数据流：`{finding.dataflow.source}` → `{finding.dataflow.sink}`"
                f"（{len(finding.dataflow.path)} 步）"
            )
    out.append("")
    return out


def _dataflow_block(dataflow) -> list[str]:
    """The evidence chain, or an explicit statement that there is none.

    An absent path is worded as "no dataflow evidence", never as "no dataflow exists": the two are
    different claims, and the second one is what a reader would wrongly infer from a blank line.
    """
    if dataflow is None:
        return ["- 数据流证据：无（该结论不基于推导的源→汇聚点路径）", ""]
    if dataflow.error:
        return [f"- 数据流证据：**不可用/未得出结论** —— {dataflow.error}", ""]
    out = [
        f"- 数据流证据（derived={dataflow.derived}）：`{dataflow.source}` → `{dataflow.sink}`",
    ]
    if dataflow.path:
        for index, step in enumerate(dataflow.path, start=1):
            out.append(f"  {index}. {step}")
    else:
        out.append("  - 引擎给出否定结论：该值到不了汇聚点（这是结论，不是验证失败）")
    if dataflow.methods:
        out.append(f"- 涉及方法：{' → '.join(dataflow.methods)}")
    if dataflow.sanitizers:
        out.append(f"- 清洗点：{'；'.join(dataflow.sanitizers)}")
    out.append("")
    return out


def _rejected_section(blackboard: Blackboard) -> list[str]:
    """Rejected candidates, aggregated by place, **with why**.

    The part a findings-only report leaves out -- and the part that made the report unreadable. Every
    rejection used to get a five-line block with its full rationale, its evidence kind and every
    reason sentence: measured on the five-file demo, 52 rejections came to 181 KB, a fifth of a
    900 KB report that a human is supposed to read.

    Aggregating by `file:line` keeps what a reader needs ("this place was considered, and this is
    why it was dismissed") while collapsing what they do not: the same place accused of three
    different things under three scopes is one row with a count. The full per-claim text stays in
    `blackboard.json`, and the section says so.
    """
    from services.harness.blackboard import rejected_candidates

    rejected = rejected_candidates(blackboard)
    out = ["## 3. 被排除的候选（按位置聚合）", ""]
    if not rejected:
        out.append("没有候选被判定为排除。")
        out.append("")
        return out

    by_place: dict[tuple[str, int | None], list] = {}
    for candidate, verdict in rejected:
        by_place.setdefault((candidate.file, candidate.line), []).append((candidate, verdict))

    out.append(
        f"共 **{len(rejected)}** 条候选被排除，落在 **{len(by_place)}** 个位置上。"
        "同一个位置被多个 scope 以不同类型指控的，合成一行（条数列给出次数）。"
        "每条候选的完整理由在 `blackboard.json` 的 `verdicts` 里，逐字未删。"
    )
    out.append("")
    out.append("| 位置 | 类型（次数） | 条数 | 代表性排除理由 |")
    out.append("| --- | --- | --- | --- |")
    for (file, line), pairs in sorted(by_place.items(), key=lambda item: (item[0][0], item[0][1] or 0)):
        where = f"`{file}`" + (f":{line}" if line else "")
        types: dict[str, int] = {}
        for candidate, _ in pairs:
            types[candidate.vulnerability_type] = types.get(candidate.vulnerability_type, 0) + 1
        listed = "、".join(f"`{name}`×{count}" if count > 1 else f"`{name}`" for name, count in types.items())
        representative = next(
            (verdict.reasons[0] for _, verdict in pairs if verdict.reasons),
            "**排除理由缺失** —— 该研判没有给出理由，属于不合格结论，请人工复核",
        )
        out.append(f"| {where} | {listed} | {len(pairs)} | {_clip(representative, 220)} |")
    out.append("")
    return out


def _trail_section(blackboard: Blackboard) -> list[str]:
    """The reasoning trail: one row per run, and the full transcript only where it matters.

    This section was 674 KB of a 910 KB report -- 88 runs, every step, every tool result -- which is
    not a report, it is a dump with a header. Nobody reads 674 KB, so the information was *lost* by
    being printed.

    What is kept, and why: a row per run answers "what did each agent do and how did it end", and the
    runs that stopped without finishing get their transcripts in full, because those are the ones a
    reader has to explain ("why did this scope never close"). Everything else is one `grep` away in
    `trail.jsonl`, which is written while the run happens and is the same record this section is
    rendered from.
    """
    out = ["## 6. 运行轨迹（逐 agent 摘要；未完成的 run 保留全文）", ""]
    if not blackboard.runs:
        out.append("没有 agent run：本次运行没有调用模型（例如 `--dry-run`）。")
        out.append("")
        return out

    early = _stopped_early(blackboard)
    early_ids = {run.run_id for run in early}
    out.append(
        f"共 {len(blackboard.runs)} 个 agent run，其中 {len(early)} 个没有正常结束"
        "（下表标注），它们的完整步骤附在本节末尾。"
        f"其余 run 的逐步记录见运行目录下的 `trail.jsonl`。"
    )
    out.append("")
    out.append("| agent | scope | 步数 | 工具调用 | 结束原因 | 最终输出 |")
    out.append("| --- | --- | --- | --- | --- | --- |")
    for run in blackboard.runs:
        tools: dict[str, int] = {}
        for step in run.steps:
            if step.call is not None:
                name = _tool_name(step.call.tool)
                tools[name] = tools.get(name, 0) + 1
        listed = "、".join(f"{name}×{count}" for name, count in sorted(tools.items())) or "（无工具调用）"
        marker = " ⚠️" if run.run_id in early_ids else ""
        output = _clip(_json(run.output), 80) if run.output else "—"
        out.append(
            f"| `{run.agent}`{marker} | `{run.scope_id}` | {len(run.steps)} | {listed} | "
            f"`{run.stop_reason}` | {output} |"
        )
    out.append("")

    if early:
        out.append("### 6.1 未正常结束的 run（全文）")
        out.append("")
        for run in early:
            out.append(f"#### {run.run_id}")
            out.append("")
            out.append(
                f"- 阶段：`{run.agent}`；scope：`{run.scope_id}`；"
                f"模型：`{run.model or '（未记录）'}`"
            )
            out.append(f"- 结束原因：`{run.stop_reason}`；步数：{len(run.steps)}")
            if run.output:
                out.append(f"- 最终输出：`{_clip(_json(run.output), 600)}`")
            out.append("")
            out.extend(_steps_block(run))
    return out


def _steps_block(run) -> list[str]:
    """One run's steps, verbatim. Used only for runs that did not finish."""
    out: list[str] = []
    for step in run.steps:
        out.append(f"**第 {step.index} 步** 思考：{_clip(step.thought, 600) or '（无）'}")
        out.append("")
        if step.call is not None:
            out.append(f"- 调用：`{_tool_name(step.call.tool)}` 参数 `{_json(step.call.arguments)}`")
        if step.result is not None:
            status = "ok" if step.result.ok else "FAILED"
            body = step.result.summary if step.result.ok else (step.result.error or "")
            out.append(f"- 结果（{status}）：{_clip(body or '', 1500)}")
            if step.result.truncated:
                out.append("- 结果被截断（工具层已标注）")
        out.append("")
    return out


def _where_the_rest_is(blackboard: Blackboard) -> list[str]:
    """Where the parts this report summarises can be read in full.

    A report that truncates without saying where the rest lives is a report that lies by omission --
    and this file is the *summary* view on purpose, because the full view is a machine-readable
    record that no human reads end to end.
    """
    return [
        "## 附：完整数据在哪里",
        "",
        f"- 运行目录：`{blackboard.workspace}`（工作区）之外的 harness 运行目录，同一次运行还写了：",
        "  - `blackboard.json` —— 全部候选、逐条研判理由、覆盖率、发现（本报告是它的摘要视图）",
        "  - `trail.jsonl` —— 每个 agent 每一步的想法/工具/结果，运行期间逐行落盘",
        "  - `report.md` —— 本文件",
        "",
        "本报告对以下内容做了压缩，压缩处均已标注：第 3 节的排除理由每条取一条代表，"
        "第 6 节只保留未正常结束 run 的全文。",
        "",
    ]


def _file_coverage_block(blackboard: Blackboard) -> list[str]:
    """Files actually read end to end, derived from the `read` calls in the transcript.

    Measured, not self-reported: see `services.harness.coverage`. The reason to print it is the list
    of files *nobody opened*. A scope-level SUFFICIENT verdict hid that on the benchmark -- every
    scope was sufficient while 21 of 30 known positives sat in unopened files -- and this number
    cannot drift from what happened, because it is read off the tool calls.
    """
    workspace = Path(blackboard.workspace)
    if not workspace.is_dir():
        return []
    try:
        lines = coverage.summarize(workspace, blackboard.runs)
    except OSError as exc:
        return [f"（文件覆盖率无法计算：{exc}）", ""]
    if not lines:
        return []
    return ["### 文件覆盖率（按 read 调用台账计算，非模型自述）", "", *lines, ""]


def _opening_block(blackboard: Blackboard) -> list[str]:
    """Whether the two opening agents ended up having read each other's work.

    Reported as its own claim because it is one: recon and threat modelling run concurrently and their
    task texts are fixed when they start, so "the threat model was written against a directory-name map"
    and "the threat model was written against what recon had read" produce the same `threats` list and
    are not the same review. Measured on the first real audit, the threat model read the board twice at
    its very first steps and never again while recon published eleven facts after that -- a reader of
    that report had no way to tell.
    """
    opening = getattr(blackboard, "opening", None)
    if opening is None:
        return []
    out = ["### 开场配对（recon × 威胁建模）", ""]
    state = "已收敛" if opening.converged else "**未收敛**"
    out.append(f"- 结论：{state}；共 {opening.passes} 轮。")
    if opening.watermarks:
        seen = "、".join(
            f"`{agent}` 读到 revision {revision}" for agent, revision in sorted(opening.watermarks.items())
        )
        out.append(f"- 各自读到的黑板版本（按真实 `board` 调用计）：{seen}。")
    if opening.unread:
        backlog = "、".join(
            f"`{agent}` 还有 {count} 条未读" for agent, count in sorted(opening.unread.items())
        )
        out.append(f"- 未读：{backlog}——下面第 2、4 节的内容是在这种情况下得出的。")
    out.append(f"- 说明：{opening.note}")
    out.append("")
    return out


def _coverage_section(blackboard: Blackboard) -> list[str]:
    out = ["## 4. 覆盖率与理由", ""]
    out.extend(_opening_block(blackboard))
    if not blackboard.coverage:
        out.append("没有覆盖率条目：本次运行没有计划任何 scope。")
        out.append("")
    else:
        out.append("| scope | 状态 | 候选 | 确认 | 理由 |")
        out.append("| --- | --- | --- | --- | --- |")
        for entry in blackboard.coverage:
            label = COVERAGE_LABEL.get(entry.state, entry.state.value)
            reason = entry.reason.replace("|", "\\|") or "（未给出理由）"
            out.append(
                f"| `{entry.scope_id}` | {label} | {entry.candidates} | {entry.confirmed} | {reason} |"
            )
        out.append("")
    out.extend(_file_coverage_block(blackboard))
    if blackboard.work:
        out.append("### 工作计划台账")
        out.append("")
        out.append("| work_id | scope | 状态 | 步数 | 打开理由 |")
        out.append("| --- | --- | --- | --- | --- |")
        for item in blackboard.work:
            rationale = item.rationale.replace("|", "\\|") or "（未给出理由）"
            out.append(
                f"| `{item.work_id}` | `{item.scope_id}` | {item.state.value} | "
                f"{item.steps_used} | {rationale} |"
            )
        out.append("")
    return out


def _early_section(blackboard: Blackboard, early: list[AgentRun]) -> list[str]:
    """Runs that stopped on `budget` or `error`. The report has to be able to say "this stopped
    early", so this section exists even when it is empty -- an absent section is indistinguishable
    from a section nobody thought to write."""
    out = ["## 5. 提前结束的 agent", ""]
    if not blackboard.runs:
        # Zero runs and zero *early* runs are different claims, and a dry run has the first: saying
        # "all agents finished" would imply agents ran at all.
        out.append("本次运行没有任何 agent run（例如 `--dry-run` 或未提供模型客户端）。")
        out.append("")
        return out
    if not early:
        out.append("所有 agent run 都以 `finished` 结束（没有撞上步数预算，也没有解析失败）。")
        out.append("")
        return out
    out.append("以下 agent 没有正常结束。它们产出的内容已经保留，但覆盖结论已按“未覆盖”处理：")
    out.append("")
    for run in early:
        out.append(f"- `{run.run_id}`（{run.agent} / {run.scope_id}）：stop_reason=`{run.stop_reason}`，"
                   f"步数 {len(run.steps)}")
    out.append("")
    return out


# ─────────────────────────────────────────────────────────── dataflow status


def dataflow_failure_note(blackboard: Blackboard) -> str | None:
    """Why `dataflow_verify` could not answer, when it could not.

    Scanned from the recorded runs rather than from a flag, because the failure is per call: a
    worker that was up in round one and gone in round three is a real sequence, and the report has
    to be able to say that dataflow evidence is missing for a stated reason rather than leaving the
    reader to infer it from an absence.
    """
    failures: list[str] = []
    for run in blackboard.runs:
        for step in run.steps:
            if step.call is None or step.result is None:
                continue
            if _tool_name(step.call.tool) != ToolName.DATAFLOW_VERIFY.value:
                continue
            if step.result.ok:
                continue
            reason = step.result.error or step.result.summary or "未说明原因"
            if reason not in failures:
                failures.append(reason)
    if not failures:
        return None
    return (
        "dataflow_verify 本次未能给出结论（"
        + " | ".join(failures[:3])
        + "）；相关研判只能按语义证据看待。“没有路径”与“没有问过引擎”不是同一件事。"
    )


# ─────────────────────────────────────────────────────────── small helpers


def _rounds(blackboard: Blackboard) -> int:
    """How many discovery→closure cycles ran, from the ledger the coordinator wrote.

    Recorded rather than derived. An earlier version counted discovery runs carrying a `:r` round
    marker, which reads zero on a dry run -- so the report's own summary line ("共 3 轮") and its
    header ("轮次：0") contradicted each other in the same document.
    """
    return blackboard.rounds_run


def _count_confirmed(blackboard: Blackboard) -> int:
    return sum(1 for verdict in blackboard.verdicts if verdict.verdict.value == "confirmed")


def _stopped_early(blackboard: Blackboard) -> list[AgentRun]:
    return [run for run in blackboard.runs if run.stop_reason not in ("finished",)]


def _tool_name(tool) -> str:
    if tool is None:
        return "（未知工具，已被拒绝）"
    return getattr(tool, "value", str(tool))


def _json(value) -> str:
    import json

    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True)
    except TypeError:  # pragma: no cover - the blackboard is JSON-serialisable by construction
        return str(value)


def _clip(text: str, limit: int) -> str:
    text = (text or "").replace("\r\n", "\n")
    if len(text) <= limit:
        return text
    return text[:limit] + f"…（已截断，共 {len(text)} 字符）"
