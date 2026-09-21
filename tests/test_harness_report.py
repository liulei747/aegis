"""The report as a *readable document*, not a dump of everything the run recorded.

The failure this file pins, measured on a real audit of a five-file demo: 910 KB, of which 74% was
every step of all 88 agent runs and 20% was every rejection written out in full. A report nobody
finishes reading has lost the information it contains, which is why "print everything" is not the
safe default the codebase usually prefers -- here the honest move is to summarise, say what was
summarised, and name the file where the full record lives.

What must stay true is that nothing is *hidden*: every finding appears, every rejected place appears
with a reason, and the runs that stopped early keep their transcripts. These tests check exactly
that, plus the caps that make the thing readable.
"""

from __future__ import annotations

from pathlib import Path

from aegis_contracts.harness import (
    AgentRun,
    AgentStep,
    AttackPath,
    Blackboard,
    Candidate,
    CandidateVerdict,
    CoverageState,
    DataflowEvidence,
    EvidenceKind,
    FinalFinding,
    OpeningConvergence,
    SecurityInventory,
    ToolCall,
    ToolName,
    ToolResult,
    VerdictKind,
)
from services.harness import blackboard as bb
from services.harness import report


def _board(tmp_path: Path) -> Blackboard:
    board = bb.new_blackboard("run-report", tmp_path)
    candidate = Candidate(
        candidate_id="C-1",
        scope_id="scope-a",
        title="拼接查询",
        vulnerability_type="sql_injection",
        file="repo.py",
        line=19,
        rationale="字符串拼接进 SQL",
    )
    bb.add_candidate(board, candidate)
    bb.add_verdict(
        board,
        CandidateVerdict(
            candidate_id="C-1",
            verdict=VerdictKind.CONFIRMED,
            evidence_kind=EvidenceKind.DATAFLOW,
            reasons=["Joern 推导出源→汇聚点路径"],
            confidence=0.9,
        ),
    )
    bb.set_coverage(board, "scope-a", CoverageState.SUFFICIENT, reason="看过且没有新地点")
    return board


def _run(*, run_id: str, stop_reason: str, steps: int) -> AgentRun:
    run = AgentRun(run_id=run_id, agent="discovery", scope_id="scope-a", model="m")
    for index in range(1, steps + 1):
        run.steps.append(
            AgentStep(
                index=index,
                thought=f"第 {index} 步的想法 " + "长" * 120,
                call=ToolCall(tool=ToolName.READ, arguments={"path": "repo.py"}),
                result=ToolResult(
                    tool=ToolName.READ, ok=True, summary="读到 34 行" * 40, data={"path": "repo.py"}
                ),
            )
        )
    run.stop_reason = stop_reason
    return run


def test_every_finding_appears_in_the_index_even_when_its_detail_is_capped(tmp_path: Path) -> None:
    """The index is the safety net for every cap in this file."""
    board = _board(tmp_path)
    for index in range(3):
        candidate = Candidate(
            candidate_id=f"C-{index + 2}",
            scope_id="scope-a",
            title=f"第 {index + 2} 条",
            vulnerability_type="path_traversal",
            file=f"f{index}.py",
            line=index + 1,
            rationale="r",
        )
        bb.add_candidate(board, candidate)
        bb.add_verdict(
            board,
            CandidateVerdict(
                candidate_id=candidate.candidate_id,
                verdict=VerdictKind.CONFIRMED,
                evidence_kind=EvidenceKind.SEMANTIC,
                reasons=["r"],
                confidence=0.5,
            ),
        )
    board = board.model_copy(deep=True)
    board.findings.extend(
        [
            FinalFinding(
                finding_id=f"F-{index}",
                candidate_id=f"C-{index}",
                title=f"第 {index} 条",
                vulnerability_type="sql_injection",
                file=f"f{index}.py",
                line=index,
                severity="low",
                evidence_kind=EvidenceKind.SEMANTIC,
            )
            for index in range(4)
        ]
    )

    text = report.render(board)

    for index in range(4):
        assert f"| {index + 1} |" in text, "every finding is a row in the index table"
        assert f"F-{index}" in text, "and every finding id appears somewhere"
    assert "| # | 位置 | 类型 | 严重度 | 证据 | 可达 |" in text


def test_the_attack_path_prose_is_capped_and_says_so(tmp_path: Path) -> None:
    """A model writes paragraphs; an uncapped list is how one finding became three pages."""
    board = _board(tmp_path)
    board.findings.append(
        FinalFinding(
            finding_id="F-1",
            candidate_id="C-1",
            title="t",
            vulnerability_type="sql_injection",
            file="repo.py",
            line=19,
            severity="high",
            evidence_kind=EvidenceKind.DATAFLOW,
            dataflow=DataflowEvidence(derived=True, source="s", sink="k", path=["a", "b"]),
            attack_path=AttackPath(
                candidate_id="C-1",
                reachable=True,
                entry_points=[f"入口 {index} " + "长" * 500 for index in range(6)],
                preconditions=["只有一个"],
                impact="影响" * 2000,
                confidence=0.9,
            ),
            summary="影响" * 2000,
        )
    )

    text = report.render(board)

    assert "另有 3 条，见 `blackboard.json`" in text, "a capped list states how many it dropped"
    assert "长" * 500 not in text, "each entry is clipped"
    assert text.count("影响") < 700, "the impact paragraph is clipped too"
    # The reachable finding gets its own section, which is what tells a reader where to start.
    assert "### 2.1 可利用的发现" in text


def test_an_unreachable_finding_is_separated_and_still_listed(tmp_path: Path) -> None:
    """"Found in the code, could not get to it" must not read as an exploit *or* as nothing."""
    board = _board(tmp_path)
    board.findings.extend(
        [
            FinalFinding(
                finding_id="F-reach",
                candidate_id="C-1",
                title="可达的",
                vulnerability_type="sql_injection",
                file="a.py",
                line=1,
                severity="high",
                attack_path=AttackPath(candidate_id="C-1", reachable=True, confidence=0.9),
            ),
            FinalFinding(
                finding_id="F-latent",
                candidate_id="C-1",
                title="不可达的",
                vulnerability_type="sql_injection",
                file="b.py",
                line=2,
                severity="low",
                attack_path=AttackPath(
                    candidate_id="C-1", reachable=False, confidence=0.2,
                    reasons=["没有任何地方调用它"],
                ),
            ),
        ]
    )

    text = report.render(board)

    assert "### 2.1 可利用的发现" in text and "F-reach" in text
    assert "### 2.2 代码中确认、但判定不可达" in text and "F-latent" in text
    assert "攻击路径判定可达 **1** 条" in text
    assert "判定依据：没有任何地方调用它" in text


def test_rejections_are_aggregated_by_place_with_one_reason_each(tmp_path: Path) -> None:
    """52 rejections came to 181 KB written out in full; the reader needs the place and the reason."""
    board = _board(tmp_path)
    for index in range(3):
        candidate = Candidate(
            candidate_id=f"C-rej-{index}",
            scope_id=f"scope-{index}",
            title=f"同一处的第 {index} 种说法",
            vulnerability_type="authz_bypass" if index else "sql_injection",
            file="handler.py",
            line=12,
            rationale="r",
        )
        bb.add_candidate(board, candidate)
        bb.add_verdict(
            board,
            CandidateVerdict(
                candidate_id=candidate.candidate_id,
                verdict=VerdictKind.REJECTED,
                evidence_kind=EvidenceKind.SEMANTIC,
                reasons=[f"理由 {index}：" + "很长的解释" * 100],
                confidence=0.5,
            ),
        )

    text = report.render(board)
    section = text.split("## 3. ")[1].split("## 4. ")[0]

    assert "落在 **1** 个位置上" in section, "three claims about one line are one row"
    assert "`sql_injection`、`authz_bypass`×2" in section
    assert "| 3 |" in section
    assert "理由 0" in section, "a representative reason survives"
    assert len(section) < 2500, "and the reason column is clipped, keeping the table scannable"
    assert "blackboard.json" in section, "the full text is pointed at"


def test_a_finished_run_is_a_row_and_an_unfinished_run_keeps_its_transcript(tmp_path: Path) -> None:
    """88 runs of steps is not a report; the runs that *stopped* are the ones worth reading.

    And since 2026-09-17 the transcript of those runs is written *beside* the report rather than in
    it: measured on the `upp-module-infra` audit, inlining them was 665 KB of a 1080 KB report. The
    content is not summarised away -- `abnormal_runs_markdown` is where it goes, and the report has to
    say so, because a report that drops a transcript without naming where it went is worse than one
    that is long.
    """
    board = _board(tmp_path)
    for index in range(20):
        bb.add_run(board, _run(run_id=f"discovery:done-{index}", stop_reason="finished", steps=6))
    bb.add_run(board, _run(run_id="discovery:stuck", stop_reason="budget", steps=4))

    text = report.render(board)
    section = text.split("## 6. ")[1]

    assert "| `discovery`" in section and "read×6" in section, "each run is one row with its tools"
    assert "第 1 步的想法" not in section, "21 runs of steps is not a report"
    assert "### 6.1 未正常结束的 run（全文另存）" in section
    assert "abnormal-runs.md" in section
    assert "discovery:stuck" in section
    assert "| `discovery:stuck` | `discovery` | `budget` | 4 |" in section

    sidecar = report.abnormal_runs_markdown(board)
    assert sidecar.count("第 1 步的想法") == 1, "the stuck run's 4 steps, and nobody else's"
    assert "discovery:stuck" in sidecar
    assert "discovery:done-0" not in sidecar, "a run that finished keeps only its row"


def test_the_report_describes_the_single_round_opening_and_the_inventory(
    tmp_path: Path,
) -> None:
    """The opening block now reports the single-round design, and the inventory its own counts.

    The old text audited the convergence loop ("已收敛/未收敛, N 条未读"); that loop is gone
    (2026-09-18) and reconciling the pair's outputs is the AI security-inventory stage's job — so the
    report shows the single-round claim plus the inventory's per-section counts and its coverage gaps.
    """
    board = _board(tmp_path)
    board.opening = OpeningConvergence(
        passes=1,
        converged=True,
        watermarks={},
        unread={},
        note="单轮独立开场：recon 与威胁建模各执行一轮、不互读收敛（设计变更）。",
    )
    board.security_inventory = SecurityInventory(
        entry_points=[{"name": "POST /admin-api/infra/file/upload", "file": "AppFileController.java",
                       "line": 38}],
        coverage_gaps=["运行期动态数据源注册未能静态确认"],
    )
    text = report.render(board)
    assert "开场（recon → 威胁建模）" in text
    assert "单轮独立完成（1 轮；设计上不互读收敛）" in text
    assert "安全清单（AI，基于开场两方的结论）" in text
    assert "入口：1 项" in text
    assert "POST /admin-api/infra/file/upload" in text
    assert "运行期动态数据源注册未能静态确认" in text
    assert "| 开场（recon → 威胁建模） | 单轮独立（1 轮，不互读收敛） |" in text
    assert "未收敛" not in text

    # A dry run has neither an opening nor an inventory, and the absence of the claim is different
    # from the claim.
    plain = _board(tmp_path)
    assert "开场（recon" not in report.render(plain)
    assert "trail.jsonl" in text, "and the full record is named"
