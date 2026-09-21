"""Unified work records must describe unfinished work honestly, including shared model runs."""

import pytest

from aegis_contracts.harness import (
    AgentRun,
    Candidate,
    CandidateVerdict,
    CoverageState,
    EvidenceKind,
    VerdictKind,
    WorkItem,
    WorkItemKind,
    WorkItemState,
)
from aegis_core.cancel import CanceledAbort
from services.harness import agents
from services.harness import blackboard as bb
from services.harness.coordinator import HarnessCoordinator
from services.harness.tasks import TaskLedger, explain_failure


def test_failure_reason_explains_tls_provider_disconnect() -> None:
    reason = explain_failure(
        "agent stopped: model call failed: AIUnavailable: SSL UNEXPECTED_EOF_WHILE_READING",
        "error",
    )
    assert "HTTPS/TLS 连接被提前关闭" in reason
    assert "本任务可重试" in reason
    assert "UNEXPECTED_EOF_WHILE_READING" in reason
from services.harness.trail import CallbackSink, Trail, read_events


def item(work_id="W-1", **kwargs):
    return WorkItem(
        work_id=work_id, scope_id="scope-a", title="检查权限", rationale="外部入口", **kwargs
    )


def test_task_retry_keeps_history_and_emits_authoritative_snapshots(tmp_path):
    board = bb.new_blackboard("run", tmp_path)
    events = []
    ledger = TaskLedger(board, Trail([CallbackSink(events.append)]))
    ledger.add(item())
    ledger.start(["W-1"], "discovery", "run-1")
    with pytest.raises(RuntimeError, match="already running"):
        ledger.start(["W-1"], "discovery", "duplicate")
    ledger.end(["W-1"], stop_reason="error", steps=2, error="工具失败")
    ledger.start(["W-1"], "discovery", "run-2")
    ledger.end(["W-1"], stop_reason="finished", steps=3)
    ledger.update("W-1", state=WorkItemState.DONE, status_reason="权限校验有证据")
    task = board.work[0]
    assert len(task.attempts) == 2
    assert task.steps_used == 5
    assert task.attempts[0].error == "工具失败"
    assert events[0]["work"]["state"] == "planned"
    assert events[-1]["work"] == task.model_dump(mode="json")
    assert task.closed_at is not None


def test_shared_run_does_not_complete_unanswered_claim(tmp_path):
    board = bb.new_blackboard("run", tmp_path)
    ledger = TaskLedger(board, Trail())
    ledger.add(item("one", kind=WorkItemKind.VALIDATION))
    ledger.add(item("two", kind=WorkItemKind.VALIDATION))
    assert board.coverage == [], "validation tasks must not create discovery coverage scopes"
    ledger.start(["one", "two"], "validation_batch", "batch")
    ledger.end(["one", "two"], stop_reason="finished", steps=2)
    ledger.update("one", state=WorkItemState.DONE, status_reason="已裁决")
    ledger.stop("预算耗尽")
    assert ledger.get("one").state is WorkItemState.DONE
    assert ledger.get("two").state is WorkItemState.BLOCKED
    assert "预算耗尽" in ledger.get("two").status_reason


def test_validation_task_is_reused_for_new_instance_of_same_claim(tmp_path):
    co = HarnessCoordinator(workspace=tmp_path)
    a = Candidate(
        candidate_id="C-1",
        scope_id="scope-a",
        title="越权",
        vulnerability_type="idor",
        file="a.py",
        line=1,
    )
    b = a.model_copy(update={"candidate_id": "C-2", "scope_id": "scope-b"})
    first = co._claim_work([a], WorkItemKind.VALIDATION)
    assert co._claim_work([b], WorkItemKind.VALIDATION) == first
    assert co.tasks.get(first).candidate_ids == ["C-1", "C-2"]
    co._apply_verdict(
        [a, b],
        CandidateVerdict(
            candidate_id="C-1",
            verdict=VerdictKind.REJECTED,
            evidence_kind=EvidenceKind.SEMANTIC,
            confidence=0.9,
            reasons=["查询按所有者过滤"],
        ),
    )
    assert co.tasks.get(first).state is WorkItemState.DONE
    assert len(co.blackboard.work) == 1


def test_cancel_persists_unfinished_tasks_and_events(tmp_path, monkeypatch):
    co = HarnessCoordinator(workspace=tmp_path, out_dir=tmp_path / "out", client=object())
    co.attach_trail()

    def cancel():
        co.tasks.add(item())
        raise CanceledAbort(stage="prep")

    monkeypatch.setattr(co, "_prepare", cancel)
    with pytest.raises(CanceledAbort):
        co.run()
    co.trail.close()
    assert co.blackboard.work[0].state is WorkItemState.CANCELED
    assert (co.run_dir / "blackboard.json").is_file()
    events = read_events(co.run_dir / "trail.jsonl")["events"]
    assert any(e["kind"] == "work_item" and e["work"]["state"] == "canceled" for e in events)


def test_budget_without_usable_output_cannot_satisfy_coverage(tmp_path, monkeypatch):
    co = HarnessCoordinator(workspace=tmp_path)
    co.tasks.add(item("W-scope-a"))
    co._planned_scopes = ["scope-a"]
    co.tasks.start(["W-scope-a"], agents.DISCOVERY, "discovery:scope-a:r0")
    co.tasks.end(["W-scope-a"], stop_reason="budget", steps=8, error="没有可用结果")
    bb.close_work(co.blackboard, "W-scope-a", state=WorkItemState.DONE)
    co._close_coverage({}, round_index=0)
    assert bb.coverage_of(co.blackboard, "scope-a").state is CoverageState.INSUFFICIENT
    assert co.tasks.get("W-scope-a").state is WorkItemState.BLOCKED


def test_rediscovery_cannot_pick_validation_task_with_same_scope(tmp_path, monkeypatch):
    co = HarnessCoordinator(workspace=tmp_path, context=object())
    co.tasks.add(item("W-scope-a"))
    co.tasks.add(item("W-validation", kind=WorkItemKind.VALIDATION, state=WorkItemState.DONE))
    seen = []

    def run(**kwargs):
        seen.append(kwargs["task"])
        return agents.AgentOutcome(
            run=AgentRun(
                run_id="discovery:scope-a:r1",
                agent="discovery",
                scope_id="scope-a",
                stop_reason="finished",
            ),
            parsed=[],
        )

    monkeypatch.setattr(co, "_agent", run)
    co._discover(["scope-a"], round_index=1)
    assert len(seen) == 1
    assert co.tasks.get("W-scope-a").state is WorkItemState.DONE
    assert co.tasks.get("W-validation").state is WorkItemState.DONE
    assert co.tasks.get("W-validation").closed_at is None, (
        "rediscovery must not close a validation item"
    )
