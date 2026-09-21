"""Gap routing, shared budgets and evidence revision regression tests, no model services."""
import json
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

import pytest

from aegis_contracts.harness import (
    AttackPath,
    Candidate,
    CandidateVerdict,
    EvidenceKind,
    VerdictKind,
    WorkItem,
    WorkItemKind,
    WorkItemState,
)
from services.harness import agents
from services.harness import blackboard as bb
from services.harness.budget import BudgetClient, BudgetStop, RunBudget
from services.harness.coordinator import HarnessConfig, HarnessCoordinator


def make(tmp_path, **config):
    (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
    co = HarnessCoordinator(workspace=tmp_path, config=HarnessConfig(**config))
    co.tasks.add(WorkItem(work_id="W-a", scope_id="a", title="download authorization", rationale="private object", files=["a.py"]))
    co._planned_scopes = ["a"]
    co._scope_files["a"] = ["a.py"]
    co._current.agent, co._current.work_id = agents.DISCOVERY, "W-a"
    return co


def record(co, record_kind, **data):
    return co._record(dict(kind=record_kind, text=json.dumps(data), scope="forged"))


def gap(co, kind="basic_check", **data):
    return record(co, "gap", kind=kind, question="Check owner before opening", file="a.py", line=1, **data)


def fact(co):
    assert record(co, "evidence", file="a.py", line=1, text="Owner guard precedes open", category="source_fact")["recorded"]
    return co.blackboard.investigation_records[-1].record_id


def test_gap_is_persistent_idempotent_and_requires_evidence(tmp_path):
    co = make(tmp_path)
    assert gap(co)["recorded"]
    assert gap(co)["recorded"]
    work = co.tasks.get("W-a")
    assert len(work.gaps) == 1
    assert json.loads((co.run_dir / "blackboard.json").read_text(encoding="utf-8"))["work"][0]["gaps"]
    assert not record(co, "gap", gap_id=work.gaps[0].gap_id, state="resolved", evidence_refs=[])["recorded"]
    assert record(co, "gap", gap_id=work.gaps[0].gap_id, state="resolved", evidence_refs=[fact(co)])["recorded"]
    assert work.gaps[0].state == "resolved"
    assert gap(co)["recorded"]
    assert work.gaps[0].state == "resolved"


def test_relationship_gap_can_only_be_resolved_by_assigned_investigator(tmp_path, monkeypatch):
    co = make(tmp_path)
    assert gap(co, "relationship")["recorded"]
    lead = co.blackboard.leads[0]
    monkeypatch.setattr(co, "_agent", lambda **kw: SimpleNamespace(parsed={"decisions": [dict(
        lead_id=lead.lead_id, action="create", reason="unknown cross-file control",
        title="download × ownership", files=["a.py"], completion_criteria="establish guard ordering")]}))
    co._plan_inbox(force=True)
    work = co.tasks.get(lead.linked_work_id)
    co._current.work_id = work.work_id
    assert co._board_view("all")["gaps"][0]["gap_id"] == co.tasks.get("W-a").gaps[0].gap_id
    gap_id = co.tasks.get("W-a").gaps[0].gap_id
    assert record(co, "gap", gap_id=gap_id, state="resolved", evidence_refs=[fact(co)])["recorded"]
    co.tasks.add(WorkItem(work_id="W-other", scope_id="other", title="other", rationale="other"))
    co._current.work_id = "W-other"
    assert not record(co, "gap", gap_id=gap_id, state="resolved", evidence_refs=[fact(co)])["recorded"]


@pytest.mark.parametrize("kind", ["basic_check", "unread", "tool_failure"])
def test_gap_no_progress_stops_original_task_with_breakpoint(tmp_path, monkeypatch, kind):
    co = make(tmp_path, max_gap_continuations=4)
    gap(co, kind)
    calls = []
    monkeypatch.setattr(co, "_discover", lambda scopes, **kw: calls.append(scopes))
    monkeypatch.setattr(co, "_validation", lambda: None)
    co._continue_gaps()
    assert calls == [["a"]]
    assert co.tasks.get("W-a").gaps[0].state == "blocked"
    assert co.tasks.get("W-a").gap_continuations == 1


def test_only_changed_evidence_invalidates_claim_decisions(tmp_path):
    co = make(tmp_path)
    candidate = Candidate(candidate_id="C", scope_id="a", title="query", file="a.py", line=1,
                          vulnerability_type="injection", rationale="entry", entry_points=["GET /private"])
    co._record_candidates([candidate])
    co._apply_verdict([candidate], CandidateVerdict(candidate_id="C", verdict=VerdictKind.CONFIRMED,
                      evidence_kind=EvidenceKind.SEMANTIC, reasons=["trace"], confidence=0.9))
    co._attack_path_one([candidate], AttackPath(candidate_id="C", reachable=True))
    co._record_candidates([candidate.model_copy(update={"title": "renamed", "rationale": "reworded"})])
    assert bb.find_verdict(co.blackboard, "C") is not None
    co._record_candidates([candidate.model_copy(update={"entry_points": ["GET /public"]})])
    assert candidate.evidence_version == 2
    assert bb.find_verdict(co.blackboard, "C") is None
    assert bb.find_attack_path(co.blackboard, "C") is None
    assert len(co.blackboard.verdict_history) == len(co.blackboard.attack_path_history) == 1
    assert co.tasks.get(co._claim_work([candidate], WorkItemKind.VALIDATION)).state is WorkItemState.PLANNED
    co._record_candidates([candidate.model_copy(update={"entry_points": ["GET /public"]})])
    assert candidate.evidence_version == 2
    co._apply_verdict([candidate], CandidateVerdict(candidate_id="C", verdict=VerdictKind.REJECTED,
                      evidence_kind=EvidenceKind.SEMANTIC))
    assert co.tasks.get(co._claim_work([candidate], WorkItemKind.ATTACK_PATH)).state is WorkItemState.CANCELED


def test_claim_retry_budget_survives_repeated_sweeps(tmp_path, monkeypatch):
    co = make(tmp_path, max_claim_attempts=2)
    candidate = Candidate(candidate_id="C", scope_id="a", title="query", file="a.py", line=1,
                          vulnerability_type="authorization", rationale="entry")
    co._record_candidates([candidate])
    def failed(**kw):
        co.tasks.start(kw["work_ids"], kw["agent"], "failed")
        co.tasks.end(kw["work_ids"], stop_reason="error", steps=1, error="missing tool")
        return SimpleNamespace(parsed=None, error="missing tool")
    monkeypatch.setattr(co, "_agent", failed)
    for _ in range(5):
        co._validation()
    task = co.tasks.get(co._claim_work([candidate], WorkItemKind.VALIDATION))
    assert len(task.attempts) == 2
    assert task.state is WorkItemState.BLOCKED


def test_parallel_calls_reserve_hard_limit_and_count_failed_attempts():
    budget = RunBudget(HarnessConfig(max_model_calls=3))
    provider = SimpleNamespace(complete=lambda *a: SimpleNamespace(usage=None))
    client = BudgetClient(provider, budget, lambda stage: None)
    def call(_):
        try:
            client.complete("system", "user")
            return 1
        except BudgetStop:
            return 0
    with ThreadPoolExecutor(max_workers=8) as pool:
        assert sum(pool.map(call, range(20))) == 3
    assert budget.snapshot()["unknown_usage"] == 3


def test_time_tokens_and_cost_limits():
    now = [0]
    timed = RunBudget(HarnessConfig(max_run_seconds=5), clock=lambda: now[0])
    now[0] = 5
    with pytest.raises(BudgetStop, match="时间"):
        timed.reserve()
    budget = RunBudget(HarnessConfig(max_model_tokens=10))
    budget.reserve()
    budget.account(SimpleNamespace(usage=dict(prompt_tokens=8, completion_tokens=2)))
    with pytest.raises(BudgetStop, match="token"):
        budget.reserve()
    cost = RunBudget(HarnessConfig(max_cost_usd=0.01, input_usd_per_million=10, output_usd_per_million=20))
    cost.reserve()
    cost.account(SimpleNamespace(usage=dict(prompt_tokens=1000, completion_tokens=10)))
    with pytest.raises(BudgetStop, match="费用"):
        cost.reserve()
    missing = RunBudget(HarnessConfig(max_model_tokens=10))
    missing.account(SimpleNamespace(usage=None))
    with pytest.raises(BudgetStop, match="用量"):
        missing.reserve()


def test_budget_stop_is_saved_as_incomplete_not_canceled(tmp_path, monkeypatch):
    co = make(tmp_path, max_model_calls=1)
    co.client = object()
    monkeypatch.setattr(co, "_prepare", lambda: None)
    def exhaust():
        co.budget.reserve()
        co.budget.reserve()
    monkeypatch.setattr(co, "_recon_and_threat_model", exhaust)
    result = co.run()
    board = result.blackboard
    assert board.closed and "调用预算耗尽" in board.closure_note
    assert all(w.state is WorkItemState.BLOCKED for w in board.work)
    assert board.execution_budget["model_calls"] == 1
    saved = json.loads((co.run_dir / "blackboard.json").read_text(encoding="utf-8"))
    assert saved["work"] and saved["execution_budget"]["stop_reason"]


def test_attack_path_failure_retries_only_path_to_limit(tmp_path, monkeypatch):
    co = make(tmp_path, max_claim_attempts=2)
    candidate = Candidate(candidate_id="C", scope_id="a", file="a.py", line=1, title="x", rationale="entry", vulnerability_type="authorization")
    co._record_candidates([candidate])
    co._apply_verdict([candidate], CandidateVerdict(candidate_id="C", verdict=VerdictKind.CONFIRMED,
                      evidence_kind=EvidenceKind.SEMANTIC))
    calls = []
    def fail(**kw):
        calls.append(kw["agent"])
        co.tasks.start(kw["work_ids"], kw["agent"], "path")
        co.tasks.end(kw["work_ids"], stop_reason="error", steps=1)
        return SimpleNamespace(parsed=None, error="unavailable")
    monkeypatch.setattr(co, "_agent", fail)
    co._complete_attack_paths()
    co._complete_attack_paths()
    assert calls == [agents.ATTACK_PATH, agents.ATTACK_PATH]
    assert bb.find_verdict(co.blackboard, "C") is not None


def test_planner_merges_only_identical_unstarted_investigations(tmp_path, monkeypatch):
    co = make(tmp_path, planner_min_interval=0)
    source = co.tasks.get("W-a").model_copy(deep=True, update={"work_id": "W-b", "scope_id": "b"})
    co.tasks.add(source)
    co._planned_scopes.append("b")
    record(co, "lead", question="Duplicate ownership check", to_scope="a", file="a.py", line=1)
    lead = co.blackboard.leads[-1]
    monkeypatch.setattr(co, "_agent", lambda **kw: SimpleNamespace(parsed={"decisions": [dict(
        lead_id=lead.lead_id, action="merge", source_work_id="W-b", work_id="W-a", reason="identical question and files")]}))
    co._plan_inbox(idle=True)
    assert source.state is WorkItemState.CANCELED and source.merged_into == "W-a"
    assert "b" not in co._planned_scopes and lead.linked_work_id == "W-a"


def test_planner_cannot_merge_file_review_and_keeps_pending_event(tmp_path, monkeypatch):
    co = make(tmp_path)
    source = co.tasks.get("W-a").model_copy(deep=True, update={"work_id": "W-b", "scope_id": "b", "kind": WorkItemKind.FILE_REVIEW})
    co.tasks.add(source)
    record(co, "lead", question="Ownership check", to_scope="a", file="a.py", line=1)
    lead = co.blackboard.leads[-1]
    monkeypatch.setattr(co, "_agent", lambda **kw: SimpleNamespace(parsed={"decisions": [dict(
        lead_id=lead.lead_id, action="merge", source_work_id="W-b", work_id="W-a", reason="duplicate")]}))
    co._plan_inbox(force=True)
    assert lead.status == "pending" and source.state is WorkItemState.PLANNED


def test_new_linked_source_fact_invalidates_existing_verdict(tmp_path):
    co = make(tmp_path)
    candidate = Candidate(candidate_id="C", scope_id="a", file="a.py", line=1, title="x", rationale="entry", vulnerability_type="authorization")
    co._record_candidates([candidate])
    co._apply_verdict([candidate], CandidateVerdict(candidate_id="C", verdict=VerdictKind.REJECTED, evidence_kind=EvidenceKind.SEMANTIC))
    payload = dict(file="a.py", line=1, category="source_fact", text="An unguarded caller", candidate_id="C")
    assert record(co, "evidence", **payload)["recorded"]
    assert bb.find_verdict(co.blackboard, "C") is None and candidate.evidence_version == 2
    assert record(co, "evidence", **payload)["recorded"]
    assert candidate.evidence_version == 2


def test_missing_ranges_union_overlap_and_keep_unknown_eof():
    from services.harness.coverage import FileCoverage, unread_ranges
    covered = {"a.py": FileCoverage(path="a.py", total_lines=10, reads=3, windows=[(1, 4), (3, 6), (8, 10)])}
    assert unread_ranges(["a.py", "b.py"], covered) == {"a.py": [(6, 7), (10, 10)], "b.py": [(1, None)]}


def test_agent_result_from_older_evidence_is_not_applied(tmp_path, monkeypatch):
    from aegis_contracts.harness import AgentRun
    co = make(tmp_path)
    candidate = Candidate(candidate_id="C", scope_id="a", file="a.py", line=1, title="x", rationale="entry", vulnerability_type="authorization")
    co._record_candidates([candidate])
    work_id = co._claim_work([candidate], WorkItemKind.VALIDATION)
    def changed(**kw):
        co._record_candidates([candidate.model_copy(update={"entry_points": ["GET /new"]})])
        return agents.AgentOutcome(run=AgentRun(run_id="validation:C", agent=agents.VALIDATION,
                                   scope_id="C", stop_reason="finished"),
                                   parsed=CandidateVerdict(candidate_id="C", verdict=VerdictKind.CONFIRMED, evidence_kind=EvidenceKind.SEMANTIC))
    monkeypatch.setattr(agents, "run", changed)
    outcome = co._agent(agent=agents.VALIDATION, scope_id="C", work_ids=[work_id], run_id="validation:C")
    assert outcome.parsed is None and "版本变化" in outcome.error
    assert co.tasks.get(work_id).state is WorkItemState.BLOCKED


def test_failed_provider_attempt_spends_budget():
    def fail(*args):
        raise RuntimeError("gateway failure")
    budget = RunBudget(HarnessConfig(max_model_calls=1))
    client = BudgetClient(SimpleNamespace(complete=fail), budget, lambda stage: None)
    with pytest.raises(RuntimeError):
        client.complete("s", "u")
    with pytest.raises(BudgetStop):
        client.complete("s", "u")
    assert budget.calls == 1


def test_idle_planner_priority_is_applied_and_budget_is_in_input(tmp_path, monkeypatch):
    co = make(tmp_path)
    record(co, "lead", question="Check ownership", to_scope="a", file="a.py", line=1)
    lead = co.blackboard.leads[-1]
    def planner(**kw):
        assert json.loads(kw["task"])["budget"]["max_model_calls"] == 512
        return SimpleNamespace(parsed={"decisions": [dict(lead_id=lead.lead_id, action="priority",
                                                          work_id="W-a", priority=1, reason="external entry")]})
    monkeypatch.setattr(co, "_agent", planner)
    co._plan_inbox(idle=True)
    assert co.tasks.get("W-a").priority == 1 and lead.status == "linked"


def test_reworded_title_with_same_handled_question_does_not_reopen(tmp_path, monkeypatch):
    co = make(tmp_path, planner_min_interval=0)
    record(co, "lead", question="Check ownership", to_scope="a", file="a.py", line=1)
    previous = co.blackboard.leads[-1]
    previous.status, previous.linked_work_id = "handled", "W-a"
    co.tasks.get("W-a").state = WorkItemState.DONE
    co.tasks.add(WorkItem(work_id="W-b", scope_id="b", title="another source", rationale="entry"))
    co._current.work_id = "W-b"
    record(co, "lead", question="Check ownership", title="changed title", to_scope="a", file="a.py", line=1)
    lead = co.blackboard.leads[-1]
    monkeypatch.setattr(co, "_agent", lambda **kw: SimpleNamespace(parsed={"decisions": [dict(
        lead_id=lead.lead_id, action="link", work_id="W-a", reason="same question")]}))
    co._plan_inbox(force=True)
    assert lead.status == "dismissed"
    assert co.tasks.get("W-a").state is WorkItemState.DONE
