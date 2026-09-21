"""Incremental discovery and bounded inbox planning, without paid model calls."""
import json
import threading
from datetime import timedelta
from types import SimpleNamespace

from aegis_contracts.harness import AgentRun, WorkItem, WorkItemState
from services.harness import agents
from services.harness import blackboard as bb
from services.harness.coordinator import HarnessConfig, HarnessCoordinator
from services.harness.trail import CallbackSink, Trail


def coordinator(tmp_path):
    (tmp_path / "a.py").write_text("value = 1\n", encoding="utf-8")
    events = []
    co = HarnessCoordinator(workspace=tmp_path, config=HarnessConfig(planner_min_interval=0),
                            trail=Trail([CallbackSink(events.append)]))
    co.tasks.add(WorkItem(work_id="W-a", scope_id="a", title="download × authorization",
                          rationale="entry", files=["a.py"]))
    co._scope_files["a"] = ["a.py"]
    co._planned_scopes = ["a"]
    co._current.agent = agents.DISCOVERY
    co._current.work_id = "W-a"
    return co, events


def record(co, kind, **payload):
    return co._record({"kind": kind, "scope": "forged", "text": json.dumps(payload)})


def lead(co, question="object authorization"):
    assert record(co, "lead", to_scope="a", question=question, file="a.py", line=1)["recorded"]
    return co.blackboard.leads[-1]


def outcome(decisions):
    return SimpleNamespace(parsed={"decisions": decisions})


def test_live_publications_persist_and_candidate_final_is_idempotent(tmp_path):
    co, events = coordinator(tmp_path)
    assert record(co, "evidence", file="a.py", line=1, text="value assignment", category="source_fact")["recorded"]
    assert not record(co, "evidence", file="a.py", line=1, text="safe", category="validated")["recorded"]
    payload = dict(file="a.py", line=1, title="authorization", vulnerability_type="idor")
    assert record(co, "candidate", **payload)["recorded"]
    co._record_candidates(agents._parse_candidates({"candidates": [payload]}, scope_id="a"))
    assert len(co.blackboard.candidates) == 1
    assert len([w for w in co.blackboard.work if w.kind.value == "validation"]) == 1
    assert co.blackboard.candidates[0].scope_id == "a"
    saved = json.loads((co.run_dir / "blackboard.json").read_text(encoding="utf-8"))
    assert saved["investigation_records"][0]["category"] == "source_fact"
    assert any(e["kind"] == "record" for e in events)


def test_distinct_questions_and_exact_duplicate(tmp_path):
    co, _ = coordinator(tmp_path)
    first = lead(co)
    lead(co)
    second = lead(co, "path traversal")
    assert len(co.blackboard.leads) == 2
    assert first.lead_id != second.lead_id
    assert first.source_work_id == "W-a"
    assert [entry.sequence for entry in co.blackboard.leads] == [1, 2]


def test_planner_snapshot_does_not_swallow_new_event(tmp_path, monkeypatch):
    co, _ = coordinator(tmp_path)
    first = lead(co)
    def plan(**kwargs):
        lead(co, "new issue during planner")
        return outcome([dict(lead_id=first.lead_id, action="link", work_id="W-a", reason="same question")])
    monkeypatch.setattr(co, "_agent", plan)
    co.tasks.update("W-a", state=WorkItemState.DONE)
    co._plan_inbox(force=True)
    assert first.status == "linked"
    assert co.blackboard.leads[1].status == "pending"
    assert co.tasks.get("W-a").state is WorkItemState.PLANNED
    assert co.tasks.get("W-a").pending_updates == [first.lead_id]


def test_invalid_planner_batch_keeps_every_lead(tmp_path, monkeypatch):
    co, _ = coordinator(tmp_path)
    first = lead(co)
    monkeypatch.setattr(co, "_agent", lambda **kw: outcome([
        dict(lead_id=first.lead_id, action="dismiss", reason="not relevant"),
        dict(lead_id="unknown", action="dismiss", reason="invalid"),
    ]))
    co._plan_inbox(force=True)
    assert first.status == "pending"
    assert co.tasks.get("W-a") is not None


def test_planner_failure_and_call_budget_preserve_inbox(tmp_path, monkeypatch):
    co, _ = coordinator(tmp_path)
    first = lead(co)
    def fail(**kwargs):
        raise ValueError("bad response")
    monkeypatch.setattr(co, "_agent", fail)
    for _ in range(10):
        co._plan_inbox(force=True)
    assert co._planner_calls == co.config.planner_calls
    assert first.status == "pending"


def test_single_planner_and_oldest_event_clock(tmp_path, monkeypatch):
    co, _ = coordinator(tmp_path)
    first = lead(co)
    first.raised_at -= timedelta(seconds=61)
    lead(co, "new event cannot reset clock")
    entered, release = threading.Event(), threading.Event()
    calls = []
    def plan(**kwargs):
        calls.append(kwargs)
        entered.set()
        assert release.wait(5)
        return outcome([])
    monkeypatch.setattr(co, "_agent", plan)
    worker = threading.Thread(target=co._plan_inbox)
    worker.start()
    assert entered.wait(5)
    co._plan_inbox(force=True)
    release.set()
    worker.join(5)
    assert not worker.is_alive()
    assert len(calls) == 1


def test_task_view_is_local_and_legacy_board_loads(tmp_path):
    co, _ = coordinator(tmp_path)
    co.tasks.add(WorkItem(work_id="W-b", scope_id="b", title="other", rationale="other"))
    record(co, "evidence", file="a.py", line=1, text="local fact")
    co._current.work_id = "W-b"
    assert co._board_view("summary")["records"] == []
    legacy = co.blackboard.model_dump()
    legacy.pop("investigation_records")
    assert type(co.blackboard).model_validate(legacy).investigation_records == []
    assert bb.new_blackboard("legacy", tmp_path).leads == []


def test_finished_agent_with_unread_update_is_continued_once_then_blocked(tmp_path, monkeypatch):
    co, _ = coordinator(tmp_path)
    pending = lead(co)
    co.config.material_budget = 0
    co.config.planner_calls = 0
    pending.status = "linked"
    pending.linked_work_id = "W-a"
    co.tasks.update("W-a", state=WorkItemState.DONE, pending_updates=[pending.lead_id])
    def run(**kw):
        return agents.AgentOutcome(run=AgentRun(run_id=kw["run_id"], agent=kw["agent"],
            scope_id=kw["scope_id"], stop_reason="finished"), parsed=[])
    monkeypatch.setattr(agents, "run", run)
    monkeypatch.setattr(co, "_validation", lambda: None)
    co._follow_leads()
    work = co.tasks.get("W-a")
    assert len(work.attempts) == 1
    assert work.state is WorkItemState.BLOCKED
    assert work.pending_updates == [pending.lead_id]


def test_board_ack_only_consumes_successful_nontruncated_read(tmp_path, monkeypatch):
    from aegis_contracts.harness import AgentStep, ToolCall, ToolName, ToolResult
    co, _ = coordinator(tmp_path)
    pending = lead(co)
    co.config.material_budget = 0
    co.config.planner_calls = 0
    pending.status = "linked"
    pending.linked_work_id = "W-a"
    co.tasks.update("W-a", pending_updates=[pending.lead_id])
    def run(**kw):
        run = AgentRun(run_id=kw["run_id"], agent=kw["agent"], scope_id=kw["scope_id"], stop_reason="finished")
        view = co._board_view("summary")
        assert view["updates"][0]["lead_id"] == pending.lead_id
        kw["on_step"](run, AgentStep(index=1, call=ToolCall(tool=ToolName.BOARD, arguments={}),
            result=ToolResult(tool=ToolName.BOARD, ok=True, summary="update")))
        return agents.AgentOutcome(run=run, parsed=[])
    monkeypatch.setattr(agents, "run", run)
    co._discover(["a"], round_index=0)
    assert co.tasks.get("W-a").pending_updates == []
    assert pending.status == "handled"


def test_partial_plan_acknowledges_only_returned_leads(tmp_path, monkeypatch):
    co, _ = coordinator(tmp_path)
    first = lead(co)
    second = lead(co, "second question")
    monkeypatch.setattr(co, "_agent", lambda **kw: outcome([
        dict(lead_id=first.lead_id, action="defer", reason="missing artifact"),
    ]))
    co._plan_inbox(force=True)
    assert first.status == "deferred"
    assert second.status == "pending"


def test_more_than_batch_limit_remain_in_ledger(tmp_path, monkeypatch):
    co, _ = coordinator(tmp_path)
    co.config.max_scopes_per_round = 2
    proposed = [WorkItem(work_id=f"W-{i}", scope_id=f"scope-{i}", title=f"topic {i}", rationale="known entry") for i in range(15)]
    monkeypatch.setattr(co, "_surveyed_scopes", lambda: [])
    monkeypatch.setattr(co, "_planner_call", lambda scopes: proposed)
    co._plan()
    assert all(co.tasks.get(item.work_id) is not None for item in proposed)
    assert any(item.kind.value == "file_review" for item in co.blackboard.work)


def test_publication_is_visible_before_agent_returns(tmp_path, monkeypatch):
    co, events = coordinator(tmp_path)
    entered, release = threading.Event(), threading.Event()
    def run(**kw):
        lead(co)
        entered.set()
        assert release.wait(5)
        return agents.AgentOutcome(run=AgentRun(run_id=kw["run_id"], agent=kw["agent"],
            scope_id=kw["scope_id"], stop_reason="finished"), parsed=[])
    monkeypatch.setattr(agents, "run", run)
    worker = threading.Thread(target=lambda: co._agent(agent=agents.DISCOVERY, scope_id="a", run_id="live",
        task="inspect", context=co.context, client=None, max_steps=2))
    worker.start()
    try:
        assert entered.wait(5)
        assert co.blackboard.leads[0].status == "pending"
        assert co.tasks.get("W-a").state is WorkItemState.RUNNING
        assert any(event.get("lead", {}).get("status") == "pending" for event in events)
        assert (co.run_dir / "blackboard.json").exists()
    finally:
        release.set()
        worker.join(5)
    assert not worker.is_alive()
