"""Concrete initial plans and validation-only closure gaps, without model calls."""
from types import SimpleNamespace

import pytest

from aegis_contracts.harness import (
    Candidate,
    CandidateVerdict,
    CoverageState,
    EvidenceKind,
    VerdictKind,
    WorkItem,
    WorkItemKind,
    WorkItemState,
)
from services.harness import agents, coverage
from services.harness import blackboard as bb
from services.harness.coordinator import HarnessConfig, HarnessCoordinator


def topic(**changes):
    return dict(scope_id="download-authz", title="download × object authorization",
                question="Can another user download this object?", rationale="private assets",
                files=["a.py"], completion_criteria="Trace caller, ownership check and file read",
                priority=1, **changes)


@pytest.mark.parametrize("field,value", [
    ("question", ""), ("completion_criteria", None), ("files", []),
    ("files", "a.py"), ("priority", True), ("priority", 4), ("title", " "),
])
def test_incomplete_topic_is_not_admitted(field, value):
    raw = topic()
    raw[field] = value
    assert agents._parse_plan({"scopes": [raw]})["scopes"] == []


def test_plan_keeps_fixed_files_and_only_valid_topics(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1\n")
    co = HarnessCoordinator(workspace=tmp_path, config=HarnessConfig(max_scopes_per_round=1))
    valid = topic()
    low = {**valid, "scope_id": "download-integrity", "priority": 3}
    reserved = {**valid, "scope_id": agents.coverage_scope_id(0), "files": ["a.py"]}
    missing = {**valid, "scope_id": "missing", "files": ["missing.py"]}
    monkeypatch.setattr(co, "_agent", lambda **kw: SimpleNamespace(
        parsed={"scopes": [low, reserved, missing, valid]}, error=None))
    co._plan()
    files = [w for w in co.blackboard.work if w.kind is WorkItemKind.FILE_REVIEW]
    topics = [w for w in co.blackboard.work if w.kind is WorkItemKind.INVESTIGATION]
    assert len(files) == 1 and files[0].files == coverage.inventory(tmp_path)
    assert [w.scope_id for w in topics] == [valid["scope_id"], low["scope_id"]]
    assert topics[0].completion_criteria == valid["completion_criteria"]
    prompt = agents.discovery_task(co.blackboard, topics[0])
    assert valid["question"] in prompt and valid["completion_criteria"] in prompt
    assert co._scope_files[files[0].scope_id] == ["a.py"]


def test_failed_planner_does_not_add_directory_investigations(tmp_path, monkeypatch):
    (tmp_path / "a.py").write_text("x = 1\n")
    co = HarnessCoordinator(workspace=tmp_path)
    monkeypatch.setattr(co, "_agent", lambda **kw: SimpleNamespace(parsed=None, error="unavailable"))
    co._plan()
    assert co.blackboard.work
    assert all(w.kind is WorkItemKind.FILE_REVIEW for w in co.blackboard.work)
    assert any("规划失败" in note for note in co.dataflow_notes)


@pytest.mark.parametrize("eventual_verdict", [False, True])
def test_validation_failure_does_not_repeat_discovery(tmp_path, monkeypatch, eventual_verdict):
    co = HarnessCoordinator(workspace=tmp_path, config=HarnessConfig(max_rounds=4))
    co.tasks.add(WorkItem(work_id="W-a", scope_id="a", title="query integrity", rationale="entry"))
    co._planned_scopes = ["a"]
    candidate = Candidate(candidate_id="C-a", scope_id="a", file="a.py", line=1,
                          title="query", vulnerability_type="injection", rationale="input reaches query")
    bb.add_candidate(co.blackboard, candidate)
    calls = []

    def discover(scopes, **kw):
        calls.append("discovery")
        co.tasks.start(["W-a"], agents.DISCOVERY, "discovery-1")
        co.tasks.end(["W-a"], stop_reason="finished", steps=1)
        co.tasks.update("W-a", state=WorkItemState.DONE)
        return {}

    def validate():
        calls.append("validation")
        if eventual_verdict and calls.count("validation") == 2:
            bb.add_verdict(co.blackboard, CandidateVerdict(
                candidate_id="C-a", verdict=VerdictKind.REJECTED,
                evidence_kind=EvidenceKind.SEMANTIC, reasons=["guard verified"], confidence=0.9))

    monkeypatch.setattr(co, "_discover", discover)
    monkeypatch.setattr(co, "_validation", validate)
    co._discovery_and_closure()
    assert calls == ["discovery", "validation", "validation"]
    expected = CoverageState.SUFFICIENT if eventual_verdict else CoverageState.INSUFFICIENT
    assert bb.coverage_of(co.blackboard, "a").state is expected
    assert len(co.tasks.get("W-a").attempts) == 1
