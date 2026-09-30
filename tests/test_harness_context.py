"""Deterministic context compaction; no model request or synthetic coverage credit.

Batch 3 of HARNESS_RUNTIME_TODO: when a transcript exceeds the configured input budget, the older
observations are folded into a traceable summary (file windows, match counts, failures -- figures
the tools produced), `record` steps and the newest steps stay verbatim, and the original
`AgentRun.steps` are never touched. The raw steps are also archived per run, apart from the trail.
"""

import json
import threading
from types import SimpleNamespace

import pytest

from aegis_contracts.harness import (
    AgentRun,
    AgentStep,
    Candidate,
    ToolCall,
    ToolName,
    ToolResult,
    WorkGap,
    WorkItem,
)
from services.ai.client import ChatResult
from services.harness import blackboard as bb
from services.harness import evidence
from services.harness.agents import SCOPE_REUSE_THOUGHT, discovery_task
from services.harness.budget import AgentBudget, AgentBudgetStop, BudgetClient, RunBudget
from services.harness.context import summarize_steps
from services.harness.coordinator import HarnessConfig, HarnessCoordinator
from services.harness.react import (
    ContextBudgetExceeded,
    _native_context_messages,
    render_user_message,
    run_agent,
)
from services.harness.trail import JsonlSink, Trail, read_events


def _read_step(index: int, path: str, *, offset: int = 1, returned: int = 100, total: int = 100,
               thought: str = "inspect") -> AgentStep:
    return AgentStep(
        index=index,
        thought=thought,
        call=ToolCall(tool=ToolName.READ, arguments={"path": path, "offset": offset}, reason=""),
        result=ToolResult(
            tool=ToolName.READ, ok=True,
            summary=f"{path} lines {offset}-{offset + returned - 1}\n" + "x" * 4000,
            data={"path": path, "offset": offset, "returned_lines": returned, "total_lines": total,
                  "next_offset": offset + returned if offset + returned - 1 < total else None},
            truncated=offset + returned - 1 < total,
        ),
    )


def _grep_step(index: int) -> AgentStep:
    return AgentStep(
        index=index, thought="search",
        call=ToolCall(tool=ToolName.GREP, arguments={"pattern": "@PreAuthorize", "path": "src"}, reason=""),
        result=ToolResult(
            tool=ToolName.GREP, ok=True, summary="3 hits\n" + "y" * 3000,
            data={"pattern": "@PreAuthorize", "path": "src", "total_matched": 3, "count": 3,
                  "matches": [{"path": "src/A.java", "line": 10, "text": "..."},
                              {"path": "src/B.java", "line": 20, "text": "..."},
                              {"path": "src/A.java", "line": 30, "text": "..."}]},
        ),
    )


def _record_step(index: int) -> AgentStep:
    return AgentStep(
        index=index, thought="note it",
        call=ToolCall(tool=ToolName.RECORD, arguments={"kind": "note", "text": "FACT: admin route lacks auth"}, reason=""),
        result=ToolResult(tool=ToolName.RECORD, ok=True, summary="recorded note", data={"kind": "note"}),
    )


def _failed_step(index: int) -> AgentStep:
    return AgentStep(
        index=index, thought="try",
        call=ToolCall(tool=ToolName.READ, arguments={"path": "missing.java"}, reason=""),
        result=ToolResult(tool=ToolName.READ, ok=False, summary="", error="文件不存在：missing.java"),
    )


# ── the summary itself ──────────────────────────────────────────────────────


def test_summary_groups_reads_by_file_and_merges_windows():
    steps = [_read_step(1, "src/A.java", offset=1, returned=100, total=250),
             _read_step(2, "src/A.java", offset=101, returned=150, total=250),
             _read_step(3, "src/B.java", offset=1, returned=40, total=90)]
    summary = summarize_steps(steps)
    text = summary.render()
    assert "src/A.java: lines 1-250/250 (complete" in text
    assert "src/B.java: lines 1-40/90 (partial" in text
    assert "refs turn 1, turn 2" in text
    assert "x" * 100 not in text  # no source body leaks into the summary
    event = summary.as_event()
    files = {entry["path"]: entry for entry in event["summary_files"]}
    assert files["src/A.java"]["complete"] is True
    assert files["src/B.java"]["complete"] is False
    assert event["summary_refs"] == ["turn 1", "turn 2", "turn 3"]


def test_summary_separates_reused_reads_from_this_runs_reads():
    reused = _read_step(0, "src/Shared.java", thought=SCOPE_REUSE_THOUGHT)
    own = _read_step(1, "src/Own.java")
    text = summarize_steps([reused, own]).render()
    reused_block = text.split("Files seeded from earlier complete reads")[1]
    assert "src/Shared.java" in reused_block and "reused from blackboard" in reused_block
    own_block = text.split("Files read by this run:")[1].split("Files seeded")[0]
    assert "src/Own.java" in own_block and "read by this run" in own_block


def test_summary_keeps_reused_and_new_windows_separate_for_same_file():
    reused = _read_step(0, "src/Shared.java", offset=1, returned=50, total=100,
                        thought=SCOPE_REUSE_THOUGHT)
    own = _read_step(1, "src/Shared.java", offset=51, returned=50, total=100)
    event = summarize_steps([reused, own]).as_event()
    files = event["summary_files"]
    assert len(files) == 2
    assert [(entry["reused"], entry["windows"], entry["complete"]) for entry in files] == [
        (True, [(1, 50)], False), (False, [(51, 100)], False),
    ]


def test_summary_reports_grep_counts_and_failures_without_bodies():
    text = summarize_steps([_grep_step(1), _failed_step(2)]).render()
    assert "grep '@PreAuthorize' under src → 3 match(es) in 2 file(s): src/A.java, src/B.java" in text
    assert "first locations src/A.java:10, src/B.java:20, src/A.java:30" in text
    assert "y" * 50 not in text
    assert "Failed calls" in text and "missing.java" in text and "文件不存在" in text


# ── text protocol ───────────────────────────────────────────────────────────


def test_text_context_compacts_old_observations_without_changing_evidence():
    steps = [_read_step(i, f"src/{i}.java") for i in range(1, 5)]
    events = []
    prompt = render_user_message("find missing auth", steps, system="policy",
                                 max_input_tokens=5000, on_context=events.append)
    assert "CONTEXT COMPACTED" in prompt
    assert "EARLIER OBSERVATIONS (SUMMARY)" in prompt
    assert "src/1.java: lines 1-100/100 (complete; read by this run; refs turn 1)" in prompt
    assert "src/2.java" in prompt
    # The two newest steps are verbatim; the older bodies are gone from the request only.
    recent = prompt.split("RECENT TRANSCRIPT")[1]
    assert "src/3.java" in recent and "src/4.java" in recent and "x" * 4000 in recent
    assert "x" * 4000 not in prompt.split("RECENT TRANSCRIPT")[0]
    assert "x" * 4000 in steps[0].result.summary  # Evidence remains intact in AgentRun.
    assert "UTF-8 bytes / 2" in prompt
    assert events[0]["state"] == "compacted"
    assert events[0]["archived_steps"] == [1, 2]
    assert events[0]["before_tokens"] > events[0]["after_tokens"]
    assert [f["path"] for f in events[0]["summary_files"]] == ["src/1.java", "src/2.java"]


def test_text_context_keeps_recorded_facts_verbatim_and_out_of_the_summary():
    steps = [_read_step(1, "src/1.java"), _record_step(2), _read_step(3, "src/3.java"),
             _read_step(4, "src/4.java"), _read_step(5, "src/5.java")]
    events = []
    prompt = render_user_message("t", steps, system="p", max_input_tokens=6000, on_context=events.append)
    assert "RECORDED FACTS (kept verbatim)" in prompt
    assert "FACT: admin route lacks auth" in prompt
    assert events[0]["archived_steps"] == [1, 3]  # the record step is neither archived nor summarised
    assert "turn 2" not in events[0]["summary_refs"]


def test_discovery_gaps_and_candidate_entry_links_survive_text_compaction(tmp_path):
    board = bb.new_blackboard("run", tmp_path)
    board.candidates.append(Candidate(
        candidate_id="C-1", scope_id="scope-x", title="unsafe fetch",
        vulnerability_type="ssrf", file="src/Fetch.java", line=42,
        entry_points=["GET /fetch", "POST /admin/fetch"],
    ))
    item = WorkItem(
        work_id="W-1", scope_id="scope-x", title="fetch", rationale="external input",
        question="Can the route reach the fetch sink?", completion_criteria="Trace both entries",
        gaps=[WorkGap(gap_id="G-1", kind="relationship", question="Check controller to service",
                      file="src/Fetch.java", line=42)],
    )
    task = discovery_task(board, item)
    prompt = render_user_message(
        task, [_read_step(i, f"src/{i}.java") for i in range(1, 5)],
        system="policy", max_input_tokens=7000,
    )
    assert "CONTEXT COMPACTED" in prompt
    for text in ("Check controller to service", "Trace both entries", "C-1", "ssrf",
                 "GET /fetch", "POST /admin/fetch"):
        assert text in prompt


def test_text_context_refuses_to_drop_task_or_recent_evidence():
    events = []
    with pytest.raises(ContextBudgetExceeded, match="input context exceeds"):
        render_user_message("task" * 1000, [_read_step(1, "a.java")],
                            max_input_tokens=100, on_context=events.append)
    assert events[0]["state"] == "rejected"


def test_text_context_stays_bounded_over_a_long_tool_sequence():
    """Acceptance: forty reads of 4 KB each; the request must not grow with the transcript."""
    budget = 9000
    sizes = []
    steps: list[AgentStep] = []
    for index in range(1, 41):
        steps.append(_read_step(index, f"src/F{index}.java"))
        prompt = render_user_message("t", steps, system="p", max_input_tokens=budget)
        sizes.append(len(prompt.encode("utf-8")))
    # Once compaction kicks in, growth is one summary line (~100 bytes) per extra file, never a body.
    assert max(sizes) <= budget * 2
    assert sizes[-1] - sizes[20] < 40 * 200
    assert all(step.result is not None and "x" * 4000 in step.result.summary for step in steps)


# ── native protocol ─────────────────────────────────────────────────────────


def _native_transcript(count: int):
    messages = [{"role": "system", "content": "policy"}, {"role": "user", "content": "task"}]
    steps = {}
    for index in range(1, count + 1):
        call_id = f"c{index}"
        messages.append({"role": "assistant", "content": None, "tool_calls": [{
            "id": call_id, "type": "function", "function": {
                "name": "read", "arguments": json.dumps({"path": f"src/{index}.java"})},
        }]})
        messages.append({"role": "tool", "tool_call_id": call_id,
                         "content": f"src/{index}.java lines 1-100\n" + "x" * 4000})
        steps[call_id] = _read_step(index, f"src/{index}.java")
    return messages, steps


def test_native_context_keeps_tool_call_ids_and_latest_replies():
    messages, steps = _native_transcript(4)
    events = []
    reduced = _native_context_messages(messages, [], 5000, events.append, steps_by_call_id=steps)
    replies = [message for message in reduced if message["role"] == "tool"]
    assert [message["tool_call_id"] for message in replies] == ["c1", "c2", "c3", "c4"]
    assert replies[0]["content"].startswith("[archived: read result for c1")
    assert "x" * 4000 in replies[-1]["content"]
    assert "x" * 4000 in messages[3]["content"]  # Original transcript is untouched.
    # The summary rides on the task message and names calls by id.
    assert "EARLIER OBSERVATIONS (SUMMARY)" in reduced[1]["content"]
    assert "src/1.java: lines 1-100/100 (complete; read by this run; refs c1)" in reduced[1]["content"]
    assert messages[1]["content"] == "task"  # the original user message is not mutated
    assert events[0]["archived_call_ids"] == ["c1", "c2"]
    assert events[0]["protocol"] == "native"
    assert events[0]["summary_refs"] == ["c1", "c2"]


def test_native_context_summarises_from_arguments_when_no_step_is_known():
    messages, _ = _native_transcript(3)
    reduced = _native_context_messages(messages, [], 5000, None)
    assert "src/1.java" in reduced[1]["content"]
    assert "[archived: read result for c1" in reduced[2 * 1 + 1]["content"]


def test_native_compaction_keeps_task_gaps_and_candidate_entries():
    messages, steps = _native_transcript(4)
    task = "Known gaps: trace controller to sink; candidate C-1 entries GET /fetch and POST /admin/fetch"
    messages[1]["content"] = task
    reduced = _native_context_messages(messages, [], 5000, steps_by_call_id=steps)
    assert "EARLIER OBSERVATIONS (SUMMARY)" in reduced[1]["content"]
    assert task in reduced[1]["content"]
    assert messages[1]["content"] == task


# ── persistence ─────────────────────────────────────────────────────────────


def test_context_compaction_event_survives_trail_reopen(tmp_path):
    path = tmp_path / "trail.jsonl"
    with JsonlSink(path, mode="w") as sink:
        trail = Trail([sink])
        render_user_message(
            "find missing auth",
            [_read_step(i, f"src/{i}.java") for i in range(1, 5)],
            system="policy",
            max_input_tokens=5000,
            on_context=lambda info: trail.emit(
                "context_compaction", agent="discovery", scope="scope-1", run_id="run-1", **info
            ),
        )
    events = read_events(path)["events"]
    assert len(events) == 1
    assert events[0]["kind"] == "context_compaction"
    assert events[0]["run_id"] == "run-1"
    assert events[0]["archived_steps"] == [1, 2]
    assert events[0]["summary_files"][0]["path"] == "src/1.java"
    assert "x" * 100 not in json.dumps(events[0])  # no source text in the trail


def test_step_archive_keeps_full_results_apart_from_the_trail(tmp_path):
    run = AgentRun(run_id="discovery:scope/1:attempt:2", agent="discovery", scope_id="scope/1")
    steps = [_read_step(1, "src/A.java"), _grep_step(2), _failed_step(3)]
    with evidence.StepArchive(tmp_path) as archive:
        for step in steps:
            run.steps.append(step)
            archive.record(run, step)
        assert archive.written == 3
    file = evidence.step_file(tmp_path, run.run_id)
    assert file.parent == tmp_path / "evidence"
    assert "/" not in file.name and ":" not in file.name
    back = evidence.read_run_steps(tmp_path, run.run_id)
    assert [s.index for s in back] == [1, 2, 3]
    assert back[0].result is not None and "x" * 4000 in back[0].result.summary  # unclipped
    assert back[1].result is not None and back[1].result.data["total_matched"] == 3
    assert back[2].result is not None and back[2].result.ok is False
    assert evidence.list_runs(tmp_path) == [run.run_id]
    # A summary built from the archive is the same summary the request carried.
    assert summarize_steps(back).render() == summarize_steps(steps).render()


def test_step_archive_write_failure_disables_that_run_but_not_others(tmp_path):
    archive = evidence.StepArchive(tmp_path)
    good = AgentRun(run_id="good", agent="a", scope_id="s")
    bad = AgentRun(run_id="bad", agent="a", scope_id="s")
    archive.record(good, _read_step(1, "a.java"))
    # Make the bad run's file path a directory so opening it fails.
    evidence.step_file(tmp_path, "bad").parent.mkdir(parents=True, exist_ok=True)
    evidence.step_file(tmp_path, "bad").mkdir()
    archive.record(bad, _read_step(1, "b.java"))
    archive.record(good, _read_step(2, "a.java"))
    archive.close()
    assert len(evidence.read_run_steps(tmp_path, "good")) == 2
    assert evidence.read_run_steps(tmp_path, "bad") == []


def test_step_archive_separates_colliding_names_and_redriven_sessions(tmp_path):
    first = AgentRun(run_id="scope/a", agent="a", scope_id="s")
    second = AgentRun(run_id="scope:a", agent="a", scope_id="s")
    assert evidence.step_file(tmp_path, first.run_id) != evidence.step_file(tmp_path, second.run_id)
    with evidence.StepArchive(tmp_path) as archive:
        archive.record(first, _read_step(1, "old.java"))
        archive.record(second, _read_step(1, "other.java"))
    with evidence.StepArchive(tmp_path) as archive:
        archive.record(first, _read_step(1, "new.java"))
    latest = evidence.read_run_steps(tmp_path, first.run_id)
    assert [step.result.data["path"] for step in latest] == ["new.java"]
    assert [step.result.data["path"] for step in evidence.read_run_steps(tmp_path, second.run_id)] == ["other.java"]


def test_agent_token_cap_stops_after_provider_omits_usage():
    calls = []
    client = SimpleNamespace(complete=lambda *_: calls.append(1) or SimpleNamespace(usage=None))
    agent_budget = AgentBudget(max_model_tokens=100)
    audit_budget = RunBudget(HarnessConfig())
    bounded = BudgetClient(client, audit_budget, lambda _: None, agent_budget=agent_budget)
    bounded.complete("system", "task")
    with pytest.raises(AgentBudgetStop, match="未返回完整 token 用量"):
        bounded.complete("system", "task")
    assert calls == [1]
    assert audit_budget.calls == 1
    assert agent_budget.usage()["unknown_usage"] == 1


def test_text_format_repair_uses_the_same_input_budget(monkeypatch):
    from services.harness import react

    seen = []
    original = react.render_user_message

    def render(*args, **kwargs):
        seen.append((kwargs.get("max_input_tokens"), kwargs.get("note", "")))
        return original(*args, **kwargs)

    monkeypatch.setattr(react, "render_user_message", render)
    answers = iter(["invalid JSON", '{"final":{"ok":true}}'])
    client = SimpleNamespace(
        context_input_tokens=100_000,
        complete=lambda *_: ChatResult(text=next(answers), model="test"),
    )
    run = run_agent(
        agent="discovery", scope_id="scope", system_prompt="policy", task="inspect",
        tools=[], context=None, client=client, max_steps=1,
    )
    assert run.stop_reason == "finished"
    assert len(seen) == 2
    assert all(limit == 100_000 for limit, _ in seen)
    assert "invalid JSON" in seen[1][1]


def test_nonstream_model_wait_is_visible_without_replaying_request():
    entered = threading.Event()
    release = threading.Event()
    reported = threading.Event()
    updates = []
    calls = []

    def complete(*_):
        calls.append(1)
        entered.set()
        assert release.wait(2)
        return ChatResult(text="ok", model="test")

    client = SimpleNamespace(streaming=False, complete=complete)
    def on_progress(update):
        updates.append(update)
        reported.set()

    bounded = BudgetClient(client, RunBudget(HarnessConfig()), lambda _: None,
                           on_progress=on_progress)
    thread = threading.Thread(target=lambda: bounded.complete("system", "task"))
    thread.start()
    assert entered.wait(1)
    assert reported.wait(1)
    assert updates and updates[0]["status"] == "waiting"
    assert updates[0]["transport"] == "nonstream"
    release.set()
    thread.join(2)
    assert not thread.is_alive()
    assert calls == [1]


def test_archive_write_failure_is_visible_in_trail_once(tmp_path):
    coordinator = HarnessCoordinator(workspace=tmp_path, out_dir=tmp_path / "runs", run_id="R-1")
    trail = coordinator.attach_trail()
    run = AgentRun(run_id="r", agent="recon", scope_id="workspace")
    path = evidence.step_file(coordinator.run_dir, run.run_id)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir()  # opening it as a JSONL file must fail
    coordinator._on_step(run, AgentStep(index=1, thought="first"))
    coordinator._on_step(run, AgentStep(index=2, thought="second"))
    trail.close()
    events = read_events(coordinator.run_dir / "trail.jsonl", limit=20)["events"]
    errors = [event for event in events if event["kind"] == "error"]
    assert len(errors) == 1
    assert errors[0]["where"] == "evidence_archive"
    assert [event["index"] for event in events if event["kind"] == "agent_step"] == [1, 2]
