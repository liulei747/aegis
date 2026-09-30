"""The native tools/tool_calls loop (`react.run_agent_native`).

Pins what batch 2 of HARNESS_RUNTIME_TODO delivered, against a client that speaks the
protocol the probe verified on the gateway (`var/probe_native_tools.py`):
`finish_reason="tool_calls"`, a `tool_call_id` round trip via `role:"tool"`, and a final
answer as plain `content`. Off by default (`AIConfig.native_tools = False`); the loop is
entered only when the client both declares the flag and carries `complete_messages`.
"""

from __future__ import annotations

import json
import threading

from aegis_contracts.harness import AgentRun, ToolCall, ToolName, ToolResult
from services.ai.client import ChatResult
from services.harness.react import run_agent


class FakeNativeClient:
    """Speaks `complete_messages` with tools and returns scripted results."""

    model = "fake-native"
    native_tools = True

    def __init__(self, *results: ChatResult) -> None:
        self.results = list(results)
        self.calls: list[dict] = []
        self.tool_payloads: list[list[dict] | None] = []

    def complete_messages(self, messages, *, tools=None):
        self.calls.append([dict(m) for m in messages])
        self.tool_payloads.append(json.loads(json.dumps(tools)) if tools else tools)
        if not self.results:
            raise AssertionError("FakeNativeClient ran out of scripted results")
        return self.results.pop(0)


def result(**body) -> ChatResult:
    """A ChatResult shaped like what `complete_messages` returns for this body — including
    the parsed `tool_calls`, which is exactly what the real adapter does for the model."""
    message = {"content": body.get("content", ""), "tool_calls": body.get("tool_calls")}
    from services.ai.client import _tool_calls_from

    return ChatResult(
        text=message["content"],
        model="fake-native",
        raw={"choices": [{"message": message, "finish_reason": body.get("finish_reason", "tool_calls" if body.get("tool_calls") else "stop")}]},
        tool_calls=_tool_calls_from(message),
    )


def test_retry_progress_exposes_attempt_and_reason(monkeypatch) -> None:
    from services.ai.client import AIUnavailable
    from services.harness.react import _complete_messages_with_retries

    class Flaky:
        on_progress = None

        def __init__(self):
            self.calls = 0
            self.events = []
            self.on_progress = self.events.append

        def complete_messages(self, messages, *, tools):
            self.calls += 1
            if self.calls == 1:
                raise AIUnavailable("temporary 503")
            return result(content='{"thought":"ok","final":{"verdict":"rejected"}}')

    monkeypatch.setattr("services.harness.react.time.sleep", lambda _: None)
    client = Flaky()
    _complete_messages_with_retries(client, [{"role": "user", "content": "test"}], [], caller="test")
    assert client.calls == 2
    assert client.events == [{
        "status": "retrying", "attempt": 2, "max_attempts": 4,
        "retry_delay_s": 1.5, "failure_code": "AIUnavailable",
        "failure_reason": "temporary 503",
    }]


def test_only_read_only_tool_batch_runs_in_parallel(monkeypatch) -> None:
    from services.harness import react

    barrier = threading.Barrier(2, timeout=2)
    worker_names = []

    def invoke(_context, call):
        worker_names.append(threading.current_thread().name)
        if call.tool is ToolName.READ:
            barrier.wait()
        return ToolResult(tool=call.tool, ok=True, summary=call.arguments.get("path", "record"))

    monkeypatch.setattr(react, "_invoke", invoke)
    reads = [ToolCall(tool=ToolName.READ, arguments={"path": path}) for path in ("a.py", "b.py")]
    assert [item.summary for item in react._invoke_batch(None, reads)] == ["a.py", "b.py"]
    assert len(set(worker_names)) == 2
    worker_names.clear()
    writes = [ToolCall(tool=ToolName.RECORD, arguments={"text": "fact"}),
              ToolCall(tool=ToolName.RECORD, arguments={"text": "fact"})]
    assert len(react._invoke_batch(None, writes)) == 2
    assert worker_names == [threading.current_thread().name] * 2


def test_native_loop_gets_the_same_final_turn_reminder_as_text_loop() -> None:
    calls = [result(tool_calls=[{
        "id": f"call_{index}", "type": "function",
        "function": {"name": "read", "arguments": '{"path":"a.py"}'},
    }]) for index in range(1, 8)]
    calls.append(result(content='{"thought":"done","final":{"verdict":"rejected"}}'))
    client = FakeNativeClient(*calls)
    run = run_agent(
        agent="validation", scope_id="C-1", system_prompt="Review", task="decide",
        tools=[ToolName.READ], context=None, client=client, max_steps=8,
        output_schema={"required": ["verdict"]},
    )
    assert run.stop_reason == "finished"
    assert "1 turn(s) left out of 8" in client.calls[6][-1]["content"]
    assert "LAST turn" in client.calls[7][-1]["content"]


def run_native(client: FakeNativeClient, *, schema: dict | None = None) -> AgentRun:
    return run_agent(
        agent="validation",
        scope_id="C-1",
        system_prompt="You are the validation agent.",
        task="decide",
        tools=[ToolName.READ],
        context=None,
        client=client,
        max_steps=6,
        output_schema=schema or {"required": ["verdict"]},
    )


def test_a_native_tool_call_is_executed_and_its_result_fed_back_by_id() -> None:
    """The protocol round trip: tools go out, one call comes back, the result goes back in."""
    client = FakeNativeClient(
        result(
            tool_calls=[{
                "id": "call_ab12", "type": "function",
                "function": {"name": "read", "arguments": json.dumps({"path": "a.java"})},
            }],
        ),
        result(content=json.dumps({"thought": "judged", "final": {"verdict": "confirmed"}})),
    )
    run = run_native(client)

    assert run.stop_reason == "finished"
    assert run.output == {"verdict": "confirmed"}
    # The request carried the tools as OpenAI function schemas.
    assert client.tool_payloads[0] and client.tool_payloads[0][0]["function"]["name"] == "read"
    # The follow-up turn answers the call by id, with the tool's own summary.
    followups = [m for m in client.calls[1] if m.get("role") == "tool"]
    assert followups and followups[0]["tool_call_id"] == "call_ab12"
    # And the transcript is a messages array, not the text protocol's re-rendered user message.
    assert client.calls[0][0]["role"] == "system" and client.calls[0][1]["role"] == "user"


def test_a_native_call_for_a_tool_outside_the_allow_list_is_refused_not_crashed() -> None:
    """The allow-list is closed in the native loop too: the refusal travels back as the result."""
    client = FakeNativeClient(
        result(
            tool_calls=[{
                "id": "call_x", "type": "function",
                "function": {"name": "shell_command", "arguments": json.dumps({"argv": ["rm"]})},
            }],
        ),
        result(content=json.dumps({"thought": "ok", "final": {"verdict": "rejected"}})),
    )
    run = run_native(client)

    assert run.stop_reason == "finished"
    followups = [m for m in client.calls[1] if m.get("role") == "tool"]
    assert followups and "未知工具" in followups[0]["content"], (
        "the model must be able to read why its call did not run"
    )


def test_a_native_final_answer_still_fits_the_stage_schema() -> None:
    """The JSON contract is unchanged: a native `content` answer goes through the same parser."""
    client = FakeNativeClient(
        result(content=json.dumps({"thought": "t", "final": {"verdict": "confirmed", "confidence": 0.7}})),
    )
    run = run_native(client, schema={"required": ["verdict", "confidence"]})

    assert run.stop_reason == "finished"
    assert run.output["confidence"] == 0.7


def test_multiple_native_calls_share_one_assistant_message() -> None:
    client = FakeNativeClient(
        result(tool_calls=[
            {"id": "a", "function": {"name": "read", "arguments": '{"path":"a.java"}'}},
            {"id": "b", "function": {"name": "read", "arguments": '{"path":"b.java"}'}},
        ]),
        result(content='{"final":{"verdict":"confirmed"}}'),
    )
    run = run_native(client)
    assert run.stop_reason == "finished"
    transcript = client.calls[1]
    assistants = [m for m in transcript if m.get("role") == "assistant" and m.get("tool_calls")]
    assert len(assistants) == 1
    assert [c["id"] for c in assistants[0]["tool_calls"]] == ["a", "b"]
    assert [m["tool_call_id"] for m in transcript if m.get("role") == "tool"] == ["a", "b"]


def test_one_tool_failure_does_not_erase_another_result(monkeypatch) -> None:
    from aegis_contracts.harness import ToolResult
    from services.harness import react

    def invoke(_context, call):
        if call.arguments["path"] == "slow.java":
            raise TimeoutError("read deadline reached")
        return ToolResult(tool=call.tool, ok=True, summary="read ok")

    original_layer = react.tool_layer
    monkeypatch.setattr(react, "tool_layer", lambda: (*original_layer()[:3], invoke, original_layer()[4]))
    client = FakeNativeClient(
        result(tool_calls=[
            {"id": "slow", "function": {"name": "read", "arguments": '{"path":"slow.java"}'}},
            {"id": "good", "function": {"name": "read", "arguments": '{"path":"good.java"}'}},
        ]),
        result(content='{"final":{"verdict":"confirmed"}}'),
    )
    run = run_native(client)
    assert run.stop_reason == "finished"
    tool_replies = [m for m in client.calls[1] if m.get("role") == "tool"]
    assert [m["tool_call_id"] for m in tool_replies] == ["slow", "good"]
    assert "TimeoutError" in tool_replies[0]["content"]
    assert tool_replies[1]["content"] == "read ok"


def test_repeated_call_id_is_stopped_before_any_tool_runs() -> None:
    import pytest

    from services.ai.client import AIError, _tool_calls_from

    with pytest.raises(AIError, match="duplicate"):
        _tool_calls_from({"tool_calls": [
            {"id": "a", "function": {"name": "read", "arguments": '{"path":"a.java"}'}},
            {"id": "a", "function": {"name": "read", "arguments": '{"path":"b.java"}'}},
        ]})


def test_native_transient_retry_is_counted_and_recorded(monkeypatch) -> None:
    from services.ai import traffic
    from services.ai.client import AIUnavailable
    from services.harness import react

    class Client:
        model = "fake-native"
        calls = 0

        def complete_messages(self, messages, *, tools):
            self.calls += 1
            if self.calls == 1:
                raise AIUnavailable("HTTP 503")
            return result(content='{"final":{"verdict":"confirmed"}}')

    rows = []
    monkeypatch.setattr(traffic, "record", lambda **kwargs: rows.append(kwargs))
    monkeypatch.setattr(react.time, "sleep", lambda _seconds: None)
    client = Client()
    completed = react._complete_messages_with_retries(
        client, [{"role": "user", "content": "decide"}], [], caller="validation:C-1")
    assert completed.text
    assert client.calls == 2
    assert [(row["attempt"], row["ok"]) for row in rows] == [(1, False), (2, True)]
    assert all(row["caller"] == "validation:C-1" for row in rows)
    assert all(row["prompt_token_estimate"] > 0 for row in rows)


def test_native_partial_stream_failure_is_not_replayed(monkeypatch) -> None:
    import pytest

    from services.ai import traffic
    from services.ai.streaming import StreamFailure
    from services.harness import react

    class Client:
        model = "fake-native"
        calls = 0

        def complete_messages(self, messages, *, tools):
            self.calls += 1
            raise StreamFailure("total_timeout", "limit", {"events": 3})

    rows = []
    monkeypatch.setattr(traffic, "record", lambda **kwargs: rows.append(kwargs))
    client = Client()
    with pytest.raises(StreamFailure):
        react._complete_messages_with_retries(client, [{"role": "user", "content": "decide"}], [])
    assert client.calls == 1
    assert len(rows) == 1
    assert rows[0]["stream_metadata"]["failure_code"] == "total_timeout"


def test_native_retry_cannot_exceed_shared_model_call_budget(monkeypatch) -> None:
    import pytest

    from services.ai import traffic
    from services.ai.client import AIUnavailable
    from services.harness import react
    from services.harness.budget import BudgetClient, BudgetStop, RunBudget
    from services.harness.coordinator import HarnessConfig

    class Client:
        model = "fake-native"
        calls = 0

        def complete_messages(self, messages, *, tools):
            self.calls += 1
            raise AIUnavailable("HTTP 503")

    rows = []
    monkeypatch.setattr(traffic, "record", lambda **kwargs: rows.append(kwargs))
    monkeypatch.setattr(react.time, "sleep", lambda _seconds: None)
    raw = Client()
    budget = RunBudget(HarnessConfig(max_model_calls=1))
    client = BudgetClient(raw, budget, lambda _stage: None)
    with pytest.raises(BudgetStop):
        react._complete_messages_with_retries(client, [{"role": "user", "content": "decide"}], [])
    assert raw.calls == 1
    assert budget.calls == 1
    assert len(rows) == 1  # No phantom model request for the refused second reservation.
