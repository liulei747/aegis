"""The native tools/tool_calls loop (`react.run_agent_native`).

Pins what batch 2 of HARNESS_RUNTIME_TODO delivered, against a client that speaks the
protocol the probe verified on the gateway (`var/probe_native_tools.py`):
`finish_reason="tool_calls"`, a `tool_call_id` round trip via `role:"tool"`, and a final
answer as plain `content`. Off by default (`AIConfig.native_tools = False`); the loop is
entered only when the client both declares the flag and carries `complete_messages`.
"""

from __future__ import annotations

import json

from aegis_contracts.harness import AgentRun, ToolName
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
        raw={"choices": [{"message": message, "finish_reason": body.get("finish_reason", "stop")}]},
        tool_calls=_tool_calls_from(message),
    )


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


def test_native_tools_and_streaming_cannot_be_combined() -> None:
    """Streaming accumulates content deltas; tool-call deltas are a later batch. Refuse the combo."""
    import pytest

    from services.ai.client import AIError, ChatClient

    client = ChatClient(
        base_url="https://gateway.invalid", api_key="k", model="m",
        streaming=True, native_tools=True,
    )
    with pytest.raises(AIError, match="流式"):
        client.complete_messages(
            [{"role": "user", "content": "hi"}],
            tools=[{"type": "function", "function": {"name": "read", "parameters": {}}}],
        )
