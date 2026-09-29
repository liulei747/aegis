"""Exercise real HTTPX SSE decoding and cancellation without a paid model."""
import asyncio
import json

import httpx
import pytest

from services.ai.streaming import StreamFailure, StreamingChatTransport


def event(content=None, reasoning=None, finish=None):
    delta = {}
    if content is not None:
        delta["content"] = content
    if reasoning is not None:
        delta["reasoning_content"] = reasoning
    return ("data: " + json.dumps({"choices": [{"delta": delta, "finish_reason": finish}]}, ensure_ascii=False) + "\n\n").encode()


class Chunks(httpx.AsyncByteStream):
    def __init__(self, chunks, delay=0, hang=False):
        self.chunks, self.delay, self.hang = chunks, delay, hang
        self.closed = False

    async def __aiter__(self):
        for chunk in self.chunks:
            await asyncio.sleep(self.delay)
            yield chunk
        if self.hang:
            await asyncio.sleep(100)

    async def aclose(self):
        self.closed = True


def transport(stream, **kwargs):
    async def handler(request):
        body = json.loads(request.content)
        assert body["stream"] is True
        assert "max_tokens" not in body
        return httpx.Response(200, headers={"content-type": "text/event-stream", "x-request-id": "provider-1"}, stream=stream)
    return StreamingChatTransport(http_transport=httpx.MockTransport(handler), **kwargs)


def call(t, first=1):
    return t("https://example.invalid/v1/chat/completions", {"model": "test"}, "secret", first)


def test_fragmented_unicode_multiline_usage_and_no_reasoning_leak():
    wire = event(reasoning="private reasoning") + event(content="你好") + event(finish="stop")
    wire += b'data: {"usage":\ndata: {"completion_tokens": 7}}\n\n' 
    wire += b"data: [DONE]\n\n"
    stream = Chunks([wire[i:i+1] for i in range(len(wire))])
    progress = []
    result = call(transport(stream, on_progress=progress.append))
    assert result["choices"][0]["message"]["content"] == "你好"
    assert result["usage"]["completion_tokens"] == 7
    assert result["stream_metadata"]["provider_request_id"] == "provider-1"
    assert "private reasoning" not in json.dumps([result, progress])
    assert progress[-1]["status"] == "completed"
    assert stream.closed


def test_active_stream_outlives_first_event_timeout():
    stream = Chunks([event(reasoning="x")] * 8 + [event(content="ok", finish="stop"), b"data: [DONE]\n\n"], delay=.02)
    result = call(transport(stream, idle_timeout_s=.1, total_timeout_s=2), first=.08)
    assert result["stream_metadata"]["elapsed_ms"] > 80


@pytest.mark.parametrize("chunks,code", [
    ([event(content="partial")], "stream_incomplete"),
    ([event(reasoning="x", finish="length"), b"data: [DONE]\n\n"], "empty_answer"),
    ([event(content="partial"), b"data: [DONE]\n\n"], "stream_incomplete"),
    ([b"data: nope\n\n"], "stream_protocol"),
    ([b'data: {"error": {"message": "secret"}}\n\n'], "provider_stream_error"),
])
def test_partial_or_bad_stream_is_not_success(chunks, code):
    stream = Chunks(chunks)
    progress = []
    with pytest.raises(StreamFailure) as caught:
        call(transport(stream, on_progress=progress.append))
    assert caught.value.metadata["failure_code"] == code
    assert not caught.value.retryable
    assert progress[-1]["status"] == "failed"
    assert stream.closed


def test_heartbeats_do_not_satisfy_first_event_deadline():
    stream = Chunks([b": ping\n\n"] * 100, delay=.01)
    with pytest.raises(StreamFailure, match="first_event_timeout"):
        call(transport(stream), first=.08)
    assert stream.closed


def test_heartbeats_do_not_reset_model_idle_deadline():
    stream = Chunks([event(reasoning="x")] + [b": ping\n\n"] * 100, delay=.01)
    with pytest.raises(StreamFailure, match="idle_timeout"):
        call(transport(stream, idle_timeout_s=.08))
    assert stream.closed


def test_total_deadline_interrupts_blocked_read():
    stream = Chunks([event(reasoning="x")], hang=True)
    with pytest.raises(StreamFailure, match="total_timeout"):
        call(transport(stream, total_timeout_s=.08))
    assert stream.closed


def test_cancellation_interrupts_blocked_read_and_closes_stream():
    class Cancelled(BaseException):
        pass
    checks = 0
    def check(stage):
        nonlocal checks
        checks += 1
        if checks > 1:
            raise Cancelled()
    stream = Chunks([event(reasoning="x")], hang=True)
    progress = []
    with pytest.raises(Cancelled):
        call(transport(stream, check=check, on_progress=progress.append))
    assert stream.closed
    assert progress[-1]["status"] == "cancelled"


def test_non_sse_response_does_not_retry_or_fallback():
    calls = []
    def handler(request):
        calls.append(request)
        return httpx.Response(200, json={"choices": []})
    with pytest.raises(StreamFailure, match="stream_unsupported"):
        call(StreamingChatTransport(http_transport=httpx.MockTransport(handler)))
    assert len(calls) == 1


def test_expensive_stream_failure_not_retried_by_harness():
    from services.harness.react import _complete_with_retries
    class Client:
        calls = 0
        def complete(self, *args):
            self.calls += 1
            raise StreamFailure("total_timeout", "limit", {"events": 3})
    client = Client()
    with pytest.raises(StreamFailure):
        _complete_with_retries(client, "s", "u")
    assert client.calls == 1


def test_reserved_last_call_can_finish_but_total_budget_still_stops():
    from services.harness.budget import BudgetStop, RunBudget
    from services.harness.coordinator import HarnessConfig
    clock = [0.0]
    budget = RunBudget(HarnessConfig(max_model_calls=1, max_run_seconds=10), clock=lambda: clock[0])
    budget.reserve()
    budget.check_inflight()
    clock[0] = 11
    with pytest.raises(BudgetStop):
        budget.check_inflight()


@pytest.mark.asyncio
async def test_real_socket_stream_is_closed_on_idle_timeout():
    closed = asyncio.Event()
    async def handler(reader, writer):
        try:
            head = await reader.readuntil(b"\r\n\r\n")
            size = next(int(row.split(b":", 1)[1]) for row in head.split(b"\r\n") if row.lower().startswith(b"content-length:"))
            await reader.readexactly(size)
            writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n" + event(reasoning="x"))
            await writer.drain()
            await reader.read()
        finally:
            writer.close()
            await writer.wait_closed()
            closed.set()
    server = await asyncio.start_server(handler, "127.0.0.1", 0)
    async with server:
        port = server.sockets[0].getsockname()[1]
        receiver = StreamingChatTransport(idle_timeout_s=.1)
        with pytest.raises(StreamFailure, match="idle_timeout"):
            await receiver.receive(f"http://127.0.0.1:{port}", {"model": "test"}, "k", 5)
        await asyncio.wait_for(closed.wait(), 2)
