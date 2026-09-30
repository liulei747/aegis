"""Bounded SSE reception. Progress contains counters, never reasoning or source text."""
from __future__ import annotations

import asyncio
import json
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import httpx

from aegis_core.logging import get_logger
from services.ai.client import AIError, AIUnavailable

log = get_logger(__name__)


class StreamFailure(AIUnavailable):
    def __init__(self, code: str, message: str, metadata: dict):
        super().__init__(f"{code}: {message}")
        self.metadata = {**metadata, "failure_code": code}
        # Retrying an expensive partially generated answer repeats all that work.
        self.retryable = code in {"connect_timeout", "connect_error", "http_transient"} and not metadata["events"]


class StreamingChatTransport:
    def __init__(self, *, connect_timeout_s=30.0, idle_timeout_s=180.0,
                 total_timeout_s=900.0, on_progress=None, check=None, http_transport=None):
        self.connect_timeout_s = connect_timeout_s
        self.idle_timeout_s = idle_timeout_s
        self.total_timeout_s = total_timeout_s
        self.on_progress = on_progress
        self.check = check
        self.http_transport = http_transport

    def __call__(self, url, payload, api_key, timeout_s):
        # The public client is synchronous; ordinary workers have no active event loop.
        # Keep compatibility with synchronous callers inside an async application too.
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            return asyncio.run(self.receive(url, payload, api_key, timeout_s))
        with ThreadPoolExecutor(max_workers=1) as executor:
            return executor.submit(lambda: asyncio.run(
                self.receive(url, payload, api_key, timeout_s))).result()

    async def receive(self, url, payload, api_key, first_timeout_s):
        started = time.monotonic()
        last_activity = started
        last_emit = started
        last_check = 0.0
        state = {"request_id": uuid.uuid4().hex, "status": "waiting", "events": 0,
                 "content_chars": 0, "reasoning_chars": 0, "first_event_ms": None,
                 "first_content_ms": None, "provider_request_id": None}

        def snapshot():
            now = time.monotonic()
            return {**state, "elapsed_ms": round((now - started) * 1000),
                    "idle_ms": round((now - last_activity) * 1000)}

        def emit():
            nonlocal last_emit
            last_emit = time.monotonic()
            if self.on_progress:
                try:
                    self.on_progress(snapshot())
                except Exception:
                    log.warning("model stream progress observer failed")

        def fail(code, message):
            return StreamFailure(code, message, snapshot())

        async def read():
            nonlocal last_activity
            content = []
            tool_calls: dict[int, dict] = {}
            model = payload.get("model", "")
            usage = None
            finish = None
            data = []
            data_size = 0
            timeout = httpx.Timeout(self.connect_timeout_s, read=None)
            async with httpx.AsyncClient(timeout=timeout, transport=self.http_transport) as client:
                async with client.stream("POST", url, json={**payload, "stream": True,
                        "stream_options": {"include_usage": True}},
                        headers={"Authorization": f"Bearer {api_key}",
                                 "Content-Type": "application/json"}) as response:
                    state["provider_request_id"] = response.headers.get("x-request-id") or response.headers.get("request-id")
                    if response.status_code >= 400:
                        # Don't echo arbitrary provider bodies, which may contain request data.
                        if response.status_code in {408, 409, 429} or response.status_code >= 500:
                            raise fail("http_transient", f"HTTP {response.status_code}")
                        raise AIError(f"HTTP {response.status_code}; streaming request rejected (no automatic fallback)")
                    if "text/event-stream" not in response.headers.get("content-type", ""):
                        raise fail("stream_unsupported", "expected text/event-stream; select non-streaming explicitly")
                    async for line in response.aiter_lines():
                        await asyncio.sleep(0)
                        if line.startswith(":"):
                            continue  # Heartbeats aren't model progress.
                        if line.startswith("data:"):
                            value = line[5:].lstrip(" ")
                            data_size += len(value)
                            if data_size > 1_048_576:
                                raise fail("stream_protocol", "SSE event exceeds size limit")
                            data.append(value)
                        if line or not data:
                            continue
                        value = "\n".join(data)
                        data, data_size = [], 0
                        if value == "[DONE]":
                            if not finish:
                                raise fail("stream_incomplete", "stream ended without finish_reason")
                            if not content and not tool_calls:
                                raise fail("empty_answer", f"no answer content; finish_reason={finish}")
                            if bool(tool_calls) != (finish == "tool_calls"):
                                raise fail("stream_protocol", "tool calls and finish_reason disagree")
                            completed_calls = []
                            for index in sorted(tool_calls):
                                call = tool_calls[index]
                                if not call["id"] or not call["name"]:
                                    raise fail("stream_incomplete", f"tool call {index} has no id or name")
                                completed_calls.append({
                                    "id": call["id"], "type": "function",
                                    "function": {"name": call["name"], "arguments": call["arguments"]},
                                })
                            return {"model": model, "choices": [{"message": {"content": "".join(content)},
                                    "finish_reason": finish}], "usage": usage} if not completed_calls else {
                                        "model": model, "choices": [{"message": {
                                            "content": "".join(content), "tool_calls": completed_calls},
                                            "finish_reason": finish}], "usage": usage,
                                    }
                        try:
                            event = json.loads(value)
                            if not isinstance(event, dict):
                                raise ValueError()
                        except (ValueError, TypeError):
                            raise fail("stream_protocol", "invalid SSE JSON") from None
                        if event.get("error"):
                            raise fail("provider_stream_error", "provider reported an error inside the stream")
                        state["events"] += 1
                        now = time.monotonic()
                        if state["first_event_ms"] is None:
                            state["first_event_ms"] = round((now - started) * 1000)
                            last_activity = now
                        model = event.get("model") or model
                        usage = event.get("usage") or usage
                        choices = event.get("choices") or []
                        if not choices:
                            continue
                        if not isinstance(choices, list) or not isinstance(choices[0], dict):
                            raise fail("stream_protocol", "invalid choices")
                        choice = choices[0]
                        delta = choice.get("delta") or {}
                        if not isinstance(delta, dict):
                            raise fail("stream_protocol", "invalid delta")
                        text = delta.get("content") or ""
                        reasoning = delta.get("reasoning_content") or delta.get("reasoning") or ""
                        if not isinstance(text, str) or not isinstance(reasoning, str):
                            raise fail("stream_protocol", "unsupported delta content type")
                        tool_deltas = delta.get("tool_calls") or []
                        if not isinstance(tool_deltas, list):
                            raise fail("stream_protocol", "tool_calls delta is not a list")
                        for part in tool_deltas:
                            if not isinstance(part, dict) or type(part.get("index")) is not int:
                                raise fail("stream_protocol", "tool call has no integer index")
                            index = part["index"]
                            if index < 0 or index >= 8:
                                raise fail("stream_protocol", "too many tool calls in one response")
                            call = tool_calls.setdefault(index, {"id": "", "name": "", "arguments": ""})
                            function = part.get("function") or {}
                            if not isinstance(function, dict):
                                raise fail("stream_protocol", "invalid tool function delta")
                            for target, fragment in (("id", part.get("id")),
                                                     ("name", function.get("name")),
                                                     ("arguments", function.get("arguments"))):
                                if fragment is not None:
                                    if not isinstance(fragment, str):
                                        raise fail("stream_protocol", "tool call fragment is not text")
                                    call[target] += fragment
                            if any(len(call[key]) > limit for key, limit in
                                   (("id", 256), ("name", 256), ("arguments", 65_536))):
                                raise fail("stream_protocol", "tool call exceeds size limit")
                        previous = state["status"]
                        if text:
                            content.append(text)
                            state["content_chars"] += len(text)
                            if state["content_chars"] > 8_388_608:
                                raise fail("stream_protocol", "answer exceeds size limit")
                            if state["first_content_ms"] is None:
                                state["first_content_ms"] = round((now - started) * 1000)
                            state["status"] = "responding"
                        elif reasoning:
                            state["status"] = "reasoning"
                        state["reasoning_chars"] += len(reasoning)
                        if text or reasoning or tool_deltas or choice.get("finish_reason"):
                            last_activity = now
                        finish = choice.get("finish_reason") or finish
                        if previous != state["status"]:
                            emit()
                    raise fail("stream_incomplete", "connection closed before [DONE]; partial answer discarded")

        emit()
        task = asyncio.create_task(read())
        try:
            while True:
                now = time.monotonic()
                if self.check and now - last_check >= 0.5:
                    self.check("model-stream")
                    last_check = now
                if now - started >= self.total_timeout_s:
                    raise fail("total_timeout", f"request exceeded {self.total_timeout_s:g}s total limit")
                if state["first_event_ms"] is None and now - started >= first_timeout_s:
                    raise fail("first_event_timeout", f"no model event within {first_timeout_s:g}s")
                if state["first_event_ms"] is not None and now - last_activity >= self.idle_timeout_s:
                    raise fail("idle_timeout", f"no model progress for {self.idle_timeout_s:g}s")
                if now - last_emit >= 5:
                    emit()
                done, _ = await asyncio.wait({task}, timeout=0.05)
                if done:
                    result = task.result()
                    state["status"] = "completed"
                    emit()
                    result["stream_metadata"] = snapshot()
                    return result
        except BaseException as exc:
            mapped = exc
            if isinstance(exc, httpx.ConnectTimeout):
                mapped = fail("connect_timeout", "connection timed out")
            elif isinstance(exc, httpx.ConnectError):
                mapped = fail("connect_error", "connection could not be established")
            elif isinstance(exc, httpx.HTTPError):
                mapped = fail("stream_disconnected", "transport failed; partial answer discarded")
            state["status"] = "failed" if isinstance(mapped, Exception) else (
                "cancelled" if type(mapped).__name__ in {"CanceledAbort", "Cancelled", "CancelledError", "KeyboardInterrupt"} else "stopped")
            state["failure_code"] = getattr(mapped, "metadata", {}).get("failure_code", type(mapped).__name__)
            mapped.metadata = snapshot()
            emit()
            if mapped is not exc:
                raise mapped from None
            raise
        finally:
            if not task.done():
                task.cancel()
            await asyncio.gather(task, return_exceptions=True)
