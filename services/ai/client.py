"""The model call: one OpenAI-compatible `/chat/completions` round trip.

The transport is injectable on purpose. Tests must be able to exercise retries, malformed
answers and timeouts without a network, and the field cares about what the *stage* does with a
bad answer far more than about urllib.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from aegis_contracts.ai import TokenUsage
from aegis_core.logging import get_logger

log = get_logger(__name__)


class AIUnavailable(RuntimeError):
    """The endpoint could not be reached, or refused us. Retrying may help."""


class AIError(RuntimeError):
    """The endpoint answered something we cannot use. Retrying usually will not help."""


@dataclass
class ChatResult:
    text: str
    model: str
    usage: TokenUsage | None = None
    raw: dict[str, Any] = field(default_factory=dict)
    #: Native `tool_calls` the model asked for, in order. Empty unless the request carried `tools`
    #: and the model chose to call one; `text` is then usually empty or a short preamble. Parsing and
    #: *executing* them is the caller's job — the adapter's contract stops at "what the model asked".
    tool_calls: tuple[NativeToolCall, ...] = ()


@dataclass(frozen=True)
class NativeToolCall:
    """One native tool call the model emitted: `id` is what the follow-up `role:"tool"` message
    must carry, `arguments` is the raw JSON string the model wrote (not yet validated)."""

    call_id: str
    name: str
    arguments: str


#: The provider's words for "generation stopped because it ran out of output tokens". Names differ by
#: provider and a gateway may pass any of them through, so all of them are recognised rather than one
#: being assumed -- and an unknown word simply is not a truncation, which is the safe direction.
TRUNCATION_REASONS = frozenset({"length", "max_tokens", "max_output_tokens"})


def finish_reason(result: ChatResult) -> str:
    """Why generation stopped, in the provider's own words. Empty when the response did not say.

    Read off `raw` rather than added to `ChatResult` as a field, because it is not this codebase's
    concept: `text` is what a caller consumes, and a provider-specific string is only useful to a
    caller that wants to explain a failure. Keeping it here means the loop can say "your answer hit
    the output limit" instead of reporting a JSON syntax error the model cannot act on.
    """
    choices = result.raw.get("choices")
    if isinstance(choices, list) and choices and isinstance(choices[0], dict):
        for key in ("finish_reason", "stop_reason"):
            if choices[0].get(key):
                return str(choices[0][key])
    # Anthropic-shaped bodies carry `stop_reason` at the top level.
    return str(result.raw.get("stop_reason") or "")


def truncated(result: ChatResult) -> bool:
    """Whether the model was cut off at the output limit rather than choosing to stop."""
    return finish_reason(result) in TRUNCATION_REASONS


#: What a transport is: `(url, payload, api_key, timeout_s) -> parsed response body`.
Transport = Callable[[str, dict, str, float], dict]


def urllib_transport(url: str, payload: dict, api_key: str, timeout_s: float) -> dict:
    request = urllib.request.Request(
        url,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json", "Authorization": f"Bearer {api_key}"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout_s) as response:
            return json.loads(response.read().decode("utf-8"))
    except TimeoutError as exc:
        # A timeout during `read()` after the connection was established. `socket.timeout` is
        # `TimeoutError` since 3.10, and it is neither an `HTTPError` nor a `URLError`, so it used to
        # escape both handlers below -- and because the ReAct loop only catches `AIUnavailable` /
        # `AIError`, it killed the whole run instead of one call. Measured: a single hung request out
        # of roughly 170 ended a benchmark run with a bare traceback. The full response may
        # already have been generated upstream, so do not resend this expensive request blindly.
        failure = AIUnavailable(f"{url} timed out after {timeout_s:.0f}s")
        failure.retryable = False
        raise failure from exc
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:600]
        # 4xx is our fault (bad key, bad model, prompt too long); 5xx and 429 are worth another
        # try. The distinction decides whether the runner retries or reports.
        if exc.code in (408, 409, 429) or exc.code >= 500:
            raise AIUnavailable(f"HTTP {exc.code} from {url}: {detail}") from exc
        raise AIError(f"HTTP {exc.code} from {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise AIUnavailable(f"cannot reach {url}: {exc.reason}") from exc


def _usage_from(body: dict) -> TokenUsage | None:
    """Normalise the provider's token accounting, including both names for a cache hit."""
    usage = body.get("usage")
    if not isinstance(usage, dict):
        return None
    details = usage.get("prompt_tokens_details") or {}
    cached = usage.get("prompt_cache_hit_tokens")
    if cached is None:
        cached = details.get("cached_tokens") if isinstance(details, dict) else None
    return TokenUsage(
        prompt_tokens=usage.get("prompt_tokens"),
        completion_tokens=usage.get("completion_tokens"),
        total_tokens=usage.get("total_tokens"),
        cached_tokens=cached,
        raw=usage,
    )


def _tool_calls_from(message: dict) -> tuple[NativeToolCall, ...]:
    """Validate all native calls before the harness may execute any of them."""
    out: list[NativeToolCall] = []
    seen: set[str] = set()
    for raw in message.get("tool_calls") or []:
        if not isinstance(raw, dict) or not isinstance(raw.get("function"), dict):
            raise AIError("malformed native tool call: missing function")
        function = raw["function"]
        call_id, name = raw.get("id"), function.get("name")
        if not isinstance(call_id, str) or not call_id or not isinstance(name, str) or not name:
            raise AIError("malformed native tool call: missing id or name")
        if call_id in seen:
            raise AIError("duplicate native tool_call_id in one response")
        seen.add(call_id)
        arguments = function.get("arguments")
        if not isinstance(arguments, str):
            raise AIError("malformed native tool call: arguments must be text")
        out.append(NativeToolCall(
            call_id=call_id,
            name=name,
            arguments=arguments,
        ))
    return tuple(out)


class ChatClient:
    """Calls an OpenAI-compatible chat endpoint. One instance per configured model."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        temperature: float = 0.0,
        timeout_s: float = 180.0,
        max_tokens: int = 0,
        streaming: bool = False,
        connect_timeout_s: float = 30.0,
        stream_idle_timeout_s: float = 180.0,
        stream_total_timeout_s: float = 900.0,
        native_tools: bool = False,
        context_input_tokens: int = 0,
        transport: Transport = urllib_transport,
    ) -> None:
        if not base_url.strip():
            raise AIError("no endpoint configured: refusing to guess one")
        if not api_key.strip():
            raise AIError("no API key: refusing to call without one")
        if not model.strip():
            raise AIError("no model configured")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.temperature = temperature
        self.timeout_s = timeout_s
        #: Sent as `max_tokens` when positive, omitted when zero. Omitting is the historical
        #: behaviour: the provider's default applies, and the harness cannot say what it is.
        self.max_tokens = max_tokens
        self._transport = transport
        self.streaming = streaming
        self.connect_timeout_s = connect_timeout_s
        self.stream_idle_timeout_s = stream_idle_timeout_s
        self.stream_total_timeout_s = stream_total_timeout_s
        #: Deployment intent for the native tools/tool_calls protocol. The adapter can always speak
        #: it (`complete_messages` with `tools`); this flag is what the harness loop reads to decide
        #: which protocol a run uses.
        self.native_tools = native_tools
        self.context_input_tokens = context_input_tokens

    @property
    def url(self) -> str:
        return f"{self.base_url}/chat/completions"

    def complete(self, system: str, user: str, *, on_progress=None, check=None) -> ChatResult:
        return self.complete_messages(
            [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            on_progress=on_progress,
            check=check,
        )

    def complete_messages(
        self,
        messages: list[dict[str, Any]],
        *,
        tools: list[dict[str, Any]] | None = None,
        on_progress=None,
        check=None,
    ) -> ChatResult:
        """One round trip over an explicit message list — the native tool-calls path.

        `messages` is sent as given: the caller owns the transcript shape, including
        `role:"tool"` messages that answer earlier `tool_calls` (each must carry the
        `tool_call_id` the model emitted). `tools` is a list of OpenAI function schemas;
        when present the request carries `tools` + `tool_choice:"auto"` and the response's
        `message.tool_calls` are parsed into `ChatResult.tool_calls`.

        Streaming accumulates tool-call fragments by index, then validates them before any
        tool is executed. A disconnected partial stream is never surfaced as a tool request.
        """
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": messages,
        }
        if self.max_tokens > 0:
            payload["max_tokens"] = self.max_tokens
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"
        transport = self._transport
        if self.streaming and transport is urllib_transport:
            from services.ai.streaming import StreamingChatTransport
            transport = StreamingChatTransport(
                connect_timeout_s=self.connect_timeout_s,
                idle_timeout_s=self.stream_idle_timeout_s,
                total_timeout_s=self.stream_total_timeout_s,
                on_progress=on_progress, check=check,
            )
        body = transport(self.url, payload, self.api_key, self.timeout_s)
        choices = body.get("choices") or []
        if not choices:
            raise AIError(f"no choices in the response: {json.dumps(body)[:400]}")
        message = choices[0].get("message") or {}
        text = message.get("content") or ""
        if not isinstance(text, str):
            raise AIError(f"the answer content is not text: {type(text).__name__}")
        return ChatResult(
            text=text,
            model=str(body.get("model") or self.model),
            usage=_usage_from(body),
            raw=body,
            tool_calls=_tool_calls_from(message),
        )
