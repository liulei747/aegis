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
        # of roughly 170 ended a benchmark run with a bare traceback. Classified as unavailable it is
        # retried by `react._complete_with_retries`, and if it keeps failing it costs one agent.
        raise AIUnavailable(f"{url} timed out after {timeout_s:.0f}s") from exc
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
        self._transport = transport

    @property
    def url(self) -> str:
        return f"{self.base_url}/chat/completions"

    def complete(self, system: str, user: str) -> ChatResult:
        payload: dict[str, Any] = {
            "model": self.model,
            "temperature": self.temperature,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        }
        body = self._transport(self.url, payload, self.api_key, self.timeout_s)
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
        )
