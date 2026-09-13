"""The AI stage's contract: what the model must answer, and what we store about the call.

The prompt (`services/extraction/assembler/render.py`, "Required output") demands **one JSON
object and nothing else** with exactly nine keys. This module is that demand as a type, so a
malformed answer is a reported gap rather than a silent hole in the artifact.

Two deliberate asymmetries:

* the **raw answer is kept** next to the parsed one. A verdict you cannot trace back to the
  model's own words is not evidence;
* a **parse failure is a result**, not an exception. Losing the model's answer because it wrapped
  it in prose would throw away the only intelligence the call produced.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class VerdictKind(str, Enum):
    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    NEEDS_MORE_CONTEXT = "needs_more_context"


class VerdictSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFORMATIONAL = "informational"


#: Every key the instructions demand, in the order they list them. A verdict missing one of
#: these is still stored -- but the omission is recorded, because "the model did not say" and
#: "the model said nothing was missing" are different answers.
REQUIRED_VERDICT_FIELDS: tuple[str, ...] = (
    "verdict",
    "severity",
    "confidence",
    "reachability",
    "chain",
    "data_flow",
    "evidence",
    "missing",
    "fix",
)

#: The three without which the answer is not a verdict at all.
DECISIVE_VERDICT_FIELDS: tuple[str, ...] = ("verdict", "severity", "confidence")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Verdict(BaseModel):
    """One model answer about one context."""

    verdict: VerdictKind
    severity: VerdictSeverity
    confidence: float = Field(ge=0.0, le=1.0)
    #: Free text from here down: the instructions ask for strings, and constraining their shape
    #: would push the model into writing less than it knows.
    #:
    #: `severity_qualifier` is not decoration. The instructions *tell* the model to put the
    #: conditional reasoning in the severity string ("if your severity depends on something
    #: unproven, say so in `severity` itself"), so `"high -- impact depends on X"` is a correct
    #: answer. The enum above is the category read off the front; this keeps the rest, because
    #: dropping it would throw away the model's own caveat about its own answer.
    severity_qualifier: str = ""
    reachability: str = ""
    chain: list[str] = Field(default_factory=list)
    data_flow: str = ""
    evidence: list[str] = Field(default_factory=list)
    missing: list[str] = Field(default_factory=list)
    fix: str = ""


class TokenUsage(BaseModel):
    """Whatever the provider reported, plus the cache fields named the way each provider names
    them. Two keys exist because two providers disagree: `prompt_cache_hit_tokens` (DeepSeek)
    versus `prompt_tokens_details.cached_tokens` (OpenAI-compatible others). Normalising them
    here is what makes "the prefix cache actually hit" a measurement instead of a belief.
    """

    prompt_tokens: int | None = None
    completion_tokens: int | None = None
    total_tokens: int | None = None
    cached_tokens: int | None = None
    raw: dict[str, Any] = Field(default_factory=dict)

    @property
    def cache_hit_ratio(self) -> float | None:
        """Share of the **input** that was served from cache, or None when unreported."""
        if not self.prompt_tokens or self.cached_tokens is None:
            return None
        return self.cached_tokens / self.prompt_tokens


class AICall(BaseModel):
    """One round trip, recorded whether or not it produced a verdict."""

    context_id: str | None = Field(
        default=None,
        description="Which context this call was about; None means the bundle was sent whole.",
    )
    model: str = ""
    endpoint: str = ""
    called_at: datetime = Field(default_factory=_utcnow)
    elapsed_s: float = 0.0
    usage: TokenUsage | None = None
    parsed: bool = False
    #: Why the answer could not be used as a verdict, when it could not.
    error: str | None = None
    #: Which of the demanded keys the model left out.
    missing_fields: list[str] = Field(default_factory=list)
    verdict: Verdict | None = None
    #: The model's own words. Kept on the call, and also written beside the bundle.
    raw_answer: str = ""


class AIReport(BaseModel):
    """What the AI stage did for one bundle."""

    bundle_id: str
    model: str = ""
    endpoint: str = ""
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    calls: list[AICall] = Field(default_factory=list)
    #: Set when the stage did not run at all (not configured, no contexts). A run that ran and
    #: failed per call says so through `calls`, not here.
    skipped: str | None = None

    @property
    def parsed_calls(self) -> list[AICall]:
        return [call for call in self.calls if call.parsed]

    @property
    def failed_calls(self) -> list[AICall]:
        return [call for call in self.calls if not call.parsed]

    def verdict_for(self, context_id: str) -> Verdict | None:
        for call in self.calls:
            if call.context_id == context_id and call.verdict is not None:
                return call.verdict
        return None
