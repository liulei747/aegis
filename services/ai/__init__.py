"""The AI stage: one model call per analysis context, over an OpenAI-compatible endpoint.

The pipeline produces a bundle whose `ai/` directory is a finished prompt. This package spends
it: `blocks` reads that directory the way the contract says to, `client` performs one round trip,
`parse` turns the answer into a `Verdict` without ever discarding it, and `runner` fans the calls
out and writes the verdicts back beside the bundle.
"""

from __future__ import annotations

from services.ai.blocks import (
    BlocksUnavailable,
    context_ids,
    read_blocks,
    read_prefix_ids,
    system_text,
    user_text,
    volatile_blocks,
)
from services.ai.client import AIError, AIUnavailable, ChatClient, ChatResult
from services.ai.parse import parse_verdict
from services.ai.runner import (
    AINotConfigured,
    analyse_bundle,
    call_with_retries,
    client_from,
    write_report,
)

__all__ = [
    "AIError",
    "AINotConfigured",
    "AIUnavailable",
    "BlocksUnavailable",
    "ChatClient",
    "ChatResult",
    "analyse_bundle",
    "call_with_retries",
    "client_from",
    "context_ids",
    "parse_verdict",
    "read_blocks",
    "read_prefix_ids",
    "system_text",
    "user_text",
    "volatile_blocks",
    "write_report",
]
