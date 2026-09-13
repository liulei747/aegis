"""Reading a bundle's AI blocks the way the contract says to read them.

Never by re-parsing `prompt.md`. `ai/blocks.jsonl` is the machine-readable form, and
`ai/cache_prefix.json` says where the reusable prefix ends -- the part that holds still across
bundles from the same workspace, which is what makes provider-side caching possible at all.
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis_contracts.domain import PromptBlock


class BlocksUnavailable(RuntimeError):
    """The bundle has no usable `ai/` directory."""


def read_blocks(bundle: Path) -> list[PromptBlock]:
    path = bundle / "ai" / "blocks.jsonl"
    if not path.is_file():
        raise BlocksUnavailable(f"not a bundle with an ai/ directory: {bundle}")
    blocks: list[PromptBlock] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            blocks.append(PromptBlock.model_validate(json.loads(line)))
    return blocks


def read_prefix_ids(bundle: Path) -> list[str]:
    """Which block ids are the reusable prefix. Empty when the file is absent or unreadable."""
    path = bundle / "ai" / "cache_prefix.json"
    if not path.is_file():
        return []
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return []
    return [str(item) for item in (document.get("prefix_blocks") or [])]


def system_text(blocks: list[PromptBlock], prefix_ids: list[str]) -> str:
    """Everything up to and including the prefix: instructions, legend, method catalog.

    Sent as the system message, byte-identical across bundles of the same workspace, so a
    provider can cache it. Nothing is rewritten or summarised on the way out.
    """
    return "\n\n---\n\n".join(b.content for b in blocks if b.block_id in prefix_ids)


def volatile_blocks(blocks: list[PromptBlock], prefix_ids: list[str]) -> list[PromptBlock]:
    """The per-bundle remainder: fan-out plan, this bundle's contexts, run notes."""
    return [b for b in blocks if b.block_id not in prefix_ids]


def context_ids(volatile: list[PromptBlock]) -> list[str]:
    return [b.block_id for b in volatile if b.block_id.startswith("context.")]


def user_text(bundle_id: str, volatile: list[PromptBlock], *, only: str | None) -> str:
    """The user message for one call.

    `only=None` sends the whole remainder in one message (useful for a cheap look and for
    gateways that handle a big prompt fine). Naming a context narrows the call to that one unit:
    one sub-agent per context is the intended fan-out, and it is what keeps a 200-context bundle
    from becoming one unreadable wall of text.
    """
    if only is None:
        return "\n\n---\n\n".join(b.content for b in volatile)

    kept = [b for b in volatile if b.block_id == only or not b.block_id.startswith("context.")]
    if not any(b.block_id == only for b in kept):
        available = [b.block_id for b in volatile if b.block_id.startswith("context.")]
        raise BlocksUnavailable(
            f"no such context: {only}\navailable: {', '.join(available) or '(none)'}"
        )
    # Every other context is dropped: this call is about one unit of work.
    kept = [b for b in kept if not b.block_id.startswith("context.") or b.block_id == only]
    header = f"# Aegis analysis bundle {bundle_id}\nanalysing context: {only}\n"
    return header + "\n\n---\n\n".join(b.content for b in kept)
