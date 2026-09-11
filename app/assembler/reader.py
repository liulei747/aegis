"""Stage: read full method bodies.

Bodies are read by slicing the *file bytes* using the offsets the LSP gave us —
no re-parsing, no re-request. Reading is parallel, ordered, and cache-friendly:
the same method reached from five findings is read once and stored once, which
is what makes the later prompt layout prefix-stable (good for provider-side
prompt caching).
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field

from aegis_contracts.domain import MethodRef, MethodSymbol, Provider, PruneDecision
from aegis_core.config import BudgetConfig
from aegis_core.logging import get_logger
from aegis_core.utils import clamp_text, content_hash, estimate_tokens
from app.graph.builder import FocusSlice
from app.graph.resolver import Workspace

log = get_logger(__name__)


@dataclass
class MethodBody:
    method: MethodSymbol
    text: str
    content_hash: str
    chars: int
    lines: int
    tokens: int
    truncated_chars: bool = False
    truncated_lines: bool = False
    sources: list[str] = field(default_factory=list)


@dataclass
class BodySet:
    bodies: dict[str, MethodBody] = field(default_factory=dict)
    prunes: list[PruneDecision] = field(default_factory=list)

    @property
    def total_chars(self) -> int:
        return sum(b.chars for b in self.bodies.values())

    @property
    def total_tokens(self) -> int:
        return sum(b.tokens for b in self.bodies.values())


class MethodReader:
    def __init__(self, workspace: Workspace, budget: BudgetConfig) -> None:
        self.workspace = workspace
        self.budget = budget
        self._focus_ids: set[str] = set()

    async def read_slices(self, slices: list[FocusSlice]) -> BodySet:
        """Read every distinct method once, concurrently."""
        wanted: dict[str, MethodSymbol] = {}
        self._focus_ids = {
            ref.method.method_id
            for slice_ in slices
            for ref in slice_.methods.values()
            if ref.is_focus
        }
        for slice_ in slices:
            for ref in slice_.methods.values():
                wanted.setdefault(ref.method.method_id, ref.method)

        semaphore = asyncio.Semaphore(self.budget.expand_concurrency)

        async def one(method: MethodSymbol) -> MethodBody | None:
            async with semaphore:
                return await asyncio.to_thread(self._read_one, method)

        results = await asyncio.gather(*(one(m) for m in wanted.values()))
        body_set = BodySet()
        for method, body in zip(wanted.values(), results, strict=False):
            if body is None:
                body_set.prunes.append(
                    PruneDecision(
                        rule="unreadable",
                        detail="method body could not be read from disk",
                        method_id=method.method_id,
                        path=method.path,
                        line=method.region.start_line,
                        provider=method.provider,
                    )
                )
                continue
            body_set.bodies[method.method_id] = body

        self._apply_global_budget(body_set)
        log.info(
            "bodies read: %d unique methods, %d chars",
            len(body_set.bodies),
            body_set.total_chars,
        )
        return body_set

    # ------------------------------------------------------------------
    def _read_one(self, method: MethodSymbol) -> MethodBody | None:
        text = self.workspace.read(method.path)
        if text is None:
            return None
        start, end = method.region.start_offset, method.region.end_offset
        if start is None or end is None:
            slice_text = self.workspace.slice_lines(
                method.path, method.region.start_line, method.region.end_line
            )
            snippet = slice_text or ""
        else:
            snippet = text[start:end]
            if not snippet.strip():
                fallback = self.workspace.slice_lines(
                    method.path, method.region.start_line, method.region.end_line
                )
                snippet = fallback or snippet
        # Canonical form for hashing and for handing over: no trailing whitespace at
        # all, then exactly one terminating newline. Without the full strip, a range
        # that happens to end one byte later (say, just past the file's final newline)
        # yields a different content hash for byte-identical code, and content-based
        # dedupe silently stops working across providers.
        snippet = snippet.rstrip("\n").rstrip() + ("\n" if snippet.strip() else "")
        clamped, cut_chars, cut_lines = clamp_text(
            snippet, self.budget.max_chars_per_method, self.budget.max_lines_per_method
        )
        return MethodBody(
            method=method,
            text=clamped,
            content_hash=content_hash(clamped),
            chars=len(clamped),
            lines=clamped.count("\n"),
            tokens=estimate_tokens(clamped),
            truncated_chars=cut_chars,
            truncated_lines=cut_lines,
        )

    def _apply_global_budget(self, body_set: BodySet) -> None:
        """Drop the least valuable bodies once the whole bundle is over budget.

        Focus (sink-containing) bodies are never dropped: they are the reason the
        bundle exists. If the budget cannot even hold those, the cap is reported
        as exceeded rather than silently gutting the analysis.
        """
        remaining = self.budget.max_total_chars
        if body_set.total_chars <= remaining:
            return
        droppable = sorted(
            (b for b in body_set.bodies.values() if b.method.method_id not in self._focus_ids),
            key=lambda b: (b.method.provider is Provider.SYNTAX_REGEX, b.chars),
        )
        for body in droppable:
            if body_set.total_chars <= remaining:
                break
            del body_set.bodies[body.method.method_id]
            body_set.prunes.append(
                PruneDecision(
                    rule="max_total_chars",
                    detail=(
                        "method body dropped to respect max_total_chars="
                        f"{self.budget.max_total_chars}"
                    ),
                    method_id=body.method.method_id,
                    path=body.method.path,
                    line=body.method.region.start_line,
                    provider=body.method.provider,
                )
            )
        if body_set.total_chars > remaining:
            body_set.prunes.append(
                PruneDecision(
                    rule="max_total_chars_exceeded",
                    detail=(
                        f"focus bodies alone total {body_set.total_chars} chars, above "
                        f"max_total_chars={self.budget.max_total_chars}; raise the budget or "
                        "split the run"
                    ),
                    provider=Provider.NONE,
                )
            )


def skeleton_body(method: MethodSymbol) -> str:
    """A cheap placeholder for methods referenced but not inlined."""
    return f"// {method.qualified_name} @ {method.path}:{method.region.start_line + 1} (not inlined)"


def dedupe_index(body_set: BodySet) -> dict[str, list[str]]:
    """content_hash -> method_ids sharing identical source."""
    index: dict[str, list[str]] = {}
    for body in body_set.bodies.values():
        index.setdefault(body.content_hash, []).append(body.method.method_id)
    return index


def refs_sorted(refs: list[MethodRef]) -> list[MethodRef]:
    return sorted(refs, key=lambda r: (not r.is_focus, r.depth, r.method.path, r.method.region.start_line))
