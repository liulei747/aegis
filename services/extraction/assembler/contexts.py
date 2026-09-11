"""Stage: assemble analysis packages (the AI input atoms).

An :class:`AssembledContext` is one self-contained reasoning unit:

* the sink (static-scan hit location + rule + evidence),
* the call-graph slice around it (callers = entry side, callees = sink side),
* the full source of every method in that slice, deduplicated,
* every pruning decision that shaped it, so the model can say "coverage is
  incomplete here" instead of guessing.

Contexts are also *stable*: ids and order depend only on content, never on
timing, which keeps prompt prefixes reusable across runs and across the
per-context fan-out to sub-agents.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from aegis_contracts.domain import (
    CallEdge,
    Coverage,
    Finding,
    MethodContext,
    MethodRef,
    Provider,
    PruneDecision,
    Severity,
)
from aegis_core.config import BudgetConfig
from aegis_core.logging import get_logger
from aegis_core.utils import estimate_tokens, sha1
from services.extraction.assembler.reader import BodySet, MethodBody, refs_sorted
from services.extraction.graph.builder import FocusSlice

log = get_logger(__name__)

_SEVERITY_RANK = {
    Severity.ERROR: 0,
    Severity.WARNING: 1,
    Severity.INFO: 2,
    Severity.NOTE: 3,
}


@dataclass
class AssembledContext:
    context_id: str
    focus: MethodRef
    findings: list[Finding]
    refs: list[MethodRef]
    edges: list[CallEdge]
    bodies: dict[str, MethodBody]
    prunes: list[PruneDecision]
    aliases: dict[str, list[str]] = field(default_factory=dict)
    truncated: bool = False
    estimated_tokens: int = 0

    @property
    def total_chars(self) -> int:
        return sum(b.chars for b in self.bodies.values())

    @property
    def worst_severity(self) -> Severity:
        if not self.findings:
            return Severity.NOTE
        return min(self.findings, key=lambda f: _SEVERITY_RANK.get(f.severity, 4)).severity

    def to_model(self) -> MethodContext:
        return MethodContext(
            context_id=self.context_id,
            finding_ids=[f.finding_id for f in self.findings],
            focus_id=self.focus.method.method_id,
            focus=self.focus.method,
            methods=self.refs,
            edges=self.edges,
            total_chars=self.total_chars,
            estimated_tokens=self.estimated_tokens,
            truncated=self.truncated,
        )


@dataclass
class AssemblyResult:
    contexts: list[AssembledContext] = field(default_factory=list)
    bodies: BodySet = field(default_factory=BodySet)
    coverage: Coverage = field(default_factory=Coverage)
    prunes: list[PruneDecision] = field(default_factory=list)
    # content_hash -> the method whose body is the one we keep, bundle-wide.
    canonical_bodies: dict[str, str] = field(default_factory=dict)
    # method_id -> the method whose body replaces it (dropped from the bundle's
    # inline set because an identical one is already there).
    bundle_aliases: dict[str, str] = field(default_factory=dict)

    @property
    def inlined_bodies(self) -> dict[str, MethodBody]:
        """The unique bodies to inline into a prompt, deduplicated bundle-wide."""
        out: dict[str, MethodBody] = {}
        for context in self.contexts:
            for method_id, body in context.bodies.items():
                canonical = self.canonical_bodies.get(body.content_hash, method_id)
                out.setdefault(canonical, body)
        return out


class ContextAssembler:
    def __init__(self, budget: BudgetConfig) -> None:
        self.budget = budget

    def assemble(
        self,
        slices: list[FocusSlice],
        findings_by_id: dict[str, Finding],
        bodies: BodySet,
    ) -> AssemblyResult:
        result = AssemblyResult(bodies=bodies)
        self._bodies = bodies

        # Findings pointing at the same enclosing method collapse into one context.
        grouped: dict[str, list[FocusSlice]] = {}
        for slice_ in slices:
            grouped.setdefault(slice_.focus.method_id, []).append(slice_)

        ordered = sorted(
            grouped.values(),
            key=lambda group: _group_sort_key(group, findings_by_id),
        )
        kept: list[AssembledContext] = []
        for group in ordered:
            if len(kept) >= self.budget.max_contexts:
                result.prunes.append(
                    PruneDecision(
                        rule="max_contexts",
                        detail=f"context dropped: max_contexts={self.budget.max_contexts} reached",
                        method_id=group[0].focus.method_id,
                        path=group[0].focus.path,
                        line=group[0].focus.region.start_line,
                        provider=group[0].focus.provider,
                    )
                )
                continue
            kept.append(self._one(group, findings_by_id))
            if len(group) > 1:
                # Collapsed slices (same focus reached from several findings).
                result.coverage.deduped += len(group) - 1
        result.contexts = kept
        result.coverage.discoverable = sum(len(s.finding_ids) for s in slices)
        result.coverage.bundled = sum(len(c.findings) for c in kept)
        result.coverage.rejected = max(0, result.coverage.discoverable - result.coverage.bundled)
        result.prunes.extend(bodies.prunes)
        for context in kept:
            result.prunes.extend(context.prunes)
        _mark_bundle_level_duplicates(result)
        return result

    # ------------------------------------------------------------------
    def _one(
        self,
        group: list[FocusSlice],
        findings_by_id: dict[str, Finding],
    ) -> AssembledContext:
        primary = group[0]
        finding_ids: list[str] = []
        for slice_ in group:
            finding_ids.extend(slice_.finding_ids)
        findings = [findings_by_id[fid] for fid in finding_ids if fid in findings_by_id]

        refs: dict[str, MethodRef] = {}
        edges: list[CallEdge] = []
        prunes: list[PruneDecision] = []
        for slice_ in group:
            for method_id, ref in slice_.methods.items():
                existing = refs.get(method_id)
                if existing is None or ref.depth < existing.depth:
                    refs[method_id] = ref
            edges.extend(slice_.edges)
            prunes.extend(slice_.prunes)

        aliases: dict[str, list[str]] = {}
        inlined: dict[str, MethodBody] = {}
        by_hash: dict[str, str] = {}
        for method_id in sorted(refs):
            body = self._bodies.bodies.get(method_id)
            if body is None:
                continue
            owner = by_hash.get(body.content_hash)
            if owner is not None:
                # Byte-identical source: inline once, keep the other symbol as an alias.
                aliases.setdefault(owner, []).append(method_id)
                continue
            by_hash[body.content_hash] = method_id
            inlined[method_id] = body

        truncated = False
        for method_id, body in inlined.items():
            ref = refs[method_id]
            if body.truncated_chars or body.truncated_lines:
                truncated = True
                prunes.append(
                    PruneDecision(
                        rule="max_chars_per_method",
                        detail=(
                            "body truncated to "
                            f"{self.budget.max_lines_per_method} lines / "
                            f"{self.budget.max_chars_per_method} chars"
                        ),
                        method_id=method_id,
                        path=ref.method.path,
                        line=ref.method.region.start_line,
                        provider=ref.method.provider,
                    )
                )

        context_id = "C-" + sha1(
            primary.focus.method_id,
            ",".join(sorted(refs)),
            ",".join(sorted(f.finding_id for f in findings)),
            length=12,
        )
        context = AssembledContext(
            context_id=context_id,
            focus=refs.get(primary.focus.method_id, primary.methods[primary.focus.method_id]),
            findings=findings,
            refs=refs_sorted(list(refs.values())),
            edges=_dedupe_edges(edges),
            bodies=inlined,
            prunes=prunes,
            aliases=aliases,
            truncated=truncated,
        )
        context.estimated_tokens = estimate_tokens(
            "\n".join(b.text for b in inlined.values())
        ) + estimate_tokens("\n".join(e.call_site_snippet for e in context.edges))
        return context


def _mark_bundle_level_duplicates(result: AssemblyResult) -> None:
    """Decide, bundle-wide, which copy of each identical body we keep.

    Context-local dedupe is not enough: the same method can appear in several
    contexts (a helper reached from two different sinks), and then its source gets
    inlined once per context *and* once in the method catalog. That contradicts the
    whole point of dedupe — the model pays for the same text several times.

    Deterministic choice: the earliest method id in sort order wins, and every
    other copy is recorded as an alias so the reader still sees the symbol.
    """
    for context in result.contexts:
        for method_id, body in context.bodies.items():
            result.canonical_bodies.setdefault(body.content_hash, method_id)

    for context in result.contexts:
        for method_id, body in list(context.bodies.items()):
            canonical = result.canonical_bodies.get(body.content_hash, method_id)
            if canonical != method_id:
                result.bundle_aliases[method_id] = canonical
                context.aliases.setdefault(canonical, []).append(method_id)
                del context.bodies[method_id]


def _group_sort_key(group: list[FocusSlice], findings_by_id: dict[str, Finding]) -> tuple:
    first = group[0]
    severities = [
        _SEVERITY_RANK.get(findings_by_id[fid].severity, 4)
        for slice_ in group
        for fid in slice_.finding_ids
        if fid in findings_by_id
    ]
    worst = min(severities, default=4)
    syntax_penalty = 1 if first.focus.provider is Provider.SYNTAX_REGEX else 0
    return (-len(group), syntax_penalty, worst, first.focus.path, first.focus.region.start_line)


def _dedupe_edges(edges: list[CallEdge]) -> list[CallEdge]:
    seen: set[tuple[str, str, str]] = set()
    out: list[CallEdge] = []
    for edge in edges:
        key = (edge.caller_id, edge.callee_id, edge.direction.value)
        if key in seen:
            continue
        seen.add(key)
        out.append(edge)
    return out
