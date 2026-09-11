"""Call-graph expansion with an explicit, auditable budget.

This is the "去重、限制展开范围、保留来源" stage. Nothing is dropped silently:
every cap that bites emits a :class:`PruneDecision` naming the rule and the
offending node, so the bundle can explain its own coverage.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field

from app.core.config import BudgetConfig
from app.core.logging import get_logger
from app.graph.providers import CallGraphResolver
from app.graph.resolver import Workspace
from app.schemas.domain import (
    CallEdge,
    EdgeDirection,
    Finding,
    MethodRef,
    MethodSymbol,
    Provider,
    PruneDecision,
    SymbolKind,
)

log = get_logger(__name__)


@dataclass
class FocusSlice:
    """One sink plus the call-graph slice assembled around it."""

    focus: MethodSymbol
    finding_ids: list[str] = field(default_factory=list)
    methods: dict[str, MethodRef] = field(default_factory=dict)
    edges: list[CallEdge] = field(default_factory=list)
    prunes: list[PruneDecision] = field(default_factory=list)
    degraded_providers: set[str] = field(default_factory=set)
    # Methods the walk reached but a cap refused to keep. Without this the caps
    # look like they never fired: a dropped method never enters ``methods``.
    methods_dropped: int = 0


class CallGraphBuilder:
    def __init__(
        self,
        workspace: Workspace,
        resolver: CallGraphResolver,
        budget: BudgetConfig,
    ) -> None:
        self.workspace = workspace
        self.resolver = resolver
        self.budget = budget

    # ------------------------------------------------------------------
    def build(self, focus: MethodSymbol, findings: list[Finding]) -> FocusSlice:
        started = time.perf_counter()
        slice_ = FocusSlice(focus=focus, finding_ids=[f.finding_id for f in findings])
        slice_.methods[focus.method_id] = MethodRef(
            method=focus,
            provider=focus.provider,
            depth=0,
            origin_path=[focus.method_id],
            is_focus=True,
            via="static-scan hit location",
        )

        queue: deque[tuple[MethodSymbol, int, EdgeDirection]] = deque()
        queue.append((focus, 0, EdgeDirection.CALLEE))
        queue.append((focus, 0, EdgeDirection.CALLER))
        expanded: set[tuple[str, EdgeDirection]] = set()

        while queue:
            method, depth, direction = queue.popleft()
            if depth >= self.budget.max_depth:
                # Be honest about what this cost us: the node's fan-out was never
                # requested, so whatever it calls (or is called by) is absent from
                # the bundle. A prune that only says "the walk stopped here" cannot
                # answer "what is missing", which is the whole point of recording it.
                slice_.prunes.append(
                    PruneDecision(
                        rule="max_depth",
                        detail=(
                            f"stopped at depth {depth} (limit {self.budget.max_depth}): "
                            f"the "
                            f"{'callers' if direction is EdgeDirection.CALLER else 'callees'} "
                            f"of {method.qualified_name} were never looked up, so they are "
                            f"absent from this bundle"
                        ),
                        method_id=method.method_id,
                        path=method.path,
                        line=method.region.start_line,
                        provider=method.provider,
                    )
                )
                continue
            if (method.method_id, direction) in expanded:
                continue
            expanded.add((method.method_id, direction))

            remaining = self.budget.max_nodes - len(slice_.methods)
            if remaining <= 0:
                # The cap is already reached, so this node's fan-out is never
                # explored. Count it: "we would have walked further here".
                slice_.methods_dropped += 1
                slice_.prunes.append(
                    PruneDecision(
                        rule="max_nodes",
                        detail=(
                            f"bundle holds {len(slice_.methods)} methods (limit "
                            f"{self.budget.max_nodes}): the "
                            f"{'callers' if direction is EdgeDirection.CALLER else 'callees'} "
                            f"of {method.qualified_name} were never collected"
                        ),
                        method_id=method.method_id,
                        path=method.path,
                        provider=method.provider,
                    )
                )
                break

            per_node = (
                self.budget.max_callers_per_node
                if direction is EdgeDirection.CALLER
                else self.budget.max_callees_per_node
            )
            limit = max(0, min(per_node, remaining))
            if direction is EdgeDirection.CALLER:
                neighbours, provider = self.resolver.callers(method, limit=limit)
            else:
                neighbours, provider = self.resolver.callees(method, limit=limit)
            if provider is Provider.NONE and method.provider is Provider.SYNTAX_REGEX:
                slice_.degraded_providers.add("lsp_unavailable")

            for symbol, edge in neighbours:
                is_new = symbol.method_id not in slice_.methods
                if is_new and len(slice_.methods) >= self.budget.max_nodes:
                    slice_.methods_dropped += 1
                    slice_.prunes.append(
                        PruneDecision(
                            rule="max_nodes",
                            detail="method dropped: node budget exhausted",
                            method_id=symbol.method_id,
                            path=symbol.path,
                            line=symbol.region.start_line,
                            provider=symbol.provider,
                        )
                    )
                    continue
                if is_new:
                    parent_path = slice_.methods[method.method_id].origin_path
                    slice_.methods[symbol.method_id] = MethodRef(
                        method=symbol,
                        provider=edge.provider,
                        depth=depth + 1,
                        direction=direction,
                        origin_path=[*parent_path, symbol.method_id],
                        via=edge.call_site_snippet or edge.notes,
                    )
                    queue.append((symbol, depth + 1, direction))
                slice_.edges.append(edge)

            # ``len(neighbours) >= limit`` only means "the resolver handed back as
            # many as we asked for" — more may or may not exist. Say exactly that,
            # and name the fan-out pressure so a reader knows where to raise a cap.
            if limit > 0 and len(neighbours) >= limit:
                kept_names = ", ".join(s.qualified_name for s, _ in neighbours[:3])
                slice_.prunes.append(
                    PruneDecision(
                        rule=(
                            "max_callers_per_node"
                            if direction is EdgeDirection.CALLER
                            else "max_callees_per_node"
                        ),
                        detail=(
                            f"kept at most {limit} "
                            f"{'callers' if direction is EdgeDirection.CALLER else 'callees'}"
                            f" of {method.qualified_name} and the limit was reached"
                            f" (kept e.g. {kept_names}); it may have more"
                        ),
                        method_id=method.method_id,
                        path=method.path,
                        provider=method.provider,
                    )
                )

        self._attach_implementations(slice_)
        slice_.edges = _dedupe_edges(slice_.edges)
        log.debug(
            "slice built: %s methods=%d edges=%d in %.0fms",
            focus.qualified_name,
            len(slice_.methods),
            len(slice_.edges),
            (time.perf_counter() - started) * 1000,
        )
        return slice_

    # ------------------------------------------------------------------
    def _attach_implementations(self, slice_: FocusSlice) -> None:
        """Abstract targets matter for taint analysis: resolve dispatch targets."""
        if self.budget.max_implementations <= 0:
            return
        candidates = [
            ref.method
            for ref in slice_.methods.values()
            if ref.method.kind in {SymbolKind.METHOD, SymbolKind.FUNCTION}
        ]
        for method in candidates:
            impls = self.resolver.implementations(method, limit=self.budget.max_implementations)
            if not impls:
                continue
            for impl in impls:
                if impl.method_id not in slice_.methods:
                    if len(slice_.methods) >= self.budget.max_nodes:
                        slice_.methods_dropped += 1
                        slice_.prunes.append(
                            PruneDecision(
                                rule="max_nodes",
                                detail="implementation dropped: node budget exhausted",
                                method_id=impl.method_id,
                                path=impl.path,
                                provider=impl.provider,
                            )
                        )
                        continue
                    slice_.methods[impl.method_id] = MethodRef(
                        method=impl,
                        provider=Provider.LSP_IMPLEMENTATION,
                        depth=1,
                        direction=EdgeDirection.CALLEE,
                        origin_path=[
                            *slice_.methods[method.method_id].origin_path,
                            impl.method_id,
                        ],
                        via=f"implements {method.qualified_name}",
                    )
                slice_.edges.append(
                    CallEdge(
                        caller_id=method.method_id,
                        callee_id=impl.method_id,
                        direction=EdgeDirection.CALLEE,
                        provider=Provider.LSP_IMPLEMENTATION,
                        confidence=0.8,
                        notes=f"dispatch target of {method.qualified_name}",
                    )
                )


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
