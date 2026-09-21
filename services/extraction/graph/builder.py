"""Call-graph expansion with an explicit, auditable budget.

This is the "去重、限制展开范围、保留来源" stage. Nothing is dropped silently:
every cap that bites emits a :class:`PruneDecision` naming the rule and the
offending node, so the bundle can explain its own coverage.
"""

from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Protocol

from aegis_contracts.dataflow import FlowBundle
from aegis_contracts.domain import (
    CallEdge,
    EdgeDirection,
    Finding,
    MethodRef,
    MethodSymbol,
    Provider,
    PruneDecision,
    SymbolKind,
)
from aegis_core.config import BudgetConfig
from aegis_core.logging import get_logger
from services.extraction.graph.providers import CallGraphResolver
from services.extraction.graph.resolver import Workspace

log = get_logger(__name__)


class DataflowProvider(Protocol):
    """Anything that can produce a taint trace for a workspace.

    A protocol rather than the concrete client so the graph layer does not import the
    dataflow service -- the same reason `TeardownHandle` exists in `aegis_core.cancel`. It
    also makes the builder testable with a stub instead of a JVM.

    `finding_path` / `finding_line` are how the provider learns where the rule fired, and they
    are the pipeline's **only** description of the endpoint: there is no sink to configure, so
    the provider derives its own anchor from that position and reports which one it chose.

    The three `source_*` arguments name the **source** end, which the finding cannot:
    `source_kind="parameter"` means "the value enters through `source_parameter` of
    `source_method`". This is what a caller walk hands over -- the sink's own position says
    nothing about where the data came from, and a method *name* passed as a call anchor resolves
    to the call site instead (measured: 0 flows, which reads as "proved unreachable").
    """

    def extract(
        self,
        *,
        force_build: bool = False,
        finding_path: str | None = None,
        finding_line: int | None = None,
        source_kind: str = "call",
        source_method: str = "",
        source_parameter: str = "",
    ) -> FlowBundle:  # pragma: no cover
        ...


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
    # Fan-out lookups a cap prevented from happening at all (depth/limit). These
    # are not "dropped methods" — we never asked — which is exactly why they need
    # their own counter: otherwise a truncated walk is indistinguishable from a
    # complete one in the funnel arithmetic.
    fanouts_skipped: int = 0
    # Which source anchor the dataflow engine was given, and the walk that chose it. A flow that
    # starts at an inner method *looks* complete (measured: 8 elements against 24), so the choice
    # has to travel with the slice for anyone reading the bundle to be able to check it.
    dataflow_anchor: dict = field(default_factory=dict)


_SYNTHETIC_MARK = "<"


def _is_synthetic(name: str) -> bool:
    """Is this a frontend artefact rather than a real method?

    pysrc2cpg/pyright create `<module>`, `<body>`, `<fakeNew>`, `<metaClassAdapter>` and the
    like. Measured, a walk that does not filter them climbs onto a synthesised class shim and
    stops there, and a "no callers" question about them is meaningless.
    """
    return name.startswith(_SYNTHETIC_MARK) or _SYNTHETIC_MARK in name


def _unlanded_detail(
    bundle: FlowBundle, *, missing_sink: bool, unmatched_sink: bool
) -> str:
    """Why an empty flow is a statement about the question and not about the code.

    Three sentences for three cases, because a reader deciding whether to trust the bundle has to
    be able to tell them apart: "no sink could be derived at all", "the sink we derived matches no
    call node", and "the source anchor matches no node". Each ends by saying what happened next --
    the slice fell back to the crawl -- because an empty flow that silently becomes an empty slice
    is the failure this wording exists to prevent.

    The frontend is appended when the bundle names one: "the anchor matched nothing" and "the graph
    was built in the wrong language" produce the same empty flow, and only this distinguishes them.
    """
    note = f"（图由 {bundle.frontend} 构建）" if bundle.frontend else ""
    if missing_sink:
        return (
            "无法解析出任何汇聚点锚点：没有告诉数据流引擎要找什么，"
            "而命中的位置也没有产出可调用的调用。这不是“不存在数据流”，"
            f"因此这个切片回退到调用方/被调用方爬取{note}"
        )
    if unmatched_sink:
        return (
            f"汇聚点锚点 `{bundle.sink_anchor}` 没有匹配到任何节点"
            f"（匹配到 {bundle.source_candidates} 个源）。空路径在这里只是"
            "“这个问题没有落在图上”，不能证明不存在数据流；"
            f"因此这个切片回退到调用方/被调用方爬取{note}"
        )
    return (
        f"来源锚点 `{bundle.source_anchor}` 没有匹配到任何节点"
        f"（其余候选：汇聚点 {bundle.sink_candidates} 个）。空路径在这里只是"
        "“这个问题没有落在图上”，不能证明不存在数据流；"
        f"因此这个切片回退到调用方/被调用方爬取{note}"
    )


class CallGraphBuilder:
    def __init__(
        self,
        workspace: Workspace,
        resolver: CallGraphResolver,
        budget: BudgetConfig,
        dataflow: DataflowProvider | None = None,
    ) -> None:
        self.workspace = workspace
        self.resolver = resolver
        self.budget = budget
        #: When set, the slice comes from a real dataflow trace instead of the crawl below.
        #: See `_build_from_dataflow` for why that matters.
        self.dataflow = dataflow
        self._walk_cache: dict[str, tuple[list[MethodSymbol], int]] = {}
        self._warmed_files: int | None = None

    # ------------------------------------------------------------------
    # the source end: walking up from the sink to where input enters
    # ------------------------------------------------------------------
    def _warm(self) -> int:
        """Warm the language server once per builder, and remember the number.

        `None` means "not warmed yet" and is deliberately distinct from `0` ("warmed, but the
        server answered for no file"), because `0` is the case where the walk's answers must not
        be believed.
        """
        if self._warmed_files is None:
            self._warmed_files = self.resolver.warm()
            log.info("dataflow: warmed %d file(s) before the caller walk", self._warmed_files)
        return self._warmed_files

    def walk_callers(self, focus: MethodSymbol, *, max_depth: int = 6,
                     limit: int = 20) -> tuple[list[MethodSymbol], int]:
        """Methods from the sink upwards, nearest first. `([focus], 0)` when there is no LSP.

        Cached per method id: the crawler asks the same questions repeatedly, and each step is a
        round trip to a language server.
        """
        if focus.method_id in self._walk_cache:
            return self._walk_cache[focus.method_id]
        warmed = self._warm()
        chain: list[MethodSymbol] = [focus]
        seen = {focus.method_id}
        level = [focus]
        depth = 0
        while level and depth < max_depth:
            next_level: list[MethodSymbol] = []
            for method in level:
                callers, _provider = self.resolver.callers(method, limit=limit)
                for caller, _edge in callers:
                    if caller.method_id in seen or _is_synthetic(caller.name):
                        continue
                    seen.add(caller.method_id)
                    next_level.append(caller)
                    chain.append(caller)
            level = next_level
            depth += 1
        self._walk_cache[focus.method_id] = (chain, warmed)
        return chain, warmed

    def _parameters_of(self, method: MethodSymbol) -> list[str]:
        """Parameter names, read from the `def` line.

        Not from the language server: measured, its callHierarchy item is
        `{name, kind, detail: "(file.py)", uri, range}` -- no parameter list -- and the resolver's
        `signature` comes out equal to the method name. Reading the definition line is cheap and
        the text is already cached.
        """
        text = self.workspace.read(method.path)
        if text is None:
            return []
        lines = text.splitlines()
        for line in lines[method.region.start_line: method.region.start_line + 3]:
            stripped = line.strip()
            if not stripped.startswith(("def ", "async def ")) or "(" not in stripped:
                continue
            inside = stripped.split("(", 1)[1].split(")", 1)[0]
            names = []
            for part in inside.split(","):
                part = part.strip().split("=")[0].strip().lstrip("*")
                if part and part not in ("self", "cls"):
                    names.append(part)
            return names
        return []

    def entry_anchor(self, focus: MethodSymbol) -> dict | None:
        """The `(kind, method, parameter)` to hand the dataflow provider, or None.

        The rule is "outermost real caller": walk up until the only callers left are frontend
        scaffolding (`<module>`, `<metaClassAdapter>`), then take that method's first non-self
        parameter. Measured on the demo, the walk is
        `query_user <- load_user <- handle_request <- dispatch` and the anchors it yields produce
        paths of 6 / 8 / 24 / 26 elements: only the outermost is the whole story, the inner ones
        start mid-chain and *look* complete.

        **Deliberately stops at a class method when that is where the call graph ends.** On the
        demo that is `Controller.dispatch`, one hop above the module-level `handle_request`, and
        a "prefer the outermost module-level function" refinement was considered and rejected:
        `Controller.dispatch` is the shape of a real HTTP entry (a class-based view or a
        dispatcher), so the method that nothing calls is the better answer than a function that
        something does. The walk is recorded in `dataflow_anchors.walk`, so the hop that a
        *different* choice would have added is still visible for audit -- and both anchors carry
        the sanitizer, so the judgement the model has to make does not depend on the choice.

        Returns None only when the walk cannot be trusted: no file was analysed, so "no callers"
        is not evidence of anything and the caller keeps the configured call anchor.
        """
        chain, warmed = self.walk_callers(focus)
        if warmed == 0:
            # Nothing was ever analysed, so zero callers means "we did not look", not "there is
            # no caller". Measured, believing it here anchors the flow at the sink's own method.
            log.warning("dataflow: caller walk warmed no file; keeping the configured call anchor")
            return None
        # `chain` always starts at the focus. When it is one long, the focus itself has no real
        # caller -- measured on single-function samples, where its parameter is the correct
        # anchor and yields a 4-6x longer path than the call anchor.
        entry = chain[-1]
        parameters = self._parameters_of(entry)
        return {
            "kind": "parameter",
            "method": entry.name,
            "parameter": parameters[0] if parameters else "",
            "walk": [method.name for method in chain],
            "entry": entry,
        }

    # ------------------------------------------------------------------
    def _build_from_dataflow(
        self,
        focus: MethodSymbol,
        slice_: FocusSlice,
        findings: list[Finding],
    ) -> FocusSlice | None:
        """Build the slice from a real taint trace instead of a graph crawl.

        Why this exists (measured, `docs/DATAFLOW_CONTRACT.md`): the crawl below freezes the
        direction a node was discovered with, so a method called by the sink's *caller* -- the
        classic sanitizer, and the one thing a reviewer must see -- is never visited, and no
        prune records the omission. In the demo repo that silently hid `safe_escape`, which is
        the single function that decides whether the finding is real.

        Returns None in two situations, both of which fall back to the crawl: the engine failed
        (recorded as `dataflow_unavailable`), and the question never landed on the graph (recorded
        as `dataflow_sink_unresolved`, `dataflow_sink_unmatched` or `dataflow_source_unmatched`).
        An empty flow where both anchors *did* land is the third case and is not a fallback: the
        engine proved the value never reaches the sink, so the focus stands alone and
        `dataflow_no_path` says why.
        """
        assert self.dataflow is not None
        try:
            # Hand over the FINDING's own position, not the focus method's start line. The
            # finding is reported on the dangerous expression (`repo.py:6`, the concatenation)
            # while the enclosing method starts earlier (`repo.py:4`); using the method's start
            # makes the derivation pick the first call in the body instead of the sink. Measured:
            # that mistake resolved the sink to `connect` on line 5 rather than `execute` on 7.
            finding_path = findings[0].path if findings else focus.path
            finding_line = (
                findings[0].region.start_line + 1 if findings
                else focus.region.start_line + 1
            )
            # Where does the data enter? The finding only says where the danger is. Without a
            # source the engine can only be asked "backwards", which it cannot do, so the sink's
            # own method is used instead -- and that returns a non-empty path with no source side
            # (measured: 6 elements, 1 file, against 24 across 4 for the entry's parameter).
            anchor = self.entry_anchor(focus)
            kwargs: dict = {"finding_path": finding_path, "finding_line": finding_line}
            if anchor is not None:
                kwargs.update(
                    source_kind=anchor["kind"],
                    source_method=anchor["method"],
                    source_parameter=anchor["parameter"],
                )
            bundle = self.dataflow.extract(**kwargs)
            slice_.dataflow_anchor = {
                "kind": anchor["kind"] if anchor else "call",
                "method": anchor["method"] if anchor else "",
                "parameter": anchor["parameter"] if anchor else "",
                "walk": anchor["walk"] if anchor else [],
                "warmed_files": self._warmed_files or 0,
            }
        except Exception as exc:  # noqa: BLE001 - a dataflow failure must degrade, not crash
            slice_.prunes.append(
                PruneDecision(
                    rule="dataflow_unavailable",
                    detail=(
                        f"数据流引擎无法给出答案（{type(exc).__name__}: {exc}）；"
                        "这个切片回退到调用方/被调用方爬取，而它看不到由汇聚点调用方发起的"
                        "净化函数"
                    ),
                    method_id=focus.method_id,
                    path=focus.path,
                    line=focus.region.start_line,
                    provider=focus.provider,
                )
            )
            return None

        if not bundle.reachable:
            # An empty flow has two meanings, and telling them the same way is a lie:
            #
            #   * **the question never landed on the graph** -- the source anchor matched no node,
            #     or the sink was never derived, or the derived sink matches no call node. The
            #     empty flow is then a statement about the *question*, not about the code;
            #   * **the engine proved there is no path** -- a source and a sink that both resolved,
            #     with no flow between them. That is a finding about the code.
            #
            # This is not academic. Measured on a Java project whose CPG was built by the Python
            # frontend (the harness records the same measurement in
            # `services/harness/tools/dataflow.py`): every question matched 0 nodes. Reporting that
            # as `dataflow_no_path` claimed "the value cannot reach the sink" -- a claim about code
            # the engine never read -- *and* returned `slice_`, which took away the LSP call graph
            # that was already working and left a single-method slice. So the unlanded cases name
            # themselves and fall through to the crawl.
            missing_sink = not bundle.sink_anchor
            unmatched_sink = not missing_sink and bundle.sink_candidates == 0
            unmatched_source = bundle.source_candidates == 0
            if missing_sink or unmatched_sink or unmatched_source:
                slice_.prunes.append(
                    PruneDecision(
                        rule=(
                            "dataflow_sink_unresolved"
                            if missing_sink
                            else "dataflow_sink_unmatched"
                            if unmatched_sink
                            else "dataflow_source_unmatched"
                        ),
                        detail=_unlanded_detail(
                            bundle, missing_sink=missing_sink, unmatched_sink=unmatched_sink
                        ),
                        method_id=focus.method_id,
                        path=focus.path,
                        line=focus.region.start_line,
                        provider=Provider.JOERN_DATAFLOW,
                    )
                )
                # None rather than `slice_`: the crawl below is material that already worked, and a
                # question that never landed on the graph is not a reason to take it away. The
                # prune stays on the slice, so the bundle still says the engine answered nothing.
                return None

            slice_.prunes.append(
                PruneDecision(
                    rule="dataflow_no_path",
                    detail=(
                        f"数据流引擎没有找到从 `{bundle.source_anchor}` 到 "
                        f"`{bundle.sink_anchor}` 的路径"
                        f"（匹配到 {bundle.source_candidates} 个源、"
                        f"{bundle.sink_candidates} 个汇聚点）：该值到不了汇聚点，"
                        "因此没有污点链可以交给模型"
                    ),
                    method_id=focus.method_id,
                    path=focus.path,
                    line=focus.region.start_line,
                    provider=Provider.JOERN_DATAFLOW,
                )
            )
            return slice_

        built = self._slice_from_flows(focus, slice_, bundle)
        if built is None:
            return None
        built.prunes.extend(self._dataflow_prunes(bundle, focus))
        return built

    def _slice_from_flows(
        self, focus: MethodSymbol, slice_: FocusSlice, bundle: FlowBundle
    ) -> FocusSlice | None:
        """Turn the method sequence of each flow into methods and edges on one slice."""
        # Resolve every method name the flow mentions, once.
        resolved: dict[str, MethodSymbol] = {}
        for name in bundle.path_methods:
            symbol = self._resolve_flow_method(bundle, name)
            if symbol is not None:
                resolved[name] = symbol
        if not resolved:
            return None

        # Which method holds the sink? That is the focus, even if the crawler located the
        # finding elsewhere -- the sink is where the path ends.
        sink_method: str | None = None
        for flow in bundle.flows:
            for element in reversed(flow.elements):
                if element.method:
                    sink_method = element.method
                    break
            if sink_method:
                break
        focus_name = sink_method if sink_method in resolved else None
        if focus_name is None:
            focus_name = next(
                (name for name in bundle.path_methods if resolved[name].method_id
                 == focus.method_id),
                bundle.path_methods[0] if bundle.path_methods else None,
            )
        if focus_name is None:
            return None

        # Depth = number of method boundaries crossed from the focus, following the flow.
        # The focus itself is depth 0 and gets is_focus; the source end has the largest depth.
        depths: dict[str, int] = {focus_name: 0}
        for flow in bundle.flows:
            sequence = [e.method for e in flow.elements if e.method]
            if focus_name not in sequence:
                continue
            pivot = max(index for index, name in enumerate(sequence) if name == focus_name)
            for offset, name in enumerate(sequence[:pivot + 1][::-1]):
                depths[name] = min(depths.get(name, offset), offset)

        # focus first so the renderer's ordering is not at the mercy of dict insertion order.
        ordered = sorted(resolved.items(), key=lambda kv: (depths.get(kv[0], 999), kv[0]))
        # Name the source end the engine was actually given. Without it the reader (and the
        # model) cannot tell a complete path from one that starts mid-chain: measured, an inner
        # anchor yields 8 elements where the entry's parameter yields 24, and both render as a
        # tidy chain.
        source_note = (
            f"数据流来自 {bundle.source_expr}"
            if bundle.source_expr
            else "数据流路径来自已配置的源"
        )
        # It also goes on the FOCUS, not only on the source-side methods. A single-function
        # sample has no source-side refs at all (the sink's method *is* the entry), so without
        # this the prompt never states which anchor the flow was analysed from -- the one thing a
        # reader needs to tell "the value enters here" from "we started in the middle".
        focus_via = "静态扫描命中位置"
        if bundle.source_expr:
            focus_via = f"{focus_via}; {source_note}"
        for name, symbol in ordered:
            depth = depths.get(name, 0)
            slice_.methods[symbol.method_id] = MethodRef(
                method=symbol,
                provider=Provider.JOERN_DATAFLOW,
                depth=depth,
                # Everything on the source side of the focus is "who calls this"; anything on
                # the sink side is "what this calls". A flow can have both.
                direction=(
                    EdgeDirection.CALLER if depth > 0 else None
                ),
                origin_path=[resolved[focus_name].method_id, symbol.method_id],
                via=(
                    source_note
                    if depth > 0
                    else focus_via
                ),
                is_focus=(name == focus_name),
            )
        return slice_

    def _resolve_flow_method(self, bundle: FlowBundle, name: str) -> MethodSymbol | None:
        """Map a bare method name from the flow onto a MethodSymbol, using the flow's own
        file+line as the locator so the symbol matches what the reader will read."""
        for flow in bundle.flows:
            for element in flow.elements:
                if element.method != name or not element.file:
                    continue
                line = element.line_number
                if line is None:
                    continue
                found = self.resolver.locate_method(element.file, max(0, line - 1), 0)
                if found is not None:
                    return found[0]
        return self.workspace.find_local_method(name)

    @staticmethod
    def _dataflow_prunes(bundle: FlowBundle, focus: MethodSymbol) -> list[PruneDecision]:
        """Say out loud what the path does not cover, so an incomplete flow is never silent."""
        prunes: list[PruneDecision] = []
        if len(bundle.flows) > 1:
            prunes.append(
                PruneDecision(
                    rule="dataflow_multiple_paths",
                    detail=(
                        f"引擎返回了 {len(bundle.flows)} 条不同的源->汇聚点路径；"
                        "它们全部被包含，因此方法集合是它们的并集"
                    ),
                    method_id=focus.method_id,
                    path=focus.path,
                    line=focus.region.start_line,
                    provider=Provider.JOERN_DATAFLOW,
                )
            )
        if len(bundle.flows) > bundle.sink_candidates * max(1, bundle.source_candidates):
            prunes.append(
                PruneDecision(
                    rule="dataflow_truncated",
                    detail=(
                        f"{bundle.source_candidates} 个源 x {bundle.sink_candidates} 个汇聚点"
                        f"可能产出比这里报告的 {len(bundle.flows)} 条更多的路径；"
                        "引擎并不承诺给出的集合是穷尽的"
                    ),
                    method_id=focus.method_id,
                    path=focus.path,
                    line=focus.region.start_line,
                    provider=Provider.JOERN_DATAFLOW,
                )
            )
        return prunes

    # ------------------------------------------------------------------
    def build(self, focus: MethodSymbol, findings: list[Finding]) -> FocusSlice:
        """Assemble the slice around the focus.

        Dispatcher: a dataflow trace when the engine is configured, otherwise the crawl. The
        crawl stays the default because it needs no JVM, and it stays reachable even with the
        engine on -- a dataflow failure must degrade to it rather than lose the slice.
        """
        started = time.perf_counter()
        slice_ = FocusSlice(focus=focus, finding_ids=[f.finding_id for f in findings])
        slice_.methods[focus.method_id] = MethodRef(
            method=focus,
            provider=focus.provider,
            depth=0,
            origin_path=[focus.method_id],
            is_focus=True,
            via="静态扫描命中位置",
        )

        if self.dataflow is not None:
            built = self._build_from_dataflow(focus, slice_, findings)
            if built is not None:
                built.edges = _dedupe_edges(built.edges)
                log.debug(
                    "slice built from dataflow: %s methods=%d edges=%d in %.0fms",
                    focus.qualified_name, len(built.methods), len(built.edges),
                    (time.perf_counter() - started) * 1000,
                )
                return built
            # else: fall through to the crawl, which the dataflow path already recorded.

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
                slice_.fanouts_skipped += 1
                slice_.prunes.append(
                    PruneDecision(
                        rule="max_depth",
                        detail=(
                            f"停在深度 {depth}（上限 {self.budget.max_depth}）："
                            f"{method.qualified_name} 的"
                            f"{'调用方' if direction is EdgeDirection.CALLER else '被调用方'}"
                            "从未被查找过，因此它们不在这个分析包里"
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
                # explored. Count it separately from a refused node: no method was
                # dropped here, we simply never looked.
                slice_.fanouts_skipped += 1
                slice_.prunes.append(
                    PruneDecision(
                        rule="max_nodes",
                        detail=(
                            f"分析包已持有 {len(slice_.methods)} 个方法（上限 "
                            f"{self.budget.max_nodes}）：{method.qualified_name} 的"
                            f"{'调用方' if direction is EdgeDirection.CALLER else '被调用方'}"
                            "从未被收集"
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
                            detail="方法被丢弃：节点预算已耗尽",
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
                            f"最多保留 {method.qualified_name} 的 {limit} 个"
                            f"{'调用方' if direction is EdgeDirection.CALLER else '被调用方'}"
                            "，且已达到该上限"
                            f"（例如保留了 {kept_names}）；它可能还有更多"
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
                                detail="实现被丢弃：节点预算已耗尽",
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
                        via=f"实现 {method.qualified_name}",
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
