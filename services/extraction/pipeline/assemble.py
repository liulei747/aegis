"""The assembly pipeline.

    opengrep hit
        -> locate enclosing method (LSP documentSymbol, syntax fallback)
        -> expand the call graph (LSP call hierarchy / definition / implementation)
        -> read the complete methods
        -> dedupe, bound, keep provenance
        -> assemble contexts + render the AI bundle
        -> package on disk

Every stage is timed, every degradation is recorded, and no single failure
aborts the run: a bundle with fewer methods and an honest ``degradations`` list
is more useful than an exception.
"""

from __future__ import annotations

import asyncio
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from aegis_contracts.domain import (
    AnalysisBundle,
    AnalysisBundleManifest,
    Degradation,
    Finding,
    MethodSymbol,
    Provider,
    PruneDecision,
    RunStats,
    ScanRecord,
)
from aegis_core.cancel import CanceledAbort, TeardownHandle
from aegis_core.config import BudgetConfig, Settings
from aegis_core.logging import get_logger
from aegis_core.utils import sha1
from aegis_core.workspace import workspace_digest
from services.extraction.assembler.contexts import AssemblyResult, ContextAssembler
from services.extraction.assembler.package import BundlePackager, write_text
from services.extraction.assembler.reader import MethodReader
from services.extraction.assembler.render import BundleRenderer
from services.extraction.graph.builder import CallGraphBuilder, DataflowProvider, FocusSlice
from services.extraction.graph.providers import CallGraphResolver
from services.extraction.graph.resolver import SymbolIndex, Workspace
from services.extraction.lsp.manager import LanguageServerManager, load_catalog
from services.extraction.pipeline.ids import compute_bundle_id
from services.scan.client import run_scan_anywhere
from services.scan.runner import ScanRequest, parse_sarif
from services.scan.scanrecord import build_scan_record

log = get_logger(__name__)


@dataclass
class StageEvent:
    """One thing that happened, addressed to whoever is watching this run.

    Named for the pipeline's own segments (the keys of ``RunStats.stage_ms``), which are
    *time*; the funnel's nine steps are *counts* and only some of them become knowable at
    each boundary. ``counters`` therefore carries whichever funnel steps are ready when
    the event fires -- never a guess, because a number that arrives early and wrong is
    worse than one that arrives late (see ``docs/QUEUE_PLAN.md`` §3).
    """

    stage: str
    phase: str  # "start" | "end"
    ms: int | None = None
    counters: dict[str, int] = field(default_factory=dict)
    units_done: int = 0
    units_total: int = 0
    unit_label: str = ""
    note: str | None = None


Observer = Callable[[StageEvent], None]
AbortCheck = Callable[[], bool]


@dataclass
class PipelineRequest:
    workspace: Path
    sarif_path: Path | None = None
    rules: list[str] = field(default_factory=list)
    rule_config: str | None = None
    include_globs: list[str] = field(default_factory=list)
    exclude_globs: list[str] = field(default_factory=list)
    budget: BudgetConfig | None = None
    max_findings: int | None = None
    lsp: bool = True
    package_name: str | None = None


@dataclass
class PipelineResult:
    bundle: AnalysisBundle | None
    assembly: AssemblyResult | None
    package_path: Path | None
    run_id: str
    warnings: list[str] = field(default_factory=list)
    sarif_path: Path | None = None
    scan_engine: str | None = None
    scan_record: ScanRecord | None = None
    findings: list[Finding] = field(default_factory=list)


class ScanOnlyPipeline:
    """The scan stage alone, so operators can eyeball scanner output before assembly."""

    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    def run(self, request: PipelineRequest) -> PipelineResult:
        run_id = "R-" + sha1(str(request.workspace), str(time.time()), length=10)
        pipeline = AssemblyPipeline(self.settings)
        findings, sarif_path, engine, warnings, scan_record = pipeline._collect_findings(
            request, run_id
        )
        return PipelineResult(
            bundle=None,
            assembly=None,
            package_path=None,
            run_id=run_id,
            warnings=warnings,
            sarif_path=sarif_path,
            scan_engine=engine,
            scan_record=scan_record,
            findings=findings,
        )


class AssemblyPipeline:
    def __init__(self, settings: Settings) -> None:
        self.settings = settings

    async def run(
        self,
        request: PipelineRequest,
        *,
        observer: Observer | None = None,
        abort: AbortCheck | None = None,
        teardown: TeardownHandle | None = None,
        staging: bool = False,
    ) -> PipelineResult:
        """Assemble one bundle.

        The three keyword arguments are all optional and all default to `None`, in which
        case this method behaves exactly as it did before they existed: no events, no
        interruption, resources owned locally. The queue passes them; the CLI, the HTTP
        route and the test-suite do not.
        """
        budget = request.budget or self.settings.budget
        stats = RunStats()
        warnings: list[str] = []
        degradations: list[Degradation] = []
        workspace_root = request.workspace.resolve()
        run_id = "R-" + sha1(str(workspace_root), str(time.time()), length=10)

        def emit(
            stage: str,
            phase: str,
            *,
            ms: int | None = None,
            counters: dict[str, int] | None = None,
            units_done: int = 0,
            units_total: int = 0,
            unit_label: str = "",
            note: str | None = None,
        ) -> None:
            if observer is None:
                return
            observer(
                StageEvent(
                    stage=stage,
                    phase=phase,
                    ms=ms,
                    counters=counters or {},
                    units_done=units_done,
                    units_total=units_total,
                    unit_label=unit_label,
                    note=note,
                )
            )

        def check_abort(stage: str) -> None:
            """Cooperative stop, asked once per stage boundary.

            Deliberately not called inside the concurrent fan-out: interrupting a slice
            would mean either changing `asyncio.gather`'s semantics or writing to Redis
            from a worker thread, and neither is worth it for a progress bar. The
            granularity is one slice, which is what the blocking waits provide anyway.
            """
            if abort is not None and abort():
                raise CanceledAbort(stage=stage, resource="stage_boundary")

        # ---------------------------------------------------------- scan
        # No `scan.start` event is emitted, and that is a fact about this pipeline rather
        # than an omission: `_collect_findings` is a *synchronous* call that spawns and
        # waits for a scanner subprocess, so the event loop does not run again until it
        # returns -- an event sent here would be delivered after the stage it describes.
        # The scan stage is the one stage that is silent from start to finish (up to
        # AEGIS_SCAN_TIMEOUT_S); a worker that wants to show "scanning" must record that
        # before calling run(), which is what the queue worker does.
        started = time.perf_counter()
        findings, sarif_path, scan_engine, scan_degradations, scan_record = self._collect_findings(
            request, run_id, abort=abort, teardown=teardown
        )
        warnings.extend(scan_degradations)
        stats.scan = scan_record
        stats.stage_ms["scan"] = _ms(started)
        emit(
            "scan",
            "end",
            ms=stats.stage_ms["scan"],
            counters={"discovered": len(findings)},
            note=f"scan_transport={scan_record.location}",
        )
        check_abort("scan")
        if not findings:
            log.warning("no findings; producing an empty bundle for auditability")
        if scan_record.location == "remote" and sarif_path is not None:
            # The SARIF lives in the scan service's filesystem. We cannot attach it
            # to the package, so say so instead of writing a path we cannot read.
            warnings.append(
                "扫描在扫描服务中运行：其原始 SARIF 不在本文件系统中 "
                f"（{sarif_path}），因此未附加到分析包"
            )
            sarif_path = None

        if request.max_findings is not None:
            findings = _prioritize(findings)[: request.max_findings]

        if not request.lsp:
            degradations.append(
                Degradation(
                    capability="lsp",
                    reason="LSP 已被配置禁用",
                    impact="所有方法位置与调用边都来自语法启发式",
                )
            )

        # ---------------------------------------------- workspace + LSP
        started = time.perf_counter()
        workspace = Workspace(workspace_root, max_file_bytes=self.settings.max_file_bytes)
        lsp: LanguageServerManager | None = None
        if request.lsp and self.settings.lsp_enabled:
            lsp = load_catalog(
                self.settings.lsp_config_file,
                root=workspace_root,
                timeout_s=self.settings.lsp_request_timeout_s,
            )
        index = SymbolIndex(workspace, lsp)
        resolver = CallGraphResolver(
            workspace, index, lsp, timeout_s=self.settings.lsp_request_timeout_s
        )
        stats.stage_ms["setup"] = _ms(started)
        if lsp is not None:
            # Hand the language servers over, then make their requests interruptible. Order
            # matters: register first, so a cancel arriving between these two lines still
            # finds something to kill.
            if teardown is not None:
                teardown.register_lsp(lsp)
            lsp.bind_run(abort, stage="setup")
        emit(
            "setup",
            "end",
            ms=stats.stage_ms["setup"],
            note=_lsp_note(lsp),
        )
        check_abort("setup")

        # The bundle id is a *content* fingerprint: same workspace + same findings +
        # same budget => same id, so re-runs overwrite instead of piling up, and any
        # prompt prefix keyed on the id stays valid. The run id still changes.
        # The formula lives in `ids.py` because the startup reconcile has to ask the same
        # question without re-running; see that module for why duplication is the risk.
        bundle_id = request.package_name or compute_bundle_id(
            workspace_root=workspace_root,
            findings=findings,
            budget_json=budget.model_dump_json(),
            rule_config=request.rule_config,
            rules=request.rules,
        )

        try:
            # ---------------------------------------------------- locate
            started = time.perf_counter()
            located, locate_prunes, merged_findings = self._locate(
                findings, workspace, resolver, budget
            )
            for prune in locate_prunes:
                log.debug("locate prune: %s", prune.detail)
            stats.stage_ms["locate"] = _ms(started)
            located_findings = sum(len(group) for _, group in located)
            stats.counts.update(
                {
                    "findings_discovered": len(findings),
                    "findings_located": located_findings,
                    "findings_dropped_at_locate": len(findings) - located_findings,
                    "findings_merged_into_existing_method": merged_findings,
                    "distinct_focus_methods": len(located),
                    "locate_failures": sum(1 for p in locate_prunes if p.rule == "locate_failed"),
                    "findings_skipped_by_max_contexts": sum(
                        1 for p in locate_prunes if p.rule == "max_contexts"
                    ),
                }
            )
            emit(
                "locate",
                "end",
                ms=stats.stage_ms["locate"],
                counters={"located": located_findings, "focus_methods": len(located)},
                units_done=len(located),
                units_total=len(located),
                unit_label="焦点方法",
            )
            check_abort("locate")

            # ---------------------------------------------------- expand
            started = time.perf_counter()
            slices = await self._expand(located, resolver, budget, warnings, workspace_root)
            stats.stage_ms["expand"] = _ms(started)
            stats.counts["slices_expanded"] = len(slices)
            stats.counts["slices_lost_to_errors"] = len(located) - len(slices)
            stats.counts["methods_collected"] = sum(len(s.methods) for s in slices)
            stats.counts["edges_collected"] = sum(len(s.edges) for s in slices)
            stats.counts["methods_dropped_at_expand"] = sum(s.methods_dropped for s in slices)
            stats.counts["fanouts_skipped"] = sum(s.fanouts_skipped for s in slices)
            # `contexts` is reported here as the number of focus methods, which is what it
            # will be unless a slice failed. It is corrected from the manifest once
            # assembly is done: the funnel defines it as `len(manifest.contexts)`, and a
            # count that is briefly optimistic is better than one that is never available.
            emit(
                "expand",
                "end",
                ms=stats.stage_ms["expand"],
                counters={"contexts": len(located), "slices": len(slices)},
                units_done=len(slices),
                units_total=len(located),
                unit_label="切片",
                note=(
                    f"{len(located) - len(slices)} 个切片失败，已记录为警告"
                    if len(slices) < len(located)
                    else None
                ),
            )
            check_abort("expand")

            # ------------------------------------------------------ read
            started = time.perf_counter()
            reader = MethodReader(workspace, budget)
            body_set = await reader.read_slices(slices)
            stats.stage_ms["read"] = _ms(started)
            stats.counts["bodies_read"] = len(body_set.bodies)
            stats.counts["bodies_unreadable"] = sum(
                1 for p in body_set.prunes if p.rule == "unreadable"
            )
            # Gross vs net: what the walk reached, versus what survived every cap.
            net_methods = len({ref.method.method_id for s in slices for ref in s.methods.values()})
            stats.counts["methods_proposed"] = (
                stats.counts["methods_collected"] + stats.counts["methods_dropped_at_expand"]
            )
            stats.counts["methods_kept"] = net_methods
            stats.counts["methods_dropped_by_caps"] = stats.counts["methods_dropped_at_expand"] + max(
                0, stats.counts["methods_collected"] - net_methods
            )
            # Emitted here rather than next to `stage_ms["read"]` above, because `kept` and
            # `proposed` do not exist until the three lines above have run. The rule for
            # every event in this method is "the variables it reports are ready", not
            # "the timer was just written".
            emit(
                "read",
                "end",
                ms=stats.stage_ms["read"],
                counters={
                    "proposed": stats.counts["methods_proposed"],
                    "kept": net_methods,
                    "read": len(body_set.bodies),
                },
                units_done=len(body_set.bodies),
                units_total=net_methods,
                unit_label="方法体",
            )
            check_abort("read")

            # -------------------------------------------------- assemble
            started = time.perf_counter()
            assembler = ContextAssembler(budget)
            assembly = assembler.assemble(slices, {f.finding_id: f for f in findings}, body_set)
            # findings that collapsed onto an already-expanded method are still coverage
            assembly.coverage.deduped += merged_findings
            # locate-time prunes are bundle-level, keep them visible
            assembly.prunes.extend(locate_prunes)
            renderer = BundleRenderer(budget)
            manifest = self._manifest(
                bundle_id=bundle_id,
                run_id=run_id,
                workspace_root=workspace_root,
                findings=findings,
                assembly=assembly,
                index=index,
                resolver=resolver,
                lsp=lsp,
                stats=stats,
                degradations=degradations,
                scan_record=scan_record,
                warnings=warnings,
                dataflow_anchors=[s.dataflow_anchor for s in slices],
            )
            bundle = AnalysisBundle(manifest=manifest)
            for context in assembly.contexts:
                for ref in context.refs:
                    bundle.methods.setdefault(ref.method.method_id, ref.method)
            # Inline each distinct body exactly once across the whole bundle, not
            # once per context: the catalog would otherwise repeat identical text.
            bundle.sources = {
                method_id: body.text
                for method_id, body in assembly.inlined_bodies.items()
            }
            bundle.recompute_totals()
            bundle.prompts = renderer.render(
                assembly, bundle_id=bundle_id, workspace_root=str(workspace_root)
            )
            manifest.total_chars = bundle.manifest.total_chars
            manifest.estimated_tokens = sum(block.estimated_tokens for block in bundle.prompts)
            stats.counts.update(
                {
                    "contexts_built": len(assembly.contexts),
                    "contexts_dropped_by_max_contexts": sum(
                        1 for p in assembly.prunes if p.rule == "max_contexts"
                    ),
                    "methods_inline_duplicates": sum(
                        len(aliases) for c in assembly.contexts for aliases in c.aliases.values()
                    ),
                    "prunes_total": len(assembly.prunes),
                    "truncated_contexts": sum(1 for c in assembly.contexts if c.truncated),
                    "prompt_blocks": len(bundle.prompts),
                }
            )
            stats.stage_ms["assemble"] = _ms(started)
            emit(
                "assemble",
                "end",
                ms=stats.stage_ms["assemble"],
                # The authoritative value, replacing the optimistic one from `expand`.
                # `inlined` matches the funnel's definition: bodies actually inlined into a
                # context, summed over contexts (an aliased body appears once per context
                # that references it -- that is what the funnel counts).
                counters={
                    "contexts": len(assembly.contexts),
                    "inlined": sum(len(c.bodies) for c in assembly.contexts),
                },
                units_done=sum(len(c.bodies) for c in assembly.contexts),
                units_total=net_methods,
                unit_label="方法体",
            )
            check_abort("assemble")

            # --------------------------------------------------- package
            # Last chance to stop: from here on the run is writing a bundle, and a bundle
            # abandoned halfway is worse than one that was never started. The packaging
            # stage is short and is deliberately *not* interruptible once entered.
            check_abort("package")
            stats.finished_at = _now()
            stats.duration_ms = sum(stats.stage_ms.values())
            started = time.perf_counter()
            packager = BundlePackager(self.settings.output_dir, renderer)
            if teardown is not None and staging:
                teardown.register_artifact_dir(
                    self.settings.output_dir / f".staging-{bundle.manifest.bundle_id}"
                )
            package_path = packager.write(
                bundle,
                assembly,
                sarif_source=sarif_path,
                degradations=degradations,
                stats=stats,
                staging=staging,
            )
            stats.stage_ms["package"] = _ms(started)
            stats.duration_ms = sum(stats.stage_ms.values())
            write_text(package_path / "manifest.json", bundle.manifest.model_dump_json(indent=2))
            # After the write, so "package done" never precedes the directory existing.
            emit("package", "end", ms=stats.stage_ms["package"])
        finally:
            if lsp is not None:
                lsp.stop_all()

        log.info(
            "pipeline finished: %d contexts, %d methods, %d ms",
            len(assembly.contexts),
            len(bundle.methods),
            stats.duration_ms,
        )
        return PipelineResult(
            bundle=bundle,
            assembly=assembly,
            package_path=package_path,
            run_id=run_id,
            warnings=warnings,
            sarif_path=sarif_path,
            scan_engine=scan_engine,
            scan_record=scan_record,
        )

    # ------------------------------------------------------------------
    def _collect_findings(
        self,
        request: PipelineRequest,
        run_id: str,
        *,
        abort: AbortCheck | None = None,
        teardown: TeardownHandle | None = None,
    ) -> tuple[list[Finding], Path | None, str, list[str], ScanRecord]:
        """Ask the scan capability for findings, or read a SARIF we were handed.

        The scan capability lives in its own service (`services.scan.runner`).
        Extraction calls it in-process here because this deployment has no queue
        yet; the call boundary is already the right one, so moving it to HTTP later
        is a one-line change rather than a refactor (see docs/SERVICE_TOPOLOGY.md).

        This stage never raises *for scan failures*: a scanner that fails, a missing SARIF
        and an unparseable SARIF all return zero findings plus a named failure mode, so the
        run still produces an auditable (empty) bundle with the reason in it.

        Cancellation is the one exception, and it is not a failure. `run_scan` reports it
        as `canceled=True` in its outcome (it cannot raise, by contract); this method turns
        that into a `CanceledAbort` so the run stops, carrying the scan ledger with it --
        a cancel during the scan stage never reaches packaging, so the exception is the
        only place that record can travel.
        """
        if request.sarif_path is not None:
            sarif_path = Path(request.sarif_path).resolve()
            findings = parse_sarif(sarif_path, workspace=request.workspace.resolve())
            return (
                findings,
                sarif_path,
                "sarif-input",
                [],
                build_scan_record(
                    engine="sarif-input",
                    engine_version="",
                    sarif_path=sarif_path,
                    command=[],
                    configured=True,
                    stderr="",
                    findings=findings,
                ),
            )

        # The process handle is what makes this stage interruptible. Without it a cancel
        # waits out the whole scan (AEGIS_SCAN_TIMEOUT_S, 900s by default).
        process_sink = None
        process_done = None
        if teardown is not None:
            process_sink = lambda proc: teardown.register_process("scan", proc)  # noqa: E731
            process_done = lambda: teardown.unregister_process("scan")  # noqa: E731

        outcome = run_scan_anywhere(
            ScanRequest(
                workspace=request.workspace,
                rules=request.rules,
                rule_config=request.rule_config,
                include_globs=request.include_globs,
                exclude_globs=request.exclude_globs,
                out_dir=self.settings.work_dir / run_id,
                binary=self.settings.opengrep_bin,
                fallback_binary=self.settings.opengrep_fallback_bin,
                timeout_s=self.settings.scan_timeout_s,
                abort=abort,
                process_sink=process_sink,
                process_done=process_done,
            )
        )
        assert outcome.scan_record is not None
        if outcome.canceled:
            raise CanceledAbort(
                stage="scan",
                resource="scan_process",
                detail=(outcome.scan_record.stderr_tail or "")[-200:],
                scan_record=outcome.scan_record,
            )
        return (
            outcome.findings,
            outcome.sarif_path,
            outcome.engine,
            outcome.warnings,
            outcome.scan_record,
        )

    # ------------------------------------------------------------------
    def _locate(
        self,
        findings: list[Finding],
        workspace: Workspace,
        resolver: CallGraphResolver,
        budget: BudgetConfig,
    ) -> tuple[list[tuple[MethodSymbol, list[Finding]]], list[PruneDecision], int]:
        """Resolve each finding to its enclosing method.

        Returns the merged (method, findings) pairs, the prunes, and how many
        findings collapsed into a method that already had one (for coverage).
        """
        located: list[tuple[MethodSymbol, list[Finding]]] = []
        prunes: list[PruneDecision] = []
        merged_away = 0

        for finding in _prioritize(findings):
            if len(located) >= budget.max_contexts:
                prunes.append(
                    PruneDecision(
                        rule="max_contexts",
                        detail=(
                            f"命中未展开：上下文上限（{budget.max_contexts}）"
                            "已经达到，因此这个命中既没有得到方法，也没有得到上下文；"
                            "提高 max_contexts 即可把它纳入"
                        ),
                        path=finding.path,
                        line=finding.region.start_line,
                        provider=Provider.OPENGREP,
                    )
                )
                continue
            result = resolver.locate_method(
                finding.path, finding.region.start_line, finding.region.start_char
            )
            if result is None:
                message = workspace.failures.get(finding.path) or "没有找到任何可调用体"
                prunes.append(
                    PruneDecision(
                        rule="locate_failed",
                        detail=f"无法定位所属方法：{message}",
                        path=finding.path,
                        line=finding.region.start_line,
                        provider=Provider.NONE,
                    )
                )
                continue
            symbol, _provider = result
            located.append((symbol, [finding]))

        # Merge findings that resolved to the same method.
        merged: dict[str, tuple[MethodSymbol, list[Finding]]] = {}
        for symbol, group in located:
            key = symbol.method_id
            if key in merged:
                merged[key][1].extend(group)
                merged_away += len(group)
            else:
                merged[key] = (symbol, list(group))
        return list(merged.values()), prunes, merged_away

    # ------------------------------------------------------------------
    async def _expand(
        self,
        located: list[tuple[MethodSymbol, list[Finding]]],
        resolver: CallGraphResolver,
        budget: BudgetConfig,
        warnings: list[str],
        workspace_root: Path,
    ) -> list[FocusSlice]:
        dataflow = self._dataflow_provider(workspace_root, warnings)
        builder = CallGraphBuilder(resolver.workspace, resolver, budget, dataflow=dataflow)
        semaphore = asyncio.Semaphore(max(1, budget.expand_concurrency))

        async def one(symbol: MethodSymbol, group: list[Finding]) -> FocusSlice | None:
            async with semaphore:
                try:
                    return await asyncio.to_thread(builder.build, symbol, group)
                except Exception as exc:  # a single bad node must not kill the run
                    log.warning("call-graph expansion failed for %s: %s", symbol.qualified_name, exc)
                    warnings.append(f"调用图展开失败（{symbol.qualified_name}）：{exc}")
                    return None

        results = await asyncio.gather(*(one(sym, group) for sym, group in located))
        return [slice_ for slice_ in results if slice_ is not None]

    # ------------------------------------------------------------------
    def _dataflow_provider(
        self, workspace_root: Path, warnings: list[str]
    ) -> DataflowProvider | None:
        """Build the worker client, or return None so the crawl stays in charge.

        Configuration is a promise, not a hint: if dataflow is switched on and the worker that
        owns this project cannot be reached, that is recorded as a warning the bundle carries,
        rather than quietly falling back to a crawl that cannot see a sanitizer called by the
        sink's caller.
        """
        config = self.settings.dataflow
        if not config.enabled:
            return None

        from services.extraction.dataflow import WorkerDataflowClient

        client = WorkerDataflowClient(config, workspace_root=workspace_root)
        if not client.health():
            message = (
                f"已请求数据流，但 worker {client.index}（{client.url}）未响应 "
                "/health；本次运行回退到调用方/被调用方爬取，而它看不到由汇聚点调用方调用的"
                "净化函数"
            )
            warnings.append(message)
            log.warning(message)
            return None
        log.info(
            "dataflow: project %s routed to worker %s (%s)",
            workspace_digest(workspace_root), client.index, client.url,
            extra={"stage": "dataflow"},
        )
        return client

    # ------------------------------------------------------------------
    def _manifest(
        self,
        *,
        bundle_id: str,
        run_id: str,
        workspace_root: Path,
        findings: list[Finding],
        assembly: AssemblyResult,
        index: SymbolIndex,
        resolver: CallGraphResolver,
        lsp: LanguageServerManager | None,
        stats: RunStats,
        degradations: list[Degradation],
        scan_record: ScanRecord,
        warnings: list[str],
        dataflow_anchors: list[dict] | None = None,
    ) -> AnalysisBundleManifest:
        dataflow_anchors = dataflow_anchors or []
        all_edges = [edge for context in assembly.contexts for edge in context.edges]
        methods = {
            ref.method.method_id: ref.method
            for context in assembly.contexts
            for ref in context.refs
        }
        collected = list(degradations)
        if lsp is not None:
            collected.extend(lsp.degradations)
        collected.extend(index.degradations)
        for message in resolver.degradations:
            collected.append(
                Degradation(
                    capability="callHierarchy",
                    reason=message,
                    impact="调用方方向回退到基于引用的边（置信度更低）",
                )
            )
        # Only surface degradations that actually changed the outcome: if no LSP
        # provider contributed anything, say so once instead of listing every
        # language server that is missing from the image.
        used_providers = {ref.provider.value for context in assembly.contexts for ref in context.refs}
        lsp_contributed = any(p.startswith("lsp_") for p in used_providers)
        if not lsp_contributed:
            collected = [d for d in collected if d.capability not in {"documentSymbol", "callHierarchy"}]
            if not any(d.capability == "lsp" for d in collected) and (
                Provider.SYNTAX_REGEX.value in used_providers
            ):
                collected.append(
                    Degradation(
                        capability="lsp",
                        reason="被扫描的文件没有可用的语言服务器",
                        impact=(
                            "每个方法位置与每条调用图边都来自语法启发式"
                            "（syntax_regex，置信度 0.40）"
                        ),
                    )
                )
        else:
            collected = [
                d for d in collected if not d.reason.startswith("没有可用于")
            ]

        capabilities: dict[str, object] = {
            "lsp_enabled": bool(lsp is not None),
            "language_servers": lsp.capabilities() if lsp is not None else {},
            "symbol_index": index.provider_summary(),
            "providers_used": sorted(used_providers),
            "edge_providers": sorted({edge.provider.value for edge in all_edges}),
            "scan_transport": scan_record.location,
            # Which source anchor each slice was analysed from, and the caller walk that chose
            # it. A flow that starts at an inner method *looks* complete (measured: 8 elements
            # against 24 for the entry's parameter), so the choice has to be auditable from the
            # bundle rather than only from a log line.
            "dataflow_anchors": [anchor for anchor in dataflow_anchors if anchor],
            # Warnings are the run's own caveats (a delegated scan whose SARIF could
            # not be attached, a scanner fallback, ...). They belong in the contract,
            # not only in a log line, or a consumer never learns about them.
            "warnings": list(warnings),
        }

        return AnalysisBundleManifest(
            bundle_id=bundle_id,
            run_id=run_id,
            workspace_root=str(workspace_root),
            focus_count=len(assembly.contexts),
            methods=sorted(methods.values(), key=lambda m: (m.path, m.region.start_line)),
            findings=findings,
            edges=all_edges,
            contexts=[c.to_model() for c in assembly.contexts],
            prunes=assembly.prunes,
            degradations=collected,
            coverage=assembly.coverage,
            stats=stats,
            capabilities=capabilities,
        )


# ----------------------------------------------------------------------
def _prioritize(findings: list[Finding]) -> list[Finding]:
    rank = {"error": 0, "warning": 1, "info": 2, "note": 3}
    return sorted(
        findings,
        key=lambda f: (
            rank.get(f.severity.value, 4),
            f.path,
            f.region.start_line,
            f.finding_id,
        ),
    )


def _scan_record(
    *,
    engine: str,
    engine_version: str,
    sarif_path: Path | None,
    command: list[str],
    configured: bool,
    stderr: str,
    findings: list[Finding],
    returncode: int = 0,
    failure_mode: str | None = None,
) -> ScanRecord:
    rule_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    path_counts: dict[str, int] = {}
    for finding in findings:
        rule_counts[finding.rule_id] = rule_counts.get(finding.rule_id, 0) + 1
        severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
        path_counts[finding.path] = path_counts.get(finding.path, 0) + 1
    top_paths = sorted(path_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]

    # Zero findings is only "clean" if the scanner actually succeeded and we told it
    # what to look for. Everything else is a scan that cannot be trusted as a result.
    suspicious = not findings and (
        failure_mode is not None or returncode not in (0, 1) or not configured
    )

    return ScanRecord(
        engine=engine,
        engine_version=engine_version,
        sarif_path=str(sarif_path) if sarif_path else None,
        command=command,
        returncode=returncode,
        configured=configured,
        zero_findings_is_suspicious=suspicious,
        failure_mode=failure_mode,
        stderr_tail=stderr,
        rule_counts=dict(sorted(rule_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        severity_counts=severity_counts,
        top_paths=top_paths,
    )


def _ms(started: float) -> int:
    return int((time.perf_counter() - started) * 1000)


def _lsp_note(lsp) -> str:
    """What the setup stage says about language servers.

    Names the *usable* languages, and names the ones the catalog lists but this image cannot
    serve. The second half is the important one: a Java project on an image without ``jdtls``
    silently gets a heuristic graph, and this note is the only place a reader can find out why
    before reading 52 degradations.
    """
    if lsp is None:
        return "LSP 已被配置禁用"
    usable, missing = lsp.installable()
    note = "LSP 可用：" + (",".join(usable) if usable else "（无）")
    if missing:
        note += f"；目录中另有 {','.join(missing)}，但镜像未安装其语言服务器"
    return note


def _now() -> datetime:
    return datetime.now(timezone.utc)
