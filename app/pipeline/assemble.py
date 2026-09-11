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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

from app.assembler.contexts import AssemblyResult, ContextAssembler
from app.assembler.package import BundlePackager, write_text
from app.assembler.reader import MethodReader
from app.assembler.render import BundleRenderer
from app.core.config import BudgetConfig, Settings
from app.core.logging import get_logger
from app.core.utils import sha1
from app.graph.builder import CallGraphBuilder, FocusSlice
from app.graph.providers import CallGraphResolver
from app.graph.resolver import SymbolIndex, Workspace
from app.lsp.manager import LanguageServerManager, load_catalog
from app.scanner.opengrep import OpengrepRunner
from app.scanner.sarif import SarifParser
from app.schemas.domain import (
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

log = get_logger(__name__)


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

    async def run(self, request: PipelineRequest) -> PipelineResult:
        budget = request.budget or self.settings.budget
        stats = RunStats()
        warnings: list[str] = []
        degradations: list[Degradation] = []
        workspace_root = request.workspace.resolve()
        run_id = "R-" + sha1(str(workspace_root), str(time.time()), length=10)

        # ---------------------------------------------------------- scan
        started = time.perf_counter()
        findings, sarif_path, scan_engine, scan_degradations, scan_record = self._collect_findings(
            request, run_id
        )
        warnings.extend(scan_degradations)
        stats.scan = scan_record
        stats.stage_ms["scan"] = _ms(started)
        if not findings:
            log.warning("no findings; producing an empty bundle for auditability")

        if request.max_findings is not None:
            findings = _prioritize(findings)[: request.max_findings]

        if not request.lsp:
            degradations.append(
                Degradation(
                    capability="lsp",
                    reason="LSP disabled by configuration",
                    impact="all method locations and edges come from syntax heuristics",
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

        # The bundle id is a *content* fingerprint: same workspace + same findings +
        # same budget => same id, so re-runs overwrite instead of piling up, and any
        # prompt prefix keyed on the id stays valid. The run id still changes.
        bundle_id = request.package_name or (
            "B-"
            + sha1(
                workspace_root.as_posix(),
                ",".join(sorted(f.finding_id for f in findings)),
                budget.model_dump_json(),
                request.rule_config or "",
                ",".join(request.rules),
                length=10,
            )
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

            # ---------------------------------------------------- expand
            started = time.perf_counter()
            slices = await self._expand(located, resolver, budget, warnings)
            stats.stage_ms["expand"] = _ms(started)
            stats.counts["slices_expanded"] = len(slices)
            stats.counts["slices_lost_to_errors"] = len(located) - len(slices)
            stats.counts["methods_collected"] = sum(len(s.methods) for s in slices)
            stats.counts["edges_collected"] = sum(len(s.edges) for s in slices)
            stats.counts["methods_dropped_at_expand"] = sum(s.methods_dropped for s in slices)

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
            )
            bundle = AnalysisBundle(manifest=manifest)
            for context in assembly.contexts:
                for ref in context.refs:
                    bundle.methods.setdefault(ref.method.method_id, ref.method)
            bundle.sources = {
                method_id: body.text for method_id, body in body_set.bodies.items()
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

            # --------------------------------------------------- package
            stats.finished_at = _now()
            stats.duration_ms = sum(stats.stage_ms.values())
            started = time.perf_counter()
            packager = BundlePackager(self.settings.output_dir, renderer)
            package_path = packager.write(
                bundle, assembly, sarif_source=sarif_path, degradations=degradations, stats=stats
            )
            stats.stage_ms["package"] = _ms(started)
            stats.duration_ms = sum(stats.stage_ms.values())
            write_text(package_path / "manifest.json", bundle.manifest.model_dump_json(indent=2))
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
        self, request: PipelineRequest, run_id: str
    ) -> tuple[list[Finding], Path | None, str, list[str], ScanRecord]:
        """Run the scanner (or read SARIF) and describe *how* it was run.

        The description matters as much as the findings: a run that reports zero
        hits because the scanner was misconfigured looks identical to a clean
        repository unless the invocation and stderr are recorded.

        This stage never raises: a scanner that fails, a missing SARIF and an
        unparseable SARIF all return zero findings plus a named failure mode, so
        the run still produces an auditable (empty) bundle with the reason in it.
        """
        warnings: list[str] = []
        if request.sarif_path is not None:
            sarif_path = Path(request.sarif_path).resolve()
            parser = SarifParser(workspace_root=request.workspace.resolve())
            findings = parser.parse_file(sarif_path)
            return findings, sarif_path, "sarif-input", warnings, _scan_record(
                engine="sarif-input",
                engine_version="",
                sarif_path=sarif_path,
                command=[],
                configured=True,
                stderr="",
                findings=findings,
            )

        runner = OpengrepRunner(
            self.settings.opengrep_bin,
            fallback_binary=self.settings.opengrep_fallback_bin,
            timeout_s=self.settings.scan_timeout_s,
        )
        out_dir = self.settings.work_dir / run_id
        outcome = runner.scan(
            request.workspace,
            out_dir=out_dir,
            rule_config=request.rule_config,
            rules=request.rules,
            include_globs=request.include_globs,
            exclude_globs=request.exclude_globs,
        )
        configured = bool(request.rule_config or request.rules)
        if outcome.degraded and outcome.degrade_reason:
            warnings.append(outcome.degrade_reason)

        def failed(reason: str) -> tuple[list[Finding], Path | None, str, list[str], ScanRecord]:
            """Return the empty-but-auditable result for a scan that could not yield findings."""
            warnings.append(reason)
            log.error("scan stage produced no usable findings: %s", reason)
            return (
                [],
                outcome.sarif_path,
                outcome.engine,
                warnings,
                _scan_record(
                    engine=outcome.engine,
                    engine_version=runner.version(),
                    sarif_path=outcome.sarif_path,
                    command=outcome.command,
                    configured=configured,
                    stderr=outcome.stderr_tail,
                    findings=[],
                    returncode=outcome.returncode,
                    failure_mode=reason,
                ),
            )

        if outcome.returncode not in (0, 1):
            return failed(
                f"scanner exited with rc={outcome.returncode}"
                + (f": {outcome.stderr_tail.splitlines()[-1]}" if outcome.stderr_tail else "")
            )
        if not outcome.sarif_path.exists():
            return failed(f"scanner produced no SARIF output (rc={outcome.returncode})")
        if outcome.sarif_path.stat().st_size == 0:
            return failed(f"scanner wrote an empty SARIF file (rc={outcome.returncode})")

        parser = SarifParser(workspace_root=request.workspace.resolve())
        try:
            findings = parser.parse_file(outcome.sarif_path)
        except ValueError as exc:
            return failed(f"scanner output is not valid SARIF: {exc}")

        return (
            findings,
            outcome.sarif_path,
            outcome.engine,
            warnings,
            _scan_record(
                engine=outcome.engine,
                engine_version=runner.version(),
                sarif_path=outcome.sarif_path,
                command=outcome.command,
                configured=configured,
                stderr=outcome.stderr_tail,
                findings=findings,
                returncode=outcome.returncode,
            ),
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
                        detail=f"finding not expanded: max_contexts={budget.max_contexts} reached",
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
                message = workspace.failures.get(finding.path) or "no enclosing callable found"
                prunes.append(
                    PruneDecision(
                        rule="locate_failed",
                        detail=f"could not locate enclosing method: {message}",
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
    ) -> list[FocusSlice]:
        builder = CallGraphBuilder(resolver.workspace, resolver, budget)
        semaphore = asyncio.Semaphore(max(1, budget.expand_concurrency))

        async def one(symbol: MethodSymbol, group: list[Finding]) -> FocusSlice | None:
            async with semaphore:
                try:
                    return await asyncio.to_thread(builder.build, symbol, group)
                except Exception as exc:  # a single bad node must not kill the run
                    log.warning("call-graph expansion failed for %s: %s", symbol.qualified_name, exc)
                    warnings.append(f"call-graph expansion failed for {symbol.qualified_name}: {exc}")
                    return None

        results = await asyncio.gather(*(one(sym, group) for sym, group in located))
        return [slice_ for slice_ in results if slice_ is not None]

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
    ) -> AnalysisBundleManifest:
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
                    impact="caller direction falls back to reference-based edges (lower confidence)",
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
                        reason="no language server was available for the scanned files",
                        impact=(
                            "every method location and call graph edge comes from syntax "
                            "heuristics (syntax_regex, confidence 0.40)"
                        ),
                    )
                )
        else:
            collected = [d for d in collected if not d.reason.startswith("no usable language server")]

        capabilities: dict[str, object] = {
            "lsp_enabled": bool(lsp is not None),
            "language_servers": lsp.capabilities() if lsp is not None else {},
            "symbol_index": index.provider_summary(),
            "providers_used": sorted(used_providers),
            "edge_providers": sorted({edge.provider.value for edge in all_edges}),
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


def _now() -> datetime:
    return datetime.now(timezone.utc)
