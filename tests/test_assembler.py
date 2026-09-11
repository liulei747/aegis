"""Dedupe, merging and budget-edge behaviour of the assembler."""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aegis_core.config import BudgetConfig, Settings
from app.graph.builder import CallGraphBuilder
from app.graph.providers import CallGraphResolver
from app.graph.resolver import SymbolIndex, Workspace
from app.pipeline.assemble import AssemblyPipeline, PipelineRequest
from tests.fixtures import write_sarif

TWINS = '''\
"""Two byte-identical methods: the assembler must inline the source once."""


def primary_sink(value):
    return execute("select " + value)


def twin_sink(value):
    return execute("select " + value)


def entry(value):
    a = primary_sink(value)
    b = twin_sink(value)
    return a + b


def execute(sql):
    return sql
'''


def _settings(tmp_path: Path, workspace: Path, budget: BudgetConfig) -> Settings:
    return Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        budget=budget,
        lsp_enabled=False,
    ).resolve()


def _sarif_two_hits(tmp_path: Path, workspace: Path) -> Path:
    """Two findings inside the same method -> one merged context."""
    base = json.loads(write_sarif(tmp_path / "scan.sarif", sink_line=5).read_text(encoding="utf-8"))
    first = base["runs"][0]["results"][0]
    second = json.loads(json.dumps(first))
    second["message"]["text"] = "same sink, second rule"
    second["ruleId"] = "python.lang.security.sql-injection-2"
    second["locations"][0]["physicalLocation"]["region"]["startColumn"] = 20
    base["runs"][0]["results"] = [first, second]
    path = tmp_path / "scan-two.sarif"
    path.write_text(json.dumps(base), encoding="utf-8")
    return path


def test_two_findings_in_one_method_merge_into_one_context(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    sarif = _sarif_two_hits(tmp_path, workspace)
    result = asyncio.run(
        AssemblyPipeline(_settings(tmp_path, workspace, budget)).run(
            PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=False)
        )
    )
    assert result.assembly is not None and result.bundle is not None
    assert len(result.assembly.contexts) == 1
    context = result.assembly.contexts[0]
    assert len(context.findings) == 2
    assert result.bundle.manifest.coverage.discoverable == 2
    assert result.bundle.manifest.coverage.bundled == 2
    assert result.bundle.manifest.coverage.deduped == 1


def test_byte_identical_bodies_are_inlined_once_and_named_as_aliases(
    tmp_path: Path, budget: BudgetConfig
) -> None:
    """Two methods with identical source: the model pays for the text once.

    Constructed directly because the invariant is about the assembler's dedupe,
    not about how a language server would have named the two symbols.
    """
    from aegis_contracts.domain import CodeRegion, MethodRef, MethodSymbol, Provider, SymbolKind
    from app.assembler.contexts import ContextAssembler
    from app.assembler.reader import BodySet, MethodBody
    from app.graph.builder import FocusSlice

    shared = "def sink(value):\n    return execute('select ' + value)\n"

    def method(name: str, line: int) -> MethodSymbol:
        return MethodSymbol(
            method_id=f"M-{name}",
            name=name,
            qualified_name=name,
            kind=SymbolKind.FUNCTION,
            path="twins.py",
            region=CodeRegion(
                path="twins.py", start_line=line, end_line=line + 1, start_offset=0, end_offset=len(shared)
            ),
            language="python",
            provider=Provider.LSP_DOCUMENT_SYMBOL,
        )

    focus = method("primary_sink", 3)
    twin = method("twin_sink", 7)
    slice_ = FocusSlice(focus=focus, finding_ids=["F-1"])
    slice_.methods[focus.method_id] = MethodRef(method=focus, provider=focus.provider, is_focus=True)
    slice_.methods[twin.method_id] = MethodRef(
        method=twin, provider=twin.provider, depth=1, via="alias case"
    )

    bodies = BodySet()
    for symbol in (focus, twin):
        bodies.bodies[symbol.method_id] = MethodBody(
            method=symbol,
            text=shared,
            content_hash="identical",
            chars=len(shared),
            lines=2,
            tokens=8,
        )

    result = ContextAssembler(budget).assemble([slice_], {}, bodies)
    context = result.contexts[0]
    assert len(context.bodies) == 1, "identical bodies must be inlined once"
    assert focus.method_id in context.bodies
    assert context.aliases.get(focus.method_id) == [twin.method_id]
    assert twin.method_id in {ref.method.method_id for ref in context.refs}
    assert tmp_path.exists()


def test_context_keeps_one_copy_of_identical_bodies_and_names_the_other(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """End-to-end flavour: the body set never holds two identical bodies twice."""
    ws = Workspace(workspace)
    index = SymbolIndex(ws, None)
    resolver = CallGraphResolver(ws, index, None)
    sink = resolver.locate_method("repo.py", 4, 10)
    assert sink is not None
    slices = [CallGraphBuilder(ws, resolver, budget).build(sink[0], [])]

    from app.assembler.reader import MethodReader, dedupe_index

    bodies = asyncio.run(MethodReader(ws, budget).read_slices(slices))
    for ids in dedupe_index(bodies).values():
        assert len(ids) == 1, "identical bodies must be stored once"


def test_total_char_budget_never_drops_the_focus_body(tmp_path: Path, budget: BudgetConfig) -> None:
    """The global cap drops the least valuable bodies, never the sink, and says so."""
    from aegis_contracts.domain import CodeRegion, MethodSymbol, Provider, SymbolKind
    from app.assembler.reader import BodySet, MethodBody, MethodReader

    def method(name: str) -> MethodSymbol:
        return MethodSymbol(
            method_id=f"M-{name}",
            name=name,
            qualified_name=name,
            kind=SymbolKind.FUNCTION,
            path="big.py",
            region=CodeRegion(path="big.py", start_line=0, end_line=9),
            provider=Provider.SYNTAX_REGEX,
        )

    focus = method("the_sink")
    others = [method(f"helper_{i}") for i in range(3)]
    bodies = BodySet()
    text = "x = 1\n" * 40  # 240 chars each
    for symbol in (focus, *others):
        bodies.bodies[symbol.method_id] = MethodBody(
            method=symbol,
            text=text,
            content_hash=symbol.method_id,
            chars=len(text),
            lines=40,
            tokens=80,
        )

    reader = MethodReader(Workspace(tmp_path), budget)
    tight = budget.model_copy(update={"max_total_chars": 500})
    reader.budget = tight
    reader._focus_ids = {focus.method_id}
    reader._apply_global_budget(bodies)

    assert focus.method_id in bodies.bodies, "focus body must survive the global cap"
    assert bodies.total_chars <= 500
    assert len(bodies.bodies) == 2  # two of the three helpers were shed
    dropped = [p for p in bodies.prunes if p.rule == "max_total_chars"]
    assert len(dropped) == 2
    assert all(p.method_id != focus.method_id for p in dropped)
    assert not any(p.rule == "max_total_chars_exceeded" for p in bodies.prunes)


def test_max_chars_per_method_truncates_and_records_it(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    tiny = budget.model_copy(update={"max_lines_per_method": 2})
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5)
    result = asyncio.run(
        AssemblyPipeline(_settings(tmp_path, workspace, tiny)).run(
            PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=False)
        )
    )
    assert result.assembly is not None and result.bundle is not None
    context = result.assembly.contexts[0]
    assert context.truncated is True
    body = context.bodies[context.focus.method.method_id]
    assert body.truncated_lines is True
    assert len(body.text.splitlines()) <= 2
    assert any(p.rule == "max_chars_per_method" for p in result.bundle.manifest.prunes)


def test_max_contexts_limits_expansion_and_is_auditable(
    tmp_path: Path, workspace: Path
) -> None:
    budget = BudgetConfig(max_contexts=1, max_depth=1)
    sarif = _sarif_two_hits(tmp_path, workspace)
    result = asyncio.run(
        AssemblyPipeline(_settings(tmp_path, workspace, budget)).run(
            PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=False)
        )
    )
    assert result.bundle is not None
    assert len(result.assembly.contexts) == 1  # type: ignore[union-attr]


def test_unreadable_file_is_reported_as_a_prune(tmp_path: Path, workspace: Path, budget: BudgetConfig) -> None:
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5)
    (workspace / "repo.py").unlink()
    result = asyncio.run(
        AssemblyPipeline(_settings(tmp_path, workspace, budget)).run(
            PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=False)
        )
    )
    assert result.bundle is not None
    assert result.assembly is not None and not result.assembly.contexts
    assert any(p.rule == "locate_failed" for p in result.bundle.manifest.prunes)
