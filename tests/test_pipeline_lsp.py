from __future__ import annotations

import asyncio
from pathlib import Path

import pytest

from aegis_core.config import BudgetConfig, Settings
from services.extraction.graph.providers import CallGraphResolver
from services.extraction.graph.resolver import SymbolIndex, Workspace
from services.extraction.lsp.manager import load_catalog
from services.extraction.pipeline.assemble import AssemblyPipeline, PipelineRequest
from tests.fixtures import write_sarif

pytestmark = pytest.mark.slow


def _settings(tmp_path: Path, workspace: Path, config: Path | None, budget: BudgetConfig) -> Settings:
    return Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        budget=budget,
        lsp_config_file=config,
        lsp_enabled=config is not None,
    ).resolve()


def _resolver(
    workspace: Path, config: Path | None, tmp_path: Path
) -> tuple[Workspace, SymbolIndex, CallGraphResolver, object]:
    ws = Workspace(workspace)
    manager = load_catalog(config, root=workspace, timeout_s=30.0) if config else None
    index = SymbolIndex(ws, manager)
    resolver = CallGraphResolver(ws, index, manager, timeout_s=30.0)
    return ws, index, resolver, manager


def test_lsp_locates_enclosing_method(tmp_path: Path, workspace: Path, fake_lsp_config: Path) -> None:
    ws, index, resolver, manager = _resolver(workspace, fake_lsp_config, tmp_path)
    try:
        found = resolver.locate_method("repo.py", 4, 10)  # the sql = "..." line
        assert found is not None
        symbol, provider = found
        assert symbol.name == "query_user"
        assert provider.value == "lsp_document_symbol"
        body = ws.read("repo.py").splitlines()
        assert body[symbol.region.start_line].startswith("def query_user")
    finally:
        manager.stop_all()  # type: ignore[union-attr]


def test_lsp_call_hierarchy_both_directions(
    tmp_path: Path, workspace: Path, fake_lsp_config: Path
) -> None:
    ws, index, resolver, manager = _resolver(workspace, fake_lsp_config, tmp_path)
    try:
        located = resolver.locate_method("repo.py", 4, 10)
        assert located is not None
        symbol, _ = located
        callees, callee_provider = resolver.callees(symbol, limit=10)
        callee_names = {c.qualified_name for c, _ in callees}
        assert "connect" in callee_names
        assert callee_provider.value == "lsp_call_hierarchy"
        assert all(edge.provider.value == "lsp_call_hierarchy" for _, edge in callees)

        callers, caller_provider = resolver.callers(symbol, limit=10)
        names = {c.qualified_name for c, _ in callers}
        assert "load_user" in names
        assert caller_provider.value == "lsp_call_hierarchy"
    finally:
        manager.stop_all()  # type: ignore[union-attr]


def test_bundle_from_lsp_has_full_call_chain(
    tmp_path: Path, workspace: Path, fake_lsp_config: Path, budget: BudgetConfig
) -> None:
    settings = _settings(tmp_path, workspace, fake_lsp_config, budget)
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5)
    pipeline = AssemblyPipeline(settings)

    result = asyncio.run(
        pipeline.run(PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=True))
    )

    assert result.bundle is not None and result.assembly is not None
    assert len(result.assembly.contexts) == 1
    context = result.assembly.contexts[0]
    assert context.focus.method.name == "query_user"
    names = {ref.method.qualified_name for ref in context.refs}
    # callers (entry side) and callees (sink side) were both walked
    assert {"query_user", "load_user", "handle_request", "connect"} <= names

    providers = {ref.provider.value for ref in context.refs}
    assert "lsp_call_hierarchy" in providers
    assert context.focus.method.provider.value == "lsp_document_symbol"

    # The complete method body is what gets handed to the model.
    focus_body = context.bodies[context.focus.method.method_id].text
    assert "SELECT * FROM users" in focus_body
    assert "def query_user" in focus_body

    package = Path(result.package_path)
    assert (package / "manifest.json").exists()
    assert (package / "ai" / "prompt.md").exists()
    assert (package / "graph" / "callgraph.dot").exists()
    assert (package / "contexts" / f"{context.context_id}.md").exists()
    assert package.with_suffix(".zip").exists()

    prompt = (package / "ai" / "prompt.md").read_text(encoding="utf-8")
    assert "lsp_call_hierarchy" in prompt
    assert "query_user" in prompt
    assert "Required output" in prompt


def test_bundle_depth_limit_emits_prune(
    tmp_path: Path, workspace: Path, fake_lsp_config: Path
) -> None:
    budget = BudgetConfig(max_depth=1, max_nodes=30, max_contexts=10)
    settings = _settings(tmp_path, workspace, fake_lsp_config, budget)
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5)
    pipeline = AssemblyPipeline(settings)

    result = asyncio.run(
        pipeline.run(PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=True))
    )
    assert result.bundle is not None
    names = {ref.method.qualified_name for ref in result.assembly.contexts[0].refs}  # type: ignore[union-attr]
    assert "handle_request" not in names  # depth 2, correctly cut
    assert any(p.rule == "max_depth" for p in result.bundle.manifest.prunes)


def test_syntax_only_mode_still_assembles(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    settings = _settings(tmp_path, workspace, None, budget)
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5)
    pipeline = AssemblyPipeline(settings)

    result = asyncio.run(
        pipeline.run(PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=True))
    )

    assert result.bundle is not None
    assert len(result.assembly.contexts) == 1  # type: ignore[union-attr]
    context = result.assembly.contexts[0]  # type: ignore[union-attr]
    assert context.focus.method.name == "query_user"
    assert context.focus.method.provider.value == "syntax_regex"
    focus_body = context.bodies[context.focus.method.method_id].text
    assert "SELECT * FROM users" in focus_body
    # the degradation is recorded, not hidden
    assert any(d.capability == "lsp" for d in result.bundle.manifest.degradations)


def test_max_nodes_prunes_and_is_auditable(
    tmp_path: Path, workspace: Path, fake_lsp_config: Path
) -> None:
    budget = BudgetConfig(max_depth=3, max_nodes=3, max_contexts=10)
    settings = _settings(tmp_path, workspace, fake_lsp_config, budget)
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5)
    pipeline = AssemblyPipeline(settings)

    result = asyncio.run(
        pipeline.run(PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=True))
    )
    assert result.bundle is not None
    assert len(result.assembly.contexts[0].refs) <= 3  # type: ignore[union-attr]
    assert any(p.rule == "max_nodes" for p in result.bundle.manifest.prunes)
