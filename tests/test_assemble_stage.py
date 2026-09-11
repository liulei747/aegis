"""Fifth stage (assemble): dedupe + one self-contained context per sink.

The property that matters: the model must never pay for the same body twice, and
a body removed by dedupe must remain *findable* — either it is inlined, or the
text tells the reader where it went.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aegis_core.config import BudgetConfig, Settings
from services.extraction.assembler.render import BundleRenderer
from services.extraction.pipeline.assemble import AssemblyPipeline, PipelineRequest
from tests.fixtures import write_sarif

IDENTICAL = "def validate(value):\n    return value.strip()[:100]\n"


def _duplicate_repo(root: Path) -> Path:
    """Two files holding byte-identical `validate`, plus a caller of one of them."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "a.py").write_text(IDENTICAL, encoding="utf-8")
    (root / "c.py").write_text(IDENTICAL, encoding="utf-8")
    (root / "caller.py").write_text(
        "from c import validate\n\n\ndef handle(payload):\n"
        "    first = validate(payload)\n    return first\n",
        encoding="utf-8",
    )
    return root


def _sarif_with_two_contexts(tmp_path: Path, repo: Path) -> Path:
    sarif = write_sarif(tmp_path / "s.sarif", sink_line=2, workspace=repo)
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    first = doc["runs"][0]["results"][0]
    first["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "a.py"
    second = json.loads(json.dumps(first))
    second["ruleId"] = "second-rule"
    second["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] = "caller.py"
    second["locations"][0]["physicalLocation"]["region"]["startLine"] = 4
    doc["runs"][0]["results"] = [first, second]
    sarif.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return sarif


def _run(tmp_path: Path, repo: Path, **budget_overrides):
    base = {"max_depth": 1, "max_nodes": 20, "max_contexts": 10}
    base.update(budget_overrides)
    budget = BudgetConfig(**base)
    settings = Settings(
        workspace_root=repo,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        budget=budget,
        lsp_enabled=False,
    ).resolve()
    sarif = _sarif_with_two_contexts(tmp_path, repo)
    return asyncio.run(
        AssemblyPipeline(settings).run(
            PipelineRequest(workspace=repo, sarif_path=sarif, lsp=False, package_name="B-test")
        )
    )


# ----------------------------------------------------------------------
# Grouping
# ----------------------------------------------------------------------
def test_two_findings_on_one_method_collapse_into_one_context(
    tmp_path: Path, workspace: Path
) -> None:
    """Two rules hitting the same function is one thing to analyse, not two."""
    from tests.fixtures import write_two_hits_sarif

    budget = BudgetConfig(max_depth=2, max_nodes=20, max_contexts=10)
    settings = Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        budget=budget,
        lsp_enabled=False,
    ).resolve()
    sarif = write_two_hits_sarif(tmp_path / "two.sarif", workspace=workspace)
    result = asyncio.run(
        AssemblyPipeline(settings).run(
            PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=False)
        )
    )
    manifest = result.bundle.manifest  # type: ignore[union-attr]

    assert len(manifest.findings) == 2
    assert len(manifest.contexts) == 1
    context = manifest.contexts[0]
    assert len(context.finding_ids) == 2
    # nothing lost, and the merge is reported as a merge
    assert manifest.coverage.bundled == 2
    assert manifest.coverage.rejected == 0
    assert result.assembly.coverage.deduped == 1  # type: ignore[union-attr]


def test_max_contexts_drops_whole_contexts_and_says_which(tmp_path: Path) -> None:
    repo = _duplicate_repo(tmp_path / "repo")
    result = _run(tmp_path, repo, max_contexts=1)
    manifest = result.bundle.manifest  # type: ignore[union-attr]

    assert len(manifest.contexts) == 1
    dropped = [p for p in manifest.prunes if p.rule == "max_contexts"]
    assert dropped, "a dropped context must be recorded"
    prune = dropped[0]
    # The finding is cut *before* a method is resolved, so there is no method id to
    # name — the location plus an actionable message are what identify it.
    assert prune.path and prune.line is not None
    assert "raise max_contexts" in prune.detail


# ----------------------------------------------------------------------
# Dedupe
# ----------------------------------------------------------------------
def test_identical_bodies_are_inlined_once_bundle_wide(tmp_path: Path) -> None:
    """Same body reached from two contexts must not be paid for twice."""
    repo = _duplicate_repo(tmp_path / "repo")
    result = _run(tmp_path, repo)
    assembly = result.assembly
    assert assembly is not None
    bundle = result.bundle
    assert bundle is not None

    hashes = [hash_ for hash_ in assembly.canonical_bodies]
    inlined = [b.content_hash for b in assembly.inlined_bodies.values()]
    assert len(inlined) == len(set(inlined)), "a body was inlined twice"
    assert set(inlined) <= set(hashes)

    # the bundle's inline set only carries unique bodies
    assert len(bundle.sources) == len(set(bundle.sources.values()))


def test_a_deduplicated_body_is_pointed_at_not_dropped(tmp_path: Path) -> None:
    repo = _duplicate_repo(tmp_path / "repo")
    result = _run(tmp_path, repo)
    assembly = result.assembly
    assert assembly is not None
    assert assembly.bundle_aliases, "the fixture should produce at least one alias"

    alias_id, canonical_id = next(iter(assembly.bundle_aliases.items()))
    # the alias is no longer inlined in its context...
    holder = next(c for c in assembly.contexts if alias_id in c.aliases.get(canonical_id, []))
    assert alias_id not in holder.bodies
    # ...but it is still a member of the slice, with its own symbol
    assert alias_id in {r.method.method_id for r in holder.refs}
    # ...and its content is inlined exactly once, under the canonical id
    assert canonical_id in assembly.inlined_bodies


def test_the_prompt_says_where_a_deduplicated_body_lives(tmp_path: Path) -> None:
    repo = _duplicate_repo(tmp_path / "repo")
    result = _run(tmp_path, repo)
    bundle = result.bundle
    assembly = result.assembly
    assert bundle is not None and assembly is not None

    alias_id = next(iter(assembly.bundle_aliases))
    context_block = next(
        b for b in bundle.prompts if b.block_id.startswith("context.") and alias_id in b.content
    )
    assert "identical to" in context_block.content
    assert "method_catalog" in context_block.content
    # and the catalog holds the text exactly once
    catalog = next(b for b in bundle.prompts if b.block_id == "method_catalog")
    assert catalog.content.count("def validate(value):") == 1


def test_dedupe_is_deterministic(tmp_path: Path) -> None:
    repo = _duplicate_repo(tmp_path / "repo")
    first = _run(tmp_path / "a", repo)
    second = _run(tmp_path / "b", repo)
    assert first.assembly is not None and second.assembly is not None
    assert first.assembly.canonical_bodies == second.assembly.canonical_bodies
    assert first.assembly.bundle_aliases == second.assembly.bundle_aliases


def test_context_ids_are_content_derived(tmp_path: Path) -> None:
    """Same input -> same context ids, which is what makes prompt prefixes reusable."""
    repo = _duplicate_repo(tmp_path / "repo")
    first = _run(tmp_path / "a", repo)
    second = _run(tmp_path / "b", repo)
    assert first.bundle is not None and second.bundle is not None
    assert [c.context_id for c in first.bundle.manifest.contexts] == [
        c.context_id for c in second.bundle.manifest.contexts
    ]


def test_metrics_are_consistent_after_dedupe(tmp_path: Path) -> None:
    repo = _duplicate_repo(tmp_path / "repo")
    result = _run(tmp_path, repo)
    assembly = result.assembly
    bundle = result.bundle
    assert assembly is not None and bundle is not None

    counts = bundle.manifest.stats.counts
    assert counts["methods_inline_duplicates"] == sum(
        len(ids) for c in assembly.contexts for ids in c.aliases.values()
    )
    # total_chars describes what actually goes into the prompt
    assert bundle.manifest.total_chars == sum(len(t) for t in bundle.sources.values())


# ----------------------------------------------------------------------
# The unit of work
# ----------------------------------------------------------------------
def test_every_context_carries_its_own_findings_chain_and_bodies(tmp_path: Path) -> None:
    repo = _duplicate_repo(tmp_path / "repo")
    result = _run(tmp_path, repo)
    assembly = result.assembly
    assert assembly is not None

    renderer = BundleRenderer(BudgetConfig())
    blocks = renderer.render(assembly, bundle_id="B-x", workspace_root=str(repo))
    context_blocks = [b for b in blocks if b.block_id.startswith("context.")]

    assert len(context_blocks) == len(assembly.contexts)
    for context in assembly.contexts:
        block = next(b for b in context_blocks if b.block_id == f"context.{context.context_id}")
        assert context.focus.method.qualified_name in block.content
        assert "Call chain slice" in block.content
        for finding in context.findings:
            assert finding.finding_id in block.content


def test_sink_body_survives_a_tight_global_cap(tmp_path: Path) -> None:
    repo = _duplicate_repo(tmp_path / "repo")
    result = _run(tmp_path, repo, max_total_chars=1000)
    assembly = result.assembly
    assert assembly is not None
    for context in assembly.contexts:
        assert context.focus.method.method_id in assembly.inlined_bodies or any(
            context.focus.method.method_id in ids for ids in context.aliases.values()
        ), "the sink's body must never be dropped from the bundle"
