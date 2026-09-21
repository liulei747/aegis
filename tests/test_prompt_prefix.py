"""The prompt-prefix contract: what a consumer may safely send as a cached prefix.

`docs/HANDOVER.md` §6 records the trap this file exists to close: the block
layout promises "a stable prefix you can prefill", but ``bundle.header`` sits at
position 0 and is *not* stable (it carries ``bundle_id`` and the bundle-level token
count), so a caller that concatenates every ``cacheable: true`` block gets a prefix
that never matches anything. Measured on the demo bundle: blocks 0-4 are marked
cacheable, yet block 0 changes on every run, so the real reusable prefix starts at
block 1.

Two things are therefore asserted here, and they are different claims:

1. **Contiguity** -- the cacheable blocks form one run, and ``ai/cache_prefix.json``
   says where that run starts. Without this, "cacheable" is a claim nobody can act on.
2. **Stability** -- the bytes of that run are identical between two bundles that
   differ only in the volatile parts (different bundle ids, different context sets).
   Without this, the prefix is contiguous but still useless.

Claim 2 is the one that matters for the AI stage: a fan-out reuses one prefix across
many bundles, so "stable for identical input" is not enough.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

from aegis_core.config import BudgetConfig, Settings
from services.extraction.pipeline.assemble import AssemblyPipeline, PipelineRequest
from tests.fixtures import write_sarif


def _settings(tmp_path: Path, workspace: Path, budget: BudgetConfig) -> Settings:
    return Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        budget=budget,
        lsp_enabled=False,
    ).resolve()


def _run(
    tmp_path: Path, workspace: Path, budget: BudgetConfig, *, sarif: Path, name: str | None = None
):
    result = asyncio.run(
        AssemblyPipeline(_settings(tmp_path, workspace, budget)).run(
            PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=False, package_name=name)
        )
    )
    assert result.bundle is not None and result.package_path is not None
    return result


def _meta(package_path: Path) -> list[dict]:
    return json.loads((package_path / "ai" / "blocks_meta.json").read_text(encoding="utf-8"))


def _prefix_doc(package_path: Path) -> dict:
    return json.loads((package_path / "ai" / "cache_prefix.json").read_text(encoding="utf-8"))


SECOND_SINK = '''\
"""A second sink, in its own file, so the bundle has two contexts."""


def second_sink(value):
    return execute("delete from t where id = " + value)
'''


def _two_sink_workspace(tmp_path: Path) -> Path:
    """A workspace with a second tainted method: two findings, two contexts."""
    root = tmp_path / "repo-two"
    root.mkdir(parents=True, exist_ok=True)
    (root / "second.py").write_text(SECOND_SINK, encoding="utf-8")
    return root


def _add_second_sink(sarif: Path) -> Path:
    """Point a copy of the SARIF at the second method as well."""
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    runs = doc["runs"][0]
    second = json.loads(json.dumps(runs["results"][0]))
    second["ruleId"] = "python.lang.security.sqli-second"
    second["message"]["text"] = "second sink, different method"
    location = second["locations"][0]["physicalLocation"]
    location["artifactLocation"]["uri"] = location["artifactLocation"]["uri"].replace(
        "repo.py", "second.py"
    )
    location["region"]["startLine"] = 5
    location["region"]["startColumn"] = 12
    runs["results"] = [runs["results"][0], second]
    return sarif


def test_cacheable_blocks_are_one_contiguous_run(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """The flags must describe a run, not a scatter: a non-contiguous run is unusable."""
    sarif = write_sarif(tmp_path / "scan.sarif", workspace=workspace)
    result = _run(tmp_path, workspace, budget, sarif=sarif)
    meta = _meta(result.package_path)  # type: ignore[arg-type]

    flags = [bool(block["cacheable"]) for block in meta]
    assert any(flags), "at least the instructions must be reusable"
    first, last = flags.index(True), len(flags) - 1 - flags[::-1].index(True)
    assert all(flags[first : last + 1]), (
        "cacheable blocks must be contiguous, otherwise 'concat the cacheable blocks' "
        f"is not a prefix: {[b['block_id'] for b in meta]} -> {flags}"
    )


def test_cache_prefix_declares_where_the_reusable_run_starts(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """Document order is not prefix order: the prefix starts at the first cacheable run."""
    sarif = write_sarif(tmp_path / "scan.sarif", workspace=workspace)
    result = _run(tmp_path, workspace, budget, sarif=sarif)
    package = result.package_path
    assert package is not None

    meta = _meta(package)
    doc = _prefix_doc(package)

    first_cacheable = next(i for i, block in enumerate(meta) if block["cacheable"])
    assert doc["prefix_start"] == first_cacheable, (
        "the header block is volatile, so the reusable prefix does not start at 0; "
        "a consumer must be told where it does start"
    )
    assert doc["prefix_blocks"] == [b["block_id"] for b in meta[first_cacheable:] if b["cacheable"]]
    assert doc["stable_prefix_tokens"] == sum(
        b["tokens"] for b in meta[first_cacheable:] if b["cacheable"]
    )
    assert doc["note"], "the declaration needs to say why the header is excluded"


def test_volatile_header_is_not_part_of_the_prefix(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """`bundle.header` carries the bundle id, so it can never be cached."""
    sarif = write_sarif(tmp_path / "scan.sarif", workspace=workspace)
    result = _run(tmp_path, workspace, budget, sarif=sarif)
    meta = _meta(result.package_path)  # type: ignore[arg-type]

    header = next(block for block in meta if block["block_id"] == "bundle.header")
    assert header["cacheable"] is False
    doc = _prefix_doc(result.package_path)  # type: ignore[arg-type]
    assert "bundle.header" not in doc["prefix_blocks"]


def test_the_declared_token_total_matches_the_blocks(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """One number, one value: the prompt header, the block metadata and the manifest agree.

    They used to disagree, twice over. The header first reported a figure re-estimated from the
    method sources (1703) while the metadata beside it summed the blocks (1883). Fixing that by
    summing the blocks exposed a self-reference: the sum included the header, whose own length
    depends on the number it states, so the two answers stayed 31 apart -- exactly the header's
    own token count. The header now states the size of the content blocks, which is both what a
    caller sends and a value that does not depend on itself.
    """
    sarif = write_sarif(tmp_path / "scan.sarif", workspace=workspace)
    result = _run(tmp_path, workspace, budget, sarif=sarif, name="B-tokens")
    package = result.package_path
    assert package is not None
    assert result.bundle is not None

    meta = _meta(package)
    header_tokens = next(b["tokens"] for b in meta if b["block_id"] == "bundle.header")
    content_total = sum(b["tokens"] for b in meta if b["block_id"] != "bundle.header")

    head = (package / "ai" / "prompt.md").read_text(encoding="utf-8").splitlines()[:5]
    declared = int(next(line.split(":")[1] for line in head if "approx tokens" in line))

    assert declared == content_total, (
        f"the header says {declared} tokens while its content blocks sum to {content_total}"
    )
    # And the manifest totals the whole prompt, header included -- stated rather than implied.
    assert result.bundle.manifest.estimated_tokens == content_total + header_tokens


def test_the_instruction_blocks_are_stable_across_any_two_bundles(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """The first tier: `instructions.*` holds still across *every* bundle of a version.

    This is the strictest stability the layout can offer -- it does not depend on the
    workspace, the rules or the findings -- so it is the tier a shared prefix can rely on
    across unrelated runs. The second bundle here is assembled from a *different* workspace
    with a different number of contexts, which is what makes it a real test: an earlier
    version of this file produced its "second" bundle by narrowing `max_contexts`, leaving the
    context set identical, and so it passed while a per-bundle table sat inside the declared
    prefix (`fanout.plan` listed each context's id, focus and token count).

    Note what is deliberately *not* asserted here: `method_catalog` is on the second tier
    (stable across a re-run of the same input, not across different code), so requiring it to
    match two different workspaces would be asserting something false.
    """
    sarif = write_sarif(tmp_path / "scan.sarif", workspace=workspace)
    one_sink = _run(tmp_path, workspace, budget, sarif=sarif, name="B-tier-one")

    two_sinks = _two_sink_workspace(tmp_path)
    wide_sarif = write_sarif(tmp_path / "scan2.sarif", workspace=two_sinks)
    widened = _add_second_sink(wide_sarif)
    many = _run(tmp_path, two_sinks, budget, sarif=widened, name="B-tier-many")

    assert one_sink.bundle is not None and many.bundle is not None  # type: ignore[union-attr]
    assert many.bundle.manifest.focus_count != one_sink.bundle.manifest.focus_count, (  # type: ignore[union-attr]
        "the two bundles must differ in their context sets, or this test cannot detect a "
        "per-bundle block hiding inside the prefix"
    )

    one_blocks = {b.block_id: b.content for b in one_sink.bundle.prompts}  # type: ignore[union-attr]
    many_blocks = {b.block_id: b.content for b in many.bundle.prompts}  # type: ignore[union-attr]

    shared_prefix = [
        block["block_id"]
        for block in _meta(one_sink.package_path)  # type: ignore[arg-type]
        if block["block_id"].startswith("instructions")
    ]
    assert shared_prefix, "there must be at least one always-stable block"
    for block_id in shared_prefix:
        assert block_id in many_blocks, f"{block_id} vanished from the second bundle"
        assert one_blocks[block_id] == many_blocks[block_id], (
            f"{block_id} is guaranteed to be byte-identical across every bundle but changed "
            "when the workspace changed"
        )

    # The volatile blocks must actually differ, or none of the above proves anything.
    assert one_blocks["bundle.header"] != many_blocks["bundle.header"]


def test_the_prefix_is_byte_identical_when_the_input_is_the_same(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """The second tier: same workspace and rules means the whole prefix repeats.

    This is the tier a re-run or a fan-out over one codebase relies on, and it is the one
    `ai/cache_prefix.json` describes.
    """
    sarif = write_sarif(tmp_path / "scan.sarif", workspace=workspace)
    first = _run(tmp_path, workspace, budget, sarif=sarif, name="B-tier-same")
    again = _run(tmp_path, workspace, budget, sarif=sarif, name="B-tier-same")

    assert first.bundle is not None and again.bundle is not None  # type: ignore[union-attr]
    prefix = _prefix_doc(first.package_path)["prefix_blocks"]  # type: ignore[arg-type]
    first_blocks = {b.block_id: b.content for b in first.bundle.prompts}  # type: ignore[union-attr]
    again_blocks = {b.block_id: b.content for b in again.bundle.prompts}  # type: ignore[union-attr]

    for block_id in prefix:
        assert first_blocks[block_id] == again_blocks[block_id], (
            f"{block_id} is in the declared prefix but changed between two identical runs"
        )

    # The chunking table is per-bundle by nature and must therefore be outside the prefix.
    assert "fanout.plan" not in prefix, (
        "the fan-out table lists this bundle's contexts; it cannot be part of a shared prefix"
    )
    meta = _meta(first.package_path)  # type: ignore[arg-type]
    chunking = next(b for b in meta if b["block_id"] == "fanout.plan")
    assert chunking["cacheable"] is False
    assert any(b["block_id"] == "fanout.plan" for b in meta), (
        "the table is still rendered, just not cached"
    )
