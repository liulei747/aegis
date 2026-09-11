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


def test_cacheable_blocks_are_one_contiguous_run(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """The flags must describe a run, not a scatter: a non-contiguous run is unusable."""
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
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
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
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
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    result = _run(tmp_path, workspace, budget, sarif=sarif)
    meta = _meta(result.package_path)  # type: ignore[arg-type]

    header = next(block for block in meta if block["block_id"] == "bundle.header")
    assert header["cacheable"] is False
    doc = _prefix_doc(result.package_path)  # type: ignore[arg-type]
    assert "bundle.header" not in doc["prefix_blocks"]


def test_prefix_bytes_are_identical_across_two_different_bundles(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """The claim that actually matters: a fan-out reuses one prefix across bundles.

    The two runs differ in bundle id and in how many contexts they carry, which is
    exactly the difference a fan-out sees. Everything the prefix claims to contain
    must still be byte-identical.
    """
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    wide = _run(tmp_path, workspace, budget, sarif=sarif, name="B-prefix-wide")
    narrow = _run(
        tmp_path,
        workspace,
        budget.model_copy(update={"max_contexts": 1, "max_depth": 1}),
        sarif=sarif,
        name="B-prefix-narrow",
    )

    assert wide.bundle is not None and narrow.bundle is not None  # type: ignore[union-attr]
    assert wide.bundle.manifest.bundle_id != narrow.bundle.manifest.bundle_id  # type: ignore[union-attr]

    wide_blocks = {b.block_id: b.content for b in wide.bundle.prompts}  # type: ignore[union-attr]
    narrow_blocks = {b.block_id: b.content for b in narrow.bundle.prompts}  # type: ignore[union-attr]

    prefix = _prefix_doc(wide.package_path)["prefix_blocks"]  # type: ignore[arg-type]
    assert prefix, "the prefix must not be empty"
    for block_id in prefix:
        assert block_id in narrow_blocks, f"{block_id} vanished from the second bundle"
        assert wide_blocks[block_id] == narrow_blocks[block_id], (
            f"{block_id} is declared cacheable but changed between bundles, "
            "so a shared prefix would miss"
        )

    # And the volatile blocks must actually differ, or the test proves nothing.
    assert wide_blocks["bundle.header"] != narrow_blocks["bundle.header"]
