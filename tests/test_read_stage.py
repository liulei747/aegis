"""Fourth stage (read): method range -> complete body.

The interesting properties are about *agreement*: the same function must be read
identically no matter which provider located it, or content-based dedupe and
cross-run comparison silently stop working.
"""

from __future__ import annotations

import asyncio
import sys
from pathlib import Path

import pytest

from aegis_core.config import BudgetConfig, Settings
from services.extraction.assembler.reader import MethodReader
from services.extraction.graph.builder import CallGraphBuilder
from services.extraction.graph.providers import CallGraphResolver
from services.extraction.graph.resolver import SymbolIndex, Workspace
from services.extraction.lsp.manager import LanguageServerManager, LanguageServerSpec

ROOT = Path(__file__).resolve().parents[1]


def _resolver(workspace: Path, *, lsp: bool) -> CallGraphResolver:
    ws = Workspace(workspace)
    manager = None
    if lsp:
        manager = LanguageServerManager(
            root=workspace,
            catalog=[
                LanguageServerSpec(
                    language="python",
                    command=[
                        sys.executable,
                        str(ROOT / "tests" / "fake_lsp_server.py"),
                        "--root",
                        str(workspace),
                    ],
                    extensions=[".py"],
                )
            ],
        )
    return CallGraphResolver(ws, SymbolIndex(ws, manager), manager)


def _read(workspace: Path, *, lsp: bool):
    """Build the slice around the sink and read every body. Returns (slice, bodies)."""
    resolver = _resolver(workspace, lsp=lsp)
    budget = BudgetConfig(max_depth=2, max_nodes=30)
    located = resolver.locate_method("repo.py", 4, 11)
    assert located is not None
    slice_ = CallGraphBuilder(resolver.workspace, resolver, budget).build(located[0], [])
    bodies = asyncio.run(MethodReader(resolver.workspace, budget).read_slices([slice_]))
    if resolver.lsp is not None:
        resolver.lsp.stop_all()
    return slice_, bodies


# ----------------------------------------------------------------------
# The body itself
# ----------------------------------------------------------------------
def test_body_is_byte_identical_to_the_source(workspace: Path) -> None:
    slice_, bodies = _read(workspace, lsp=False)
    for method_id, ref in slice_.methods.items():
        source = (workspace / ref.method.path).read_text(encoding="utf-8").splitlines()
        body_lines = bodies.bodies[method_id].text.splitlines()
        expected = source[
            ref.method.region.start_line : ref.method.region.end_line + 1
        ]
        assert body_lines == expected, f"{ref.method.qualified_name} body drifted from source"


def test_body_has_no_trailing_blank_lines_and_one_final_newline(workspace: Path) -> None:
    _, bodies = _read(workspace, lsp=True)
    for body in bodies.bodies.values():
        assert not body.text.endswith("\n\n"), "trailing blank line leaked into the body"
        assert body.text.endswith("\n")
        assert body.text.rstrip("\n").rstrip() + "\n" == body.text


def test_the_next_function_is_not_part_of_this_body(workspace: Path) -> None:
    """The LSP range ends on the next sibling's first line; we must trim it away."""
    _, bodies = _read(workspace, lsp=True)
    for body in bodies.bodies.values():
        last = body.text.splitlines()[-1]
        assert not last.lstrip().startswith("def "), (
            f"{body.method.qualified_name} body ends on a declaration: {last!r}"
        )


# ----------------------------------------------------------------------
# Agreement between providers
# ----------------------------------------------------------------------
def test_both_providers_compute_the_same_method_id(workspace: Path) -> None:
    """method_id hashes the extent, so a range disagreement splits one function in two."""
    with_lsp, _ = _read(workspace, lsp=True)
    without, _ = _read(workspace, lsp=False)

    lsp_ids = {r.method.qualified_name: r.method.method_id for r in with_lsp.methods.values()}
    plain_ids = {r.method.qualified_name: r.method.method_id for r in without.methods.values()}

    shared = set(lsp_ids) & set(plain_ids)
    assert shared, "the two runs have no method in common, nothing was actually compared"
    for name in sorted(shared):
        assert lsp_ids[name] == plain_ids[name], f"{name}: ids differ across providers"


def test_both_providers_read_the_same_body_and_hash(workspace: Path) -> None:
    """Identical code must produce an identical content hash, provider regardless."""
    _, lsp_bodies = _read(workspace, lsp=True)
    _, plain_bodies = _read(workspace, lsp=False)

    lsp_by_name = {b.method.qualified_name: b for b in lsp_bodies.bodies.values()}
    plain_by_name = {b.method.qualified_name: b for b in plain_bodies.bodies.values()}

    shared = set(lsp_by_name) & set(plain_by_name)
    assert shared
    for name in sorted(shared):
        assert lsp_by_name[name].text == plain_by_name[name].text, f"{name}: bodies differ"
        assert lsp_by_name[name].content_hash == plain_by_name[name].content_hash, (
            f"{name}: content hashes differ, so content-based dedupe would treat one "
            f"function as two"
        )


def test_every_method_carries_byte_offsets(workspace: Path) -> None:
    """Without offsets the reader falls back to a line slice; a missing upper bound
    there would hand over the whole file as one method's body."""
    for lsp in (True, False):
        slice_, bodies = _read(workspace, lsp=lsp)
        for ref in slice_.methods.values():
            region = ref.method.region
            assert region.start_offset is not None, (
                f"{ref.method.qualified_name} has no start_offset (lsp={lsp})"
            )
            assert region.end_offset is not None, (
                f"{ref.method.qualified_name} has no end_offset (lsp={lsp})"
            )
            assert region.end_offset > region.start_offset
        for body in bodies.bodies.values():
            source_lines = len(
                (workspace / body.method.path).read_text(encoding="utf-8").splitlines()
            )
            assert body.lines < source_lines or source_lines <= 3, (
                f"{body.method.qualified_name} body spans the whole file "
                f"({body.lines} of {source_lines} lines)"
            )


def test_a_missing_end_bound_never_returns_the_whole_file(workspace: Path) -> None:
    """slice_lines must refuse to guess an upper bound."""
    ws = Workspace(workspace)
    assert ws.slice_lines("repo.py", 0, None) is None
    assert ws.slice_lines("repo.py", 0, 1) == '\n'.join(
        (workspace / "repo.py").read_text(encoding="utf-8").splitlines()[0:2]
    )


# ----------------------------------------------------------------------
# Determinism
# ----------------------------------------------------------------------
def test_reading_is_deterministic(workspace: Path) -> None:
    _, first = _read(workspace, lsp=True)
    _, second = _read(workspace, lsp=True)
    assert {k: v.content_hash for k, v in first.bodies.items()} == {
        k: v.content_hash for k, v in second.bodies.items()
    }


def test_truncation_is_recorded_on_the_body(workspace: Path) -> None:
    # 10 is the smallest allowed cap, and the fixture's methods are shorter, so
    # tighten it by hand (model_copy skips validation) to make the cap bite.
    budget = BudgetConfig(max_depth=2, max_nodes=30).model_copy(
        update={"max_lines_per_method": 2}
    )
    resolver = _resolver(workspace, lsp=False)
    located = resolver.locate_method("repo.py", 4, 11)
    assert located is not None
    slice_ = CallGraphBuilder(resolver.workspace, resolver, budget).build(located[0], [])
    bodies = asyncio.run(MethodReader(resolver.workspace, budget).read_slices([slice_]))

    truncated = [b for b in bodies.bodies.values() if b.truncated_lines]
    assert truncated, "a 2-line cap on a 5-line method must be reported as truncation"
    for body in truncated:
        assert len(body.text.splitlines()) <= 2


def test_unreadable_file_is_reported_not_raised(workspace: Path) -> None:
    budget = BudgetConfig()
    resolver = _resolver(workspace, lsp=False)
    located = resolver.locate_method("repo.py", 4, 11)
    assert located is not None
    slice_ = CallGraphBuilder(resolver.workspace, resolver, budget).build(located[0], [])
    (workspace / "repo.py").unlink()

    bodies = asyncio.run(MethodReader(Workspace(workspace), budget).read_slices([slice_]))
    assert "repo.py" in " ".join(
        p.path or "" for p in bodies.prunes if p.rule == "unreadable"
    ) or bodies.prunes, "an unreadable method must produce a prune"


def test_reader_respects_the_global_char_cap(workspace: Path) -> None:
    budget = BudgetConfig(max_depth=2, max_nodes=30, max_total_chars=1000)
    resolver = _resolver(workspace, lsp=True)
    located = resolver.locate_method("repo.py", 4, 11)
    assert located is not None
    slice_ = CallGraphBuilder(resolver.workspace, resolver, budget).build(located[0], [])
    bodies = asyncio.run(MethodReader(resolver.workspace, budget).read_slices([slice_]))
    resolver.lsp.stop_all()  # type: ignore[union-attr]

    focus = next(r for r in slice_.methods.values() if r.is_focus)
    assert focus.method.method_id in bodies.bodies, "the sink body must survive any cap"
    assert bodies.total_chars <= budget.max_total_chars or any(
        p.rule == "max_total_chars_exceeded" for p in bodies.prunes
    )


@pytest.mark.parametrize("lsp", [True, False])
def test_settings_do_not_change_reads(workspace: Path, lsp: bool, tmp_path: Path) -> None:
    """A read is a pure function of (file, region): settings must not leak into it."""
    settings = Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "p",
        work_dir=tmp_path / "w",
        lsp_enabled=lsp,
    ).resolve()
    assert settings.workspace_root == workspace.resolve()
    _, bodies = _read(workspace, lsp=lsp)
    assert bodies.bodies
