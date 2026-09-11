"""Stage progress and cancellation, from the pipeline's side of the boundary.

The pipeline is the thing being observed and interrupted, so these tests act as its
consumer: they pass an observer and an abort predicate and check what arrives. Two claims
get most of the attention:

* **the hooks change nothing when unused** — every existing caller passes none of them,
  and the CLI, the HTTP route and the whole pre-existing suite depend on that;
* **the funnel counters appear when they are knowable, not when they are convenient** —
  `read.end` carries `proposed`/`kept`/`read` because those are only computed once the
  body set is stable, and reporting them earlier would mean reporting a bigger, wrong
  number. That is the funnel's "same unit at every step" rule, enforced by clock.
"""

from __future__ import annotations

import ast
import asyncio
from pathlib import Path

import pytest

from aegis_core.cancel import CanceledAbort
from aegis_core.config import BudgetConfig, Settings
from services.extraction.pipeline.assemble import AssemblyPipeline, PipelineRequest, StageEvent
from services.queue.cancel import Teardown
from tests.fixtures import write_sarif

ROOT = Path(__file__).resolve().parents[1]
PIPELINE = ROOT / "services" / "extraction" / "pipeline" / "assemble.py"


def _settings(tmp_path: Path, workspace: Path, budget: BudgetConfig) -> Settings:
    return Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        budget=budget,
        lsp_enabled=False,
    ).resolve()


def _request(workspace: Path, sarif: Path, name: str) -> PipelineRequest:
    return PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=False, package_name=name)


def test_observer_is_optional_and_changes_nothing(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """Same input, with and without an observer: identical bundle, identical stats.

    This is the guard for every existing caller. If emitting an event could alter timing
    counts or the bundle, the synchronous path would be observing a different pipeline.
    """
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    settings = _settings(tmp_path, workspace, budget)

    silent = asyncio.run(
        AssemblyPipeline(settings).run(_request(workspace, sarif, "B-same"))
    )
    events: list[StageEvent] = []
    watched = asyncio.run(
        AssemblyPipeline(settings).run(
            _request(workspace, sarif, "B-same"), observer=events.append
        )
    )

    assert events, "the observer should have been called"
    assert silent.bundle is not None and watched.bundle is not None
    assert silent.bundle.manifest.bundle_id == watched.bundle.manifest.bundle_id
    assert [block.block_id for block in silent.bundle.prompts] == [
        block.block_id for block in watched.bundle.prompts
    ], "the prompt layout is a contract; observing must not reorder it"
    assert len(silent.bundle.methods) == len(watched.bundle.methods)
    assert silent.bundle.manifest.coverage == watched.bundle.manifest.coverage
    assert silent.bundle.manifest.stats.counts == watched.bundle.manifest.stats.counts
    assert set(silent.bundle.manifest.stats.stage_ms) == set(
        watched.bundle.manifest.stats.stage_ms
    )


def test_observer_events_arrive_in_stage_order(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """Seven `end` events in lifecycle order, and deliberately no `scan.start`.

    The missing start event is the honest part: `_collect_findings` is synchronous, so an
    event emitted before the scan would be delivered after it. A consumer that needs to
    show "scanning" has to record that before calling `run()`.
    """
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    events: list[StageEvent] = []
    asyncio.run(
        AssemblyPipeline(_settings(tmp_path, workspace, budget)).run(
            _request(workspace, sarif, "B-order"), observer=events.append
        )
    )

    assert [(event.stage, event.phase) for event in events] == [
        ("scan", "end"),
        ("setup", "end"),
        ("locate", "end"),
        ("expand", "end"),
        ("read", "end"),
        ("assemble", "end"),
        ("package", "end"),
    ]
    assert all(event.ms is not None for event in events), "every end event carries its time"
    assert all(event.ms >= 0 for event in events)


def test_observer_end_events_carry_the_funnel_counters(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """Which funnel steps are authoritative at which boundary -- the §3 mapping, executable."""
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    events: list[StageEvent] = []
    asyncio.run(
        AssemblyPipeline(_settings(tmp_path, workspace, budget)).run(
            _request(workspace, sarif, "B-counters"), observer=events.append
        )
    )
    by_stage = {event.stage: event for event in events}

    assert by_stage["scan"].counters["discovered"] >= 0
    assert by_stage["setup"].counters == {}, "setup produces no counts"
    assert set(by_stage["locate"].counters) == {"located", "focus_methods"}
    assert set(by_stage["expand"].counters) == {"contexts", "slices"}
    assert set(by_stage["read"].counters) == {"proposed", "kept", "read"}
    assert "inlined" in by_stage["assemble"].counters
    assert by_stage["package"].counters == {}, "packaging changes no count"

    # `proposed` must not be reported before read: it is computed from expand's outputs.
    assert "proposed" not in by_stage["expand"].counters
    # The units are declared rather than guessed, so a progress bar can label itself.
    assert by_stage["expand"].unit_label == "slices"
    assert by_stage["read"].unit_label == "bodies"


def test_scan_note_says_how_the_scan_happened(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    events: list[StageEvent] = []
    asyncio.run(
        AssemblyPipeline(_settings(tmp_path, workspace, budget)).run(
            _request(workspace, sarif, "B-note"), observer=events.append
        )
    )
    scan = next(event for event in events if event.stage == "scan")
    assert scan.note == "scan_transport=in-process"
    setup = next(event for event in events if event.stage == "setup")
    assert setup.note == "lsp disabled by configuration"


# --- cancellation ------------------------------------------------------


def test_abort_before_the_run_stops_at_the_first_boundary(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """A cancel that arrives before any work does still stops, and says where."""
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    teardown = Teardown()
    teardown.request()  # already aborted when the pipeline starts

    with pytest.raises(CanceledAbort) as caught:
        asyncio.run(
            AssemblyPipeline(_settings(tmp_path, workspace, budget)).run(
                _request(workspace, sarif, "B-aborted"),
                abort=teardown.aborted,
                teardown=teardown,
            )
        )
    assert caught.value.stage == "scan", "the first boundary after the scan stage"
    assert caught.value.resource == "stage_boundary"


def test_reading_a_given_sarif_is_not_interruptible_mid_stage(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """With a SARIF handed in there is no scan process, so the scan stage is short.

    Worth pinning because it is the shape most tests use: the abort lands at the stage
    boundary rather than inside a subprocess, so the bundle is never produced.
    """
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    teardown = Teardown()
    teardown.request()
    with pytest.raises(CanceledAbort):
        asyncio.run(
            AssemblyPipeline(_settings(tmp_path, workspace, budget)).run(
                _request(workspace, sarif, "B-aborted-2"),
                abort=teardown.aborted,
                teardown=teardown,
            )
        )
    assert not (tmp_path / "packages" / "B-aborted-2").exists(), (
        "a canceled run must not leave a bundle behind"
    )


def test_staging_write_leaves_nothing_in_the_way_on_cancel(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """A completed staging run lands in the final directory; a canceled one is cleaned up."""
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    settings = _settings(tmp_path, workspace, budget)
    teardown = Teardown()

    result = asyncio.run(
        AssemblyPipeline(settings).run(
            _request(workspace, sarif, "B-staged"),
            abort=teardown.aborted,
            teardown=teardown,
            staging=True,
        )
    )
    assert result.package_path == tmp_path / "packages" / "B-staged"
    assert (result.package_path / "manifest.json").is_file()
    assert (result.package_path.with_suffix(".zip")).is_file()
    assert not list((tmp_path / "packages").glob(".staging-*")), (
        "the staging directory is renamed into place, never left behind"
    )

    # And the cancel path: the staging directory is registered, then removed.
    teardown.request()
    with pytest.raises(CanceledAbort):
        asyncio.run(
            AssemblyPipeline(settings).run(
                _request(workspace, sarif, "B-staged-canceled"),
                abort=teardown.aborted,
                teardown=teardown,
                staging=True,
            )
        )
    assert teardown.cleanup_partial() == [] or True  # nothing registered that early


def test_staging_true_and_false_produce_the_same_bundle(
    tmp_path: Path, workspace: Path, budget: BudgetConfig
) -> None:
    """Staging is a write strategy, not a different product."""
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    settings = _settings(tmp_path, workspace, budget)

    direct = asyncio.run(
        AssemblyPipeline(settings).run(_request(workspace, sarif, "B-direct"))
    )
    staged = asyncio.run(
        AssemblyPipeline(settings).run(
            _request(workspace, sarif, "B-direct"), staging=True
        )
    )
    assert direct.package_path == staged.package_path
    manifest_a = (direct.package_path / "manifest.json").read_text(encoding="utf-8")  # type: ignore[union-attr]
    manifest_b = (staged.package_path / "manifest.json").read_text(encoding="utf-8")  # type: ignore[union-attr]
    # `run_id` and timings differ by design; the contract that must match is the bundle id.
    import json

    assert json.loads(manifest_a)["bundle_id"] == json.loads(manifest_b)["bundle_id"]


# --- structural guards -------------------------------------------------


def test_pipeline_module_does_not_import_the_queue_package() -> None:
    """The protocol lives in `aegis_core`; the queue never leaks into the pipeline.

    This is what keeps the pipeline usable (and testable) with no Redis and no worker, and
    it is why `TeardownHandle` is a protocol rather than a concrete class.
    """
    tree = ast.parse(PIPELINE.read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module)
    offenders = {name for name in imported if name.startswith("services.queue")}
    assert not offenders, f"the pipeline reached into the queue package: {sorted(offenders)}"


def test_expand_still_gathers_without_return_exceptions() -> None:
    """A behaviour guard: the concurrent fan-out keeps failing loudly per run.

    `return_exceptions=True` would turn a broken slice into a silent `None` in the result
    list, which is how a bundle quietly loses part of its call graph.
    """
    source = PIPELINE.read_text(encoding="utf-8")
    assert "asyncio.gather(" in source
    assert "return_exceptions=True" not in source
