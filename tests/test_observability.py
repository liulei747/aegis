"""Observability views + endpoints.

The point of these tests is that the derived views stay *truthful*: every number
must be traceable to the manifest, and losses must be visible rather than implied.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.api.deps import clear_pipeline_cache
from app.core.config import BudgetConfig, Settings, get_settings
from app.main import create_app
from app.observability import views
from app.pipeline.assemble import AssemblyPipeline, PipelineRequest
from app.schemas.domain import AnalysisBundleManifest
from tests.fixtures import write_sarif, write_two_hits_sarif


def _run(
    tmp_path: Path,
    workspace: Path,
    *,
    budget: BudgetConfig | None = None,
    lsp: bool = False,
    name: str | None = None,
):
    settings = Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        budget=budget or BudgetConfig(max_depth=2, max_nodes=30, max_contexts=10),
        lsp_enabled=False,
    ).resolve()
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5)
    result = asyncio.run(
        AssemblyPipeline(settings).run(
            PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=lsp, package_name=name)
        )
    )
    return result, settings


def _manifest(result) -> AnalysisBundleManifest:
    assert result.bundle is not None
    return result.bundle.manifest


# ----------------------------------------------------------------------
# Views
# ----------------------------------------------------------------------
def test_overview_reports_trust_mix_and_no_warnings_for_a_clean_run(
    tmp_path: Path, workspace: Path
) -> None:
    result, _ = _run(tmp_path, workspace)
    overview = views.overview(_manifest(result))

    assert overview.context_count == 1
    # Syntax-only run: the sink plus the same-file callee it can resolve by name.
    assert overview.method_count >= 2
    assert overview.finding_count == 1
    assert overview.worst_trust == "guess"  # nothing here is a server fact
    assert set(overview.trust_mix) == {"guess"}
    assert any("no language server" in flag for flag in overview.warning_flags)


def test_overview_flags_a_scan_that_returned_nothing(tmp_path: Path, workspace: Path) -> None:
    settings = Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        lsp_enabled=False,
    ).resolve()
    empty = tmp_path / "empty.sarif"
    empty.write_text(json.dumps({"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]}))

    result = asyncio.run(
        AssemblyPipeline(settings).run(
            PipelineRequest(workspace=workspace, sarif_path=empty, lsp=False)
        )
    )
    overview = views.overview(_manifest(result))
    assert overview.context_count == 0
    assert any("no findings" in flag for flag in overview.warning_flags)


def test_funnel_counts_are_traceable_to_the_manifest(
    tmp_path: Path, workspace: Path
) -> None:
    result, _ = _run(tmp_path, workspace)
    manifest = _manifest(result)
    funnel = {step.key: step for step in views.funnel(manifest)}

    assert funnel["discovered"].count == len(manifest.findings)
    assert funnel["located"].count == 1
    assert funnel["focus_methods"].count == 1
    assert funnel["contexts"].count == len(manifest.contexts)
    assert funnel["kept"].count == len(manifest.methods)
    assert funnel["read"].count == manifest.stats.counts["bodies_read"]
    # every finding is still accounted for, and nothing was silently dropped
    assert funnel["located"].lost == 0
    assert funnel["contexts"].lost == 0
    assert manifest.coverage.rejected == 0


def test_funnel_names_the_rule_that_caused_a_loss(tmp_path: Path, workspace: Path) -> None:
    """A cap that fires must be visible in the funnel, with the rule that caused it.

    This budget truncates the walk rather than dropping a built method, which is
    the harder case: nothing is "lost" arithmetically, so the reason has to be
    carried explicitly or the funnel would read as complete.
    """
    budget = BudgetConfig(max_depth=1, max_nodes=2, max_contexts=10)
    result, _ = _run(tmp_path, workspace, budget=budget)
    manifest = _manifest(result)
    funnel = {step.key: step for step in views.funnel(manifest)}

    assert manifest.stats.counts["fanouts_skipped"] > 0
    assert funnel["kept"].loss_reasons
    assert set(funnel["kept"].loss_reasons) & {
        "max_nodes",
        "max_depth",
        "max_callees_per_node",
        "max_callers_per_node",
    }
    assert funnel["kept"].lost_items
    assert all(item["rule"] for item in funnel["kept"].lost_items)


def test_a_truncated_walk_cannot_look_complete(tmp_path: Path, workspace: Path) -> None:
    """The subtle failure mode: a fan-out we never looked up leaves no count.

    With max_depth=0 the focus's callees are never requested, so no method is
    "dropped" and every delta in the funnel is zero — yet the bundle is missing
    something. The prune detail and the funnel note must both say so.
    """
    result, _ = _run(tmp_path, workspace, budget=BudgetConfig(max_depth=0, max_nodes=10))
    manifest = _manifest(result)
    funnel = {step.key: step for step in views.funnel(manifest)}

    assert manifest.stats.counts["fanouts_skipped"] > 0
    assert manifest.stats.counts["methods_dropped_at_expand"] == 0
    assert funnel["kept"].count == 1  # only the sink
    # arithmetic cannot express the loss, so it is stated instead
    assert funnel["kept"].note and "skipped" in funnel["kept"].note
    # and the prune names what is missing, not just that the walk stopped
    depth_prune = next(p for p in manifest.prunes if p.rule == "max_depth")
    assert "never looked up" in depth_prune.detail
    assert "absent" in depth_prune.detail


def test_prune_detail_names_the_affected_method_and_fanout_direction(
    tmp_path: Path, workspace: Path
) -> None:
    result, _ = _run(tmp_path, workspace, budget=BudgetConfig(max_depth=0, max_nodes=10))
    details = [p.detail for p in _manifest(result).prunes if p.rule == "max_depth"]
    assert any("callees of query_user" in d for d in details)
    assert any("callers of query_user" in d for d in details)


def test_funnel_reports_merged_findings_as_deduped_not_lost(
    tmp_path: Path, workspace: Path
) -> None:
    settings = Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        budget=BudgetConfig(max_depth=1, max_nodes=10, max_contexts=10),
        lsp_enabled=False,
    ).resolve()
    sarif = write_two_hits_sarif(tmp_path / "two.sarif")

    result = asyncio.run(
        AssemblyPipeline(settings).run(
            PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=False)
        )
    )
    manifest = _manifest(result)
    assert len(manifest.findings) == 2
    assert len(manifest.contexts) == 1
    assert manifest.stats.counts["findings_merged_into_existing_method"] == 1
    # both findings are still accounted for
    assert manifest.coverage.bundled == 2
    assert manifest.coverage.rejected == 0


def test_timeline_shares_sum_to_one_and_cover_every_stage(
    tmp_path: Path, workspace: Path
) -> None:
    result, _ = _run(tmp_path, workspace)
    manifest = _manifest(result)
    timeline = views.timeline(manifest)

    assert {stage.key for stage in timeline} == set(manifest.stats.stage_ms)
    assert pytest.approx(sum(stage.share for stage in timeline), abs=1e-6) == 1.0
    assert timeline[0].ms >= timeline[-1].ms  # sorted slowest first
    for stage in timeline:
        assert stage.label  # every stage has a human label


def test_providers_view_sums_to_the_method_and_edge_counts(
    tmp_path: Path, workspace: Path
) -> None:
    result, _ = _run(tmp_path, workspace)
    manifest = _manifest(result)
    stats = views.providers(manifest)

    assert sum(s.methods for s in stats) == len(manifest.methods)
    assert sum(s.edges for s in stats) == len(manifest.edges)
    for stat in stats:
        assert stat.trust in {"fact", "strong", "weak", "guess", "unknown"}
        assert stat.label and stat.note
    # worst trust first: heuristics are listed before server facts
    trusts = [s.trust for s in stats]
    order = [views.TRUST_ORDER[t] for t in trusts]
    assert order == sorted(order)


def test_context_view_exposes_the_provenance_chain_for_every_method(
    tmp_path: Path, workspace: Path
) -> None:
    result, _ = _run(tmp_path, workspace)
    views_ = views.context_views(_manifest(result))

    assert len(views_) == 1
    view = views_[0]
    assert not view.unreached_focus
    focus_ids = [row["method_id"] for row in view.methods if row["is_focus"]]
    assert len(focus_ids) == 1
    focus_id = focus_ids[0]
    for row in view.methods:
        assert row["origin_chain"], f"{row['qualified_name']} has no provenance chain"
        assert row["origin_chain"][0] == focus_id, "every chain starts at the sink"
        assert row["origin_chain"][-1] == row["method_id"], "every chain ends at the method"
        assert len(row["origin_chain"]) == row["depth"] + 1
    assert view.depth_histogram
    assert view.findings and view.findings[0]["severity"] == "error"


def test_method_index_answers_why_is_this_method_here(tmp_path: Path, workspace: Path) -> None:
    result, _ = _run(tmp_path, workspace)
    manifest = _manifest(result)
    index = views.method_index(manifest)

    assert index["count"] == len(manifest.methods)
    rows = {row["qualified_name"]: row for row in index["methods"]}
    assert "query_user" in rows
    sink = rows["query_user"]
    assert sink["is_focus"] is True
    assert sink["finding_ids"]
    assert sink["contexts"]

    # the only callee a syntax-only run can resolve: same file, by name
    callee = rows["connect"]
    assert callee["is_focus"] is False
    assert callee["depth"] == 1
    assert callee["direction"] == "callee"
    assert callee["origin_chain"] == ["query_user", "connect"]
    assert callee["via"]  # the call-site snippet is kept as evidence


def test_assemble_is_idempotent_for_the_same_input(tmp_path: Path, workspace: Path) -> None:
    """Same workspace + same SARIF must produce the same bundle id and overwrite.

    This is what makes re-runs cheap and prefixes reusable, so it is asserted
    rather than assumed.
    """
    first, _ = _run(tmp_path, workspace)
    second, _ = _run(tmp_path, workspace)
    assert _manifest(first).bundle_id == _manifest(second).bundle_id
    assert _manifest(first).run_id != _manifest(second).run_id  # but the run is new


def test_diff_identifies_what_a_tighter_budget_removed(
    tmp_path: Path, workspace: Path
) -> None:
    # The fixture only has one method of depth 2, so the interesting axis is the
    # node cap: the loose run keeps exploring, the tight run stops at the sink.
    loose, _ = _run(
        tmp_path / "a", workspace, budget=BudgetConfig(max_depth=3, max_nodes=30), name="B-loose"
    )
    tight, _ = _run(
        tmp_path / "b", workspace, budget=BudgetConfig(max_depth=1, max_nodes=1), name="B-tight"
    )
    delta = views.diff(_manifest(loose), _manifest(tight))

    assert delta["left"]["bundle_id"] == "B-loose"
    assert delta["right"]["bundle_id"] == "B-tight"
    assert delta["left"]["methods"] > delta["right"]["methods"]
    assert delta["delta"]["methods"] < 0
    assert delta["methods"]["only_left"], "the tighter run should be missing methods"
    # the tighter run stopped walking, and says so instead of looking complete
    tight_counts = _manifest(tight).stats.counts
    assert tight_counts["fanouts_skipped"] > 0
    assert tight_counts["methods_kept"] < _manifest(loose).stats.counts["methods_kept"]


def test_scan_summary_surfaces_the_invocation(tmp_path: Path, workspace: Path) -> None:
    result, _ = _run(tmp_path, workspace)
    summary = views.scan_summary(_manifest(result))

    assert summary is not None
    assert summary["engine"] == "sarif-input"
    assert summary["configured"] is True
    assert summary["rule_counts"] == {"python.lang.security.sql-injection": 1}
    assert summary["severity_counts"] == {"error": 1}
    assert summary["top_paths"] == [("repo.py", 1)]


def test_views_do_not_mutate_the_manifest(tmp_path: Path, workspace: Path) -> None:
    result, _ = _run(tmp_path, workspace)
    manifest = _manifest(result)
    before = manifest.model_dump_json()

    views.overview(manifest)
    views.funnel(manifest)
    views.timeline(manifest)
    views.providers(manifest)
    views.context_views(manifest)
    views.method_index(manifest)
    views.diff(manifest, manifest)
    views.scan_summary(manifest)

    assert manifest.model_dump_json() == before


# ----------------------------------------------------------------------
# Endpoints
# ----------------------------------------------------------------------
@pytest.fixture()
def client(tmp_path: Path, workspace: Path, monkeypatch) -> TestClient:
    monkeypatch.setenv("AEGIS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(tmp_path / "packages"))
    monkeypatch.setenv("AEGIS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AEGIS_LSP_ENABLED", "false")
    # Both caches must be dropped: the pipeline holds a Settings snapshot, so
    # leaving it cached makes tests share whichever tmp dir ran first.
    get_settings.cache_clear()
    clear_pipeline_cache()
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()
    clear_pipeline_cache()


def _assemble(client: TestClient, workspace: Path, tmp_path: Path, name: str | None = None) -> str:
    sarif = write_sarif(tmp_path / f"api-{name or 'x'}.sarif", sink_line=5, workspace=workspace)
    data = {"workspace": str(workspace), "lsp": "false"}
    if name:
        data["package_name"] = name
    with sarif.open("rb") as handle:
        response = client.post(
            "/v1/assemble/upload",
            files={"sarif": ("api.sarif", handle, "application/json")},
            data=data,
        )
    assert response.status_code == 200, response.text
    return response.json()["bundle_id"]


def test_observability_endpoint_returns_every_view(
    client: TestClient, tmp_path: Path, workspace: Path
) -> None:
    bundle_id = _assemble(client, workspace, tmp_path)
    body = client.get(f"/v1/bundles/{bundle_id}/observability").json()

    assert body["overview"]["bundle_id"] == bundle_id
    assert [step["key"] for step in body["funnel"]][0] == "discovered"
    assert body["timeline"] and body["providers"]
    assert body["scan"]["engine"] == "sarif-input"
    assert body["provider_legend"]["syntax_regex"]["trust"] == "guess"
    assert body["stage_labels"]["locate"] == "locate enclosing method"
    assert isinstance(body["counts"], dict)
    assert body["counts"]["findings_discovered"] == 1


def test_contexts_and_methods_endpoints(
    client: TestClient, tmp_path: Path, workspace: Path
) -> None:
    bundle_id = _assemble(client, workspace, tmp_path)

    contexts = client.get(f"/v1/bundles/{bundle_id}/contexts").json()["contexts"]
    assert len(contexts) == 1
    assert contexts[0]["methods"][0]["origin_chain"]

    methods = client.get(f"/v1/bundles/{bundle_id}/methods").json()
    assert methods["count"] >= 2
    assert all(row["trust"] for row in methods["methods"])


def test_diff_endpoint_compares_two_bundles(
    client: TestClient, tmp_path: Path, workspace: Path
) -> None:
    first = _assemble(client, workspace, tmp_path, name="B-diff-a")
    second = _assemble(client, workspace, tmp_path, name="B-diff-b")
    body = client.get(f"/v1/bundles/{first}/diff/{second}").json()
    assert body["left"]["bundle_id"] == first
    assert body["right"]["bundle_id"] == second
    assert "delta" in body


def test_list_bundles_surfaces_trust_and_engine(
    client: TestClient, tmp_path: Path, workspace: Path
) -> None:
    bundle_id = _assemble(client, workspace, tmp_path, name="B-listed")
    listing = client.get("/v1/bundles").json()["bundles"]
    row = next(b for b in listing if b["bundle_id"] == bundle_id)
    assert row["providers"] == ["syntax_regex"]
    assert row["engine"] == "sarif-input"
    assert row["focus_count"] == 1


def test_review_console_renders_the_observability_views(
    client: TestClient, tmp_path: Path, workspace: Path
) -> None:
    """The page is a renderer, not a calculator: it must only consume the API."""
    _assemble(client, workspace, tmp_path, name="B-console")
    page = client.get("/")
    assert page.status_code == 200
    body = page.text
    # it reads the derived views...
    for endpoint in ("/observability", "/contexts", "/diff/", "/v1/bundles"):
        assert endpoint in body
    # ...and does not reach for raw artifact files or re-derive findings itself
    for forbidden in ("/manifest", "blocks.jsonl"):
        assert forbidden not in body
    assert "Funnel" in body and "Providers" in body and "why each method is here" in body.lower()


def test_bundle_endpoints_reject_traversal_and_unknown_ids(client: TestClient) -> None:
    assert client.get("/v1/bundles/..%2F..%2Fetc/observability").status_code in (400, 404)
    assert client.get("/v1/bundles/nope/observability").status_code == 404
