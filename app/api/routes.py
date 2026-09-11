"""HTTP surface.

The API is deliberately small: one call to produce a bundle, plus inspection
endpoints for the pipeline's own observability. Tool choice is not the agent's
problem here — the agent receives a finished bundle.
"""

from __future__ import annotations

import asyncio
import json
import shutil
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from aegis_contracts.domain import AnalysisBundleManifest
from aegis_core.config import Settings
from aegis_core.logging import get_logger
from app import __version__
from app.api.deps import (
    bundle_dir,
    get_pipeline,
    get_scan_pipeline,
    get_settings,
    load_manifest,
    load_method_body,
    probe_lsp,
    resolve_workspace,
)
from app.observability import views
from app.pipeline.assemble import AssemblyPipeline, PipelineRequest, ScanOnlyPipeline
from app.schemas.api import (
    AssembleRequest,
    AssembleResponse,
    HealthResponse,
    LspProbeResponse,
    ScanOnlyResponse,
    ScanRequest,
)
from services.extraction.client import (
    ExtractionUnavailable,
    extraction_is_remote,
    request_extraction,
)
from services.scan.opengrep import OpengrepRunner

log = get_logger(__name__)
router = APIRouter()

SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")


def _safe_segment(value: str) -> str:
    if not value or any(ch not in SAFE for ch in value) or ".." in value:
        raise HTTPException(status_code=400, detail=f"unsafe path segment: {value!r}")
    return value


@router.get("/health", response_model=HealthResponse)
def health(settings: Settings = Depends(get_settings)) -> HealthResponse:
    """Report the scanner that will actually be used.

    When scanning is delegated, the local binary is irrelevant, so the remote
    service is probed instead — otherwise this endpoint answers a question nobody
    asked and hides an unreachable scan service behind a stale local version.
    """
    from services.scan.client import scan_service_url

    remote = scan_service_url()
    engine = _probe_remote_scanner(remote) if remote else _local_scanner(settings)

    return HealthResponse(
        status="ok" if not engine.startswith("scan service") else "degraded",
        version=__version__,
        opengrep=engine,
        lsp_enabled=settings.lsp_enabled,
        capabilities={
            "workspace_root": str(settings.workspace_root),
            "output_dir": str(settings.output_dir),
            "budget": settings.budget.model_dump(),
            "scan_transport": "remote" if remote else "in-process",
            "scan_service_url": remote,
        },
    )


def _local_scanner(settings: Settings) -> str:
    runner = OpengrepRunner(settings.opengrep_bin, fallback_binary=settings.opengrep_fallback_bin)
    return runner.version()


def _probe_remote_scanner(url: str) -> str:
    """What the scan service says it can run, or an explicit failure."""
    try:
        import httpx

        response = httpx.get(f"{url}/health", timeout=5.0)
        response.raise_for_status()
        body = response.json()
    except Exception as exc:
        return f"scan service unreachable: {exc}"
    if not body.get("available"):
        return f"scan service has no engine ({body.get('reason', 'unknown')})"
    return f"{body.get('binary')} {body.get('engine_version')} (remote)"


@router.post("/v1/scan", response_model=ScanOnlyResponse)
def scan(
    payload: ScanRequest,
    pipeline: ScanOnlyPipeline = Depends(get_scan_pipeline),
) -> ScanOnlyResponse:
    workspace = resolve_workspace(payload.workspace)
    result = pipeline.run(
        PipelineRequest(
            workspace=workspace,
            rules=payload.rules,
            rule_config=payload.rule_config,
            include_globs=payload.include_globs,
            exclude_globs=payload.exclude_globs,
        )
    )
    return ScanOnlyResponse(
        run_id=result.run_id,
        findings=len(result.findings),
        sarif_path=str(result.sarif_path) if result.sarif_path else "",
        engine=result.scan_engine or "unknown",
    )


@router.post("/v1/assemble", response_model=AssembleResponse)
async def assemble(
    payload: AssembleRequest,
    pipeline: AssemblyPipeline = Depends(get_pipeline),
) -> AssembleResponse:
    workspace = resolve_workspace(payload.workspace)
    sarif_path = Path(payload.sarif_path) if payload.sarif_path else None
    if sarif_path is not None and not sarif_path.exists():
        raise HTTPException(status_code=400, detail=f"sarif not found: {sarif_path}")

    # Delegated deployment: hand the whole job to the extraction service. The
    # gateway stays thin, and a language server that dies there cannot kill the API.
    if extraction_is_remote():
        return await _assemble_remotely(payload, workspace, sarif_path)

    result = await pipeline.run(
        PipelineRequest(
            workspace=workspace,
            sarif_path=sarif_path,
            rules=payload.rules,
            rule_config=payload.rule_config,
            include_globs=payload.include_globs,
            exclude_globs=payload.exclude_globs,
            budget=payload.budget,
            max_findings=payload.max_findings,
            lsp=payload.lsp,
            package_name=payload.package_name,
        )
    )
    assert result.bundle is not None and result.package_path is not None
    return AssembleResponse(
        bundle_id=result.bundle.manifest.bundle_id,
        run_id=result.run_id,
        package_path=str(result.package_path),
        manifest=result.bundle.manifest,
        warnings=result.warnings,
    )


async def _assemble_remotely(
    payload: AssembleRequest, workspace: Path, sarif_path: Path | None
) -> AssembleResponse:
    """Delegate the whole assembly to the extraction service."""
    body: dict = {
        "workspace": str(workspace),
        "sarif_path": str(sarif_path) if sarif_path else None,
        "rules": payload.rules,
        "rule_config": payload.rule_config,
        "include_globs": payload.include_globs,
        "exclude_globs": payload.exclude_globs,
        "max_findings": payload.max_findings,
        "lsp": payload.lsp,
        "package_name": payload.package_name,
    }
    if payload.budget is not None:
        body["budget"] = payload.budget.model_dump()

    try:
        result = await asyncio.to_thread(request_extraction, body)
    except ExtractionUnavailable as exc:
        # 503, not 500: the request was fine, a *dependency* is down. A caller can
        # retry, and the message names the service so an operator knows where to look.
        raise HTTPException(status_code=503, detail=str(exc)) from exc

    return AssembleResponse(
        bundle_id=result["bundle_id"],
        run_id=result["run_id"],
        package_path=result["package_path"],
        manifest=AnalysisBundleManifest.model_validate(result["manifest"]),
        warnings=list(result.get("warnings", [])),
    )


@router.post("/v1/assemble/upload", response_model=AssembleResponse)
async def assemble_upload(
    sarif: UploadFile = File(..., description="SARIF produced by opengrep/semgrep"),
    workspace: str = Form(...),
    lsp: bool = Form(True),
    max_findings: int | None = Form(None),
    budget_json: str | None = Form(None),
    package_name: str | None = Form(
        None, description="explicit bundle id; reused ids overwrite the previous bundle"
    ),
    pipeline: AssemblyPipeline = Depends(get_pipeline),
    settings: Settings = Depends(get_settings),
) -> AssembleResponse:
    workspace_path = resolve_workspace(workspace)
    upload_dir = settings.work_dir / "uploads"
    upload_dir.mkdir(parents=True, exist_ok=True)
    target = upload_dir / _safe_segment(sarif.filename or "upload.sarif")
    with target.open("wb") as handle:
        shutil.copyfileobj(sarif.file, handle)

    budget = None
    if budget_json:
        from aegis_core.config import BudgetConfig

        try:
            budget = BudgetConfig(**json.loads(budget_json))
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"invalid budget_json: {exc}") from exc

    result = await pipeline.run(
        PipelineRequest(
            workspace=workspace_path,
            sarif_path=target,
            lsp=lsp,
            max_findings=max_findings,
            budget=budget,
            package_name=package_name,
        )
    )
    assert result.bundle is not None and result.package_path is not None
    return AssembleResponse(
        bundle_id=result.bundle.manifest.bundle_id,
        run_id=result.run_id,
        package_path=str(result.package_path),
        manifest=result.bundle.manifest,
        warnings=result.warnings,
    )


@router.get("/v1/bundles")
def list_bundles(settings: Settings = Depends(get_settings)) -> dict:
    root = settings.output_dir
    if not root.exists():
        return {"bundles": []}
    bundles = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir():
            continue
        manifest = entry / "manifest.json"
        summary = {"bundle_id": entry.name, "path": str(entry)}
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                stats = data.get("stats") or {}
                coverage = data.get("coverage") or {}
                summary.update(
                    {
                        "created_at": data.get("created_at"),
                        "focus_count": data.get("focus_count"),
                        "estimated_tokens": data.get("estimated_tokens"),
                        "coverage": coverage,
                        "duration_ms": stats.get("duration_ms"),
                        "prune_count": len(data.get("prunes") or []),
                        "degradation_count": len(data.get("degradations") or []),
                        # Surface the trust level of every method in the list view:
                        # a bundle built from heuristics should look different at a glance.
                        "providers": sorted(
                            {m.get("provider") for m in (data.get("methods") or []) if m.get("provider")}
                        ),
                        "engine": (stats.get("scan") or {}).get("engine"),
                        "zero_findings_suspicious": (stats.get("scan") or {}).get(
                            "zero_findings_is_suspicious"
                        ),
                    }
                )
            except json.JSONDecodeError:
                summary["error"] = "manifest unreadable"
        bundles.append(summary)
    bundles.sort(key=lambda b: b.get("created_at") or "", reverse=True)
    return {"bundles": bundles}


# ----------------------------------------------------------------------
# Observability: read-only derived views. The same builders feed the HTML
# console, so the JSON and the page can never disagree.
# ----------------------------------------------------------------------
@router.get("/v1/bundles/{bundle_id}/observability")
def bundle_observability(bundle_id: str, settings: Settings = Depends(get_settings)) -> dict:
    manifest = load_manifest(bundle_id, settings)
    return {
        "overview": asdict(views.overview(manifest)),
        "funnel": [asdict(step) for step in views.funnel(manifest)],
        "timeline": [asdict(stage) for stage in views.timeline(manifest)],
        "providers": [asdict(stat) for stat in views.providers(manifest)],
        "scan": views.scan_summary(manifest),
        "degradations": [d.model_dump() for d in manifest.degradations],
        "prunes": [p.model_dump() for p in manifest.prunes],
        "provider_legend": views.PROVIDER_NOTES,
        "stage_labels": views.STAGE_LABELS,
        "counts": manifest.stats.counts,
    }


@router.get("/v1/bundles/{bundle_id}/contexts")
def bundle_contexts(bundle_id: str, settings: Settings = Depends(get_settings)) -> dict:
    manifest = load_manifest(bundle_id, settings)
    return {"contexts": [asdict(view) for view in views.context_views(manifest)]}


@router.get("/v1/bundles/{bundle_id}/methods")
def bundle_methods(bundle_id: str, settings: Settings = Depends(get_settings)) -> dict:
    manifest = load_manifest(bundle_id, settings)
    return views.method_index(manifest)


@router.get("/v1/bundles/{bundle_id}/methods/{method_id}/body", response_class=PlainTextResponse)
def method_body(
    bundle_id: str, method_id: str, settings: Settings = Depends(get_settings)
) -> PlainTextResponse:
    """One method's complete source, as stored in the package."""
    return PlainTextResponse(
        load_method_body(bundle_id, method_id, settings), media_type="text/plain"
    )


@router.get("/v1/bundles/{bundle_id}/diff/{other_id}")
def bundle_diff(
    bundle_id: str, other_id: str, settings: Settings = Depends(get_settings)
) -> dict:
    left = load_manifest(bundle_id, settings)
    right = load_manifest(other_id, settings)
    return views.diff(left, right)


@router.get("/v1/bundles/{bundle_id}/manifest")
def bundle_manifest(bundle_id: str, settings: Settings = Depends(get_settings)) -> JSONResponse:
    manifest = load_manifest(bundle_id, settings)
    return JSONResponse(json.loads(manifest.model_dump_json()))


@router.get("/v1/bundles/{bundle_id}/summary", response_class=PlainTextResponse)
def bundle_summary(bundle_id: str, settings: Settings = Depends(get_settings)) -> PlainTextResponse:
    directory = bundle_dir(bundle_id, settings)
    summary = directory / "summary.md"
    if not summary.exists():
        raise HTTPException(status_code=404, detail="summary not found")
    return PlainTextResponse(summary.read_text(encoding="utf-8"), media_type="text/markdown")


@router.get("/v1/bundles/{bundle_id}/blocks")
def bundle_blocks(bundle_id: str, settings: Settings = Depends(get_settings)) -> JSONResponse:
    directory = bundle_dir(bundle_id, settings)
    meta = directory / "ai" / "blocks_meta.json"
    if not meta.exists():
        raise HTTPException(status_code=404, detail="blocks not found")
    return JSONResponse(json.loads(meta.read_text(encoding="utf-8")))


@router.get("/v1/bundles/{bundle_id}/blocks/{block_id}", response_class=PlainTextResponse)
def bundle_block(
    bundle_id: str, block_id: str, settings: Settings = Depends(get_settings)
) -> PlainTextResponse:
    directory = bundle_dir(bundle_id, settings)
    path = directory / "ai" / "blocks.jsonl"
    if not path.exists():
        raise HTTPException(status_code=404, detail="blocks not found")
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        block = json.loads(line)
        if block.get("block_id") == block_id:
            return PlainTextResponse(block["content"], media_type="text/markdown")
    raise HTTPException(status_code=404, detail=f"block not found: {block_id}")


@router.get("/v1/bundles/{bundle_id}/graph", response_class=PlainTextResponse)
def bundle_graph(bundle_id: str, settings: Settings = Depends(get_settings)) -> PlainTextResponse:
    directory = bundle_dir(bundle_id, settings)
    dot = directory / "graph" / "callgraph.dot"
    if not dot.exists():
        raise HTTPException(status_code=404, detail="graph not found")
    return PlainTextResponse(dot.read_text(encoding="utf-8"), media_type="text/vnd.graphviz")


@router.get("/v1/bundles/{bundle_id}/archive")
def bundle_archive(bundle_id: str, settings: Settings = Depends(get_settings)) -> FileResponse:
    directory = bundle_dir(bundle_id, settings)
    archive = directory.with_suffix(".zip")
    if not archive.exists():
        raise HTTPException(status_code=404, detail="archive not found")
    return FileResponse(archive, media_type="application/zip", filename=f"{bundle_id}.zip")


@router.get("/v1/lsp/probe", response_model=LspProbeResponse)
def lsp_probe(workspace: str | None = None) -> LspProbeResponse:
    workspace_path = resolve_workspace(workspace)
    manager, available, missing = probe_lsp(workspace_path)
    return LspProbeResponse(
        workspace=str(workspace_path),
        available=available,
        missing=missing,
        degradations=[d.reason for d in manager.degradations],
    )
