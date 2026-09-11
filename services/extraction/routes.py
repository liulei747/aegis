"""HTTP surface of the extraction service.

Thin on purpose: it validates the request, calls the pipeline, and returns the
manifest. Anything resembling orchestration (deciding whether a scan is needed,
where the SARIF came from, what the caller asked for) belongs to the gateway.
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from aegis_contracts.domain import AnalysisBundleManifest
from aegis_core.config import BudgetConfig, Settings
from app.pipeline.assemble import AssemblyPipeline, PipelineRequest

router = APIRouter()


def _settings() -> Settings:
    """Read settings fresh: in a worker, env is stable, but tmp dirs differ per run."""
    return Settings().resolve()


class ExtractBody(BaseModel):
    workspace: str = Field(description="Repository path, as seen by *this* service.")
    sarif_path: str | None = Field(
        default=None,
        description=(
            "SARIF to assemble from. When omitted the service runs a scan itself "
            "(used by deployments with no separate scan service)."
        ),
    )
    rules: list[str] = Field(default_factory=list)
    rule_config: str | None = None
    include_globs: list[str] = Field(default_factory=list)
    exclude_globs: list[str] = Field(default_factory=list)
    rule_config_file: str | None = None
    max_findings: int | None = None
    budget: BudgetConfig | None = None
    lsp: bool = True
    package_name: str | None = None


class ExtractResult(BaseModel):
    bundle_id: str
    run_id: str
    package_path: str
    manifest: AnalysisBundleManifest
    warnings: list[str] = Field(default_factory=list)


@router.get("/health")
def health() -> dict:
    settings = _settings()
    lsp_configured = settings.lsp_config_file
    return {
        "status": "ok",
        "service": "extraction",
        "version": "0.1.0",
        "workspace_root": str(settings.workspace_root),
        "output_dir": str(settings.output_dir),
        "lsp_enabled": settings.lsp_enabled,
        "lsp_catalog": str(lsp_configured) if lsp_configured else None,
        "lsp_catalog_present": bool(lsp_configured and Path(lsp_configured).exists()),
        "budget": settings.budget.model_dump(),
    }


@router.post("/v1/extract", response_model=ExtractResult)
async def extract(body: ExtractBody) -> ExtractResult:
    workspace = Path(body.workspace)
    if not workspace.is_dir():
        raise HTTPException(status_code=400, detail=f"workspace is not a directory: {workspace}")

    sarif_path = Path(body.sarif_path) if body.sarif_path else None
    if sarif_path is not None and not sarif_path.exists():
        # Name it clearly: the usual cause is a shared-volume path mismatch between
        # the gateway and this service, not a missing file.
        raise HTTPException(
            status_code=400,
            detail=(
                f"sarif not found from this service: {sarif_path}. If the gateway produced "
                "it, check that both containers mount the same work directory."
            ),
        )

    settings = _settings()
    pipeline = AssemblyPipeline(settings)
    result = await pipeline.run(
        PipelineRequest(
            workspace=workspace,
            sarif_path=sarif_path,
            rules=body.rules,
            rule_config=body.rule_config,
            include_globs=body.include_globs,
            exclude_globs=body.exclude_globs,
            budget=body.budget,
            max_findings=body.max_findings,
            lsp=body.lsp,
            package_name=body.package_name,
        )
    )
    assert result.bundle is not None and result.package_path is not None
    return ExtractResult(
        bundle_id=result.bundle.manifest.bundle_id,
        run_id=result.run_id,
        package_path=str(result.package_path),
        manifest=result.bundle.manifest,
        warnings=result.warnings,
    )


@router.get("/v1/lsp/probe")
def lsp_probe(workspace: str | None = None) -> dict:
    """Which language servers this container can actually start for a workspace.

    Lives here rather than in the gateway because it is *this* container that owns
    the language-server processes: asking the gateway would answer about a
    different filesystem and a different set of installed servers.
    """
    from app.api.deps import probe_lsp
    from app.api.deps import resolve_workspace as _resolve

    target = _resolve(workspace)
    manager, available, missing = probe_lsp(target)
    return {
        "workspace": str(target),
        "available": available,
        "missing": missing,
        "degradations": [d.reason for d in manager.degradations],
    }
