"""API request/response contracts (kept separate from the internal domain model)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from app.core.config import BudgetConfig
from app.schemas.domain import AnalysisBundleManifest


class AssembleRequest(BaseModel):
    """Either point at a repo to scan, or hand over an existing SARIF file."""

    workspace: str | None = Field(
        default=None, description="Repo path inside the container/workspace."
    )
    sarif_path: str | None = Field(default=None, description="Pre-computed SARIF JSON.")
    rules: list[str] = Field(default_factory=list, description="opengrep --config values.")
    rule_config: str | None = Field(
        default=None, description="opengrep config path or registry id (default: auto)."
    )
    include_globs: list[str] = Field(default_factory=list)
    exclude_globs: list[str] = Field(default_factory=list)
    budget: BudgetConfig | None = None
    max_findings: int | None = Field(default=None, ge=1)
    lsp: bool = Field(default=True, description="Disable to run in syntax-only degraded mode.")
    package_name: str | None = None


class AssembleResponse(BaseModel):
    bundle_id: str
    run_id: str
    package_path: str
    manifest: AnalysisBundleManifest
    warnings: list[str] = Field(default_factory=list)


class ScanOnlyResponse(BaseModel):
    run_id: str
    findings: int
    sarif_path: str
    engine: str


class ScanRequest(BaseModel):
    workspace: str
    rules: list[str] = Field(default_factory=list)
    rule_config: str | None = None
    include_globs: list[str] = Field(default_factory=list)
    exclude_globs: list[str] = Field(default_factory=list)


class LspProbeResponse(BaseModel):
    workspace: str
    available: dict[str, Any] = Field(default_factory=dict)
    missing: dict[str, Any] = Field(default_factory=dict)
    degradations: list[str] = Field(default_factory=list)


class HealthResponse(BaseModel):
    status: str
    version: str
    opengrep: str
    lsp_enabled: bool
    capabilities: dict[str, Any] = Field(default_factory=dict)
