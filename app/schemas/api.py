"""API request/response contracts (kept separate from the internal domain model)."""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, Field

from aegis_contracts.domain import AnalysisBundleManifest
from aegis_contracts.jobs import AuditOptions
from aegis_core.config import BudgetConfig


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


class AnalyzeRequest(BaseModel):
    """Analyse an already-finished bundle with the model.

    Only `bundle_id` is required: the AI stage *consumes* a bundle, so it needs no repository,
    and asking for one would invite a second, contradictory answer about which code the verdicts
    describe.
    """

    bundle_id: str = Field(description="Which finished bundle under the output dir to analyse.")
    workspace: str | None = Field(
        default=None, description="Provenance only; the bundle already says what was analysed."
    )


class ScanRequest(BaseModel):
    workspace: str
    rules: list[str] = Field(default_factory=list)
    rule_config: str | None = None
    include_globs: list[str] = Field(default_factory=list)
    exclude_globs: list[str] = Field(default_factory=list)


class AuditRequest(BaseModel):
    """Ask the agent harness to review a whole repository.

    Optional, bounded audit controls are stored in the job and included in its fingerprint.
    """

    workspace: str = Field(description="Repo path inside the container/workspace, e.g. /data/projects/x.")
    audit_options: AuditOptions | None = None


class LspProbeResponse(BaseModel):
    workspace: str
    available: dict[str, Any] = Field(default_factory=dict)
    missing: dict[str, Any] = Field(default_factory=dict)
    degradations: list[str] = Field(default_factory=list)


class CreateProjectRequest(BaseModel):
    """Create a project by cloning a public repository.

    `https://` only, and no credential field: a request that cannot carry a token is a request
    whose token cannot end up in a log line. A private repository is brought in as an uploaded
    archive instead, which is why there is no `token` here to be tempted by.
    """

    git_url: str = Field(description="https:// URL of a public repository.")
    ref: str | None = Field(default=None, description="Branch or tag; the default branch when empty.")
    name: str | None = Field(default=None, description="Project name; derived from the URL when empty.")
    analyze: bool = Field(
        default=True,
        description="Submit one analysis job for the project once it is fetched.",
    )


class HealthResponse(BaseModel):
    status: str
    version: str
    opengrep: str
    lsp_enabled: bool
    capabilities: dict[str, Any] = Field(default_factory=dict)
