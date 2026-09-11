"""HTTP surface of the scan service.

One endpoint, no state, no database. The API gateway calls this over HTTP so that
scanner work is scaled, restarted and crash-isolated independently of everything
else. Locally it is also importable in-process, which is what keeps development
from requiring a queue (see `client.py`).
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from aegis_contracts.domain import Finding, ScanRecord
from aegis_core.logging import setup_logging
from services.scan.runner import ScanRequest, run_scan

app = FastAPI(
    title="Aegis scan service",
    description="Wraps opengrep/semgrep. SARIF in or repository in, findings out.",
    version="0.1.0",
)

setup_logging(os.getenv("AEGIS_LOG_LEVEL", "INFO"))


class ScanBody(BaseModel):
    workspace: str = Field(description="Repository path, as seen by this service.")
    rules: list[str] = Field(default_factory=list, description="opengrep --config values.")
    rule_config: str | None = None
    include_globs: list[str] = Field(default_factory=list)
    exclude_globs: list[str] = Field(default_factory=list)
    out_dir: str | None = Field(
        default=None, description="Where to write the raw SARIF. Defaults to a temp dir."
    )
    include_sarif: bool = Field(
        default=False,
        description=(
            "Return the SARIF document inline. Needed when the caller (extraction) runs "
            "in another container and cannot read this service's filesystem."
        ),
    )


class ScanResult(BaseModel):
    engine: str
    engine_version: str = ""
    sarif_path: str | None = None
    sarif: str | None = Field(
        default=None, description="The raw SARIF document, when `include_sarif` was set."
    )
    findings: list[Finding] = Field(default_factory=list)
    scan_record: ScanRecord
    warnings: list[str] = Field(default_factory=list)
    degraded: bool = False


@app.get("/health")
def health() -> dict:
    from services.scan.runner import probe

    engine = probe()
    # `engine_version` rather than `version`: spreading the probe dict used to
    # overwrite the service's own version and report opengrep's instead.
    return {
        "status": "ok" if engine["available"] else "degraded",
        "service": "scan",
        "version": app.version,
        "available": engine.get("available", False),
        "binary": engine.get("binary"),
        "path": engine.get("path"),
        "engine_version": engine.get("version"),
        "degraded": engine.get("degraded", False),
        "fallback": engine.get("fallback"),
        "reason": engine.get("reason"),
    }


@app.post("/v1/scan", response_model=ScanResult)
def scan(body: ScanBody) -> ScanResult:
    workspace = Path(body.workspace)
    if not workspace.is_dir():
        raise HTTPException(status_code=400, detail=f"workspace is not a directory: {workspace}")

    outcome = run_scan(
        ScanRequest(
            workspace=workspace,
            rules=body.rules,
            rule_config=body.rule_config,
            include_globs=body.include_globs,
            exclude_globs=body.exclude_globs,
            out_dir=Path(body.out_dir) if body.out_dir else None,
        )
    )
    sarif_text: str | None = None
    if body.include_sarif and outcome.sarif_path is not None and outcome.sarif_path.exists():
        sarif_text = outcome.sarif_path.read_text(encoding="utf-8", errors="replace")

    return ScanResult(
        engine=outcome.engine,
        engine_version=outcome.engine_version,
        sarif_path=str(outcome.sarif_path) if outcome.sarif_path else None,
        sarif=sarif_text,
        findings=outcome.findings,
        scan_record=outcome.scan_record,
        warnings=outcome.warnings,
        degraded=outcome.degraded,
    )
