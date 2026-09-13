"""HTTP surface of the scan service.

Two shapes, one engine:

* **`POST /v1/scan`** — run a scan and return it. Unchanged, and still what a caller with
  nothing to cancel should use; it is also the path the extraction service's in-process
  transport mirrors.
* **`POST /v1/scan/jobs`** — start a scan and return an id, then poll `GET` and stop it with
  `DELETE`. This exists because the blocking shape cannot be cancelled from outside: a
  measured cancel of a running remote scan used to take 131 seconds (the remainder of the
  scan), because the caller was parked on the HTTP response and the service had no name for
  the work in progress.

Both call `run_scan`, so there is one engine and one cancellation mechanism. The job routes
add addressability; they do not add a second implementation.

The API gateway calls this service over HTTP so scanner work is scaled, restarted and
crash-isolated independently of everything else. Locally it is also importable in-process,
which is what keeps development from requiring a queue (see `client.py`).
"""

from __future__ import annotations

import os
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from aegis_contracts.domain import Finding, ScanRecord
from aegis_core.logging import setup_logging
from services.scan.jobs import ScanJobs
from services.scan.runner import ScanRequest, run_scan

app = FastAPI(
    title="Aegis scan service",
    description="Wraps opengrep/semgrep. SARIF in or repository in, findings out.",
    version="0.1.0",
)

setup_logging(os.getenv("AEGIS_LOG_LEVEL", "INFO"))

#: One registry per process. Scans are owned by the process that spawned them; there is
#: nothing to persist.
jobs = ScanJobs(retain_s=float(os.getenv("AEGIS_SCAN_JOB_RETAIN_S", "600")))


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


class ScanJobAccepted(BaseModel):
    job_id: str
    state: str
    status_url: str


class ScanJobStatus(BaseModel):
    """A poll response. `result` is present only once the scan is terminal."""

    job_id: str
    state: str
    created_at: str
    started_at: str | None = None
    finished_at: str | None = None
    detail: str | None = None
    result: ScanResult | None = None


def _workspace(raw: str) -> Path:
    workspace = Path(raw)
    if not workspace.is_dir():
        raise HTTPException(status_code=400, detail=f"workspace is not a directory: {workspace}")
    return workspace


def _request(body: ScanBody) -> ScanRequest:
    """The request, without a cancellation source: the job supplies its own."""
    return ScanRequest(
        workspace=_workspace(body.workspace),
        rules=body.rules,
        rule_config=body.rule_config,
        include_globs=body.include_globs,
        exclude_globs=body.exclude_globs,
        out_dir=Path(body.out_dir) if body.out_dir else None,
    )


def _serialize(outcome, *, include_sarif: bool) -> ScanResult:
    """One shape for both routes, so the poll result cannot drift from the blocking one."""
    sarif_text: str | None = None
    if include_sarif and outcome.sarif_path is not None and outcome.sarif_path.exists():
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
        # Which scans are in flight. A scan that outlives its caller is invisible without
        # this, and the registry is the only place that knows.
        "running_scans": jobs.running(),
    }


@app.post("/v1/scan", response_model=ScanResult)
def scan(body: ScanBody) -> ScanResult:
    """Blocking scan. Kept as-is: callers that cannot cancel anything lose nothing here."""
    outcome = run_scan(_request(body))
    return _serialize(outcome, include_sarif=body.include_sarif)


@app.post("/v1/scan/jobs", response_model=ScanJobAccepted, status_code=202)
def submit_scan_job(body: ScanBody) -> ScanJobAccepted:
    """Start a scan and return immediately with an address for it."""
    job = jobs.submit(_request(body))
    return ScanJobAccepted(
        job_id=job.job_id,
        state=job.state,
        status_url=f"/v1/scan/jobs/{job.job_id}",
    )


@app.get("/v1/scan/jobs/{job_id}", response_model=ScanJobStatus)
def scan_job_status(job_id: str, include_sarif: bool = False) -> ScanJobStatus:
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan job not found or expired")
    snapshot = job.snapshot()
    result = None
    if job.outcome is not None:
        result = _serialize(job.outcome, include_sarif=include_sarif)
    return ScanJobStatus(**snapshot, result=result)


@app.delete("/v1/scan/jobs/{job_id}", response_model=ScanJobStatus)
def cancel_scan_job(job_id: str) -> ScanJobStatus:
    """Stop a running scan and terminate its process. Idempotent."""
    job = jobs.get(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="scan job not found or expired")
    job.cancel()
    # A scan that has already finished is not an error: the caller asked for it to be over,
    # and it is. Saying so honestly beats a 409 that invites a retry loop.
    return ScanJobStatus(**job.snapshot(), result=None)


@app.on_event("shutdown")
def _stop_running_scans() -> None:  # pragma: no cover - exercised by container restart
    """Do not leave opengrep processes behind when this service goes away."""
    jobs.shutdown()
