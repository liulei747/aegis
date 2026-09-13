"""HTTP surface.

The API is deliberately small: one call to produce a bundle, plus inspection
endpoints for the pipeline's own observability. Tool choice is not the agent's
problem here — the agent receives a finished bundle.
"""

from __future__ import annotations

import asyncio
import json
import os
import shutil
from dataclasses import asdict
from pathlib import Path

from fastapi import APIRouter, Depends, File, Form, HTTPException, Query, Response, UploadFile
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse

from aegis_contracts import views
from aegis_contracts.ai import AIReport
from aegis_contracts.domain import AnalysisBundleManifest
from aegis_contracts.jobs import JobAcceptedResponse, JobKind
from aegis_contracts.projects import ProjectRecord, ProjectSource
from aegis_core.config import Settings
from aegis_core.logging import get_logger
from app import __version__
from app.api.deps import (
    bundle_dir,
    get_job_queue,
    get_pipeline,
    get_scan_pipeline,
    get_settings,
    load_manifest,
    load_method_body,
    probe_lsp,
    queue_enabled,
    resolve_workspace,
)
from app.api.jobs import submit
from app.schemas.api import (
    AnalyzeRequest,
    AssembleRequest,
    AssembleResponse,
    CreateProjectRequest,
    HealthResponse,
    LspProbeResponse,
    ScanOnlyResponse,
    ScanRequest,
)
from services.ai.runner import analyse_bundle, write_report
from services.extraction.client import (
    ExtractionUnavailable,
    extraction_is_remote,
    request_extraction,
)
from services.extraction.pipeline.assemble import (
    AssemblyPipeline,
    PipelineRequest,
    ScanOnlyPipeline,
)
from services.projects import (
    ProjectError,
    ProjectExists,
    ProjectRejected,
    ProjectTooLarge,
    detect_languages,
    extract_archive,
    fetch_git,
    find_record,
    list_records,
    name_from_url,
    slugify,
    write_record,
)
from services.scan.opengrep import OpengrepRunner

log = get_logger(__name__)
router = APIRouter()

SAFE = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")


def _safe_segment(value: str) -> str:
    if not value or any(ch not in SAFE for ch in value) or ".." in value:
        raise HTTPException(status_code=400, detail=f"不安全的路径段：{value!r}")
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
        status="ok" if not engine.startswith("扫描服务") else "degraded",
        version=__version__,
        opengrep=engine,
        lsp_enabled=settings.lsp_enabled,
        capabilities={
            "workspace_root": str(settings.workspace_root),
            "output_dir": str(settings.output_dir),
            "budget": settings.budget.model_dump(),
            "scan_transport": "remote" if remote else "in-process",
            "scan_service_url": remote,
            # Whether the AI stage could run if asked. The one thing nobody can tell by looking
            # at a container: it is enabled in config but has no credential, which fails safely
            # and invisibly. Booleans only -- the key's *value* never appears here.
            "ai": {
                "enabled": settings.ai.enabled,
                "model": settings.ai.model,
                "endpoint_configured": bool(settings.ai.base_url),
                "api_key_present": bool(
                    os.environ.get(settings.ai.api_key_env, "").strip()
                ),
                "api_key_env": settings.ai.api_key_env,
                "concurrency": settings.ai.concurrency,
            },
            # Whether projects can be created at all, so a front-end can hide the form rather
            # than offer one whose every submission fails. `writable` is the honest part: the
            # feature can be enabled in config while the volume is mounted read-only.
            "projects": {
                "enabled": settings.projects.enabled,
                "root": str(settings.projects.root),
                "writable": _projects_root_writable(settings.projects),
                "allow_private_hosts": settings.projects.allow_private_hosts,
                # What this deployment can actually analyse, per depth. Published so a client
                # can warn about a project *before* an analysis runs: uploading a Java archive
                # to an image without `jdtls` yields opengrep findings, a heuristic call graph
                # and no taint flow, and nothing else in the API says so.
                "deep_analysis": {
                    "call_graph": _installable_languages()[0],
                    # The taint stage is Joern with one hardcoded frontend (pysrc2cpg), so this
                    # list is a fact about the code rather than about the image.
                    "taint": ["python"],
                },
            },
        },
    )


@router.get("/v1/settings")
def settings_view(settings: Settings = Depends(get_settings)) -> dict:
    """The effective configuration, read-only.

    Every value here comes from an environment variable, so there is nothing to write back: the
    honest answer to "can I change this?" is that it is a redeploy, and a PUT route would either
    lie or mutate a process-local copy that the next request re-reads from the environment.

    The AI credential is the one field with a rule of its own. The *name* of the variable is part
    of the configuration a caller needs in order to diagnose "the stage is enabled but has no
    key"; the key's *value* is not configuration and never appears -- not here, not in `/health`,
    not in a bundle. `api_key_present` carries the only part a caller can act on.
    """
    ai = settings.ai
    return {
        "workspace_root": str(settings.workspace_root),
        "output_dir": str(settings.output_dir),
        "work_dir": str(settings.work_dir),
        "log_level": settings.log_level,
        "budget": settings.budget.model_dump(mode="json"),
        "queue": settings.queue.model_dump(mode="json"),
        "dataflow": settings.dataflow.model_dump(mode="json"),
        # Keys describing what the stage *is* are configuration; `api_key_env` is the variable's
        # name and is safe, and the value behind it is replaced by the boolean.
        "ai": {
            "enabled": ai.enabled,
            "model": ai.model,
            "base_url": ai.base_url,
            "api_key_env": ai.api_key_env,
            "api_key_present": bool(os.environ.get(ai.api_key_env, "").strip()),
            "timeout_s": ai.timeout_s,
            "concurrency": ai.concurrency,
            "temperature": ai.temperature,
            "max_contexts": ai.max_contexts,
        },
        "cors": settings.cors.model_dump(mode="json"),
        "note": (
            "只读：这些值来自环境变量，因此修改其中一个需要重新部署，而不是发一个请求"
        ),
    }


def _local_scanner(settings: Settings) -> str:
    runner = OpengrepRunner(settings.opengrep_bin, fallback_binary=settings.opengrep_fallback_bin)
    return runner.version()


# ----------------------------------------------------------------------
# Projects: get source code into the projects root, then analyse it.
#
# Every other service mounts one target read-only at /workspace, which cannot receive new
# code, so projects land in a separate root instead (see `services/projects/fetcher.py`).
# ----------------------------------------------------------------------


def _projects_root(settings: Settings) -> Path:
    if not settings.projects.enabled:
        raise HTTPException(status_code=503, detail="项目功能已关闭（AEGIS_PROJECTS__ENABLED=false）")
    return Path(settings.projects.root)


def _installable_languages() -> tuple[list[str], list[str]]:
    """Which language servers this image can actually start.

    Never raises: `/health` must answer even when the LSP catalog is missing or malformed, and a
    capability report that takes the health check down with it is worse than one that says
    "none".
    """
    try:
        from services.extraction.lsp.probe import installable_languages

        return installable_languages()
    except Exception:  # noqa: BLE001 - see docstring
        log.warning("could not read the LSP catalog for /health", exc_info=True)
        return [], []


def _projects_root_writable(config) -> bool:
    """Can this deployment actually create a project?

    Checked rather than assumed because the projects root is mounted read-only in every service
    that analyses code, and only the gateway gets it writable. A deployment that mounts it
    read-only everywhere looks configured and fails on the first upload, so `/health` answers
    the question instead of leaving it to be discovered.
    """
    if not config.enabled:
        return False
    root = Path(config.root)
    try:
        # Created if absent: the route creates it on first use, so "not there yet" is a
        # deployment that has not made a project, not one that cannot.
        root.mkdir(parents=True, exist_ok=True)
        probe = root / f".write-probe-{os.getpid()}"
        probe.touch()
        probe.unlink()
        return True
    except OSError:
        return False


def _submit_analysis(project_dir: Path, *, store, stream, settings: Settings) -> str | None:
    """Submit one analysis job for a freshly created project.

    Reuses `app.api.jobs.submit` rather than reimplementing it: the fingerprint is what makes a
    resubmission of the same work collapse onto the existing job, and a second implementation
    would be a second definition of "the same work".

    A queue that disappears between the pre-flight check and here is not worth destroying a
    fetched project over -- the sources are the expensive part and re-fetching them may not even
    be possible. The record keeps `job_id = None`, which the front-end renders as "created but
    not analysed", and the caller can submit from the jobs screen.
    """
    probe = Response()
    try:
        accepted = submit(
            payload=AssembleRequest(workspace=str(project_dir)),
            kind=JobKind.ASSEMBLE,
            force=False,
            store=store,
            stream=stream,
            settings=settings,
            response=probe,
        )
    except HTTPException as exc:
        log.warning("project %s was created but its analysis was not submitted: %s", project_dir, exc.detail)
        return None
    return getattr(accepted, "job_id", None)


@router.get("/v1/projects")
def list_projects(settings: Settings = Depends(get_settings)) -> dict:
    """Every registered project, newest first.

    Read straight off disk: the registry *is* the directories, so there is no index that can
    disagree with what is there.
    """
    root = Path(settings.projects.root)
    return {"projects": [record.model_dump(mode="json") for record in list_records(root)]}


@router.get("/v1/projects/{name}")
def get_project(name: str, settings: Settings = Depends(get_settings)) -> dict:
    record = find_record(Path(settings.projects.root), name)
    if record is None:
        raise HTTPException(status_code=404, detail=f"未找到项目：{name}")
    return record.model_dump(mode="json")


@router.post("/v1/projects", status_code=201)
async def create_project(
    payload: CreateProjectRequest,
    settings: Settings = Depends(get_settings),
) -> dict:
    """Create a project by shallow-cloning a public repository, then optionally analyse it.

    Order matters here. The name and the queue are checked **before** the clone, because a
    fetch that is going to be rejected anyway costs a network round trip and a queue slot to
    find that out. The clone itself runs in a thread: it is seconds to minutes of blocking
    `subprocess`, and the gateway must keep answering while it happens.
    """
    root = _projects_root(settings)
    try:
        name = slugify(payload.name) if payload.name else name_from_url(payload.git_url)
    except ProjectRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if (root / name).exists():
        raise HTTPException(status_code=409, detail=f"项目 {name} 已存在")

    store = stream = None
    if payload.analyze:
        store, stream = get_job_queue()

    try:
        project_dir, commit, total, count = await asyncio.to_thread(
            fetch_git,
            settings.projects,
            url=payload.git_url,
            ref=payload.ref or None,
            name=name,
        )
    except ProjectRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ProjectExists as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ProjectTooLarge as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except ProjectError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    record = ProjectRecord(
        name=name,
        workspace=str(project_dir),
        source=ProjectSource.GIT,
        origin=payload.git_url.strip(),
        ref=payload.ref or None,
        commit=commit,
        bytes=total,
        files=count,
        languages=detect_languages(project_dir),
    )
    write_record(project_dir, record)
    if payload.analyze and store is not None and stream is not None:
        record.job_id = await asyncio.to_thread(
            _submit_analysis, project_dir, store=store, stream=stream, settings=settings
        )
        write_record(project_dir, record)
    log.info("project %s created from %s (%s files)", name, payload.git_url, count)
    return record.model_dump(mode="json")


@router.post("/v1/projects/upload", status_code=201)
async def upload_project(
    file: UploadFile = File(..., description="源码压缩包（.zip）"),
    name: str | None = Form(default=None),
    analyze: bool = Form(default=True),
    settings: Settings = Depends(get_settings),
) -> dict:
    """Create a project from an uploaded `.zip`, then optionally analyse it.

    The archive is streamed to a temporary file rather than read into memory: the cap is
    hundreds of megabytes, and `await file.read()` on that is a way to take the gateway down
    with a large upload.
    """
    root = _projects_root(settings)
    try:
        project_name = slugify(name) if name else slugify(Path(file.filename or "project").stem)
    except ProjectRejected as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    if (root / project_name).exists():
        raise HTTPException(status_code=409, detail=f"项目 {project_name} 已存在")

    store = stream = None
    if analyze:
        store, stream = get_job_queue()

    # Spooled to disk, so a large upload does not sit in the request's memory.
    import tempfile

    with tempfile.SpooledTemporaryFile(max_size=8 << 20) as spool:
        while True:
            chunk = await file.read(1 << 20)
            if not chunk:
                break
            spool.write(chunk)
        spool.seek(0)
        try:
            project_dir, total, count = await asyncio.to_thread(
                extract_archive,
                settings.projects,
                filename=file.filename or "upload.zip",
                stream=spool,
                name=project_name,
            )
        except ProjectRejected as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        except ProjectExists as exc:
            raise HTTPException(status_code=409, detail=str(exc)) from exc
        except ProjectTooLarge as exc:
            raise HTTPException(status_code=413, detail=str(exc)) from exc
        except ProjectError as exc:
            raise HTTPException(status_code=502, detail=str(exc)) from exc

    record = ProjectRecord(
        name=project_name,
        workspace=str(project_dir),
        source=ProjectSource.ARCHIVE,
        origin=file.filename or "upload.zip",
        bytes=total,
        files=count,
        languages=detect_languages(project_dir),
    )
    write_record(project_dir, record)
    if analyze and store is not None and stream is not None:
        record.job_id = await asyncio.to_thread(
            _submit_analysis, project_dir, store=store, stream=stream, settings=settings
        )
        write_record(project_dir, record)
    log.info("project %s created from %s (%s files)", project_name, file.filename, count)
    return record.model_dump(mode="json")


def _probe_remote_scanner(url: str) -> str:
    """What the scan service says it can run, or an explicit failure."""
    try:
        import httpx

        response = httpx.get(f"{url}/health", timeout=5.0)
        response.raise_for_status()
        body = response.json()
    except Exception as exc:
        return f"扫描服务不可达：{exc}"
    if not body.get("available"):
        return f"扫描服务没有可用引擎（{body.get('reason', 'unknown')}）"
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


@router.post("/v1/scan/jobs", status_code=202, response_model=None)
def scan_job(
    payload: ScanRequest,
    response: Response,
    force: bool = Query(False),
    queue: tuple = Depends(get_job_queue),
    settings: Settings = Depends(get_settings),
):
    """The asynchronous form of `/v1/scan`. The synchronous route is unchanged.

    A separate path rather than a change to `/v1/scan`: that response is a documented
    contract (`run_id`/`findings`/`sarif_path`/`engine`) with existing consumers, and
    quietly turning it into "202 and an id" would be a breaking change disguised as a
    feature.
    """
    store, stream = queue
    return submit(
        payload=payload,
        kind=JobKind.SCAN,
        force=force,
        store=store,
        stream=stream,
        settings=settings,
        response=response,
    )


@router.post(
    "/v1/assemble",
    # Two shapes from one route: a finished bundle (synchronous) or an accepted job (queued).
    # `response_model=AssembleResponse` describes only the first, and FastAPI *validates* the
    # return value against it -- so the queued path answered 500 with a ResponseValidationError
    # for every request, on a deployment that configures a queue (compose always does). That is
    # why `/v1/jobs` already sets `response_model=None`; the shapes are documented through
    # `responses` here instead, which does not validate.
    response_model=None,
    responses={
        200: {"model": AssembleResponse, "description": "the bundle, assembled synchronously"},
        202: {"model": JobAcceptedResponse, "description": "accepted as a queued job"},
    },
)
async def assemble(
    payload: AssembleRequest,
    response: Response,
    force: bool = Query(False, description="Run it again even though a previous attempt finished"),
    pipeline: AssemblyPipeline = Depends(get_pipeline),
):
    """Assemble a bundle: synchronously, or as a queued job when a queue is configured.

    The synchronous path is unchanged -- same request model, same response, same status --
    which is what keeps the CLI, the tests and a broker-free local setup working. With
    `AEGIS_QUEUE__REDIS_URL` set this returns 202 and an id instead, and the work happens in
    a worker that can report progress and be cancelled.
    """
    if queue_enabled():
        store, stream = get_job_queue()
        return submit(
            payload=payload,
            kind=JobKind.ASSEMBLE,
            force=force,
            store=store,
            stream=stream,
            settings=get_settings(),
            response=response,
        )

    workspace = resolve_workspace(payload.workspace)
    sarif_path = Path(payload.sarif_path) if payload.sarif_path else None
    if sarif_path is not None and not sarif_path.exists():
        raise HTTPException(status_code=400, detail=f"未找到 SARIF：{sarif_path}")

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
            raise HTTPException(status_code=400, detail=f"无效的 budget_json：{exc}") from exc

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


@router.post(
    "/v1/bundles/{bundle_id}/analyze",
    # No response_model, and no return annotation -- both would make FastAPI validate the 202
    # path against a type it cannot satisfy: when a queue is configured this route returns a
    # `JobAcceptedResponse`, not a report. Declaring `-> dict` here answered 500 on the first real
    # queued call, while the synchronous tests passed because they never reach `submit`.
    # `POST /v1/jobs` sets the same thing for the same reason.
    response_model=None,
    summary="Analyse a finished bundle with the model (queued when a queue is configured)",
)
async def analyze_bundle_route(
    bundle_id: str,
    response: Response,
    payload: AnalyzeRequest | None = None,
    force: bool = Query(False, description="Run it again even though a previous attempt finished"),
    settings: Settings = Depends(get_settings),
):
    """Send a finished bundle to the model: queued when a queue is configured, synchronous when not.

    The two shapes are the same contract as `/v1/assemble`: 202 + a job id when Redis is there, a
    finished report when it is not. That keeps a broker-free local setup working, which is how
    the stage is developed.

    A bundle that was never built is a 404 rather than an empty report -- "there is nothing to
    analyse" and "the model found nothing" must not look alike.
    """
    package = Path(settings.output_dir) / bundle_id
    if not (package / "ai" / "blocks.jsonl").is_file():
        raise HTTPException(
            status_code=404,
            detail=(
                f"没有包含 AI 区块的分析包：{bundle_id}"
                f"（期望 {package / 'ai' / 'blocks.jsonl'}）"
            ),
        )

    if queue_enabled():
        store, stream = get_job_queue()
        return submit(
            payload=payload or AnalyzeRequest(bundle_id=bundle_id),
            kind=JobKind.AI_FANOUT,
            force=force,
            store=store,
            stream=stream,
            settings=settings,
            response=response,
        )

    report = await asyncio.to_thread(analyse_bundle, package, settings.ai)
    if report.skipped:
        # Not an error: the stage is off by default, and saying so is the useful answer.
        return {"bundle_id": bundle_id, "skipped": report.skipped, "calls": []}
    await asyncio.to_thread(write_report, package, report)
    return report.model_dump(mode="json")


@router.get("/v1/bundles/{bundle_id}/verdicts")
def bundle_verdicts(bundle_id: str, settings: Settings = Depends(get_settings)) -> dict:
    """The raw report a previous AI run wrote, or a 404 explaining that none exists.

    Served as the *stored file* rather than as a view: the front-end is its own deployment and
    computes its own display numbers, so there is nothing a server-side aggregate could add that
    the caller cannot derive from `calls[]` -- and there is everything to lose, because two
    implementations of "how many contexts answered" drift apart silently. The failures
    (`parsed: false`) stay in the payload rather than being filtered out, because a context the
    model could not answer about is not a context with nothing to say.
    """
    report_path = Path(settings.output_dir) / bundle_id / "ai" / "report.json"
    if not report_path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"{bundle_id} 尚未被分析：{report_path} 不存在",
        )
    return AIReport.model_validate_json(report_path.read_text(encoding="utf-8")).model_dump(
        mode="json"
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
        if entry.name.startswith("."):
            # A staging directory is a bundle being written, not a bundle. Listing it would
            # offer a half-finished tree as a finished one; the worker renames it into place
            # only once it is complete.
            continue
        manifest = entry / "manifest.json"
        summary = {
            "bundle_id": entry.name,
            "path": str(entry),
            # Two raw facts a project view would otherwise fetch per row: which repository this
            # bundle describes, and whether there are verdicts to open. Published here so the
            # list stays one request; "has an AI report" is the presence of the file, not a
            # judgement about whether the run was any good.
            "has_ai_report": (entry / "ai" / "report.json").is_file(),
        }
        if manifest.exists():
            try:
                data = json.loads(manifest.read_text(encoding="utf-8"))
                stats = data.get("stats") or {}
                coverage = data.get("coverage") or {}
                summary.update(
                    {
                        "created_at": data.get("created_at"),
                        "workspace": data.get("workspace_root"),
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
                summary["error"] = "清单不可读"
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
        raise HTTPException(status_code=404, detail="未找到摘要")
    return PlainTextResponse(summary.read_text(encoding="utf-8"), media_type="text/markdown")


@router.get("/v1/bundles/{bundle_id}/blocks")
def bundle_blocks(bundle_id: str, settings: Settings = Depends(get_settings)) -> JSONResponse:
    directory = bundle_dir(bundle_id, settings)
    meta = directory / "ai" / "blocks_meta.json"
    if not meta.exists():
        raise HTTPException(status_code=404, detail="未找到区块")
    return JSONResponse(json.loads(meta.read_text(encoding="utf-8")))


@router.get("/v1/bundles/{bundle_id}/blocks/{block_id}", response_class=PlainTextResponse)
def bundle_block(
    bundle_id: str, block_id: str, settings: Settings = Depends(get_settings)
) -> PlainTextResponse:
    directory = bundle_dir(bundle_id, settings)
    path = directory / "ai" / "blocks.jsonl"
    if not path.exists():
        raise HTTPException(status_code=404, detail="未找到区块")
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        block = json.loads(line)
        if block.get("block_id") == block_id:
            return PlainTextResponse(block["content"], media_type="text/markdown")
    raise HTTPException(status_code=404, detail=f"未找到区块：{block_id}")


@router.get("/v1/bundles/{bundle_id}/graph", response_class=PlainTextResponse)
def bundle_graph(bundle_id: str, settings: Settings = Depends(get_settings)) -> PlainTextResponse:
    directory = bundle_dir(bundle_id, settings)
    dot = directory / "graph" / "callgraph.dot"
    if not dot.exists():
        raise HTTPException(status_code=404, detail="未找到调用图")
    return PlainTextResponse(dot.read_text(encoding="utf-8"), media_type="text/vnd.graphviz")


@router.get("/v1/bundles/{bundle_id}/archive")
def bundle_archive(bundle_id: str, settings: Settings = Depends(get_settings)) -> FileResponse:
    directory = bundle_dir(bundle_id, settings)
    archive = directory.with_suffix(".zip")
    if not archive.exists():
        raise HTTPException(status_code=404, detail="未找到归档")
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
