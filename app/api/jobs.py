"""Job endpoints: submit work, watch it, cancel it.

The gateway owns no work and no handles. It validates a request, records that the work
exists, and answers questions about it -- which is why cancelling here only *asks*: the
process that can actually stop a scan is the worker holding its handle, and a gateway with
that power would be a gateway that can kill jobs by accident.

Three boundaries are load-bearing and each has a test:

* **Validation happens before enqueueing.** A request that cannot possibly work gets a 400
  now, not a job id and a failure ten seconds later.
* **202 means "this will change"; 200 means "this is the answer".** A duplicate submission
  of finished work returns the finished job; a duplicate of in-flight work returns 202 with
  the job it attached to, and says so in `deduplicated`.
* **A failed job is not retried behind the caller's back.** Retrying needs `?force=true`,
  because automatic retry is what turns one deterministic failure into an endless one and
  breaks "same input, same answer".
"""

from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from redis.exceptions import RedisError

from aegis_contracts.jobs import (
    TERMINAL_STATES,
    Job,
    JobAcceptedResponse,
    JobKind,
    JobListResponse,
    JobRequest,
    JobState,
    JobSummary,
    QueueStatus,
)
from aegis_core.config import Settings
from aegis_core.logging import get_logger
from app.api.deps import get_job_queue, get_settings, resolve_workspace
from app.schemas.api import AnalyzeRequest, AssembleRequest, ScanRequest
from services.queue.jobs import JobStore
from services.queue.streams import JobStream

log = get_logger(__name__)
router = APIRouter()

#: Statuses that mean "somebody is on it". A duplicate submission attaches instead of
#: creating a second run, which is the whole point of a content-derived fingerprint.
IN_FLIGHT = frozenset({JobState.QUEUED, JobState.RUNNING})


def _queue_unavailable(exc: Exception) -> HTTPException:
    """503, not 500: the request was fine, the queue is down.

    Distinguishing those matters to a caller deciding whether to retry, and it matches how
    the existing `/v1/assemble` route already answers an unreachable extraction service.
    """
    return HTTPException(status_code=503, detail=f"队列不可用：{exc}")


def _job_request(
    payload: AssembleRequest | ScanRequest | AnalyzeRequest, workspace: Path
) -> JobRequest:
    """One job request from any of the HTTP shapes.

    Every field is read with `getattr`, and that is not defensive style -- the payloads genuinely
    differ. `ScanRequest` has no budget or bundle name; `AnalyzeRequest` has neither rules nor a
    workspace of its own, because an AI job consumes a finished bundle and needs only its id.
    Inventing defaults would put values in the fingerprint that the caller never chose, which is
    what makes two different requests look identical.

    This used to read `rules`/`rule_config`/`include_globs`/`exclude_globs` directly, which
    crashed with a 500 the first time an `AnalyzeRequest` reached it -- the synchronous path never
    calls this function, so the unit tests (which had no queue) never saw it.
    """
    budget = getattr(payload, "budget", None)
    return JobRequest(
        workspace=str(workspace),
        sarif_path=getattr(payload, "sarif_path", None) or None,
        rules=list(getattr(payload, "rules", None) or []),
        rule_config=getattr(payload, "rule_config", None),
        include_globs=list(getattr(payload, "include_globs", None) or []),
        exclude_globs=list(getattr(payload, "exclude_globs", None) or []),
        budget=budget.model_dump() if budget else None,
        max_findings=getattr(payload, "max_findings", None),
        lsp=getattr(payload, "lsp", True),
        package_name=getattr(payload, "package_name", None),
        bundle_id=getattr(payload, "bundle_id", None),
        audit_options=getattr(payload, "audit_options", None),
    )


def _lsp_config_fingerprint(settings: Settings) -> str:
    """The catalog's identity, not its path: same path with new content is a new request.

    The contract may not read files, so this is computed here and passed in. Two catalogs
    that differ select different language servers, which changes the bundle.
    """
    import hashlib

    path = settings.lsp_config_file
    if path is None or not Path(path).is_file():
        return ""
    try:
        return hashlib.sha1(Path(path).read_bytes()).hexdigest()[:20]
    except OSError:  # pragma: no cover - unreadable catalog
        return ""


def _artifact_available(job: Job) -> bool:
    """Is a succeeded job's output still there? Cleaned-up output means "run it again".

    What "the output" is depends on the kind, and getting that wrong is not a cosmetic detail: a
    resubmission of a finished job whose artifact is missing is *re-run*, so a kind whose marker is
    misread is re-run every single time. An audit's result is the run directory holding the report
    and the trail -- there is no bundle and therefore no `manifest.json`, and asking for one would
    answer "gone" forever, turning every second click into another half-hour paid run.
    """
    if job.result is None:
        return False
    if job.kind is JobKind.AUDIT:
        return bool(job.result.package_path) and (
            Path(job.result.package_path) / "report.md"
        ).is_file()
    if job.result.package_path:
        return (Path(job.result.package_path) / "manifest.json").is_file()
    return False


def submit(
    *,
    payload: AssembleRequest | ScanRequest | AnalyzeRequest,
    kind: JobKind,
    force: bool,
    store: JobStore,
    stream: JobStream,
    settings: Settings,
    response: Response,
) -> JobAcceptedResponse | Job:
    """Shared submission path for assemble, scan and AI jobs.

    Returns either a 202 body (accepted, will change) or a full `Job` (already final), which
    the route turns into the matching status code.
    """
    workspace = resolve_workspace(payload.workspace)
    sarif = getattr(payload, "sarif_path", None)
    if sarif:
        path = Path(sarif)
        if not path.exists():
            # Before enqueueing: a request that cannot work should not cost a queue slot
            # and a round trip to find out.
            raise HTTPException(status_code=400, detail=f"未找到 SARIF：{path}")

    request = _job_request(payload, workspace)
    submission = store.new_submission(
        request,
        kind=kind,
        lsp_config_fingerprint=_lsp_config_fingerprint(settings),
    )

    try:
        existing = store.get_by_fingerprint(submission.fingerprint)
        if existing is not None:
            return _handle_duplicate(
                existing,
                submission,
                force=force,
                store=store,
                stream=stream,
                settings=settings,
                response=response,
            )

        job, created = store.create(submission)
        if not created:
            # Lost a race with a concurrent submission of the same request: attach to theirs.
            return _handle_duplicate(
                job,
                submission,
                force=False,
                store=store,
                stream=stream,
                settings=settings,
                response=response,
            )
        stream.ensure_group()
        stream.enqueue_submission(submission)
    except RedisError as exc:
        raise _queue_unavailable(exc) from exc

    response.status_code = status.HTTP_202_ACCEPTED
    response.headers["Location"] = f"/v1/jobs/{job.job_id}"
    log.info("accepted %s job %s", kind.value, job.job_id)
    return JobAcceptedResponse(
        job_id=job.job_id, state=job.state, deduplicated=False, revision=job.revision
    )


def _archive_previous_audit_attempt(existing: Job, settings: Settings) -> None:
    """Move a finished audit attempt's artifacts aside, before the redrive is enqueued.

    A redrive reuses the job id -- it is a fingerprint of the workspace -- and therefore the run
    directory. Until the new attempt writes its first byte, `<work_dir>/audit/<job_id>/report.md`
    and `trail.jsonl` still hold the previous attempt's bytes, and `GET /v1/audit/{id}/report`
    serves them as this attempt's conclusion; the worker only truncates the trail once the harness
    attaches, which is after a worker picks the job up. So the archiving happens here, at the
    moment the request is accepted, which is the earliest instant the gateway can act.

    Called at the two points where a duplicate actually *starts* a new attempt, never on the
    "this is the answer" path: a 200 that returns the finished job must not touch its artifacts.

    Only an audit has a run directory like this. The other kinds write a content-addressed bundle
    under `output_dir`, whose files must not be moved or deleted by a resubmission.

    Never raises: an archive that fails is a stale file, not a reason to refuse a valid re-run.
    """
    if existing.kind is not JobKind.AUDIT:
        return
    # Imported here, not at module scope: `app.api.audit` imports `submit` from this module, so a
    # top-level import would be a cycle at import time.
    from app.api.audit import archive_previous_attempt

    # The number of the attempt being replaced. `store.redrive` increments the record's counter, so
    # it is read here -- attempt N's report is archived as attempt N.
    archive_previous_attempt(existing.job_id, existing.progress.attempt, settings)


def _handle_duplicate(
    existing: Job,
    submission,
    *,
    force: bool,
    store: JobStore,
    stream: JobStream,
    settings: Settings,
    response: Response,
) -> JobAcceptedResponse | Job:
    """A request with this fingerprint already exists. Decide what that means."""
    if existing.state in IN_FLIGHT:
        response.status_code = status.HTTP_202_ACCEPTED
        response.headers["Location"] = f"/v1/jobs/{existing.job_id}"
        return JobAcceptedResponse(
            job_id=existing.job_id,
            state=existing.state,
            deduplicated=True,
            revision=existing.revision,
        )

    if existing.state is JobState.SUCCEEDED:
        if _artifact_available(existing) and not force:
            # 200: this is the final answer, not a promise to produce one.
            response.status_code = status.HTTP_200_OK
            return existing
        # Either the bundle was cleaned up (the result is a dangling reference), or the caller
        # asked for it again. `force` has to reach a succeeded job too: for an AI job the answer
        # is a model's opinion, so running it again is meaningful in a way that re-running a
        # content-addressed bundle is not -- and without this the same request could never be
        # re-run at all, because the fingerprint (and therefore the job id) does not change.
        reason = (
            "重新运行：先前的分析包已不存在"
            if not _artifact_available(existing)
            else "按请求重新运行"
        )
        _archive_previous_audit_attempt(existing, settings)
        restarted = store.redrive(existing.job_id, note=reason, allow_success=True)
        if restarted is not None:
            _reenqueue(stream, restarted)
        response.status_code = status.HTTP_202_ACCEPTED
        response.headers["Location"] = f"/v1/jobs/{existing.job_id}"
        return JobAcceptedResponse(
            job_id=existing.job_id,
            state=JobState.QUEUED,
            deduplicated=False,
            revision=restarted.revision if restarted else existing.revision,
        )

    # failed or canceled. Not retried automatically, and the refusal explains itself.
    if not force:
        detail = {
            "detail": f"previous attempt {existing.state.value}: "
            + (existing.failure.message if existing.failure else "no reason recorded")
            + "; resubmit with ?force=true to run it again",
            "job_id": existing.job_id,
            "state": existing.state.value,
        }
        if existing.failure is not None:
            detail["failure"] = existing.failure.model_dump(mode="json")
        raise HTTPException(status_code=409, detail=detail)

    _archive_previous_audit_attempt(existing, settings)
    restarted = store.redrive(existing.job_id, note="按调用方请求重新运行")
    if restarted is None:  # pragma: no cover - it existed a moment ago
        raise HTTPException(status_code=409, detail="任务在重试前消失了")
    _reenqueue(stream, restarted)
    response.status_code = status.HTTP_202_ACCEPTED
    response.headers["Location"] = f"/v1/jobs/{restarted.job_id}"
    return JobAcceptedResponse(
        job_id=restarted.job_id,
        state=restarted.state,
        deduplicated=False,
        revision=restarted.revision,
    )


def _reenqueue(stream: JobStream, job: Job) -> None:
    try:
        stream.ensure_group()
        stream.enqueue(
            job.job_id,
            kind=job.submission.kind.value,
            fingerprint=job.submission.fingerprint,
            attempt=job.progress.attempt,
            submitted_at=job.submission.submitted_at,
        )
    except RedisError as exc:  # pragma: no cover - Redis trouble
        raise _queue_unavailable(exc) from exc


# ----------------------------------------------------------------------
# routes
# ----------------------------------------------------------------------
@router.post(
    "/v1/jobs",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=None,
    summary="Submit an assemble job (the asynchronous form of POST /v1/assemble)",
)
def submit_assemble(
    payload: AssembleRequest,
    response: Response,
    force: bool = Query(False, description="Run it again even though a previous attempt finished"),
    queue: tuple[JobStore, JobStream] = Depends(get_job_queue),
    settings: Settings = Depends(get_settings),
):
    store, stream = queue
    return submit(
        payload=payload,
        kind=JobKind.ASSEMBLE,
        force=force,
        store=store,
        stream=stream,
        settings=settings,
        response=response,
    )


@router.get("/v1/jobs", response_model=JobListResponse)
def list_jobs(
    state_filter: JobState | None = Query(None, alias="state"),
    kind: JobKind | None = Query(None),
    limit: int = Query(50, ge=1, le=500),
    queue: tuple[JobStore, JobStream] = Depends(get_job_queue),
) -> JobListResponse:
    """The first screen's payload: what is running, what is queued, what just finished."""
    store, stream = queue
    try:
        jobs = store.list_jobs(limit=limit)
        if state_filter is not None:
            jobs = [job for job in jobs if job.state is state_filter]
        if kind is not None:
            jobs = [job for job in jobs if job.kind is kind]
        summaries = [JobSummary.of(job) for job in jobs]
        return JobListResponse(
            jobs=summaries,
            total=len(summaries),
            queue=_queue_status(store, stream),
        )
    except RedisError as exc:
        raise _queue_unavailable(exc) from exc


def _queue_status(store: JobStore, stream: JobStream) -> QueueStatus:
    """Queue health, computed from the numbers that reveal the silent failure.

    `queued` counted from the job records versus `lag` from the group is the comparison
    that catches entries trimmed by `MAXLEN`: jobs waiting with no message to deliver them.
    """
    status_ = QueueStatus()
    try:
        info = stream.group_info()
        status_.pending = int(info.get("pending") or 0)
        lag = info.get("lag")
        status_.lag = int(lag) if lag is not None else None
        status_.stream_length = stream.stream_length()
        status_.queued = store.count_by_state(state=JobState.QUEUED)
        status_.workers_alive = _workers_alive(store)
    except RedisError as exc:  # pragma: no cover - the route already failed
        status_.degraded = True
        status_.detail = str(exc)
        return status_
    if status_.lag is not None and status_.queued > status_.lag + status_.pending:
        status_.degraded = True
        status_.detail = (
            f"{status_.queued} jobs are queued but the stream holds no entry for them; "
            "a worker restart will re-enqueue them"
        )
    return status_


def _workers_alive(store: JobStore) -> int:
    """Workers that wrote a heartbeat recently. Liveness, not task completion."""
    try:
        keys = list(store.redis.scan_iter(match="aegis:queue:worker:*"))
    except RedisError:  # pragma: no cover
        return 0
    return len(keys)


@router.get("/v1/jobs/{job_id}", response_model=Job)
def get_job(
    job_id: str,
    queue: tuple[JobStore, JobStream] = Depends(get_job_queue),
) -> Job:
    """The whole job, including failures and cancellations: a terminal state is an answer."""
    store, _ = queue
    try:
        job = store.get(job_id)
    except RedisError as exc:
        raise _queue_unavailable(exc) from exc
    if job is None:
        raise HTTPException(status_code=404, detail="未找到任务或任务已过期")
    return job


@router.post("/v1/jobs/{job_id}/cancel", response_model=None)
def cancel_job(
    job_id: str,
    response: Response,
    queue: tuple[JobStore, JobStream] = Depends(get_job_queue),
):
    """Ask for a job to stop. Records intent only -- a worker holds the handles."""
    store, _ = queue
    try:
        job = store.get(job_id)
        if job is None:
            raise HTTPException(status_code=404, detail="未找到任务或任务已过期")

        if job.state in TERMINAL_STATES:
            if job.state is JobState.CANCELED:
                # Idempotent: pressing cancel twice is not an error.
                response.status_code = status.HTTP_200_OK
                return job
            raise HTTPException(
                status_code=409,
                detail={
                    "detail": f"job already finished ({job.state.value})",
                    "state": job.state.value,
                    "job_id": job.job_id,
                },
            )

        if job.state is JobState.QUEUED:
            # Nobody has claimed it, so it can be finished off right here. If a worker does
            # claim it a moment later, `handle()` sees a terminal job and stops.
            updated = store.mark_canceled(job.job_id, note="启动前已取消")
            response.status_code = status.HTTP_202_ACCEPTED
            return {
                "job_id": job.job_id,
                "state": (updated or job).state.value,
                "cancel_requested": True,
                "revision": (updated or job).revision,
            }

        # Running: accept the request and let the worker reach an interrupt point.
        updated = store.request_cancel(job.job_id)
        response.status_code = status.HTTP_202_ACCEPTED
        current = updated or job
        return {
            "job_id": current.job_id,
            "state": current.state.value,
            "cancel_requested": current.cancel_requested,
            "revision": current.revision,
        }
    except RedisError as exc:
        raise _queue_unavailable(exc) from exc
