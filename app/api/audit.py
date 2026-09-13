"""Audit endpoints: start an autonomous repository review, watch it, read its report.

The gateway owns no work here either: it records the request and answers questions about it. What
makes an audit different from the other job kinds is that it is *long* -- half an hour, 150 agent
runs -- so "watch it" is not a nice-to-have. Three routes, and the split between them is the design:

* **`POST /v1/audit`** submits. It goes through the same `jobs.submit` path as everything else, so
  it inherits request deduplication, the 202-vs-200 rule, `?force=true` and cancellation without a
  second implementation of any of them.
* **`GET /v1/audit/{id}/trail`** is the live one: the run's event log, paged by `after_seq`. This is
  where the agent conversations, the coverage decisions and the candidates appear while the run is
  still happening. It is deliberately *not* a websocket or an SSE stream -- the console polls, which
  is what every other screen already does, and an incremental page costs one small request instead
  of a connection the gateway would have to keep for 30 minutes.
* **`GET /v1/audit/{id}/report`** is the finished artifact: the same markdown the CLI writes.

Why the trail is read from disk rather than from Redis: it is written by the worker, appended line
by line, and it must survive the worker dying -- that is the whole point of it. `work_dir` is the
one path every container mounts at the same place, so the gateway reads the file the worker wrote,
with no copy step that could lag behind or lose the last events.

**404 vs empty.** A trail for a job that does not exist is a 404. A trail for a job that exists but
has not written one yet is an empty page with `exists: false` -- "not started" is a legitimate answer
to "what has it done so far", and answering it with an error would make the console show a failure
for the first two seconds of every audit.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from redis.exceptions import RedisError

from aegis_contracts.jobs import Job, JobKind
from aegis_core.config import Settings
from aegis_core.logging import get_logger
from app.api.deps import get_job_queue, get_settings
from app.api.jobs import _queue_unavailable, submit
from app.schemas.api import AuditRequest
from services.harness import trail as trail_mod

log = get_logger(__name__)
router = APIRouter()

#: Where the worker puts a run. The job id *is* the run id, so the path is derivable from the URL
#: and does not need the job record -- which is why a trail read works even if Redis has forgotten
#: the job but the run is still on disk.
AUDIT_ROOT = "audit"


def _run_dir(job_id: str, settings: Settings) -> Path:
    """The run directory for a job id, refusing anything that could escape the audit root.

    The job id comes from the URL, so it is untrusted input used to build a path. It is validated
    rather than trusted for the same reason `bundle_dir` validates a bundle id: `../` in a path
    segment is one request away from reading an arbitrary file.
    """
    if not job_id or not job_id.startswith("J-") or any(
        character not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        for character in job_id
    ):
        raise HTTPException(status_code=400, detail=f"不安全的任务 ID：{job_id!r}")
    return settings.work_dir / AUDIT_ROOT / job_id


def _known_job(job_id: str, queue) -> Job:
    """The job, or 404. Used by the routes that must not invent a run for a made-up id."""
    store, _ = queue
    try:
        job = store.get(job_id)
    except RedisError as exc:
        raise _queue_unavailable(exc) from exc
    if job is None:
        raise HTTPException(status_code=404, detail="未找到任务或任务已过期")
    if job.kind is not JobKind.AUDIT:
        raise HTTPException(
            status_code=400, detail=f"任务 {job_id} 不是 AI 审计（kind={job.kind.value}）"
        )
    return job


#: The artifacts a finished attempt leaves behind, and what a redrive does to each. Only the two
#: documents are archived: a trail is one line per event and can be hundreds of megabytes, so
#: keeping every attempt's would fill `work_dir` with copies of something nobody re-reads. Deleting
#: it is what makes a redrive honest -- `GET /{id}/trail` would otherwise serve the previous
#: attempt's events until the new worker attaches and truncates the file.
ATTEMPT_ARTIFACTS: dict[str, str] = {
    "report.md": "report",
    "blackboard.json": "blackboard",
}
TRAIL_ARTIFACT = "trail.jsonl"


def _attempt_stamp() -> str:
    """UTC, filename-safe, and the same shape as the harness run id (`20250913T114500Z`).

    Seconds of resolution, no colons: this string becomes part of a filename on Windows too.
    """
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def archive_previous_attempt(job_id: str, attempt: int, settings: Settings) -> list[Path]:
    """Move the previous attempt's artifacts out of the live paths, before the redrive is queued.

    Why here and not in the worker: the job id is a fingerprint of the workspace, so a redrive
    reuses the same id, the same run directory, and the same `report.md`/`blackboard.json`/
    `trail.jsonl` paths. Until the new attempt writes its first byte, those paths still hold the
    *previous* attempt's bytes, and `GET /v1/audit/{id}/report` served them as this attempt's
    conclusion -- a reader (our own console included) could take a stale report for a fresh one.
    The worker is no help: it only truncates the trail when the harness attaches, which is after a
    worker picks the job up, so the window is as long as the queue is deep. This runs at the moment
    the gateway accepts the re-run, which is the earliest instant the gateway can act.

    `attempt` is the number of the attempt being *replaced*, not the new one, so an archived
    `report.attempt2-...md` is the report attempt 2 produced.

    Returns the paths of the renamed artifacts; `trail.jsonl` is deleted rather than kept and is
    therefore not in the list. Renames `report.md` and `blackboard.json` to
    `report.attempt<N>-<UTC stamp>.md` and `blackboard.attempt<N>-<UTC stamp>.json`. A missing run
    directory, or any of those files not being there, is a no-op: an attempt that failed before
    writing has nothing to archive, and a redrive must still work.

    An `OSError` on one file is logged and skipped rather than raised: the request is a valid
    re-run and losing a stale artifact is not a reason to refuse it -- the new attempt will
    overwrite the live path anyway. `OSError` is also caught around the run dir itself, so a
    directory that cannot even be inspected is a no-op too. The path is built by `_run_dir`, so a
    job id from a URL cannot escape the audit root.
    """
    try:
        run_dir = _run_dir(job_id, settings)
    except (OSError, HTTPException) as exc:
        # An id that fails validation is not reachable from here -- the id comes from the job
        # store, not from a request -- but "never fail the redrive" should not depend on that.
        log.warning("无法定位作业 %s 的运行目录以归档：%s", job_id, exc)
        return []
    stamp = _attempt_stamp()
    archived: list[Path] = []
    for name, prefix in ATTEMPT_ARTIFACTS.items():
        source = run_dir / name
        try:
            if not source.is_file():
                continue
            target = run_dir / f"{prefix}.attempt{attempt}-{stamp}{source.suffix}"
            # `replace`, not `rename`: POSIX `rename(2)` silently overwrites an existing target
            # while `Path.rename` on Windows raises if one is there, and this must behave the same
            # on both. It is also atomic, so a reader never sees a half-archived pair.
            source.replace(target)
        except OSError as exc:
            log.warning("无法归档上次尝试的 %s（作业 %s）：%s", name, job_id, exc)
            continue
        archived.append(target)
    trail = run_dir / TRAIL_ARTIFACT
    try:
        if trail.is_file():
            trail.unlink()
    except OSError as exc:
        log.warning("无法删除上次尝试的 %s（作业 %s）：%s", TRAIL_ARTIFACT, job_id, exc)
    return archived


# ----------------------------------------------------------------------
# routes
# ----------------------------------------------------------------------
@router.post(
    "/v1/audit",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=None,
    summary="Submit an autonomous repository audit (the agent harness, as a queued job)",
)
def submit_audit(
    payload: AuditRequest,
    response: Response,
    force: bool = Query(False, description="Run it again even though a previous attempt finished"),
    queue: tuple = Depends(get_job_queue),
    settings: Settings = Depends(get_settings),
):
    store, stream = queue
    return submit(
        payload=payload,
        kind=JobKind.AUDIT,
        force=force,
        store=store,
        stream=stream,
        settings=settings,
        response=response,
    )


@router.get("/v1/audit/{job_id}/trail", response_model=None)
def audit_trail(
    job_id: str,
    after_seq: int = Query(0, ge=0, description="Return only events with a larger seq"),
    limit: int = Query(500, ge=1, le=5000),
    queue: tuple = Depends(get_job_queue),
    settings: Settings = Depends(get_settings),
) -> dict:
    """The run's events after `after_seq`, oldest first.

    `exists: false` with an empty list means "this audit has not written a trail yet" -- a queued
    job, or one that has not reached its first stage. `more: true` means the page filled up and the
    caller should immediately ask again rather than wait for the next poll tick.

    `job.running` is included because the console needs to know whether to keep polling, and
    deriving it from `events[-1].kind == "summary"` would make a killed run look finished.
    """
    _known_job(job_id, queue)
    path = _run_dir(job_id, settings) / trail_mod.TRAIL_NAME
    page = trail_mod.read_events(path, after_seq=after_seq, limit=limit)
    return {
        "job_id": job_id,
        "trail": str(path),
        **page,
    }


@router.get("/v1/audit/{job_id}/report", response_model=None)
def audit_report(
    job_id: str,
    queue: tuple = Depends(get_job_queue),
    settings: Settings = Depends(get_settings),
) -> dict:
    """The finished markdown report, or a 404 while the run is still going.

    Returned as JSON with the text in a field rather than as `text/markdown`, because the console
    renders it in a pane with other metadata and a bare text body would leave it guessing which
    fields exist. The run directory is included so a reader can find the blackboard and the trail
    next to it.
    """
    _known_job(job_id, queue)
    run_dir = _run_dir(job_id, settings)
    path = run_dir / "report.md"
    if not path.is_file():
        raise HTTPException(
            status_code=404,
            detail=f"审计报告尚未生成：{job_id}（运行中或已失败；进度见 /v1/audit/{job_id}/trail）",
        )
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:  # pragma: no cover - the file was there a moment ago
        raise HTTPException(status_code=500, detail=f"报告不可读：{exc}") from exc
    return {
        "job_id": job_id,
        "run_dir": str(run_dir),
        "report": str(path),
        "markdown": text,
    }
