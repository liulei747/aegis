"""Recovering abandoned work: the periodic reaper, and the check that runs at boot.

Two mechanisms, because they answer different questions.

* **`reconcile_startup`** asks "who is `running` with nobody watching?" It runs when a
  worker boots, so a crash is cleared within seconds of a restart rather than after
  `visibility_timeout_s`. It does not depend on the pending-entries list at all, which is
  what makes it work when the crash happened before the message was ever delivered.
* **`reap_once`** asks "whose claim has gone quiet?" It uses `XAUTOCLAIM`, so it only sees
  messages that were delivered and never acknowledged.

The dangerous case for both is a *slow* job. A fifteen-minute scan and a dead worker look
identical from the outside except for one thing: the heartbeat. So neither mechanism
decides on elapsed time alone -- both re-read the job immediately before writing and refuse
to overwrite a heartbeat that is still fresh. A job declared dead while it is alive is the
worst outcome this file can produce, because it is a failure the user did not have.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

from aegis_contracts.jobs import (
    TERMINAL_STATES,
    FailureMode,
    Job,
    JobResult,
    JobStage,
    JobState,
)
from aegis_core.config import Settings
from aegis_core.logging import get_logger
from services.queue.jobs import JobStore
from services.queue.streams import JobStream

log = get_logger(__name__)


def _seconds_since(moment: datetime | None) -> float:
    if moment is None:
        return float("inf")
    if moment.tzinfo is None:  # pragma: no cover - stored values are aware
        moment = moment.replace(tzinfo=timezone.utc)
    return (datetime.now(timezone.utc) - moment).total_seconds()


class Reaper:
    """Periodic adjudication of stale claims, run from the worker's own loop."""

    def __init__(
        self, store: JobStore, stream: JobStream, settings: Settings, *, worker_id: str
    ) -> None:
        self.store = store
        self.stream = stream
        self.settings = settings
        self.worker_id = worker_id
        self.enabled = True

    # ------------------------------------------------------------------
    def reap_once(self) -> dict:
        """Take over quiet claims and decide what each one meant.

        Every claimed message is acknowledged exactly once, whether it was adjudicated,
        requeued or skipped: leaving it pending would hand it to the next reaper pass and
        the pass after that.
        """
        queue = self.settings.queue
        claimed = self.stream.claim_stale(
            self.worker_id,
            min_idle_ms=int(queue.visibility_timeout_s * 1000),
            count=queue.reap_batch,
        )
        report = {"claimed": len(claimed), "recovered": 0, "requeued": 0, "failed": 0, "skipped": 0}
        for entry in claimed:
            try:
                outcome = self._adjudicate(entry)
            except Exception:  # pragma: no cover - a bad entry must not stop the pass
                log.error("reaper could not adjudicate %s", entry.get("job_id"), exc_info=True)
                outcome = "skipped"
            report[outcome] = report.get(outcome, 0) + 1
            try:
                self.stream.ack(entry["entry_id"])
            except Exception:  # pragma: no cover
                log.error("reaper failed to ACK %s", entry["entry_id"], exc_info=True)
        if report["claimed"]:
            log.info("reaper pass: %s", report)
        return report

    def _adjudicate(self, entry: dict) -> str:
        """Decide one stale entry. Returns which bucket it landed in, for the report."""
        job_id = entry["job_id"]
        job = self.store.get(job_id)
        if job is None:
            # Expired, or the record was evicted. Nothing to say about it.
            return "skipped"
        if job.state in TERMINAL_STATES:
            # The common, benign case: the worker finished and was killed before ACKing.
            return "skipped"
        if not self._claim_is_stale(job):
            # A live worker that is merely slow. Put the message back and change nothing.
            self._requeue_message(job, attempt=job.progress.attempt)
            return "skipped"

        recovered = recoverable_artifact(self.store, job, self.settings)
        if recovered is not None:
            self.store.mark_succeeded(
                job_id,
                result=JobResult(
                    bundle_id=recovered.name,
                    package_path=str(recovered),
                    warnings=["已恢复：产物已经在磁盘上"],
                ),
                note="已恢复",
            )
            return "recovered"

        attempt = job.progress.attempt
        if attempt < self.settings.queue.max_attempts:
            self.store.requeue(job_id, note=f"静默认领后已重新认领（第 {attempt} 次尝试）")
            self._requeue_message(job, attempt=attempt + 1)
            return "requeued"

        self.store.mark_failed(
            job_id,
            mode=FailureMode.WORKER_LOST,
            message="持有此任务的 worker 已停止上报，且重试次数已用尽",
            detail=f"attempt={attempt} max_attempts={self.settings.queue.max_attempts}",
            recoverable=True,
        )
        return "failed"

    def _claim_is_stale(self, job: Job) -> bool:
        """Re-read the heartbeat immediately before deciding, and only then judge.

        This second read is the guard that makes the reaper safe: between claiming a stale
        entry and writing a verdict, the owning worker may have written a heartbeat. The
        staleness measured from the pending-entry idle time is a *hint*; this is the fact.
        """
        fresh = self.store.get(job.job_id)
        if fresh is None:  # pragma: no cover - it existed a moment ago
            return False
        if fresh.state in TERMINAL_STATES:
            return False
        heartbeat_age = _seconds_since(fresh.progress.worker_heartbeat_at)
        if heartbeat_age < self.settings.queue.visibility_timeout_s:
            return False
        return True

    def _requeue_message(self, job: Job, *, attempt: int) -> None:
        try:
            self.stream.enqueue(
                job.job_id,
                kind=job.submission.kind.value,
                fingerprint=job.submission.fingerprint,
                attempt=attempt,
                submitted_at=job.submission.submitted_at,
            )
        except Exception:  # pragma: no cover - Redis trouble
            log.error("reaper failed to re-enqueue %s", job.job_id, exc_info=True)


def recoverable_artifact(store: JobStore, job: Job, settings: Settings) -> Path | None:
    """Is this job's output already on disk? If so, re-running it is waste.

    Three places to look, and the third one is the reason this is not a one-liner:

    1. the path the job recorded when it finished packaging;
    2. `output_dir/<bundle_id>` from that same record;
    3. **a finished staging directory.** The worker writes under `.staging-<bundle_id>` and
       renames only at the end, so a crash in between leaves a complete tree under the
       staging name. The rename is atomic but the *state write* after it is not, so this is
       exactly the window in which a job's work is done and its record does not yet say so.

    What this deliberately does *not* do is recompute the bundle id from the request. That
    would need the finding set, which only exists mid-run; `reconcile_startup` runs before
    any of that. The consequences are documented rather than papered over: a crash *during*
    a run is retried even though its staging directory exists, and
    `tests/test_queue_worker.py` records that.
    """
    for candidate in _candidate_paths(job, settings):
        if (candidate / "manifest.json").is_file():
            return candidate
    return None


def _candidate_paths(job: Job, settings: Settings) -> list[Path]:
    paths: list[Path] = []
    if job.result and job.result.package_path:
        paths.append(Path(job.result.package_path))
    if job.result and job.result.bundle_id:
        paths.append(settings.output_dir / job.result.bundle_id)
        paths.append(settings.output_dir / f".staging-{job.result.bundle_id}")
    return paths


def reconcile_startup(store: JobStore, stream: JobStream, settings: Settings) -> dict:
    """Bring every job out of a state nobody is maintaining. Runs once per worker boot.

    Two sweeps, for two different kinds of orphan:

    * `running` with an old heartbeat: a worker died holding it. Recover the artifact if it
      exists, else requeue while attempts remain, else fail with a name.
    * `queued` with no stream entry: the message was trimmed by `MAXLEN` (or lost with
      Redis) and no consumer will ever see it. This is the only path that closes that hole,
      because the reaper only looks at delivered messages and the `running` sweep only looks
      at claimed ones.
    """
    report = {"running": 0, "queued_orphans": 0}
    for job in store.list_jobs(limit=settings.queue.list_limit):
        if job.state is JobState.RUNNING:
            report["running"] += 1
            _reconcile_running(store, stream, settings, job)
        elif job.state is JobState.QUEUED and not stream.was_enqueued_recently(job.job_id):
            report["queued_orphans"] += 1
            _reconcile_orphan(store, stream, job)
    return report


def _worker_is_alive(store: JobStore, worker_id: str | None) -> bool:
    """Is the worker that holds this job still reporting anywhere?

    This is the right question for the startup sweep, and it is a *different* question from
    "is this heartbeat fresh" (which is what the periodic reaper asks).

    Why it matters: a slow job has an old heartbeat and a live worker; a crashed job has an old
    heartbeat and a worker that is gone. The periodic reaper distinguishes them by waiting out
    `visibility_timeout_s`, because it has no other way to tell "slow" from "dead". A worker
    *starting up*, by contrast, can check whether the session that claimed the job still
    exists at all -- its per-worker heartbeat key is refreshed on an interval and expires
    shortly after the process stops. That is what makes this layer work within seconds of a
    restart instead of after the visibility timeout (1800s by default, which is how a crashed
    job was observed sitting in `running` for minutes while the sweep reported it and did
    nothing).
    """
    if not worker_id:
        return False
    try:
        return bool(store.redis.exists(f"aegis:queue:worker:{worker_id}"))
    except Exception:  # pragma: no cover - Redis trouble; treat as gone
        return False


def _reconcile_running(store: JobStore, stream: JobStream, settings: Settings, job: Job) -> None:
    heartbeat_age = _seconds_since(job.progress.worker_heartbeat_at)
    if _worker_is_alive(store, job.progress.worker_id):
        # The holder is still out there. A peer that is merely slow must not be robbed -- that
        # would invent a failure the user does not have -- so this one is left to the periodic
        # reaper, which can wait out the visibility timeout before deciding.
        return
    recovered = recoverable_artifact(store, job, settings)
    if recovered is not None:
        store.mark_succeeded(
            job.job_id,
            result=JobResult(
                bundle_id=recovered.name,
                package_path=str(recovered),
                warnings=["已恢复：产物已经在磁盘上"],
            ),
            note="已恢复",
        )
        return
    if job.progress.attempt < settings.queue.max_attempts:
        store.requeue(job.job_id, note="启动时已重新认领：其 worker 已消失")
        try:
            stream.enqueue(
                job.job_id,
                kind=job.submission.kind.value,
                fingerprint=job.submission.fingerprint,
                attempt=job.progress.attempt,
                submitted_at=job.submission.submitted_at,
            )
        except Exception:  # pragma: no cover
            log.error("startup reconcile could not re-enqueue %s", job.job_id, exc_info=True)
        log.info(
            "reclaimed job %s at startup (worker %s gone, heartbeat age %.0fs)",
            job.job_id,
            job.progress.worker_id,
            heartbeat_age,
        )
        return
    store.mark_failed(
        job.job_id,
        mode=FailureMode.WORKER_LOST,
        message="持有此任务的 worker 从未回来",
        detail=f"心跳距今 {heartbeat_age:.0f}s",
        recoverable=True,
    )


def _reconcile_orphan(store: JobStore, stream: JobStream, job: Job) -> None:
    """A `queued` job whose stream entry is gone. Re-enqueue it; that is all it needs.

    Safe because `job_id` is content-derived and `handle()` refuses terminal jobs, so a
    duplicate entry costs one no-op claim.
    """
    log.warning("job %s is queued with no stream entry; re-enqueueing", job.job_id)
    try:
        stream.enqueue(
            job.job_id,
            kind=job.submission.kind.value,
            fingerprint=job.submission.fingerprint,
            attempt=job.progress.attempt,
            submitted_at=job.submission.submitted_at,
        )
    except Exception:  # pragma: no cover
        log.error("could not re-enqueue orphan %s", job.job_id, exc_info=True)


def stage_from_name(name: str) -> JobStage | None:
    try:
        return JobStage(name)
    except ValueError:
        return None
