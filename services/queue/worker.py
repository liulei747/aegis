"""The worker's main loop: claim a job, run the pipeline in-process, report honestly.

Two design decisions here are the difference between a queue and a queue that lies:

**Extraction runs in this process, not over HTTP to the `extract` container.** Delegating
would cost three things at once, and each is fatal on its own: the gateway's HTTP call
blocks for up to 30 minutes so this loop could not heartbeat (the reaper would then
declare a healthy job dead), `services/extraction/routes.py` exposes no progress or cancel
channel (so stage progress collapses to two coarse phases and a cancel becomes impossible),
and the handle to the language servers would live in another container. `extract` remains
the entry point for *synchronous* callers; the worker is a second caller of the same code,
not a second implementation.

**`queued -> running` is written before the pipeline starts, and the stage is pinned to
`scan`.** The scan stage is the one stage that emits nothing while it runs -- it is a
synchronous subprocess wait -- so a job that only marked itself running on the first event
would appear stuck in `queued` for up to 900 seconds. Writing that snapshot first is what
makes "it is scanning" visible instead of "nothing is happening".
"""

from __future__ import annotations

import logging
import signal
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from aegis_contracts.jobs import (
    TERMINAL_STATES,
    FailureMode,
    Job,
    JobKind,
    JobResult,
    JobStage,
)
from aegis_core.cancel import CanceledAbort
from aegis_core.config import BudgetConfig, Settings, get_settings
from aegis_core.logging import get_logger, setup_logging
from services.extraction.pipeline.assemble import (
    AssemblyPipeline,
    PipelineRequest,
    ScanOnlyPipeline,
    StageEvent,
)
from services.queue.cancel import Teardown
from services.queue.jobs import JobStore
from services.queue.reaper import Reaper, stage_from_name
from services.queue.streams import JobStream, consumer_name

log = get_logger(__name__)

#: A job's stage name is the pipeline's, so the observer's stage string maps 1:1 onto the
#: contract's enum. Kept as a lookup rather than a cast so an unexpected name is visible.
_STAGES = {stage.value: stage for stage in JobStage}


class Worker:
    """One consumer of the job stream. There may be several; none of them coordinate."""

    def __init__(
        self,
        store: JobStore,
        stream: JobStream,
        settings: Settings,
        *,
        worker_id: str | None = None,
    ) -> None:
        self.store = store
        self.stream = stream
        self.settings = settings
        self.worker_id = worker_id or consumer_name()
        self.stop_event = threading.Event()
        self._cancel_watch = threading.Event()
        self._current_job: str | None = None
        self._current_stage: str = JobStage.SCAN.value
        self._lock = threading.Lock()
        self._last_heartbeat = 0.0
        self._last_reap = 0.0
        self._poisoned = False
        self.reaper = Reaper(store, stream, settings, worker_id=self.worker_id)

    # ------------------------------------------------------------------
    # lifecycle
    # ------------------------------------------------------------------
    def request_stop(self, *_args) -> None:
        """Signal handler. Sets the flag and nothing else -- no I/O in a handler.

        Draining happens in the loop, which is also watching this job's abort predicate, so
        a shutdown reaches a running job through exactly the same path a cancel does.
        """
        self.stop_event.set()
        self._cancel_watch.set()

    def install_signal_handlers(self) -> None:
        for name in ("SIGTERM", "SIGINT"):
            sig = getattr(signal, name, None)
            if sig is not None:
                try:
                    signal.signal(sig, self.request_stop)
                except ValueError:  # pragma: no cover - not the main thread
                    log.debug("cannot install %s handler outside the main thread", name)

    def serve_forever(self, *, max_iterations: int | None = None) -> None:
        """Claim and run until stopped. `max_iterations` exists for tests."""
        iterations = 0
        log.info("worker %s ready (group=%s)", self.worker_id, self.stream.group)
        while not self.stop_event.is_set() and not self._poisoned:
            iterations += 1
            if max_iterations is not None and iterations > max_iterations:
                break
            try:
                self._maybe_reap()
                self._maybe_heartbeat()
                entries = self.stream.claim(self.worker_id, count=1)
            except Exception as exc:  # Redis unreachable: back off, do not die
                log.error("worker loop could not reach the queue: %s", exc)
                self._sleep_interruptibly(5.0)
                continue
            if not entries:
                continue
            entry = entries[0]
            try:
                self.handle(entry)
            finally:
                # Always ACK: a message left pending forever is a job nobody will retry,
                # and the retry decision belongs to the reaper, not to the transport.
                try:
                    self.stream.ack(entry["entry_id"])
                except Exception:  # pragma: no cover - Redis trouble
                    log.error("failed to ACK %s", entry["entry_id"], exc_info=True)

    # ------------------------------------------------------------------
    # one job
    # ------------------------------------------------------------------
    def handle(self, entry: dict) -> None:
        job_id = entry["job_id"]
        job = self.store.get(job_id)
        if job is None:
            log.warning("job %s vanished (expired?) before it ran", job_id)
            return
        if job.state in TERMINAL_STATES:
            # Redelivery of finished work: the same job_id can arrive twice (reaper
            # re-enqueue, MAXLEN survivors). Re-running it would be pure waste.
            log.info("job %s is already %s; nothing to do", job_id, job.state.value)
            return
        if job.cancel_requested:
            # Cancelled while queued: never start it.
            self.store.mark_canceled(job_id, note="canceled before it started")
            return

        attempt = entry.get("attempt") or 1
        with self._lock:
            self._current_job = job_id
            self._current_stage = JobStage.SCAN.value
        self._cancel_watch.clear()

        teardown = Teardown(reason="cancel")
        try:
            claimed = self.store.set_running(job_id, worker_id=self.worker_id, attempt=attempt)
            if claimed is None:
                log.warning("job %s disappeared between read and claim", job_id)
                return
            if claimed.state in TERMINAL_STATES:
                return

            # Pin the stage before the first silent one: the scan emits nothing while it
            # runs, so this snapshot is the only "it is scanning" the user can see.
            self.store.pin_stage(job_id, JobStage.SCAN, note="scanning")
            teardown.begin()

            result = self._run(claimed, teardown)
            self.store.mark_succeeded(job_id, result=result)
            log.info("job %s succeeded (%s)", job_id, result.bundle_id)

        except CanceledAbort as exc:
            # Must precede `except Exception`: CanceledAbort is a BaseException, so the
            # order is already safe, but stating it keeps the intent visible.
            self._finish_canceled(job_id, exc, teardown)
        except Exception as exc:
            log.exception("job %s failed", job_id)
            self.store.mark_failed(
                job_id,
                mode=_mode_for(exc),
                message=str(exc) or exc.__class__.__name__,
                detail=repr(exc),
                recoverable=True,
            )
        finally:
            with self._lock:
                self._current_job = None
            self._cancel_watch.clear()

    def _run(self, job: Job, teardown: Teardown) -> JobResult:
        request = job.submission.request
        if job.kind is JobKind.AI_FANOUT:
            # Refused loudly rather than accepted and ignored. The contract reserves the
            # enum so the AI stage needs no schema change; a worker that silently did
            # nothing with it would look like a hang.
            raise NotImplementedError("ai fanout not implemented in this build")

        workspace = Path(request.workspace).expanduser()
        if not workspace.is_dir():
            raise _JobRefused(
                FailureMode.WORKSPACE_MISSING, f"workspace is not a directory: {workspace}"
            )
        sarif_path = Path(request.sarif_path) if request.sarif_path else None
        if sarif_path is not None and not sarif_path.is_file():
            raise _JobRefused(FailureMode.SARIF_MISSING, f"sarif not found: {sarif_path}")

        budget = BudgetConfig(**request.budget) if request.budget else self.settings.budget
        pipeline_request = PipelineRequest(
            workspace=workspace,
            sarif_path=sarif_path,
            rules=request.rules,
            rule_config=request.rule_config,
            include_globs=request.include_globs,
            exclude_globs=request.exclude_globs,
            budget=budget,
            max_findings=request.max_findings,
            lsp=request.lsp,
            package_name=request.package_name,
        )

        if job.kind is JobKind.SCAN:
            return self._run_scan_only(pipeline_request)

        pipeline = AssemblyPipeline(self.settings)
        outcome = _run_async(
            pipeline.run(
                pipeline_request,
                observer=self._on_event,
                abort=self._abort_check,
                teardown=teardown,
                staging=True,
            )
        )
        if outcome.bundle is None or outcome.package_path is None:  # pragma: no cover
            raise RuntimeError("the pipeline produced no bundle")
        manifest = outcome.bundle.manifest
        return JobResult(
            bundle_id=manifest.bundle_id,
            package_path=str(outcome.package_path),
            run_id=outcome.run_id,
            sarif_path=str(outcome.sarif_path) if outcome.sarif_path else None,
            scan_record=outcome.scan_record,
            warnings=list(outcome.warnings),
            artifacts={
                "bundle": {
                    "kind": "bundle",
                    "ref": manifest.bundle_id,
                    "path": str(outcome.package_path),
                    "available": True,
                }
            },
        )

    def _run_scan_only(self, pipeline_request: PipelineRequest) -> JobResult:
        """A scan job: findings and a ledger, no bundle.

        Runs `ScanOnlyPipeline` rather than calling `run_scan` directly so the job inherits
        the existing semantics of `run_id`, `sarif_path` and `warnings` -- the same reason
        the synchronous `/v1/scan` route uses it.
        """
        result = ScanOnlyPipeline(self.settings).run(pipeline_request)
        return JobResult(
            bundle_id=None,
            run_id=result.run_id,
            sarif_path=str(result.sarif_path) if result.sarif_path else None,
            scan_record=result.scan_record,
            warnings=list(result.warnings),
        )

    # ------------------------------------------------------------------
    # progress
    # ------------------------------------------------------------------
    def _on_event(self, event: StageEvent) -> None:
        """Turn one pipeline event into one durable state write.

        The observer runs on the pipeline's thread, which is the same thread the loop runs
        on, so there is no cross-thread write here. If that ever changes, this becomes the
        place to hand events to a queue instead.
        """
        with self._lock:
            job_id, self._current_stage = self._current_job, event.stage
        if job_id is None:  # pragma: no cover - an event without a job cannot happen
            return
        stage = _STAGES.get(event.stage)
        if stage is None:  # pragma: no cover - the pipeline's vocabulary is fixed
            return
        try:
            if event.phase == "start":
                self.store.record_stage(job_id, stage, state="running", note=event.note)
            else:
                self.store.record_stage(
                    job_id,
                    stage,
                    state="done",
                    duration_ms=event.ms,
                    note=event.note,
                    counters=event.counters,
                    units_done=event.units_done,
                    units_total=event.units_total,
                    unit_label=event.unit_label,
                )
        except Exception:  # a progress write must never sink a run
            log.error("failed to record stage %s for %s", event.stage, job_id, exc_info=True)

    def _abort_check(self) -> bool:
        """The predicate the pipeline polls. Cheap, and includes a queued cancel request.

        Deliberately not one Redis round trip per poll: the local flag covers shutdown and
        any cancel this worker accepted, and the durable `cancel_requested` is consulted on
        a short interval rather than continuously. A missed poll costs one interval of
        latency; polling Redis from inside a scan loop would cost the scan.
        """
        if self._cancel_watch.is_set():
            return True
        now = time.monotonic()
        if now - getattr(self, "_last_cancel_poll", 0.0) < 1.0:
            return False
        self._last_cancel_poll = now
        job_id = self._current_job
        if job_id is None:
            return False
        try:
            job = self.store.get(job_id)
        except Exception:  # pragma: no cover - Redis trouble must not abort a run
            return False
        if job is not None and job.cancel_requested:
            self._cancel_watch.set()
            return True
        return False

    def _finish_canceled(self, job_id: str, exc: CanceledAbort, teardown: Teardown) -> None:
        """Terminal state for an interrupted run. Two different endings, same mechanism.

        A shutdown returns the job to the queue (the user still wants it); a cancel marks
        it canceled (the user does not). Recording a shutdown as a cancellation would be
        telling the user they asked for something they did not.
        """
        teardown.kill_all(
            terminate_grace_s=self.settings.queue.cancel_terminate_grace_s,
            kill_grace_s=self.settings.queue.cancel_kill_grace_s,
        )
        teardown.cleanup_partial()
        detail = f"canceled during {exc.stage} ({exc.resource})" + (
            f": {exc.detail}" if exc.detail else ""
        )
        if self.stop_event.is_set():
            self.store.requeue(job_id, note="worker restarting; job returned to the queue")
            self._reenqueue(job_id)
            log.info("job %s returned to the queue for a restart", job_id)
            return
        # The exception is the more accurate witness of where the run stopped: the pipeline
        # can raise from inside a stage before it has had a chance to report that stage.
        self.store.mark_canceled(job_id, note=detail, stage=stage_from_name(exc.stage))
        log.info("job %s canceled at %s", job_id, exc.stage)

    def _reenqueue(self, job_id: str) -> None:
        job = self.store.get(job_id)
        if job is None:  # pragma: no cover - it was just written
            return
        try:
            self.stream.ensure_group()
            self.stream.enqueue(
                job_id,
                kind=job.submission.kind.value,
                fingerprint=job.submission.fingerprint,
                attempt=job.progress.attempt,
                submitted_at=job.submission.submitted_at,
            )
        except Exception:  # pragma: no cover - Redis trouble
            log.error("failed to re-enqueue %s", job_id, exc_info=True)

    # ------------------------------------------------------------------
    # periodic work
    # ------------------------------------------------------------------
    def _maybe_heartbeat(self) -> None:
        interval = self.settings.queue.heartbeat_interval_s
        now = time.monotonic()
        if now - self._last_heartbeat < interval:
            return
        self._last_heartbeat = now
        with self._lock:
            job_id = self._current_job
            stage = _STAGES.get(self._current_stage)
        if job_id is not None:
            try:
                self.store.heartbeat(job_id, worker_id=self.worker_id, stage=stage)
            except Exception:  # pragma: no cover - Redis trouble
                log.error("heartbeat failed for %s", job_id, exc_info=True)
        try:
            self.stream.redis.setex(
                f"aegis:queue:worker:{self.worker_id}",
                max(interval * 4, 60),
                f"{datetime.now(timezone.utc).isoformat()}|{job_id or ''}",
            )
        except Exception:  # pragma: no cover - Redis trouble
            pass

    def _maybe_reap(self) -> None:
        interval = self.settings.queue.reaper_interval_s
        now = time.monotonic()
        if now - self._last_reap < interval:
            return
        self._last_reap = now
        try:
            self.reaper.reap_once()
        except Exception:  # pragma: no cover - the reaper must never kill the worker
            log.error("reaper pass failed", exc_info=True)

    def _sleep_interruptibly(self, seconds: float) -> None:
        self.stop_event.wait(seconds)


class _JobRefused(Exception):
    """A pre-flight refusal with a mode already chosen. Not a crash: a diagnosis."""

    def __init__(self, mode: FailureMode, message: str) -> None:
        super().__init__(message)
        self.mode = mode


def _mode_for(exc: Exception) -> FailureMode:
    if isinstance(exc, _JobRefused):
        return exc.mode
    if isinstance(exc, NotImplementedError):
        return FailureMode.INTERNAL_ERROR
    return FailureMode.PIPELINE_EXCEPTION


def _run_async(coro):
    """Run the pipeline's coroutine to completion from this synchronous loop."""
    import asyncio

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(coro)
    # Already inside a loop (tests, or a future async worker): use a private one.
    import concurrent.futures

    with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
        return pool.submit(asyncio.run, coro).result()


def main(argv: list[str] | None = None) -> int:
    """Entry point for `aegis-worker`.

    Refusing to start without a Redis URL is deliberate: a worker with nothing to consume
    would idle healthily forever while operators assume jobs are being processed.
    """
    import argparse

    import redis

    parser = argparse.ArgumentParser(prog="aegis-worker", description="Aegis job worker")
    parser.add_argument("--once", action="store_true", help="run one claim cycle and exit")
    parser.add_argument("--no-reap", action="store_true", help="skip the periodic reaper")
    args = parser.parse_args(argv)

    setup_logging(get_settings().log_level)
    settings = get_settings()
    if settings.queue.redis_url is None:
        print(
            "AEGIS_QUEUE__REDIS_URL is not set: there is no queue to consume.\n"
            "Set it (e.g. redis://redis:6379/0) or use the synchronous API instead.",
            flush=True,
        )
        return 2

    client = redis.Redis.from_url(settings.queue.redis_url)
    from services.queue.keys import QueueKeys

    keys = QueueKeys(settings.queue.stream, settings.queue.group)
    store = JobStore(client, settings.queue, keys=keys)
    stream = JobStream(client, settings.queue, keys=keys)
    stream.ensure_group()
    worker = Worker(store, stream, settings)
    worker.install_signal_handlers()
    if args.no_reap:
        worker.reaper.enabled = False

    # Layer 1 of crash recovery: anything left `running` by a dead worker is dealt with
    # before this one claims new work, so a restart is enough to clear the state even when
    # the visibility timeout has not elapsed.
    report = store.reconcile_startup(stream, settings)
    log.info("startup reconcile: %s", report)

    if args.once:
        entries = stream.claim(worker.worker_id, count=1, block_ms=settings.queue.block_ms)
        if entries:
            worker.handle(entries[0])
            stream.ack(entries[0]["entry_id"])
        return 0

    worker.serve_forever()
    return 0


if __name__ == "__main__":  # pragma: no cover
    logging.basicConfig(level=logging.INFO)
    raise SystemExit(main())
