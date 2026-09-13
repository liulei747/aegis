"""In-flight scan jobs: the handle that makes a *remote* scan cancellable.

`POST /v1/scan` is one blocking call, and that shape cannot be cancelled: while the caller
waits, it has no way to tell this service "stop", and this service has no name for the work
in progress. Measured consequence in the container stack: a cancel issued mid-scan took
131 seconds to take effect -- the whole remaining scan -- because the worker was blocked on
the HTTP response and could not even notice the cancel request.

So a scan becomes an addressable thing with an id. That single change buys three properties:

* a **cancel** endpoint has something to name, and it terminates the process through the same
  `abort` predicate the in-process path already uses -- one cancellation mechanism, not two;
* the caller can **poll**, so its own loop keeps running: it refreshes its heartbeat, it
  notices its own cancel request, and it stays available for the reaper's bookkeeping;
* progress is observable from outside (``state``, ``started_at``), which is what the previous
  design could only have faked.

The registry is in-memory on purpose. A scan is bounded work owned by one process; persisting
it would mean a second source of truth about running processes, and there is nothing to
recover -- if this process dies, the scan died with it. Finished jobs are kept briefly so a
poll can still read the outcome, then pruned.
"""

from __future__ import annotations

import threading
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from aegis_core.logging import get_logger
from services.scan.runner import ScanOutcome, ScanRequest, run_scan

log = get_logger(__name__)

#: States a scan job can be in. Terminal: succeeded and failed.
QUEUED = "queued"
RUNNING = "running"
SUCCEEDED = "succeeded"
CANCELED = "canceled"
FAILED = "failed"
TERMINAL = frozenset({SUCCEEDED, CANCELED, FAILED})


@dataclass
class ScanJob:
    """One scan, addressable by id for as long as the service remembers it."""

    job_id: str
    request: ScanRequest
    state: str = QUEUED
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    started_at: datetime | None = None
    finished_at: datetime | None = None
    outcome: ScanOutcome | None = None
    detail: str | None = None
    #: Set by a cancel request, read by the running scan. This is the whole mechanism.
    cancel_event: threading.Event = field(default_factory=threading.Event)
    _thread: threading.Thread | None = None
    _lock: threading.Lock = field(default_factory=threading.Lock)
    _proc: Any = None

    def __post_init__(self) -> None:
        # The job owns the cancellation source; `run_scan` polls it through the request. Set
        # here rather than by the caller so the two can never disagree about which event
        # stops this scan.
        self.request.cancel_event = self.cancel_event
        self.request.process_sink = self.process_started
        self.request.process_done = self._process_done

    # -- lifecycle ------------------------------------------------------
    def start(self) -> None:
        self._thread = threading.Thread(
            target=self._run, name=f"scan-{self.job_id}", daemon=True
        )
        self._thread.start()

    def _run(self) -> None:
        with self._lock:
            if self.cancel_event.is_set():
                # Cancelled between registration and start: never spawn the scanner.
                self.state = CANCELED
                self.detail = "扫描器启动前已取消"
                self.finished_at = datetime.now(timezone.utc)
                return
            self.state = RUNNING
            self.started_at = datetime.now(timezone.utc)
        try:
            outcome = run_scan(self.request)
        except BaseException as exc:  # pragma: no cover - run_scan does not raise
            # `run_scan` promises never to raise for scan failures; this only catches a
            # programming error, and it must still end in a terminal state.
            log.exception("scan job %s crashed", self.job_id)
            with self._lock:
                self.state = FAILED
                self.detail = f"{type(exc).__name__}: {exc}"
                self.finished_at = datetime.now(timezone.utc)
            return
        with self._lock:
            self.outcome = outcome
            self.state = CANCELED if outcome.canceled else SUCCEEDED
            if outcome.canceled:
                # Keep the cancel request's own wording: it is the reason a reader cares
                # about. The ledger separately records `scan_aborted` for audit.
                self.detail = self.detail or "已按请求取消"
            else:
                self.detail = outcome.scan_record.failure_mode if outcome.scan_record else None
            self.finished_at = datetime.now(timezone.utc)
        if outcome.canceled:
            log.info("scan job %s was canceled", self.job_id)
        else:
            log.info("scan job %s finished (%d findings)", self.job_id, len(outcome.findings))

    def process_started(self, proc) -> None:
        """The subprocess exists. Keep the handle so a cancel can terminate it."""
        with self._lock:
            self._proc = proc
            already = self.cancel_event.is_set()
        if already:
            # The cancel arrived in the window between the check above and the spawn.
            from services.scan.opengrep import terminate_tree

            terminate_tree(proc, grace_s=1.0)

    def _process_done(self) -> None:
        with self._lock:
            self._proc = None

    def cancel(self, *, note: str = "已按请求取消") -> str:
        """Ask the running scan to stop, and terminate its process. Idempotent.

        Returns the state *after* the request, which for a running scan is still `running`:
        the scan thread owns the transition to `canceled`, so that the terminal state and the
        ledger it produces stay consistent with the in-process cancellation path.
        """
        with self._lock:
            if self.state in TERMINAL:
                return self.state
            self.cancel_event.set()
            self.detail = note
            proc = self._proc
        if proc is not None:
            # Terminating here rather than waiting for the scan thread to notice gives the
            # cancel a bounded response time: the poll interval is the caller's, this is the
            # service's. `terminate_tree` never raises.
            from services.scan.opengrep import terminate_tree

            terminate_tree(proc, grace_s=1.0)
        return self.state

    def snapshot(self) -> dict:
        """What a poller needs, without the (possibly large) findings payload."""
        with self._lock:
            return {
                "job_id": self.job_id,
                "state": self.state,
                "created_at": self.created_at.isoformat(),
                "started_at": self.started_at.isoformat() if self.started_at else None,
                "finished_at": self.finished_at.isoformat() if self.finished_at else None,
                "detail": self.detail,
            }


class ScanJobs:
    """The registry. One instance per process; the app owns it."""

    def __init__(self, *, retain_s: float = 600.0) -> None:
        self._jobs: dict[str, ScanJob] = {}
        self._lock = threading.Lock()
        self._retain_s = retain_s

    def submit(self, request: ScanRequest) -> ScanJob:
        self.prune()
        job = ScanJob(job_id=f"S-{uuid.uuid4().hex[:12]}", request=request)
        with self._lock:
            self._jobs[job.job_id] = job
        job.start()
        log.info("scan job %s accepted (%s)", job.job_id, request.workspace)
        return job

    def get(self, job_id: str) -> ScanJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def cancel(self, job_id: str) -> ScanJob | None:
        job = self.get(job_id)
        if job is None:
            return None
        job.cancel()
        return job

    def prune(self) -> int:
        """Forget finished jobs older than the retention window.

        Without this the registry grows for the life of the process -- and because this
        service restarts rarely, that is a slow leak rather than an obvious one.
        """
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self._retain_s)
        with self._lock:
            stale = [
                job_id
                for job_id, job in self._jobs.items()
                if job.finished_at is not None and job.finished_at < cutoff
            ]
            for job_id in stale:
                self._jobs.pop(job_id, None)
        return len(stale)

    def running(self) -> list[str]:
        with self._lock:
            return [job_id for job_id, job in self._jobs.items() if job.state == RUNNING]

    def shutdown(self, *, grace_s: float = 3.0) -> None:
        """Stop every running scan. Called when the service is going away."""
        with self._lock:
            jobs = list(self._jobs.values())
        for job in jobs:
            if job.state == RUNNING:
                job.cancel(note="服务正在关闭")
        for job in jobs:
            thread = job._thread
            if thread is not None:
                thread.join(timeout=grace_s)
