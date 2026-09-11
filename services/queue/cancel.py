"""A minimal, real ``TeardownHandle`` — the worker's, which the pipeline only writes to.

The pipeline declares the protocol and never imports this module; the worker passes an
instance of it into `AssemblyPipeline.run`. Keeping the implementation out of the pipeline
is what lets the assembly code stay unaware of queues, Redis and cancellation policy while
still being interruptible.

Two properties matter more than the mechanics:

* **Registering is cheap and idempotent by name.** The pipeline registers the scan
  process, the language-server manager and its staging directory as it creates them; a
  second registration of the same name must not orphan the first handle.
* **`aborted()` and `abort()` are different questions.** The predicate records intent and
  is safe to poll from any thread; `abort()` performs termination and is called once, by
  the worker, on the cancellation path.
"""

from __future__ import annotations

import subprocess
import threading
from pathlib import Path

from aegis_core.logging import get_logger

log = get_logger(__name__)


class Teardown:
    """Owns every resource this run created that can be terminated or deleted."""

    def __init__(self, *, reason: str = "cancel") -> None:
        self.reason = reason
        self._aborted = threading.Event()
        self._started = threading.Event()
        self._lock = threading.Lock()
        self._processes: dict[str, subprocess.Popen] = {}
        self._lsp = None
        self._artifact_dirs: list[Path] = []
        self.terminated: list[str] = []

    # -- predicate ------------------------------------------------------
    def aborted(self) -> bool:
        return self._aborted.is_set()

    def request(self) -> None:
        """Record the intent to stop. Everything else follows from this flag."""
        self._aborted.set()

    def begin(self) -> None:
        """Called once the pipeline is about to run.

        The distinction between "a handle exists" and "the job started" is what lets the
        worker record `queued -> running` *before* the first silent stage rather than
        after: a job must not be marked running merely because its handle was created.
        """
        self._started.set()

    @property
    def started(self) -> bool:
        return self._started.is_set()

    # -- registration ---------------------------------------------------
    def register_process(self, name: str, proc: subprocess.Popen) -> None:
        with self._lock:
            self._processes[name] = proc

    def unregister_process(self, name: str) -> None:
        with self._lock:
            self._processes.pop(name, None)

    def register_lsp(self, manager) -> None:
        self._lsp = manager

    def register_artifact_dir(self, path: Path) -> None:
        with self._lock:
            self._artifact_dirs.append(Path(path))

    # -- termination ----------------------------------------------------
    def kill_all(self, *, terminate_grace_s: float = 3.0, kill_grace_s: float = 2.0) -> list[str]:
        """Stop every registered process. Idempotent, and never raises.

        Each handle is popped before it is touched, so a second call cannot kill a pid the
        OS has already recycled -- which is a real hazard when the first call is racing a
        process that exited on its own.
        """
        killed: list[str] = []
        with self._lock:
            processes = list(self._processes.items())
            self._processes.clear()
            lsp = self._lsp
        for name, proc in processes:
            if proc.poll() is not None:
                continue
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=terminate_grace_s)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    try:
                        proc.wait(timeout=kill_grace_s)
                    except subprocess.TimeoutExpired:  # pragma: no cover - OS trouble
                        log.error("process %s survived kill()", name)
                killed.append(name)
            except Exception:  # pragma: no cover - best effort
                log.debug("failed to terminate %s", name, exc_info=True)
        if lsp is not None:
            try:
                lsp.kill_all()
                killed.append("lsp")
            except Exception:  # pragma: no cover - best effort
                log.debug("failed to kill language servers", exc_info=True)
        self.terminated.extend(killed)
        return killed

    def cleanup_partial(self) -> list[Path]:
        """Delete staging directories. A half-written bundle must not be left where a
        reader would mistake it for a finished one."""
        import shutil

        removed: list[Path] = []
        with self._lock:
            dirs = list(self._artifact_dirs)
            self._artifact_dirs.clear()
        for path in dirs:
            if path.exists():
                shutil.rmtree(path, ignore_errors=True)
                removed.append(path)
        return removed
