"""Opengrep process runner.

Opengrep is a Semgrep-CE fork, so the CLI surface is intentionally compatible.
We probe for the native binary first and fall back to a configured alternative
(``semgrep``) when it is absent, recording the degradation instead of failing.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from aegis_core.cancel import CanceledAbort
from aegis_core.logging import get_logger

log = get_logger(__name__)


@dataclass
class ScanOutcome:
    engine: str
    returncode: int
    sarif_path: Path
    command: list[str] = field(default_factory=list)
    stderr_tail: str = ""
    degraded: bool = False
    degrade_reason: str | None = None
    #: True when the process was killed because a cancel was requested. `run_scan`
    #: converts this into a named ledger entry instead of a failure.
    canceled: bool = False


def _as_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", errors="replace")
    return value


def terminate_tree(proc: subprocess.Popen, *, grace_s: float = 1.0) -> None:
    """Stop a scanner process and anything it spawned. Never raises.

    Windows gives no signal that a child can ignore but also does not reap grandchildren,
    so ``taskkill /T`` is tried first there; POSIX gets ``terminate`` then ``kill``. We do
    *not* put the child in a new process group: on Windows that turns ``terminate()`` from
    ``TerminateProcess`` into a ``CTRL_BREAK_EVENT``, which a child is free to ignore --
    the opposite of what a cancel needs.
    """
    if proc.poll() is not None:
        return
    if os.name == "nt":  # pragma: no cover - exercised on Windows only
        try:
            subprocess.run(
                ["taskkill", "/T", "/F", "/PID", str(proc.pid)],
                capture_output=True,
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception:
            log.debug("taskkill failed for pid=%s", proc.pid, exc_info=True)
    try:
        proc.terminate()
    except Exception:
        log.debug("terminate failed for pid=%s", proc.pid, exc_info=True)
    try:
        proc.wait(timeout=grace_s)
        return
    except subprocess.TimeoutExpired:
        pass
    try:
        proc.kill()
    except Exception:
        log.debug("kill failed for pid=%s", proc.pid, exc_info=True)
    try:
        proc.wait(timeout=grace_s)
    except subprocess.TimeoutExpired:  # pragma: no cover - the OS is very unhappy
        log.error("scanner process %s did not die after kill()", proc.pid)


class OpengrepNotFound(RuntimeError):
    pass


class OpengrepRunner:
    def __init__(
        self,
        binary: str = "opengrep",
        *,
        fallback_binary: str | None = "semgrep",
        timeout_s: int = 900,
    ) -> None:
        self.binary = binary
        self.fallback_binary = fallback_binary
        self.timeout_s = timeout_s
        self._version: str | None = None

    # -- discovery ----------------------------------------------------
    def resolve_binary(self) -> tuple[str, bool]:
        """Return (executable, degraded). Raises if neither is available."""
        found = shutil.which(self.binary)
        if found:
            return found, False
        if self.fallback_binary:
            alt = shutil.which(self.fallback_binary)
            if alt:
                log.warning(
                    "opengrep missing, falling back to %s (%s)",
                    self.fallback_binary,
                    alt,
                    extra={"stage": "scan"},
                )
                return alt, True
        raise OpengrepNotFound(
            f"neither '{self.binary}' nor '{self.fallback_binary}' is on PATH"
        )

    def version(self) -> str:
        """Cached: the version probe spawns a process, so never do it per request."""
        if self._version is not None:
            return self._version
        try:
            exe, _ = self.resolve_binary()
        except OpengrepNotFound:
            self._version = "unavailable"
            return self._version
        try:
            out = subprocess.run(
                [exe, "--version"],
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
            text = (out.stdout or out.stderr or "").strip()
        except Exception as exc:  # pragma: no cover - defensive
            self._version = f"{exe} (version probe failed: {exc})"
            return self._version
        self._version = text.splitlines()[0] if text else exe
        return self._version

    # -- execution ----------------------------------------------------
    def build_command(
        self,
        exe: str,
        *,
        target: Path,
        sarif_path: Path,
        rule_config: str | None,
        rules: list[str],
        include_globs: list[str],
        exclude_globs: list[str],
    ) -> list[str]:
        # opengrep uses `scan`, semgrep infers it from the flags. Both accept
        # --sarif/--output/--quiet/--config; --metrics is semgrep-only and makes
        # opengrep exit with rc=2 (verified against opengrep 1.16.0).
        is_opengrep = Path(exe).stem.startswith("opengrep")
        cmd = [exe]
        if is_opengrep:
            cmd.append("scan")
        cmd += ["--sarif", "--output", str(sarif_path)]

        configs = list(rules)
        if rule_config:
            configs.append(rule_config)
        if not configs:
            configs = ["auto"]
        for cfg in configs:
            cmd += ["--config", cfg]

        if not is_opengrep:
            # Telemetry opt-out; opengrep has no --metrics flag (and sends nothing).
            cmd.append("--metrics=off")
        cmd.append("--quiet")
        for glob in include_globs:
            cmd += ["--include", glob]
        for glob in exclude_globs:
            cmd += ["--exclude", glob]
        cmd.append(str(target))
        return cmd

    def scan(
        self,
        target: Path,
        *,
        out_dir: Path | None = None,
        rule_config: str | None = None,
        rules: list[str] | None = None,
        include_globs: list[str] | None = None,
        exclude_globs: list[str] | None = None,
        abort: Callable[[], bool] | None = None,
        process_sink: Callable[[subprocess.Popen], None] | None = None,
        process_done: Callable[[], None] | None = None,
        cancel_poll_s: float = 0.05,
    ) -> ScanOutcome:
        exe, degraded = self.resolve_binary()
        target = target.resolve()
        if not target.exists():
            raise FileNotFoundError(f"scan target does not exist: {target}")

        holder = Path(out_dir) if out_dir else Path(tempfile.mkdtemp(prefix="aegis-scan-"))
        holder.mkdir(parents=True, exist_ok=True)
        sarif_path = holder / "opengrep.sarif"

        cmd = self.build_command(
            exe,
            target=target,
            sarif_path=sarif_path,
            rule_config=rule_config,
            rules=rules or [],
            include_globs=include_globs or [],
            exclude_globs=exclude_globs or [],
        )
        log.info("running static scan", extra={"stage": "scan"})
        log.debug("command: %s", " ".join(cmd))

        # `Popen` rather than `subprocess.run`: the handle is the whole point. Without it
        # the caller cannot terminate a scan, and the scan stage is the longest one
        # (AEGIS_SCAN_TIMEOUT_S defaults to 900). Waiting is therefore a poll loop, which
        # also has to keep the partial output that `TimeoutExpired` carries -- the old
        # `subprocess.run` path lost it.
        proc = subprocess.Popen(  # noqa: S603 - argv is built, never shell-interpreted
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if process_sink is not None:
            process_sink(proc)

        err = ""
        try:
            deadline = time.monotonic() + self.timeout_s
            while True:
                try:
                    _stdout, err = proc.communicate(timeout=min(cancel_poll_s, 1.0))
                    break
                except subprocess.TimeoutExpired as expired:
                    # Keep whatever the process already wrote: `TimeoutExpired` carries the
                    # partial streams, and discarding them loses the only clue about why a
                    # scan was slow. Only stderr is kept -- it is what the ledger records --
                    # and stdout is dropped deliberately (the SARIF goes to a file).
                    err = _as_text(expired.stderr)
                    if abort is not None and abort():
                        terminate_tree(proc, grace_s=1.0)
                        raise CanceledAbort(
                            stage="scan",
                            resource="scan_process",
                            detail=f"rc={proc.returncode}",
                        ) from None
                    if time.monotonic() >= deadline:
                        terminate_tree(proc, grace_s=1.0)
                        err = (err or "") + (
                            f"\nscanner exceeded {self.timeout_s}s and was terminated"
                        )
                        break
        finally:
            if process_done is not None:
                process_done()

        tail = "\n".join((err or "").strip().splitlines()[-20:])
        if proc.returncode not in (0, 1):  # semgrep-family: 1 == findings present
            log.error("static scan failed rc=%s: %s", proc.returncode, tail)
        elif not sarif_path.exists():
            log.error("static scan produced no SARIF: rc=%s", proc.returncode)
        return ScanOutcome(
            engine=Path(exe).stem,
            returncode=proc.returncode,
            sarif_path=sarif_path,
            command=cmd,
            stderr_tail=tail,
            degraded=degraded,
            degrade_reason=(
                f"'{self.binary}' not found on PATH; used '{Path(exe).stem}' instead"
                if degraded
                else None
            ),
        )
