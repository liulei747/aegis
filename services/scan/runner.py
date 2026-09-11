"""One scan, done once, described honestly.

This is the whole scan capability in one function: locate an engine, invoke it,
parse what it produced, and return findings **plus a record of the invocation**.
It is deliberately usable two ways:

* the scan service calls it behind an HTTP endpoint;
* the extraction pipeline calls it in-process when running locally with no queue.

Both paths must behave identically, so there is no second implementation to drift.
"""

from __future__ import annotations

import shutil
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from subprocess import Popen

from aegis_contracts.domain import Finding, ScanRecord
from aegis_core.cancel import CanceledAbort
from aegis_core.logging import get_logger
from services.scan.opengrep import OpengrepRunner
from services.scan.sarif import SarifParser
from services.scan.scanrecord import build_scan_record

log = get_logger(__name__)


@dataclass
class ScanRequest:
    workspace: Path
    rules: list[str] = field(default_factory=list)
    rule_config: str | None = None
    include_globs: list[str] = field(default_factory=list)
    exclude_globs: list[str] = field(default_factory=list)
    out_dir: Path | None = None
    binary: str = "opengrep"
    fallback_binary: str | None = "semgrep"
    timeout_s: int = 900
    # --- interruptibility (all optional; None means "behave exactly as before") ---
    #: Consulted while waiting for the scanner. True means "stop and say so".
    abort: Callable[[], bool] | None = None
    #: Handed the process as soon as it exists, so the caller can terminate it.
    process_sink: Callable[[Popen], None] | None = None
    #: Called once the process is finished, however it finished, to drop the handle.
    process_done: Callable[[], None] | None = None


@dataclass
class ScanOutcome:
    """The scan phase's result.

    A flattened view of the engine runner's outcome plus this layer's bookkeeping: the
    caller wants "what did we find, and what happened", not the runner's raw streams.
    """

    engine: str
    engine_version: str = ""
    sarif_path: Path | None = None
    findings: list[Finding] = field(default_factory=list)
    scan_record: ScanRecord | None = None
    warnings: list[str] = field(default_factory=list)
    degraded: bool = False
    #: Why we degraded, e.g. "opengrep missing, used semgrep instead". Carried through so
    #: the reason reaches the bundle rather than only the logs.
    degrade_reason: str | None = None
    #: Copied from the engine runner so the ledger and the failure checks below stay
    #: readable; this layer decides what they mean, the runner only reports them.
    command: list[str] = field(default_factory=list)
    stderr_tail: str = ""
    returncode: int = 0
    #: The scan was killed on request. Not a failure: `run_scan` reports it in the ledger
    #: and the caller turns it into a cancellation.
    canceled: bool = False


def probe(binary: str = "opengrep", fallback: str | None = "semgrep") -> dict:
    """Is a scanner reachable from this process? Used by /health."""
    runner = OpengrepRunner(binary, fallback_binary=fallback)
    try:
        executable, degraded = runner.resolve_binary()
    except Exception as exc:
        return {"available": False, "reason": str(exc), "binary": binary}
    return {
        "available": True,
        "binary": Path(executable).name,
        "path": executable,
        "version": runner.version(),
        "degraded": degraded,
        "fallback": fallback if degraded else None,
    }


def parse_sarif(sarif_path: Path, *, workspace: Path) -> list[Finding]:
    """Read findings out of an existing SARIF file, without running anything."""
    return SarifParser(workspace_root=workspace).parse_file(sarif_path)


def run_scan(request: ScanRequest) -> ScanOutcome:
    """Run the scanner and always return a result — never raise for scan failures.

    A scanner that fails, or writes nothing usable, yields zero findings plus a
    named `failure_mode`. The alternative (raising) makes "the scanner broke"
    indistinguishable from "the repository is clean" one layer up.
    """
    runner = OpengrepRunner(
        request.binary,
        fallback_binary=request.fallback_binary,
        timeout_s=request.timeout_s,
    )
    warnings: list[str] = []
    configured = bool(request.rule_config or request.rules)

    try:
        engine_result = runner.scan(
            request.workspace,
            out_dir=request.out_dir,
            rule_config=request.rule_config,
            rules=request.rules,
            include_globs=request.include_globs,
            exclude_globs=request.exclude_globs,
            abort=request.abort,
            process_sink=request.process_sink,
            process_done=request.process_done,
        )
    except CanceledAbort:
        # Caught, not propagated: this function's contract is that it never raises, and the
        # caller still has to learn *why* the scan is empty. Both jobs are done by
        # returning a named ledger entry plus `canceled=True` -- the flag says "do not
        # treat me as a failure", the ledger says what happened for anyone reading the
        # manifest later. This is the one place cancellation and the never-raise rule meet.
        reason = "the scan was terminated on request"
        log.info("scan aborted during %s", request.workspace)
        return ScanOutcome(
            engine=Path(request.binary).stem,
            sarif_path=None,
            findings=[],
            warnings=[reason],
            degraded=True,
            canceled=True,
            scan_record=build_scan_record(
                engine=Path(request.binary).stem,
                engine_version="",
                sarif_path=None,
                command=[],
                configured=configured,
                stderr=reason,
                findings=[],
                returncode=-15,
                failure_mode="scan_aborted",
            ),
        )
    except Exception as exc:  # no engine at all
        log.error("scan could not start: %s", exc)
        reason = f"scanner could not be started: {exc}"
        return ScanOutcome(
            engine=Path(request.binary).stem,
            sarif_path=None,
            findings=[],
            warnings=[reason],
            degraded=True,
            scan_record=build_scan_record(
                engine=Path(request.binary).stem,
                engine_version="",
                sarif_path=None,
                command=[],
                configured=configured,
                stderr=str(exc),
                findings=[],
                returncode=-1,
                failure_mode=reason,
            ),
        )

    engine_version = runner.version()
    # `OpengrepRunner.scan` has its own, flatter outcome shape. Normalise it once here so
    # the rest of this function only ever talks about this layer's `ScanOutcome`.
    outcome = ScanOutcome(
        engine=engine_result.engine,
        engine_version=engine_version,
        sarif_path=engine_result.sarif_path,
        warnings=warnings,
        degraded=engine_result.degraded,
        degrade_reason=engine_result.degrade_reason,
        command=engine_result.command,
        stderr_tail=engine_result.stderr_tail,
        returncode=engine_result.returncode,
    )
    if outcome.degraded and outcome.degrade_reason:
        warnings.append(outcome.degrade_reason)

    def failed(reason: str, *, failure_mode: str | None = None) -> ScanOutcome:
        warnings.append(reason)
        log.error("scan produced no usable findings: %s", reason)
        return ScanOutcome(
            engine=outcome.engine,
            engine_version=engine_version,
            sarif_path=outcome.sarif_path,
            findings=[],
            warnings=warnings,
            degraded=True,
            scan_record=build_scan_record(
                engine=outcome.engine,
                engine_version=engine_version,
                sarif_path=outcome.sarif_path,
                command=outcome.command,
                configured=configured,
                stderr=outcome.stderr_tail,
                findings=[],
                returncode=outcome.returncode,
                failure_mode=failure_mode or reason,
            ),
        )

    if outcome.returncode not in (0, 1):  # 1 means "findings present" for this family
        tail = outcome.stderr_tail.splitlines()[-1] if outcome.stderr_tail else ""
        # Two ways to get a bad exit code, and they must not read the same in the ledger:
        # we killed it (a cancel) versus it died on its own (OOM killer, an operator's
        # `kill`). The caller's abort predicate is the only witness -- the return code
        # itself cannot tell them apart, which is why `aborted()` is asked here and
        # nowhere else.
        was_aborted = request.abort is not None and request.abort()
        if was_aborted:
            reason = "the scan was terminated on request"
            log.info("scan process killed while a cancel was pending")
            return ScanOutcome(
                engine=outcome.engine,
                engine_version=engine_version,
                sarif_path=outcome.sarif_path,
                findings=[],
                warnings=warnings + [reason],
                degraded=True,
                canceled=True,
                scan_record=build_scan_record(
                    engine=outcome.engine,
                    engine_version=engine_version,
                    sarif_path=outcome.sarif_path,
                    command=outcome.command,
                    configured=configured,
                    stderr=outcome.stderr_tail,
                    findings=[],
                    returncode=outcome.returncode,
                    failure_mode="scan_aborted",
                ),
            )
        killed = _looks_killed(outcome.returncode)
        return failed(
            f"scanner exited with rc={outcome.returncode}" + (f": {tail}" if tail else ""),
            # Killed without a cancel pending: an external stop (OOM killer, an operator's
            # `kill`). It is a failure, and it gets its own name so it is not confused with
            # a scanner that ran and objected.
            failure_mode="scan_aborted" if killed else None,
        )
    if outcome.sarif_path is None:
        # A scanner that reports success without a path is a failure with a name, not a
        # crash: `run_scan` may not raise, and a missing artifact is exactly the case it
        # exists to describe.
        return failed("scanner reported success but produced no SARIF path")
    if not outcome.sarif_path.exists():
        return failed(f"scanner produced no SARIF output (rc={outcome.returncode})")
    if outcome.sarif_path.stat().st_size == 0:
        return failed(f"scanner wrote an empty SARIF file (rc={outcome.returncode})")

    try:
        findings = parse_sarif(outcome.sarif_path, workspace=request.workspace)
    except ValueError as exc:
        return failed(f"scanner output is not valid SARIF: {exc}")

    return ScanOutcome(
        engine=outcome.engine,
        engine_version=engine_version,
        sarif_path=outcome.sarif_path,
        findings=findings,
        warnings=warnings,
        scan_record=build_scan_record(
            engine=outcome.engine,
            engine_version=engine_version,
            sarif_path=outcome.sarif_path,
            command=outcome.command,
            configured=configured,
            stderr=outcome.stderr_tail,
            findings=findings,
            returncode=outcome.returncode,
        ),
    )


def engine_available(binary: str = "opengrep") -> bool:
    return shutil.which(binary) is not None


def _looks_killed(returncode: int) -> bool:
    """Whether an exit code is evidence of an external stop rather than a scanner error.

    POSIX reports a fatal signal as a negative code (``-15`` SIGTERM, ``-9`` SIGKILL).
    That is real evidence. Everything else is not: opengrep exits ``rc=2`` on an
    unsupported flag, and calling that "aborted" would hide a misconfiguration behind a
    word that means "somebody stopped us on purpose". So the test is deliberately narrow,
    and the authoritative witness stays the caller's abort predicate, consulted above.
    """
    return returncode in (-15, -9, -1)
