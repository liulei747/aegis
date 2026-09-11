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
from dataclasses import dataclass, field
from pathlib import Path

from aegis_contracts.domain import Finding, ScanRecord
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


@dataclass
class ScanOutcome:
    engine: str
    engine_version: str = ""
    sarif_path: Path | None = None
    findings: list[Finding] = field(default_factory=list)
    scan_record: ScanRecord | None = None
    warnings: list[str] = field(default_factory=list)
    degraded: bool = False


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
        outcome = runner.scan(
            request.workspace,
            out_dir=request.out_dir,
            rule_config=request.rule_config,
            rules=request.rules,
            include_globs=request.include_globs,
            exclude_globs=request.exclude_globs,
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
    if outcome.degraded and outcome.degrade_reason:
        warnings.append(outcome.degrade_reason)

    def failed(reason: str) -> ScanOutcome:
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
                failure_mode=reason,
            ),
        )

    if outcome.returncode not in (0, 1):  # 1 means "findings present" for this family
        tail = outcome.stderr_tail.splitlines()[-1] if outcome.stderr_tail else ""
        return failed(
            f"scanner exited with rc={outcome.returncode}" + (f": {tail}" if tail else "")
        )
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
