"""Build the scan record: what the scanner was asked to do, not just what it found.

This lives with the scan service because it is the only component that knows how a
scan was invoked. Everything downstream (assembly, the API, the console) consumes
the record; nothing else should be constructing one.
"""

from __future__ import annotations

from pathlib import Path

from aegis_contracts.domain import Finding, ScanRecord

# a scan is only "clean" when it succeeded AND we told it what to look for
SUCCESS_CODES = (0, 1)  # semgrep family: 1 means "findings present"


def build_scan_record(
    *,
    engine: str,
    engine_version: str,
    sarif_path: Path | None,
    command: list[str],
    configured: bool,
    stderr: str,
    findings: list[Finding],
    returncode: int = 0,
    failure_mode: str | None = None,
) -> ScanRecord:
    rule_counts: dict[str, int] = {}
    severity_counts: dict[str, int] = {}
    path_counts: dict[str, int] = {}
    for finding in findings:
        rule_counts[finding.rule_id] = rule_counts.get(finding.rule_id, 0) + 1
        severity_counts[finding.severity.value] = severity_counts.get(finding.severity.value, 0) + 1
        path_counts[finding.path] = path_counts.get(finding.path, 0) + 1
    top_paths = sorted(path_counts.items(), key=lambda kv: (-kv[1], kv[0]))[:10]

    suspicious = not findings and (
        failure_mode is not None or returncode not in SUCCESS_CODES or not configured
    )

    return ScanRecord(
        engine=engine,
        engine_version=engine_version,
        sarif_path=str(sarif_path) if sarif_path else None,
        command=command,
        returncode=returncode,
        configured=configured,
        zero_findings_is_suspicious=suspicious,
        failure_mode=failure_mode,
        stderr_tail=stderr,
        rule_counts=dict(sorted(rule_counts.items(), key=lambda kv: (-kv[1], kv[0]))),
        severity_counts=severity_counts,
        top_paths=top_paths,
    )
