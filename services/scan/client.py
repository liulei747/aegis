"""How extraction talks to the scan capability.

Two transports, one contract:

* **in-process** (default) - calls `services.scan.runner` directly. Local
  development and the all-in-one image keep working with no queue, no extra
  container and no network failure modes.
* **over HTTP** - when `AEGIS_SCAN_SERVICE_URL` is set, scanning is delegated to
  the standalone scan service, so scanner work is scaled, restarted and
  crash-isolated independently of extraction.

The caller never learns which one it got. `ScanRequest` is a dataclass that
serialises cleanly, and both paths return the same `ScanOutcome`, which is what
keeps the two from drifting.
"""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from aegis_contracts.domain import Finding, ScanRecord
from aegis_core.logging import get_logger
from services.scan.runner import ScanOutcome, ScanRequest, run_scan

log = get_logger(__name__)

ENV_SCAN_SERVICE_URL = "AEGIS_SCAN_SERVICE_URL"


@dataclass
class ScanOutcomeWire:
    """What the HTTP service returns, minus the caller's concerns.

    Kept separate from `ScanOutcome` because a remote scan cannot hand back a
    Path in *our* filesystem; it hands back a path in *its* filesystem, which the
    caller must not assume is readable.
    """

    engine: str
    engine_version: str = ""
    sarif_path: str | None = None
    findings: list[Finding] | None = None
    scan_record: ScanRecord | None = None
    warnings: list[str] | None = None
    degraded: bool = False


def scan_service_url() -> str | None:
    url = os.getenv(ENV_SCAN_SERVICE_URL, "").strip()
    return url.rstrip("/") or None


def scanning_is_remote() -> bool:
    return scan_service_url() is not None


def run_scan_anywhere(request: ScanRequest) -> ScanOutcome:
    """Run a scan, in-process or over HTTP, whichever this deployment is set up for."""
    url = scan_service_url()
    if url is None:
        return run_scan(request)

    payload = {
        "workspace": str(request.workspace),
        "rules": list(request.rules),
        "rule_config": request.rule_config,
        "include_globs": list(request.include_globs),
        "exclude_globs": list(request.exclude_globs),
        "out_dir": str(request.out_dir) if request.out_dir else None,
    }
    log.info("delegating scan to %s", url)
    try:
        import httpx

        response = httpx.post(f"{url}/v1/scan", json=payload, timeout=request.timeout_s)
        response.raise_for_status()
        body = response.json()
    except Exception as exc:
        # A remote failure must degrade exactly like a local one: the run continues
        # and the bundle records that scanning did not happen.
        reason = f"scan service at {url} failed: {exc}"
        log.error(reason)
        return ScanOutcome(
            engine="scan-service",
            findings=[],
            warnings=[reason],
            degraded=True,
            scan_record=ScanRecord(
                engine="scan-service",
                returncode=-1,
                configured=bool(request.rule_config or request.rules),
                zero_findings_is_suspicious=True,
                failure_mode=reason,
                stderr_tail=str(exc),
            ),
        )

    record = ScanRecord.model_validate(body["scan_record"])
    # Say where the scan ran. The argv and SARIF path in the record are real, but
    # they name paths inside *the scan service's* filesystem: a reader must not try
    # to open them from here.
    record.location = "remote"
    return ScanOutcome(
        engine=body.get("engine", "scan-service"),
        engine_version=body.get("engine_version", ""),
        sarif_path=Path(body["sarif_path"]) if body.get("sarif_path") else None,
        findings=[Finding.model_validate(f) for f in body.get("findings", [])],
        scan_record=record,
        warnings=list(body.get("warnings", [])),
        degraded=bool(body.get("degraded", False)),
    )


def local_sarif_readable(outcome: ScanOutcome) -> bool:
    """Is the SARIF path in this outcome something *we* can read?

    False for a remote scan: the file exists, just not in this container. The
    packaging step uses this to decide whether it can attach the raw SARIF for audit.
    """
    if outcome.scan_record is not None and outcome.scan_record.location == "remote":
        return False
    return outcome.sarif_path is not None and outcome.sarif_path.exists()
