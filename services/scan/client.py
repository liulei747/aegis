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
#: How often the remote-scan poll asks for progress, in milliseconds. This is also the
#: cancel latency ceiling for a delegated scan, so it trades responsiveness against the
#: number of small requests a long scan makes.
ENV_SCAN_JOB_POLL_MS = "AEGIS_SCAN_JOB_POLL_MS"


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
    return _run_scan_remotely(url, request)


def _run_scan_remotely(url: str, request: ScanRequest) -> ScanOutcome:
    """Delegate a scan through the job protocol, so it stays cancellable.

    Why not one blocking `POST /v1/scan`: while that call is in flight the caller cannot do
    anything at all. Measured in the container stack, a cancel issued mid-scan took **131
    seconds** to take effect -- the remainder of the scan -- because the worker was parked on
    the response and could not even see its own cancel request. Polling costs one small
    request per interval and buys back the caller's loop: it notices cancels, it keeps its
    heartbeat fresh, and it can tell the scan service to stop the work rather than merely
    walking away from it.

    `POST /v1/scan` is untouched for callers that want the simple shape.
    """
    import time

    import httpx

    payload = {
        "workspace": str(request.workspace),
        "rules": list(request.rules),
        "rule_config": request.rule_config,
        "include_globs": list(request.include_globs),
        "exclude_globs": list(request.exclude_globs),
        "out_dir": str(request.out_dir) if request.out_dir else None,
    }
    # Short per-request timeouts: the point of polling is that no single call can park us.
    # The overall budget is still the caller's `timeout_s`, enforced by the loop below.
    limits = httpx.Timeout(connect=10.0, read=30.0, write=10.0, pool=10.0)
    deadline = time.monotonic() + request.timeout_s

    try:
        with httpx.Client(timeout=limits) as client:
            accepted = client.post(f"{url}/v1/scan/jobs", json=payload)
            accepted.raise_for_status()
            job_id = accepted.json()["job_id"]
            log.info("delegating scan to %s as %s", url, job_id)

            while True:
                if request.cancel_event is not None and request.cancel_event.is_set():
                    return _cancel_remote(client, url, job_id)
                if request.abort is not None and request.abort():
                    return _cancel_remote(client, url, job_id)
                if time.monotonic() >= deadline:
                    _cancel_remote(client, url, job_id, reason="client deadline exceeded")
                    return _degraded_scan(
                        url, f"扫描服务未在 {request.timeout_s}s 内完成", request
                    )

                status = client.get(f"{url}/v1/scan/jobs/{job_id}")
                if status.status_code == 404:
                    # Expired after finishing: the result is gone, so ask for a fresh scan
                    # rather than reporting a phantom success.
                    return _degraded_scan(
                        url, f"扫描任务 {job_id} 在读取前已过期", request
                    )
                status.raise_for_status()
                body = status.json()
                state = body.get("state")
                if state == "canceled":
                    return _canceled_scan(url, job_id)
                if state in {"succeeded", "failed"}:
                    result = body.get("result")
                    if result is None:  # pragma: no cover - terminal implies a result
                        return _degraded_scan(
                            url, f"扫描任务 {job_id} 结束时没有结果", request
                        )
                    return _outcome_from_wire(url, result)
                time.sleep(_poll_interval())
    except Exception as exc:
        # A remote failure must degrade exactly like a local one: the run continues and the
        # bundle records that scanning did not happen.
        reason = f"扫描服务 {url} 失败：{exc}"
        log.error(reason)
        return _degraded_scan(url, reason, request)


def _poll_interval() -> float:
    raw = os.getenv(ENV_SCAN_JOB_POLL_MS, "").strip()
    try:
        return max(0.05, float(raw) / 1000.0) if raw else 0.25
    except ValueError:  # pragma: no cover - bad env value
        return 0.25


def _cancel_remote(client, url: str, job_id: str, *, reason: str = "cancel requested") -> ScanOutcome:
    """Tell the scan service to stop, then report a cancellation.

    The DELETE is what makes this a *real* cancel rather than walking away: it terminates the
    scanner process in the other container instead of leaving it to burn CPU until its own
    timeout. If the DELETE itself fails the outcome is the same -- we are not waiting any
    more -- but the caller learns the remote side may still be working.
    """
    try:
        client.delete(f"{url}/v1/scan/jobs/{job_id}")
        log.info("cancelled remote scan %s (%s)", job_id, reason)
    except Exception as exc:  # pragma: no cover - the cancel still takes effect locally
        log.warning("could not cancel remote scan %s: %s", job_id, exc)
    return _canceled_scan(f"{url} ({job_id})", job_id)


def _canceled_scan(engine: str, job_id: str) -> ScanOutcome:
    """A cancellation, in the same shape the in-process path produces."""
    return ScanOutcome(
        engine="scan-service",
        findings=[],
        warnings=["扫描已按请求终止"],
        degraded=True,
        canceled=True,
        scan_record=ScanRecord(
            engine="scan-service",
            returncode=-15,
            configured=True,
            zero_findings_is_suspicious=False,
            failure_mode="scan_aborted",
            stderr_tail=f"远程扫描 {job_id} 已取消",
            location="remote",
        ),
    )


def _degraded_scan(url: str, reason: str, request: ScanRequest) -> ScanOutcome:
    """A scan that did not happen, in the shape the rest of the pipeline expects.

    `configured` and `zero_findings_is_suspicious` are carried from the *request*, not
    assumed: a scan that was asked to run with no rules at all returning nothing is the
    suspicious case, and hardcoding this to True would hide exactly that. (It did, briefly,
    while this file was being rewritten -- the transport tests caught it.)
    """
    configured = bool(request.rule_config or request.rules)
    return ScanOutcome(
        engine="scan-service",
        findings=[],
        warnings=[reason],
        degraded=True,
        scan_record=ScanRecord(
            engine="scan-service",
            returncode=-1,
            configured=configured,
            zero_findings_is_suspicious=not configured,
            failure_mode=reason,
            stderr_tail=reason,
            location="remote",
        ),
    )


def _outcome_from_wire(url: str, body: dict) -> ScanOutcome:
    record = ScanRecord.model_validate(body["scan_record"])
    # Say where the scan ran. The argv and SARIF path in the record are real, but they name
    # paths inside *the scan service's* filesystem: a reader must not try to open them here.
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
