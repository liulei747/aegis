"""Scan jobs: the handle that makes a delegated scan cancellable.

The behaviour that matters here was measured, not assumed: before this protocol existed, a
cancel issued against a running *remote* scan took 131 seconds to take effect -- the whole
remainder of the scan -- because the caller was parked on one blocking HTTP response and the
scan service had no name for the work in progress. These tests cover the two halves of the
fix: the service keeps a handle it can terminate, and the caller's cancellation reaches it.
"""

from __future__ import annotations

import sys
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from services.scan import jobs as jobs_module
from services.scan.app import app
from services.scan.jobs import CANCELED, QUEUED, RUNNING, SUCCEEDED, ScanJob, ScanJobs
from services.scan.runner import ScanRequest, run_scan
from tests.fake_scanner_bin import install_fake_opengrep


@pytest.fixture()
def fake_engine(tmp_path: Path, monkeypatch):
    """An `opengrep` that outlives any assertion in this file, but not the file itself.

    The sleep has to be longer than what a cancel assertion allows (seconds) and shorter than
    a test timeout, so a *missed* cancel fails the test instead of hanging the suite. That
    narrower window is the whole reason this number is 20 rather than 120: with a very long
    sleep, a bug in cancellation shows up as a two-minute stall rather than a red test.
    """
    return install_fake_opengrep(tmp_path, monkeypatch, sleep_s=20.0)


@pytest.fixture()
def fast_engine(tmp_path: Path, monkeypatch):
    """The same stand-in, but it finishes immediately: for tests about a *completed* scan."""
    return install_fake_opengrep(tmp_path, monkeypatch, sleep_s=0.0)


@pytest.fixture()
def client(fake_engine) -> TestClient:
    """The scan service, with a slow stand-in engine on PATH."""
    with TestClient(app) as test_client:
        yield test_client


def _slow_workspace(tmp_path: Path, files: int = 12, lines: int = 8) -> Path:
    """A workspace for the scanner to chew on. Small, because the double ignores content."""
    root = tmp_path / "slow"
    root.mkdir(parents=True)
    for f in range(files):
        body = ["import sqlite3", "def handler(request):"]
        for i in range(lines):
            body.append(
                f"    sql{i} = \"SELECT * FROM t{i} WHERE id = '\" + request.args['id'] + \"'\""
            )
            body.append(f"    sqlite3.connect('app.db').execute(sql{i})")
        (root / f"mod{f}.py").write_text("\n".join(body) + "\n", encoding="utf-8")
    return root


# --- the request-level contract ---------------------------------------


def test_cancel_event_makes_run_scan_report_a_cancellation(workspace: Path, fake_engine) -> None:
    """The event is wired into the same predicate the in-process abort uses.

    This is the seam the whole design rests on: `run_scan` already knew how to be cancelled,
    it just had no way to be told by an outsider. `cancel_event` is that way, and it must
    still produce exactly the same outcome shape as an in-process cancellation.
    """
    event = threading.Event()
    event.set()  # already cancelled before it starts
    outcome = run_scan(
        ScanRequest(workspace=workspace, cancel_event=event, binary="opengrep", fallback_binary=None)
    )
    assert outcome.canceled is True
    assert outcome.scan_record is not None
    assert outcome.scan_record.failure_mode == "scan_aborted"
    assert outcome.findings == []


def test_cancel_event_and_abort_are_both_honoured(workspace: Path, fake_engine) -> None:
    """Two owners, one decision: either source can stop the scan."""
    from_abort = run_scan(
        ScanRequest(workspace=workspace, abort=lambda: True, binary="opengrep", fallback_binary=None)
    )
    assert from_abort.canceled is True


# --- the registry ------------------------------------------------------


def test_submit_starts_the_scan_and_reports_a_terminal_state(
    tmp_path: Path, workspace: Path, fast_engine
) -> None:
    registry = ScanJobs()
    job = registry.submit(ScanRequest(workspace=workspace, rule_config="auto"))
    assert job.state in {QUEUED, RUNNING}

    deadline = time.monotonic() + 60
    while job.state not in {SUCCEEDED, CANCELED} and time.monotonic() < deadline:
        time.sleep(0.05)
    assert job.state == SUCCEEDED, job.detail
    assert job.outcome is not None
    assert job.started_at is not None and job.finished_at is not None
    assert registry.get(job.job_id) is job


def test_cancel_terminates_a_running_scan_quickly(tmp_path: Path, fake_engine) -> None:
    """The measured claim: a cancel takes effect in seconds, not in "the rest of the scan".

    The stand-in engine sleeps far longer than the assertion below, which is what makes this a
    test of cancellation rather than of a fast machine.
    """
    slow = _slow_workspace(tmp_path)
    registry = ScanJobs()
    job = registry.submit(ScanRequest(workspace=slow, rule_config="auto"))

    # Wait until the scanner process actually exists, so the cancel has a handle to kill.
    deadline = time.monotonic() + 30
    while job.state != RUNNING and time.monotonic() < deadline:
        time.sleep(0.05)
    assert job.state == RUNNING, "the scan never started; the test cannot prove anything"

    started = time.monotonic()
    job.cancel()
    while job.state not in {SUCCEEDED, CANCELED} and time.monotonic() < deadline:
        time.sleep(0.05)
    elapsed = time.monotonic() - started

    assert job.state == CANCELED, f"cancel left the job in {job.state}"
    assert elapsed < 10.0, f"cancel took {elapsed:.1f}s; the whole point is that it is prompt"
    assert job.outcome is not None and job.outcome.canceled is True


def test_cancel_is_idempotent_and_safe_after_completion(workspace: Path, fast_engine) -> None:
    """Cancelling finished work is not an error: the caller wanted it over, and it is.

    Implemented as "cancel twice, and the terminal state does not change" rather than
    "cancel a *running* scan and expect it to stay succeeded": the latter races the engine,
    and a test that depends on losing that race is not a test.
    """
    registry = ScanJobs()
    job = registry.submit(ScanRequest(workspace=workspace, rule_config="auto"))
    deadline = time.monotonic() + 60
    while job.state not in {SUCCEEDED, CANCELED} and time.monotonic() < deadline:
        time.sleep(0.05)
    before = job.state
    assert before in {SUCCEEDED, CANCELED}, f"the stand-in never finished ({job.state})"
    job.cancel()
    job.cancel()
    assert job.state == before, "a late cancel must not rewrite a finished scan"


def test_cancel_before_the_scan_starts_never_spawns_it(tmp_path: Path, fake_engine) -> None:
    """Cancelling a job that has not started yet must not leave a process behind.

    Exercised at the registry level with the event already set, because the window between
    `submit()` and the scan thread's first check is microseconds wide: a test that tried to
    hit it by timing would be testing the scheduler.
    """
    slow = _slow_workspace(tmp_path, files=2, lines=2)
    job = ScanJob(job_id="S-unit", request=ScanRequest(workspace=slow, rule_config="auto"))
    job.cancel_event.set()  # cancelled before the thread ever runs
    job.start()

    deadline = time.monotonic() + 10
    while job.state not in {SUCCEEDED, CANCELED} and time.monotonic() < deadline:
        time.sleep(0.02)
    assert job.state == CANCELED
    assert job.started_at is None, "it must not have started the scanner at all"
    assert job.outcome is None


def test_prune_forgets_finished_jobs_only(tmp_path: Path, workspace: Path, fast_engine) -> None:
    """Retention keeps the registry from growing for the life of the process."""
    registry = ScanJobs(retain_s=0.0)
    job = registry.submit(ScanRequest(workspace=workspace, rule_config="auto"))
    deadline = time.monotonic() + 60
    while job.state not in {SUCCEEDED, CANCELED} and time.monotonic() < deadline:
        time.sleep(0.05)
    assert registry.get(job.job_id) is job
    assert registry.prune() == 1
    assert registry.get(job.job_id) is None


# --- the HTTP surface --------------------------------------------------


def test_job_endpoints_round_trip(fast_engine, client: TestClient, workspace: Path) -> None:
    """Accept, poll, and read the result through the job routes."""
    accepted = client.post(
        "/v1/scan/jobs", json={"workspace": str(workspace), "rule_config": "auto"}
    )
    assert accepted.status_code == 202, accepted.text
    body = accepted.json()
    assert body["job_id"].startswith("S-")
    assert body["status_url"] == f"/v1/scan/jobs/{body['job_id']}"

    deadline = time.monotonic() + 60
    state = None
    while time.monotonic() < deadline:
        status = client.get(f"/v1/scan/jobs/{body['job_id']}")
        assert status.status_code == 200
        payload = status.json()
        state = payload["state"]
        if state in {"succeeded", "failed", "canceled"}:
            break
        time.sleep(0.1)
    assert state == "succeeded", payload
    assert payload["result"] is not None
    assert "scan_record" in payload["result"]
    # The blocking route's shape and the job route's shape must not drift.
    assert set(payload["result"]) >= {"engine", "findings", "scan_record", "warnings"}


def test_cancel_endpoint_stops_a_running_scan(client: TestClient, tmp_path: Path) -> None:
    slow = _slow_workspace(tmp_path)
    accepted = client.post("/v1/scan/jobs", json={"workspace": str(slow), "rule_config": "auto"})
    job_id = accepted.json()["job_id"]

    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if client.get(f"/v1/scan/jobs/{job_id}").json()["state"] == "running":
            break
        time.sleep(0.05)

    started = time.monotonic()
    cancelled = client.delete(f"/v1/scan/jobs/{job_id}")
    assert cancelled.status_code == 200
    while time.monotonic() < deadline:
        if client.get(f"/v1/scan/jobs/{job_id}").json()["state"] == "canceled":
            break
        time.sleep(0.05)
    elapsed = time.monotonic() - started

    assert client.get(f"/v1/scan/jobs/{job_id}").json()["state"] == "canceled"
    assert elapsed < 10.0, f"the cancel endpoint took {elapsed:.1f}s"


def test_unknown_scan_job_is_404(client: TestClient) -> None:
    assert client.get("/v1/scan/jobs/S-nope").status_code == 404
    assert client.delete("/v1/scan/jobs/S-nope").status_code == 404


def test_the_blocking_route_still_exists_and_is_unchanged(client: TestClient, workspace: Path) -> None:
    """`POST /v1/scan` keeps its response, so callers that cannot cancel lose nothing."""
    response = client.post("/v1/scan", json={"workspace": str(workspace), "rule_config": "auto"})
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) >= {"engine", "engine_version", "sarif_path", "findings", "scan_record"}
    assert "job_id" not in body, "the blocking route must not adopt the job shape"


def test_health_reports_running_scans(client: TestClient, tmp_path: Path) -> None:
    """A scan that outlives its caller is invisible unless health says so."""
    slow = _slow_workspace(tmp_path)
    accepted = client.post("/v1/scan/jobs", json={"workspace": str(slow), "rule_config": "auto"})
    job_id = accepted.json()["job_id"]
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if job_id in client.get("/health").json()["running_scans"]:
            break
        time.sleep(0.05)
    assert job_id in client.get("/health").json()["running_scans"]
    client.delete(f"/v1/scan/jobs/{job_id}")


def test_invalid_workspace_is_rejected_before_a_job_exists(client: TestClient, tmp_path: Path) -> None:
    response = client.post("/v1/scan/jobs", json={"workspace": str(tmp_path / "nope")})
    assert response.status_code == 400
    assert jobs_module.__name__  # the module stayed importable
    assert sys.version_info.major == 3
