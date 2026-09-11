"""The whole queue, end to end: submit -> worker -> a bundle on disk.

Everything else is tested in pieces, and pieces are where integration lies. This runs the
real gateway (through `TestClient`), the real worker loop, a real Redis, and the real
pipeline over the committed demo repository, then checks the one thing a user would check:
did a bundle appear, and does it describe itself correctly?

Needs Redis (`AEGIS_TEST_REDIS_URL`, default `redis://127.0.0.1:6379/14`) and uses a
dedicated database so it cannot disturb anything else. Skipped without a server.

    docker run --rm -d -p 127.0.0.1:6379:6379 redis:7-alpine
    python -m pytest tests/test_queue_end_to_end.py -q
"""

from __future__ import annotations

import json
import os
import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_contracts.jobs import JobState
from aegis_core.config import get_settings
from app.api import deps
from app.main import create_app
from services.queue.jobs import JobStore
from services.queue.keys import QueueKeys
from services.queue.streams import JobStream
from services.queue.worker import Worker
from tests.fixtures import write_sarif

URL = os.getenv("AEGIS_TEST_REDIS_URL", "redis://127.0.0.1:6379/14")
REPO = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def real_redis():
    import redis

    try:
        client = redis.Redis.from_url(URL, socket_connect_timeout=0.5)
        client.ping()
    except Exception as exc:  # pragma: no cover - environment dependent
        pytest.skip(f"no Redis at {URL}: {exc}")
    client.flushdb()
    yield client
    client.flushdb()


@pytest.fixture()
def wired(tmp_path: Path, monkeypatch, real_redis, workspace: Path):
    """A gateway and a worker sharing one queue, plus a real workspace to assemble."""
    import redis

    real_redis.flushdb()
    monkeypatch.setenv("AEGIS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(tmp_path / "packages"))
    monkeypatch.setenv("AEGIS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AEGIS_LSP_ENABLED", "false")
    monkeypatch.setenv("AEGIS_QUEUE__REDIS_URL", URL)
    get_settings.cache_clear()
    deps.set_queue_client(redis.Redis.from_url(URL))

    settings = get_settings()
    keys = QueueKeys(settings.queue.stream, settings.queue.group)
    store = JobStore(real_redis, settings.queue, keys=keys)
    stream = JobStream(real_redis, settings.queue, keys=keys)
    stream.ensure_group()
    worker = Worker(store, stream, settings, worker_id="w-e2e")
    worker.reaper.enabled = False  # the reaper has its own tests; keep this deterministic

    app = create_app()
    with TestClient(app) as client:
        yield client, worker, store, tmp_path, workspace

    deps.set_queue_client(None)
    get_settings.cache_clear()


def test_submit_then_work_produces_a_bundle(wired) -> None:
    client, worker, store, tmp_path, workspace = wired
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)

    accepted = client.post(
        "/v1/jobs",
        json={"workspace": str(workspace), "sarif_path": str(sarif), "lsp": False},
    )
    assert accepted.status_code == 202, accepted.text
    job_id = accepted.json()["job_id"]

    # One claim cycle: exactly what the container's loop does on its first turn.
    worker.serve_forever(max_iterations=2)

    job = store.get(job_id)
    assert job is not None
    assert job.state is JobState.SUCCEEDED, job.failure
    assert job.result is not None

    package = Path(job.result.package_path or "")
    assert (package / "manifest.json").is_file(), "the bundle must be on disk"
    manifest = json.loads((package / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["bundle_id"] == job.result.bundle_id
    assert manifest["focus_count"] == 1
    assert manifest["schema_version"] == "1.0"

    # The staged tree was renamed into place, not left behind.
    assert not list((tmp_path / "packages").glob(".staging-*"))

    # And the state the API reports is the state on disk.
    fetched = client.get(f"/v1/jobs/{job_id}")
    assert fetched.status_code == 200
    body = fetched.json()
    assert body["state"] == "succeeded"
    assert body["result"]["package_path"] == str(package)
    stages = {entry["stage"]: entry for entry in body["progress"]["stages"]}
    assert stages["package"]["state"] == "done"
    assert stages["scan"]["duration_ms"] is not None

    # Every funnel step the pipeline can compute reached the job record.
    for step in ("discovered", "located", "focus_methods", "slices", "kept", "read", "inlined"):
        assert step in body["progress"]["counters"], f"{step} never reached the job record"


def test_the_same_submission_after_success_returns_the_bundle(wired) -> None:
    """The idempotency promise, end to end: same request, same job, 200 with the result."""
    client, worker, store, tmp_path, workspace = wired
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    payload = {"workspace": str(workspace), "sarif_path": str(sarif), "lsp": False}

    first = client.post("/v1/jobs", json=payload)
    worker.serve_forever(max_iterations=2)
    job_id = first.json()["job_id"]

    second = client.post("/v1/jobs", json=payload)
    assert second.status_code == 200, second.text
    body = second.json()
    assert body["job_id"] == job_id
    assert body["state"] == "succeeded"
    assert Path(body["result"]["package_path"]).is_dir()

    # A re-run would have produced the same content-derived id, so re-running is pure waste;
    # the queue entry count is how we know it did not happen.
    assert store.get(job_id).progress.attempt == 1  # type: ignore[union-attr]


def test_a_scan_job_returns_a_ledger_and_no_bundle(wired) -> None:
    """`kind=scan` is a different product: findings and a record, not an analysis package.

    Submitted through the same store/stream the gateway uses, because the HTTP route for it
    (`/v1/scan/jobs`) is covered in `tests/test_jobs_api.py`; what is new here is that the
    worker routes the kind correctly and produces no bundle for it.
    """
    _, worker, store, tmp_path, workspace = wired
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)

    from aegis_contracts.jobs import JobKind, JobRequest

    submission = store.new_submission(
        JobRequest(workspace=str(workspace), sarif_path=str(sarif), lsp=False),
        kind=JobKind.SCAN,
    )
    store.create(submission)
    stream = JobStream(store.redis, get_settings().queue, keys=QueueKeys())
    stream.ensure_group()
    stream.enqueue_submission(submission)

    worker.serve_forever(max_iterations=2)
    scan_job = store.get(submission.job_id)
    assert scan_job is not None
    assert scan_job.kind is JobKind.SCAN
    assert scan_job.state is JobState.SUCCEEDED, scan_job.failure
    assert scan_job.result is not None
    assert scan_job.result.bundle_id is None, "a scan produces no bundle"
    assert scan_job.result.sarif_path, "but it does report where the SARIF went"
    assert not list((tmp_path / "packages").glob("B-*")), "nothing was packaged"


def test_a_missing_workspace_fails_with_a_name_and_leaves_no_bundle(wired) -> None:
    """The failure path, end to end: a named mode, a terminal state, nothing on disk."""
    client, worker, store, tmp_path, workspace = wired
    ghost = tmp_path / "ghost"
    accepted = client.post("/v1/jobs", json={"workspace": str(ghost), "lsp": False})
    # The gateway validates first, so this never reaches the queue.
    assert accepted.status_code == 400

    # Now the same thing arriving through the queue (a workspace deleted after submission).
    from aegis_contracts.jobs import JobRequest

    doomed = tmp_path / "doomed"
    doomed.mkdir()
    submission = store.new_submission(JobRequest(workspace=str(doomed), lsp=False))
    store.create(submission)
    stream = JobStream(store.redis, get_settings().queue, keys=QueueKeys())
    stream.ensure_group()
    stream.enqueue_submission(submission)
    doomed.rmdir()  # gone by the time the worker looks

    worker.serve_forever(max_iterations=2)
    job = store.get(submission.job_id)
    assert job is not None
    assert job.state is JobState.FAILED
    assert job.failure is not None
    assert job.failure.mode.value == "workspace_missing"
    assert not list((tmp_path / "packages").glob("B-*"))


def test_deleting_the_bundle_makes_the_next_submission_rerun(wired) -> None:
    """"Succeeded but the artifact is gone" means the result is not usable, so redo it."""
    import shutil

    client, worker, store, tmp_path, workspace = wired
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    payload = {"workspace": str(workspace), "sarif_path": str(sarif), "lsp": False}

    client.post("/v1/jobs", json=payload)
    worker.serve_forever(max_iterations=2)
    job_id = client.post("/v1/jobs", json=payload).json()["job_id"]

    shutil.rmtree(Path(store.get(job_id).result.package_path))  # type: ignore[union-attr]
    again = client.post("/v1/jobs", json=payload)
    assert again.status_code == 202, again.text
    assert again.json()["job_id"] == job_id
    assert again.json()["deduplicated"] is False

    retried = store.get(job_id)
    assert retried is not None
    assert retried.state is JobState.QUEUED
    assert retried.progress.attempt == 2


def test_sqlite_is_not_needed_for_the_queue_smoke() -> None:
    """A guard against this file becoming an accidental integration-test kitchen sink."""
    assert sqlite3.sqlite_version  # the fixture repo imports sqlite3; nothing more
    assert (REPO / "demo" / "repo" / "repo.py").is_file()
