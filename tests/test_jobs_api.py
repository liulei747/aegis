"""The job HTTP surface: submission, idempotency, cancellation, and honest failure codes.

The status codes here are a contract, not a style choice, and three pairs are easy to get
wrong in a way nobody notices until a caller misbehaves:

* **400 must come before 202.** A request that cannot possibly work is rejected now, not
  queued and failed after the caller has walked away.
* **202 versus 200 is "will change" versus "is the answer".** A duplicate of in-flight work
  attaches to it (202, `deduplicated=true`); a duplicate of finished work returns it (200).
* **A failure is not retried silently.** Same input, same answer -- so re-running a failed
  job needs `?force=true`, otherwise a deterministic failure becomes an infinite retry.

And the property that keeps this from being a breaking change: with no queue configured,
`POST /v1/assemble` is exactly what it was before -- asserted field by field.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_contracts.jobs import FailureMode, JobResult, JobStage, JobState
from aegis_core.config import QueueConfig, Settings, get_settings
from app.api import deps
from app.main import create_app
from services.queue.jobs import JobStore
from services.queue.keys import QueueKeys
from services.queue.streams import JobStream
from tests.fixtures import write_sarif


@pytest.fixture()
def queued_client(tmp_path: Path, monkeypatch, workspace: Path, fake_redis):
    """A gateway whose queue is backed by fakeredis.

    The client is injected rather than dialled so the tests need no server; everything above
    it -- settings, dependencies, routes -- is the real thing.
    """
    monkeypatch.setenv("AEGIS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(tmp_path / "packages"))
    monkeypatch.setenv("AEGIS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AEGIS_LSP_ENABLED", "false")
    monkeypatch.setenv("AEGIS_QUEUE__REDIS_URL", "redis://localhost:6379/0")
    get_settings.cache_clear()
    deps.set_queue_client(fake_redis)

    settings = get_settings()
    keys = QueueKeys(settings.queue.stream, settings.queue.group)
    store = JobStore(fake_redis, settings.queue, keys=keys)
    stream = JobStream(fake_redis, settings.queue, keys=keys)
    stream.ensure_group()

    app = create_app()
    with TestClient(app) as client:
        client.queue = (store, stream, tmp_path, workspace)  # type: ignore[attr-defined]
        yield client

    deps.set_queue_client(None)
    get_settings.cache_clear()


def _body(workspace: Path, **overrides) -> dict:
    body = {"workspace": str(workspace), "lsp": False}
    body.update(overrides)
    return body


def _store_stream(client) -> tuple[JobStore, JobStream]:
    store, stream, _, _ = client.queue  # type: ignore[attr-defined]
    return store, stream


def test_assemble_through_the_queued_path_answers_202(queued_client, workspace: Path) -> None:
    """`/v1/assemble` must behave like `/v1/jobs` once a queue is configured.

    The route declares `response_model=AssembleResponse`, which describes the *synchronous*
    answer, while the queued path returns a `JobAcceptedResponse` from `submit()`. Measured, that
    mismatch made FastAPI answer 500 with a `ResponseValidationError` -- and nothing caught it,
    because every queued test posts to `/v1/jobs` instead. The same shape broke the AI route the
    first time it ran for real.
    """
    response = queued_client.post(
        "/v1/assemble", json={"workspace": str(workspace), "lsp": False}
    )

    assert response.status_code == 202, response.text
    assert response.json()["job_id"].startswith("J-")


def test_submitting_a_job_returns_202_and_a_queued_job(queued_client, workspace: Path) -> None:
    response = queued_client.post("/v1/jobs", json=_body(workspace))
    assert response.status_code == 202, response.text
    body = response.json()
    assert body["state"] == JobState.QUEUED.value
    assert body["deduplicated"] is False
    assert response.headers["location"] == f"/v1/jobs/{body['job_id']}"

    store, stream = _store_stream(queued_client)
    job = store.get(body["job_id"])
    assert job is not None
    assert job.state is JobState.QUEUED
    assert stream.was_enqueued_recently(job.job_id), "an accepted job must be claimable"


def test_the_same_request_twice_attaches_instead_of_duplicating(queued_client, workspace: Path) -> None:
    """Idempotency, and the caller can see it happened: `deduplicated: true`."""
    first = queued_client.post("/v1/jobs", json=_body(workspace))
    second = queued_client.post("/v1/jobs", json=_body(workspace))

    assert first.status_code == 202 and second.status_code == 202
    assert first.json()["job_id"] == second.json()["job_id"]
    assert first.json()["deduplicated"] is False
    assert second.json()["deduplicated"] is True

    _, stream = _store_stream(queued_client)
    assert stream.stream_length() == 1, "one request, one queue entry"


def test_invalid_requests_are_rejected_before_enqueueing(queued_client, tmp_path: Path) -> None:
    """400 now, not a job id and a failure later."""
    _, stream = _store_stream(queued_client)

    missing_workspace = queued_client.post("/v1/jobs", json=_body(tmp_path / "nope"))
    assert missing_workspace.status_code == 400

    missing_sarif = queued_client.post(
        "/v1/jobs", json=_body(tmp_path, sarif_path=str(tmp_path / "nope.sarif"))
    )
    assert missing_sarif.status_code == 400

    assert stream.stream_length() == 0, "a doomed request must not occupy the queue"


def test_duplicate_after_success_returns_200_with_the_result(queued_client, workspace: Path) -> None:
    """202 means "will change"; 200 means "this is the answer"."""
    store, _ = _store_stream(queued_client)
    accepted = queued_client.post("/v1/jobs", json=_body(workspace)).json()
    job_id = accepted["job_id"]

    store.set_running(job_id, worker_id="w-1")
    bundle = workspace.parent / "packages" / "B-done"
    bundle.mkdir(parents=True, exist_ok=True)
    (bundle / "manifest.json").write_text("{}", encoding="utf-8")
    store.mark_succeeded(job_id, result=JobResult(bundle_id="B-done", package_path=str(bundle)))

    again = queued_client.post("/v1/jobs", json=_body(workspace))
    assert again.status_code == 200, again.text
    assert again.json()["job_id"] == job_id
    assert again.json()["result"]["bundle_id"] == "B-done"


def test_duplicate_after_failure_is_409_and_force_retries(queued_client, workspace: Path) -> None:
    """No silent retry: the refusal names the failure, and `?force=true` is the override."""
    store, stream = _store_stream(queued_client)
    accepted = queued_client.post("/v1/jobs", json=_body(workspace)).json()
    job_id = accepted["job_id"]
    store.set_running(job_id, worker_id="w-1")
    store.mark_failed(job_id, mode=FailureMode.SCAN_FAILED, message="scanner exited with rc=2")

    refused = queued_client.post("/v1/jobs", json=_body(workspace))
    assert refused.status_code == 409
    detail = refused.json()["detail"]
    assert "rc=2" in detail["detail"]
    assert detail["failure"]["mode"] == "scan_failed"

    before = stream.stream_length()
    forced = queued_client.post("/v1/jobs?force=true", json=_body(workspace))
    assert forced.status_code == 202, forced.text
    assert forced.json()["job_id"] == job_id, "the same input keeps the same id"
    assert forced.json()["deduplicated"] is False
    assert stream.stream_length() == before + 1

    retried = store.get(job_id)
    assert retried is not None
    assert retried.state is JobState.QUEUED
    assert retried.failure is None
    assert retried.progress.attempt == 2, "the attempt counter is what bounds retries"


def test_get_job_returns_the_whole_record_including_failure(queued_client, workspace: Path) -> None:
    store, _ = _store_stream(queued_client)
    accepted = queued_client.post("/v1/jobs", json=_body(workspace)).json()
    job_id = accepted["job_id"]
    store.set_running(job_id, worker_id="w-1")
    store.record_stage(job_id, JobStage.SCAN, state="done", duration_ms=12, counters={"discovered": 3})
    store.mark_failed(job_id, mode=FailureMode.PIPELINE_EXCEPTION, message="boom")

    response = queued_client.get(f"/v1/jobs/{job_id}")
    assert response.status_code == 200, "a terminal state is a normal answer"
    body = response.json()
    assert body["state"] == "failed"
    assert body["failure"]["mode"] == "pipeline_exception"
    stages = {entry["stage"]: entry for entry in body["progress"]["stages"]}
    assert stages["scan"]["duration_ms"] == 12
    assert body["progress"]["counters"]["discovered"] == 3


def test_get_job_is_404_when_unknown(queued_client) -> None:
    response = queued_client.get("/v1/jobs/J-does-not-exist")
    assert response.status_code == 404
    assert "已过期" in response.json()["detail"]


def test_the_job_list_is_the_first_screen_payload(queued_client, workspace: Path) -> None:
    """Summaries, newest first, plus the queue's own health in the same response."""
    store, _ = _store_stream(queued_client)
    for index in range(3):
        queued_client.post("/v1/jobs", json=_body(workspace, rule_config=f"p/{index}"))

    response = queued_client.get("/v1/jobs")
    assert response.status_code == 200
    body = response.json()
    assert body["total"] == 3
    assert len(body["jobs"]) == 3
    assert "queue" in body

    # The list view trades detail for size; that is the point of JobSummary.
    summary = body["jobs"][0]
    assert "stages" not in summary["progress"] if "progress" in summary else True
    assert "job_id" in summary and "state" in summary and "submitted_at" in summary
    # Which repository each row is about, published so the table needs no second request per job.
    assert summary["workspace"] == str(workspace)
    assert "queue" in body and "stream_length" in body["queue"]

    filtered = queued_client.get("/v1/jobs?state=running").json()
    assert filtered["total"] == 0


def test_cancelling_a_queued_job_finishes_it_immediately(queued_client, workspace: Path) -> None:
    """Nobody is holding it, so there is nothing to interrupt."""
    store, _ = _store_stream(queued_client)
    job_id = queued_client.post("/v1/jobs", json=_body(workspace)).json()["job_id"]

    response = queued_client.post(f"/v1/jobs/{job_id}/cancel")
    assert response.status_code == 202
    assert response.json()["state"] == "canceled"
    assert store.get(job_id).state is JobState.CANCELED  # type: ignore[union-attr]


def test_cancelling_a_running_job_only_records_the_intent(queued_client, workspace: Path) -> None:
    """The gateway has no handles and must not pretend otherwise."""
    store, _ = _store_stream(queued_client)
    job_id = queued_client.post("/v1/jobs", json=_body(workspace)).json()["job_id"]
    store.set_running(job_id, worker_id="w-1")

    response = queued_client.post(f"/v1/jobs/{job_id}/cancel")
    assert response.status_code == 202
    body = response.json()
    assert body["state"] == "running", "accepted, not performed"
    assert body["cancel_requested"] is True

    job = store.get(job_id)
    assert job is not None
    assert job.state is JobState.RUNNING
    assert job.cancel_requested is True, "the worker polls this flag"


def _finished_job(queued_client, workspace: Path, *, bundle_id: str = "B-done"):
    """Submit a job and mark it succeeded with output that is really on disk.

    The output matters: `_artifact_available` re-runs a succeeded job whose bundle is gone, so a
    fake path would exercise *that* branch and say nothing about `force`.
    """
    accepted = queued_client.post("/v1/jobs", json=_body(workspace)).json()
    store, _stream = _store_stream(queued_client)
    from aegis_core.config import get_settings

    package = get_settings().output_dir / bundle_id
    package.mkdir(parents=True, exist_ok=True)
    (package / "manifest.json").write_text("{}", encoding="utf-8")
    store.mark_succeeded(
        accepted["job_id"], result=JobResult(bundle_id=bundle_id, package_path=str(package))
    )
    return accepted, store


def test_force_re_runs_a_succeeded_job(queued_client, workspace: Path) -> None:
    """`force` has to reach a finished job, or the same request can never be run twice.

    The fingerprint does not change, so neither does the job id: without this, a request whose
    result is useless -- an AI answer thrown away by a parser bug, say -- is returned forever.
    Measured on the live stack before the fix: `?force=true` answered 200 with the stored job.
    """
    accepted, store = _finished_job(queued_client, workspace)

    again = queued_client.post("/v1/jobs?force=true", json=_body(workspace))

    assert again.status_code == 202, again.text
    body = again.json()
    assert body["job_id"] == accepted["job_id"], "a re-run keeps the id: it comes from the fingerprint"
    assert body["deduplicated"] is False
    assert body["revision"] > accepted["revision"]
    assert store.get(accepted["job_id"]).state is JobState.QUEUED


def test_without_force_a_succeeded_job_is_still_the_answer(queued_client, workspace: Path) -> None:
    """The ordinary duplicate case must not change: the same request is the same answer."""
    accepted, _store = _finished_job(queued_client, workspace)

    again = queued_client.post("/v1/jobs", json=_body(workspace))

    assert again.status_code == 200, again.text
    assert again.json()["state"] == JobState.SUCCEEDED.value


def test_cancelling_a_finished_job_is_409_and_changes_nothing(queued_client, workspace: Path) -> None:
    store, _ = _store_stream(queued_client)
    job_id = queued_client.post("/v1/jobs", json=_body(workspace)).json()["job_id"]
    store.set_running(job_id, worker_id="w-1")
    store.mark_succeeded(job_id, result=JobResult(bundle_id="B-1"))

    response = queued_client.post(f"/v1/jobs/{job_id}/cancel")
    assert response.status_code == 409
    assert "succeeded" in response.json()["detail"]["detail"]
    job = store.get(job_id)
    assert job is not None
    assert job.cancel_requested is False, "history is not rewritten"


def test_cancelling_twice_is_idempotent(queued_client, workspace: Path) -> None:
    store, _ = _store_stream(queued_client)
    job_id = queued_client.post("/v1/jobs", json=_body(workspace)).json()["job_id"]
    store.set_running(job_id, worker_id="w-1")

    first = queued_client.post(f"/v1/jobs/{job_id}/cancel")
    store.mark_canceled(job_id)
    second = queued_client.post(f"/v1/jobs/{job_id}/cancel")

    assert first.status_code == 202
    assert second.status_code == 200, "asking twice is not an error"
    assert second.json()["state"] == "canceled"


def test_a_broken_queue_is_503_not_500(queued_client, workspace: Path) -> None:
    """The request was fine; a dependency is down. That is a 503 and a retryable signal.

    Injected at the Redis client rather than at the store, because the route builds its own
    store per request through a dependency -- patching a store instance would test nothing.
    """

    broken = _FailingClient(deps.get_queue_client())
    deps.set_queue_client(broken)

    response = queued_client.post("/v1/jobs", json=_body(workspace))
    assert response.status_code == 503
    assert "队列不可用" in response.json()["detail"]


class _FailingClient:
    """Delegates to a real client but fails on read, like an unreachable Redis."""

    def __init__(self, inner) -> None:
        self._inner = inner

    def __getattr__(self, name):
        if name not in {"get", "exists"}:
            return getattr(self._inner, name)

        import redis

        def fail(*args, **kwargs):
            raise redis.ConnectionError("connection refused")

        return fail


def test_scan_jobs_get_their_own_asynchronous_route(queued_client, workspace: Path) -> None:
    """A new path, not a change to `/v1/scan`: that response has existing consumers."""
    response = queued_client.post("/v1/scan/jobs", json=_body(workspace))
    assert response.status_code == 202, response.text
    store, _ = _store_stream(queued_client)
    job = store.get(response.json()["job_id"])
    assert job is not None
    assert job.kind.value == "scan"


def test_bundle_listing_skips_staging_directories(queued_client, tmp_path: Path) -> None:
    """A bundle being written must not be offered as a finished one."""
    from aegis_core.config import get_settings as current

    output = current().output_dir
    staging = output / ".staging-B-halfwritten"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.json").write_text("{}", encoding="utf-8")
    real = output / "B-finished"
    real.mkdir(parents=True, exist_ok=True)

    body = queued_client.get("/v1/bundles").json()
    names = [entry["bundle_id"] for entry in body["bundles"]]
    assert ".staging-B-halfwritten" not in names
    assert "B-finished" in names


# --- the synchronous path must not drift ---------------------------------


@pytest.fixture()
def sync_client(tmp_path: Path, monkeypatch, workspace: Path):
    """The gateway with no queue configured: today's behaviour, unchanged."""
    monkeypatch.setenv("AEGIS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(tmp_path / "packages"))
    monkeypatch.setenv("AEGIS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AEGIS_LSP_ENABLED", "false")
    monkeypatch.delenv("AEGIS_QUEUE__REDIS_URL", raising=False)
    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as client:
        yield client
    get_settings.cache_clear()


def test_without_a_queue_the_old_synchronous_path_is_used(
    sync_client: TestClient, tmp_path: Path, workspace: Path
) -> None:
    """Field-by-field, because this is the contract existing callers depend on.

    If queue-first had changed this response, every consumer of `/v1/assemble` would have
    broken silently -- and the CLI, the scripts and the Docker smoke test all use it.
    """
    sarif = write_sarif(tmp_path / "scan.sarif", workspace=workspace)
    response = sync_client.post(
        "/v1/assemble",
        json={"workspace": str(workspace), "sarif_path": str(sarif), "lsp": False},
    )
    assert response.status_code == 200, response.text
    body = response.json()
    assert set(body) == {"bundle_id", "run_id", "package_path", "manifest", "warnings"}
    assert body["bundle_id"].startswith("B-")
    assert body["run_id"].startswith("R-")
    assert body["manifest"]["coverage"]["discoverable"] == 1
    assert Path(body["package_path"]).is_dir()


def test_the_job_routes_explain_themselves_when_no_queue_is_configured(
    sync_client: TestClient, workspace: Path
) -> None:
    """503 with a reason, not a 500 or an empty list that looks like "no jobs"."""
    response = sync_client.get("/v1/jobs")
    assert response.status_code == 503
    assert "未配置 Redis" in response.json()["detail"]


def test_the_api_is_still_headless(sync_client: TestClient) -> None:
    """Adding routes must not resurrect a console or break the OpenAPI document."""
    assert sync_client.get("/").status_code == 404
    assert sync_client.get("/openapi.json").status_code == 200
    paths = sync_client.get("/openapi.json").json()["paths"]
    for path in ("/v1/jobs", "/v1/jobs/{job_id}", "/v1/jobs/{job_id}/cancel", "/v1/assemble"):
        assert path in paths, f"{path} is missing from the route table"


def test_queue_settings_reach_the_gateway(monkeypatch, tmp_path: Path) -> None:
    """The switch is configuration, not code: setting the URL enables the queue."""
    monkeypatch.setenv("AEGIS_WORKSPACE_ROOT", str(tmp_path))
    monkeypatch.setenv("AEGIS_QUEUE__REDIS_URL", "redis://example:6379/1")
    monkeypatch.setenv("AEGIS_QUEUE__MAX_ATTEMPTS", "4")
    get_settings.cache_clear()
    settings = Settings()
    assert settings.queue.redis_url == "redis://example:6379/1"
    assert settings.queue.max_attempts == 4
    assert isinstance(settings.queue, QueueConfig)
    get_settings.cache_clear()
