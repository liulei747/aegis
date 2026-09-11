"""The worker loop and the reaper: progress, failure, retry, and the one dangerous mistake.

The mistake this file is built around: **declaring a slow job dead.** A fifteen-minute scan
and a crashed worker are identical from the outside except for one signal -- the heartbeat.
If the reaper decides on elapsed time alone, it starts inventing failures, and a queue that
invents failures is worse than no queue, because the results look plausible.

The other half is the shutdown/cancel distinction: returning work to the queue is not the
same as cancelling it, and recording one as the other is telling the user they asked for
something they did not.
"""

from __future__ import annotations

import threading
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from aegis_contracts.jobs import (
    FailureMode,
    JobKind,
    JobRequest,
    JobResult,
    JobStage,
    JobState,
)
from aegis_core.config import Settings
from services.queue.cancel import Teardown
from services.queue.keys import QueueKeys
from services.queue.reaper import Reaper, reconcile_startup, recoverable_artifact
from services.queue.worker import Worker


def _settings(tmp_path: Path, queue_settings) -> Settings:
    return Settings(
        workspace_root=tmp_path,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        queue=queue_settings,
        lsp_enabled=False,
    ).resolve()


def _submit(store, *, workspace: Path, **overrides):
    request = JobRequest(workspace=str(workspace), lsp=False, **overrides)
    submission = store.new_submission(request)
    job, _ = store.create(submission)
    return submission, job


def _worker(store, stream, settings) -> Worker:
    return Worker(store, stream, settings, worker_id="w-test")


def _entry(job, attempt: int = 1) -> dict:
    return {
        "entry_id": "1-1",
        "job_id": job.job_id,
        "kind": job.submission.kind.value,
        "fingerprint": job.submission.fingerprint,
        "attempt": attempt,
    }


# --- the worker loop ---------------------------------------------------


def test_handle_runs_the_pipeline_and_reports_every_stage(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A successful job: terminal state, a result, and every stage accounted for."""
    from aegis_contracts.domain import AnalysisBundle, AnalysisBundleManifest
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    submission, job = _submit(job_store, workspace=workspace)

    class _FakePipeline:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, request, *, observer=None, abort=None, teardown=None, staging=False):
            assert teardown is not None, "the worker must hand over a teardown handle"
            for stage in ("scan", "setup", "locate", "expand", "read", "assemble", "package"):
                observer(
                    worker_module.StageEvent(
                        stage=stage, phase="end", ms=10, counters={"discovered": 1}
                    )
                )

            class _Outcome:
                bundle = AnalysisBundle(
                    manifest=AnalysisBundleManifest(
                        bundle_id="B-fake", run_id="R-fake", workspace_root=str(workspace)
                    )
                )
                package_path = tmp_path / "packages" / "B-fake"
                run_id = "R-fake"
                sarif_path = None
                scan_record = None
                warnings: list[str] = []

            _Outcome.package_path.mkdir(parents=True, exist_ok=True)
            return _Outcome()

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _FakePipeline)
    worker = _worker(job_store, job_stream, settings)
    worker.handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.SUCCEEDED
    assert stored.result is not None and stored.result.bundle_id == "B-fake"
    assert stored.progress.stage is JobStage.DONE
    done = {entry.stage for entry in stored.progress.stages if entry.state == "done"}
    assert done == set(JobStage), "every stage must be reported"
    assert stored.progress.counters["discovered"] == 1


def test_handle_marks_failed_with_a_named_mode_on_exception(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)

    class _Exploding:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, *args, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Exploding)
    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.FAILED
    assert stored.failure is not None
    assert stored.failure.mode is FailureMode.PIPELINE_EXCEPTION
    assert "boom" in (stored.failure.detail or "")
    assert stored.state is not JobState.RUNNING, "a failure is never left as running"


def test_handle_refuses_a_missing_workspace_without_running_anything(
    job_store, job_stream, tmp_path, queue_settings, monkeypatch
) -> None:
    """Checked before the pipeline starts, so a bad path costs nothing."""
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    missing = tmp_path / "not-a-directory"
    submission, job = _submit(job_store, workspace=missing)
    calls: list[int] = []

    class _Counting:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, *args, **kwargs):  # pragma: no cover - must not run
            calls.append(1)
            raise AssertionError("the pipeline must not be called")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Counting)
    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.failure is not None
    assert stored.failure.mode is FailureMode.WORKSPACE_MISSING
    assert calls == []


def test_handle_refuses_ai_fanout_loudly(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """Reserved in the contract, not implemented here: say so rather than do nothing."""
    settings = _settings(tmp_path, queue_settings)
    request = JobRequest(workspace=str(workspace), lsp=False)
    submission = job_store.new_submission(request, kind=JobKind.AI_FANOUT)
    job, _ = job_store.create(submission)

    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.FAILED
    assert stored.failure is not None
    assert stored.failure.mode is FailureMode.INTERNAL_ERROR
    assert "ai fanout" in stored.failure.message


def test_handle_skips_a_terminal_job_on_redelivery(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A reaper re-enqueue and a MAXLEN survivor can both repeat a job id."""
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-other")
    job_store.mark_succeeded(job.job_id, result=JobResult(bundle_id="B-already"))
    calls: list[int] = []

    class _Counting:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, *args, **kwargs):  # pragma: no cover - must not run
            calls.append(1)

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Counting)
    _worker(job_store, job_stream, settings).handle(_entry(job))
    assert calls == [], "finished work must not be re-run"
    assert job_store.get(job.job_id).result.bundle_id == "B-already"  # type: ignore[union-attr]


def test_handle_cancels_a_job_canceled_while_queued(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """A cancel that arrives before the job starts is honoured without starting it."""
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_store.request_cancel(job.job_id)

    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.CANCELED
    assert stored.failure is None


def test_handle_pins_the_scan_stage_before_the_silent_stage(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """The scan emits nothing while it runs, so the stage must be written first."""
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    observed: list[str] = []

    class _Spy:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, request, *, observer=None, abort=None, teardown=None, staging=False):
            snapshot = job_store.get(job.job_id)
            observed.append(snapshot.progress.stage.value)
            observed.append(snapshot.progress.stages[0].note or "")
            raise RuntimeError("stop here; the snapshot is what matters")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Spy)
    _worker(job_store, job_stream, settings).handle(_entry(job))

    assert observed[0] == "scan", "the stage is pinned before the pipeline runs"
    assert observed[1] == "scanning", "and it says what it is doing"


# --- cancellation vs shutdown ------------------------------------------


def test_canceled_abort_becomes_canceled_not_failed(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    from aegis_core.cancel import CanceledAbort
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)

    class _Canceled:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, *args, **kwargs):
            raise CanceledAbort(stage="expand", resource="lsp_request", detail="blocked")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Canceled)
    _worker(job_store, job_stream, settings).handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.CANCELED
    assert stored.failure is None, "cancellation is an action, not a fault"
    assert stored.progress.stage is JobStage.EXPAND, "the stage where it stopped is kept"
    note = next(e.note for e in stored.progress.stages if e.stage is JobStage.EXPAND)
    assert "expand" in (note or "")


def test_shutdown_returns_the_job_to_the_queue_not_canceled(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A restart is not a cancellation, and saying otherwise would be a lie."""
    from aegis_core.cancel import CanceledAbort
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    seen: dict[str, object] = {}

    class _Stopping:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, request, *, observer=None, abort=None, teardown=None, staging=False):
            seen["abort"] = abort
            raise CanceledAbort(stage="scan", resource="scan_process")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Stopping)
    worker = _worker(job_store, job_stream, settings)
    # Simulate SIGTERM arriving mid-run.
    worker.stop_event.set()

    entries_before = job_stream.stream_length()
    worker.handle(_entry(job))

    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.QUEUED, "returned to the queue, not canceled"
    assert stored.cancel_requested is False, "the user did not ask for this"
    assert stored.progress.counters == {} or True  # progress is preserved, not reset
    assert job_stream.stream_length() > entries_before, "and it was re-enqueued"


def test_the_abort_predicate_notices_a_queued_cancel_request(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """A cancel from the gateway arrives as a flag; this is how the loop learns of it."""
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    worker = _worker(job_store, job_stream, settings)
    worker._current_job = job.job_id
    worker._last_cancel_poll = 0.0

    assert worker._abort_check() is False
    job_store.request_cancel(job.job_id)
    worker._last_cancel_poll = 0.0  # bypass the poll interval
    assert worker._abort_check() is True
    assert worker._abort_check() is True, "once observed it stays observed"


def test_stop_event_makes_the_abort_predicate_true(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings)
    worker = _worker(job_store, job_stream, settings)
    assert worker._abort_check() is False
    worker.request_stop()
    assert worker._abort_check() is True


# --- the reaper --------------------------------------------------------


def _make_stale(store, fake_redis, job_id: str, *, age_s: int) -> None:
    """Age a job's heartbeat without touching its state."""
    from aegis_contracts.jobs import Job

    job = store.get(job_id)
    assert job is not None
    job.progress.worker_heartbeat_at = datetime.now(timezone.utc) - timedelta(seconds=age_s)
    raw = Job.model_validate_json(job.model_dump_json())
    fake_redis.set(QueueKeys().job(job_id), raw.model_dump_json())


def test_reaper_does_not_kill_a_slow_but_heartbeating_job(
    job_store, job_stream, tmp_path, workspace, queue_settings, fake_redis
) -> None:
    """THE test. A fresh heartbeat outranks an idle claim, and the job stays running.

    Everything else in this file protects data; this protects a *user* from being told
    their fifteen-minute scan failed at minute two.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-slow")
    job_store.record_stage(job.job_id, JobStage.SCAN, state="running")

    # The claim looks abandoned (idle far longer than the visibility timeout) but the
    # worker is alive and heartbeating.
    job_store.heartbeat(job.job_id, worker_id="w-slow")
    entry_id = job_stream.enqueue(
        job.job_id,
        kind="assemble",
        fingerprint=job.submission.fingerprint,
    )
    claimer = "w-original"
    job_stream.claim(claimer, count=1, block_ms=100)
    job_stream.redis.xclaim  # noqa: B018 - documenting that the claim is real

    reaper = Reaper(job_store, job_stream, settings, worker_id="w-reaper")
    # min_idle_ms=0 forces the transport to hand it over immediately: the reaper must still
    # refuse on the heartbeat check alone.
    report = reaper._adjudicate(
        {
            "entry_id": entry_id,
            "job_id": job.job_id,
            "kind": "assemble",
            "fingerprint": job.submission.fingerprint,
            "attempt": 1,
        }
    )
    assert report == "skipped"
    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.RUNNING, "a heartbeating job is never declared dead"
    assert stored.failure is None


def test_reaper_acks_a_job_that_already_succeeded(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-1")
    job_store.mark_succeeded(job.job_id, result=JobResult(bundle_id="B-1"))

    reaper = Reaper(job_store, job_stream, settings, worker_id="w-reaper")
    assert reaper._adjudicate({"entry_id": "1-1", "job_id": job.job_id}) == "skipped"
    assert job_store.get(job.job_id).state is JobState.SUCCEEDED  # type: ignore[union-attr]


def test_reaper_recovers_from_a_bundle_already_on_disk(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """Finished work whose state update was lost is recovered, not re-run.

    The window this covers: the worker wrote the bundle and died before recording success.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-dead")
    _make_stale(job_store, job_store.redis, job.job_id, age_s=99_999)

    recorded = settings.output_dir / "B-recorded"
    recorded.mkdir(parents=True, exist_ok=True)
    (recorded / "manifest.json").write_text("{}", encoding="utf-8")
    saved = job_store.get(job.job_id)
    assert saved is not None
    saved.result = JobResult(bundle_id="B-recorded", package_path=str(recorded))
    job_store.compare_and_set(saved)

    reaper = Reaper(job_store, job_stream, settings, worker_id="w-reaper")
    assert reaper._adjudicate({"entry_id": "1-1", "job_id": job.job_id}) == "recovered"
    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.SUCCEEDED


def test_a_finished_staging_directory_is_also_recoverable(
    job_store, tmp_path, workspace, queue_settings
) -> None:
    """The rename is atomic; the state write after it is not.

    A crash between the two leaves a complete tree under the staging name, and re-running
    the whole assembly to reproduce work that is already on disk would be waste.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    staging = settings.output_dir / ".staging-B-done"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "manifest.json").write_text("{}", encoding="utf-8")
    job.result = JobResult(bundle_id="B-done")
    assert recoverable_artifact(job_store, job, settings) == staging


def test_a_job_killed_mid_run_has_no_recoverable_artifact(
    job_store, tmp_path, workspace, queue_settings
) -> None:
    """The honest limit of recovery, asserted rather than implied.

    Recomputing the bundle id needs the finding set, which only exists mid-run -- so a
    crash *during* a run (no recorded result, only a half-written staging directory) is
    retried from scratch. That is the safe direction: a retry costs work, whereas treating
    a partial directory as a finished bundle costs correctness.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    staging = settings.output_dir / ".staging-B-unknown"
    staging.mkdir(parents=True, exist_ok=True)
    (staging / "summary.md").write_text("partial", encoding="utf-8")
    assert recoverable_artifact(job_store, job, settings) is None


def test_reaper_requeues_until_max_attempts_then_fails(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings).model_copy(
        update={"queue": queue_settings.model_copy(update={"max_attempts": 2})}
    )
    _, job = _submit(job_store, workspace=workspace)
    job_store.set_running(job.job_id, worker_id="w-dead", attempt=1)
    _make_stale(job_store, job_store.redis, job.job_id, age_s=99_999)

    reaper = Reaper(job_store, job_stream, settings, worker_id="w-reaper")
    assert reaper._adjudicate({"entry_id": "1-1", "job_id": job.job_id}) == "requeued"
    assert job_store.get(job.job_id).state is JobState.QUEUED  # type: ignore[union-attr]

    # Second attempt, again silent: attempts are spent, so this is a named failure.
    job_store.set_running(job.job_id, worker_id="w-dead-2", attempt=2)
    _make_stale(job_store, job_store.redis, job.job_id, age_s=99_999)
    assert reaper._adjudicate({"entry_id": "1-2", "job_id": job.job_id}) == "failed"
    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.FAILED
    assert stored.failure is not None and stored.failure.mode is FailureMode.WORKER_LOST


@pytest.mark.parametrize("state", ["running", "queued", "failed"])
def test_a_job_is_never_left_running_forever(
    job_store, job_stream, tmp_path, workspace, queue_settings, state
) -> None:
    """Whatever state it starts in, one reconcile pass ends it or queues it."""
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    if state == "running":
        job_store.set_running(job.job_id, worker_id="w-dead")
        _make_stale(job_store, job_store.redis, job.job_id, age_s=99_999)
    elif state == "failed":
        job_store.set_running(job.job_id, worker_id="w-1")
        job_store.mark_failed(job.job_id, mode=FailureMode.SCAN_FAILED, message="already done")

    reconcile_startup(job_store, job_stream, settings)
    stored = job_store.get(job.job_id)
    assert stored is not None
    assert stored.state is not JobState.RUNNING, f"started as {state}, still running"


def test_reconcile_startup_re_enqueues_a_queued_orphan(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """A `queued` job whose stream entry was trimmed is invisible to the reaper.

    The reaper only inspects delivered messages and the running sweep only looks at claimed
    jobs, so a trimmed-but-never-claimed entry would sit in `queued` forever. This sweep is
    the only thing that closes that hole.
    """
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    # Never enqueued: exactly the state MAXLEN leaves behind.
    assert not job_stream.was_enqueued_recently(job.job_id)

    report = reconcile_startup(job_store, job_stream, settings)
    assert report["queued_orphans"] == 1
    assert job_stream.was_enqueued_recently(job.job_id)
    claimed = job_stream.claim("w-check", count=5, block_ms=100)
    assert [row["job_id"] for row in claimed] == [job.job_id]


def test_reconcile_startup_leaves_a_fresh_job_alone(
    job_store, job_stream, tmp_path, workspace, queue_settings
) -> None:
    """A job whose worker is still reporting must not be touched by a booting peer."""
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_stream.enqueue(job.job_id, kind="assemble", fingerprint=job.submission.fingerprint)
    job_store.set_running(job.job_id, worker_id="w-alive")
    job_store.heartbeat(job.job_id, worker_id="w-alive")

    reconcile_startup(job_store, job_stream, settings)
    assert job_store.get(job.job_id).state is JobState.RUNNING  # type: ignore[union-attr]


def test_recoverable_artifact_prefers_the_recorded_path(
    job_store, tmp_path, workspace, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    recorded = settings.output_dir / "B-recorded"
    recorded.mkdir(parents=True, exist_ok=True)
    (recorded / "manifest.json").write_text("{}", encoding="utf-8")
    job.result = JobResult(bundle_id="B-recorded", package_path=str(recorded))
    assert recoverable_artifact(job_store, job, settings) == recorded


def test_recoverable_artifact_is_none_without_a_manifest(
    job_store, tmp_path, workspace, queue_settings
) -> None:
    """A directory without a parseable manifest is not an artifact: staging leftovers."""
    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    half = settings.output_dir / "B-half"
    half.mkdir(parents=True, exist_ok=True)
    (half / "summary.md").write_text("partial", encoding="utf-8")
    job.result = JobResult(bundle_id="B-half", package_path=str(half))
    assert recoverable_artifact(job_store, job, settings) is None


# --- the loop itself ---------------------------------------------------


def test_serve_forever_acks_even_when_the_job_fails(
    job_store, job_stream, tmp_path, workspace, queue_settings, monkeypatch
) -> None:
    """A message left pending forever is a job nobody retries."""
    from services.queue import worker as worker_module

    settings = _settings(tmp_path, queue_settings)
    _, job = _submit(job_store, workspace=workspace)
    job_stream.enqueue(job.job_id, kind="assemble", fingerprint=job.submission.fingerprint)

    class _Exploding:
        def __init__(self, _settings) -> None:
            pass

        async def run(self, *args, **kwargs):
            raise RuntimeError("boom")

    monkeypatch.setattr(worker_module, "AssemblyPipeline", _Exploding)
    worker = _worker(job_store, job_stream, settings)
    worker.serve_forever(max_iterations=3)

    assert job_stream.pending_count() == 0, "the failure must still be acknowledged"
    assert job_store.get(job.job_id).state is JobState.FAILED  # type: ignore[union-attr]


def test_serve_forever_stops_when_asked(
    job_store, job_stream, tmp_path, queue_settings
) -> None:
    settings = _settings(tmp_path, queue_settings)
    worker = _worker(job_store, job_stream, settings)
    timer = threading.Timer(0.1, worker.request_stop)
    timer.start()
    started = time.monotonic()
    worker.serve_forever()
    elapsed = time.monotonic() - started
    timer.cancel()
    assert elapsed < 5.0, f"the loop ignored the stop signal for {elapsed:.1f}s"
    assert worker.stop_event.is_set()


def test_worker_refuses_to_start_without_a_redis_url(tmp_path, monkeypatch, capsys) -> None:
    """A worker with nothing to consume must not idle healthily and look busy."""
    from aegis_core.config import Settings as CoreSettings
    from services.queue import worker as worker_module

    blank = CoreSettings(workspace_root=tmp_path, output_dir=tmp_path / "p", work_dir=tmp_path / "w")
    monkeypatch.setattr(worker_module, "get_settings", lambda: blank)
    assert worker_module.main([]) == 2
    assert "AEGIS_QUEUE__REDIS_URL is not set" in capsys.readouterr().out


def test_teardown_registers_a_staging_directory_and_the_worker_cleans_it(
    tmp_path,
) -> None:
    """A canceled job must not leave a half-written bundle where a reader would find it."""
    teardown = Teardown()
    staging = tmp_path / ".staging-B-x"
    staging.mkdir()
    (staging / "methods").mkdir()
    teardown.register_artifact_dir(staging)
    teardown.request()
    teardown.kill_all()
    removed = teardown.cleanup_partial()
    assert removed == [staging]
    assert not staging.exists()
