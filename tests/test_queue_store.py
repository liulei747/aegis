"""Job records in Redis: transitions, counters, and the CAS that stops false failures.

The central property under test is the one the whole design is arranged around:
**a stale decision must be rejected, not applied.** The reaper declares a claim dead on a
timer; a slow worker is indistinguishable from a dead one except by its heartbeat. If the
write were an unconditional SET, a healthy 15-minute scan would be marked failed and the
user would see a failure that never happened.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from aegis_contracts.jobs import (
    FailureMode,
    JobRequest,
    JobResult,
    JobStage,
    JobState,
)
from services.queue.jobs import (
    CAS_MISSING,
    CAS_REVISION_STALE,
    CAS_STATE_MISMATCH,
)
from services.queue.keys import QueueKeys


def _submit(store, **overrides):
    request = JobRequest(workspace="/workspace", **{"rule_config": "p/default", **overrides})
    submission = store.new_submission(request)
    job, created = store.create(submission)
    assert created is True
    return job


def test_create_then_get_roundtrips(job_store) -> None:
    job = _submit(job_store)
    fetched = job_store.get(job.job_id)
    assert fetched is not None
    assert fetched.state is JobState.QUEUED
    assert fetched.revision == 0
    assert fetched.timing.submitted_at is not None
    assert [entry.stage for entry in fetched.progress.stages] == list(JobStage)
    assert fetched.progress.stages[0].state == "pending"


def test_create_is_idempotent_on_the_same_job_id(job_store) -> None:
    """Same request twice -> the same job, not a second run."""
    request = JobRequest(workspace="/workspace", rule_config="p/default")
    first_submission = job_store.new_submission(request)
    first, created_first = job_store.create(first_submission)
    assert created_first

    second_submission = job_store.new_submission(request)
    assert second_submission.job_id == first.job_id
    second, created_second = job_store.create(second_submission)

    assert created_second is False
    assert second.job_id == first.job_id
    assert second.revision == first.revision


def test_fingerprint_index_points_at_the_job(job_store) -> None:
    request = JobRequest(workspace="/workspace", rule_config="p/default")
    submission = job_store.new_submission(request)
    job_store.create(submission)
    found = job_store.get_by_fingerprint(submission.fingerprint)
    assert found is not None and found.job_id == submission.job_id
    assert job_store.get_by_fingerprint("nope") is None


def test_set_running_records_worker_and_attempt(job_store) -> None:
    job = _submit(job_store)
    running = job_store.set_running(job.job_id, worker_id="w-1", attempt=2)
    assert running is not None
    assert running.state is JobState.RUNNING
    assert running.progress.worker_id == "w-1"
    assert running.progress.attempt == 2
    assert running.progress.stage_started_at is not None
    assert running.timing.started_at is not None
    assert running.revision == 1


def test_set_running_is_a_noop_once_terminal(job_store) -> None:
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    job_store.mark_succeeded(job.job_id, result=JobResult(bundle_id="B-1"))
    after = job_store.set_running(job.job_id, worker_id="w-2")
    assert after is not None
    assert after.state is JobState.SUCCEEDED
    assert after.progress.worker_id == "w-1", "a finished job keeps its original worker"


def test_stage_finished_accumulates_counters(job_store) -> None:
    """Counters are a union, and a repeated key is overwritten, never added.

    `contexts` is genuinely reported twice -- predicted when expand ends, corrected from
    the manifest when assemble ends -- and a front-end must not see it double.
    """
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")

    job_store.record_stage(
        job.job_id, JobStage.SCAN, state="done", duration_ms=10, counters={"discovered": 37}
    )
    job_store.record_stage(
        job.job_id,
        JobStage.LOCATE,
        state="done",
        duration_ms=5,
        counters={"located": 34, "focus_methods": 19},
    )
    final = job_store.record_stage(
        job.job_id,
        JobStage.EXPAND,
        state="done",
        duration_ms=9,
        counters={"contexts": 19, "slices": 18},
    )
    assert final is not None
    assert final.progress.counters == {
        "discovered": 37,
        "located": 34,
        "focus_methods": 19,
        "contexts": 19,
        "slices": 18,
    }

    corrected = job_store.record_stage(
        job.job_id, JobStage.ASSEMBLE, state="done", duration_ms=3, counters={"contexts": 17}
    )
    assert corrected is not None
    assert corrected.progress.counters["contexts"] == 17, "a correction replaces, never sums"


def test_stage_progress_reports_duration_and_state(job_store) -> None:
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    job_store.record_stage(
        job.job_id,
        JobStage.SCAN,
        state="done",
        duration_ms=9428,
        note="scan_transport=remote",
        counters={"discovered": 37},
    )
    scan = job_store.get(job.job_id).progress.stages[0]  # type: ignore[union-attr]
    assert scan.stage is JobStage.SCAN
    assert scan.state == "done"
    assert scan.duration_ms == 9428
    assert scan.note == "scan_transport=remote"
    assert scan.finished_at is not None


def test_stage_progress_is_ignored_for_a_terminal_job(job_store) -> None:
    """A cancel or a reaper decision can land between two stage events.

    Writing progress afterwards would move a job out of its terminal state in the UI.
    """
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    job_store.mark_canceled(job.job_id)
    before = job_store.get(job.job_id)
    result = job_store.record_stage(job.job_id, JobStage.READ, state="done", counters={"kept": 5})
    assert result is not None
    assert result.state is JobState.CANCELED
    assert result.progress.counters == before.progress.counters
    assert result.revision == before.revision


def test_heartbeat_does_not_bump_revision(job_store, fake_redis) -> None:
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    before = job_store.get(job.job_id)
    assert before is not None

    stamp = job_store.heartbeat(job.job_id, worker_id="w-1")
    after = job_store.get(job.job_id)

    assert stamp is not None and after is not None
    assert after.revision == before.revision, "a heartbeat is not news for the UI"
    assert after.progress.worker_heartbeat_at >= before.progress.worker_heartbeat_at


def test_heartbeat_refreshes_ttl_of_a_running_job(job_store, fake_redis) -> None:
    """A running job has no TTL of its own, so liveness is what keeps it alive."""
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    key = QueueKeys().job(job.job_id)
    assert fake_redis.ttl(key) == -1, "a running job must not expire under the worker"

    job_store.heartbeat(job.job_id, worker_id="w-1")
    assert fake_redis.ttl(key) == -1


def test_compare_and_set_rejects_a_stale_revision(job_store) -> None:
    """The guarantee that stops the reaper from killing a healthy job."""
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    current = job_store.get(job.job_id)
    assert current is not None

    # The reaper read this job, then the worker wrote a stage in the meantime.
    job_store.record_stage(job.job_id, JobStage.EXPAND, state="done", counters={"slices": 3})

    stale = current.model_copy(deep=True)
    stale.state = JobState.FAILED
    code = job_store.compare_and_set(
        stale, expected_state=JobState.RUNNING, expected_revision=current.revision
    )
    assert code == CAS_REVISION_STALE
    assert job_store.get(job.job_id).state is JobState.RUNNING  # type: ignore[union-attr]


def test_compare_and_set_rejects_a_wrong_state(job_store) -> None:
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    job_store.mark_succeeded(job.job_id, result=JobResult(bundle_id="B-1"))

    doomed = job_store.get(job.job_id)
    assert doomed is not None
    doomed.state = JobState.FAILED
    code = job_store.compare_and_set(doomed, expected_state=JobState.RUNNING)
    assert code == CAS_STATE_MISMATCH
    assert job_store.get(job.job_id).state is JobState.SUCCEEDED  # type: ignore[union-attr]


def test_compare_and_set_reports_a_missing_job(job_store) -> None:
    job = _submit(job_store)
    job_store.redis.delete(QueueKeys().job(job.job_id))
    assert job_store.compare_and_set(job) == CAS_MISSING


def test_terminal_state_sets_a_ttl_and_running_does_not(job_store, fake_redis) -> None:
    key = QueueKeys()
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    assert fake_redis.ttl(key.job(job.job_id)) == -1

    job_store.mark_succeeded(job.job_id, result=JobResult(bundle_id="B-1"))
    ttl = fake_redis.ttl(key.job(job.job_id))
    assert ttl > 0, "a finished job eventually expires; a running one must not"


def test_mark_succeeded_records_result_and_finishes_the_track(job_store) -> None:
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    job_store.record_stage(job.job_id, JobStage.PACKAGE, state="done", duration_ms=529)

    done = job_store.mark_succeeded(
        job.job_id, result=JobResult(bundle_id="B-1", package_path="/data/packages/B-1")
    )
    assert done is not None
    assert done.state is JobState.SUCCEEDED
    assert done.result is not None and done.result.bundle_id == "B-1"
    assert done.failure is None
    assert done.timing.finished_at is not None
    assert done.progress.stage is JobStage.DONE
    done_entry = next(e for e in done.progress.stages if e.stage is JobStage.DONE)
    assert done_entry.state == "done"


def test_mark_failed_requires_a_named_mode(job_store) -> None:
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    failed = job_store.mark_failed(
        job.job_id,
        mode=FailureMode.PIPELINE_EXCEPTION,
        message="the pipeline raised",
        detail="RuntimeError('boom')",
    )
    assert failed is not None
    assert failed.state is JobState.FAILED
    assert failed.failure is not None
    assert failed.failure.mode is FailureMode.PIPELINE_EXCEPTION
    assert "RuntimeError" in (failed.failure.detail or "")
    assert failed.failure.attempt == failed.progress.attempt
    # A failure is never left without a name: the enum is the guarantee.
    assert failed.state is not JobState.RUNNING


def test_mark_canceled_leaves_progress_untouched(job_store) -> None:
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    job_store.record_stage(
        job.job_id, JobStage.EXPAND, state="running", counters={"slices": 11}
    )
    before = job_store.get(job.job_id)
    assert before is not None

    canceled = job_store.mark_canceled(job.job_id, note="canceled at slice 11/19")
    assert canceled is not None
    assert canceled.state is JobState.CANCELED
    assert canceled.failure is None, "cancellation is an action, not a fault"
    assert canceled.cancel_requested is True
    assert canceled.revision == before.revision + 1

    # Stage entries before the interruption keep their timings.
    for old, new in zip(before.progress.stages, canceled.progress.stages, strict=True):
        if old.stage is not before.progress.stage:
            assert new.state == old.state
            assert new.duration_ms == old.duration_ms


def test_request_cancel_sets_only_the_flag(job_store) -> None:
    """Requesting is not performing: the worker still has to reach an interrupt point."""
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    requested = job_store.request_cancel(job.job_id)
    assert requested is not None
    assert requested.state is JobState.RUNNING
    assert requested.cancel_requested is True
    assert requested.cancel_requested_at is not None


def test_request_cancel_on_a_finished_job_is_audit_only(job_store) -> None:
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    job_store.mark_succeeded(job.job_id, result=JobResult(bundle_id="B-1"))
    after = job_store.request_cancel(job.job_id)
    assert after is not None
    assert after.state is JobState.SUCCEEDED, "a cancel must not undo a finished job"
    assert after.cancel_requested is True, "but the request is still recorded"


def test_requeue_keeps_counters_and_clears_the_claim(job_store) -> None:
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    job_store.record_stage(job.job_id, JobStage.SCAN, state="done", counters={"discovered": 37})
    requeued = job_store.requeue(job.job_id, note="worker stopping", attempt=2)
    assert requeued is not None
    assert requeued.state is JobState.QUEUED
    assert requeued.progress.worker_id is None
    assert requeued.progress.worker_heartbeat_at is None
    assert requeued.progress.attempt == 2
    assert requeued.progress.counters == {"discovered": 37}, "progress is not thrown away"


def test_list_jobs_is_newest_first_and_filters_by_state(job_store) -> None:
    oldest = _submit(job_store, rule_config="p/one")
    middle = _submit(job_store, rule_config="p/two")
    newest = _submit(job_store, rule_config="p/three")

    # Deterministic ordering: the index score is the submission time.
    base = datetime.now(timezone.utc)
    job_store.redis.zadd(
        QueueKeys().jobs_index(),
        {oldest.job_id: (base - timedelta(seconds=30)).timestamp() * 1000},
    )
    job_store.redis.zadd(QueueKeys().jobs_index(), {middle.job_id: base.timestamp() * 1000})
    job_store.redis.zadd(
        QueueKeys().jobs_index(),
        {newest.job_id: (base + timedelta(seconds=30)).timestamp() * 1000},
    )

    ordered = [job.job_id for job in job_store.list_jobs()]
    assert ordered == [newest.job_id, middle.job_id, oldest.job_id]

    job_store.set_running(middle.job_id, worker_id="w-1")
    job_store.mark_failed(middle.job_id, mode=FailureMode.SCAN_FAILED, message="rc=2")
    failed = job_store.list_jobs(state=JobState.FAILED)
    assert [job.job_id for job in failed] == [middle.job_id]
    assert job_store.count_by_state(state=JobState.QUEUED) == 2


def test_list_jobs_drops_an_expired_member(job_store, fake_redis) -> None:
    """The index is a sorted set with no TTL, so it is pruned lazily on read."""
    job = _submit(job_store)
    fake_redis.delete(QueueKeys().job(job.job_id))
    assert job_store.list_jobs() == []
    assert fake_redis.zcard(QueueKeys().jobs_index()) == 0


def test_the_queue_is_off_until_a_url_is_configured(monkeypatch) -> None:
    """No broker configured means no queue: the sync path and the suite keep working.

    Same convention as the scan and extraction service URLs -- the presence of a URL is
    what switches behaviour -- so this test is the one that documents "unset by default".
    """
    from aegis_core.config import QueueConfig, Settings

    assert QueueConfig().redis_url is None

    monkeypatch.setenv("AEGIS_QUEUE__REDIS_URL", "redis://example:6379/3")
    monkeypatch.setenv("AEGIS_QUEUE__MAX_ATTEMPTS", "5")
    settings = Settings()
    assert settings.queue.redis_url == "redis://example:6379/3"
    assert settings.queue.max_attempts == 5
    assert settings.queue.stream == "aegis:q:jobs"


def test_a_stored_job_reads_back_equal_to_what_was_written(job_store) -> None:
    """Redis must not quietly change the contract on the way through.

    This is not theoretical: the compare-and-set script decodes and re-encodes the job
    through Lua's cjson, which has no way to represent an empty table -- `{}` and `[]`
    both come back as `[]`. A job with empty counters (the common case) then fails to
    validate at all. `JobStore.get` normalises by field name; this test is what keeps
    that normalisation from being deleted as "unnecessary".
    """
    job = _submit(job_store)
    assert job_store.get(job.job_id) == job

    job_store.set_running(job.job_id, worker_id="w-1")
    after = job_store.get(job.job_id)
    assert after is not None
    assert job_store.get(job.job_id) == after
    assert after.progress.counters == {}
    assert after.progress.stages[0].counters == {}

    job_store.record_stage(job.job_id, JobStage.SCAN, state="done", counters={"discovered": 4})
    with_counters = job_store.get(job.job_id)
    assert job_store.get(job.job_id) == with_counters
    assert with_counters.progress.counters == {"discovered": 4}  # type: ignore[union-attr]


def test_container_type_declarations_cover_every_contract_container() -> None:
    """Both name lists must cover the contract, and may overlap where the model does.

    The type of an *empty* container has to be recovered from the field name alone, because
    by the time it comes back from Redis the value is empty and says nothing. So every
    list-valued and dict-valued field in the contract has to appear in `_LIST_FIELDS` or
    `_MAP_FIELDS`. Overlap is legitimate -- `methods` is a list in the manifest and a
    mapping in `AnalysisBundle` -- which is precisely why names alone were not enough and
    `tests/test_queue_real_redis.py` exercises the real server rather than only fakeredis.
    """
    from typing import get_origin

    from aegis_contracts import domain, jobs
    from services.queue.jobs import _LIST_FIELDS, _MAP_FIELDS

    listed: set[str] = set()
    mapped: set[str] = set()
    for module in (jobs, domain):
        for name in dir(module):
            model = getattr(module, name)
            if not isinstance(model, type) or not hasattr(model, "model_fields"):
                continue
            if getattr(model, "__module__", "") not in {jobs.__name__, domain.__name__}:
                continue
            for field_name, field in model.model_fields.items():
                origin = get_origin(field.annotation)
                if origin in (list, dict):
                    target = listed if origin is list else mapped
                    target.add(field_name)
                elif origin is not None:
                    for arg in getattr(field.annotation, "__args__", ()):
                        inner = get_origin(arg)
                        if inner is list:
                            listed.add(field_name)
                        elif inner is dict:
                            mapped.add(field_name)

    assert not (listed - _LIST_FIELDS), (
        "list-valued contract fields missing from _LIST_FIELDS: "
        f"{sorted(listed - _LIST_FIELDS)}; these come back from Redis as objects"
    )
    assert not (mapped - _MAP_FIELDS), (
        "dict-valued contract fields missing from _MAP_FIELDS: "
        f"{sorted(mapped - _MAP_FIELDS)}; these come back from Redis as arrays"
    )


def test_artifacts_availability_is_computed_on_read(job_store, tmp_path) -> None:
    job = _submit(job_store)
    job_store.set_running(job.job_id, worker_id="w-1")
    present = tmp_path / "B-1"
    present.mkdir()
    result = JobResult(
        bundle_id="B-1",
        package_path=str(present),
        artifacts={
            "bundle": {"kind": "bundle", "ref": "B-1", "path": str(present), "available": False},
            "gone": {"kind": "bundle", "ref": "B-2", "path": str(tmp_path / "B-2")},
        },
    )
    done = job_store.mark_succeeded(job.job_id, result=result)
    refs = job_store.artifacts(done)  # type: ignore[arg-type]
    assert refs["bundle"].available is True, "stored False must not survive a real directory"
    assert refs["gone"].available is False
