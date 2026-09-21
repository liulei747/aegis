"""End-to-end against a real Redis: the parts fakeredis cannot vouch for.

`fakeredis` implements Lua with `lupa`, and our compare-and-swap depends on a specific
quirk of *real* Redis: cjson has no way to represent an empty table, so `{}` and `[]` both
come back as `[]`. If fakeredis were more forgiving than the server, the whole queue would
pass its tests and fail on first contact with production.

Run with a server on `AEGIS_TEST_REDIS_URL` (default redis://127.0.0.1:6379/15):

    docker run --rm -d -p 127.0.0.1:6379:6379 redis:7-alpine
    python -m pytest tests/test_queue_real_redis.py -q

Skipped when no server is reachable, so the suite stays runnable with no broker.
"""

from __future__ import annotations

import os
import time
from pathlib import Path

import pytest

from aegis_contracts.jobs import JobRequest, JobStage, JobState
from aegis_core.config import QueueConfig, Settings
from services.queue.jobs import JobStore
from services.queue.keys import QueueKeys
from services.queue.reaper import Reaper
from services.queue.streams import JobStream, consumer_name

URL = os.getenv("AEGIS_TEST_REDIS_URL", "redis://127.0.0.1:6379/15")


def _client():
    import redis

    return redis.Redis.from_url(URL, socket_connect_timeout=0.5)


@pytest.fixture(scope="module")
def real_redis():
    try:
        client = _client()
        client.ping()
    except Exception as exc:  # pragma: no cover - depends on the environment
        pytest.skip(f"no Redis at {URL}: {exc}")
    client.flushdb()
    yield client
    client.flushdb()


@pytest.fixture()
def real_queue(real_redis, tmp_path: Path):
    queue_settings = QueueConfig(
        redis_url=URL,
        visibility_timeout_s=60,
        heartbeat_interval_s=5,
        reaper_interval_s=5,
        block_ms=200,
        stream_maxlen=1000,
        job_ttl_s=600,
    )
    keys = QueueKeys(queue_settings.stream, queue_settings.group)
    store = JobStore(real_redis, queue_settings, keys=keys)
    stream = JobStream(real_redis, queue_settings, keys=keys)
    stream.ensure_group()
    settings = Settings(
        workspace_root=tmp_path,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        queue=queue_settings,
        lsp_enabled=False,
    ).resolve()
    return store, stream, settings


def _submit(store, workspace: Path, **overrides):
    request = JobRequest(workspace=str(workspace), lsp=False, **overrides)
    submission = store.new_submission(request)
    job, _ = store.create(submission)
    return submission, job


def test_real_redis_rejects_stale_writes_the_same_way(real_queue, tmp_path: Path) -> None:
    """The CAS is a Lua script, so its behaviour is the server's, not fakeredis's."""
    store, _, _ = real_queue
    _, job = _submit(store, tmp_path)
    store.set_running(job.job_id, worker_id="w-1")
    current = store.get(job.job_id)
    assert current is not None

    store.record_stage(job.job_id, JobStage.EXPAND, state="done", counters={"slices": 3})
    stale = current.model_copy(deep=True)
    stale.state = JobState.FAILED
    from services.queue.jobs import CAS_REVISION_STALE

    assert (
        store.compare_and_set(
            stale, expected_state=JobState.RUNNING, expected_revision=current.revision
        )
        == CAS_REVISION_STALE
    )
    assert store.get(job.job_id).state is JobState.RUNNING  # type: ignore[union-attr]


def test_real_redis_returns_empty_maps_as_maps(real_queue, tmp_path: Path) -> None:
    """The cjson quirk, on the real server.

    A job with empty counters is the common case, and if `get()` did not normalise, every
    read of a fresh job would raise a validation error here and nowhere else.
    """
    store, _, _ = real_queue
    _, job = _submit(store, tmp_path)
    store.set_running(job.job_id, worker_id="w-1")
    reloaded = store.get(job.job_id)
    assert reloaded is not None
    assert reloaded.progress.counters == {}
    assert reloaded.progress.stages[0].counters == {}

    store.record_stage(job.job_id, JobStage.SCAN, state="done", counters={"discovered": 7})
    again = store.get(job.job_id)
    assert again is not None
    assert again.progress.counters == {"discovered": 7}


def test_real_redis_streams_round_trip_and_reclaim(real_queue, tmp_path: Path) -> None:
    """Groups, ACK and XAUTOCLAIM against the real implementation."""
    store, stream, settings = real_queue
    submission, job = _submit(store, tmp_path)
    stream.enqueue_submission(submission)

    first = consumer_name()
    claimed = stream.claim(first, count=1, block_ms=200)
    assert [row["job_id"] for row in claimed] == [job.job_id]
    assert stream.pending_count() >= 1

    # Immediate reclaim finds nothing; zero idle time finds it.
    assert stream.claim_stale(consumer_name(), min_idle_ms=60_000, count=10) == []
    taken = stream.claim_stale(consumer_name(), min_idle_ms=0, count=10)
    assert [row["job_id"] for row in taken] == [job.job_id]

    assert stream.ack(taken[0]["entry_id"]) == 1
    assert stream.pending_count() == 0


def test_real_redis_group_created_at_zero_reads_history(
    real_redis, tmp_path: Path
) -> None:
    """`id="0"` is a hard requirement, and the real server is where it matters."""
    keys = QueueKeys("aegis:test:hist", "aegis-test-workers")
    real_redis.delete(keys.queue())
    real_redis.xadd(keys.queue(), {"job_id": "J-before-the-group"})

    queue_settings = QueueConfig(redis_url=URL, block_ms=200)
    stream = JobStream(real_redis, queue_settings, keys=keys)
    stream.ensure_group()
    claimed = stream.claim(consumer_name(), count=5, block_ms=200)
    assert [row["job_id"] for row in claimed] == ["J-before-the-group"]
    real_redis.delete(keys.queue())


def test_real_redis_reaper_spares_a_heartbeating_job(real_queue, tmp_path: Path) -> None:
    """The single most important behaviour, against the real server.

    `XAUTOCLAIM` with zero idle time hands the message over; the heartbeat check is the
    only thing standing between a slow job and a fabricated failure.
    """
    store, stream, settings = real_queue
    submission, job = _submit(store, tmp_path)
    stream.enqueue_submission(submission)
    stream.claim(consumer_name(), count=1, block_ms=200)

    store.set_running(job.job_id, worker_id="w-slow")
    store.heartbeat(job.job_id, worker_id="w-slow")

    reaper = Reaper(store, stream, settings, worker_id="w-reaper")
    idle = stream.claim_stale(consumer_name(), min_idle_ms=0, count=10)
    assert idle, "the transport hands the message over"
    outcome = reaper._adjudicate(idle[0])
    assert outcome == "skipped"
    stored = store.get(job.job_id)
    assert stored is not None
    assert stored.state is JobState.RUNNING
    assert stored.failure is None
    stream.ack(idle[0]["entry_id"])
    assert time.monotonic()  # keep the import honest
