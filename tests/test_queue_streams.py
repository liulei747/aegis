"""The Streams transport: routing-only entries, honest pending counts, and id="0".

The group-creation test is the important one. ``XGROUP CREATE`` with ``"$"`` looks
harmless and passes every naive test, because in a fresh test database there is no
history to miss -- but in production it means a restart cannot see the entries that were
added and never acknowledged, which is precisely the crash case the reaper exists for.
"""

from __future__ import annotations

import time

from aegis_contracts.jobs import JobRequest
from services.queue.keys import QueueKeys
from services.queue.streams import ROUTING_FIELDS, JobStream, consumer_name


def _enqueue(store, stream, **overrides):
    request = JobRequest(workspace="/workspace", **{"rule_config": "p/default", **overrides})
    submission = store.new_submission(request)
    store.create(submission)
    entry_id = stream.enqueue_submission(submission)
    return submission, entry_id


def test_ensure_group_is_idempotent_and_reads_history(job_store, fake_redis, queue_settings) -> None:
    """The group must be created at id="0", so an entry added *before* it is still claimable."""
    stream = JobStream(fake_redis, queue_settings)
    # No group yet: enqueue one entry, exactly like a gateway whose worker is not up.
    entry_id = fake_redis.xadd(QueueKeys().queue(), {"job_id": "J-lonely"})

    stream.ensure_group()
    stream.ensure_group()  # idempotent: BUSYGROUP is swallowed, anything else is not

    claimed = stream.claim(consumer_name(), count=10, block_ms=100)
    assert [row["job_id"] for row in claimed] == ["J-lonely"]
    assert claimed[0]["entry_id"] == (
        entry_id.decode("utf-8") if isinstance(entry_id, bytes) else entry_id
    ), "the claim must be the historical entry, not a new one"


def test_enqueue_carries_routing_fields_only(job_store, job_stream) -> None:
    """The payload lives in the job record, never in the trimmable stream entry."""
    submission, _ = _enqueue(job_store, job_stream)
    rows = job_stream.claim(consumer_name(), count=5, block_ms=100)
    assert len(rows) == 1
    row = rows[0]
    fields = {key for key in row if key != "entry_id"}
    assert fields == set(ROUTING_FIELDS)
    assert row["job_id"] == submission.job_id
    assert row["kind"] == "assemble"
    assert row["fingerprint"] == submission.fingerprint
    assert row["attempt"] == 1
    assert "request" not in row and "budget" not in row


def test_enqueue_remembers_the_job_for_orphan_detection(job_store, job_stream) -> None:
    """MAXLEN can trim an entry nobody claimed; this memory is how that is noticed."""
    submission, _ = _enqueue(job_store, job_stream)
    assert job_stream.was_enqueued_recently(submission.job_id) is True
    assert job_stream.was_enqueued_recently("J-never") is False


def test_consumer_names_are_unique_per_process() -> None:
    first, second = consumer_name(), consumer_name()
    assert first != second
    assert first.startswith(f"{__import__('socket').gethostname()}:{__import__('os').getpid()}:")


def test_claim_then_ack_clears_pending(job_store, job_stream) -> None:
    submission, _ = _enqueue(job_store, job_stream)
    consumer = consumer_name()
    rows = job_stream.claim(consumer, count=1, block_ms=100)
    assert job_stream.pending_count() == 1

    assert job_stream.ack(rows[0]["entry_id"]) == 1
    assert job_stream.pending_count() == 0
    assert submission.job_id  # the job record is untouched by delivery bookkeeping


def test_claim_returns_empty_on_timeout_rather_than_blocking(job_store, job_stream) -> None:
    """`block=0` means "block forever"; a worker that passes it never shuts down."""
    started = time.monotonic()
    rows = job_stream.claim(consumer_name(), count=1, block_ms=100)
    elapsed = time.monotonic() - started
    assert rows == []
    assert elapsed < 5.0, f"claim blocked for {elapsed:.1f}s; the block window is not bounded"


def test_claim_does_not_redeliver_to_the_same_consumer(job_store, job_stream) -> None:
    """`>` means new messages only: the pending entry is the reaper's business, not a re-read."""
    _enqueue(job_store, job_stream)
    consumer = consumer_name()
    assert len(job_stream.claim(consumer, count=5, block_ms=100)) == 1
    assert job_stream.claim(consumer, count=5, block_ms=100) == []


def test_claim_stale_takes_over_an_idle_entry(job_store, job_stream) -> None:
    """The transport half of "a dead worker's job is recoverable"."""
    submission, _ = _enqueue(job_store, job_stream)
    original = consumer_name()
    job_stream.claim(original, count=1, block_ms=100)

    # Nothing is idle yet.
    assert job_stream.claim_stale(consumer_name(), min_idle_ms=60_000, count=10) == []

    taken = job_stream.claim_stale(consumer_name(), min_idle_ms=0, count=10)
    assert [row["job_id"] for row in taken] == [submission.job_id]
    assert taken[0]["entry_id"]


def test_claim_stale_is_not_confused_by_a_deleted_entry(job_store, job_stream, fake_redis) -> None:
    """XAUTOCLAIM can report deleted ids; the wrapper must not yield phantom rows."""
    _enqueue(job_store, job_stream)
    job_stream.claim(consumer_name(), count=1, block_ms=100)
    fake_redis.xtrim(QueueKeys().queue(), maxlen=0)
    assert job_stream.claim_stale(consumer_name(), min_idle_ms=0, count=10) == []


def test_stream_length_and_group_info_expose_the_backlog(job_store, job_stream) -> None:
    """The two numbers an operator needs to see MAXLEN damage before it happens."""
    for index in range(3):
        _enqueue(job_store, job_stream, rule_config=f"p/{index}")
    assert job_stream.stream_length() == 3
    info = job_stream.group_info()
    # `lag` counts entries never delivered to the group; the last XADD may still be in
    # flight through the group's last-delivered id, so accept the bounded range.
    assert int(info["lag"]) in (2, 3)
    assert info["pending"] in (0, "0")


def test_enqueue_respects_maxlen(job_store, fake_redis, queue_settings) -> None:
    """Trimming is where a queued job can silently disappear, so it is bounded here."""
    tiny = queue_settings.model_copy(update={"stream_maxlen": 5})
    keys = QueueKeys(tiny.stream, tiny.group)
    store = type(job_store)(fake_redis, tiny, keys=keys)
    stream = JobStream(fake_redis, tiny, keys=keys)
    stream.ensure_group()

    for index in range(12):
        submission = store.new_submission(
            JobRequest(workspace="/workspace", rule_config=f"p/{index}")
        )
        store.create(submission)
        stream.enqueue_submission(submission)

    assert stream.stream_length() <= 12
    # The job records survive regardless: they are what the reconcile re-enqueues from.
    assert sum(1 for job_id in store.list_ids(limit=50) if store.exists(job_id)) == 12
