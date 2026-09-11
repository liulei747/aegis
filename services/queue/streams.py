"""Redis Streams transport: enqueue, claim, acknowledge.

The stream carries routing information only -- ``job_id`` and enough to route a retry.
The request body lives in the job record, because stream entries are subject to
``MAXLEN`` trimming while job records are not: putting the payload in the trimmable
place is how a job becomes unclaimable.

The one non-obvious requirement here is ``XGROUP CREATE ... id="0"``. Creating the group
at ``"$"`` means a restarted process cannot see entries that were added but never
acknowledged -- exactly the messages left over by a crash -- and ``XAUTOCLAIM`` has
nothing to recover. ``tests/test_queue_streams.py`` pins this by enqueueing *before*
creating the group.
"""

from __future__ import annotations

import os
import secrets
import socket
from datetime import datetime, timezone
from typing import Any

from redis.exceptions import ResponseError

from aegis_contracts.jobs import JobSubmission
from aegis_core.logging import get_logger
from services.queue.jobs import JobStore
from services.queue.keys import QueueKeys

log = get_logger(__name__)

#: Fixed, not environment-specific: the gateway and every worker must agree, and a
#: group name that varies by deployment is a silent "nobody consumes this".
CONSUMER_GROUP = "aegis-workers"

#: Every field a stream entry carries. Asserted by the tests, so adding one is a
#: deliberate act -- and so is accidentally putting a payload in here.
ROUTING_FIELDS = ("job_id", "kind", "fingerprint", "attempt", "submitted_at")


def consumer_name() -> str:
    """Unique per process, so several workers in one container keep separate PELs."""
    return f"{socket.gethostname()}:{os.getpid()}:{secrets.token_hex(2)}"


class JobStream:
    def __init__(self, redis, queue_settings, *, keys: QueueKeys | None = None) -> None:
        self.redis = redis
        self.settings = queue_settings
        self.keys = keys or QueueKeys(queue_settings.stream, queue_settings.group)
        self.group = self.keys.group or CONSUMER_GROUP

    # -- setup ---------------------------------------------------------
    def ensure_group(self) -> None:
        """Idempotent. Reads from ``id="0"`` so a restart can see unacked history."""
        try:
            self.redis.xgroup_create(self.keys.queue(), self.group, id="0", mkstream=True)
        except ResponseError as exc:
            if "BUSYGROUP" not in str(exc):
                raise

    # -- produce -------------------------------------------------------
    def enqueue(
        self,
        job_id: str,
        *,
        kind: str,
        fingerprint: str,
        attempt: int = 1,
        submitted_at: datetime | None = None,
    ) -> str:
        """Append a routing entry. Returns the stream id."""
        stamp = (submitted_at or datetime.now(timezone.utc)).isoformat()
        entry_id = self.redis.xadd(
            self.keys.queue(),
            {
                "job_id": job_id,
                "kind": kind,
                "fingerprint": fingerprint,
                "attempt": str(attempt),
                "submitted_at": stamp,
            },
            maxlen=self.settings.stream_maxlen,
            approximate=True,
        )
        # Remember that we enqueued it: the stream can be trimmed, this set is what lets
        # the startup reconcile notice a job whose entry was trimmed before a claim.
        self.redis.sadd(self.keys.seen(), job_id)
        self.redis.expire(self.keys.seen(), self.settings.job_ttl_s * 2)
        return entry_id.decode("utf-8") if isinstance(entry_id, bytes) else entry_id

    def enqueue_submission(self, submission: JobSubmission) -> str:
        return self.enqueue(
            submission.job_id,
            kind=submission.kind.value,
            fingerprint=submission.fingerprint,
            submitted_at=submission.submitted_at,
        )

    # -- consume -------------------------------------------------------
    def claim(self, consumer: str, *, count: int = 1, block_ms: int | None = None) -> list[dict[str, Any]]:
        """Read up to ``count`` new entries. Empty list on timeout, never blocks forever."""
        block = self.settings.block_ms if block_ms is None else block_ms
        entries = self.redis.xreadgroup(
            self.group, consumer, {self.keys.queue(): ">"}, count=count, block=block
        )
        out: list[dict[str, Any]] = []
        for _stream, messages in entries or []:
            for entry_id, fields in messages:
                out.append(self._decode_entry(entry_id, fields))
        return out

    def ack(self, entry_id: str) -> int:
        return int(self.redis.xack(self.keys.queue(), self.group, entry_id))

    def pending_count(self) -> int:
        summary = self.redis.xpending(self.keys.queue(), self.group)
        if not summary:
            return 0
        # redis-py returns a dict-like summary; older shapes are a list.
        if isinstance(summary, dict):
            return int(summary.get("pending", 0))
        return int(summary[0])

    def claim_stale(self, consumer: str, *, min_idle_ms: int, count: int) -> list[dict[str, Any]]:
        """Take over entries whose owner has been silent for ``min_idle_ms``.

        Returns the claimed entries only; the caller decides what each one means (a
        finished job, a slow worker, work to retry). This function deliberately makes no
        judgement -- see ``services/queue/reaper.py`` for that.
        """
        claimed: list[dict[str, Any]] = []
        start = "0-0"
        while True:
            result = self.redis.xautoclaim(
                self.keys.queue(),
                self.group,
                consumer,
                min_idle_time=min_idle_ms,
                start_id=start,
                count=count,
            )
            # redis-py >= 5 returns (next_start_id, entries, deleted_ids).
            next_id = result[0]
            entries = result[1] or []
            for entry_id, fields in entries:
                if fields:
                    claimed.append(self._decode_entry(entry_id, fields))
            if not entries or next_id in ("0-0", b"0-0"):
                break
            start = next_id
        return claimed

    def stream_length(self) -> int:
        return int(self.redis.xlen(self.keys.queue()))

    def group_info(self) -> dict[str, Any]:
        try:
            groups = self.redis.xinfo_groups(self.keys.queue())
        except ResponseError:
            return {}
        for group in groups:
            name = group.get("name")
            if isinstance(name, bytes):
                name = name.decode("utf-8")
            if name == self.group:
                return {
                    "consumers": group.get("consumers"),
                    "pending": group.get("pending"),
                    "lag": group.get("lag"),
                    "last_delivered_id": str(group.get("last-delivered-id", "")),
                }
        return {}

    def was_enqueued_recently(self, job_id: str) -> bool:
        """Whether the ``seen`` set still remembers this job. False can also mean TTL."""
        return bool(self.redis.sismember(self.keys.seen(), job_id))

    # -- helpers -------------------------------------------------------
    def _decode_entry(self, entry_id: Any, fields: dict[Any, Any]) -> dict[str, Any]:
        def text(value: Any) -> str:
            return value.decode("utf-8") if isinstance(value, bytes) else str(value)

        row = {text(k): text(v) for k, v in fields.items()}
        row["entry_id"] = text(entry_id)
        row["attempt"] = int(row.get("attempt", "1") or 1)
        return row


def store_and_stream(redis, settings) -> tuple[JobStore, JobStream]:
    """The pair every producer and consumer needs, built from one connection and config."""
    keys = QueueKeys(settings.stream, settings.group)
    return JobStore(redis, settings, keys=keys), JobStream(redis, settings, keys=keys)
