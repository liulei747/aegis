"""Every Redis key this project uses, in one place.

A single constructor means the prefix and the naming convention cannot drift between the
gateway (which writes submissions and reads status) and the worker (which claims and
updates). Those two run in different containers, so a key typo does not fail loudly --
it produces a job that is submitted and never claimed, or claimed and never found.

All keys share the ``aegis:`` prefix so an operator can look at a shared Redis without
guessing which ones are ours.
"""

from __future__ import annotations

PREFIX = "aegis:"


class QueueKeys:
    """Key names for one queue. ``stream``/``group`` come from ``Settings.queue``."""

    def __init__(self, stream: str = "aegis:q:jobs", group: str = "aegis-workers") -> None:
        self.stream = stream
        self.group = group

    # -- state ---------------------------------------------------------
    def job(self, job_id: str) -> str:
        """The whole Job as a JSON string. A string, not a hash: Job nests."""
        return f"{PREFIX}job:{job_id}"

    def fingerprint(self, fingerprint: str) -> str:
        """fingerprint -> job_id, so a resubmission attaches instead of duplicating."""
        return f"{PREFIX}job-fp:{fingerprint}"

    def jobs_index(self) -> str:
        """Sorted set of job ids scored by submission time (epoch ms)."""
        return f"{PREFIX}jobs"

    # -- transport -----------------------------------------------------
    def queue(self) -> str:
        return self.stream

    def seen(self) -> str:
        """job ids recently written to the stream, for orphan detection.

        The stream can be trimmed by ``MAXLEN``; this set is the memory of "we did
        enqueue this", which is what lets the startup reconcile notice a job whose
        entry was trimmed away before anyone claimed it.
        """
        return f"{PREFIX}q:seen"

    def events(self, job_id: str) -> str:
        """Pub/Sub channel for progress pushes. Not stored: polling is the source of truth."""
        return f"{PREFIX}events:{job_id}"

    def worker_heartbeat(self, worker_id: str) -> str:
        return f"{PREFIX}queue:worker:{worker_id}"

    def workers(self) -> str:
        return f"{PREFIX}queue:workers"

    # -- helpers -------------------------------------------------------
    def revision_sequence(self, job_id: str) -> str:
        """A monotonically increasing counter per job.

        Used only to keep a worker's stage writes from clobbering each other when they
        race; the stored ``revision`` remains the single source of ordering for clients.
        """
        return f"{PREFIX}rev:{job_id}"
