"""Job records in Redis: create, read, and the compare-and-swap that keeps them honest.

Three writers touch one job -- the worker (progress, terminal state), the reaper
(declaring a claim dead, re-enqueueing) and the gateway (recording a cancel request) --
and exactly one race among them is dangerous: the reaper deciding a *healthy* worker is
dead, while that worker is mid-run. The user then sees a failure that never happened.

Two things prevent it, and both live here:

* every state write is a compare-and-swap that can name the state and the revision it
  expects (``compare_and_set``), so a stale decision is *rejected* rather than applied;
* ``heartbeat`` refreshes liveness without bumping ``revision``, so "slow" and "dead"
  stay distinguishable. A reaper that ignoreed the heartbeat would steal slow jobs.

The CAS is a Lua script rather than ``WATCH/MULTI/EXEC`` because the three writers share
a connection pool and redis-py transactions are connection-sensitive; one script is one
round trip with no connection affinity to get wrong.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone

from pydantic import ValidationError
from redis.exceptions import ResponseError

from aegis_contracts.jobs import (
    STAGE_DONE,
    STAGE_PENDING,
    STAGE_SKIPPED,
    TERMINAL_STATES,
    ArtifactRef,
    FailureMode,
    Job,
    JobFailure,
    JobKind,
    JobProgress,
    JobRequest,
    JobResult,
    JobStage,
    JobStageProgress,
    JobState,
    JobSubmission,
    JobTiming,
    first_stage,
    job_id_for,
    request_fingerprint,
)
from aegis_core.logging import get_logger
from services.queue.keys import QueueKeys

log = get_logger(__name__)

#: Returned by ``compare_and_set`` when the stored state is not the expected one.
CAS_STATE_MISMATCH = -1
#: Returned when somebody else advanced the revision first. The caller must re-read.
CAS_REVISION_STALE = -2
#: Returned when the job key does not exist (expired, or never created).
CAS_MISSING = -3
#: Returned when Redis is unreachable, so callers can answer 503 instead of 500.
CAS_UNAVAILABLE = -4

# Lua: read, verify, write. ARGV: expected_state, expected_revision, new_json, ttl_s,
# bump_revision, new_revision. Empty expected_state means "any"; -1 means "any
# revision"; new_revision < 0 means "keep whatever the current one is".
_CAS_SCRIPT = """
local raw = redis.call('GET', KEYS[1])
if not raw then return -3 end
local cur = cjson.decode(raw)
if ARGV[1] ~= '' and cur['state'] ~= ARGV[1] then return -1 end
if tonumber(ARGV[2]) >= 0 and cur['revision'] ~= tonumber(ARGV[2]) then return -2 end
local new = cjson.decode(ARGV[3])
if tonumber(ARGV[6]) >= 0 then
  new['revision'] = tonumber(ARGV[6])
elseif ARGV[5] == '1' then
  new['revision'] = cur['revision'] + 1
else
  new['revision'] = cur['revision']
end
redis.call('SET', KEYS[1], cjson.encode(new))
local ttl = tonumber(ARGV[4])
if ttl > 0 then redis.call('EXPIRE', KEYS[1], ttl) end
return new['revision']
"""


#: Field names that are maps in the contract. `tests/test_queue_store.py` asserts this
#: list stays in step with the models, so a new map field cannot be forgotten here.
#: Nested-only names (a map inside a model that a job record embeds, such as `stage_ms`
#: inside a manifest) are listed too: the normaliser only rewrites a name when its value
#: is an empty container, so an over-broad list costs nothing and a missing name silently
#: changes the contract.
_MAP_FIELDS = frozenset(
    {
        "counters",
        "budget",
        "artifacts",
        "capabilities",
        "rule_counts",
        "severity_counts",
        "counts",
        "stage_ms",
        "methods",
        "sources",
        "properties",
    }
)

#: Field names that are lists. Needed because Lua's cjson cannot represent an empty
#: container faithfully *in either direction*, and the two Redis implementations disagree
#: about which way they lose it: fakeredis encodes `{}` as `[]`, while a real server
#: decodes `[]` as `{}`. A value that is empty therefore carries no type information at
#: all, and the only thing that can restore it is the field's name in the contract.
_LIST_FIELDS = frozenset(
    {
        "rules",
        "include_globs",
        "exclude_globs",
        "children",
        "stages",
        "findings",
        "methods",
        "edges",
        "contexts",
        "prunes",
        "degradations",
        "warnings",
        "top_paths",
        "aliases",
        "method_ids",
        "inputs",
        # Reachable through the scan ledger a job can carry:
        "command",
        "finding_ids",
        # Not reachable from a Job today, listed because the guard scans the whole contract
        # and an over-broad list costs nothing:
        "origin_path",
        "prompts",
        "jobs",  # JobListResponse; never stored, but the guard scans every model
    }
)


def _normalise_redis_json(value, *, field: str | None = None):
    """Restore the container type the contract declares, for empty containers only.

    Non-empty values are unambiguous, so they are left exactly as they are. Only the empty
    case is rewritten, and only when the field's name says which container it should be.
    A name may legitimately appear in both sets: `methods` is a list in the manifest and a
    mapping in `AnalysisBundle`, which is exactly why the field name alone was never enough
    to make this safe -- see the schema-driven check in the tests.
    """
    if isinstance(value, (list, dict)) and not value and field is not None:
        if field in _MAP_FIELDS:
            return {}
        if field in _LIST_FIELDS:
            return []
    if isinstance(value, list):
        return [_normalise_redis_json(item) for item in value]
    if isinstance(value, dict):
        return {key: _normalise_redis_json(item, field=key) for key, item in value.items()}
    return value


class JobStore:
    """Job records, keyed by a content-derived id.
    The id is derived from the request, not generated: submitting the same request twice
    is the same job. That is only sound because ``bundle_id`` is content-derived too, so
    the two idempotencies agree.
    """

    def __init__(self, redis, queue_settings, *, keys: QueueKeys | None = None) -> None:
        self.redis = redis
        self.settings = queue_settings
        self.keys = keys or QueueKeys(queue_settings.stream, queue_settings.group)
        self._cas = self.redis.register_script(_CAS_SCRIPT)

    # -- ids -----------------------------------------------------------
    def new_submission(
        self,
        request: JobRequest,
        *,
        kind: JobKind = JobKind.ASSEMBLE,
        submitted_by: str = "gateway",
        lsp_config_fingerprint: str = "",
    ) -> JobSubmission:
        fingerprint = request_fingerprint(
            request, lsp_config_fingerprint=lsp_config_fingerprint, kind=kind
        )
        return JobSubmission(
            job_id=job_id_for(fingerprint),
            kind=kind,
            request=request,
            fingerprint=fingerprint,
            submitted_by=submitted_by,
        )

    # -- create / read -------------------------------------------------
    def create(self, submission: JobSubmission) -> tuple[Job, bool]:
        """Store a queued job. Returns ``(job, created)``.

        ``created=False`` means a job for this submission already existed and is returned
        as-is: the caller should report *that* job rather than starting a second run.
        ``SET NX`` is what makes two simultaneous submissions of the same request
        converge instead of racing.
        """
        now = datetime.now(timezone.utc)
        job = Job(
            job_id=submission.job_id,
            kind=submission.kind,
            state=JobState.QUEUED,
            submission=submission,
            timing=JobTiming(submitted_at=submission.submitted_at or now),
            progress=JobProgress.fresh(submission.kind),
        )
        stored = self.redis.set(
            self.keys.job(job.job_id), job.model_dump_json(), nx=True
        )
        if not stored:
            existing = self.get(job.job_id)
            if existing is not None:
                return existing, False
            # The key vanished between SET NX and GET (TTL expiry). Try once more.
            self.redis.set(self.keys.job(job.job_id), job.model_dump_json())
        self.redis.set(self.keys.fingerprint(submission.fingerprint), job.job_id)
        self.redis.zadd(
            self.keys.jobs_index(),
            {job.job_id: job.timing.submitted_at.timestamp() * 1000},
        )
        return job, True

    def get(self, job_id: str) -> Job | None:
        raw = self.redis.get(self.keys.job(job_id))
        if raw is None:
            return None
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8")
        # Redis' Lua cjson cannot represent an empty table: it encodes both `{}` and `[]`
        # as `[]`, so a job that has been through the compare-and-set script comes back
        # with list-shaped empty dicts. Normalise on read rather than leaving a trap in
        # every consumer -- a job with empty counters is the common case, not an edge.
        try:
            return Job.model_validate_json(raw)
        except ValidationError:
            return Job.model_validate(_normalise_redis_json(json.loads(raw)))

    def get_by_fingerprint(self, fingerprint: str) -> Job | None:
        job_id = self.redis.get(self.keys.fingerprint(fingerprint))
        if job_id is None:
            return None
        if isinstance(job_id, bytes):
            job_id = job_id.decode("utf-8")
        return self.get(job_id)

    def exists(self, job_id: str) -> bool:
        return bool(self.redis.exists(self.keys.job(job_id)))

    # -- writes --------------------------------------------------------
    def _now(self) -> datetime:
        return datetime.now(timezone.utc)

    def _ttl_for(self, job: Job) -> int:
        """Only a finished job gets a TTL.

        An expiring *running* job would 404 while the worker is still writing to it --
        that is silent state loss, which is the failure this whole design is arranged
        around. The cost is that a crashed worker with a dead reaper leaves an orphan key,
        which the startup reconcile handles.
        """
        return self.settings.job_ttl_s if job.state in TERMINAL_STATES else 0

    def compare_and_set(
        self,
        job: Job,
        *,
        expected_state: JobState | None = None,
        expected_revision: int | None = None,
        bump_revision: bool = True,
        new_revision: int | None = None,
        ttl_s: int | None = None,
    ) -> int:
        """Write ``job`` only if the stored record still looks the way the caller thinks.

        Returns the stored revision on success, or a negative CAS_* code. Callers must
        treat a rejection as "somebody else got there first" and re-read, never as an
        error to retry blindly.
        """
        ttl = self._ttl_for(job) if ttl_s is None else ttl_s
        try:
            return int(
                self._cas(
                    keys=[self.keys.job(job.job_id)],
                    args=[
                        expected_state.value if expected_state else "",
                        -1 if expected_revision is None else expected_revision,
                        job.model_dump_json(),
                        ttl,
                        1 if bump_revision else 0,
                        -1 if new_revision is None else new_revision,
                    ],
                )
            )
        except ResponseError as exc:  # pragma: no cover - Lua/misuse, not data
            raise RuntimeError(f"job compare-and-set failed: {exc}") from exc

    def set_running(self, job_id: str, *, worker_id: str, attempt: int = 1) -> Job | None:
        """Claim a job for a worker. Idempotent when the worker already owns it.

        The compare-and-swap names the state we *read*, not the state we are writing --
        naming the new one would make the write reject itself.
        """
        job = self.get(job_id)
        if job is None:
            return None
        if job.state in TERMINAL_STATES:
            return job
        was = job.state
        now = self._now()
        job.state = JobState.RUNNING
        job.progress.worker_id = worker_id
        job.progress.attempt = attempt
        job.progress.stage_started_at = now
        job.progress.worker_heartbeat_at = now
        job.timing.started_at = job.timing.started_at or now
        if job.timing.started_at is not None:
            job.timing.queue_wait_ms = max(
                0, int((now - job.timing.submitted_at).total_seconds() * 1000)
            )
        job.progress.stage = first_stage(job.kind)
        self._touch_stage(job, first_stage(job.kind), state="running", started_at=now)
        if self.compare_and_set(job, expected_state=was) < 0:
            pass
        # Read back rather than returning the local object: the stored revision is
        # assigned by the script, so the in-memory copy is already one behind.
        return self.get(job_id)

    def _stage_entry(self, job: Job, stage: JobStage) -> JobStageProgress:
        for entry in job.progress.stages:
            if entry.stage is stage:
                return entry
        entry = JobStageProgress(stage=stage)
        job.progress.stages.append(entry)
        job.progress.stages.sort(key=lambda item: list(JobStage).index(item.stage))
        return entry

    def _touch_stage(
        self,
        job: Job,
        stage: JobStage,
        *,
        state: str | None = None,
        started_at: datetime | None = None,
        finished_at: datetime | None = None,
        duration_ms: int | None = None,
        note: str | None = None,
        counters: dict[str, int] | None = None,
    ):
        entry = self._stage_entry(job, stage)
        if state is not None:
            entry.state = state
        if started_at is not None:
            entry.started_at = started_at
        if finished_at is not None:
            entry.finished_at = finished_at
        if duration_ms is not None:
            entry.duration_ms = duration_ms
        if note is not None:
            entry.note = note
        if counters:
            # Union, never sum: `contexts` is reported twice (predicted, then corrected)
            # and must not be double counted.
            entry.counters.update(counters)
            job.progress.counters.update(counters)

    def pin_stage(self, job_id: str, stage: JobStage, *, note: str | None = None) -> Job | None:
        """Say "this stage is the current one" without claiming it produced anything.

        Separate from :meth:`record_stage` because the two mean different things: this is a
        snapshot written *before* a long silent stage begins (the scan), while
        `record_stage` reports a stage that has an outcome. Conflating them is how a stage
        ends up looking finished before it has started.
        """
        job = self.get(job_id)
        if job is None or job.state in TERMINAL_STATES:
            return job
        now = self._now()
        job.progress.stage = stage
        job.progress.stage_started_at = now
        job.progress.worker_heartbeat_at = now
        entry = self._stage_entry(job, stage)
        entry.state = "running"
        entry.started_at = entry.started_at or now
        if note is not None:
            entry.note = note
        if self.compare_and_set(job, expected_state=JobState.RUNNING) < 0:
            return self.get(job_id)
        return job

    def record_stage(
        self,
        job_id: str,
        stage: JobStage,
        *,
        state: str | None = None,
        duration_ms: int | None = None,
        note: str | None = None,
        counters: dict[str, int] | None = None,
        units_done: int | None = None,
        units_total: int | None = None,
        unit_label: str | None = None,
        advance_to: JobStage | None = None,
    ) -> Job | None:
        """Append one stage event. Silent when the job already finished.

        A wait-until-finished guard, not an error: a cancel or a reaper decision can land
        between two stage events, and writing progress into a terminal job would resurrect
        it in the UI.
        """
        job = self.get(job_id)
        if job is None or job.state in TERMINAL_STATES:
            return job
        now = self._now()
        if state == "running":
            # `counters` here as well as below, and that is not symmetry for its own sake: a long
            # stage reports progress *while running* -- the audit's mirror writes one running event
            # per harness phase, and the counts of candidates and findings are the whole point of it.
            # Dropping them in this branch left the job page showing zeros for the entire run while
            # the trail held thirty candidates; measured on the first live audit.
            self._touch_stage(job, stage, state=state, started_at=now, counters=counters)
            job.progress.stage = stage
            job.progress.stage_started_at = now
        else:
            self._touch_stage(
                job,
                stage,
                state=state or "done",
                finished_at=now,
                duration_ms=duration_ms,
                note=note,
                counters=counters,
            )
            if advance_to is not None:
                job.progress.stage = advance_to
            else:
                job.progress.stage = stage
        if units_done is not None:
            job.progress.units_done = units_done
        if units_total is not None:
            job.progress.units_total = units_total
        if unit_label is not None:
            job.progress.unit_label = unit_label
        if self.compare_and_set(job, expected_state=JobState.RUNNING) < 0:
            return self.get(job_id)
        return job

    def heartbeat(
        self,
        job_id: str,
        *,
        worker_id: str | None = None,
        stage: JobStage | None = None,
        note: str | None = None,
    ) -> datetime | None:
        """Refresh liveness without changing ``revision``.

        Deliberately not a state change: a heartbeat is not news the UI needs to re-render,
        but it *is* what stops the reaper from stealing the job. Returns the timestamp
        written, or None if the job is gone or already finished.
        """
        job = self.get(job_id)
        if job is None or job.state in TERMINAL_STATES:
            return None
        now = self._now()
        job.progress.worker_heartbeat_at = now
        if worker_id:
            job.progress.worker_id = worker_id
        if stage is not None:
            job.progress.stage = stage
        if note:
            entry = self._stage_entry(job, job.progress.stage)
            entry.note = note
        if self.compare_and_set(job, expected_state=JobState.RUNNING, bump_revision=False) < 0:
            return None
        return now

    def request_cancel(self, job_id: str) -> Job | None:
        """Record a cancel request. Does not interrupt anything by itself.

        While the job is still ``running`` this flag is the one signal the UI needs; once
        the state is terminal it is audit information only.
        """
        job = self.get(job_id)
        if job is None:
            return None
        if job.state in TERMINAL_STATES:
            if not job.cancel_requested:
                job.cancel_requested = True
                job.cancel_requested_at = self._now()
                self.compare_and_set(job, bump_revision=True)
            return self.get(job_id)
        job.cancel_requested = True
        job.cancel_requested_at = self._now()
        self.compare_and_set(job, bump_revision=True)
        return self.get(job_id)

    def mark_succeeded(
        self,
        job_id: str,
        *,
        result: JobResult,
        note: str | None = None,
    ) -> Job | None:
        job = self.get(job_id)
        if job is None or job.state in TERMINAL_STATES:
            return job
        was = job.state
        now = self._now()
        job.state = JobState.SUCCEEDED
        job.result = result
        job.failure = None
        job.timing.finished_at = now
        if job.timing.started_at is not None:
            job.timing.duration_ms = int(
                (now - job.timing.started_at).total_seconds() * 1000
            )
        # Finish the stage that was in flight -- but do not overwrite one that already has an
        # outcome. An AI job records its own stage as `skipped` when the model was never called
        # (the stage is off), and `done` would then claim it ran.
        in_flight = self._stage_entry(job, job.progress.stage)
        if in_flight.state not in (STAGE_DONE, STAGE_SKIPPED, "failed"):
            self._touch_stage(
                job,
                job.progress.stage,
                state="done",
                finished_at=now,
                note=note,
                duration_ms=(
                    int((now - job.progress.stage_started_at).total_seconds() * 1000)
                    if job.progress.stage_started_at
                    else None
                ),
            )
        job.progress.stage = JobStage.DONE
        self._touch_stage(job, JobStage.DONE, state="done", finished_at=now)
        # A finished job leaves no stage ambiguous. Stages this kind of job never reaches --
        # `ai` for an assemble job, `scan`..`package` for an ai_fanout job -- are `skipped`,
        # which says "this did not happen" rather than leaving a `pending` entry that reads as
        # "still to come" on a job that is over.
        for entry in job.progress.stages:
            if entry.state == STAGE_PENDING:
                entry.state = STAGE_SKIPPED
                # The AI stage is not skipped-and-forgotten: it runs as its own job against the
                # finished bundle (an assemble job cannot reach it, an ai_fanout job starts
                # there). "不属于本次任务" was read -- fairly -- as "the AI analysis was
                # ignored", so the one stage that has a home elsewhere says where that is.
                if entry.stage is JobStage.AI and job.kind is not JobKind.AI_FANOUT:
                    entry.note = entry.note or "由单独的 AI 研判任务执行（见该分析包的「AI 研判」）"
                else:
                    entry.note = entry.note or "不属于本次任务"
        self.compare_and_set(job, expected_state=was)
        return self.get(job_id)

    def mark_failed(
        self,
        job_id: str,
        *,
        mode: FailureMode,
        message: str,
        detail: str | None = None,
        recoverable: bool = False,
        result: JobResult | None = None,
        expected_revision: int | None = None,
    ) -> Job | None:
        """Terminal failure. Must be called with a *named* mode -- never a bare string.

        A job that fails without a name is indistinguishable from a job that is still
        running, which is the one outcome this project treats as unacceptable.
        """
        job = self.get(job_id)
        if job is None or job.state in TERMINAL_STATES:
            return job
        was = job.state
        now = self._now()
        job.state = JobState.FAILED
        job.failure = JobFailure(
            mode=mode,
            message=message,
            detail=detail,
            attempt=job.progress.attempt,
            recoverable=recoverable,
            scan_record=(result.scan_record if result else None),
        )
        if result is not None:
            job.result = result
        job.timing.finished_at = now
        if job.timing.started_at is not None:
            job.timing.duration_ms = int((now - job.timing.started_at).total_seconds() * 1000)
        self._touch_stage(job, job.progress.stage, state="failed", finished_at=now, note=message)
        code = self.compare_and_set(
            job, expected_state=was, expected_revision=expected_revision
        )
        if code < 0:
            return self.get(job_id)
        return job

    def mark_canceled(
        self, job_id: str, *, note: str | None = None, stage: JobStage | None = None
    ) -> Job | None:
        """Terminal cancellation. ``failure`` stays None, and progress is left alone.

        ``stage`` records where the run actually stopped, which is not always
        ``progress.stage``: the pipeline raises from inside a stage before it has had a
        chance to report that stage, so the exception is the more accurate witness.
        """
        job = self.get(job_id)
        if job is None or job.state in TERMINAL_STATES:
            return job
        was = job.state
        now = self._now()
        if stage is not None:
            job.progress.stage = stage
        job.state = JobState.CANCELED
        job.failure = None
        job.cancel_requested = True
        job.cancel_requested_at = job.cancel_requested_at or now
        job.timing.finished_at = now
        if job.timing.started_at is not None:
            job.timing.duration_ms = int((now - job.timing.started_at).total_seconds() * 1000)
        self._touch_stage(
            job, job.progress.stage, state="failed", finished_at=now, note=note or "已取消"
        )
        self.compare_and_set(job, expected_state=was)
        # Read back: the script owns the revision, so the local copy is one behind.
        return self.get(job_id)

    def requeue(
        self, job_id: str, *, note: str | None = None, attempt: int | None = None
    ) -> Job | None:
        """Return a job to ``queued`` without touching its counters.

        Used by graceful shutdown and by the reaper's retry path. Deliberately *not*
        canceled: the work is still wanted, it just lost its worker. Refuses a terminal
        job: reviving finished work needs the explicit intent of `redrive`.
        """
        job = self.get(job_id)
        if job is None or job.state in TERMINAL_STATES:
            return job
        was = job.state
        job.state = JobState.QUEUED
        if attempt is not None:
            job.progress.attempt = attempt
        job.progress.worker_id = None
        job.progress.worker_heartbeat_at = None
        if note:
            entry = self._stage_entry(job, job.progress.stage)
            entry.note = note
        self.compare_and_set(job, expected_state=was)
        return self.get(job_id)

    def redrive(
        self, job_id: str, *, note: str | None = None, allow_success: bool = False
    ) -> Job | None:
        """Explicitly re-run a **finished** job. The `?force=true` path, and nothing else.

        A failed job is not retried automatically, and that is a deliberate property: it is
        what makes "same input, same answer" hold and what stops a deterministic failure
        from becoming an infinite retry. Re-running therefore has to be somebody's decision,
        which is why this is a separate method rather than a flag on `requeue`, and why the
        attempt counter -- the thing that bounds retries -- is incremented here.

        `allow_success` exists because "succeeded" is not always "the answer is available":
        a bundle can be cleaned up while its job record says success, and then the recorded
        result is a dangling reference. That determination needs the filesystem, so it is the
        caller's to make -- the default refuses, so a caller that has not thought about it
        cannot accidentally re-run finished work.
        """
        job = self.get(job_id)
        if job is None:
            return None
        if job.state is JobState.SUCCEEDED and not allow_success:
            return job
        was = job.state
        now = self._now()
        job.state = JobState.QUEUED
        job.failure = None
        job.result = None
        job.cancel_requested = False
        job.cancel_requested_at = None
        job.progress.attempt += 1
        job.progress.worker_id = None
        job.progress.worker_heartbeat_at = None
        job.progress.stage = first_stage(job.kind)
        job.timing.started_at = None
        job.timing.finished_at = None
        job.timing.duration_ms = 0
        job.timing.queue_wait_ms = 0
        for entry in job.progress.stages:
            entry.state = "pending"
            entry.started_at = None
            entry.finished_at = None
            entry.duration_ms = None
            entry.note = None
            entry.counters = {}
        job.progress.counters = {}
        job.progress.units_done = 0
        job.progress.units_total = 0
        if note:
            # On the stage this job kind actually starts in -- `stages[0]` is `scan`, which an AI
            # job never runs, so the reason for the re-run appeared on a stage that was skipped.
            self._stage_entry(job, first_stage(job.kind)).note = note
        job.timing.submitted_at = now
        if self.compare_and_set(job, expected_state=was) < 0:
            return self.get(job_id)
        return self.get(job_id)

    # -- queries -------------------------------------------------------
    def list_ids(self, *, limit: int | None = None) -> list[str]:
        """Newest first."""
        limit = limit or self.settings.list_limit
        members = self.redis.zrevrange(self.keys.jobs_index(), 0, limit - 1)
        return [m.decode("utf-8") if isinstance(m, bytes) else m for m in members]

    def list_jobs(self, *, state: JobState | None = None, limit: int | None = None) -> list[Job]:
        """Newest first, optionally filtered. Drops ids whose record has expired."""
        out: list[Job] = []
        for job_id in self.list_ids(limit=(limit or self.settings.list_limit) * 4):
            job = self.get(job_id)
            if job is None:
                self.redis.zrem(self.keys.jobs_index(), job_id)
                continue
            if state is not None and job.state is not state:
                continue
            out.append(job)
            if len(out) >= (limit or self.settings.list_limit):
                break
        return out

    def count_by_state(self, *, state: JobState) -> int:
        return sum(1 for job in self.list_jobs(state=state, limit=self.settings.list_limit))

    def artifacts(self, job: Job) -> dict[str, ArtifactRef]:
        """Availability is computed on read, never stored as a stale fact."""
        import os

        refs = dict(job.result.artifacts) if job.result else {}
        for ref in refs.values():
            if ref.path:
                ref.available = os.path.exists(ref.path)
        return refs

    # -- recovery ------------------------------------------------------
    def reconcile_startup(self, stream, settings=None) -> dict:
        """See `services.queue.reaper.reconcile_startup`.

        A thin delegate so a worker's entry point reads as "make the state sane, then
        serve", without the store having to grow the recovery logic itself.
        """
        from services.queue.reaper import reconcile_startup

        return reconcile_startup(self, stream, settings or self.settings)
