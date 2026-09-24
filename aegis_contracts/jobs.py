"""The job contract: what a queued run is, and what a caller may ask about it.

This module is data shapes plus pure functions -- the same rule as ``domain.py``, and
``tests/test_jobs_contract.py::test_contracts_module_imports_no_io`` enforces it. The
store, the stream and the worker live in ``services/queue/``; if any of them ever
appears here, the contract has stopped being a contract.

Three decisions are load-bearing and are easy to undo by accident:

* **Cancellation is not a failure.** There is deliberately no ``canceled_by_request``
  :class:`FailureMode`: a canceled job has ``state == CANCELED`` and ``failure is None``.
  Folding "the user asked" into the same enum as "the system broke" forces every
  consumer to re-check ``state`` to tell them apart, when ``state`` is already the
  authoritative answer. ``Job`` refuses the combination outright (see the validator).
* **Progress is stage-level, and the stages are the pipeline's own segments.** They map
  onto the funnel's nine counting steps, but not one-to-one -- ``FUNNEL_STEPS`` is the
  funnel's vocabulary and ``JobStage`` is the clock's. Read ``docs/QUEUE_PLAN.md`` §3
  before changing either: ``read`` means two different things in the two lists.
* **A fingerprint is not a cache key.** It exists so that submitting the same request
  twice attaches to the same job instead of starting a second one, which is only sound
  because ``bundle_id`` is content-derived too. ``request_fingerprint`` therefore has to
  cover everything that can change the bundle -- including the LSP catalog and
  ``max_findings`` -- and the tests deliberately fail if a field is dropped from it.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from aegis_contracts.domain import ScanRecord

SCHEMA_VERSION = "1.0"

#: The funnel's counting steps, in order (`docs/ARCHITECTURE.md` §9, implemented by
#: `aegis_contracts.views.funnel`). Every step is the same unit as the one before it,
#: so `lost` is always computable. These are *counts*; `JobStage` is *time*.
FUNNEL_STEPS: tuple[str, ...] = (
    "discovered",
    "located",
    "focus_methods",
    "contexts",
    "slices",
    "proposed",
    "kept",
    "read",
    "inlined",
)


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _sha1(*parts: str, length: int = 16) -> str:
    """The same digest as ``aegis_core.utils.sha1``, kept local to avoid the import.

    `tests/test_contracts.py::test_the_contract_layer_reaches_core_exactly_once` pins the
    contracts -> core edge count at exactly one (``domain.estimate_tokens``). Reaching for
    a 30-line hash helper would make it two and quietly turn a recorded exception into a
    habit, so the four lines are duplicated here and
    `test_the_local_digest_matches_the_shared_helper` holds the two implementations
    byte-identical rather than merely similar.
    """
    h = hashlib.sha1()
    for part in parts:
        h.update(part.encode("utf-8", errors="replace"))
        h.update(b"\x00")
    return h.hexdigest()[:length]


class JobState(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELED = "canceled"


TERMINAL_STATES: frozenset[JobState] = frozenset(
    {JobState.SUCCEEDED, JobState.FAILED, JobState.CANCELED}
)


class JobStage(str, Enum):
    """Execution stages, in lifecycle order.

    The names line up with `RunStats.stage_ms` keys, so a stage's reported duration and
    the bundle's own timing can be compared directly. ``DONE`` is a sentinel with no
    timing of its own, used to mean "the run finished, nothing is in flight".
    """

    SCAN = "scan"
    SETUP = "setup"
    LOCATE = "locate"
    EXPAND = "expand"
    READ = "read"
    ASSEMBLE = "assemble"
    PACKAGE = "package"
    #: The AI stage. Last before `DONE` because that is when it runs: it reads a *finished*
    #: bundle. It exists as its own member rather than borrowing `SCAN` because a job that is
    #: asking a model about a bundle is not scanning anything -- measured, an `ai_fanout` job
    #: reported `stage=scan` from start to finish, which tells a reader the wrong thing about
    #: what the process is doing.
    AI = "ai"
    DONE = "done"


#: The stages a run actually spends time in -- everything except the ``DONE`` sentinel.
TIMED_STAGES: tuple[JobStage, ...] = tuple(stage for stage in JobStage if stage is not JobStage.DONE)


def first_stage(kind: JobKind) -> JobStage:
    """The stage a job of this kind starts in.

    A fresh job, and a re-run, both begin somewhere, and "somewhere" is not the same for every
    kind: an assemble job's first act is to scan, while an AI job never scans at all. Hardcoding
    `JobStage.SCAN` at those call sites is what made an AI job report `scan`.
    """
    return (
        JobStage.AI
        if kind in (JobKind.AI_FANOUT, JobKind.AUDIT)
        else JobStage.SCAN
    )

#: One in-flight unit inside a stage. ``SKIPPED`` exists so that a stage which cannot
#: report detail says so, instead of looking like a stage that never ran.
STAGE_PENDING = "pending"
STAGE_RUNNING = "running"
STAGE_DONE = "done"
STAGE_SKIPPED = "skipped"
STAGE_FAILED = "failed"


class JobKind(str, Enum):
    ASSEMBLE = "assemble"
    SCAN = "scan"
    #: Accepted by the contract so the AI stage does not need a schema change. A worker
    #: in this build refuses it loudly rather than accepting work it will not do.
    AI_FANOUT = "ai_fanout"
    #: The autonomous audit: the agent harness over a whole repository. Its own kind rather than an
    #: `ai_fanout` with a flag, because the two share nothing but the word "AI": an audit consumes
    #: no bundle, produces findings instead of per-context verdicts, runs for half an hour instead
    #: of two minutes, and needs its own dedup key -- sharing one with a bundle analysis of the same
    #: workspace would make a resubmission attach to the wrong job.
    AUDIT = "audit"


class FailureMode(str, Enum):
    """Named failures. The hard rule: a job never stays ``running`` because of one.

    Deliberately absent: any "canceled" member. See the module docstring.
    """

    WORKSPACE_MISSING = "workspace_missing"
    SARIF_MISSING = "sarif_missing"
    SARIF_UNREADABLE = "sarif_unreadable"
    SCAN_FAILED = "scan_failed"
    #: The scan subprocess was terminated. Written to the *scan ledger*
    #: (``ScanRecord.failure_mode``) whenever a scan is killed, including on a user
    #: cancel -- the ledger is an audit record that outlives the job. As a
    #: :class:`JobFailure` it means "killed, and not because the user asked".
    SCAN_ABORTED = "scan_aborted"
    EXTRACTION_UNAVAILABLE = "extraction_unavailable"
    PIPELINE_EXCEPTION = "pipeline_exception"
    #: An `ai_fanout` job that named no bundle, or one that is not there. Distinct from
    #: `pipeline_exception` because nothing ran: the request did not identify any work.
    AI_BUNDLE_MISSING = "ai_bundle_missing"
    #: Every model call failed. The bundle is untouched either way, but a job that produced no
    #: verdict must not report success: it would tell the caller the analysis happened, and
    #: request deduplication would then refuse to retry it.
    AI_FAILED = "ai_failed"
    #: Claimed by a worker that then stopped heartbeating.
    WORKER_LOST = "worker_lost"
    ATTEMPTS_EXHAUSTED = "attempts_exhausted"
    INTERNAL_ERROR = "internal_error"


class JobTiming(BaseModel):
    submitted_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    queue_wait_ms: int = 0
    #: Only meaningful once ``finished_at`` is set.
    duration_ms: int = 0


class JobStageProgress(BaseModel):
    stage: JobStage
    state: str = STAGE_PENDING
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int | None = None
    #: Human-readable fact about this stage, e.g. ``scan_transport=remote`` or why a
    #: stage was skipped. Same spirit as the funnel's notes: say what is missing.
    note: str | None = None
    counters: dict[str, int] = Field(default_factory=dict)


class JobChild(BaseModel):
    """One unit of a future AI fan-out. Not produced in this build."""

    child_id: str
    label: str
    state: JobState = JobState.QUEUED
    stage: JobStage | None = None
    duration_ms: int | None = None
    result_ref: str | None = None


class JobProgress(BaseModel):
    stage: JobStage = JobStage.SCAN
    #: Always all eight stages, in ``JobStage`` order, so a consumer can render a fixed
    #: track without inferring which stages apply to this job.
    stages: list[JobStageProgress] = Field(default_factory=list)
    #: Funnel counts accumulated across the job. Overwritten in place, never summed:
    #: ``contexts`` is reported twice (predicted at the end of expand, corrected from
    #: the manifest after assemble), and a front-end must not see it double.
    counters: dict[str, int] = Field(default_factory=dict)
    units_done: int = 0
    units_total: int = 0
    unit_label: str = ""
    worker_id: str | None = None
    attempt: int = 1
    stage_started_at: datetime | None = None
    #: Refreshed on every heartbeat. This is what distinguishes a slow job from a dead
    #: worker, so the reaper must consult it before stealing work.
    worker_heartbeat_at: datetime | None = None

    @classmethod
    def fresh(cls, kind: JobKind = JobKind.ASSEMBLE) -> JobProgress:
        """Every stage, with the ones this kind of job will never run marked `skipped`.

        The eight-stage track is fixed for a reason -- a consumer renders it without inferring
        which stages apply -- so an audit job shows the six bundle-building stages as `skipped`
        with a note, rather than as `pending` rows that will never move. "This job does not use
        that stage" and "that stage has not started" are different facts, and a reader who could
        not tell them apart would wait for a packaging stage that is never coming.
        """
        stages = [JobStageProgress(stage=stage) for stage in JobStage]
        if kind is JobKind.AUDIT:
            for entry in stages:
                if entry.stage not in (JobStage.AI, JobStage.DONE):
                    entry.state = STAGE_SKIPPED
                    entry.note = "AI 审计不使用这个阶段"
        return cls(stages=stages)


class AuditOptions(BaseModel):
    """Bounded, persisted controls for one audit attempt."""

    concurrency: int | None = Field(default=None, ge=1, le=8)
    max_tokens: int | None = Field(default=None, ge=0, le=32768)
    steps_per_agent: int | None = Field(default=None, ge=4, le=16)
    timeout_s: float | None = Field(default=None, ge=30, le=600)
    temperature: float | None = Field(default=None, ge=0, le=2)
    max_rounds: int | None = Field(default=None, ge=1, le=5)


class JobRequest(BaseModel):
    """What to run. Mirrors the HTTP request but does not import it."""

    workspace: str
    sarif_path: str | None = None
    rules: list[str] = Field(default_factory=list)
    rule_config: str | None = None
    include_globs: list[str] = Field(default_factory=list)
    exclude_globs: list[str] = Field(default_factory=list)
    #: ``BudgetConfig.model_dump()`` rather than the model itself: a plain dict keeps the
    #: contract's input shape from drifting every time ``aegis_core`` gains a knob.
    budget: dict[str, Any] | None = None
    max_findings: int | None = None
    lsp: bool = True
    package_name: str | None = None
    #: Which finished bundle to act on. Only the AI stage uses it: that job consumes a bundle
    #: instead of producing one, so `workspace` alone does not identify the work.
    bundle_id: str | None = None
    audit_options: AuditOptions | None = None


class JobSubmission(BaseModel):
    schema_version: str = SCHEMA_VERSION
    job_id: str
    kind: JobKind = JobKind.ASSEMBLE
    request: JobRequest
    fingerprint: str
    submitted_at: datetime = Field(default_factory=_utcnow)
    submitted_by: str = "gateway"
    children: list[JobChild] = Field(default_factory=list)


class ArtifactRef(BaseModel):
    kind: str  # "bundle" | "sarif" | "child_bundle"
    ref: str
    path: str | None = None
    #: Computed when read against the filesystem, not stored as a fact.
    available: bool = True


class JobResult(BaseModel):
    """Pointers, not payloads: the bundle itself stays on disk."""

    bundle_id: str | None = None
    package_path: str | None = None
    run_id: str | None = None
    sarif_path: str | None = None
    #: The ledger of the scan this job ran -- present even when the job was canceled or
    #: failed, because that is the only place such a run is recorded.
    scan_record: ScanRecord | None = None
    warnings: list[str] = Field(default_factory=list)
    artifacts: dict[str, ArtifactRef] = Field(default_factory=dict)


class JobFailure(BaseModel):
    mode: FailureMode
    message: str
    detail: str | None = None
    attempt: int = 1
    recoverable: bool = False
    scan_record: ScanRecord | None = None


class Job(BaseModel):
    schema_version: str = SCHEMA_VERSION
    job_id: str
    kind: JobKind = JobKind.ASSEMBLE
    state: JobState = JobState.QUEUED
    #: True from the moment a cancel is accepted. While ``state == RUNNING`` this is the
    #: one and only "accepted, still winding down" signal; once the state is terminal it
    #: is audit information only.
    cancel_requested: bool = False
    cancel_requested_at: datetime | None = None
    submission: JobSubmission
    timing: JobTiming
    progress: JobProgress = Field(default_factory=JobProgress.fresh)
    result: JobResult | None = None
    failure: JobFailure | None = None
    #: Monotonic. Lets a client discard out-of-order pushes without trusting transport
    #: ordering.
    revision: int = 0

    @model_validator(mode="after")
    def _canceled_is_not_a_failure(self) -> Job:
        if self.state is JobState.CANCELED and self.failure is not None:
            raise ValueError(
                "a canceled job must not carry a failure: cancellation is a user action, "
                f"not a fault (got failure.mode={self.failure.mode})"
            )
        return self

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_STATES


class JobSummary(BaseModel):
    """The list view: enough for a first screen, without the per-stage detail.

    Seven stage entries per job is the bulk of a `Job`, and a list page renders none of
    them. Trimming here is not tidiness -- it is the difference between one request that
    paints a queue view and one that drags every job's full history across.
    """

    job_id: str
    kind: JobKind = JobKind.ASSEMBLE
    state: JobState = JobState.QUEUED
    cancel_requested: bool = False
    submitted_at: datetime
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: int = 0
    stage: JobStage = JobStage.SCAN
    counters: dict[str, int] = Field(default_factory=dict)
    units_done: int = 0
    units_total: int = 0
    unit_label: str = ""
    attempt: int = 1
    #: Which repository the job runs against, raw. A list view has to answer "what is this job
    #: about?" and the only other place that string lives is the full `Job`; fetching one job per
    #: row to render a table is the fan-out this field exists to avoid. It stays a raw path -- no
    #: derived counters and no resolved/rebased form, because a summary that paraphrases is worse
    #: than one that omits.
    workspace: str | None = None
    bundle_id: str | None = None
    failure_mode: FailureMode | None = None
    revision: int = 0

    @classmethod
    def of(cls, job: Job) -> JobSummary:
        return cls(
            job_id=job.job_id,
            kind=job.kind,
            state=job.state,
            cancel_requested=job.cancel_requested,
            submitted_at=job.timing.submitted_at,
            started_at=job.timing.started_at,
            finished_at=job.timing.finished_at,
            duration_ms=job.timing.duration_ms,
            stage=job.progress.stage,
            counters=dict(job.progress.counters),
            units_done=job.progress.units_done,
            units_total=job.progress.units_total,
            unit_label=job.progress.unit_label,
            attempt=job.progress.attempt,
            workspace=job.submission.request.workspace,
            bundle_id=(job.result.bundle_id if job.result else None),
            failure_mode=(job.failure.mode if job.failure else None),
            revision=job.revision,
        )


class QueueStatus(BaseModel):
    """What the queue itself is doing, alongside the jobs.

    `queued` climbing while `lag` stays flat is the signature of jobs that were submitted
    and never claimed -- the one failure mode that neither the reaper nor the running sweep
    can see, because it happens before either has anything to look at.
    """

    workers_alive: int = 0
    pending: int = 0
    lag: int | None = None
    stream_length: int = 0
    queued: int = 0
    degraded: bool = False
    detail: str | None = None


class JobAcceptedResponse(BaseModel):
    """The 202 body: something was started and the answer will change.

    Deliberately not the full `Job` -- the caller gets an id to poll and a flag telling it
    whether this call did anything. `deduplicated=True` means "this request was already in
    flight and you are attached to it", which is the visible half of the idempotency
    promise: the caller learns its submission did not create a second run.
    """

    job_id: str
    state: JobState
    deduplicated: bool = False
    revision: int = 0


class JobListResponse(BaseModel):
    jobs: list[JobSummary] = Field(default_factory=list)
    total: int = 0
    queue: QueueStatus = Field(default_factory=QueueStatus)


def canonical_json(value: Any) -> str:
    """Stable JSON for hashing: key order in the source must not change the fingerprint."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def request_fingerprint(
    request: JobRequest, *, lsp_config_fingerprint: str = "", kind: JobKind = JobKind.ASSEMBLE
) -> str:
    """A digest of everything that can change what a job produces.

    Two submissions with the same fingerprint are the same request, so the second one is
    attached to the first job instead of doing the work twice. That makes every omitted
    field a correctness bug rather than a missed optimisation: the tests assert that
    ``lsp``, ``max_findings``, ``package_name``, the globs and the *contents* of a SARIF
    file all separate two fingerprints.

    ``kind`` and ``bundle_id`` were both missing, and the symptom was not a missed optimisation
    but a false success: an `ai_fanout` job for one bundle produced the same fingerprint as an
    earlier `scan` job on the same workspace, so it was deduplicated onto that job, reused its
    id, and "succeeded" without analysing anything at all. Measured on the live stack -- the
    report on disk was 25 minutes older than the job that claimed to have written it.

    ``lsp_config_fingerprint`` is the sha1 of the language-server catalog, passed in by
    the caller (the contract may not read files). Two catalogs at the same path with
    different contents select different servers and therefore different bundles.
    """
    workspace = Path(request.workspace).expanduser().resolve().as_posix()

    if request.sarif_path:
        sarif = Path(request.sarif_path).expanduser().resolve()
        stat = sarif.stat() if sarif.exists() else None
        # Path alone is not enough: the same path can be rewritten between submissions,
        # and a re-run of the old bundle would be silently reused.
        artifact = (
            f"sarif:{sarif.as_posix()}:"
            f"{stat.st_size if stat else -1}:{int(stat.st_mtime) if stat else -1}"
        )
    else:
        artifact = f"rule_config:{request.rule_config or ''}"

    extra = [
        f"kind:{kind.value}",
        f"bundle_id:{request.bundle_id or ''}",
        f"include:{','.join(sorted(request.include_globs))}",
        f"exclude:{','.join(sorted(request.exclude_globs))}",
        f"lsp:{int(request.lsp)}",
        f"max_findings:{request.max_findings if request.max_findings is not None else ''}",
        f"package_name:{request.package_name or ''}",
        f"lsp_config:{lsp_config_fingerprint}",
    ]
    if kind is JobKind.AUDIT and request.audit_options is not None:
        selected_options = request.audit_options.model_dump(exclude_none=True)
        if selected_options:
            extra.append(f"audit_options:{canonical_json(selected_options)}")
    return _sha1(
        workspace,
        artifact,
        canonical_json(request.budget or {}),
        ",".join(sorted(request.rules)),
        *extra,
        length=40,
    )


def job_id_for(fingerprint: str) -> str:
    """Derive the job id from the fingerprint.

    Kept at the full 40 hex characters: this id is both the idempotency key and the
    string a user copies out of a UI or a log, and those two jobs want different
    guarantees. A short id would need a collision story; the fingerprint already has one.
    """
    return "J-" + _sha1(fingerprint, length=40)
