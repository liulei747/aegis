"""The shared vocabulary of the agent harness.

Every agent in the harness reads from and writes to one **blackboard**, so the types here are
the only thing that keeps them agreeing about what a "candidate", a "verdict" or a "scope" is.
They live in ``aegis_contracts`` rather than in the harness package for the same reason the job
contract does: they are the interface, and an implementation detail that leaks into them is a
detail no other agent can rely on.

Two rules in this file are load-bearing rather than stylistic:

* **A candidate is not a finding.** Discovery produces candidates -- things worth checking. Only
  Validation, with evidence, turns one into a confirmed finding, and the Attack-Path stage then
  argues about whether a human should act on it. Keeping those three separate is what stops the
  harness from reporting every suspicious line it reads.
* **`dataflow_verify` is never told what the sink is.** It takes the site of the static hit and
  derives the sink from the code, exactly as the assembly pipeline does. A tool that accepted a
  caller-supplied sink would let the model -- or a prompt injection in the repository under
  review -- nominate the answer, and every "confirmed" verdict downstream would inherit it.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ─────────────────────────────────────────────────────────── tools

class ToolName(str, Enum):
    """The tools an agent may call. Deliberately few: every tool is reach a model can abuse."""

    READ = "read"
    LIST_FILES = "list_files"
    SHELL = "shell_command"
    #: Regex search across the workspace, as a tool rather than as a shell command. Measured on the
    #: `upp-module-infra` audit: of 5198 agent steps, 1344 were `shell_command` and most of them were
    #: a search -- one round trip to build the command, one to read its output -- while the same
    #: search as a native tool is one call with a bounded, structured result. It also removes the
    #: only reason an agent needed a shell at all for the common case, which is the case a reviewer
    #: should be able to reason about by reading one tool instead of a command policy.
    GREP = "grep"
    DATAFLOW_VERIFY = "dataflow_verify"
    #: The one tool that *writes*. Everything else reads the repository; this records a fact on the
    #: blackboard, immediately, where every other agent can see it. It exists because the opening
    #: agents (recon, threat modelling) investigate concurrently and their findings used to be merged
    #: only when their run *finished* -- so a second agent starting at the same time reasoned against
    #: an empty board, and the run had to serialise them to avoid that.
    RECORD = "record"
    #: The other half of `record`: read what is on the blackboard *now*, including what the agent
    #: running beside you has just written. A write-only shared medium is not a shared medium -- the
    #: threat model's task is fixed when its run starts, so without this tool the facts recon records
    #: one step later would only ever reach the planner and the report, never its peer.
    BOARD = "board"


class ToolCall(BaseModel):
    """One tool invocation proposed by the model.

    `reason` is required: a ReAct transcript whose steps cannot be explained after the fact is
    not auditable, and this harness's output ends up in a security report.
    """

    tool: ToolName
    arguments: dict[str, Any] = Field(default_factory=dict)
    reason: str = ""


class ToolResult(BaseModel):
    """What came back.

    `summary` is what the model reads next; `data` is the structured form the blackboard keeps.
    They are separate because a tool's raw output can be megabytes (a grep over a repository)
    while the model's context is not, and truncation has to be visible rather than silent.

    ``tool`` is optional because a *refused* call has no tool to name: the model asked for
    something that is not in its allow-list, so the enum cannot represent it. Recording the
    refusal as ``tool=None`` plus an ``error`` saying what is callable keeps the transcript
    honest -- attributing that failure to one of the four real tools would blame a tool that was
    never called.
    """

    tool: ToolName | None = None
    ok: bool
    summary: str = ""
    data: dict[str, Any] = Field(default_factory=dict)
    error: str | None = None
    truncated: bool = False


class ShellCommandPolicy(BaseModel):
    """The allow-list `shell_command` is held to.

    Read-only by construction: the harness reads a repository it did not write and must not be
    able to change it. See `services/harness/tools/shell.py` for how each clause is enforced --
    every one of them exists because a shell makes it easy to reach outside what a "read a file"
    tool would.
    """

    allowed_binaries: list[str] = Field(
        default_factory=lambda: [
            "ls", "cat", "head", "tail", "wc", "grep", "rg", "find", "file", "stat",
            "sort", "uniq", "cut", "tr", "sed", "awk", "basename", "dirname", "realpath",
            "git", "tree", "du", "diff",
        ]
    )
    #: Refused even though the binary is allowed: `git` can write (`commit`, `checkout`),
    #: `find` can delete (`-delete`), `sed`/`awk` can write in place.
    #:
    #: The options are spelled the way the binaries spell them, with their dashes. `--in-place` used
    #: to be recorded as `in-place`, which no argument ever equals -- `sed --in-place` and
    #: `cat --in-place` both slipped past the equality test, and only the old substring matcher
    #: caught them. That matcher is gone (it refused `grep permitAll` because the word contains
    #: "rm"), so the entry has to be reachable by name: `services/harness/tools/shell.py` compares
    #: flag names with the dashes stripped, which makes `-delete` and `--in-place` one shape.
    forbidden_subcommands: list[str] = Field(
        default_factory=lambda: [
            "commit", "checkout", "reset", "clean", "apply", "stash", "add", "rm", "mv",
            "push", "pull", "fetch", "merge", "rebase", "cherry-pick", "init", "clone",
            "-delete", "-exec", "-execdir", "--in-place", "-i",
        ]
    )
    max_seconds: float = 20.0
    max_output_bytes: int = 60_000


# ─────────────────────────────────────────────────────────── blackboard

class ProjectContext(BaseModel):
    """What the repository is. Filled by the recon agent before anything else."""

    workspace: str
    languages: dict[str, int] = Field(default_factory=dict)
    build_systems: list[str] = Field(default_factory=list)
    entry_points: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ArchitectureMap(BaseModel):
    """Where the trust boundaries are. The threat model is only as good as this."""

    components: list[dict[str, Any]] = Field(default_factory=list)
    trust_boundaries: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class ThreatModel(BaseModel):
    """What is worth attacking here, and why. Also what is explicitly out of scope."""

    assets: list[str] = Field(default_factory=list)
    actors: list[str] = Field(default_factory=list)
    threats: list[dict[str, Any]] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class SecurityInventory(BaseModel):
    """Security-relevant surfaces established by the inventory agent after opening analysis."""

    entry_points: list[dict[str, Any]] = Field(default_factory=list)
    authorization_controls: list[dict[str, Any]] = Field(default_factory=list)
    dangerous_capabilities: list[dict[str, Any]] = Field(default_factory=list)
    configurations: list[dict[str, Any]] = Field(default_factory=list)
    dependencies: list[dict[str, Any]] = Field(default_factory=list)
    state_controls: list[dict[str, Any]] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)
    files_reviewed: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)


class WorkItemState(str, Enum):
    PLANNED = "planned"
    RUNNING = "running"
    DONE = "done"
    ABANDONED = "abandoned"
    BLOCKED = "blocked"
    CANCELED = "canceled"


class WorkItemKind(str, Enum):
    FILE_REVIEW = "file_review"
    INVESTIGATION = "investigation"
    VALIDATION = "validation"
    ATTACK_PATH = "attack_path"


class WorkAttempt(BaseModel):
    run_id: str
    agent: str
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None
    stop_reason: str = ""
    steps: int = 0
    error: str = ""


class WorkGap(BaseModel):
    gap_id: str
    kind: Literal["unread", "basic_check", "relationship", "tool_failure"]
    question: str
    file: str
    line: int = Field(ge=1)
    evidence_refs: list[str] = Field(default_factory=list)
    state: Literal["pending", "resolved", "blocked"] = "pending"
    reason: str = ""
    lead_id: str = ""


class WorkItem(BaseModel):
    """One unit of investigation the coordinator decided to spend budget on.

    The ledger records *why* each was opened, because the interesting failure of a coverage-driven
    scan is not "it missed a file" but "it decided the file was not worth opening".
    """

    work_id: str
    scope_id: str
    title: str
    rationale: str
    state: WorkItemState = WorkItemState.PLANNED
    opened_at: datetime = Field(default_factory=_utcnow)
    closed_at: datetime | None = None
    steps_used: int = 0
    kind: WorkItemKind = WorkItemKind.INVESTIGATION
    files: list[str] = Field(default_factory=list)
    completion_criteria: str = ""
    question: str = ""
    priority: int = Field(default=2, ge=1, le=3)
    status_reason: str = ""
    candidate_ids: list[str] = Field(default_factory=list)
    attempts: list[WorkAttempt] = Field(default_factory=list)
    read_files: int = 0
    unread_ranges: dict[str, list[tuple[int, int | None]]] = Field(default_factory=dict)
    pending_updates: list[str] = Field(default_factory=list)
    gaps: list[WorkGap] = Field(default_factory=list)
    gap_continuations: int = 0
    no_progress_continuations: int = 0
    merged_into: str = ""


class CoverageState(str, Enum):
    #: Nothing has looked at it yet.
    UNSEEN = "unseen"
    #: Looked at, and what was found is judged sufficient for the threat model.
    SUFFICIENT = "sufficient"
    #: Looked at, but the evidence is not enough to close it -- the closure loop re-dispatches.
    INSUFFICIENT = "insufficient"
    #: Deliberately skipped, with a reason. Distinct from `unseen`: "we decided not to" is a
    #: different claim from "we never looked", and a reader needs to be able to tell them apart.
    EXCLUDED = "excluded"


class CoverageEntry(BaseModel):
    scope_id: str
    title: str
    state: CoverageState = CoverageState.UNSEEN
    reason: str = ""
    candidates: int = 0
    confirmed: int = 0


class EvidenceKind(str, Enum):
    SEMANTIC = "semantic"
    DATAFLOW = "dataflow"


class Candidate(BaseModel):
    """Something worth checking. Not yet a finding."""

    evidence_version: int = 1
    candidate_id: str
    scope_id: str
    title: str
    vulnerability_type: str
    file: str
    line: int | None = None
    #: The method the site is in, when the harness could resolve it.
    method: str | None = None
    rationale: str = ""
    #: Free-form pointers to what made this worth recording (tool results, snippets).
    evidence: list[str] = Field(default_factory=list)
    #: The entries that reach this site, as discovery named them (`GET /admin-api/x
    #: (XController.java:41)`). Kept per *instance*, not per claim, on purpose: candidates merge by
    #: sink location, and two records of one sink routinely name different entries -- one anonymous,
    #: one guarded. Merging those into a single verdict is right; forgetting that the anonymous entry
    #: exists is not, so the list rides along to the validator, the attack-path agent and the finding.
    entry_points: list[str] = Field(default_factory=list)
    discovered_by: str = ""
    discovered_at: datetime = Field(default_factory=_utcnow)


class DataflowEvidence(BaseModel):
    """What `dataflow_verify` came back with.

    `source`/`sink` are the *derived* ends, and `path` is the chain between them. `derived` says
    whether they came from the tool or from the model's reading -- a verdict resting on a
    derived path and one resting on the model's say-so are not the same claim.
    """

    derived: bool = False
    source: str = ""
    sink: str = ""
    path: list[str] = Field(default_factory=list)
    sanitizers: list[str] = Field(default_factory=list)
    methods: list[str] = Field(default_factory=list)
    error: str | None = None


class VerdictKind(str, Enum):
    CONFIRMED = "confirmed"
    REJECTED = "rejected"


class CandidateVerdict(BaseModel):
    evidence_version: int = 1
    candidate_id: str
    verdict: VerdictKind
    evidence_kind: EvidenceKind
    dataflow: DataflowEvidence | None = None
    reasons: list[str] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    decided_at: datetime = Field(default_factory=_utcnow)


class AttackPath(BaseModel):
    """Why a human should (or should not) act on a confirmed candidate.

    Confirmed means "the code does this". This stage asks the separate question of whether
    anyone can make it happen, which is where most real-world severity comes from.
    """

    evidence_version: int = 1
    candidate_id: str
    reachable: bool = False
    entry_points: list[str] = Field(default_factory=list)
    preconditions: list[str] = Field(default_factory=list)
    auth_conditions: list[str] = Field(default_factory=list)
    state_conditions: list[str] = Field(default_factory=list)
    impact: str = ""
    alternative_paths: list[str] = Field(default_factory=list)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    reasons: list[str] = Field(default_factory=list)


class FinalFinding(BaseModel):
    """What leaves the harness.

    ``affected_locations`` carries the other places the *same* claim was recorded at. Agents overlap:
    one site is reached from several scopes, and a run that filed the same ``ORDER BY ${}`` sink eight
    times reported eight findings for one vulnerability. The candidates are still all recorded and all
    judged -- coverage is counted per scope and depends on that -- but the finding is one entry, and
    this is where the other instances stay visible instead of being dropped. ``file``/``line`` are the
    representative location, not the only one.
    """

    finding_id: str
    candidate_id: str
    title: str
    vulnerability_type: str
    file: str
    line: int | None = None
    severity: str = "medium"
    evidence_kind: EvidenceKind = EvidenceKind.SEMANTIC
    dataflow: DataflowEvidence | None = None
    attack_path: AttackPath | None = None
    summary: str = ""
    #: Other recorded instances of the same claim, as `{candidate_id, scope_id, file, line, title}`.
    affected_locations: list[dict] = Field(default_factory=list)


class CrossScopeLead(BaseModel):
    """An independent question for the coordinator's persistent planning inbox.

    Cross-file tracing needed for the current question stays with its investigator;
    only independent questions need scheduling. Legacy records default to pending.
    """

    lead_id: str
    from_scope: str
    to_scope: str
    title: str
    detail: str = ""
    raised_by: str = ""
    raised_at: datetime = Field(default_factory=_utcnow)
    question: str = ""
    file: str = ""
    line: int | None = None
    evidence_refs: list[str] = Field(default_factory=list)
    source_work_id: str = ""
    status: str = "pending"
    linked_work_id: str = ""
    processing_reason: str = ""
    sequence: int = 0


class InvestigationRecord(BaseModel):
    record_id: str
    work_id: str
    scope_id: str
    category: str = "hypothesis"
    file: str
    line: int
    text: str
    created_at: datetime = Field(default_factory=_utcnow)


# ─────────────────────────────────────────────────────────── transcript

class AgentStep(BaseModel):
    """One turn of a constrained ReAct loop: what the model said, what it did, what happened."""

    index: int
    thought: str = ""
    call: ToolCall | None = None
    result: ToolResult | None = None
    at: datetime = Field(default_factory=_utcnow)


class AgentRun(BaseModel):
    """One agent's whole turn, kept for audit and for the report's reasoning trail."""

    run_id: str
    agent: str
    scope_id: str
    model: str = ""
    steps: list[AgentStep] = Field(default_factory=list)
    #: Workspace-relative files this run did **not** read from disk because the run had already read
    #: them completely and the bytes came out of the blackboard instead (`agents.replayable_reads`).
    #: Empty for a run that fetched everything itself. Derived from the seeded `index=0` steps, not
    #: reported by the agent, for the same reason the coverage ledger is: a claim is not evidence.
    reused_files: list[str] = Field(default_factory=list)
    #: Why it stopped: `finished`, `budget`, `error` or `no_tool`. A run that ended because the
    #: step budget ran out produced whatever it had, and the report has to say so.
    stop_reason: str = ""
    #: True when the answer this run ended on was **recovered from a reply the output limit cut in
    #: half** (`react._salvage_final`). The fields are the model's, but lists may stop early, so a
    #: reader has to be able to tell a salvaged answer from a complete one. Set only when the
    #: fallback was actually spent -- a run that retried and answered properly is not salvaged.
    salvaged: bool = False
    output: dict[str, Any] = Field(default_factory=dict)
    started_at: datetime = Field(default_factory=_utcnow)
    finished_at: datetime | None = None


# ─────────────────────────────────────────────────────────── blackboard root

class OpeningConvergence(BaseModel):
    """Whether the two opening agents finished having read each other's work.

    The opening stage (recon and threat modelling) runs concurrently, and each agent's task text is
    fixed when its run starts -- so a fact one of them records is only shared if the other reads the
    blackboard afterwards. The stage therefore repeats until neither has unread material, and this
    record is what the report reads to say whether that actually happened.

    The watermark is *derived from real `board` calls* (the revision each read served), never from the
    model saying it has caught up: same rule as the coverage table, which counts real `read` calls
    rather than a model's claim to have looked. A pass cap that runs out is recorded as
    `converged=False` with the backlog that was still unread -- an opening stage that did not converge
    is a fact about the run, not something to round up to "done".
    """

    passes: int = 1
    converged: bool = True
    #: Per opening agent: the highest board revision it is known to have read.
    watermarks: dict[str, int] = Field(default_factory=dict)
    #: Per opening agent: how many substantive publications it never read (empty when converged).
    unread: dict[str, int] = Field(default_factory=dict)
    note: str = ""


class Blackboard(BaseModel):
    """The single shared state every agent reads and writes.

    `revision` increments on every applied update. Two agents acting on the same revision is
    normal (they run in parallel); two agents *overwriting* each other is not, which is why
    updates are expressed as appends and merges rather than as whole-object replacements.
    """

    execution_budget: dict[str, Any] = Field(default_factory=dict)
    run_id: str
    workspace: str
    revision: int = 0
    project: ProjectContext | None = None
    architecture: ArchitectureMap | None = None
    threats: ThreatModel | None = None
    #: AI-established security surface inventory; still context, not candidates or findings.
    security_inventory: SecurityInventory | None = None
    work: list[WorkItem] = Field(default_factory=list)
    coverage: list[CoverageEntry] = Field(default_factory=list)
    candidates: list[Candidate] = Field(default_factory=list)
    verdicts: list[CandidateVerdict] = Field(default_factory=list)
    verdict_history: list[CandidateVerdict] = Field(default_factory=list)
    attack_path_history: list[AttackPath] = Field(default_factory=list)
    attack_paths: list[AttackPath] = Field(default_factory=list)
    leads: list[CrossScopeLead] = Field(default_factory=list)
    investigation_records: list[InvestigationRecord] = Field(default_factory=list)
    findings: list[FinalFinding] = Field(default_factory=list)
    #: Every agent run, in order. The report's "how do you know" section is built from these.
    runs: list[AgentRun] = Field(default_factory=list)
    #: How many discovery→closure cycles the coordinator actually ran. Recorded rather than derived
    #: from `runs`, because a dry run has no runs at all and a derived count would then read 0 in a
    #: report whose own text says three rounds ran -- the exact contradiction this field prevents.
    rounds_run: int = 0
    #: How the opening pair converged (or did not): passes run, each agent's read watermark, and what
    #: was still unread when the stage stopped. None for a dry run, which has no opening agents.
    opening: OpeningConvergence | None = None
    closed: bool = False
    closure_note: str = ""
    created_at: datetime = Field(default_factory=_utcnow)
    updated_at: datetime = Field(default_factory=_utcnow)
