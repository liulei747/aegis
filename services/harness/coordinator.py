"""The coordinator: the one thing allowed to decide what the run spends its budget on.

The agents are deliberately narrow. Each of them sees one scope or one candidate, and a
cross-scope lead is *recorded* rather than followed, because an agent that chases its own lead is
how a scan ends up deep in one corner with no coverage anywhere else. This module is the other half
of that arrangement: it owns the pipeline, the plan, the coverage ledger, and every bound.

The stage sequence, and the bound that stops each loop:

1. **recon** + **threat model** -- independent, run concurrently. Bound: `steps_per_agent`.
2. **planning** -- the survey-derived scopes are refined/confirmed by a planner call, which decides
   which areas are worth investigating. Bound: `max_scopes_per_round`.
3. **discovery**, then **validation**, then **attack paths**. Discovery fans out over the plan's
   scopes at `concurrency`; each scope stops at `candidates_per_scope`; each agent stops at
   `steps_per_agent`. Validation and attack paths are paid for once per *claim* rather than once per
   recorded candidate: overlapping scopes file the same site repeatedly, and `(file, line, type)`
   decides when two records are one claim. The decision is copied to every member, because a
   candidate left without a verdict would hold its scope `INSUFFICIENT` forever.
4. **coverage closure** -- every scope is decided `SUFFICIENT` / `INSUFFICIENT` / `EXCLUDED` with a
   reason. `INSUFFICIENT` scopes are re-dispatched for discovery, and the whole discovery→closure
   cycle repeats while (a) a scope is still `INSUFFICIENT` and (b) rounds remain. Bound:
   `max_rounds`.
5. **close**: emit one `FinalFinding` per claim -- carrying the claim's other recorded locations in
   `affected_locations` -- persist the blackboard, write the report.

Three things this module does on purpose, each of which is a failure mode it is avoiding:

* **A stage that produced nothing is recorded as a stage that produced nothing.** Every `AgentRun`
  goes on the blackboard whether it finished, ran out of steps or errored, and the coverage reason
  for its scope says which. A run that stopped early is visible, not silently reported as "found
  nothing".
* **Rejected candidates are kept and reported.** A reader deciding whether to trust the findings is
  really asking what was considered and dismissed, so `CandidateVerdict`s for rejections are part of
  the answer rather than debug output.
* **`--dry-run` makes no model calls at all.** It runs the deterministic survey, the plan, the
  signal scan and coverage closure, and stops. That is what makes it usable to check the plumbing
  before spending tokens -- and it is the reason the coordinator must not need the tool layer to
  plan.
"""

from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, ThreadPoolExecutor, wait
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis_contracts.harness import (
    AgentStep,
    ArchitectureMap,
    AttackPath,
    Blackboard,
    Candidate,
    CandidateVerdict,
    CoverageState,
    CrossScopeLead,
    EvidenceKind,
    FinalFinding,
    InvestigationRecord,
    OpeningConvergence,
    ProjectContext,
    ThreatModel,
    ToolName,
    VerdictKind,
    WorkGap,
    WorkItem,
    WorkItemKind,
    WorkItemState,
)
from aegis_core.cancel import CanceledAbort
from aegis_core.logging import get_logger
from services.harness import agents, coverage, report, survey
from services.harness import blackboard as bb
from services.harness import trail as trail_mod
from services.harness.budget import BudgetClient, BudgetStop, RunBudget
from services.harness.react import AgentRun, ToolLayerUnavailable
from services.harness.tasks import TaskLedger

log = get_logger(__name__)

#: A coverage reason that says a scope still owns files nobody read end to end. Named because two
#: places depend on recognising it: the closure rule writes it, and the marginal-yield stop refuses to
#: end the loop while a scope is INSUFFICIENT for this reason -- an unread file is a known target,
#: not a marginal-yield question.
UNREAD_REASON_MARKER = "覆盖率按 read 调用台账计算，搜索命中不算审完"

#: Sentinel for "this claim's `dataflow_verify` has not been run yet". Distinct from `None`, which is
#: the real answer for a claim that is not taint-shaped at all -- see `_validation_single`. Defined up
#: here because it is a *default argument*, evaluated when the class body runs.
_PREFETCH: Any = object()


class ModelUnavailableStop(BaseException):
    """Stop the run after the provider has failed across several independent agents."""

#: The heuristic plainer's reason prefix. Named so the report can mark these scopes as
#: derived-from-directory-names rather than derived-from-a-model, which is a materially weaker
#: claim and must not look identical.
SURVEY_RATIONALE_PREFIX = "survey:"


@dataclass
class HarnessConfig:
    """Every bound on the run. All of them are configurable, and all of them have a default.

    The defaults are chosen so that an accidental run is small: the failure mode of a harness with
    generous defaults is a paid run nobody meant to start.
    """

    #: Discovery→closure cycles after the first. 3 means round 0 plus two re-dispatch rounds.
    max_rounds: int = 3
    #: How many *new places* a round must find in a scope to be worth another round for it.
    #:
    #: The loop used to continue on any new place at all, and measured on a five-file Python fixture
    #: that meant four rounds of discovery for 243 lines of code: every round the model found one or
    #: two more lines to comment on, so nothing ever converged and the run stopped only because
    #: `max_rounds` ran out (88 agent runs, 564 model calls). A round that adds a single place is not
    #: evidence that the scope is unreviewed -- it is evidence that the reviewer is now annotating.
    #: `0` restores the old behaviour ("any new place justifies a round").
    min_new_places_per_round: int = 2
    #: How many times a scope that *failed to produce a run* (agent error, or a run that stopped on
    #: `budget` with nothing usable) may be re-dispatched. Beyond it the scope stays INSUFFICIENT and
    #: stops being paid for.
    #:
    #: Measured on the `upp-module-infra` audit: 3 scopes ended `budget`/`error` in **every one of the
    #: 4 rounds**, and each round re-dispatched all three -- 9 agent runs whose outcome was known
    #: before they started. One retry is kept because a failure can be transient (a gateway 504 that
    #: killed a run says nothing about the scope); a third is a pattern, not bad luck.
    max_scope_retries: int = 1
    #: Stop starting new rounds when the last round's new places are below this fraction of every
    #: place found so far. `0.0` disables the clause and restores "keep going while a scope is
    #: INSUFFICIENT and has new places".
    #:
    #: Measured on the module audit, per round: +82, +60, +28, +22 new candidates (the last two costing
    #: 25 minutes and returning 19 of the run's 161 confirmed findings). At 0.25 the loop stops after
    #: round 2 -- round 2's 28 places are 20% of the 142 found so far -- and keeps rounds 0 and 1,
    #: whose yields were 100% and 73%. The clause is a *ratio* rather than a count because a large
    #: repository legitimately yields more per round than a small one.
    min_round_yield_ratio: float = 0.25
    #: Discovery dispatch batch size; all planned tasks survive. Independent of model concurrency.
    max_scopes_per_round: int = 12
    planner_calls: int = 4
    planner_wait_seconds: float = 60.0
    planner_min_interval: float = 5.0
    max_lead_continuations: int = 1
    max_gap_continuations: int = 2
    max_no_progress_continuations: int = 1
    max_claim_attempts: int = 3
    max_run_seconds: float = 7200
    max_model_calls: int = 512
    max_model_tokens: int = 0
    max_cost_usd: float = 0
    input_usd_per_million: float = 0
    output_usd_per_million: float = 0
    #: Candidates recorded per scope. Bounds both the blackboard and the validation bill.
    candidates_per_scope: int = 5
    #: Turns per agent run. The hard budget the ReAct loop holds itself to.
    steps_per_agent: int = 8
    #: Model calls in flight at once, inherited from `AIConfig.concurrency` when built from config.
    concurrency: int = 4
    #: Every model call already retries four times. If this many independent agent runs still end
    #: in AIUnavailable, the provider is down rather than one scope being unlucky. Stop dispatching
    #: so the remaining task ledger can be retried after service recovery.
    max_consecutive_ai_unavailable: int = 4
    #: `--dry-run`: plan and scan deterministically, make no model calls, dispatch no agents.
    dry_run: bool = False
    #: Characters of source the harness inlines into a validation or attack-path task. `0` disables
    #: it, which is a real mode rather than a leftover: a run with and a run without is the only way
    #: to measure what the packet is worth.
    #:
    #: Measured on a five-file Python project: 471 of 823 model round trips were `read` calls, because
    #: every agent read the same six files from scratch (`repo.py` 88 times). The packet replaces the
    #: reads of what it contains; it never replaces the tools, and the coverage ledger keeps counting
    #: real `read` calls exactly as before.
    material_budget: int = 12_000
    #: How many *different* claims one judging run may carry -- validation first, and attack paths
    #: with the same bound. `1` is the historical behaviour: one run per claim.
    #:
    #: Why the batched form exists, measured on the `upp-module-infra` audit (177 Java files): 139
    #: validation runs for 98 distinct claims, 196 s each, 110 of the run's 274 minutes, plus 72
    #: attack-path runs for 161 confirmed candidates. Reading was the repeated part -- 2940 `read`
    #: calls over 203 distinct files, `FileController.java` alone read 261 times -- and claims from one
    #: controller share almost all of it. Batching does not merge decisions: a run judges N claims, each
    #: keeps its own verdict, confidence and reasons, and a claim that can only be settled by a traced
    #: path answers `needs_dataflow` and is re-run alone.
    #:
    #: Off by default because it changes what a judging run *is*, and a quality change of that kind
    #: should be switched on deliberately with a run in front of it.
    claim_batch_size: int = 1


@dataclass
class HarnessResult:
    """What a finished (or stopped) run leaves behind."""

    blackboard: Blackboard
    run_dir: Path
    report_path: Path | None = None
    dry_run: bool = False
    #: Set when the run could not use the tool layer at all. The CLI turns this into an exit code.
    fatal: str | None = None
    notes: list[str] = field(default_factory=list)


class HarnessCoordinator:
    """Owns one run: the blackboard, the plan, the ledger and the bounds."""

    #: How much of the board the `board` tool hands an agent. Bounded because the tool result is spent
    #: out of the asking agent's context: a component list is cheap to read and useful to a peer, while
    #: the whole of `notes` (one entry per recorded note, growing all run) would pay for the board twice.
    BOARD_COMPONENTS_LIMIT = 40
    BOARD_LIST_LIMIT = 25

    def __init__(
        self,
        *,
        workspace: Path,
        config: HarnessConfig | None = None,
        client: Any = None,
        out_dir: Path | None = None,
        run_id: str | None = None,
        context: Any = None,
        dataflow: Any = None,
        trail: trail_mod.Trail | None = None,
        abort: Callable[[], bool] | None = None,
    ) -> None:
        self.workspace = Path(workspace).resolve()
        self.config = config or HarnessConfig()
        self.budget = RunBudget(self.config)
        self.client = client
        #: Where events go while the run is happening. Defaults to a trail with no sinks, so a
        #: caller that does not care pays nothing and no code path has to check for `None`.
        self.trail = trail or trail_mod.disabled()
        #: Asked at every stage boundary and before every dispatched agent. An audit is a 30-minute
        #: job made of 150 agent runs, so a cancel that only took effect at the end would be a
        #: cancel button that does nothing -- the same reason the pipeline polls one.
        self._abort = abort
        self.run_id = run_id or _run_id(self.workspace)
        self.out_dir = Path(out_dir) if out_dir is not None else self.workspace / "var" / "harness"
        self.blackboard = bb.new_blackboard(self.run_id, self.workspace)
        # Injected only by tests. In a real run the context is built lazily so that planning and
        # `--dry-run` work on a checkout where the tool package is not installed yet.
        self._context = context
        self._dataflow = dataflow
        self.dataflow_notes: list[str] = []
        self.rounds_run = 0
        #: The scope ids the plan opened. Set by `_plan` (or by the dry run); re-dispatch and
        #: closure both iterate it rather than re-deriving the plan, so a round cannot silently
        #: cover a different set of scopes than the one the coverage table describes.
        self._planned_scopes: list[str] = []
        #: The deterministic survey snapshot, taken once in `_prepare` and reused by `_plan`. One
        #: walk of the tree per run, and the scopes the plan is built from are the same ones the
        #: opening agents were shown.
        self._snapshot: dict[str, Any] | None = None
        #: Guards the read-modify-write merges the opening agents do concurrently. The board's merges
        #: are unions, so interleaved *appends* converge on their own; what this protects is the
        #: merge helpers that read a field, compare, and append -- two threads doing that on the same
        #: field can each see the pre-state and one of them loses its update.
        self._board_lock = threading.RLock()
        self._planner_lock = threading.Lock()
        self._model_slots = threading.BoundedSemaphore(max(1, self.config.concurrency))
        self._availability_lock = threading.Lock()
        self._consecutive_ai_unavailable = 0
        self._planner_calls = 0
        self._planner_last_at: datetime | None = None
        #: Which agent is running on *this* thread. Set by `_agent` for the duration of a run, read by
        #: `_record` so a fact an agent wrote says who wrote it -- needed because recon and threat
        #: modelling write from two threads at once and the trail has no other way to tell them apart.
        self._current = threading.local()
        #: Which files each scope owns. The coverage rule reads this: a scope is not closed while a
        #: file it owns has never been read end to end, and the re-dispatch hands the unread subset
        #: back to the next agent instead of letting it guess where it left off.
        self._scope_files: dict[str, list[str]] = {}
        #: Consecutive rounds in which a scope's discovery run failed to produce one (agent error, or
        #: `budget` with nothing usable). Read by the re-dispatch decision: a scope that keeps failing
        #: is left INSUFFICIENT instead of being paid for again -- see `max_scope_retries`. Reset to 0
        #: by any run that finishes, because the counter is about consecutive failure, not history.
        self._scope_failures: dict[str, int] = {}
        self.tasks = TaskLedger(self.blackboard, self.trail)

    # ── context ────────────────────────────────────────────────────────────

    @property
    def run_dir(self) -> Path:
        return self.out_dir / self.run_id

    @property
    def context(self) -> Any:
        """The `ToolContext`, built on first use.

        `workspace` is this process's workspace, not the worker's: the tools read files locally and
        `WorkerDataflowVerifier` carries `DataflowConfig.worker_workspace` separately for the one
        thing that has to cross a mount boundary. Translating the path here as well would break the
        local reads, which is the trap the dataflow tool's own docstring warns about.

        `record` is attached here, and that is the whole of the write capability an agent has: the
        board itself is never handed over, only a callable that accepts one record. `board` is attached
        the same way and is its read-only counterpart -- one named section in, that slice out -- because
        a fact another agent recorded is only shared if someone can read it while the run is going.
        """
        if self._context is None:
            self._context = _build_context(
                self.workspace, dataflow=self._dataflow, record=self._record, board=self._board_view
            )
        return self._context

    # ── what an agent can read and write on the board ──────────────────────

    def _board_view(self, section: str) -> dict:
        """One named slice of the blackboard, for the `board` tool.

        Read under `_board_lock` for the same reason a write is: the opening agents call this while the
        other one is merging into the same fields, and a view assembled from a half-applied merge is a
        view of a state that never existed.

        Every section is bounded. `components` is capped and says how many it left out; `threats` and
        `notes` are capped per list. The cap is not about context only -- `notes` accumulates one entry
        per recorded note, and an agent handed all of them would spend its budget on the board instead
        of on the code, which is the cost this whole pipeline is built to avoid.
        """
        with self._board_lock:
            board = self.blackboard
            if getattr(self._current, "agent", "") == agents.DISCOVERY:
                work = self.tasks.get(getattr(self._current, "work_id", ""))
                if work is None:
                    return {"revision": board.revision, "error": "task_context_missing"}
                records = [r.model_dump(mode="json") for r in board.investigation_records
                           if r.work_id == work.work_id or r.file in work.files]
                candidates = [c for c in board.candidates
                              if c.scope_id == work.scope_id or c.file in work.files]
                updates = list(work.pending_updates)
                # Do not acknowledge a clipped read; completion checks actual returned updates.
                self._current.seen_updates = updates
                return {
                    "revision": board.revision, "work_id": work.work_id,
                    "records": records[-self.BOARD_LIST_LIMIT:],
                    "omitted_records": max(0, len(records) - self.BOARD_LIST_LIMIT),
                    "candidates": [c.model_dump(mode="json") for c in candidates[:self.BOARD_LIST_LIMIT]],
                    "verdicts": [v.model_dump(mode="json") for v in board.verdicts
                                 if v.candidate_id in {c.candidate_id for c in candidates}][:self.BOARD_LIST_LIMIT],
                    "updates": [lead.model_dump(mode="json") for lead in board.leads if lead.lead_id in updates],
                    "gaps": [g.model_dump(mode="json") for item in board.work for g in item.gaps
                             if item.work_id == work.work_id or g.lead_id in updates],
                }
            project = board.project
            architecture = board.architecture
            threats = board.threats
            components = list(getattr(architecture, "components", []) or [])
            # The revision at the moment of the read, in every section: this is what makes an agent's
            # "how much of the board have I actually seen" a fact the ledger can compute from its tool
            # calls, instead of a claim the model makes about itself. The opening stage's convergence
            # rule is built on it (`_opening_watermarks`).
            revision = board.revision
            if section == "components":
                shown = components[: self.BOARD_COMPONENTS_LIMIT]
                return {
                    "revision": revision,
                    "count": len(components),
                    "components": [
                        {
                            "id": item.get("id"),
                            "name": item.get("name"),
                            "kind": item.get("kind"),
                            "path": item.get("path"),
                            # Per component, not only in the map's notes: the architecture is a union of
                            # the pre-scan's directories, recon's reading and this agent's peers, and an
                            # agent has to be able to tell which claim it is looking at.
                            "origin": item.get("origin") or "model",
                            # The row's own place, when it was created from one: a component whose first
                            # arrival was a file/route carries it at the top level, and one that started
                            # as an area gathers the places in `sites`. Both are read here, because a
                            # peer asking "where does this happen" does not care which order they came in.
                            "route": item.get("route") or item.get("endpoint"),
                            "line": item.get("line"),
                            # The places the row covers. A component is an *area*; a route or a file that
                            # arrived at the same id accumulates here instead of overwriting the area, so
                            # a peer can see all of them rather than only the one that came first.
                            "sites": [
                                {
                                    "route": site.get("route") or site.get("endpoint"),
                                    "path": site.get("path"),
                                    "line": site.get("line"),
                                    "name": site.get("name"),
                                }
                                for site in (item.get("sites") or [])
                                if isinstance(site, dict)
                            ][: self.BOARD_LIST_LIMIT]
                            or None,
                        }
                        for item in shown
                    ],
                    "omitted": max(0, len(components) - len(shown)),
                    "note": (
                        "origin=survey 的是编排层从目录名/构建设施推出的（不是读过代码）；"
                        "origin=model 的是某个 agent 记录的。两者冲突时以你在代码里验证的为准。"
                        "这是**区域**维度：一条具体路由看 section=entry_points，不要为每条路由新建组件。"
                    ),
                }
            if section == "entry_points":
                # The other granularity, and the one that is genuinely unknown-in-advance: a repository
                # has as many endpoints as it has. This section exists so an agent can read them all --
                # the components list is the wrong place to look for "which requests can reach this".
                points = list(project.entry_points) if project else []
                routes = [
                    {
                        "component": item.get("id"),
                        "route": place.get("route") or place.get("endpoint"),
                        "path": place.get("path"),
                        "line": place.get("line"),
                    }
                    # The row itself *and* its `sites`: a place that arrived first sits on the row, the
                    # ones that arrived after it sit in the list, and both are equally real.
                    for item in components
                    for place in [
                        item,
                        *[site for site in (item.get("sites") or []) if isinstance(site, dict)],
                    ]
                    if place.get("route") or place.get("endpoint")
                ]
                return {
                    "revision": revision,
                    "count": len(points) + len(routes),
                    "entry_points": points[: self.BOARD_LIST_LIMIT],
                    "routes_from_components": routes[: self.BOARD_LIST_LIMIT],
                    "note": (
                        "entry_points 是 recon 的最终结论，routes_from_components 是从区域行的 sites 里"
                        "读出来的；两者都算“已确认的入口”，重复是正常的。记新的端点用 "
                        "`record(kind=\"entry_point\")`，一条一个。"
                    ),
                }
            if section == "threats":
                if threats is None:
                    return {
                        "revision": revision,
                        "established": False,
                        "note": "威胁模型还没有产出任何内容",
                    }
                return {
                    "revision": revision,
                    "established": True,
                    "assets": list(threats.assets)[: self.BOARD_LIST_LIMIT],
                    "actors": list(threats.actors)[: self.BOARD_LIST_LIMIT],
                    "threats": [
                        {
                            "id": item.get("id"),
                            "title": item.get("title"),
                            "asset": item.get("asset"),
                        }
                        for item in list(threats.threats)[: self.BOARD_LIST_LIMIT]
                        if isinstance(item, dict)
                    ],
                    "out_of_scope": list(threats.out_of_scope)[: self.BOARD_LIST_LIMIT],
                }
            if section == "notes":
                notes = [*(project.notes if project else []), *(architecture.notes if architecture else [])]
                return {
                    "revision": revision,
                    "count": len(notes),
                    "notes": notes[-self.BOARD_LIST_LIMIT:],
                    "note": "以 [scope] 开头的是某个 agent 用 record 写下的；以 survey: 开头的是编排层预扫描写下的。",
                }
            # `summary` -- and anything else, since the tool refuses an unknown section before this.
            confirmed = len(bb.confirmed_candidates(board))
            return {
                "revision": revision,
                "workspace": str(self.workspace),
                "languages": dict(project.languages) if project else {},
                "build_systems": list(project.build_systems) if project else [],
                "entry_points": list(project.entry_points)[: self.BOARD_LIST_LIMIT] if project else [],
                "counts": {
                    "components": len(components),
                    "trust_boundaries": len(getattr(architecture, "trust_boundaries", []) or []),
                    "assets": len(threats.assets) if threats else 0,
                    "actors": len(threats.actors) if threats else 0,
                    "threats": len(threats.threats) if threats else 0,
                    "notes": (len(project.notes) if project else 0)
                    + (len(architecture.notes) if architecture else 0),
                    "candidates": len(board.candidates),
                    "confirmed": confirmed,
                    "scopes": len(board.coverage),
                },
                "note": (
                    "这是本次运行此刻的黑板状态。看不清要哪些组件就调 section=components；"
                    "想知道威胁模型已经确认了什么就调 section=threats。"
                ),
            }

    # ── the one write an agent can make ────────────────────────────────────

    def _record(self, record: dict) -> dict:
        """Append one agent-recorded fact to the blackboard. Returns what happened.

        Called from the `record` tool, which runs on an agent's thread -- two opening agents write
        concurrently, so the read-modify-write merges are taken under `_board_lock`. Everything here
        is additive: the kinds map onto the fields the coordinator itself writes, through the same
        merge helpers, and there is no path by which an agent can delete or replace anything.

        Unknown kinds are refused rather than stored: a fact the report cannot render and the closure
        rule cannot read is worse than a refused call, because it looks like state.
        """
        from services.harness.tools.record import KINDS

        kind = str(record.get("kind") or "")
        text = str(record.get("text") or "").strip()
        scope = str(record.get("scope") or "").strip()
        if getattr(self._current, "agent", "") == agents.DISCOVERY:
            work = self.tasks.get(getattr(self._current, "work_id", ""))
            if work is None or kind not in {"evidence", "candidate", "lead", "gap"}:
                return {"recorded": False, "reason": "discovery_record_not_allowed"}
            scope = work.scope_id
        if kind not in KINDS:
            return {"recorded": False, "reason": f"unknown_kind:{kind}"}
        if not text:
            return {"recorded": False, "reason": "empty_text"}

        with self._board_lock:
            # `changed` comes from the revision, not from the merge helper's return value:
            # `bb.set_context` returns the *blackboard*, which is always truthy, so the obvious
            # `changed = bb.set_context(...)` is a silent lie -- measured here, it made the
            # "already on the board, deduplicated" branch below dead code that no test could reach.
            # The revision is bumped by `_touch` only when a merge actually appended something, so it
            # is the ledger's own answer to "did anything change".
            self._current.record_fields = {}
            before = self.blackboard.revision
            try:
                note = self._apply_record(kind, text, scope)
            except (ValueError, TypeError) as exc:
                # A payload that does not fit the contract is the model's mistake, and it has to come
                # back as a refusal it can act on rather than as a pydantic traceback it cannot.
                # Measured on the first real run: the `entry_point` branch built a `ProjectContext`
                # without its required `workspace` field, so every entry-point call died inside the
                # tool and the transcript showed "工具 record 执行失败: ValidationError: ... Field
                # required" -- true, unactionable, and repeated by the model until it gave up.
                return {
                    "recorded": False,
                    "reason": f"{kind} 未被接受：{trail_mod.clip(str(exc), 200)}",
                }
            changed = self.blackboard.revision > before
            revision = self.blackboard.revision
            agent = getattr(self._current, "agent", "")
            if changed and agent == agents.DISCOVERY:
                bb.save(self.blackboard, self.run_dir)

        if not changed:
            # A duplicate is not a failure, and saying so is what stops an agent from retrying it or
            # from believing its write was lost.
            return {"recorded": True, "revision": revision, "note": f"{note}（与已有内容重复，已去重）"}
        self.trail.emit(
            # `record_kind`, not `kind`: `emit` merges its fields over the event dict, so a field named
            # `kind` would overwrite the event's own kind and the write would land in the trail as a
            # bogus event type instead of as a record.
            "record", agent=agent, scope=scope,
            record_kind=kind, revision=revision, text=trail_mod.clip(text), note=note,
            work_id=getattr(self._current, "work_id", ""),
            **getattr(self._current, "record_fields", {}),
        )
        return {"recorded": True, "revision": revision, "note": note}

    def _apply_record(self, kind: str, text: str, scope: str) -> str:
        """Merge one recorded fact into the field its kind names. Returns the note for the model.

        Every branch goes through an existing blackboard merge helper, so a record is exactly the same
        kind of write the coordinator makes itself: additive, de-duplicated, and unable to replace
        anything. Raises `ValueError` for a payload the contract cannot hold -- the caller turns that
        into a refusal, because a model cannot act on a pydantic error string.

        Whether anything *changed* is deliberately not reported here: the merge helpers signal it
        through the blackboard's revision, and the caller reads that (see `_record` for why).

        Called with `_board_lock` held. The lock is the caller's because the merge helpers read a field
        and then append to it, and two opening agents doing that to the same field can lose a write.
        """
        if kind == "gap":
            return self._record_gap(text)
        if kind in {"evidence", "candidate"}:
            payload = _json_object(text)
            if payload is None:
                raise ValueError("需要 JSON 对象")
            work_id = getattr(self._current, "work_id", "")
            work = self.tasks.get(work_id)
            if work is None:
                raise ValueError("需要当前调查任务")
            file = str(payload.get("file") or "").replace("\\", "/")
            line = payload.get("line")
            if file not in set(coverage.inventory(self.workspace)) or not isinstance(line, int) or isinstance(line, bool) or line < 1:
                raise ValueError("需要仓库内源码位置 file 和正整数 line")
            payload["file"] = file
            if kind == "candidate":
                candidates = agents._parse_candidates({"candidates": [payload]}, scope_id=scope)
                if not candidates:
                    raise ValueError("候选需要 title、file 和漏洞类型")
                existing = [c for c in self.blackboard.candidates if c.scope_id == scope]
                if len(existing) >= self.config.candidates_per_scope and candidates[0].candidate_id not in {c.candidate_id for c in existing}:
                    raise ValueError("当前任务候选预算耗尽；保留断点后结束")
                self._record_candidates(candidates)
                self.tasks.link_candidates(work_id, [c.candidate_id for c in candidates])
                for candidate in candidates:
                    self._claim_work([candidate], WorkItemKind.VALIDATION)
                return "候选已登记验证待办（尚未裁决）"
            category = payload.get("category", "hypothesis")
            if category not in {"source_fact", "hypothesis"}:
                raise ValueError("Discovery 只能发布 source_fact 或 hypothesis，不能发布验证结论")
            detail = str(payload.get("text") or "").strip()
            if not detail:
                raise ValueError("证据 text 不能为空")
            affected = bb.find_candidate(self.blackboard, str(payload.get("candidate_id") or ""))
            if payload.get("candidate_id") and (affected is None or category != "source_fact"):
                raise ValueError("关联候选的证据需要已存在的 candidate_id 和 source_fact")
            identity = json.dumps([work_id, file, line, category, detail], ensure_ascii=False)
            record_id = "E-" + hashlib.sha256(identity.encode()).hexdigest()[:20]
            if not any(r.record_id == record_id for r in self.blackboard.investigation_records):
                self.blackboard.investigation_records.append(InvestigationRecord(
                    record_id=record_id, work_id=work_id, scope_id=scope,
                    file=file, line=line, category=category, text=detail,
                ))
                self.blackboard.revision += 1
            self._current.record_fields = {"file": file, "line": line, "category": category, "record_id": record_id}
            if affected is not None:
                self._record_candidates([affected.model_copy(update={"evidence": [*affected.evidence, record_id]})])
            return f"证据已记录：{record_id} ({category})"
        if kind == "note":
            bb.set_context(
                self.blackboard,
                project=ProjectContext(
                    workspace=str(self.workspace),
                    notes=[f"[{scope or 'workspace'}] {text}"],
                ),
            )
            return "已记入 project.notes"
        if kind == "component":
            component = _json_object(text)
            if component is None:
                raise ValueError("component 需要 JSON 对象，例如 {\"id\": ..., \"name\": ..., \"kind\": ...}")
            bb.set_context(
                self.blackboard,
                architecture=ArchitectureMap(components=[component], trust_boundaries=[]),
            )
            name = component.get("name") or component.get("id")
            return f"已记入 architecture.components（{name}）"
        if kind == "entry_point":
            # `workspace` is required on `ProjectContext`: every fragment carries the run's identity,
            # and a fragment that omits it is rejected by the contract. That is the bug the first real
            # run found -- this branch used to build the model without it.
            bb.set_context(
                self.blackboard,
                project=ProjectContext(workspace=str(self.workspace), entry_points=[text]),
            )
            return "已记入 project.entry_points"
        if kind == "trust_boundary":
            bb.set_context(
                self.blackboard, architecture=ArchitectureMap(trust_boundaries=[text])
            )
            return "已记入 architecture.trust_boundaries"
        if kind in ("asset", "actor"):
            field = "assets" if kind == "asset" else "actors"
            bb.set_context(self.blackboard, threats=ThreatModel(**{field: [text]}))
            return f"已记入 threats.{field}"
        if kind == "threat":
            payload = _json_object(text)
            if payload is None:
                raise ValueError("threat 需要 JSON 对象，例如 {\"id\": ..., \"title\": ..., \"asset\": ...}")
            bb.set_context(self.blackboard, threats=ThreatModel(threats=[payload]))
            title = payload.get("title") or payload.get("id")
            return f"已记入 threats.threats（{title}）"
        if kind == "lead":
            payload = _json_object(text)
            if payload is None:
                raise ValueError("lead 需要 JSON 对象，例如 {\"to_scope\": ..., \"why\": ...}")
            target = str(payload.get("to_scope") or "").strip()
            if not target:
                # A lead with no target cannot be handed to anyone, and `to_scope` is what the
                # coordinator would route on. Accepting it would put a row on the board that looks
                # like a thread and leads nowhere.
                raise ValueError("lead 需要 to_scope：说的是把它交给哪个 scope")
            if getattr(self._current, "agent", "") == agents.DISCOVERY:
                if not str(payload.get("question") or payload.get("why") or "").strip():
                    raise ValueError("独立线索需要具体 question")
                if payload.get("file") not in set(coverage.inventory(self.workspace)):
                    raise ValueError("线索需要仓库内起点 file")
                if not isinstance(payload.get("line"), int) or isinstance(payload.get("line"), bool) or payload["line"] < 1:
                    raise ValueError("线索需要正整数 line")
                refs = payload.get("evidence_refs") or []
                if not isinstance(refs, list) or any(ref not in {r.record_id for r in self.blackboard.investigation_records} for ref in refs):
                    raise ValueError("evidence_refs 必须引用已存在的证据")
            new_lead = CrossScopeLead(
                    lead_id=agents.stable_candidate_id(
                        scope or "workspace", target, None, "lead:" + json.dumps(
                            [" ".join(str(payload.get("question") or payload.get("why") or payload.get("title") or "").split()).casefold(),
                             payload.get("file"), payload.get("line")], ensure_ascii=False, sort_keys=True
                        )
                    ),
                    from_scope=scope or "workspace",
                    to_scope=target,
                    title=str(payload.get("title") or target),
                    detail=text,
                    raised_by=getattr(self._current, "agent", ""),
                    question=str(payload.get("question") or payload.get("why") or payload.get("title") or target),
                    file=str(payload.get("file") or ""), line=payload.get("line"),
                    evidence_refs=payload.get("evidence_refs") or [],
                    source_work_id=getattr(self._current, "work_id", ""),
                    sequence=max((lead.sequence for lead in self.blackboard.leads), default=0) + 1,
            )
            bb.add_lead(self.blackboard, new_lead)
            self._current.record_fields = {"lead": new_lead.model_dump(mode="json")}
            return "已记入持久化线索收件箱，等待协调器处理"
        # Unreachable: the caller validated `kind` against `KINDS` before taking the lock. Raising
        # rather than returning keeps a future kind from silently recording nothing.
        raise ValueError(f"没有实现记录方式：{kind}")

    # ── entry point ────────────────────────────────────────────────────────

    def run(self) -> HarnessResult:
        """Run the pipeline. Returns a result; never raises for a stage failure."""
        if self.config.dry_run:
            return self._dry_run()
        if self.client is None:
            # Not a crash: the caller asked for a model-driven run without a client, and the
            # honest answer is a result that says so rather than an empty blackboard.
            self.blackboard = bb.mark_closed(
                self.blackboard, "未提供模型客户端：本次没有发起任何模型调用。"
            )
            return self._finish(fatal="AI 阶段未配置：没有可用的模型客户端")

        try:
            # `prep` is a stage of its own, in the stage table and in the trail, rather than the first
            # line of the opening stage: a reader watching the run has to see the deterministic survey
            # finish *before* the first agent starts, and a stage that begins with someone else's work
            # inside it reports the wrong thing at the wrong time (measured in the deployed image: the
            # stage table said 仓库勘察 had started while the pre-scan was still walking the tree).
            self._stage("prep", self._prepare)
            bb.add_work(self.blackboard, self._coverage_items())
            self._publish_discovery_tasks()
            self._stage("recon", self._recon_and_threat_model)
            self._stage("security_inventory", self._build_security_inventory)
            self._stage("plan", self._plan)
            self._stage("discovery", self._discovery_and_closure)
            self._stage("attack_path", self._complete_attack_paths)
            self._stage("findings", self._emit_findings)
        except BudgetStop as exc:
            self._emit_findings()
            self.tasks.stop(str(exc))
            self.blackboard.execution_budget = self.budget.snapshot()
            bb.mark_closed(self.blackboard, f"{exc}；未完成任务与线索保留。")
            return self._finish()
        except ModelUnavailableStop as exc:
            reason = str(exc)
            self.tasks.stop(reason)
            self.blackboard = bb.mark_closed(
                self.blackboard, f"{reason}；已停止派发新任务，未完成任务与线索保留，可在服务恢复后重新审计。"
            )
            self.trail.emit("error", where="model_provider", message=reason)
            return self._finish(fatal=reason)
        except (CanceledAbort, KeyboardInterrupt):
            self.tasks.stop("运行已取消", canceled=True)
            bb.mark_closed(self.blackboard, "运行已取消；未完成任务保留在任务清单中。")
            self._finish()
            raise
        except ToolLayerUnavailable as exc:
            # A missing tool package is a broken installation, not a stage result. Recorded and
            # returned so the CLI can exit non-zero with the actionable message intact.
            log.error("harness: %s", exc)
            self.trail.emit("error", where="tool_layer", message=str(exc))
            self.blackboard = bb.mark_closed(self.blackboard, f"工具层不可用：{exc}")
            return self._finish(fatal=str(exc))

        note = (
            f"审计执行结束，共 {self.rounds_run} 轮；"
            f"{len(self.blackboard.candidates)} 个候选、"
            f"{len(bb.confirmed_candidates(self.blackboard))} 个确认、"
            f"{len(self.blackboard.findings)} 条最终发现。"
        )
        self.blackboard = bb.mark_closed(self.blackboard, note)
        self.trail.emit("stage", stage="close", state="end", note=note,
                        counters=self.trail.counters(self.blackboard))
        return self._finish()

    # ── observability ──────────────────────────────────────────────────────

    def attach_trail(self, *sinks, base: dict | None = None) -> trail_mod.Trail:
        """Send this run's events to `<run_dir>/trail.jsonl`, plus any extra sinks.

        Called after construction because the run directory is the coordinator's own knowledge --
        `out_dir` plus the generated `run_id` -- so a caller never has to recompute the path and
        cannot get it wrong. The JSONL sink is always first: it is the durable one, and a caller
        that only wanted the callback still gets the file that survives the process.
        """
        self.trail = trail_mod.Trail(
            # `mode="w"`: attaching a trail *begins* a run. A redriven job keeps its id and therefore
            # its run directory, so appending would put a second attempt's seq 1,2,3… after the
            # first's and leave the console paging a file that holds two runs.
            [trail_mod.JsonlSink(self.run_dir / trail_mod.TRAIL_NAME, mode="w"), *sinks],
            base={"run_id": self.run_id, **(base or {})},
        )
        self.tasks.trail = self.trail
        return self.trail

    def _stage(self, name: str, fn) -> None:
        """Run one stage with its start/end events around it.

        Wrapped here rather than emitted inside each stage so that the two events cannot drift from
        the call they describe: a stage that raised still gets its `end`, with the failure visible
        in the error event and in the report. Callers see no difference -- the wrapped function's
        return value is passed through.
        """
        self.check_abort(name)
        self.trail.emit("stage", stage=name, state="start",
                        counters=self.trail.counters(self.blackboard))
        try:
            fn()
        except BaseException:
            self.trail.emit("stage", stage=name, state="failed",
                            counters=self.trail.counters(self.blackboard))
            raise
        self.trail.emit("stage", stage=name, state="end",
                        counters=self.trail.counters(self.blackboard))

    def check_abort(self, stage: str) -> None:
        """Stop between units of work if the caller asked us to.

        `CanceledAbort` rather than an exception of our own: it is `BaseException` on purpose, so a
        stage's own `except Exception` cannot swallow it, and the worker that owns the job already
        knows how to turn it into a terminal state. `stage="ai"` because the job contract has one
        AI stage -- an audit *is* that stage -- and the harness phase rides in `detail`, where it
        reaches the cancel note without inventing a job stage nobody else knows.
        """
        if self._abort is not None and self._abort():
            raise CanceledAbort(stage="ai", resource="harness_stage_boundary",
                                detail=f"harness stage: {stage}")
        if not self.config.dry_run:
            self.budget.check()

    def _on_step(self, run: AgentRun, step) -> None:
        """One turn of one agent, as an event. This is the agent's side of the conversation."""
        result = step.result
        self._current.active_run = run
        call = step.call
        arguments = {}
        if call is not None:
            arguments = {
                key: (trail_mod.clip(value, 200) if isinstance(value, str) else value)
                for key, value in (call.arguments or {}).items()
            }
        self.trail.emit(
            "agent_step",
            agent=run.agent,
            scope=run.scope_id,
            run_id=run.run_id,
            index=step.index,
            thought=trail_mod.clip(step.thought),
            tool=call.tool.value if call is not None else None,
            arguments=arguments,
            path=str(call.arguments.get("path") or "") if call is not None else "",
            ok=result.ok if result is not None else None,
            summary=trail_mod.clip(result.summary) if result is not None else "",
            error=result.error if result is not None else None,
        )
        if call is not None and call.tool is ToolName.BOARD and result is not None and result.ok and not result.truncated:
            work = self.tasks.get(getattr(self._current, "work_id", ""))
            if work is not None:
                seen = set(getattr(self._current, "seen_updates", []))
                self._current.consumed_updates = set(getattr(self._current, "consumed_updates", set())) | seen
        if call is not None and call.tool is ToolName.READ and result is not None and result.ok:
            item = self.tasks.get(f"W-{run.scope_id}")
            if item is not None and item.files:
                reads = coverage.from_runs([*self.blackboard.runs, run])
                count = sum(bool(reads.get(name) and reads[name].fully_read) for name in item.files)
                if count != item.read_files:
                    self.tasks.update(item.work_id, read_files=count)

    def _agent(self, **kwargs) -> agents.AgentOutcome:
        """`agents.run` plus the three events that make it watchable, and the ledger write.

        Every stage used to call `agents.run` and then `bb.add_run` itself. Funnelling that through
        one place means a new stage cannot forget the trail, and the per-step observer is installed
        once instead of at six call sites.

        It is also the one place that knows *which* agent is on this thread, which is what `record`
        needs: two agents run concurrently on two threads, so a recorded fact has to carry its author
        or the trail shows writes from nowhere. The attribution lives on a thread-local rather than in
        the tool's arguments because the model must not be able to claim someone else's name.
        """
        agent = kwargs.get("agent", "")
        scope_id = kwargs.get("scope_id", "")
        work_ids = kwargs.pop("work_ids", [])
        if agent == agents.DISCOVERY and self.tasks.get(f"W-{scope_id}"):
            work_ids = [f"W-{scope_id}"]
        self.check_abort(f"{agent}:{scope_id}")
        self.tasks.trail = self.trail
        base_run_id = kwargs.get("run_id") or f"{agent}:{scope_id}"
        previous_attempts = max((len(self.tasks.get(wid).attempts) for wid in work_ids), default=0)
        if previous_attempts and (agent != agents.DISCOVERY or any(
            attempt.run_id == base_run_id for wid in work_ids for attempt in self.tasks.get(wid).attempts
        )):
            kwargs["run_id"] = f"{base_run_id}:attempt:{previous_attempts + 1}"
        self.tasks.start(work_ids, agent, kwargs.get("run_id") or f"{agent}:{scope_id}")
        started = _now()
        self.trail.emit(
            "agent_start",
            agent=agent,
            scope=scope_id,
            run_id=kwargs.get("run_id") or f"{agent}:{scope_id}",
            tools=_tools_of(agent),
        )
        previous = getattr(self._current, "agent", "")
        self._current.agent = agent
        previous_work = getattr(self._current, "work_id", "")
        self._current.work_id = work_ids[0] if work_ids else ""
        self._current.consumed_updates = set()
        self._current.active_run = None
        claim_ids = {cid for wid in work_ids for cid in self.tasks.get(wid).candidate_ids}
        versions = {c.candidate_id: c.evidence_version for c in self.blackboard.candidates if c.candidate_id in claim_ids}
        try:
            with self._model_slots:
                self.check_abort(f"{agent}:{scope_id}")
                client = kwargs.get("client")
                if client is not None:
                    kwargs["client"] = BudgetClient(client, self.budget, self.check_abort)
                outcome = agents.run(on_step=self._on_step, **kwargs)
        except BaseException as exc:
            active = getattr(self._current, "active_run", None)
            if active is not None:
                active.stop_reason = "budget" if isinstance(exc, BudgetStop) else "aborted"
                active.finished_at = _now()
                bb.add_run(self.blackboard, active)
            self.tasks.end(
                work_ids, stop_reason="aborted" if isinstance(exc, (CanceledAbort, KeyboardInterrupt)) else "error",
                steps=len(active.steps) if active is not None else 0, error=f"{type(exc).__name__}: {exc}",
            )
            # A run that dies *inside* the orchestrator still gets its `end`. The trail's contract is
            # that every announced run is closed, and a screen that shows an agent which never finished
            # cannot tell "still working" from "died here" -- which is exactly what happened when the
            # opening stage learned to re-dispatch: a client that raised mid-pass left an `agent_start`
            # with no `agent_end` and an audit that looked like it was still thinking. `CanceledAbort`
            # rides through untouched; it is `BaseException` precisely so nothing swallows it.
            self.trail.emit(
                "agent_end",
                agent=agent,
                scope=scope_id,
                run_id=kwargs.get("run_id") or f"{agent}:{scope_id}",
                stop_reason="aborted" if isinstance(exc, CanceledAbort) else "error",
                steps=0,
                parsed=False,
                error=f"{type(exc).__name__}: {exc}",
            )
            raise
        finally:
            # Restored rather than cleared: an agent run nested in another (a re-dispatch inside a
            # stage) must leave the outer attribution as it found it.
            self._current.agent = previous
            self._current.work_id = previous_work
        bb.add_run(self.blackboard, outcome.run)
        if agent in {agents.VALIDATION, agents.VALIDATION_BATCH, agents.ATTACK_PATH, agents.ATTACK_PATH_BATCH} and any(
            c.evidence_version != versions.get(c.candidate_id, c.evidence_version)
            for c in self.blackboard.candidates if c.candidate_id in claim_ids
        ):
            outcome.parsed, outcome.error = None, "执行期间关键证据版本变化，保留待复核，未采用旧结果"
        self.blackboard.execution_budget = self.budget.snapshot()
        self.tasks.end(
            work_ids, stop_reason=outcome.run.stop_reason, steps=len(outcome.run.steps),
            error=outcome.error or ("模型未返回可用结果" if outcome.parsed is None else ""),
        )
        step_count = len(outcome.run.steps)
        self.trail.emit(
            "agent_end",
            agent=agent,
            scope=scope_id,
            run_id=outcome.run.run_id,
            stop_reason=outcome.run.stop_reason,
            steps=step_count,
            parsed=outcome.parsed is not None,
            error=outcome.error,
            # Whether this run's answer came out of a truncated reply (`react._salvage_final`). In the
            # trail because it is the only place a reader can see the recovery working: the run looks
            # `finished` in every other record, and its lists may stop early.
            salvaged=outcome.run.salvaged,
            duration_ms=int((_now() - started).total_seconds() * 1000),
        )
        self._check_model_availability(outcome.run)
        return outcome

    def _check_model_availability(self, run: AgentRun) -> None:
        """Trip a run-wide circuit after repeated, fully retried provider failures."""
        unavailable = bool(
            run.stop_reason == "error"
            and run.steps
            and run.steps[-1].thought.startswith("model call failed: AIUnavailable:")
        )
        with self._availability_lock:
            if unavailable:
                self._consecutive_ai_unavailable += 1
            else:
                self._consecutive_ai_unavailable = 0
            failures = self._consecutive_ai_unavailable
        threshold = max(1, self.config.max_consecutive_ai_unavailable)
        if failures >= threshold:
            raise ModelUnavailableStop(
                f"模型服务连续 {failures} 个 agent 不可用（每次请求已完成内部重试）"
            )

    # ── stage 0: prep, stage 1: recon + threat model ───────────────────────

    def _recon_and_threat_model(self) -> None:
        """The opening: recon and threat modelling once each, concurrently and without cross-reading.

        This used to be a convergence loop (up to `max_opening_passes`, each pass re-dispatching
        whichever agent had unread peer publications), copied from MetaGPT's message pool and AutoGen's
        delta termination. Two measurements killed it. On the real module audit the pair ran 3 passes
        and still reported `unread=2`; on the demo, pass 2's publications were rephrasings of what both
        sides had already seen -- the loop paid for a third agent run to re-read a sentence. The design
        change that replaces it: the two agents **do not react to each other at all**. Recon describes
        the system; threat modelling reasons independently from the deterministic survey;
        whatever neither of them established is the job of the next stage -- the AI security inventory,
        which runs after both and is the only place expected to reconcile their outputs.

        Both tasks are built before either run starts, from the same frozen survey state. They then run
        concurrently. Their final outputs are merged only after both futures finish, so scheduling can
        never leak recon's answer into the threat-model prompt.
        """
        self._prepare()
        frozen = self.blackboard.model_copy(deep=True)
        recon_task = agents.recon_task(str(self.workspace), prep=self._snapshot)
        threat_task = agents.threat_model_task(frozen)
        with ThreadPoolExecutor(max_workers=2) as pool:
            recon_future = pool.submit(self._run_recon, recon_task)
            threat_future = pool.submit(self._run_threat_model, threat_task)
            recon_run = recon_future.result()
            threat_run = threat_future.result()
        self.blackboard.opening = OpeningConvergence(
            passes=1,
            converged=True,
            watermarks={},
            unread={},
            note=(
                "单轮独立开场：recon 与威胁建模各执行一轮、不互读收敛（设计变更）；"
                "两者结论由随后的 AI 安全清单阶段统一核对与补全。"
                + (
                    ""
                    if recon_run is not None and threat_run is not None
                    else "（其中一方未产出结论，见其 run 的 stop_reason。）"
                )
            ),
        )
        log.info("harness: opening finished (single round, independent)")

    def _prepare(self) -> None:
        """Write the deterministic facts onto the blackboard before any model call.

        `survey_workspace` is the same function the dry run uses, and it makes no model calls and
        touches no tool: it walks the tree, counts files by language, notices build files and derives
        candidate scopes from the directory layout. Running it here does three things the pipeline
        was missing -- the opening agents start from facts instead of an empty board, the planner no
        longer re-derives scopes the survey already knows (it reuses this snapshot), and the coverage
        table has an addressable inventory even if recon produces nothing.

        **The route markers stay out of the board.** `survey_workspace` also greps files for entry-point
        markers, and its answer is *file-level* -- "this file registers REST controllers" -- which is a
        hint about where to look, not an answer to "which requests can arrive here". Writing it to
        `project.entry_points` put it in the same list as the agent's route-level findings, where nothing
        can merge the two (different locations) and the reader gets 55 entries for 42 routes. They still
        reach recon, in its task text, labelled as markers to verify and enumerate (`prep_payload`); what
        changes is that the board's list means one thing -- entries an agent read -- the same rule the
        components follow.

        Idempotent, and that is load-bearing rather than tidy: `run()` calls it as the `prep` stage and
        the opening stage calls it again as a fallback, and a second survey would be a second reading of
        the tree -- exactly the disagreement between `architecture` and `work` this exists to prevent.
        """
        if self._snapshot is not None:
            return
        snapshot = survey.survey_workspace(self.workspace)
        self._snapshot = snapshot
        scopes: list[survey.Scope] = snapshot["scopes"]
        # A copy with the markers removed, so the snapshot itself (which the recon task reads for those
        # same markers) is untouched.
        project = snapshot["project"].model_copy(deep=True)
        project.entry_points = []
        bb.set_context(
            self.blackboard,
            project=project,
            architecture=ArchitectureMap(
                components=[
                    {
                        "id": scope.scope_id,
                        "name": scope.title,
                        "kind": scope.kind,
                        "path": scope.path,
                        # Provenance, per component rather than only in the map's notes: recon's
                        # components are merged into this same list, and an agent reading it (through
                        # the `board` tool) has to be able to tell a directory name from a reading of
                        # the code. `files` is deliberately left out here -- 59 file names per scope,
                        # stored on every run, is weight the map does not need.
                        "origin": survey.SURVEY_ORIGIN,
                    }
                    for scope in scopes
                ],
                trust_boundaries=[],
                notes=[
                    f"{SURVEY_RATIONALE_PREFIX} 目录结构勘察（确定性、未调用模型）："
                    f"{len(scopes)} 个候选 scope，语言 {snapshot['project'].languages}"
                ],
            ),
        )

    def _build_security_inventory(self) -> None:
        """Run the AI security-inventory agent **once**, after recon and threat modelling.

        This is the stage the opening was refactored for. It used to be a deterministic regex pre-scan
        run *before* the opening pair (measured: 659 regex records over the inventory, most of them
        keyword hits a model then had to disown) -- both the order and the mechanism were wrong. The
        inventory is a *judgement* about entry points, authorization controls, dangerous capabilities,
        configuration and dependencies, and it needs the two opening agents' conclusions as input:
        recon says what the system is, the threat model says what matters, and this agent reconciles
        both against the source and manifests, with its own reads.

        Its output is what the planner is asked to turn into investigations, and `coverage_gaps` is
        the honest part: uncertainty is recorded there instead of being padded into a section.
        """
        if self.blackboard.security_inventory is not None:
            return
        if self.blackboard.project is None and self.blackboard.architecture is None:
            # Without the opening there is nothing to reconcile against; recorded as skipped rather
            # than run on an empty board, exactly like the threat model's own guard.
            self.dataflow_notes.append(
                "warning: the opening produced nothing usable, so the security-inventory stage was "
                "skipped; the planner below works from the deterministic survey only"
            )
            return
        outcome = self._agent(
            agent=agents.SECURITY_INVENTORY,
            scope_id="workspace",
            task=agents.security_inventory_task(self.blackboard),
            context=self.context,
            client=self.client,
            max_steps=self.config.steps_per_agent,
            blackboard=self.blackboard,
        )
        if outcome.parsed is None:
            log.warning(
                "harness: security inventory produced nothing usable (%s)", outcome.error
            )
            self.dataflow_notes.append(
                "warning: 安全清单阶段没有产出（%s）；planner 只依据勘察与威胁模型。"
                % (outcome.error or "no answer")
            )
            return
        inventory: agents.SecurityInventory = outcome.parsed
        if outcome.run.salvaged:
            # A repaired final can contain the first rows of a list but lose its tail. Asking the
            # same large question again tends to hit the same limit, so repair in three small parts.
            sections = (
                ("entry_points", "authorization_controls"),
                ("dangerous_capabilities", "configurations"),
                ("dependencies", "state_controls"),
            )
            merged = inventory.model_dump()
            for group in sections:
                focused = self._agent(
                    agent=agents.SECURITY_INVENTORY,
                    scope_id="workspace:repair:" + ":".join(group),
                    task=agents.security_inventory_task(self.blackboard)
                    + "\nRecovery sections: " + ", ".join(group)
                    + ". Check these sections fully; return empty arrays for all other sections."
                    + " Keep each row concise and put uncertainty in coverage_gaps.",
                    context=self.context,
                    client=self.client,
                    max_steps=self.config.steps_per_agent,
                    blackboard=self.blackboard,
                )
                if focused.parsed is None:
                    merged["coverage_gaps"].append(
                        "安全清单分段补全失败：" + ", ".join(group)
                    )
                    continue
                for name in (*group, "coverage_gaps", "files_reviewed", "notes"):
                    for item in getattr(focused.parsed, name):
                        if item not in merged[name]:
                            merged[name].append(item)
            inventory = agents.SecurityInventory.model_validate(merged)
        bb.set_security_inventory(self.blackboard, inventory)
        counts = {
            name: len(getattr(inventory, name) or [])
            for name in (
                "entry_points",
                "authorization_controls",
                "dangerous_capabilities",
                "configurations",
                "dependencies",
                "state_controls",
            )
        }
        self.trail.emit(
            "summary",
            phase="security_inventory",
            note=(
                f"AI 安全清单完成：入口 {counts['entry_points']}、鉴权控制 "
                f"{counts['authorization_controls']}、危险能力 {counts['dangerous_capabilities']}、"
                f"配置 {counts['configurations']}、依赖 {counts['dependencies']}、"
                f"状态控制 {counts['state_controls']}；未决 {len(inventory.coverage_gaps)} 条。"
            ),
            inventory={"counts": counts, "coverage_gaps": len(inventory.coverage_gaps),
                       "files_reviewed": len(inventory.files_reviewed)},
            counters=self.trail.counters(self.blackboard),
        )

    def _run_recon(self, task: str | None = None) -> AgentRun | None:
        """One recon run. There is no second one: the opening is single-round by design."""
        outcome = self._agent(
            agent=agents.RECON,
            scope_id="workspace",
            run_id=_opening_run_id(agents.RECON),
            task=task or agents.recon_task(str(self.workspace), prep=self._snapshot),
            context=self.context,
            client=self.client,
            max_steps=self.config.steps_per_agent,
            blackboard=self.blackboard,
        )
        if outcome.parsed is None:
            log.warning("harness: recon produced nothing usable (%s)", outcome.error)
            return outcome.run
        project, architecture = outcome.parsed
        # `workspace` comes from the coordinator, not from the model: it is the identity of the run.
        project.workspace = str(self.workspace)
        with self._board_lock:
            bb.set_context(self.blackboard, project=project, architecture=architecture)
        return outcome.run

    def _run_threat_model(self, task: str | None = None) -> AgentRun | None:
        """One threat-model run from the deterministic survey. No peer read or re-dispatch."""
        if self.blackboard.project is None and self.blackboard.architecture is None:
            # Threat modelling without the deterministic survey would be reasoning about a project
            # nobody described.
            # Recorded as a skipped stage rather than run on nothing -- a threat model invented
            # without the architecture map is exactly the generic output this pipeline exists to
            # avoid, and the report has to be able to see that the stage did not run.
            log.warning("harness: no recon findings; skipping the threat-model call")
            self.dataflow_notes.append(
                "warning: deterministic survey produced nothing usable, so threat modelling was skipped; "
                "the plan and the coverage table below are not guided by a threat model"
            )
            return None
        outcome = self._agent(
            agent=agents.THREAT_MODEL,
            scope_id="workspace",
            run_id=_opening_run_id(agents.THREAT_MODEL),
            task=task or agents.threat_model_task(self.blackboard),
            context=self.context,
            client=self.client,
            max_steps=self.config.steps_per_agent,
            blackboard=self.blackboard,
        )
        if outcome.parsed is None:
            log.warning("harness: threat model produced nothing usable (%s)", outcome.error)
            return outcome.run
        with self._board_lock:
            bb.set_context(self.blackboard, threats=outcome.parsed)
        return outcome.run
    # ── stage 2: planning ──────────────────────────────────────────────────

    def _plan(self) -> list[WorkItem]:
        """Fix file ownership, then add concrete threat-model investigations.

        Directory survey entries are architecture context only. On planner failure the complete
        deterministic file review remains available without another directory investigation layer.
        """
        scopes = self._surveyed_scopes()
        if self.blackboard.architecture is None:
            # Recon may have failed, or may have produced no components. Recording the survey's
            # reading keeps the coverage table addressable and the report honest about where the
            # scopes came from.
            bb.set_context(
                self.blackboard,
                architecture=ArchitectureMap(
                    components=[
                        {
                            "id": scope.scope_id,
                            "name": scope.title,
                            "kind": scope.kind,
                            "path": scope.path,
                            "origin": survey.SURVEY_ORIGIN,
                        }
                        for scope in scopes
                    ],
                    trust_boundaries=[],
                    notes=[f"{SURVEY_RATIONALE_PREFIX} architecture derived from directory names"],
                ),
            )
        file_items = self._coverage_items()
        refined = self._planner_call(scopes)
        items = sorted(refined, key=lambda item: item.priority)
        # Coverage groups are added *outside* the cap: see `_coverage_items`.
        bb.add_work(
            self.blackboard,
            [*file_items, *items],
        )
        self._publish_discovery_tasks()
        # Keep the derived scope list so discovery/closure can re-dispatch the same scope ids.
        self._planned_scopes = [
            item.scope_id
            for item in self.blackboard.work
            if item.state in (WorkItemState.PLANNED, WorkItemState.RUNNING)
            and item.kind in (WorkItemKind.FILE_REVIEW, WorkItemKind.INVESTIGATION)
        ]
        log.info("harness: planned %d scope(s): %s", len(self._planned_scopes), self._planned_scopes)
        return items

    def _publish_discovery_tasks(self) -> None:
        self.tasks.trail = self.trail
        for item in self.blackboard.work:
            if item.kind not in (WorkItemKind.FILE_REVIEW, WorkItemKind.INVESTIGATION):
                continue
            is_file = item.scope_id.startswith(coverage.COVERAGE_SCOPE_PREFIX)
            self.tasks.update(
                item.work_id,
                kind=WorkItemKind.FILE_REVIEW if is_file else WorkItemKind.INVESTIGATION,
                files=list(self._scope_files.get(item.scope_id) or []),
                completion_criteria=item.completion_criteria or "完成归属文件读取、提交调查结果并通过本轮覆盖检查；读取不等于安全检查完成",
                status_reason="等待派发",
            )

    def _claim_work(self, members: list[Candidate], kind: WorkItemKind) -> str:
        candidate = agents.group_representative(members)
        key = repr(agents.validation_group_key(candidate)).encode("utf-8")
        work_id = f"W-{kind.value}-{hashlib.sha256(key).hexdigest()[:16]}"
        self.tasks.trail = self.trail
        item = self.tasks.add(WorkItem(
            work_id=work_id, scope_id=candidate.scope_id, kind=kind,
            title=f"{'验证候选' if kind is WorkItemKind.VALIDATION else '攻击路径'}：{candidate.title}",
            rationale=candidate.rationale,
            files=sorted({member.file for member in members}),
            candidate_ids=[member.candidate_id for member in members],
            completion_criteria="每项候选有独立裁决和依据" if kind is WorkItemKind.VALIDATION else "记录入口、可达性、影响及限制",
            status_reason="等待派发",
        ))
        self.tasks.link_candidates(item.work_id, [member.candidate_id for member in members])
        return work_id

    def _claim_allowed(self, members: list[Candidate], kind: WorkItemKind) -> bool:
        work = self.tasks.get(self._claim_work(members, kind))
        if len(work.attempts) >= self.config.max_claim_attempts:
            self.tasks.update(work.work_id, state=WorkItemState.BLOCKED,
                              status_reason="该项验证/攻击路径重试预算耗尽，保留未完成结果")
            return False
        return True

    def _surveyed_scopes(self) -> list[survey.Scope]:
        """The scope list the planner works from, surveyed at most once per run.

        `_prepare` already walked the tree, and re-deriving the scopes here would be a second walk whose
        answer could differ from the components already on the board -- two readings of the same tree,
        one in `architecture` and one in `work`, which is how a coverage table ends up naming scopes the
        plan does not have. Only a run that never reached `_prepare` (dry run, a `_plan` called alone)
        surveys here, and then it is the only survey.
        """
        snapshot = self._snapshot
        if snapshot and snapshot.get("scopes"):
            return list(snapshot["scopes"])
        return survey.discover_scopes(self.workspace)

    def _survey_work_items(self, scopes: list[survey.Scope]) -> list[WorkItem]:
        for scope in scopes:
            # The survey knows each scope's files; recording them here is what lets the closure rule
            # hold a scope to having *read* what it owns rather than to the model's opinion of it.
            self._scope_files.setdefault(scope.scope_id, list(scope.files))
        return [
            WorkItem(
                work_id=f"W-{scope.scope_id}",
                scope_id=scope.scope_id,
                title=scope.title,
                rationale=f"{SURVEY_RATIONALE_PREFIX} {scope.rationale}",
            )
            for scope in scopes
        ]

    def _coverage_items(self) -> list[WorkItem]:
        """The whole inventory split into groups, one work item per group.

        This is what makes coverage a *constraint* rather than an opinion. A single agent handed 59
        files and a normal step budget reads about a third of them -- measured: 30 of 59 files fully
        read, 29 never opened, while every scope still closed as SUFFICIENT. The same files split
        into groups of six are all assigned, and the closure rule can then name the group that did
        not finish.

        Added outside `max_scopes_per_round` on purpose: that cap governs which *model-chosen* scopes
        are worth spending on, while these are the guarantee that every file belongs to someone. A
        cap that can drop the guarantee drops it exactly when the plan is wrong -- and the measured
        failure was a plan whose four scopes were all `web-route`, leaving the service and data-access
        layers unassigned.

        Groups are sequential rather than clustered by directory: a vulnerability spans layers
        (controller to service to mapper), and clustering by directory would rebuild the partitioning
        this exists to work around.
        """
        files = coverage.inventory(self.workspace)
        items: list[WorkItem] = []
        for index, group in enumerate(coverage.chunk(files)):
            scope_id = agents.coverage_scope_id(index)
            self._scope_files[scope_id] = list(group)
            items.append(
                WorkItem(
                    work_id=f"W-{scope_id}",
                    scope_id=scope_id,
                    title=f"覆盖组 {index + 1}（{len(group)} 个文件）",
                    rationale=(
                        "按覆盖率分配的整仓分片：本组文件必须逐个读完；"
                        "覆盖率按 read 调用台账计算，搜索命中不算审完一个文件。"
                    ),
                )
            )
        return items

    def _planner_call(self, scopes: list[survey.Scope]) -> list[WorkItem]:
        """Validate concrete investigations; file-review assignments cannot be changed."""
        components = [
            {
                "id": scope.scope_id,
                "name": scope.title,
                "kind": scope.kind,
                "path": scope.path,
                "files": scope.files[:10],
            }
            for scope in scopes
        ]
        task = "\n".join(
            [
                "Directory survey (architecture context, not investigation assignments):",
                agents._json(components),
                "Security inventory (the AI stage's structured read of entry points, authorization "
                "controls, dangerous capabilities, configuration and dependencies; unverified, "
                "with its own coverage_gaps):",
                agents._json(
                    agents.security_inventory_payload(
                        self.blackboard.security_inventory, per_section=None
                    )
                ),
                "Create independent operation/asset × security property investigations. Each needs "
                "scope_id, title, question, rationale, files (concrete source starting points), "
                "completion_criteria, priority (1 highest, 3 lowest). Architecture and risk names "
                "are labels, not separate full-repository investigations. Explore proactively using "
                "the threat model; do not wait for candidates. File review assignments are fixed "
                "by the coordinator and cannot be removed or renamed. Return excluded with reasons.",
                agents._json({"file_tasks": [
                    {"scope_id": key, "files": value} for key, value in self._scope_files.items()
                    if key.startswith(coverage.COVERAGE_SCOPE_PREFIX)
                ], "batch_size": self.config.max_scopes_per_round,
                    "model_concurrency": self.config.concurrency}),
                "Batch size limits dispatch, not retained tasks or total model budget.",
            ]
        )
        # The opening stage has already read part of this repository, and the planner's second turn is
        # otherwise spent re-fetching it (measured: one pure-read turn on the four-file project).
        reuse, _reused_files, _missing_files = agents.replayable_reads(
            self.blackboard,
            sorted({name for scope in scopes for name in scope.files}),
            budget=self.config.material_budget,
        )
        outcome = self._agent(
            agent=agents.PLANNER,
            scope_id="plan",
            task=task,
            context=self.context,
            client=self.client,
            max_steps=self.config.steps_per_agent,
            blackboard=self.blackboard,
            initial_steps=reuse or None,
        )
        if outcome.parsed is None:
            log.warning("harness: planner produced nothing usable (%s); retaining file review fallback",
                        outcome.error)
            self.dataflow_notes.append("初始专题规划失败；保留完整文件审查兜底，未生成专题调查。")
            return []
        planned = agents._parse_plan(outcome.parsed)
        inventory = set(coverage.inventory(self.workspace))
        items = [
            WorkItem(
                work_id=f"W-{scope['scope_id']}",
                scope_id=str(scope["scope_id"]),
                title=str(scope.get("title") or scope["scope_id"]),
                rationale=str(scope.get("rationale") or ""),
                question=scope["question"],
                completion_criteria=scope["completion_criteria"],
                priority=scope["priority"],
                files=scope["files"],
            )
            for scope in planned.get("scopes", [])
            if all(name in inventory for name in scope["files"])
            and not scope["scope_id"].startswith(coverage.COVERAGE_SCOPE_PREFIX)
        ]
        accepted = {item.scope_id for item in items}
        if not items:
            self.dataflow_notes.append("初始 Planner 未提供有效专题；保留完整文件审查，主动专题探索未执行。")
        # The planner is asked for each scope's `files` and the list was being dropped. Two things
        # depended on that list and both were silently dead for a planner-created scope: the prefetch
        # above had nothing to reuse (measured: `scope-data-access` carried `files=0` and its
        # re-dispatch prefetch seeded nothing), and `_close_coverage`'s "N files never read end to end"
        # clause never fired for it because `_unread_in` returned empty.
        #
        # Filtered against the real inventory, not trusted: the same rule as `docs/HANDOVER.md` §14.12
        # item 1 -- a path a model wrote is a string, and nobody has checked it against the workspace.
        inventory = set(coverage.inventory(self.workspace))
        for scope in planned.get("scopes", []):
            if scope.get("scope_id") not in accepted:
                continue
            named = [
                str(name) for name in (scope.get("files") or []) if str(name) in inventory
            ]
            if named:
                self._scope_files.setdefault(str(scope["scope_id"]), named)
        for scope_id in planned.get("excluded", []):
            # An excluded scope is decided, not forgotten: it gets a coverage row in EXCLUDED with
            # the planner's reason, which is a different claim from `unseen` and must stay so.
            text = str(scope_id)
            bb.set_coverage(
                self.blackboard,
                _exclusion_scope_id(text),
                CoverageState.EXCLUDED,
                reason=f"planner excluded it: {text}",
            )
        return items

    # ── stage 3–6: discovery, validation, attack paths, closure ────────────

    def _discovery_and_closure(self) -> None:
        """Discovery rounds, each followed by a coverage decision and then validation.

        The loop is bounded by `max_rounds`, and it only continues while a scope is genuinely
        `INSUFFICIENT`. Both halves matter: without the state check the run would re-dispatch
        everything until the round budget ran out, which is a run that spends its whole budget
        re-reading the same files.

        Validation sits *inside* the loop, after the closure decision. It has to: the decision is
        "is this scope's evidence sufficient", and a candidate nobody has judged yet is not
        evidence, so closure can only converge if the judging has happened. An earlier version ran
        validation once after the loop, which left the final coverage table describing round 0 --
        every scope still `INSUFFICIENT` next to a blackboard full of verdicts. The verdicts and
        the coverage table have to be about the same run.
        """
        pending = list(self._planned_scopes)
        new_by_scope: dict[str, int] = {}
        rounds = max(1, self.config.max_rounds)
        for round_index in range(rounds + 1):
            if not pending:
                break
            # Round 0 is a round. The counter is the number of discovery passes that actually
            # happened, because that is what the report's "共 N 轮" claims -- counting only the
            # re-dispatches made a two-pass run report one.
            self.rounds_run += 1
            self.trail.emit(
                "stage",
                stage="discovery",
                state="round",
                round=round_index,
                scopes=len(pending),
                counters=self.trail.counters(self.blackboard),
            )
            if round_index > 0:
                log.info(
                    "harness: round %d re-dispatches %d scope(s) left INSUFFICIENT: %s",
                    round_index,
                    len(pending),
                    ", ".join(pending),
                )
            new_by_scope = self._discover(pending, round_index=round_index)
            # Validate *before* deciding coverage, not after. The reason closure needs the verdicts is
            # the whole argument for validating inside the loop at all; running it afterwards made
            # closure look at this round's candidates while they were still undecided, so every round
            # was forced to add another one just to clear that clause. Measured on the demo: the loop
            # always ran to `max_rounds`, and the coverage reasons blamed "本轮新发现 N 个候选" for
            # rounds where N was 1.
            #
            # Wrapped as its own stage, because it *is* one. Called plainly, validation's agent runs
            # inherit the enclosing "discovery" stage, and a reader watching the run sees "探索代码"
            # for the whole loop while more than half the agent runs were validation -- measured on
            # the first real audit: 13 validation runs inside a stage labelled discovery.
            self._stage("validation", self._validation)
            self._close_coverage(
                self._candidate_map(), round_index=round_index, new_by_scope=new_by_scope
            )
            pending = [
                scope_id
                for scope_id in self._planned_scopes
                if (entry := bb.coverage_of(self.blackboard, scope_id)) is not None
                and entry.state is CoverageState.INSUFFICIENT
                and self._needs_discovery(scope_id, new_by_scope)
            ]
            give_up = [
                scope_id
                for scope_id in pending
                if self._scope_failures.get(scope_id, 0) > self.config.max_scope_retries
            ]
            if give_up:
                # A scope that has failed `max_scope_retries` times is not dispatched again. It stays
                # INSUFFICIENT in the coverage table -- that is the honest record -- but the run stops
                # paying an agent to fail at it, and the note says which scopes and why. Measured: 3
                # scopes ended budget/error in each of the 4 rounds of the module audit.
                pending = [scope_id for scope_id in pending if scope_id not in give_up]
                self.dataflow_notes.append(
                    f"{len(give_up)} scope(s) stopped being re-dispatched after "
                    f"{self.config.max_scope_retries} failed attempt(s): {', '.join(give_up)} -- "
                    "their coverage rows stay INSUFFICIENT"
                )
            if pending and not self._round_is_worth_it(new_by_scope, pending):
                self.dataflow_notes.append(
                    f"stopped after round {round_index}: this round found "
                    f"{sum(new_by_scope.values())} new place(s), below "
                    f"{self.config.min_round_yield_ratio:.0%} of everything found so far -- "
                    f"{len(pending)} scope(s) were still INSUFFICIENT"
                )
                pending = []
            if round_index < rounds:
                for scope_id in pending:
                    self.tasks.update(f"W-{scope_id}", state=WorkItemState.PLANNED)
        # Closing sweep. Validation now runs inside every round, so this only catches what a round
        # could not decide (an agent that errored on a candidate leaves it without a verdict), and it
        # is cheap by construction: `_validation` only looks at candidates that have none.
        self._follow_leads()
        self._continue_gaps()
        self._stage("validation", self._complete_validation)
        still_open_new_places = {
            scope: count for scope, count in new_by_scope.items()
            if (entry := bb.coverage_of(self.blackboard, scope)) is not None
            and entry.state is CoverageState.INSUFFICIENT
        }
        self._close_coverage(self._candidate_map(), round_index=self.rounds_run,
                             new_by_scope=still_open_new_places)
        if pending:
            # The bound bit. Recorded here because the report has to be able to say "this stopped
            # early", and the coverage rows already carry the reason each scope is still open.
            self.dataflow_notes.append(
                f"round budget exhausted after {self.rounds_run} round(s): "
                f"{len(pending)} scope(s) are still INSUFFICIENT ({', '.join(pending)}) -- "
                "the report below shows what was reached, not a converged picture"
            )
        log.info("harness: discovery/closure finished after %d round(s)", self.rounds_run)

    def _needs_discovery(self, scope_id: str, new_by_scope: dict[str, int]) -> bool:
        """Validation gaps alone must never restart a completed investigation."""
        return (
            not self._covered(scope_id)
            or self._scope_failures.get(scope_id, 0) > 0
            or bool(self._unread_in(scope_id))
            or new_by_scope.get(scope_id, 0) >= max(1, self.config.min_new_places_per_round)
            or any(item.pending_updates for item in self.blackboard.work
                   if item.scope_id == scope_id
                   and item.kind in (WorkItemKind.FILE_REVIEW, WorkItemKind.INVESTIGATION))
        )

    def _record_gap(self, text: str) -> str:
        work = self.tasks.get(getattr(self._current, "work_id", ""))
        payload = _json_object(text)
        if work is None or not payload:
            raise ValueError("gap 必须关联当前调查任务")
        if payload.get("gap_id"):
            linked = {lead.lead_id for lead in self.blackboard.leads if lead.linked_work_id == work.work_id}
            target = next(((item, gap) for item in self.blackboard.work for gap in item.gaps
                           if gap.gap_id == payload["gap_id"] and (item.work_id == work.work_id or gap.lead_id in linked)), None)
            if target is None:
                raise ValueError("不能修改未分配给当前任务的缺口")
            owner, gap = target
            refs = payload.get("evidence_refs")
            facts = {r.record_id for r in self.blackboard.investigation_records
                     if r.category == "source_fact" and r.work_id == work.work_id}
            if payload.get("state") != "resolved" or not isinstance(refs, list) or not refs or any(ref not in facts for ref in refs):
                raise ValueError("解决已分配缺口需要本任务记录的源码事实证据")
            gap.state, gap.reason = "resolved", str(payload.get("reason") or "已补充源码检查")
            gap.evidence_refs = sorted(set(gap.evidence_refs) | set(refs))
            self.tasks.update(owner.work_id, gaps=owner.gaps)
            return f"缺口 {gap.gap_id} 已解决"
        kind, question = payload.get("kind"), payload.get("question")
        if kind not in {"unread", "basic_check", "relationship", "tool_failure"} or not isinstance(question, str) or not question.strip():
            raise ValueError("gap 需要具体 kind 和 question")
        file, line = payload.get("file"), payload.get("line")
        if file not in set(coverage.inventory(self.workspace)) or type(line) is not int or line < 1:
            raise ValueError("gap 需要仓库内源码位置")
        refs = payload.get("evidence_refs", [])
        facts = {r.record_id for r in self.blackboard.investigation_records if r.category == "source_fact"}
        if not isinstance(refs, list) or any(not isinstance(ref, str) or ref not in facts for ref in refs):
            raise ValueError("缺口证据必须引用已记录的源码事实")
        state = payload.get("state", "pending")
        if state not in {"pending", "resolved"} or (state == "resolved" and not refs):
            raise ValueError("解决缺口需要源码事实证据")
        identity = json.dumps([work.work_id, kind, file, line, " ".join(question.split()).casefold()])
        gap_id = "G-" + hashlib.sha256(identity.encode()).hexdigest()[:20]
        gap = next((g for g in work.gaps if g.gap_id == gap_id), None)
        if gap is not None and gap.state == "resolved":
            return "已解决的重复缺口不重启调查"
        created = gap is None
        if gap is None:
            gap = WorkGap(gap_id=gap_id, kind=kind, question=question.strip(), file=file, line=line)
            work.gaps.append(gap)
        before = gap.model_dump()
        gap.evidence_refs = sorted(set(gap.evidence_refs) | set(refs))
        gap.state = state
        gap.reason = str(payload.get("reason") or "待补充具体检查")
        if kind == "relationship" and state == "pending" and not gap.lead_id:
            self._apply_record("lead", json.dumps(dict(to_scope="investigation", question=question,
                               file=file, line=line, evidence_refs=refs)), work.scope_id)
            gap.lead_id = self.blackboard.leads[-1].lead_id
        if before != gap.model_dump() or created:
            self.tasks.update(work.work_id, gaps=work.gaps)
        return f"缺口 {gap_id}：{state}"

    def _progress_key(self, work: WorkItem) -> tuple:
        # Titles and free-text reasons do not count as new evidence.
        ranges = coverage.unread_ranges(work.files, coverage.from_runs(self.blackboard.runs))
        return (tuple((name, tuple(windows)) for name, windows in sorted(ranges.items())),
                tuple(sorted({(r.file, r.line) for r in self.blackboard.investigation_records
                              if r.work_id == work.work_id and r.category == "source_fact"})),
                tuple(sorted(g.gap_id for g in work.gaps if g.state == "resolved")))

    def _continue_gaps(self) -> None:
        for turn in range(max(0, self.config.max_gap_continuations)):
            runnable = []
            before = {}
            for work in self.blackboard.work:
                pending = [g for g in work.gaps if g.state == "pending" and g.kind != "relationship"]
                if not pending or work.state in {WorkItemState.CANCELED, WorkItemState.RUNNING}:
                    continue
                if (work.gap_continuations >= self.config.max_gap_continuations
                        or work.no_progress_continuations >= self.config.max_no_progress_continuations):
                    for gap in pending:
                        gap.state, gap.reason = "blocked", "缺口续查次数耗尽或没有新的源码证据"
                    self.tasks.update(work.work_id, gaps=work.gaps, state=WorkItemState.BLOCKED,
                                      status_reason="具体缺口受阻，已有证据保留")
                    continue
                before[work.work_id] = self._progress_key(work)
                self.tasks.update(work.work_id, state=WorkItemState.PLANNED,
                                  gap_continuations=work.gap_continuations + 1)
                runnable.append(work.scope_id)
            if not runnable:
                break
            self._discover(runnable, round_index=f"gap:{turn}")
            for work_id, old in before.items():
                work = self.tasks.get(work_id)
                stalled = old == self._progress_key(work)
                self.tasks.update(work_id, no_progress_continuations=(work.no_progress_continuations + 1 if stalled else 0))
            self._stage("validation", self._validation)
            self._follow_leads()
        for work in self.blackboard.work:
            for gap in work.gaps:
                if gap.state == "pending" and gap.kind != "relationship":
                    gap.state, gap.reason = "blocked", "本次缺口续查已停止，保留未完成检查"
            if work.gaps:
                self.tasks.update(work.work_id, gaps=work.gaps)

    def _round_is_worth_it(self, new_by_scope: dict[str, int], pending: list[str]) -> bool:
        """Whether another round is worth paying for, by marginal yield rather than by "not converged".

        The clause this replaces let the loop run to `max_rounds` on a *technicality*: as long as one
        scope anywhere found two new places, the run had "somewhere not yet looked at". With 42 scopes
        that is almost always true, so the last rounds were decided by the round bound, not by the
        evidence -- measured: rounds 2 and 3 cost 25 minutes and returned 19 of 161 confirmed findings.

        Two things are deliberately *not* stopped by it:

        * a scope whose files nobody has opened. That is not a marginal-yield question -- the next
          round has a known target (those files) rather than a guess -- so a concrete unread backlog
          keeps the loop alive;
        * anything at all when `min_round_yield_ratio` is 0, which restores the old behaviour.
        """
        ratio = self.config.min_round_yield_ratio
        if ratio <= 0:
            return True
        for scope_id in pending:
            entry = bb.coverage_of(self.blackboard, scope_id)
            if entry is not None and UNREAD_REASON_MARKER in (entry.reason or ""):
                return True
        found_now = sum(new_by_scope.values())
        places = {(candidate.file, candidate.line) for candidate in self.blackboard.candidates}
        if not places:
            return True
        return found_now >= ratio * len(places)

    def _discover(self, scope_ids: list[str], *, round_index: int) -> dict[str, int]:
        """Run discovery for each scope, bounded by `concurrency`, each stopping at its bound.

        Returns how many *new* candidates each scope produced this round -- the signal closure uses
        to tell "there is more here" from "this is everything". One agent run per scope, and a scope
        that fails (or runs out of steps) is closed `ABANDONED`, which the coverage pass reads as
        "not covered". Nothing here retries inside a round: a retry would spend a second agent's
        budget on a scope without any record that it did.

        The scopes are taken as given, *not* filtered to the work items still in `PLANNED` state.
        That filter is how a re-dispatched round silently did nothing: round 0 closes every work
        item, so a second round that selected only open items selected nothing, and the coverage
        loop burned its whole round budget re-dispatching to nobody while still reporting
        `INSUFFICIENT`. `round_index` is what says whether this is a first pass or a re-dispatch;
        the callers pass exactly the scopes they mean to spend on.

        Reuse happens in **every** round, round 0 included: a file another scope already read
        completely is the same bytes, and re-fetching it costs a round trip per scope.
        """
        items = {
            item.scope_id: item for item in self.blackboard.work
            if item.kind in (WorkItemKind.FILE_REVIEW, WorkItemKind.INVESTIGATION)
        }
        work = sorted([items[scope_id] for scope_id in scope_ids if scope_id in items], key=lambda item: item.priority)
        if not work:
            return {}
        new_by_scope: dict[str, int] = {}
        # Position plus round, so a scope re-dispatched for being INSUFFICIENT is approached from a
        # different perspective than the pass that failed to close it.
        positions = {item.scope_id: index for index, item in enumerate(work)}

        def one(item: WorkItem) -> None:
            if item.state is WorkItemState.CANCELED:
                return
            try:
                _discover_one(item)
            except Exception:
                # A run that raised (an unreachable gateway, a broken tool) never reached the
                # bookkeeping below, so the failure is counted here -- otherwise a scope whose agent
                # dies every round looks like a scope nobody ever tried to run.
                self._scope_failures[item.scope_id] = (
                    self._scope_failures.get(item.scope_id, 0) + 1
                )
                raise

        def _discover_one(item: WorkItem) -> None:
            with self._board_lock:
                initial_places = {(c.file, c.line) for c in self.blackboard.candidates if c.scope_id == item.scope_id}
            owned = self._scope_files.get(item.scope_id) or []
            previous_reads = coverage.from_runs(self.blackboard.runs)
            self.tasks.update(item.work_id, unread_ranges=coverage.unread_ranges(owned, previous_reads))
            prefetched_steps: list[AgentStep] = []
            prefetched_files: list[str] = []
            skipped_files: list[str] = []
            reused_files: list[str] = []
            if round_index:
                # A re-dispatch is handed only what is still unread: starting the whole group again
                # spends the budget re-reading files the previous agent already finished.
                assigned = self._unread_in(item.scope_id) or None
            else:
                assigned = owned or None
            # Reuse happens in **every** round, round 0 included: a file another scope already read
            # completely is the same bytes, and re-fetching it costs a round trip per scope -- measured
            # on a four-file project, five scopes each spent a turn reading the same four files.
            #
            # A scope that owns no files shares nothing rather than everything (`replayable_reads`
            # treats an empty list as a no-op): a planner-created scope with no `files` has no
            # assignment to base the reuse on, and handing it the whole repository would be a scope
            # whose context is the workspace.
            if owned:
                wanted = (self._unread_in(item.scope_id) or owned) if round_index else owned
                if round_index:
                    wanted = [name for name in wanted if name not in previous_reads or previous_reads[name].fully_read]
                (
                    prefetched_steps,
                    reused_files,
                    prefetched_files,
                    skipped_files,
                ) = agents.prefetch_scope_files(
                    wanted,
                    self.context,
                    budget=self.config.material_budget,
                    blackboard=self.blackboard,
                )
            outcome = self._agent(
                agent=agents.DISCOVERY,
                scope_id=item.scope_id,
                task=agents.discovery_task(
                    self.blackboard,
                    item,
                    attempt=round_index + 1 if isinstance(round_index, int) else 2,
                    files=assigned,
                    reused=reused_files,
                    prefetched=prefetched_files,
                    skipped=skipped_files,
                ),
                context=self.context,
                client=self.client,
                max_steps=self.config.steps_per_agent,
                blackboard=self.blackboard,
                run_id=f"discovery:{item.scope_id}:r{round_index}",
                initial_steps=prefetched_steps or None,
                extra_system="Pending task updates (read BOARD before finishing): " + agents._json(item.pending_updates) + "\n" + agents.discovery_extra_system(
                    self.blackboard,
                    item.scope_id,
                    index=positions.get(item.scope_id, 0) + (round_index if isinstance(round_index, int) else 0),
                    files=self._scope_files.get(item.scope_id),
                ),
            )
            found = outcome.parsed or []
            if outcome.parsed is None:
                log.warning(
                    "harness: discovery for %s produced nothing usable (%s)",
                    item.scope_id,
                    outcome.error,
                )
            # Places this scope had already recorded, before this round. What closure needs to know
            # is whether the scope found somewhere **new to look at**, and a second opinion about a
            # line already in the ledger is not that -- see `_close_coverage` for the measurement
            # that made this distinction necessary.
            with self._board_lock:
                existing = {c.candidate_id for c in self.blackboard.candidates if c.scope_id == item.scope_id}
                remaining_budget = max(0, self.config.candidates_per_scope - len(existing))
                accepted = [c for c in found if c.candidate_id in existing]
                accepted.extend([c for c in found if c.candidate_id not in existing][:remaining_budget])
                self._record_candidates(accepted)
                new_by_scope[item.scope_id] = len(
                    {(c.file, c.line) for c in self.blackboard.candidates if c.scope_id == item.scope_id} - initial_places
                )
            # `DONE` is what marks the scope as looked at; a run that hit its step budget still
            # looked, and `stop_reason` in the transcript is what says it stopped early. Only an
            # outright error leaves the item ABANDONED, which closes the scope as uncovered.
            finished = outcome.run.stop_reason in ("finished", "budget")
            bb.close_work(
                self.blackboard,
                item.work_id,
                state=WorkItemState.DONE if finished else WorkItemState.ABANDONED,
                steps_used=len(outcome.run.steps),
            )
            with self._board_lock:
                consumed = getattr(self._current, "consumed_updates", set()) if finished and outcome.parsed is not None else set()
                remaining = [lead_id for lead_id in item.pending_updates if lead_id not in consumed]
                for lead in self.blackboard.leads:
                    if lead.lead_id in consumed:
                        lead.status = "handled"
                        self.trail.emit("record", record_kind="lead_status", scope=item.scope_id,
                                        text=f"{lead.question}：handled", lead=lead.model_dump(mode="json"), work_id=item.work_id)
                self.tasks.update(item.work_id, pending_updates=remaining,
                                  state=WorkItemState.PLANNED if remaining else item.state,
                                  status_reason="仍有待处理线索" if remaining else "本次调查已结束，等待覆盖检查")
                if consumed or remaining:
                    bb.save(self.blackboard, self.run_dir)
            # Counted per scope, so a scope that fails every round can be dropped from the re-dispatch
            # list instead of being paid for again: measured on the module audit, 3 scopes ended
            # budget/error in every one of the 4 rounds, and each was re-dispatched anyway.
            self._scope_failures[item.scope_id] = (
                0 if finished else self._scope_failures.get(item.scope_id, 0) + 1
            )

        batch_size = max(1, self.config.max_scopes_per_round)
        for offset in range(0, len(work), batch_size):
            work[offset:] = sorted(work[offset:], key=lambda item: item.priority)
            self._bounded(work[offset:offset + batch_size], one, label="discovery")
        return new_by_scope

    def _plan_inbox(self, *, force: bool = False, idle: bool = False) -> None:
        """Snapshot/commit only known pending leads. Failure never acknowledges the snapshot."""
        if not self._planner_lock.acquire(blocking=False):
            return
        try:
            with self._board_lock:
                pending = [lead for lead in self.blackboard.leads if lead.status == "pending"]
                if not pending or self._planner_calls >= self.config.planner_calls:
                    return
                now = _now()
                oldest = min(lead.raised_at for lead in pending)
                due = (now - oldest).total_seconds() >= self.config.planner_wait_seconds
                if not force and not due and not idle:
                    return
                if not idle and not due and self._planner_last_at and (now - self._planner_last_at).total_seconds() < self.config.planner_min_interval:
                    return
                snapshot = {lead.lead_id: lead.model_copy(deep=True) for lead in pending[:40]}
                directory = [{"work_id": w.work_id, "title": w.title, "state": w.state.value,
                              "kind": w.kind.value, "files": w.files, "completion_criteria": w.completion_criteria,
                              "question": w.question, "priority": w.priority}
                             for w in self.blackboard.work]
                refs = {ref for lead in snapshot.values() for ref in lead.evidence_refs}
                evidence = [r.model_dump(mode="json") for r in self.blackboard.investigation_records if r.record_id in refs]
                self._planner_calls += 1
                self._planner_last_at = now
            outcome = self._agent(
                agent=agents.PLAN_UPDATE, scope_id="plan-inbox", context=self.context,
                client=self.client, max_steps=min(3, self.config.steps_per_agent),
                run_id=f"planner-inbox:{self._planner_calls}",
                task=agents._json({"tasks": directory, "leads": [v.model_dump(mode="json") for v in snapshot.values()],
                                   "evidence": evidence, "budget": self.budget.snapshot(),
                                   "remaining_planner_calls": self.config.planner_calls - self._planner_calls}),
            )
            if not isinstance(outcome.parsed, dict):
                return
            decisions = outcome.parsed.get("decisions")
            if not isinstance(decisions, list):
                return
            inventory = set(coverage.inventory(self.workspace))
            # Validate the complete response before applying any decision.
            seen = set()
            for decision in decisions:
                if not isinstance(decision, dict):
                    return
                lead_id, action = decision.get("lead_id"), decision.get("action")
                if not isinstance(lead_id, str) or not isinstance(action, str) or lead_id not in snapshot or lead_id in seen or action not in {"link", "create", "defer", "dismiss", "priority", "merge"} or not isinstance(decision.get("reason"), str) or not decision["reason"].strip():
                    return
                seen.add(lead_id)
                if action in {"link", "priority", "merge"}:
                    if not isinstance(decision.get("work_id"), str):
                        return
                    work = self.tasks.get(decision.get("work_id", ""))
                    if work is None or work.kind not in {WorkItemKind.FILE_REVIEW, WorkItemKind.INVESTIGATION} or work.state is WorkItemState.CANCELED:
                        return
                    if action in {"priority", "merge"} and work.state is not WorkItemState.PLANNED:
                        return
                if "priority" in decision and (type(decision["priority"]) is not int or decision["priority"] not in (1, 2, 3)):
                    return
                if action == "priority" and "priority" not in decision:
                    return
                if action == "merge":
                    source = self.tasks.get(decision.get("source_work_id", ""))
                    if (source is None or source.work_id == work.work_id
                            or source.kind is not WorkItemKind.INVESTIGATION or source.state is not WorkItemState.PLANNED
                            or source.attempts or source.gaps or work.kind is not WorkItemKind.INVESTIGATION
                            or set(source.files) != set(work.files)
                            or " ".join((source.question or source.title).split()).casefold() != " ".join((work.question or work.title).split()).casefold()):
                        return
                if action == "create":
                    files = decision.get("files")
                    if not isinstance(files, list) or not files or any(not isinstance(f, str) or f not in inventory for f in files):
                        return
                    if not all(isinstance(decision.get(key), str) and decision[key].strip() for key in ("title", "completion_criteria")):
                        return
            with self._board_lock:
                for decision in decisions:
                    lead = next(entry for entry in self.blackboard.leads if entry.lead_id == decision["lead_id"])
                    if lead.status != "pending" or lead.sequence != snapshot[lead.lead_id].sequence:
                        continue
                    action = decision["action"]
                    if action in {"link", "priority", "merge"}:
                        target = self.tasks.get(decision["work_id"])
                        if target.state is WorkItemState.CANCELED or (action != "link" and target.state is not WorkItemState.PLANNED):
                            continue
                    if action == "merge":
                        source = self.tasks.get(decision["source_work_id"])
                        if source.state is not WorkItemState.PLANNED or source.attempts or source.gaps:
                            continue
                        updates = list(dict.fromkeys([*target.pending_updates, *source.pending_updates]))
                        self.tasks.update(target.work_id, pending_updates=updates)
                        self.tasks.update(source.work_id, state=WorkItemState.CANCELED, merged_into=target.work_id,
                                          pending_updates=[], status_reason=decision["reason"])
                        bb.set_coverage(self.blackboard, source.scope_id, CoverageState.EXCLUDED,
                                        reason=f"重复待办已合并到 {target.work_id}：{decision['reason']}")
                        self._planned_scopes = [scope for scope in self._planned_scopes if scope != source.scope_id]
                        for previous in self.blackboard.leads:
                            if previous.linked_work_id == source.work_id:
                                previous.linked_work_id = target.work_id
                                self.trail.emit("record", record_kind="lead_status", lead=previous.model_dump(mode="json"))
                    lead.processing_reason = str(decision["reason"])
                    if action in {"dismiss", "defer"}:
                        lead.status = "dismissed" if action == "dismiss" else "deferred"
                    else:
                        if action == "create":
                            question_key = " ".join(lead.question.split()).casefold()
                            existing = next((w for w in self.blackboard.work
                                             if w.kind is WorkItemKind.INVESTIGATION and not w.merged_into
                                             and " ".join(w.question.split()).casefold() == question_key
                                             and set(w.files) == set(decision["files"])), None)
                            scope_id = existing.scope_id if existing else "lead-" + lead.lead_id
                            work = self.tasks.add(WorkItem(
                                work_id=f"W-{scope_id}", scope_id=scope_id, title=str(decision["title"]),
                                rationale=lead.processing_reason, files=decision["files"],
                                completion_criteria=str(decision["completion_criteria"]),
                                question=lead.question, priority=decision.get("priority", 2),
                            ))
                            self._scope_files[scope_id] = list(work.files)
                            if scope_id not in self._planned_scopes:
                                self._planned_scopes.append(scope_id)
                        else:
                            work = self.tasks.get(decision["work_id"])
                        if action == "priority":
                            self.tasks.update(work.work_id, priority=decision["priority"])
                        lead.status = "linked"
                        lead.linked_work_id = work.work_id
                        duplicate = next((previous for previous in self.blackboard.leads
                                          if previous.lead_id != lead.lead_id and previous.linked_work_id == work.work_id
                                          and previous.status == "handled" and previous.file == lead.file and previous.line == lead.line
                                          and " ".join(previous.question.split()).casefold() == " ".join(lead.question.split()).casefold()
                                          and set(lead.evidence_refs) <= set(previous.evidence_refs)), None)
                        if duplicate:
                            lead.status, lead.processing_reason = "dismissed", "相同起点、问题与证据的线索已处理，不重新启动调查"
                            self.blackboard.revision += 1
                            self.trail.emit("record", record_kind="lead_status", lead=lead.model_dump(mode="json"))
                            continue
                        if work.state is WorkItemState.CANCELED:
                            lead.status, lead.processing_reason = "deferred", "相同任务已取消，不自动重启"
                            self.blackboard.revision += 1
                            self.trail.emit("record", record_kind="lead_status", lead=lead.model_dump(mode="json"))
                            continue
                        updates = list(dict.fromkeys([*work.pending_updates, lead.lead_id]))
                        self.tasks.update(work.work_id, pending_updates=updates,
                                          status_reason=f"线索待处理：{lead.question}；{lead.processing_reason}")
                        if work.state is not WorkItemState.RUNNING:
                            self.tasks.update(work.work_id, state=WorkItemState.PLANNED)
                    self.blackboard.revision += 1
                    self.trail.emit("record", record_kind="lead_status", scope=lead.to_scope,
                                    text=f"{lead.question}：{lead.status}；{lead.processing_reason}",
                                    lead=lead.model_dump(mode="json"), work_id=lead.linked_work_id)
                bb.save(self.blackboard, self.run_dir)
        except Exception as exc:
            self.trail.emit("record", record_kind="planner_error", text=f"Planner 失败，收件箱保留：{exc}")
        finally:
            self._planner_lock.release()

    def _follow_leads(self) -> None:
        """Bounded known-gap sweep, reusing original tasks and retaining blocked updates."""
        for turn in range(self.config.planner_calls + self.config.max_lead_continuations + 1):
            self.check_abort("lead-followup")
            before_calls = self._planner_calls
            self._plan_inbox(force=True, idle=True)
            runnable = []
            with self._board_lock:
                for work in self.blackboard.work:
                    if not work.pending_updates or work.state in {WorkItemState.CANCELED, WorkItemState.RUNNING}:
                        continue
                    continuations = sum(":rlead:" in a.run_id for a in work.attempts)
                    if continuations >= self.config.max_lead_continuations:
                        self.tasks.update(work.work_id, state=WorkItemState.BLOCKED, status_reason="线索续查次数耗尽，未处理更新保留")
                        continue
                    runnable.append(work.scope_id)
            if not runnable:
                if self._planner_calls > before_calls and any(entry.status == "pending" for entry in self.blackboard.leads):
                    continue
                break
            self._discover(runnable, round_index=f"lead:{turn}")
            self._stage("validation", self._validation)
            self._close_coverage(self._candidate_map(), round_index=turn, new_by_scope={})

        if self._planner_calls >= self.config.planner_calls:
            for lead in self.blackboard.leads:
                if lead.status == "pending" and not lead.processing_reason:
                    lead.processing_reason = "Planner 调用预算耗尽；未处理事件保留"
                    self.blackboard.revision += 1
                    self.trail.emit("record", record_kind="lead_status", lead=lead.model_dump(mode="json"))

    def _candidate_map(self) -> dict[str, list[Candidate]]:
        out: dict[str, list[Candidate]] = {}
        for candidate in self.blackboard.candidates:
            out.setdefault(candidate.scope_id, []).append(candidate)
        return out

    def _record_candidates(self, candidates: list[Candidate]) -> list[Candidate]:
        """Append discovery results. Returns the ones that were new.

        `add_candidate` is idempotent on `candidate_id`, which is why a second round over a scope
        cannot duplicate what the first found -- the ids are derived from the site, not generated.

        Returning the candidates rather than a count is what lets the two callers -- a real round and
        the dry run's signal scan -- share this path, and with it the trail events. A dry run that
        recorded candidates without emitting them would show a candidate count next to an empty
        candidate table, which reads as "the scan found nothing" instead of "the record is partial".
        """
        added: list[Candidate] = []
        for candidate in candidates:
            group = [c for c in self.blackboard.candidates
                     if agents.validation_group_key(c) == agents.validation_group_key(candidate)]
            def facts(members):
                return {" ".join(value.split()).casefold() for member in members
                        for value in [*member.evidence, *member.entry_points] if value.strip()}
            new_facts = facts([candidate]) - facts(group)
            old = bb.find_candidate(self.blackboard, candidate.candidate_id)
            version = max((c.evidence_version for c in group), default=1)
            if group and new_facts:
                version += 1
                ids = {c.candidate_id for c in group}
                for existing in group:
                    existing.evidence_version = version
                self.blackboard.verdict_history.extend(v for v in self.blackboard.verdicts if v.candidate_id in ids)
                self.blackboard.attack_path_history.extend(p for p in self.blackboard.attack_paths if p.candidate_id in ids)
                self.blackboard.verdicts = [v for v in self.blackboard.verdicts if v.candidate_id not in ids]
                for entry in self.blackboard.coverage:
                    entry.confirmed = sum(1 for c in self.blackboard.candidates if c.scope_id == entry.scope_id
                                          and (v := bb.find_verdict(self.blackboard, c.candidate_id)) is not None
                                          and v.verdict is VerdictKind.CONFIRMED)
                self.blackboard.attack_paths = [p for p in self.blackboard.attack_paths if p.candidate_id not in ids]
                self.blackboard.findings = [f for f in self.blackboard.findings if f.candidate_id not in ids]
                for kind in (WorkItemKind.VALIDATION, WorkItemKind.ATTACK_PATH):
                    if kind is WorkItemKind.ATTACK_PATH and not any(
                        w.kind is kind and ids.intersection(w.candidate_ids) for w in self.blackboard.work
                    ):
                        continue
                    work_id = self._claim_work(group, kind)
                    self.tasks.update(work_id, state=WorkItemState.PLANNED if kind is WorkItemKind.VALIDATION else WorkItemState.BLOCKED,
                                      status_reason=f"关键证据已更新至版本 {version}，等待重新验证")
                self.trail.emit("record", record_kind="evidence_changed", candidate_ids=sorted(ids),
                                evidence_version=version, text="新增入口或证据，旧裁决和攻击路径已归档")
                self.blackboard.revision += 1
            candidate.evidence_version = version
            if old is not None:
                old.evidence = list(dict.fromkeys([*old.evidence, *candidate.evidence]))
                old.entry_points = list(dict.fromkeys([*old.entry_points, *candidate.entry_points]))
                old.evidence_version = version
                continue
            if bb.add_candidate(self.blackboard, candidate):
                added.append(candidate)
                self.trail.emit(
                    "candidate",
                    candidate_id=candidate.candidate_id,
                    scope=candidate.scope_id,
                    file=candidate.file,
                    line=candidate.line,
                    vulnerability_type=candidate.vulnerability_type,
                    title=trail_mod.clip(candidate.title, 200),
                    method=candidate.method,
                    evidence_version=candidate.evidence_version,
                )
        return added

    def _close_coverage(
        self,
        candidates_by_scope: dict[str, list[Candidate]],
        *,
        round_index: int,
        new_by_scope: dict[str, int] | None = None,
    ) -> None:
        """Decide every planned scope, with a reason a reader can check.

        The decision rule, and why each clause is there:

        * nothing covered the scope -- no discovery run for it (dry run), or its work item is
          `ABANDONED` because the agent errored -> `INSUFFICIENT`. "We did not look" must never be
          dressed up as "we looked and it was clean".
        * this round's discovery found **new places** -- file:line pairs the scope had not recorded
          before -> `INSUFFICIENT`. There is somewhere here the last round never looked, so the scope
          is not saturated yet.
        * otherwise, if every candidate the scope has carries a verdict -> `SUFFICIENT`. This is the
          clause that lets the run terminate: a re-dispatched scope that found nowhere new, and whose
          candidates have since been decided, is genuinely closed.
        * otherwise the scope has candidates nobody has judged yet -> `INSUFFICIENT`. Closure runs
          before validation by construction, so at closure time "found something we have not judged"
          is not sufficient evidence.

        `new_by_scope` is passed in rather than recomputed because only the discovery step knows
        what *this round* added; the blackboard can only say what exists. The distinction is what
        makes the loop converge: round 0 finds places (INSUFFICIENT), round 1 finds nowhere new and
        closes -- instead of re-dispatching forever because candidates exist.

        **Places, not candidate ids, and that distinction cost 25 minutes.** This clause used to
        count every newly added *candidate*, and `candidate_id` includes the vulnerability type, so a
        model that revisited one line and gave it a second type produced what the code called a new
        candidate. Measured on a five-file Python fixture: every round re-flagged `orders.py:17/18`
        under a different type, so every scope stayed INSUFFICIENT for all four rounds and the run
        spent 21 discovery + 26 validation agent runs on 243 lines of code, stopping only because the
        round bound bit. A second opinion about a line already in the ledger is not "somewhere we have
        not looked", which is what this rule has always claimed to be about.

        **And a round has to clear a threshold** (`min_new_places_per_round`): the clause above is
        now "at least N new places", not "any new place". One new line per round is a reviewer
        annotating, not a scope that has not been looked at -- and the difference is 2 rounds instead
        of 4 on the fixture. `min_new_places_per_round = 0` restores the old behaviour.
        """
        new_by_scope = new_by_scope or {}
        for scope_id in self._planned_scopes:
            entry = bb.coverage_of(self.blackboard, scope_id)
            if entry is not None and entry.state is CoverageState.EXCLUDED:
                continue
            candidates = candidates_by_scope.get(scope_id, [])
            work = self.tasks.get(f"W-{scope_id}")
            gaps = [g for g in work.gaps if g.state != "resolved"] if work else []
            if gaps:
                bb.set_coverage(self.blackboard, scope_id, CoverageState.INSUFFICIENT,
                                reason="未完成检查：" + "；".join(g.question + "（" + g.reason + "）" for g in gaps))
                continue
            if not self._covered(scope_id):
                latest = work.attempts[-1] if work and work.attempts else None
                if latest is not None and latest.stop_reason == "error":
                    total = len(work.files)
                    read = work.read_files
                    reason = (
                        f"第 {round_index} 轮：没有任何 discovery 成功完成；"
                        f"已完整读取 {read}/{total} 个归属文件，"
                        f"但 discovery 执行失败，未产生可用于覆盖结论的最终回答："
                        f"{latest.error or '未知执行错误'}"
                    )
                else:
                    reason = (
                        f"第 {round_index} 轮：没有成功完成的 discovery"
                        "（没有对应工作项，或 agent 以 error/budget 结束），因此它是未覆盖的"
                    )
                bb.set_coverage(self.blackboard, scope_id, CoverageState.INSUFFICIENT, reason=reason)
                continue
            discovered_now = new_by_scope.get(scope_id, 0)
            threshold = max(1, self.config.min_new_places_per_round)
            if discovered_now >= threshold:
                reason = (
                    f"第 {round_index} 轮：本轮在 {discovered_now} 个此前没见过位置发现了候选"
                    f"（阈值 {threshold}），说明还有上一轮没看到的地点，尚不能判定为收敛"
                    "（同一位置换个类型再报一次不算新地点）"
                )
                bb.set_coverage(self.blackboard, scope_id, CoverageState.INSUFFICIENT, reason=reason)
                continue
            unread = self._unread_in(scope_id)
            if unread:
                # Coverage measured from the `read` calls outranks every clause below it, and this is
                # the clause whose absence let every scope close while 29 of 59 files had never been
                # opened. A scope whose files nobody finished reading has not been looked at, whatever
                # the model concluded about it -- and naming the files is what makes the next round a
                # second look rather than a re-run.
                listed = "、".join(unread[:6]) + ("…" if len(unread) > 6 else "")
                reason = (
                    f"第 {round_index} 轮：本 scope 还有 {len(unread)} 个文件从未被完整读取"
                    f"（{listed}）；{UNREAD_REASON_MARKER}，搜索命中不算审完"
                )
                bb.set_coverage(self.blackboard, scope_id, CoverageState.INSUFFICIENT, reason=reason)
                continue
            undecided = [
                candidate
                for candidate in candidates
                if bb.find_verdict(self.blackboard, candidate.candidate_id) is None
            ]
            if undecided:
                reason = (
                    f"第 {round_index} 轮：该 scope 的 {len(undecided)}/{len(candidates)} "
                    "个候选尚无研判结论，证据不足以收敛"
                )
                bb.set_coverage(self.blackboard, scope_id, CoverageState.INSUFFICIENT, reason=reason)
                continue
            if candidates:
                small = (
                    f"；本轮只新发现 {discovered_now} 个位置（低于阈值 {threshold}），"
                    "该数量不足以再付一轮的代价"
                    if discovered_now
                    else "；本轮未发现新地点"
                )
                reason = (
                    f"第 {round_index} 轮：discovery 已覆盖该 scope{small}，"
                    f"已有 {len(candidates)} 个候选全部有研判结论，判定为收敛"
                )
            else:
                reason = (
                    f"第 {round_index} 轮：discovery 已覆盖该 scope 且未发现任何候选；"
                    "这是“看过且没有命中”，不是“跳过”"
                )
            bb.set_coverage(self.blackboard, scope_id, CoverageState.SUFFICIENT, reason=reason)

        # One event per scope, read back from the ledger rather than emitted at the five
        # `set_coverage` calls above: there is one decision per scope per round, and a record that
        # could disagree with the ledger it describes would be worse than no record.
        for scope_id in self._planned_scopes:
            entry = bb.coverage_of(self.blackboard, scope_id)
            if entry is None:
                continue
            self.tasks.update(
                f"W-{scope_id}",
                state=WorkItemState.DONE if entry.state is CoverageState.SUFFICIENT else (
                    WorkItemState.CANCELED if entry.state is CoverageState.EXCLUDED else WorkItemState.BLOCKED
                ),
                status_reason=entry.reason,
                read_files=len(self._scope_files.get(scope_id) or []) - len(self._unread_in(scope_id)),
                unread_ranges=coverage.unread_ranges(self._scope_files.get(scope_id) or [], coverage.from_runs(self.blackboard.runs)),
                candidate_ids=[c.candidate_id for c in self.blackboard.candidates if c.scope_id == scope_id],
            )
            self.trail.emit(
                "coverage",
                scope=scope_id,
                state=entry.state.value,
                round=round_index,
                reason=trail_mod.clip(entry.reason),
                files=len(self._scope_files.get(scope_id) or []),
                unread=len(self._unread_in(scope_id)),
            )

    def _unread_in(self, scope_id: str) -> list[str]:
        """Files this scope owns that nobody has read end to end.

        A planner-created scope may own no files -- the planner returns ids, and not always an
        inventory -- while the survey's scopes carry theirs and coverage groups always do. An empty
        result means "nothing to hold this scope to", which is why the other closure clauses still
        matter rather than being replaced by this one.
        """
        owned = self._scope_files.get(scope_id)
        if not owned:
            return []
        return coverage.unread_in(owned, coverage.from_runs(self.blackboard.runs))

    def _covered(self, scope_id: str) -> bool:
        """Whether anything actually looked at this scope.

        Read from the work ledger, not from `runs`: a dry run has no agent runs at all, and a
        closure rule that keyed on runs marked every dry-run scope "nothing has looked at it" --
        while the dry run's own note said it had scanned them. The work item is the right record
        because it is what the planner opened and what the discovery step closes.
        """
        items = [item for item in self.blackboard.work if item.scope_id == scope_id]
        if not items:
            return False
        return any(
            (item.state is WorkItemState.DONE if not item.attempts else any(
                attempt.agent == agents.DISCOVERY and not attempt.error
                and attempt.stop_reason in ("finished", "budget")
                for attempt in item.attempts
            ))
            for item in items
            if item.kind in (WorkItemKind.FILE_REVIEW, WorkItemKind.INVESTIGATION)
        )

    def _complete_validation(self) -> None:
        for _ in range(max(1, self.config.max_claim_attempts)):
            before = sum(len(w.attempts) for w in self.blackboard.work if w.kind is WorkItemKind.VALIDATION)
            self._validation()
            after = sum(len(w.attempts) for w in self.blackboard.work if w.kind is WorkItemKind.VALIDATION)
            if before == after:
                break

    def _validation(self) -> None:
        """Validate every *claim* that does not already have a verdict.

        Idempotent by construction: the input is "claims without verdicts", so re-entering this stage
        (a resumed run, or the next discovery round) validates only what is missing instead of
        re-deciding and appending.

        **By claim, not by candidate id, and that distinction cost 41 agent runs.** Measured on the
        `upp-module-infra` audit: 139 validation runs for 98 distinct claims. The extra 41 are the same
        position re-registered in a later round -- discovery files an instance the round before did not
        name, `find_verdict` is asked about *that* `candidate_id`, gets None, and the claim is paid for
        a second and third time. The decision for a location is a property of the location, so a new
        instance inherits it; it is copied rather than skipped, because a candidate with no verdict
        would hold its scope INSUFFICIENT forever.
        """
        pending = [
            candidate
            for candidate in self.blackboard.candidates
            if bb.find_verdict(self.blackboard, candidate.candidate_id) is None
        ]
        if not pending:
            return

        # What each already-decided location was decided as. Built from the ledger, not from a second
        # source of truth: the verdicts are the decisions this run actually paid for.
        decided: dict[tuple[str, int | None, str], CandidateVerdict] = {}
        for candidate in self.blackboard.candidates:
            verdict = bb.find_verdict(self.blackboard, candidate.candidate_id)
            if verdict is not None:
                decided.setdefault(agents.validation_group_key(candidate), verdict)

        inherited = 0
        undecided: list[Candidate] = []
        for candidate in pending:
            verdict = decided.get(agents.validation_group_key(candidate))
            if verdict is None:
                undecided.append(candidate)
                continue
            copy = verdict.model_copy(deep=True)
            copy.reasons = [
                *copy.reasons,
                f"同一位置（{candidate.file}:{candidate.line}）此前已有裁决，"
                "本条作为该位置的后续记录继承结论，没有为同一位置重复付费",
            ]
            self._apply_verdict([candidate], copy)
            inherited += 1
        if inherited:
            log.info(
                "harness: %d candidate(s) inherited an existing verdict for their own location; "
                "%d claim(s) still need one",
                inherited,
                len(undecided),
            )
        pending = undecided
        if not pending:
            return

        # One validation per *claim*, not per recorded instance. The ledger keeps every instance --
        # coverage is counted per scope and a scope whose candidate carried no verdict would stay
        # INSUFFICIENT forever -- but the decision is paid for once and copied, which is what turns
        # 106 candidates into 56 agent runs without touching the closure rule.
        groups = agents.validation_groups(pending)
        groups = {key: members for key, members in groups.items()
                  if self._claim_allowed(members, WorkItemKind.VALIDATION)}
        for members in groups.values():
            self._claim_work(members, WorkItemKind.VALIDATION)
        if self.config.claim_batch_size > 1:
            self._validation_batched(groups)
            return

        def one(members: list[Candidate]) -> None:
            self._validation_single(members)

        self._bounded(list(groups.values()), one, label="validation")

    def _apply_verdict(self, members: list[Candidate], verdict: CandidateVerdict) -> None:
        """Record one decision for every instance of the claim it was reached for.

        Split out of `_validation` because the batched path reaches decisions too, and the property
        that matters -- *every* instance carries the verdict, with the merge made visible in
        `reasons` -- has to hold identically on both paths. A batch that recorded the verdict only for
        the representative would leave the other instances undecided, which the closure rule reads as
        "this scope was not looked at", and the run would re-dispatch it forever.
        """
        candidate = agents.group_representative(members)
        for member in members:
            copy = verdict.model_copy(deep=True)
            copy.candidate_id = member.candidate_id
            copy.evidence_version = member.evidence_version
            if len(members) > 1:
                copy.reasons = [
                    *copy.reasons,
                    f"由同一位置（{candidate.file}:{candidate.line}，共 {len(members)} 条实例）"
                    "的一次验证统一判定",
                ]
            bb.add_verdict(self.blackboard, copy)
            self.trail.emit(
                "verdict",
                candidate_id=copy.candidate_id,
                scope=member.scope_id,
                file=member.file,
                line=member.line,
                vulnerability_type=member.vulnerability_type,
                verdict=copy.verdict.value,
                evidence_kind=copy.evidence_kind.value,
                confidence=copy.confidence,
                merged_from=len(members),
                reason=trail_mod.clip("；".join(copy.reasons[:2])),
            )
        self.tasks.update(
            self._claim_work(members, WorkItemKind.VALIDATION),
            state=WorkItemState.DONE,
            status_reason=f"{verdict.verdict.value}：{'；'.join(verdict.reasons)}",
        )
        if verdict.verdict is VerdictKind.REJECTED:
            ids = {member.candidate_id for member in members}
            for work in self.blackboard.work:
                if work.kind is WorkItemKind.ATTACK_PATH and ids.intersection(work.candidate_ids):
                    self.tasks.update(work.work_id, state=WorkItemState.CANCELED,
                                      status_reason="当前证据版本的候选已排除，无需补攻击路径")

    @staticmethod
    def _prefetch_derived(step: Any) -> bool:
        """Whether a harness-run `dataflow_verify` produced a path this run must carry itself.

        A trace that derived a path is typed evidence attached to *the run it happened in*, so a claim
        holding one cannot share a run with other claims. A trace that failed, or that the worker could
        not answer, leaves nothing to attribute -- which is what makes batching such a claim safe.
        """
        if step is None or getattr(step, "result", None) is None or not step.result.ok:
            return False
        evidence = (step.result.data or {}).get("evidence") or {}
        return bool(evidence.get("path")) and not evidence.get("error")

    def _validation_batched(self, groups: dict[tuple[str, int | None, str], list[Candidate]]) -> None:
        """Validate several *different* claims per run, each with its own verdict.

        Batching changes what a run reads, never how a claim is decided: the decisions are copied to
        every instance by the same `_apply_verdict` the single-claim path uses, and a batch that
        cannot settle a claim by reading says `needs_dataflow` for it and is re-run alone with the
        trace tool. See `agents.pack_claim_batches` for how the batches are packed (material overlap,
        deep claims alone) and `HarnessConfig.claim_batch_size` for why this is off by default.
        """
        from services.harness import material

        def files_of(candidate: Candidate) -> list[str]:
            return material.files_for(candidate)

        # A claim whose *prefetch derived a path* runs alone: the path is typed evidence attached while
        # the run is happening (`dataflow_evidence` reads the last trace in the run), and one run
        # cannot attribute one trace to four claims. A taint-*shaped* claim whose prefetch produced
        # nothing has no such evidence to mis-attribute, so it is batchable -- and a batch that turns
        # out to need a trace for it answers `needs_dataflow` and gets a second, tool-rich run.
        singleton: list[list[Candidate]] = []
        batchable: list[list[Candidate]] = []
        prefetched_by_id: dict[str, Any] = {}
        for group in groups.values():
            candidate = agents.group_representative(group)
            if agents.is_taint_candidate(candidate):
                prefetched = agents.verify_taint_candidate(candidate, self.context)
                if self._prefetch_derived(prefetched):
                    singleton.append(group)
                    prefetched_by_id[candidate.candidate_id] = prefetched
                    continue
            batchable.append(group)

        for members in singleton:
            candidate_id = agents.group_representative(members).candidate_id
            if not self._validation_single(members, prefetched=prefetched_by_id[candidate_id]):
                # An agent that produced nothing must not be turned into a `rejected` verdict: the
                # next round re-dispatches the scope and this claim is validated then, exactly as the
                # single-claim path has always done.
                log.info("harness: validation for %s deferred", candidate_id)

        by_id = {agents.group_representative(g).candidate_id: g for g in batchable}
        batches = agents.pack_claim_batches(
            batchable, files_of=files_of, max_batch=self.config.claim_batch_size
        )
        escalate: list[str] = []

        def run_batch(batch: list[list[Candidate]]) -> None:
            claims = [(agents.group_representative(g), g) for g in batch]
            ids = [candidate.candidate_id for candidate, _ in claims]
            outcome = self._agent(
                agent=agents.VALIDATION_BATCH,
                work_ids=[self._claim_work(group, WorkItemKind.VALIDATION) for group in batch],
                scope_id=f"batch({len(claims)})",
                task=agents.validation_batch_task(
                    self.blackboard, claims, material_budget=self.config.material_budget
                ),
                context=self.context,
                client=self.client,
                max_steps=self.config.steps_per_agent,
                blackboard=self.blackboard,
                run_id=f"validation:batch:{ids[0]}+{len(ids) - 1}",
                extra_system=agents.validation_extra_system(
                    self.blackboard,
                    claims[0][0].scope_id,
                    files=[candidate.file for candidate, _ in claims],
                ),
            )
            if outcome.parsed is None:
                log.warning(
                    "harness: batch validation produced nothing (%s); %d claim(s) stay undecided",
                    outcome.error,
                    len(claims),
                )
                return
            parsed: agents.BatchVerdicts = outcome.parsed
            for verdict in parsed.verdicts:
                members = by_id.get(verdict.candidate_id)
                if members is None:
                    log.warning(
                        "harness: batch verdict for %s is not in this batch; dropped",
                        verdict.candidate_id,
                    )
                    continue
                self._apply_verdict(members, verdict)
            escalate.extend(parsed.escalate)

        self._bounded(batches, run_batch, label="validation")
        # `needs_dataflow` claims, and any claim the batch never answered, get their own run -- which
        # is the tool-rich path. Answering "I need a trace" must not be a way to drop a claim.
        undecided = [
            candidate_id
            for candidate_id in by_id
            if bb.find_verdict(self.blackboard, candidate_id) is None
        ]
        for candidate_id in dict.fromkeys([*escalate, *undecided]):
            members = by_id.get(candidate_id)
            if members is not None:
                self._validation_single(members)

    def _validation_single(self, members: list[Candidate], *, prefetched: Any = _PREFETCH) -> bool:
        """One validation run for one claim. `False` when the run produced no verdict.

        `prefetched` is the harness-run `dataflow_verify` step for this claim, or the `_PREFETCH`
        sentinel meaning "run it if this claim is taint-shaped". The batched path already ran it while
        deciding whether the claim could be batched, and re-running it would spend the same tool call
        twice for no new information.
        """
        if not self._claim_allowed(members, WorkItemKind.VALIDATION):
            return False
        candidate = agents.group_representative(members)
        if prefetched is _PREFETCH:
            # Taint-shaped candidates are traced *before* the model sees them, so whether dataflow
            # was consulted stops being a preference the model can decline -- see
            # `agents.verify_taint_candidate` for why that delegation failed in practice. The step
            # is prepended at index 0 so the transcript reads in the order things happened, and so a
            # model that runs its own trace still has the last word: `dataflow_evidence` searches
            # the run backwards.
            prefetched = (
                agents.verify_taint_candidate(candidate, self.context)
                if agents.is_taint_candidate(candidate)
                else None
            )
        # The path the prefetch just derived is exactly the material this validator needs: the
        # functions the value crosses, taken out of the files so it does not have to read them
        # again. When there is no prefetch (a non-taint-shaped candidate) the packet is still the
        # hit's own function, which is what a validator reads first anyway.
        evidence = None
        if prefetched is not None and prefetched.result is not None:
            evidence = (prefetched.result.data or {}).get("evidence") or None
        task = agents.validation_task(
            self.blackboard,
            candidate,
            prefetched=prefetched,
            dataflow=evidence,
            material_budget=self.config.material_budget,
        )
        note = agents.group_note(members)
        if note:
            task = f"{task}\n\n{note}"
        outcome = self._agent(
            agent=agents.VALIDATION,
            work_ids=[self._claim_work(members, WorkItemKind.VALIDATION)],
            scope_id=candidate.candidate_id,
            task=task,
            context=self.context,
            client=self.client,
            max_steps=self.config.steps_per_agent,
            blackboard=self.blackboard,
            run_id=f"validation:{candidate.candidate_id}",
            # The lite skill is keyed on the *candidate's* file rather than on a scope name: the
            # skill is about the kind of code, and a scope id says nothing about that. The sibling
            # rule rides along, because a validator that finds a control on one member of a family
            # will otherwise reject the whole family with it.
            extra_system=agents.validation_extra_system(
                self.blackboard, candidate.scope_id, files=[candidate.file]
            ),
            # Seeded, not appended afterwards: the verdict is parsed from this run while it is
            # still inside `agents.run`, so a step added on the way out is a step the verdict
            # never sees -- which is exactly how the first version of this lost the trace it had
            # just paid for.
            initial_steps=[prefetched] if prefetched is not None else None,
        )
        if outcome.parsed is None:
            # No verdict is recorded for any member: an agent that produced nothing must not be
            # turned into a `rejected` verdict, which would put a decision in the report that
            # nobody made.
            log.warning(
                "harness: validation for %s produced no verdict (%s)",
                candidate.candidate_id,
                outcome.error,
            )
            return False
        self._apply_verdict(members, outcome.parsed)
        return True

    def _complete_attack_paths(self) -> None:
        for _ in range(max(1, self.config.max_claim_attempts)):
            before = sum(len(w.attempts) for w in self.blackboard.work if w.kind is WorkItemKind.ATTACK_PATH)
            self._attack_paths()
            after = sum(len(w.attempts) for w in self.blackboard.work if w.kind is WorkItemKind.ATTACK_PATH)
            if before == after:
                break

    def _attack_paths(self) -> None:
        confirmed = [
            candidate
            for candidate in bb.confirmed_candidates(self.blackboard)
            if bb.find_attack_path(self.blackboard, candidate.candidate_id) is None
        ]
        if not confirmed:
            return

        groups = list(agents.validation_groups(confirmed).values())
        groups = [members for members in groups if self._claim_allowed(members, WorkItemKind.ATTACK_PATH)]
        for members in groups:
            self._claim_work(members, WorkItemKind.ATTACK_PATH)
        if self.config.claim_batch_size > 1:
            self._attack_paths_batched(groups)
            return

        def one(members: list[Candidate]) -> None:
            self._attack_path_one(members, self._attack_path_run(members))

        self._bounded(groups, one, label="attack_path")

    def _attack_path_run(self, members: list[Candidate]) -> AttackPath | None:
        """The agent run for one confirmed claim, or None when it produced nothing usable."""
        if not self._claim_allowed(members, WorkItemKind.ATTACK_PATH):
            return None
        candidate = agents.group_representative(members)
        verdict = bb.find_verdict(self.blackboard, candidate.candidate_id)
        if verdict is None:  # pragma: no cover - confirmed implies a verdict
            return None
        outcome = self._agent(
            agent=agents.ATTACK_PATH,
            work_ids=[self._claim_work(members, WorkItemKind.ATTACK_PATH)],
            scope_id=candidate.candidate_id,
            task=agents.attack_path_task(
                self.blackboard,
                candidate,
                verdict,
                material_budget=self.config.material_budget,
                members=members,
            ),
            context=self.context,
            client=self.client,
            max_steps=self.config.steps_per_agent,
            blackboard=self.blackboard,
            run_id=f"attack_path:{candidate.candidate_id}",
            extra_system=agents.lite_skill_for_scope(self.blackboard, candidate.scope_id),
        )
        if outcome.parsed is None:
            log.warning(
                "harness: attack path for %s produced nothing usable (%s)",
                candidate.candidate_id,
                outcome.error,
            )
            return None
        path: AttackPath = outcome.parsed
        # Every entry the instances named, not only the ones the agent echoed back. The agent is
        # asked for the union and usually returns it; this is what makes "usually" not matter, because
        # an entry that was recorded once must not vanish from the report.
        for entry in agents.instance_entry_points(members):
            if entry not in path.entry_points:
                path.entry_points.append(entry)
        return path

    def _attack_path_one(self, members: list[Candidate], path: AttackPath | None) -> None:
        """Record one path for every instance of the claim it was established for."""
        if path is None:
            return
        for member in members:
            copy = path.model_copy(deep=True)
            copy.candidate_id = member.candidate_id
            copy.evidence_version = member.evidence_version
            bb.add_attack_path(self.blackboard, copy)
            self.trail.emit(
                "attack_path",
                candidate_id=copy.candidate_id,
                scope=member.scope_id,
                file=member.file,
                line=member.line,
                reachable=copy.reachable,
                confidence=copy.confidence,
                impact=trail_mod.clip(copy.impact),
                entry_points=copy.entry_points[:4],
            )
        self.tasks.update(
            self._claim_work(members, WorkItemKind.ATTACK_PATH),
            state=WorkItemState.DONE,
            status_reason=f"可达性：{'可达' if path.reachable else '未确认可达'}；{path.impact}",
        )

    def _attack_paths_batched(self, groups: list[list[Candidate]]) -> None:
        """Several confirmed claims per attack-path run, each with its own path.

        Measured basis: 72 attack-path runs for 161 confirmed candidates, 34 minutes. Confirmed
        candidates that sit in one file share the entry points their stage exists to find, so the
        packing is the same one validation uses (`agents.pack_claim_batches`). A claim the batch does
        not answer is re-run alone: `reachable=False` is a claim about the code, and must not double as
        "nobody looked".
        """
        from services.harness import material

        by_id = {agents.group_representative(g).candidate_id: g for g in groups}
        batches = agents.pack_claim_batches(
            groups,
            files_of=lambda candidate: material.files_for(candidate),
            max_batch=self.config.claim_batch_size,
        )

        def run_batch(batch: list[list[Candidate]]) -> None:
            claims = []
            for group in batch:
                candidate = agents.group_representative(group)
                verdict = bb.find_verdict(self.blackboard, candidate.candidate_id)
                if verdict is not None:
                    claims.append((candidate, group, verdict))
            if not claims:
                return
            ids = [candidate.candidate_id for candidate, _, _ in claims]
            outcome = self._agent(
                agent=agents.ATTACK_PATH_BATCH,
                work_ids=[self._claim_work(group, WorkItemKind.ATTACK_PATH) for group in batch],
                scope_id=f"batch({len(claims)})",
                task=agents.attack_path_batch_task(
                    self.blackboard, claims, material_budget=self.config.material_budget
                ),
                context=self.context,
                client=self.client,
                max_steps=self.config.steps_per_agent,
                blackboard=self.blackboard,
                run_id=f"attack_path:batch:{ids[0]}+{len(ids) - 1}",
                extra_system=agents.lite_skill_for_scope(
                    self.blackboard, claims[0][0].scope_id
                ),
            )
            if outcome.parsed is None:
                log.warning(
                    "harness: batch attack path produced nothing (%s); %d claim(s) have no path",
                    outcome.error,
                    len(claims),
                )
                return
            for path in outcome.parsed:
                members = by_id.get(path.candidate_id)
                if members is None:
                    log.warning(
                        "harness: batch attack path for %s is not in this batch; dropped",
                        path.candidate_id,
                    )
                    continue
                for entry in agents.instance_entry_points(members):
                    if entry not in path.entry_points:
                        path.entry_points.append(entry)
                self._attack_path_one(members, path)

        self._bounded(batches, run_batch, label="attack_path")
        # Whatever the batch did not answer gets its own run, which is the shape this stage always
        # had -- so batching can add cost, but it can never leave a confirmed candidate unexplained.
        for candidate_id, members in by_id.items():
            if bb.find_attack_path(self.blackboard, candidate_id) is None:
                self._attack_path_one(members, self._attack_path_run(members))

    # ── stage 7: findings ──────────────────────────────────────────────────

    def _emit_findings(self) -> None:
        """Turn confirmed candidates into `FinalFinding`s.

        Severity is derived here rather than asked of a model: it is a function of confirmed impact
        and reachability, both of which are already in the blackboard, and a model asked for a
        severity score would be inventing a number whose only support is its own confidence.
        """
        findings: list[FinalFinding] = []
        # One finding per *claim*. The candidates were all recorded and all judged -- coverage is
        # counted per scope and depends on every instance carrying a verdict -- but the report is a
        # list a human reads, and eight entries for one `ORDER BY ${}` sink is not eight findings.
        # The other instances travel with the finding instead of being dropped.
        for members in agents.validation_groups(bb.confirmed_candidates(self.blackboard)).values():
            candidate = agents.group_representative(members)
            verdict = bb.find_verdict(self.blackboard, candidate.candidate_id)
            path = bb.find_attack_path(self.blackboard, candidate.candidate_id)
            if verdict is None:  # pragma: no cover - confirmed implies a verdict
                continue
            if path is None:
                # Reachability was never established. Recorded at the lowest severity and said so:
                # "confirmed but unreachable-unknown" must not read like a live vulnerability.
                severity = "low"
                summary = (
                    "已确认存在，但攻击路径阶段没有得出结论（可达性未知）："
                    "在按可利用漏洞处置之前需要人工确认可达性。"
                )
            else:
                severity = _severity(
                    path,
                    vulnerability_type=candidate.vulnerability_type,
                    dataflow=verdict.dataflow,
                )
                summary = path.impact or "；".join(verdict.reasons[:3])
            if len(members) > 1:
                summary = f"{summary}（同位点共 {len(members)} 条实例，合并为一条发现）"
            findings.append(
                FinalFinding(
                    finding_id=f"F-{candidate.candidate_id.removeprefix('C-')}",
                    candidate_id=candidate.candidate_id,
                    title=candidate.title,
                    vulnerability_type=candidate.vulnerability_type,
                    file=candidate.file,
                    line=candidate.line,
                    severity=severity,
                    evidence_kind=verdict.evidence_kind,
                    dataflow=verdict.dataflow,
                    attack_path=path,
                    summary=summary,
                    affected_locations=[
                        {
                            "candidate_id": member.candidate_id,
                            "scope_id": member.scope_id,
                            "file": member.file,
                            "line": member.line,
                            "title": member.title,
                            # Per instance, because that is where the difference lives: the report
                            # must be able to show that one record of this sink named an anonymous
                            # route and another named a guarded one.
                            "entry_points": list(member.entry_points),
                        }
                        for member in members
                    ]
                    if len(members) > 1
                    else [],
                )
            )
        # Same-claim merge first (the loop above), then the flow merge: two findings at opposite ends
        # of *one* Joern-derived path are one vulnerability, and reporting them separately is how a
        # five-file demo delivered ten findings for one bug.
        findings = _merge_findings_by_flow(findings)
        bb.set_findings(self.blackboard, findings)
        for finding in findings:
            self.trail.emit(
                "finding",
                finding_id=finding.finding_id,
                candidate_id=finding.candidate_id,
                file=finding.file,
                line=finding.line,
                vulnerability_type=finding.vulnerability_type,
                severity=finding.severity,
                title=trail_mod.clip(finding.title, 200),
                merged_locations=len(finding.affected_locations),
                summary=trail_mod.clip(finding.summary),
            )

    # ── dry run ────────────────────────────────────────────────────────────

    def _dry_run(self) -> HarnessResult:
        """Plan and scan deterministically. No model call, no agent, no tool.

        The point is to exercise the plumbing end to end -- survey, plan, coverage ledger, report --
        on a checkout where nothing is configured. It deliberately does *not* claim to have covered
        anything: the closure note and every coverage reason say this was a dry run, and the
        signal-scan candidates are recorded as rejected with the reason, so the report can never be
        mistaken for a real result.
        """
        started = _now()
        # The dry run emits the same stage vocabulary as a real one, so a screen watching a run
        # does not need a second code path for the plumbing check. It does not run the stages --
        # there is no model -- it reports the phases it actually executed.
        self.trail.emit("stage", stage="plan", state="start", dry_run=True)
        snapshot = survey.survey_workspace(self.workspace)
        project: ProjectContext = snapshot["project"]
        scopes: list[survey.Scope] = snapshot["scopes"]
        bb.set_context(self.blackboard, project=project)
        bb.set_context(
            self.blackboard,
            architecture=ArchitectureMap(
                components=snapshot["components"],
                trust_boundaries=[],
                notes=[f"{SURVEY_RATIONALE_PREFIX} dry run: architecture from directory names only"],
            ),
            threats=ThreatModel(
                notes=["dry run: the threat model needs a model call and was not produced"],
            ),
        )
        items = self._survey_work_items(scopes)
        bb.add_work(
            self.blackboard,
            [*self._coverage_items(), *items],
        )
        self._publish_discovery_tasks()
        self._planned_scopes = [item.scope_id for item in self.blackboard.work]
        self.trail.emit(
            "stage", stage="plan", state="end", dry_run=True, scopes=len(self._planned_scopes)
        )
        self.trail.emit("stage", stage="discovery", state="start", dry_run=True)

        new_by_scope: dict[str, int] = {}
        signals = [
            Candidate(
                candidate_id=agents.stable_candidate_id(
                    signal.scope_id, signal.file, signal.line, signal.vulnerability_type
                ),
                scope_id=signal.scope_id,
                title=signal.title,
                vulnerability_type=signal.vulnerability_type,
                file=signal.file,
                line=signal.line,
                rationale=signal.rationale,
                evidence=[f"dry-run signal at {signal.file}:{signal.line}"],
                discovered_by="survey",
            )
            for signal in survey.signals(
                self.workspace, scopes, max_per_scope=self.config.candidates_per_scope
            )
        ]
        # The same recorder a real round uses, so the dry run's trail carries the same events --
        # its candidates show up in the audit screen's candidate table instead of only in a count.
        # Counted per *place*, exactly as `_discover` counts it: the two paths have to agree on what
        # "new" means, or a dry run and a real run would answer differently about one repository.
        places: dict[str, set[tuple[str, int | None]]] = {}
        for candidate in self._record_candidates(signals):
            places.setdefault(candidate.scope_id, set()).add((candidate.file, candidate.line))
        new_by_scope: dict[str, int] = {scope: len(found) for scope, found in places.items()}

        # The scan is what "covered" means here: every planned scope was walked by the signal scan,
        # including the ones that matched nothing. Closing the work items is what records that, and
        # it is the same record a real run's discovery step writes -- so the coverage rule is one
        # rule, not two.
        for item in self.blackboard.work:
            bb.close_work(self.blackboard, item.work_id, state=WorkItemState.DONE, steps_used=0)

        # The verdict pass stands in for the validation stage, which needs a model. Every signal
        # is recorded as *rejected with the reason that it was never judged*: leaving them without a
        # verdict would let the report show candidates and no decision, and marking them confirmed
        # would be the one thing a dry run must never do.
        for candidate in self.blackboard.candidates:
            verdict = CandidateVerdict(
                candidate_id=candidate.candidate_id,
                verdict=VerdictKind.REJECTED,
                evidence_kind=EvidenceKind.SEMANTIC,
                reasons=[
                    "dry run：未执行验证阶段（没有模型调用），因此这条信号既未确认也未排除。"
                    "它只是关键词/正则命中，不是污点分析结论。"
                ],
                confidence=0.0,
            )
            bb.add_verdict(self.blackboard, verdict)
            self.trail.emit(
                "verdict",
                candidate_id=verdict.candidate_id,
                scope=candidate.scope_id,
                file=candidate.file,
                line=candidate.line,
                vulnerability_type=candidate.vulnerability_type,
                verdict=verdict.verdict.value,
                evidence_kind=verdict.evidence_kind.value,
                confidence=verdict.confidence,
                merged_from=1,
                reason=trail_mod.clip("；".join(verdict.reasons[:2])),
            )
        self.trail.emit(
            "stage",
            stage="discovery",
            state="end",
            dry_run=True,
            counters=self.trail.counters(self.blackboard),
        )

        # Coverage, run to closure so the re-dispatch path is exercised without a model: round 0
        # finds signals (new -> INSUFFICIENT), round 1 rescans and re-derives the same candidate ids
        # (nothing new, and the verdicts now exist) and closes. Empty scopes close in round 0.
        for round_index in range(max(1, self.config.max_rounds)):
            self.rounds_run += 1
            self.trail.emit(
                "stage", stage="discovery", state="round", round=round_index, dry_run=True
            )
            self._close_coverage(
                self._candidate_map(), round_index=round_index, new_by_scope=new_by_scope
            )
            pending = [
                scope_id
                for scope_id in self._planned_scopes
                if (entry := bb.coverage_of(self.blackboard, scope_id)) is not None
                and entry.state is CoverageState.INSUFFICIENT
            ]
            if not pending:
                break
            self.dataflow_notes.append(
                f"dry run：第 {round_index} 轮结束时有 {len(pending)} 个 scope 为 INSUFFICIENT，"
                f"按覆盖率收敛规则会重新派发 discovery：{', '.join(sorted(pending))}"
            )
            # The rescan finds the same sites, which dedupe against the ids already on the
            # blackboard -- so the next round sees nothing new and can close.
            new_by_scope = {}

        self._emit_findings()
        note = (
            f"dry run：未调用任何模型，未调用任何工具，未产生 FinalFinding。"
            f"共 {self.rounds_run} 轮覆盖率遍历、{len(self.blackboard.candidates)} 条信号、"
            f"{len(self.blackboard.coverage)} 个 scope。"
            f"（耗时 {(_now() - started).total_seconds():.2f}s）"
        )
        self.blackboard = bb.mark_closed(self.blackboard, note)
        return self._finish(dry_run=True)

    # ── plumbing ───────────────────────────────────────────────────────────

    def _finish(self, *, dry_run: bool = False, fatal: str | None = None) -> HarnessResult:
        """Persist the blackboard and write the report. Always both, even after a fatal error."""
        self.tasks.trail = self.trail
        self.tasks.board = self.blackboard
        self.blackboard.execution_budget = self.budget.snapshot()
        if not dry_run:
            for item in self.blackboard.work:
                if item.kind not in (WorkItemKind.FILE_REVIEW, WorkItemKind.INVESTIGATION):
                    continue
                if item.state is WorkItemState.CANCELED:
                    continue
                entry = bb.coverage_of(self.blackboard, item.scope_id)
                if entry is None or entry.state not in (CoverageState.SUFFICIENT, CoverageState.EXCLUDED):
                    self.tasks.update(
                        item.work_id, state=WorkItemState.BLOCKED,
                        status_reason=self.budget.reason or (entry.reason if entry and entry.reason else "覆盖检查尚未完成"),
                    )
        self.tasks.stop(fatal or self.budget.reason or "本次运行结束，任务尚未满足完成条件")
        unfinished_leads = [lead for lead in self.blackboard.leads if lead.status not in {"handled", "dismissed"}]
        if unfinished_leads:
            self.blackboard.closure_note += f" 仍有 {len(unfinished_leads)} 条未完成线索（预算耗尽、延期或等待处理），收件箱已保留。"
        incomplete = sum(item.state not in (WorkItemState.DONE, WorkItemState.CANCELED) for item in self.blackboard.work)
        if incomplete:
            self.blackboard.closure_note += f" 仍有 {incomplete} 项任务未完成，见任务清单。"
        run_dir = self.run_dir
        run_dir.mkdir(parents=True, exist_ok=True)
        # The round count is written onto the blackboard before it is serialised: the report reads
        # it from there, so a dry run (no agent runs at all) reports the same number the CLI does.
        self.blackboard.rounds_run = self.rounds_run
        bb.save(self.blackboard, run_dir)
        notes = list(self.dataflow_notes)
        unavailable = report.dataflow_failure_note(self.blackboard)
        if unavailable:
            notes.append(unavailable)
        report_path = report.write_report(self.blackboard, run_dir, notes=notes)
        # Last event, and the only one that is a *summary* rather than a happening: it carries the
        # counters a screen shows when the run is over, and `closed` so a reader polling the trail
        # can stop without also polling the job.
        self.trail.emit(
            "summary",
            run_dir=str(run_dir),
            report=str(report_path) if report_path else None,
            closed=self.blackboard.closed,
            closure_note=trail_mod.clip(self.blackboard.closure_note),
            dry_run=dry_run,
            fatal=fatal,
            counters=self.trail.counters(self.blackboard),
            execution_budget=self.blackboard.execution_budget,
        )
        return HarnessResult(
            blackboard=self.blackboard,
            run_dir=run_dir,
            report_path=report_path,
            dry_run=dry_run,
            fatal=fatal,
            notes=notes,
        )

    def _bounded(self, work: list, worker, *, label: str) -> None:
        """Run `worker` over `work` with `concurrency` threads, swallowing per-item failures.

        A stage failure is a result, not an exception: the run continues and the failure is visible
        in the ledger (an `ABANDONED` work item, a scope with no verdict). Letting one thread's
        exception escape would lose every other item's work with it.

        The abort check is inside `guarded` rather than around the pool, and that placement is the
        whole point: `pool.map` submits every item up front, so checking once before the pool would
        let all 56 validations run after a cancel and only then stop. Checked per item, at most the
        `concurrency` already in flight finish, and the queued ones raise immediately -- which is
        why the cancel takes effect in seconds instead of in the stage's remaining minutes.
        """
        if not work:
            return
        workers = max(1, min(self.config.concurrency, len(work)))

        def guarded(item):
            self.check_abort(label)
            try:
                return worker(item)
            except (ToolLayerUnavailable, CanceledAbort):
                raise
            except Exception as exc:  # noqa: BLE001 - one item's failure must not lose the others
                log.warning("harness: %s item failed (%s: %s)", label, type(exc).__name__, exc)
                return None

        # Keep at most `workers` submitted. `pool.map` eagerly queues the entire stage, which means a
        # provider outage discovered by the first four agents still launches every remaining scope.
        # Incremental submission makes the circuit breaker effective: only calls already in flight
        # finish after it trips.
        iterator = iter(work)
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = set()
            for _ in range(workers):
                try:
                    futures.add(pool.submit(guarded, next(iterator)))
                except StopIteration:
                    break
            while futures:
                done, futures = wait(futures, timeout=0.25, return_when=FIRST_COMPLETED)
                for future in done:
                    future.result()
                if label == "discovery":
                    self._plan_inbox(force=bool(done), idle=not futures)
                for _ in range(len(done)):
                    try:
                        futures.add(pool.submit(guarded, next(iterator)))
                    except StopIteration:
                        break


# ─────────────────────────────────────────────────────────── helpers


def _opening_run_id(agent: str) -> str:
    """The ledger id of an opening agent's run.

    The opening is single-round by design (recon once, threat model once, no cross-reading), so there
    is no pass suffix: `bb.add_run` keys on `run_id`, and a second opening run under the same id would
    be *dropped* rather than duplicated -- which is the safety net if someone reintroduces a loop
    without also restoring the suffix.
    """
    return f"{agent}:workspace"


def _json_object(text: str) -> dict | None:
    """A `{...}` out of whatever the model wrote, or None.

    Used by the `record` tool for the kinds whose payload is structured (a component, a threat, a
    lead). Lenient about fences and surrounding prose -- `services.ai.parse` already does that for
    answers, and a model that wraps JSON in a code fence has still produced the object -- but strict
    about the result being an object: a list or a bare string is not a component, and storing it would
    put something into the architecture map that no renderer can draw.
    """
    from services.ai.parse import extract_json_object

    raw = extract_json_object(text)
    if raw is None:
        return None
    try:
        payload = json.loads(raw)
    except json.JSONDecodeError:
        return None
    return payload if isinstance(payload, dict) else None


def _tools_of(agent: str) -> list[str]:
    """The tool names an agent may call, for the `agent_start` event.

    Read from the agent spec rather than repeated in the coordinator: a screen that listed the
    wrong tools for an agent would make the run's own record wrong about what it was allowed to do.
    """
    try:
        return [tool.value for tool in agents.spec(agent).tools]
    except Exception:  # pragma: no cover - an unknown agent is a programming error
        return []


def _build_context(
    workspace: Path, *, dataflow: Any = None, record: Any = None, board: Any = None
) -> Any:
    """Build the tool layer's `ToolContext`. Imported here, not at module import.

    A dry run, a coverage pass or `--help` must work without the tool package installed -- and
    during development it may genuinely not exist yet. The import is therefore inside the function
    that needs it, and the failure is turned into `ToolLayerUnavailable` naming what is missing.
    """
    from services.harness.tools import ToolContext, ToolLimits

    verifier = dataflow
    if verifier is None:
        verifier = _default_verifier(workspace)
    return ToolContext(
        workspace=workspace, limits=ToolLimits(), dataflow=verifier, record=record, board=board
    )


def _default_verifier(workspace: Path) -> Any:
    """The production `DataflowVerifier`, or None with a recorded reason.

    None is not a silent degradation: `dataflow_verify` reports `ok=False` with an explanation, the
    validation prompt tells the agent not to read that as "no path", and `dataflow_failure_note`
    carries the reason into the report.
    """
    try:
        from aegis_core.config import get_settings

        config = get_settings().dataflow
    except Exception as exc:  # pragma: no cover - settings are importable in this codebase
        log.warning("harness: dataflow settings unavailable (%s); dataflow_verify will refuse",
                    type(exc).__name__)
        return None
    if not config.enabled:
        return None
    try:
        from services.harness.tools import WorkerDataflowVerifier

        return WorkerDataflowVerifier(workspace, config=config)
    except Exception as exc:
        log.warning("harness: cannot build the dataflow verifier (%s: %s)", type(exc).__name__, exc)
        return None


#: Vulnerability classes whose severity is about *availability*. A reachable code smell is not a
#: denial of service: there is no measured magnitude and usually no armed entry point, and on the
#: five-file demo these were the two findings that came back `high` while the actual SQL injection
#: came back `low`. Capped at `medium` unless the flow behind them is specific (see `_severity`).
AVAILABILITY_TYPES = frozenset(
    {"denial_of_service", "resource_exhaustion", "security_misconfiguration"}
)

#: How many distinct methods a derived path may span and still count as *a path*.
#:
#: A parameter-anchored flow through a handful of functions is evidence. A "path" that visits eight
#: methods of a nine-function program is not a path, it is a pattern match on a call name -- measured
#: on the demo, the DoS candidate's derived source was `request.args.get` (a call anchor, not an
#: entry) and its flow covered every function in the repository, including the sanitised sibling.
MAX_FLOW_METHODS = 4


def _severity(path: AttackPath, *, vulnerability_type: str = "", dataflow: Any = None) -> str:
    """Severity from what is already established, not from a model's opinion.

    Reachability is the multiplier that matters: confirmed-and-reachable outranks
    confirmed-and-gated, and a finding whose impact was never established stays at `medium` rather
    than being promoted on the strength of a scary-looking weakness class.

    Two caps, both added after reading a real report where two code smells outranked the one real
    bug:

    * **availability classes** top out at `medium`. "Unclosed SQLite handle" and "`.replace` on a
      missing parameter" are defects; calling them `high` asserts a magnitude nobody measured.
    * **a broad flow is not a specific flow.** If the derived path spans more than
      `MAX_FLOW_METHODS` methods, it says "this value can reach that call somewhere in this program",
      which is not the same claim as "this entry reaches this sink".
    """
    if not path.reachable:
        return "low"
    breadth = len(getattr(dataflow, "methods", None) or [])
    broad = breadth > MAX_FLOW_METHODS
    if path.auth_conditions and not _looks_anonymous(path.auth_conditions):
        return "medium"
    if vulnerability_type in AVAILABILITY_TYPES or broad:
        return "medium"
    return "high"


def _looks_anonymous(auth_conditions: list[str]) -> bool:
    joined = " ".join(auth_conditions).lower()
    return any(word in joined for word in ("anonymous", "unauthenticated", "no auth", "none", "public"))


def _flow_locations(finding: FinalFinding) -> set[tuple[str, int | None]]:
    """The `file:line` pairs a finding's derived path touches, plus its own location.

    Empty when there is no derived path: a finding whose evidence is the model reading code cannot
    be joined to a flow, and must not be merged into one on the strength of a shared file name.
    """
    dataflow = finding.dataflow
    if dataflow is None or not dataflow.derived:
        return set()
    locations: set[tuple[str, int | None]] = {(finding.file, finding.line)}
    for step in dataflow.path:
        # The worker renders a step as `<file>:<line> <node>` (and inserts an explanatory node
        # between concatenated flows). Only the location prefix is usable; anything else is skipped
        # rather than guessed at.
        head = str(step).split(" ", 1)[0]
        if ":" not in head:
            continue
        file, _, line = head.rpartition(":")
        if not file or not line.isdigit():
            continue
        locations.add((file, int(line)))
    return locations


def _parameter_anchored(finding: FinalFinding) -> bool:
    """Whether the path starts at a *named entry function's parameter* rather than at a call pattern.

    This is the difference between "this entry reaches this sink" (a flow) and "some value matching
    this call name reaches that call somewhere" (a pattern). Measured on the demo: the denial-of-
    service claim's anchor was `request.args.get` and its "path" ran through all eight functions of
    the repository -- including the sanitised sibling -- so joining flows by that one would have
    merged a real injection with a control that neutralises it.
    """
    dataflow = finding.dataflow
    if dataflow is None or not dataflow.derived:
        return False
    source = (dataflow.source or "").strip()
    return source.endswith(")") and "(" in source and "." not in source.split("(", 1)[0]


def _merge_findings_by_flow(findings: list[FinalFinding]) -> list[FinalFinding]:
    """One vulnerability, one finding: merge the ends of the same Joern-derived path.

    Why this exists, measured: the injected SQL injection in `orders.order_report` came back as six
    findings -- the source line, the call site, the concatenation, the `execute`, and two more under
    a second vulnerability type -- because the same-claim merge keys on `(file, line, type)` and one
    flow has several lines and can be described as more than one class. A reader who has to triage
    ten findings to find one bug is reading a report that failed.

    Only *parameter-anchored* paths join, and only when their location sets intersect: two segments
    of one traced flow share the function where the value crosses over. Everything else -- semantic
    findings, pattern-anchored paths, unrelated flows through a shared file -- stays separate, which
    is what keeps a real bug from being merged with a control that defuses it.

    The merged finding keeps the representative's identity and severity is the **maximum** of the
    members', because merging must not quietly downgrade what one of the parts claimed.
    """
    flows: list[tuple[FinalFinding, set[tuple[str, int | None]]]] = [
        (finding, _flow_locations(finding))
        for finding in findings
        if _parameter_anchored(finding)
    ]
    if len(flows) < 2:
        return findings

    # Union-find over intersecting location sets.
    parent = {index: index for index in range(len(flows))}

    def find(index: int) -> int:
        while parent[index] != index:
            parent[index] = parent[parent[index]]
            index = parent[index]
        return index

    def union(left: int, right: int) -> None:
        root_left, root_right = find(left), find(right)
        if root_left != root_right:
            parent[max(root_left, root_right)] = min(root_left, root_right)

    for left in range(len(flows)):
        for right in range(left + 1, len(flows)):
            if flows[left][1] & flows[right][1]:
                union(left, right)

    groups: dict[int, list[FinalFinding]] = {}
    for index, (finding, _) in enumerate(flows):
        groups.setdefault(find(index), []).append(finding)

    merged: list[FinalFinding] = []
    for members in groups.values():
        if len(members) == 1:
            continue
        # The first member is the one the run reached first, which is the outermost claim (the
        # candidate that named the entry point) in practice.
        primary = members[0]
        locations = list(primary.affected_locations)
        seen = {(item.get("file"), item.get("line")) for item in locations}
        for member in members[1:]:
            if (member.file, member.line) in seen:
                continue
            seen.add((member.file, member.line))
            locations.append(
                {
                    "candidate_id": member.candidate_id,
                    "scope_id": "",
                    "file": member.file,
                    "line": member.line,
                    "title": member.title,
                }
            )
        severity = max(
            (member.severity for member in members),
            key=lambda name: ["low", "medium", "high", "critical"].index(name)
            if name in ("low", "medium", "high", "critical")
            else 0,
        )
        merged.append(
            primary.model_copy(
                deep=True,
                update={
                    "severity": severity,
                    "affected_locations": locations,
                    "summary": (
                        f"{primary.summary}"
                        f"（同一条 Joern 推导路径上的 {len(members)} 条发现，已合并为一条）"
                    ),
                },
            )
        )
        for member in members:
            findings.remove(member)
    return findings + merged


def _exclusion_scope_id(text: str) -> str:
    """A stable scope id for an excluded area, which the planner names in prose.

    Hashed because the planner's exclusion text is a sentence, not an identifier, and two
    exclusions that differ only in punctuation must not become two rows for one decision.
    """
    digest = hashlib.sha1(text.encode("utf-8")).hexdigest()[:8]  # noqa: S324 - a stable key only
    slug = "".join(ch if ch.isalnum() else "-" for ch in text.lower())
    return f"excluded-{slug.strip('-')[:32]}-{digest}"


def _merge_work_items(
    survey_items: list[WorkItem], planned: list[WorkItem], *, limit: int
) -> list[WorkItem]:
    """The planner's plan where it has one, the survey's scopes for anything it dropped.

    Not a replacement: a planner that quietly drops a scope would drop it from the coverage table
    too, and the whole point of the ledger is that a scope nobody planned for is visible as exactly
    that. Survey scopes the plan did not mention survive with their fallback rationale.
    """
    chosen: dict[str, WorkItem] = {item.scope_id: item for item in planned}
    for item in survey_items:
        chosen.setdefault(item.scope_id, item)
    return list(chosen.values())[:limit]


def _run_id(workspace: Path) -> str:
    """A run id that says what it is about and when, and is unique without coordination."""
    stamp = _now().strftime("%Y%m%dT%H%M%SZ")
    digest = hashlib.sha1(str(workspace).encode("utf-8")).hexdigest()[:8]  # noqa: S324 - a key only
    return f"run-{stamp}-{digest}"


def _now() -> datetime:
    return datetime.now(timezone.utc)


__all__ = ["HarnessConfig", "HarnessCoordinator", "HarnessResult"]
