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
from concurrent.futures import ThreadPoolExecutor
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
    OpeningConvergence,
    ProjectContext,
    ThreatModel,
    ToolName,
    VerdictKind,
    WorkItem,
    WorkItemState,
)
from aegis_core.cancel import CanceledAbort
from aegis_core.logging import get_logger
from services.harness import agents, coverage, report, survey
from services.harness import blackboard as bb
from services.harness import trail as trail_mod
from services.harness.react import AgentRun, ToolLayerUnavailable

log = get_logger(__name__)

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
    #: Scopes planned in one round. Also the cap on how many scopes a single round may dispatch.
    max_scopes_per_round: int = 12
    #: How many passes the opening pair (recon + threat modelling) may take before the pipeline moves
    #: on. Copied from the frameworks that hit this problem first rather than invented here: MetaGPT
    #: bounds its own iterative feedback loop at three retries, and AutoGen never ships a termination
    #: condition without a hard cap beside it (`MaxMessageTermination`, `TokenUsageTermination`, …).
    #:
    #: Three, and the number is structural rather than generous. An agent's run ends at its `final`, so
    #: whatever it publishes in pass N can only be read by its peer in pass N+1. With a cap of 2 the pair
    #: can publish in both passes and still never reach quiescence: measured on the six-file demo, pass 2
    #: ended with recon having recorded four trust boundaries (`request.args` reaching a concatenated
    #: query, `repo.connect` opening a cwd-relative `app.db`) that the threat model had never seen, and
    #: the stage reported "未收敛" for a run in which nothing was wrong. Pass 3 is what lets the lagging
    #: agent read the last pass's material -- and it is cheap, because it goes only to whoever is behind
    #: and its task is the delta, not the repository: measured at 12-16 model steps, against 22-30 for a
    #: first pass.
    max_opening_passes: int = 3
    #: Candidates recorded per scope. Bounds both the blackboard and the validation bill.
    candidates_per_scope: int = 5
    #: Turns per agent run. The hard budget the ReAct loop holds itself to.
    steps_per_agent: int = 8
    #: Model calls in flight at once, inherited from `AIConfig.concurrency` when built from config.
    concurrency: int = 4
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
        self._board_lock = threading.Lock()
        #: Which agent is running on *this* thread. Set by `_agent` for the duration of a run, read by
        #: `_record` so a fact an agent wrote says who wrote it -- needed because recon and threat
        #: modelling write from two threads at once and the trail has no other way to tell them apart.
        self._current = threading.local()
        #: The opening stage's substantive publications, in order: what an agent recorded or merged,
        #: which board revision it produced, and who wrote it. The convergence rule is "does the peer
        #: have anything published after its watermark", and this log is the only place that can answer
        #: it -- a revision number alone cannot say *whether* what changed is something a peer's answer
        #: could depend on, and re-dispatching on a note would double the opening stage for nothing.
        self._publications: list[dict] = []
        #: Which files each scope owns. The coverage rule reads this: a scope is not closed while a
        #: file it owns has never been read end to end, and the re-dispatch hands the unread subset
        #: back to the next agent instead of letting it guess where it left off.
        self._scope_files: dict[str, list[str]] = {}

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
            before = self.blackboard.revision
            # How much substantive material the board held before this write, so what the write
            # *added* can be published for the peer's convergence check (`_opening_growth`). A record
            # that changed nothing publishes nothing, which is what keeps a duplicate from waking the
            # other agent up.
            before_counts = self._opening_counts()
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
            self._publish(agent, self._opening_growth(before_counts), f"{kind}: {text}")

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
            bb.add_lead(
                self.blackboard,
                CrossScopeLead(
                    lead_id=agents.stable_candidate_id(
                        scope or "workspace", target, None, "lead"
                    ),
                    from_scope=scope or "workspace",
                    to_scope=target,
                    title=str(payload.get("title") or target),
                    detail=text,
                    raised_by=getattr(self._current, "agent", ""),
                ),
            )
            return "已记入 leads（交给目标 scope，不是自己追过去）"
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
            self._stage("recon", self._recon_and_threat_model)
            self._stage("plan", self._plan)
            self._stage("discovery", self._discovery_and_closure)
            self._stage("attack_path", self._attack_paths)
        except ToolLayerUnavailable as exc:
            # A missing tool package is a broken installation, not a stage result. Recorded and
            # returned so the CLI can exit non-zero with the actionable message intact.
            log.error("harness: %s", exc)
            self.trail.emit("error", where="tool_layer", message=str(exc))
            self.blackboard = bb.mark_closed(self.blackboard, f"工具层不可用：{exc}")
            return self._finish(fatal=str(exc))

        self._stage("findings", self._emit_findings)
        note = (
            f"覆盖率收敛完成，共 {self.rounds_run} 轮；"
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

    def _on_step(self, run: AgentRun, step) -> None:
        """One turn of one agent, as an event. This is the agent's side of the conversation."""
        result = step.result
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
        self.check_abort(f"{agent}:{scope_id}")
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
        try:
            outcome = agents.run(on_step=self._on_step, **kwargs)
        except BaseException as exc:
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
        bb.add_run(self.blackboard, outcome.run)
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
            duration_ms=int((_now() - started).total_seconds() * 1000),
        )
        return outcome

    # ── stage 0: prep, stage 1: recon + threat model ───────────────────────

    def _recon_and_threat_model(self) -> None:
        """The opening: recon and threat modelling, concurrently, until neither has unread work.

        The parallelism is deliberate, and it was arrived at by being wrong first. An earlier version
        ran these two concurrently and reverted to sequential, with a comment explaining why: threat
        modelling builds its task from the architecture map, so whichever call lost the race saw an
        empty blackboard, and the stage was skipped when recon had produced nothing. That was a symptom
        of *when* findings were merged, not of concurrency being wrong: each agent merged its output
        only after its run had finished.

        Three things make the overlap work, and the third is what this method is about:

        * the deterministic prep ran as its own stage before this one, so both agents start from facts
          instead of an empty board -- and those facts are the seed revision, which neither is asked to
          re-read because both were handed them in their task;
        * `record` lets an agent write a fact the moment it has it, so each can see what the other has
          established *while* both are still working (the board's merges are unions and `_board_lock`
          covers the read-modify-write ones);
        * the stage **repeats** until each agent has read what the other published.

        That last part is copied rather than invented, because the failure it fixes is a known one.
        MetaGPT's answer to the same problem is a shared message pool with publish-subscribe: agents
        "publish their structured messages in the pool", each subscribes by role, and "an agent
        activates its action only after receiving all its prerequisite dependencies"
        (https://arxiv.org/abs/2308.00352 §3.2). AutoGen's answer to *when to stop* is a termination
        condition that sees "the delta sequence of messages since the last time it was called", is
        composable (`|` = stop if either holds), carries a `stop_reason` saying which one fired, and is
        always paired with a hard cap (`MaxMessageTermination`, `TokenUsageTermination`, …)
        (https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/termination.html).
        Both shapes are reused here: the delta is "publications after this agent's watermark", the
        condition is `converged | passes exhausted`, and the cap is `max_opening_passes`.

        The watermark is taken from the board revision each agent's `board` calls actually served --
        a tool call in the ledger -- and never from the agent saying it has caught up. That is the same
        rule the coverage table follows, and it exists because measurement said so: on the first real
        audit the threat model called `board` at steps 1 and 2 (before recon had published anything),
        then finished 50 events later without looking again, while recon published eleven facts in
        between. The tool worked; the timing did not, and a prompt telling it to re-read was ignored.
        """
        # Idempotent: this runs the survey only for a caller that skipped the prep stage (a bare
        # `_recon_and_threat_model()` in a test). In `run()` the snapshot is already taken and this
        # returns immediately.
        self._prepare()
        seed = self.blackboard.revision
        watermarks = {agents.RECON: seed, agents.THREAT_MODEL: seed}
        passes = max(1, self.config.max_opening_passes)
        pending: list[str] = [agents.RECON, agents.THREAT_MODEL]
        converged = False
        index = 0
        for index in range(1, passes + 1):
            self._opening_pass(index, pending, watermarks)
            backlog = self._opening_backlog(watermarks)
            pending = [agent for agent in (agents.RECON, agents.THREAT_MODEL) if backlog.get(agent)]
            if not pending:
                converged = True
                break

        unread = {
            agent: len(items)
            for agent, items in self._opening_backlog(watermarks).items()
            if items
        }
        note = (
            f"开场第 {index} 轮达成静默：两个 agent 都已读过对方发布的内容。"
            if converged
            else (
                f"开场跑了 {index} 轮仍未收敛（上限 {passes} 轮）："
                f"{'、'.join(f'{agent} 还有 {count} 条未读' for agent, count in unread.items())}。"
                "这是本次运行的已知缺口，不是“已完成”。"
            )
        )
        self.blackboard.opening = OpeningConvergence(
            passes=index,
            converged=converged,
            watermarks=dict(watermarks),
            unread=unread,
            note=note,
        )
        log.info("harness: opening %s", note)

    def _opening_pass(
        self, index: int, pending: list[str], watermarks: dict[str, int]
    ) -> None:
        """Run one pass of the opening stage: every agent in `pending`, concurrently.

        Later passes dispatch **only the agents that are behind**, which is the point of computing a
        backlog at all: an agent that has already been handed everything the other published has nothing
        left to react to, and re-running it would pay for a fresh reading of the repository to reach the
        same answer. Pass 2 onwards also gets a task built from the backlog instead of the whole board.
        """
        backlog = {agent: self._opening_backlog(watermarks).get(agent, []) for agent in pending}
        runners = {
            agents.RECON: self._run_recon,
            agents.THREAT_MODEL: self._run_threat_model,
        }
        # What each dispatched agent's task text carries. Captured before the pool starts, so a peer's
        # concurrent write during this pass is *not* counted as delivered -- conservative, and the reason
        # the loop alternates: what one publishes in pass N is read in pass N+1.
        delivered = {agent: self.blackboard.revision for agent in pending}
        with ThreadPoolExecutor(max_workers=max(1, len(pending))) as pool:
            futures = {
                pool.submit(runners[agent], index, backlog.get(agent, [])): agent
                for agent in pending
            }
            for future in futures:
                # Every future is awaited before the pass ends. A failure in one is already recorded as
                # that agent's result; letting it escape here would lose the other's work, which is the
                # same rule `_bounded` follows.
                try:
                    future.result()
                except ToolLayerUnavailable:
                    raise
                except Exception as exc:  # noqa: BLE001
                    log.warning(
                        "harness: opening pass %d failed for %s (%s: %s)",
                        index, futures[future], type(exc).__name__, exc,
                    )
        # Watermarks move on *delivery*, not on a model promise: an agent counts as up to date once it
        # has been handed the material (the task text it was given, which for a re-dispatch is the delta)
        # or has read at least that far itself (`board`). Both are facts the coordinator owns.
        #
        # The first version required a `board` call, and that was a proxy that fails on the one case it
        # was built for: a model that ignores the tool stays "behind" forever, so the loop could never
        # converge and always ran to its cap -- which is also what the fake tool layer (no board
        # revision at all) showed immediately. Requiring the read measures willingness to call a tool;
        # delivering the delta measures what the agent was actually given, and the loop terminates when a
        # pass adds nothing new, which is the blackboard architecture's own stopping rule.
        for agent in pending:
            given = delivered.get(agent, 0)
            run = self._opening_runs(index).get(agent)
            seen = _board_revision_seen(run) if run is not None else None
            if seen is not None:
                given = max(given, seen)
            if given > watermarks.get(agent, 0):
                watermarks[agent] = given

    def _opening_runs(self, index: int) -> dict[str, AgentRun]:
        """This pass's opening runs, read back off the ledger by their pass-suffixed id."""
        runs: dict[str, AgentRun] = {}
        for agent in (agents.RECON, agents.THREAT_MODEL):
            run_id = _opening_run_id(agent, index)
            run = next((item for item in self.blackboard.runs if item.run_id == run_id), None)
            if run is not None:
                runs[agent] = run
        return runs

    def _opening_backlog(self, watermarks: dict[str, int]) -> dict[str, list[dict]]:
        """Per opening agent, the substantive publications it has not read.

        Substantive means something a peer's *conclusions about the code* could depend on: a component,
        a trust boundary, an entry point or a threat. Notes, leads, assets and actors are deliberately
        excluded -- notes and leads are commentary, and assets/actors are prose descriptions of the same
        few things, which two agents will keep rewriting (see `SUBSTANTIVE` for the measurement). An
        agent never goes stale on its own writes: the point is to read the *other* one.
        """
        backlog: dict[str, list[dict]] = {}
        for agent in (agents.RECON, agents.THREAT_MODEL):
            watermark = watermarks.get(agent, 0)
            backlog[agent] = [
                item
                for item in self._publications
                if item["revision"] > watermark and item["by"] != agent and item["kinds"]
            ]
        return backlog

    def _publish(self, by: str, kinds: list[str], label: str) -> None:
        """Log one substantive publication, at the board revision it produced.

        Called from both writers of the opening stage: `_record` when an agent writes a fact mid-run,
        and the two stage methods when an agent's final answer is merged. Both matter -- measured on
        the real audit, most of recon's material arrived as `record` calls, and the rest arrived in its
        final answer; a watermark that watched only one of them would declare convergence while
        half the board was still unread.
        """
        if not kinds:
            return
        self._publications.append(
            {
                "revision": self.blackboard.revision,
                "by": by,
                "kinds": list(kinds),
                "label": trail_mod.clip(label, 200),
            }
        )

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

    def _run_recon(self, index: int = 1, backlog: list[dict] | None = None) -> AgentRun | None:
        """One recon run. `backlog` is what the peer published since this agent last read the board.

        Pass 2 onwards is a *re-read*, not a re-investigation: the agent is handed the publications it
        has not seen and asked whether they change its answer. Its tool surface is unchanged -- it may
        still read code to check a peer's claim -- but the task no longer describes the repository from
        scratch, so the common case is one short turn rather than a second full survey.
        """
        outcome = self._agent(
            agent=agents.RECON,
            scope_id="workspace",
            run_id=_opening_run_id(agents.RECON, index),
            task=agents.recon_task(
                str(self.workspace),
                prep=self._snapshot if index == 1 else None,
                delta=agents.opening_delta_block(backlog or []),
            ),
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
        before = self._opening_counts()
        bb.set_context(self.blackboard, project=project, architecture=architecture)
        self._publish(agents.RECON, self._opening_growth(before), "recon 的最终结论")
        return outcome.run

    def _run_threat_model(
        self, index: int = 1, backlog: list[dict] | None = None
    ) -> AgentRun | None:
        if self.blackboard.project is None and self.blackboard.architecture is None:
            # Threat modelling without recon would be reasoning about a project nobody described.
            # Recorded as a skipped stage rather than run on nothing -- a threat model invented
            # without the architecture map is exactly the generic output this pipeline exists to
            # avoid, and the report has to be able to see that the stage did not run.
            log.warning("harness: no recon findings; skipping the threat-model call")
            self.dataflow_notes.append(
                "warning: recon produced nothing usable, so the threat-model stage was skipped; "
                "the plan and the coverage table below are not guided by a threat model"
            )
            return None
        outcome = self._agent(
            agent=agents.THREAT_MODEL,
            scope_id="workspace",
            run_id=_opening_run_id(agents.THREAT_MODEL, index),
            task=agents.threat_model_task(
                self.blackboard, delta=agents.opening_delta_block(backlog or [])
            ),
            context=self.context,
            client=self.client,
            max_steps=self.config.steps_per_agent,
            blackboard=self.blackboard,
        )
        if outcome.parsed is None:
            log.warning("harness: threat model produced nothing usable (%s)", outcome.error)
            return outcome.run
        before = self._opening_counts()
        bb.set_context(self.blackboard, threats=outcome.parsed)
        self._publish(agents.THREAT_MODEL, self._opening_growth(before), "威胁模型的最终结论")
        return outcome.run

    #: The fields an opening agent's next answer can depend on, and therefore the only ones whose growth
    #: makes the peer stale enough to re-dispatch. Notes and leads are absent because commentary does not
    #: make a peer's answer wrong -- and `assets`/`actors` joined them after a real run, for a subtler
    #: reason: they are *descriptions* of the same few things, so two agents writing them will always
    #: produce more of them, and every pass therefore looked like it had work waiting.
    #:
    #: Measured on the demo: pass 2 published an asset, an actor, a note and a lead, all of them
    #: rephrasings, and the stage reported "未收敛（recon 还有 3 条未读、threat_model 还有 1 条未读）" when
    #: nothing in those four could have changed either agent's reading of the code. What the pair had
    #: actually established -- components, trust boundaries, entry points, threats -- both sides had
    #: already seen. Narrowing the set here does not drop those descriptions: the planner, discovery,
    #: validation and the report all read the final board. It only stops paying for a third agent run to
    #: re-read a sentence.
    SUBSTANTIVE = ("components", "trust_boundaries", "entry_points", "threats")

    def _opening_counts(self) -> dict[str, int]:
        """How much substantive material is on the board right now, by field."""
        board = self.blackboard
        threats = board.threats
        architecture = board.architecture
        return {
            "components": len(getattr(architecture, "components", []) or []),
            "trust_boundaries": len(getattr(architecture, "trust_boundaries", []) or []),
            "entry_points": len(board.project.entry_points) if board.project else 0,
            "assets": len(threats.assets) if threats else 0,
            "actors": len(threats.actors) if threats else 0,
            "threats": len(threats.threats) if threats else 0,
        }

    def _opening_growth(self, before: dict[str, int]) -> list[str]:
        """Which substantive fields a merge actually added to. Empty means nothing to publish."""
        after = self._opening_counts()
        return [field for field in self.SUBSTANTIVE if after.get(field, 0) > before.get(field, 0)]

    # ── stage 2: planning ──────────────────────────────────────────────────

    def _plan(self) -> list[WorkItem]:
        """Turn the survey plus the threat model into `WorkItem`s with a stated rationale.

        The survey always exists, and always before this: `_prepare` ran it before the opening model
        calls, so this stage reads the scopes it already derived (`_surveyed_scopes`) instead of walking
        the tree again. Two reasons it must be there regardless: it is what makes the scopes a property
        of *this* repository rather than of a fixed count, and it is the fallback when the planner call
        fails -- a run whose planning stage errored must still investigate something, and must say in the
        ledger that the plan is a fallback.
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
        items = self._survey_work_items(scopes)
        refined = self._planner_call(scopes)
        if refined:
            items = _merge_work_items(items, refined, limit=self.config.max_scopes_per_round)
        # Coverage groups are added *outside* the cap: see `_coverage_items`.
        bb.add_work(
            self.blackboard,
            [*self._coverage_items(), *items[: self.config.max_scopes_per_round]],
        )
        # Keep the derived scope list so discovery/closure can re-dispatch the same scope ids.
        self._planned_scopes = [
            item.scope_id
            for item in self.blackboard.work
            if item.state in (WorkItemState.PLANNED, WorkItemState.RUNNING)
        ]
        log.info("harness: planned %d scope(s): %s", len(self._planned_scopes), self._planned_scopes)
        return items

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
        """Ask the planner to confirm or replace the survey's scopes. Empty on any failure.

        Failure is not fatal and is not silent: the survey plan is used, and the ledger's rationale
        prefix is what tells a reader that the scopes were derived from directory names rather than
        from the model reading the repository.
        """
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
                "A directory-name survey proposed these candidate investigation scopes:",
                agents._json(components),
                "Decide which are worth investigating. Return `scopes` with, for each: "
                "`scope_id` (reuse the survey id when you keep it), `title`, `kind`, `path`, "
                "`rationale` (why this area, for this threat model), and `files` (the files in it). "
                "You may split, merge, add or drop scopes when the code justifies it -- but say so "
                "in the rationale. Also return `excluded`: areas you deliberately do not plan for, "
                "each with its reason.",
            ]
        )
        outcome = self._agent(
            agent=agents.PLANNER,
            scope_id="plan",
            task=task,
            context=self.context,
            client=self.client,
            max_steps=self.config.steps_per_agent,
            blackboard=self.blackboard,
        )
        if outcome.parsed is None:
            log.warning("harness: planner produced nothing usable (%s); using the survey plan",
                        outcome.error)
            return []
        planned = outcome.parsed
        items = [
            WorkItem(
                work_id=f"W-{scope['scope_id']}",
                scope_id=str(scope["scope_id"]),
                title=str(scope.get("title") or scope["scope_id"]),
                rationale=str(scope.get("rationale") or ""),
            )
            for scope in planned.get("scopes", [])
            if isinstance(scope, dict) and scope.get("scope_id")
        ]
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
            ]
        # Closing sweep. Validation now runs inside every round, so this only catches what a round
        # could not decide (an agent that errored on a candidate leaves it without a verdict), and it
        # is cheap by construction: `_validation` only looks at candidates that have none.
        self._stage("validation", self._validation)
        if pending:
            # The bound bit. Recorded here because the report has to be able to say "this stopped
            # early", and the coverage rows already carry the reason each scope is still open.
            self.dataflow_notes.append(
                f"round budget exhausted after {self.rounds_run} round(s): "
                f"{len(pending)} scope(s) are still INSUFFICIENT ({', '.join(pending)}) -- "
                "the report below shows what was reached, not a converged picture"
            )
        log.info("harness: discovery/closure finished after %d round(s)", self.rounds_run)

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
        """
        items = {item.scope_id: item for item in self.blackboard.work}
        work = [items[scope_id] for scope_id in scope_ids if scope_id in items]
        if not work:
            return {}
        new_by_scope: dict[str, int] = {}
        # Position plus round, so a scope re-dispatched for being INSUFFICIENT is approached from a
        # different perspective than the pass that failed to close it.
        positions = {item.scope_id: index for index, item in enumerate(work)}

        def one(item: WorkItem) -> None:
            owned = self._scope_files.get(item.scope_id) or []
            prefetched_steps: list[AgentStep] = []
            prefetched_files: list[str] = []
            skipped_files: list[str] = []
            reused_files: list[str] = []
            if round_index and owned:
                # A re-dispatch is handed only what is still unread: starting the whole group again
                # spends the budget re-reading files the previous agent already finished.
                assigned = self._unread_in(item.scope_id) or None
                # ...and it is handed the files themselves -- **out of the blackboard when the run has
                # already read them**, off the disk otherwise -- because a fresh agent has never seen
                # this code and cannot be told to remember it. Measured: rounds 1-3 read *more* per run
                # than round 0 (5.9 vs 4.7 files), 110 of the 143 discovery reads.
                (
                    prefetched_steps,
                    reused_files,
                    prefetched_files,
                    skipped_files,
                ) = agents.prefetch_scope_files(
                    self._unread_in(item.scope_id) or owned,
                    self.context,
                    budget=self.config.material_budget,
                    blackboard=self.blackboard,
                )
            else:
                assigned = owned or None
            outcome = self._agent(
                agent=agents.DISCOVERY,
                scope_id=item.scope_id,
                task=agents.discovery_task(
                    self.blackboard,
                    item,
                    attempt=round_index + 1,
                    files=assigned,
                    prefetched=prefetched_files,
                    skipped=skipped_files,
                ),
                context=self.context,
                client=self.client,
                max_steps=self.config.steps_per_agent,
                blackboard=self.blackboard,
                run_id=f"discovery:{item.scope_id}:r{round_index}",
                initial_steps=prefetched_steps or None,
                extra_system=agents.discovery_extra_system(
                    self.blackboard,
                    item.scope_id,
                    index=positions.get(item.scope_id, 0) + round_index,
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
            seen_before = {
                (candidate.file, candidate.line)
                for candidate in self.blackboard.candidates
                if candidate.scope_id == item.scope_id
            }
            added = self._record_candidates(found[: self.config.candidates_per_scope])
            new_by_scope[item.scope_id] = len(
                {(candidate.file, candidate.line) for candidate in added} - seen_before
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

        self._bounded(work, one, label="discovery")
        return new_by_scope

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
            if not self._covered(scope_id):
                reason = (
                    f"第 {round_index} 轮：没有任何 discovery 看过这个 scope"
                    "（没有对应的工作项，或其 agent 以 error/budget 结束），因此它是未覆盖的"
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
                    f"（{listed}）；覆盖率按 read 调用台账计算，搜索命中不算审完"
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
        return any(item.state is WorkItemState.DONE for item in items)

    def _validation(self) -> None:
        """Validate every candidate that does not already have a verdict.

        Idempotent by construction: the input is "candidates without verdicts", so re-entering this
        stage (a resumed run) validates only what is missing instead of re-deciding and appending.
        """
        pending = [
            candidate
            for candidate in self.blackboard.candidates
            if bb.find_verdict(self.blackboard, candidate.candidate_id) is None
        ]
        if not pending:
            return

        # One validation per *claim*, not per recorded instance. The ledger keeps every instance --
        # coverage is counted per scope and a scope whose candidate carried no verdict would stay
        # INSUFFICIENT forever -- but the decision is paid for once and copied, which is what turns
        # 106 candidates into 56 agent runs without touching the closure rule.
        groups = agents.validation_groups(pending)

        def one(members: list[Candidate]) -> None:
            candidate = agents.group_representative(members)
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
                return
            verdict: CandidateVerdict = outcome.parsed
            for member in members:
                copy = verdict.model_copy(deep=True)
                copy.candidate_id = member.candidate_id
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

        self._bounded(list(groups.values()), one, label="validation")

    def _attack_paths(self) -> None:
        confirmed = [
            candidate
            for candidate in bb.confirmed_candidates(self.blackboard)
            if bb.find_attack_path(self.blackboard, candidate.candidate_id) is None
        ]
        if not confirmed:
            return

        def one(members: list[Candidate]) -> None:
            candidate = agents.group_representative(members)
            verdict = bb.find_verdict(self.blackboard, candidate.candidate_id)
            if verdict is None:  # pragma: no cover - confirmed implies a verdict
                return
            outcome = self._agent(
                agent=agents.ATTACK_PATH,
                scope_id=candidate.candidate_id,
                task=agents.attack_path_task(
                    self.blackboard,
                    candidate,
                    verdict,
                    material_budget=self.config.material_budget,
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
                return
            path: AttackPath = outcome.parsed
            # Copied to every member, for the same reason the verdict is: a confirmed candidate with
            # no attack path would be reported as "reachability never established", which is a weaker
            # claim than the run actually earned.
            for member in members:
                copy = path.model_copy(deep=True)
                copy.candidate_id = member.candidate_id
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

        self._bounded(list(agents.validation_groups(confirmed).values()), one, label="attack_path")

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
            [*self._coverage_items(), *items[: self.config.max_scopes_per_round]],
        )
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

        with ThreadPoolExecutor(max_workers=workers) as pool:
            list(pool.map(guarded, work))


# ─────────────────────────────────────────────────────────── helpers


def _opening_run_id(agent: str, index: int) -> str:
    """The ledger id of one opening agent's run in pass `index`.

    Suffixed from pass 2 on because `bb.add_run` keys on `run_id`: without it a re-dispatched recon
    would be filed under the id its first run already used and the ledger would *drop* the second run
    -- keeping the report's account of the pass that changed the answer while losing the pass itself.
    """
    base = f"{agent}:workspace"
    return base if index <= 1 else f"{base}:p{index}"


def _board_revision_seen(run: AgentRun) -> int | None:
    """The highest board revision this run's `board` calls actually served, or None if it never read.

    This is the watermark the opening stage converges on, and it is read out of the run's tool calls
    rather than out of anything the model said: the `board` tool stamps each result with the revision
    it served, so "how much of the board has this agent seen" is a ledger fact. Deriving it from the
    agent's own claim ("I have read the peer's components") would be the same category of evidence the
    coverage rule refuses -- and measured on the first real audit, the threat model's claim to be
    finished was worth nothing while it had read at step 1 and never looked again.
    """
    seen: int | None = None
    for step in run.steps:
        call, result = step.call, step.result
        if call is None or result is None or not result.ok:
            continue
        if call.tool is not ToolName.BOARD:
            continue
        revision = (result.data or {}).get("revision")
        if isinstance(revision, int) and (seen is None or revision > seen):
            seen = revision
    return seen


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
