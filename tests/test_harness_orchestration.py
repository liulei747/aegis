"""The orchestration layer: the ReAct bounds, the blackboard's append rules, the pipeline's loops.

No network and (for most of this file) no real tool layer. The tools are replaced by a fake module
injected into ``sys.modules`` and the model by a scripted client, because every property under test
here is about what the *orchestrator* does with an answer -- a budget stop, a refused tool, a
duplicate candidate, an unparsed answer -- and none of those can be produced on demand by a real
endpoint or a real file system.

The last group of tests deliberately does the opposite: it runs against the real tool layer, which
is the only way to check that the frozen surface is being called the way its author built it.
"""

from __future__ import annotations

import json
import sys
import threading
import types
from pathlib import Path

import pytest

from aegis_contracts.harness import (
    AgentRun,
    AgentStep,
    ArchitectureMap,
    AttackPath,
    Blackboard,
    Candidate,
    CandidateVerdict,
    CoverageEntry,
    CoverageState,
    DataflowEvidence,
    EvidenceKind,
    ProjectContext,
    ToolCall,
    ToolName,
    ToolResult,
    VerdictKind,
    WorkItem,
    WorkItemState,
)
from aegis_core.cancel import CanceledAbort
from services.ai.client import AIUnavailable, ChatResult
from services.harness import agents, coverage, react, report, skills, survey, trail
from services.harness import blackboard as bb
from services.harness.cli import EXIT_NOT_CONFIGURED, main
from services.harness.coordinator import HarnessConfig, HarnessCoordinator, _severity
from services.harness.react import run_agent

# ─────────────────────────────────────────────────────────── fakes


class CallCounter:
    """Shared between a fake client's calls and the test that asserts none happened."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def __len__(self) -> int:
        return len(self.calls)

    def __bool__(self) -> bool:
        """An empty counter is still a counter.

        Without this, `ScriptedClient`'s `counter or CallCounter()` sees `len(...) == 0` and silently
        substitutes a *different* counter, so a test that passed one in to inspect it afterwards read
        an empty list no matter what the client did -- including the tests asserting that no model
        call happened, which passed for the wrong reason.
        """
        return True


class ScriptedClient:
    """The model, scripted.

    Two shapes of answer, because the tests need both: a queue of answers in call order (for the
    ReAct loop, where the transcript is the point) and a per-agent registry (for the pipeline,
    where the order of calls is deliberately nondeterministic because recon and threat modelling
    run concurrently).

    An agent nothing was scripted for raises, deliberately: a test whose script does not cover a
    stage the pipeline reaches should fail loudly, not pass on a stub.
    """

    model = "scripted-model"

    def __init__(self, counter: CallCounter | None = None) -> None:
        self.queued: list[str | Exception] = []
        self.by_agent: dict[tuple[str, str], list[str | Exception]] = {}
        self.stub: dict[str, list[str | Exception]] = {}
        self.counter = counter or CallCounter()

    # -- scripting -----------------------------------------------------
    def queue(self, *answers: str | Exception) -> ScriptedClient:
        self.queued.extend(answers)
        return self

    def script(self, agent: str, scope_id: str, *answers: str | Exception) -> ScriptedClient:
        self.by_agent.setdefault((agent, scope_id), []).extend(answers)
        return self

    def stub_agent(self, agent: str, answer: str | Exception) -> ScriptedClient:
        """An endless answer for every call to `agent`, whatever scope it is about.

        Used for the stages whose scope id the test cannot know in advance -- discovery over the
        scopes the *survey* derived, for instance, where the id depends on directory layout.
        """
        self.stub[agent] = [answer] * 50
        return self

    # -- the client protocol -------------------------------------------
    def complete(self, system: str, user: str) -> ChatResult:
        which = _which_agent(system)
        scope = _which_scope(user)
        self.counter.calls.append((which, scope, user))
        answer = self._pop(which, scope)
        if isinstance(answer, Exception):
            raise answer
        return ChatResult(text=answer, model=self.model, raw={})

    def _pop(self, agent: str, scope: str) -> str | Exception:
        if self.queued:
            return self.queued.pop(0)
        key = (agent, scope)
        if self.by_agent.get(key):
            return self.by_agent[key].pop(0)
        if self.stub.get(agent):
            return self.stub[agent].pop(0)
        # A single unclaimed queue for this agent is used whatever scope asked for it (validation
        # and attack-path runs are filed under generated candidate ids, so a test often keys them on
        # the scope instead). More than one unclaimed queue is an *error*, not a guess: silently
        # handing one scope's answer to another is how a test passes while proving nothing.
        unclaimed = [
            candidate_key
            for candidate_key, answers in self.by_agent.items()
            if candidate_key[0] == agent and answers
        ]
        if len(unclaimed) == 1:
            return self.by_agent[unclaimed[0]].pop(0)
        if unclaimed:
            raise AssertionError(
                f"scripted client cannot choose between {unclaimed} for {agent}/{scope}"
            )
        raise AssertionError(
            f"scripted client ran out of answers for {agent}/{scope}; queued={len(self.queued)}"
        )


def _which_agent(system: str) -> str:
    for marker, name in (
        ("reconnaissance agent", agents.RECON),
        ("threat-modelling agent", agents.THREAT_MODEL),
        ("planning stage", agents.PLANNER),
        ("discovery agent", agents.DISCOVERY),
        ("validation agent", agents.VALIDATION),
        ("attack-path agent", agents.ATTACK_PATH),
    ):
        if marker in system:
            return name
    return "unknown"


def _which_scope(user: str) -> str:
    for line in user.splitlines():
        if line.startswith("Scope: "):
            return line[len("Scope: "):].split(" --")[0].strip()
        if line.startswith("Workspace root:"):
            return "workspace"
    return "?"


class FakeToolContext:
    """Stands in for `services.harness.tools.ToolContext` in the injected fake module."""

    def __init__(self, workspace, shell_policy=None, limits=None, dataflow=None) -> None:
        self.workspace = Path(workspace)
        self.shell_policy = shell_policy
        self.limits = limits
        self.dataflow = dataflow
        self.calls: list[ToolCall] = []


class FakeToolLimits:
    def __init__(self, max_read_lines=200, max_list_files=200, max_output_chars=8000) -> None:
        self.max_read_lines = max_read_lines
        self.max_list_files = max_list_files
        self.max_output_chars = max_output_chars


def make_fake_tools(*, answers: dict[str, ToolResult] | None = None) -> types.ModuleType:
    """A module that looks like `services.harness.tools`, with an `invoke` that records calls.

    The scripted answers are keyed on the tool name; a tool with no scripted answer returns a
    successful stub, so a test that does not care about tool output does not have to script one.
    """
    module = types.ModuleType("services.harness.tools")
    recorded: list[ToolCall] = []
    scripted = dict(answers or {})

    def invoke(context, call: ToolCall) -> ToolResult:
        recorded.append(call)
        if hasattr(context, "calls"):
            context.calls.append(call)
        if call.tool.value in scripted:
            return scripted[call.tool.value]
        return ToolResult(
            tool=call.tool,
            ok=True,
            summary=f"stub result for {call.tool.value}",
            data={"stub": True},
        )

    module.ToolContext = FakeToolContext
    module.ToolLimits = FakeToolLimits
    module.invoke = invoke
    module.schemas = lambda: [
        {"name": name.value, "description": name.value, "parameters": {"type": "object"}}
        for name in ToolName
    ]
    module.TOOLS = {name: object() for name in ToolName}
    module.recorded = recorded
    module.scripted = scripted
    return module


@pytest.fixture(autouse=True)
def _clean_tool_layer():
    """Every test starts with no cached tool layer and no leftover fake module.

    `react.tool_layer()` is `lru_cache`d and the fake module lives in `sys.modules`, so without this
    a test that injected a fake would leak it into the next test -- and the real-tool-layer tests
    would silently run against a stub. Order-dependent leakage like that is worse than a failure,
    because the test passes.
    """
    sys.modules.pop("services.harness.tools", None)
    react.clear_tool_layer_cache()
    yield
    sys.modules.pop("services.harness.tools", None)
    react.clear_tool_layer_cache()


@pytest.fixture()
def fake_tools(monkeypatch):
    """Inject the fake tool layer and make sure `react` picks it up rather than a cached import."""
    module = make_fake_tools()
    monkeypatch.setitem(sys.modules, "services.harness.tools", module)
    react.clear_tool_layer_cache()
    yield module
    react.clear_tool_layer_cache()


def workspace(tmp_path: Path) -> Path:
    """A tiny Java-shaped project: a controller, a service, a DAO with a concatenated query."""
    root = tmp_path / "repo"
    (root / "src/main/java/com/example/controller").mkdir(parents=True)
    (root / "src/main/java/com/example/service").mkdir(parents=True)
    (root / "src/main/resources").mkdir(parents=True)
    (root / "pom.xml").write_text("<project><version>1.0</version></project>", encoding="utf-8")
    (
        root / "src/main/java/com/example/controller/UserController.java"
    ).write_text(
        "@RestController\npublic class UserController {\n"
        "  @GetMapping(\"/users\")\n"
        "  public String list(@RequestParam String sort) { return userService.list(sort); }\n"
        "}\n",
        encoding="utf-8",
    )
    (
        root / "src/main/java/com/example/service/UserService.java"
    ).write_text(
        "public class UserService {\n"
        "  public String list(String sort) {\n"
        "    String q = \"SELECT * FROM users ORDER BY \" + sort;\n"
        "    return db.execute(q);\n"
        "  }\n"
        "}\n",
        encoding="utf-8",
    )
    (root / "src/main/resources/application.yml").write_text(
        "spring:\n  datasource:\n    password: \"hunter2secret\"\n", encoding="utf-8"
    )
    return root


def react_task(scope_id: str = "s1") -> str:
    return f"Scope: {scope_id} -- test scope\nWorkspace root: /tmp/repo"


def turn(tool: str, **arguments) -> str:
    return json.dumps({"thought": f"call {tool}", "tool": tool, "arguments": arguments})


def final(**payload) -> str:
    return json.dumps({"thought": "done", "final": payload})


def candidate_payload(**overrides) -> dict:
    base = {
        "title": "SQL built by concatenation",
        "vulnerability_type": "sql_injection",
        "file": "src/main/java/com/example/service/UserService.java",
        "line": 3,
        "method": "list",
        "rationale": "the sort parameter is concatenated into the query",
    }
    base.update(overrides)
    return base


def discovery_answer(*candidates) -> str:
    return final(candidates=list(candidates or [candidate_payload()]), notes=[])


#: The scope ids the test workspace's layout produces, and which the planner below therefore uses.
#: Both halves matter: the coordinator unions the planner's plan with the survey's scopes, so an id
#: the survey did not derive becomes a *second* scope for the same directory.
SERVICE_SCOPE = "scope-service-layer-com-example-service"
WEB_SCOPE = "scope-web-route-com-example-controller"


def validation_answer(
    verdict: str = "confirmed", kind: str = "semantic", confidence: float = 0.8, **overrides
) -> str:
    payload = {
        "verdict": verdict,
        "evidence_kind": kind,
        "confidence": confidence,
        "reasons": ["the request parameter reaches the query unfiltered"],
    }
    payload.update(overrides)
    return final(**payload)


# ─────────────────────────────────────────────────────────── the ReAct loop


def test_budget_stop_keeps_the_steps_and_says_it_stopped_early(fake_tools, tmp_path: Path) -> None:
    """Hitting `max_steps` is a result, not a failure, and the transcript must show the work."""
    client = ScriptedClient().queue(*[turn("read", path="a.java")] * 3)
    run = run_agent(
        agent="discovery",
        scope_id="s1",
        system_prompt="sys",
        task=react_task(),
        tools=[ToolName.READ],
        context=FakeToolContext(tmp_path),
        client=client,
        max_steps=3,
    )

    assert run.stop_reason == "budget"
    assert len(run.steps) == 3, "the steps actually taken must be kept, not discarded"
    assert all(step.call is not None and step.result is not None for step in run.steps)
    assert run.output == {}
    assert run.finished_at is not None


def test_a_turn_may_carry_several_tool_calls(fake_tools, tmp_path: Path) -> None:
    """Batching is a transport optimisation, and every call in it is still recorded separately.

    A turn is a round trip with the whole transcript re-sent on the next one, so reading a six-file
    group one call per turn cost six round trips -- measured at roughly 25 s each, which is what made
    a discovery round take 35 minutes. The record must not change: the coverage ledger counts `read`
    windows per call, so a batch that collapsed into one step would under-count what was read.
    """
    client = ScriptedClient().queue(
        json.dumps(
            {
                "thought": "read both files in one turn; they do not depend on each other",
                "calls": [
                    {"tool": "read", "arguments": {"path": "app.py"}},
                    {"tool": "read", "arguments": {"path": "handler.py"}},
                ],
            }
        ),
        final(ok=True),
    )
    run = run_agent(
        agent="discovery",
        scope_id="s1",
        system_prompt="sys",
        task=react_task(),
        tools=[ToolName.READ],
        context=FakeToolContext(tmp_path),
        client=client,
        max_steps=3,
    )

    assert run.stop_reason == "finished"
    recorded = [step for step in run.steps if step.call is not None]
    assert len(recorded) == 2, "each call in a batch is its own recorded step"
    assert [step.call.arguments["path"] for step in recorded] == ["app.py", "handler.py"]
    assert all(step.result is not None for step in recorded)
    # One turn, two calls: they share the turn number, because that is when they happened.
    assert {step.index for step in recorded} == {1}


def test_an_unparseable_answer_is_fed_back_then_stops_with_error(fake_tools, tmp_path: Path) -> None:
    """A model that cannot answer in the contract stops the run and says why -- it does not hang."""
    client = ScriptedClient().queue("I am not going to answer in JSON.", "still not JSON")
    run = run_agent(
        agent="discovery",
        scope_id="s1",
        system_prompt="sys",
        task=react_task(),
        tools=[ToolName.READ],
        context=FakeToolContext(tmp_path),
        client=client,
        max_steps=8,
        max_parse_attempts=2,
    )

    assert run.stop_reason == "error"
    assert len(run.steps) == 2
    # The parse error is fed back verbatim, which is what gives the model a chance to fix *this*
    # mistake rather than guess.
    second_user = client.counter.calls[1][2]
    assert "could not be used" in second_user


def test_a_tool_outside_the_allow_list_is_refused_without_raising(fake_tools, tmp_path: Path) -> None:
    """The allow-list is the blast-radius bound: an unknown tool is an observation, not a crash."""
    client = ScriptedClient().queue(
        turn("shell_command", argv=["rm", "-rf", "/"]),
        final(ok=True),
    )
    run = run_agent(
        agent="discovery",
        scope_id="s1",
        system_prompt="sys",
        task=react_task(),
        tools=[ToolName.READ],
        context=FakeToolContext(tmp_path),
        client=client,
        max_steps=4,
    )

    assert run.stop_reason == "finished"
    refusal = run.steps[0]
    assert refusal.call is None, "a refused call never becomes a ToolCall"
    assert refusal.result is not None and refusal.result.ok is False
    assert "shell_command" in (refusal.result.error or "")
    assert fake_tools.recorded == [], "a refused tool must not reach the tool layer at all"


def test_the_final_answer_is_recorded_and_every_step_carries_its_result(fake_tools, tmp_path: Path) -> None:
    client = ScriptedClient().queue(turn("read", path="a.java"), final(answer=42))
    run = run_agent(
        agent="discovery",
        scope_id="s1",
        system_prompt="sys",
        task=react_task(),
        tools=[ToolName.READ],
        context=FakeToolContext(tmp_path),
        client=client,
        max_steps=4,
    )

    assert run.stop_reason == "finished"
    assert run.output == {"answer": 42}
    assert len(run.steps) == 2
    assert run.steps[0].thought == "call read"
    assert run.steps[0].result is not None and run.steps[0].result.ok


def test_a_client_failure_stops_the_run_and_is_recorded(fake_tools, tmp_path: Path) -> None:
    """An unreachable endpoint must not lose the run: the transcript says what happened.

    `AIUnavailable` is retried by design (it is the transient failure), so the script supplies one
    failure per allowed attempt -- derived from the constant rather than written out, so raising the
    retry count cannot make this test pass for the wrong reason.
    """
    client = ScriptedClient().queue(
        *[AIUnavailable("cannot reach https://example.invalid")] * react.MAX_CLIENT_ATTEMPTS
    )
    run = run_agent(
        agent="validation",
        scope_id="C-1",
        system_prompt="sys",
        task=react_task("C-1"),
        tools=[ToolName.READ],
        context=FakeToolContext(tmp_path),
        client=client,
        max_steps=4,
    )

    assert run.stop_reason == "error"
    assert "AIUnavailable" in run.steps[-1].thought
    assert run.finished_at is not None


def test_a_non_retryable_model_error_is_not_retried(fake_tools, tmp_path: Path) -> None:
    """`AIError` is our fault (bad key, bad model): retrying it only burns the budget."""
    from services.ai.client import AIError

    client = ScriptedClient().queue(AIError("HTTP 401"))
    run = run_agent(
        agent="validation",
        scope_id="C-1",
        system_prompt="sys",
        task=react_task("C-1"),
        tools=[ToolName.READ],
        context=FakeToolContext(tmp_path),
        client=client,
        max_steps=4,
    )

    assert run.stop_reason == "error"
    assert len(client.counter.calls) == 1, "a 401 must not be retried"


# ─────────────────────────────────────────────────────────── the blackboard


def test_a_candidate_appearing_twice_is_appended_once(tmp_path: Path) -> None:
    """Idempotent by id, because re-entering a stage must not duplicate what it already wrote."""
    board = bb.new_blackboard("run-1", tmp_path)
    candidate = Candidate(
        candidate_id="C-1",
        scope_id="scope-a",
        title="first",
        vulnerability_type="sql_injection",
        file="a.java",
    )

    assert bb.add_candidate(board, candidate) is True
    assert bb.add_candidate(board, candidate) is False
    assert bb.add_candidate(board, candidate.model_copy(update={"title": "second wording"})) is False

    assert len(board.candidates) == 1
    assert board.candidates[0].title == "first", "a re-run must not overwrite what is there"
    entry = bb.coverage_of(board, "scope-a")
    assert entry is not None and entry.candidates == 1, "the counter must not double-count either"


def test_verdicts_and_attack_paths_are_keyed_on_the_candidate(tmp_path: Path) -> None:
    board = bb.new_blackboard("run-1", tmp_path)
    board.candidates.append(
        Candidate(
            candidate_id="C-1",
            scope_id="scope-a",
            title="t",
            vulnerability_type="sql_injection",
            file="a.java",
        )
    )
    bb.ensure_coverage(board, "scope-a")

    confirmed = CandidateVerdict(
        candidate_id="C-1",
        verdict=VerdictKind.CONFIRMED,
        evidence_kind=EvidenceKind.SEMANTIC,
        confidence=0.9,
    )
    assert bb.add_verdict(board, confirmed) is True
    assert bb.add_verdict(board, confirmed) is False
    entry = bb.coverage_of(board, "scope-a")
    assert entry is not None and entry.confirmed == 1

    path = AttackPath(candidate_id="C-1", reachable=True, impact="read the table")
    assert bb.add_attack_path(board, path) is True
    assert bb.add_attack_path(board, path) is False
    assert len(board.attack_paths) == 1


def test_every_applied_update_bumps_the_revision_and_the_timestamp(tmp_path: Path) -> None:
    board = bb.new_blackboard("run-1", tmp_path)
    start = board.revision
    before = board.updated_at

    bb.add_candidate(
        board,
        Candidate(
            candidate_id="C-1",
            scope_id="s",
            title="t",
            vulnerability_type="xss",
            file="a.java",
        ),
    )
    assert board.revision == start + 1
    assert board.updated_at >= before

    # A no-op append must NOT bump: the revision is a progress signal, and inflating it makes it
    # useless for exactly the purpose it exists for.
    bb.add_candidate(
        board,
        Candidate(
            candidate_id="C-1",
            scope_id="s",
            title="t",
            vulnerability_type="xss",
            file="a.java",
        ),
    )
    assert board.revision == start + 1


def test_the_blackboard_round_trips_through_disk(tmp_path: Path) -> None:
    board = bb.new_blackboard("run-1", tmp_path)
    bb.set_context(
        board,
        project=ProjectContext(workspace=str(tmp_path), languages={"java": 3}),
    )
    bb.close_work(board, "no-such-item")  # a no-op must not raise

    bb.save(board, tmp_path)
    loaded = bb.load(tmp_path)

    assert loaded is not None
    assert loaded.run_id == "run-1"
    assert loaded.project is not None and loaded.project.languages == {"java": 3}
    assert bb.load(tmp_path / "empty") is None, "an unopened run is None, not an empty board"


def test_context_is_merged_field_by_field_not_replaced(tmp_path: Path) -> None:
    """Two agents contribute different fields to the same object; neither may erase the other."""
    board = bb.new_blackboard("run-1", tmp_path)
    bb.set_context(
        board,
        project=ProjectContext(workspace="w", languages={"java": 10}, entry_points=["Main"]),
    )
    bb.set_context(
        board,
        project=ProjectContext(
            workspace="",
            build_systems=["maven"],
            notes=["a note from a second pass"],
        ),
    )

    assert board.project is not None
    assert board.project.languages == {"java": 10}, "the first pass's counts must survive"
    assert board.project.build_systems == ["maven"]
    assert board.project.entry_points == ["Main"]
    assert board.project.workspace == "w", "the workspace is the run's identity and must not blank"


def test_a_component_an_agent_verified_upgrades_the_prescan_guess_for_the_same_id(
    tmp_path: Path,
) -> None:
    """One row per id, and the row gets the better evidence -- the pre-scan must not shadow it.

    Measured on the first real audit: recon read the code and recorded its own version of the three
    components the pre-scan had inferred from directory names, using the same ids (as it was told to).
    The merge dropped all three whole -- `path: "."` and a name guessed from a directory survived while
    `path: "handler.py"` and the real description were thrown away -- and the write was reported to the
    model as landed. The board therefore handed the planner a guess and kept the evidence out.
    """
    board = bb.new_blackboard("run-1", tmp_path)
    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[
                {
                    "id": "scope-web-route",
                    "name": "web-route（.）",
                    "kind": "web-route",
                    "path": ".",
                    "origin": "survey",
                }
            ]
        ),
    )

    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[
                {
                    "id": "scope-web-route",
                    "name": "handler.request handler",
                    "kind": "web-route",
                    "path": "handler.py",
                    "description": "reads request.args.get('id')",
                }
            ]
        ),
    )

    assert len(board.architecture.components) == 1, "one row per id; downstream keys on it"
    component = board.architecture.components[0]
    assert component["id"] == "scope-web-route", "the id is the key and is never rewritten"
    assert component["path"] == "handler.py", "the verified path must replace the inferred one"
    assert component["name"] == "handler.request handler"
    assert component["description"] == "reads request.args.get('id')"
    assert component["origin"] == "model", "the strongest producer is carried"
    assert component["sources"] == ["survey", "model"], "and both contributors are visible"


def test_a_weak_producer_cannot_undo_what_an_agent_read(tmp_path: Path) -> None:
    """Evidence is ordered, so a later component that only repeats hearsay cannot overwrite a reading.

    The threat model names components too, and it may name one it never opened. If a weaker producer's
    value won by arriving later, the board would slowly drift back to guesses.
    """
    board = bb.new_blackboard("run-1", tmp_path)
    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[
                {"id": "scope-a", "name": "read by recon", "path": "svc.py", "origin": "model"}
            ]
        ),
    )
    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[
                {
                    "id": "scope-a",
                    "name": "guessed again",
                    "path": ".",
                    "origin": "survey",
                    "files": ["svc.py", "svc_test.py"],
                }
            ]
        ),
    )

    component = board.architecture.components[0]
    assert component["name"] == "read by recon" and component["path"] == "svc.py"
    assert component["files"] == ["svc.py", "svc_test.py"], (
        "a field the verified row did not have is still filled in: filling holes is safe"
    )
    assert component["origin"] == "model"


# ─────────────────────────────────────────────────────────── the pipeline


def pipeline(tmp_path: Path, client: ScriptedClient, *, config: HarnessConfig, context=None):
    return HarnessCoordinator(
        workspace=workspace(tmp_path),
        config=config,
        client=client,
        out_dir=tmp_path / "out",
        run_id="run-test",
        context=context or FakeToolContext(tmp_path),
    )


def opening_answers() -> dict[str, str]:
    """The answers an opening agent gives on the first pass and again on the re-dispatch.

    Two passes are the *normal* shape of the opening stage, not an edge case: each agent's task text is
    fixed when its run starts, so an agent only ever sees the other's final answer by reading the board
    after that answer was merged -- and one of the two runs always ends last. A scripted client with a
    single answer per opening agent therefore leaves the pipeline mid-re-dispatch, which is how these
    fixtures first broke. Both passes get the same payload here because the point of the second one is
    "does this change your answer": the honest answer is no.
    """
    return {
        agents.RECON: final(
            languages={"java": 2, "yml": 1},
            build_systems=["maven"],
            entry_points=["UserController.java (@RestController)"],
            components=[
                {"id": SERVICE_SCOPE, "name": "service", "kind": "service-layer"},
                {"id": WEB_SCOPE, "name": "controller", "kind": "web-route"},
            ],
            trust_boundaries=["HTTP request parameters"],
            notes=[],
        ),
        agents.THREAT_MODEL: final(
            assets=["the users table"],
            actors=["anonymous internet user"],
            threats=[{"id": "T-1", "title": "SQL injection in the product list", "asset": "users"}],
            out_of_scope=["the build"],
            notes=[],
        ),
    }


def two_scope_client(counter: CallCounter | None = None) -> ScriptedClient:
    """A client that answers the fixed stages and yields one candidate for one scope only.

    The scope ids used here are the ones the real survey derives from the test workspace's layout
    (`.../service/...` and `.../controller/...`): the coordinator unions the planner's plan with the
    survey's scopes, so a test that invented ids would be planning against scopes the survey never
    proposed and would not exercise the pipeline it means to.
    """
    client = ScriptedClient(counter)
    answers = opening_answers()
    for agent, answer in answers.items():
        # Twice: the second one answers the re-dispatch the opening stage makes because a concurrent
        # agent cannot have read the peer's *final* answer while both were still running.
        client.script(agent, "workspace", answer, answer)
    client.script(
        agents.PLANNER,
        "plan",
        final(
            scopes=[
                {
                    "scope_id": SERVICE_SCOPE,
                    "title": "service layer",
                    "kind": "service-layer",
                    "rationale": "this is where the concatenated query lives",
                },
                {
                    "scope_id": WEB_SCOPE,
                    "title": "controllers",
                    "kind": "web-route",
                    "rationale": "the entry point that carries the sort parameter",
                },
            ],
            excluded=["the Maven wrapper -- build tooling, not runtime"],
            rationale="both scopes are needed to trace request data to the query",
        ),
    )
    # Every other scope the survey derived (config, root, anything else) is covered and finds
    # nothing -- an honest empty scope. A stub rather than a per-scope script because those ids
    # depend on the layout, and an empty result is what makes the assertion below unambiguous:
    # the one candidate in the blackboard can only have come from the service scope.
    client.stub_agent(agents.DISCOVERY, final(candidates=[], notes=["nothing here"]))
    client.script(agents.DISCOVERY, SERVICE_SCOPE, discovery_answer())
    return client


def _one_candidate_client(counter: CallCounter | None = None) -> ScriptedClient:
    """A full pipeline run over the test workspace: one candidate, confirmed, reachable.

    The smallest client that exercises every stage, used by the observability tests -- they assert
    about the *record* of a run, so they need a run that actually went through all of it.
    """
    client = two_scope_client(counter)
    client.script(agents.VALIDATION, SERVICE_SCOPE, validation_answer("confirmed"))
    client.script(agents.ATTACK_PATH, SERVICE_SCOPE, final(
        reachable=True, entry_points=["GET /users"], impact="full table read", confidence=0.7,
    ))
    return client


def test_coverage_redispatches_only_the_insufficient_scopes(tmp_path: Path) -> None:
    """The closure loop re-runs exactly what it judged uncovered, and closes when it converges."""
    counter = CallCounter()
    client = two_scope_client(counter)
    # The first discovery run for the service scope finds a candidate (so it is INSUFFICIENT until
    # validation has judged it); the re-dispatched round must find the *same* site and add nothing.
    client.by_agent[(agents.DISCOVERY, SERVICE_SCOPE)] = [
        discovery_answer(),
        discovery_answer(),
    ]
    # A `validation` or `attack_path` run is filed under the candidate id, so the script is keyed
    # on the candidate's *scope*: the task's first line states it, which is what makes a scripted
    # client able to answer the right run without knowing the generated candidate id. The web-route
    # scope is scripted too even though its discovery finds nothing -- a scope the fake has no
    # answer for must fail the test, not fall through to the service scope's script.
    client.script(agents.VALIDATION, WEB_SCOPE, validation_answer("confirmed"))
    client.script(agents.VALIDATION, SERVICE_SCOPE, validation_answer("confirmed"))
    client.script(agents.ATTACK_PATH, WEB_SCOPE, final(
        reachable=False, impact="not reachable", confidence=0.9,
    ))
    client.script(agents.ATTACK_PATH, SERVICE_SCOPE, final(
        reachable=True, entry_points=["GET /users"], impact="full table read", confidence=0.7,
    ))

    coordinator = pipeline(tmp_path, client, config=HarnessConfig(max_rounds=3))
    result = coordinator.run()
    board = result.blackboard

    discovery_scopes = [run.scope_id for run in board.runs if run.agent == agents.DISCOVERY]
    coverage_groups = sorted({s for s in discovery_scopes if s.startswith("scope-coverage-")})
    assert coverage_groups, "the inventory must be assigned to coverage groups"
    reasons = {entry.scope_id: entry.reason for entry in board.coverage}
    # The rule this test now pins. The fake tool layer never returns a `read`, so no file is ever
    # fully read and every file-owning scope stays INSUFFICIENT -- including the web scope, which
    # found nothing. That is the change: "discovery found nothing here" used to be enough to close a
    # scope, and it closed scopes whose files nobody had opened (measured: 29 of 59 files on the Java
    # benchmark, while all six scopes reported SUFFICIENT).
    assert discovery_scopes.count(SERVICE_SCOPE) >= 2, "an undecided scope is re-dispatched"
    assert discovery_scopes.count(WEB_SCOPE) >= 2, (
        "a scope whose files were never read is not closed, even when discovery found nothing"
    )
    assert "从未被完整读取" in reasons[WEB_SCOPE], reasons[WEB_SCOPE]
    assert "从未被完整读取" in reasons[SERVICE_SCOPE], reasons[SERVICE_SCOPE]
    assert board.coverage, "closure must produce a row per planned scope"
    planned_rows = [e for e in board.coverage if e.state is not CoverageState.EXCLUDED]
    assert planned_rows
    assert all(entry.state is CoverageState.INSUFFICIENT for entry in planned_rows), "; ".join(
        f"{e.scope_id}={e.state.value}: {e.reason}" for e in planned_rows
    )
    assert all("从未被完整读取" in entry.reason for entry in planned_rows)
    assert board.findings and board.findings[0].vulnerability_type == "sql_injection"
    assert board.rounds_run == 4, "with unreadable files the loop can only stop on the round bound"
    # The excluded area is a decided scope, and distinct from `unseen`.
    assert any(entry.state is CoverageState.EXCLUDED for entry in board.coverage)


def test_a_second_opinion_about_a_known_line_is_not_a_new_place(tmp_path: Path) -> None:
    """Closure asks "did we find somewhere new to look", not "did the model say something new".

    The measured failure this pins: on a five-file Python fixture, every discovery round re-flagged
    `orders.py:17`/`:18` under a different vulnerability type. `candidate_id` includes the type, so
    those counted as new *candidates* to the closure rule, every scope stayed INSUFFICIENT, and the
    run spent 21 discovery + 26 validation agent runs on 243 lines of code -- stopping only because
    the round bound ran out. A second opinion about a line already in the ledger is not a place
    nobody looked at.

    Driven through `_discover` rather than a whole run, because that is where the counting happens
    and a whole run cannot show it: in this fake tool layer no `read` is ever returned, so the
    separate "files never opened" clause keeps every file-owning scope INSUFFICIENT regardless --
    which is correct behaviour and would hide the thing under test.
    """
    client = two_scope_client()
    client.by_agent[(agents.DISCOVERY, SERVICE_SCOPE)] = [
        discovery_answer(candidate_payload(vulnerability_type="sql_injection")),
        discovery_answer(candidate_payload(vulnerability_type="authz_bypass")),
    ]
    coordinator = pipeline(tmp_path, client, config=HarnessConfig(max_rounds=1))
    bb.add_work(
        coordinator.blackboard,
        [WorkItem(work_id="W-1", scope_id=SERVICE_SCOPE, title="service", rationale="r")],
    )
    coordinator._planned_scopes = [SERVICE_SCOPE]
    coordinator._scope_files = {
        SERVICE_SCOPE: ["src/main/java/com/example/service/UserService.java"]
    }

    first = coordinator._discover([SERVICE_SCOPE], round_index=0)
    second = coordinator._discover([SERVICE_SCOPE], round_index=1)

    assert first[SERVICE_SCOPE] == 1, "round 0 found a place"
    assert second[SERVICE_SCOPE] == 0, "the same line under a second type is not a new place"
    assert len(coordinator.blackboard.candidates) == 2, (
        "both claims are still recorded -- the ledger keeps them, only the closure signal ignores "
        "the second one"
    )

    # And the reason a reader sees says which of the two things happened.
    coordinator._close_coverage(coordinator._candidate_map(), round_index=1, new_by_scope=second)
    entry = bb.coverage_of(coordinator.blackboard, SERVICE_SCOPE)
    assert entry is not None and "从未被完整读取" in entry.reason, (
        "with no new places found, the scope is held open by the unread files -- not by the model "
        f"having restated itself; got: {entry.reason if entry else None}"
    )


def test_the_round_bound_stops_the_closure_loop(tmp_path: Path) -> None:
    """`max_rounds` bounds the re-dispatch loop, and the report says the bound bit.

    The discovery script keeps finding a *new* site every round, which is the only way to observe
    the bound: a scope that converges would stop the loop for the right reason, and the test would
    pass even with no bound at all.
    """
    counter = CallCounter()
    client = two_scope_client(counter)
    # A different file every time the service scope is scanned, so it keeps producing new candidates
    # and cannot converge on its own -- the loop can only stop because `max_rounds` ran out. Enough
    # answers for every possible round, so a shortfall in the script can never look like the bound.
    client.by_agent[(agents.DISCOVERY, SERVICE_SCOPE)] = [
        discovery_answer(
            candidate_payload(file=f"src/main/java/com/example/service/Service{i}.java")
        )
        for i in range(12)
    ]
    client.stub_agent(agents.VALIDATION, validation_answer("confirmed"))
    client.script(agents.ATTACK_PATH, SERVICE_SCOPE, final(reachable=True, impact="x", confidence=0.5))
    client.script(agents.ATTACK_PATH, WEB_SCOPE, final(reachable=False, impact="x", confidence=0.5))

    max_rounds = 2
    # `concurrency=1` serialises the discovery threads. The assertion `by_round["0"] == planned`
    # compares completion order with plan order, and with concurrent threads that order is
    # scheduling-dependent -- which made this test flaky. Serialising makes the order deterministic
    # without changing what is being verified (the round bound still stops the loop).
    coordinator = pipeline(
        tmp_path, client,
        config=HarnessConfig(max_rounds=max_rounds, concurrency=1),
    )
    result = coordinator.run()

    board = result.blackboard
    planned = planned_scopes(board, ids=True)
    discovery_runs = [run for run in board.runs if run.agent == agents.DISCOVERY]
    assert board.rounds_run == max_rounds + 1, "round 0 plus `max_rounds` re-dispatch rounds"
    # Every round is a separate dispatch, and a scope is scanned at most once per round: a round
    # that re-scanned a scope would double that scope's budget with no record of it.
    by_round: dict[str, list[str]] = {}
    for run in discovery_runs:
        assert run.run_id.startswith(f"{agents.DISCOVERY}:") and ":r" in run.run_id
        scope_id, _, round_tag = run.run_id[len(agents.DISCOVERY) + 1:].rpartition(":r")
        by_round.setdefault(round_tag, []).append(scope_id)
    assert sorted(by_round) == [str(i) for i in range(board.rounds_run)]
    for round_tag, scanned in by_round.items():
        assert len(scanned) == len(set(scanned)), f"round {round_tag} scanned a scope twice"
        assert set(scanned) <= set(planned)
    assert by_round["0"] == planned, "round 0 dispatches every planned scope"
    # Every later round re-dispatches exactly what the previous closure left INSUFFICIENT. With a
    # fake tool layer that never returns a `read`, that is *every* scope which owns files -- the
    # service scope because it keeps finding new sites, and the web-route and config scopes because
    # nobody read their files. The second half is the guarantee this test now pins: "discovery found
    # nothing here" no longer closes a scope whose files were never opened, so the loop can only stop
    # on the round bound.
    for round_tag, scanned in by_round.items():
        if round_tag != "0":
            assert set(scanned) == set(planned), (
                f"round {round_tag} must re-dispatch every scope the closure left INSUFFICIENT, "
                f"got {scanned}"
            )
    assert any("从未被完整读取" in entry.reason for entry in board.coverage)
    # The bound bit, and the run says so instead of pretending to have converged.
    assert any(entry.state is CoverageState.INSUFFICIENT for entry in board.coverage)
    assert any("round budget exhausted" in note for note in result.notes)
    assert board.closed, "a run that hit its round bound still closes and reports"
    assert result.report_path is not None and result.report_path.is_file()
    text = result.report_path.read_text(encoding="utf-8")
    # The coverage table is what a reviewer reads first, and it must be legible: the state is
    # rendered as Chinese prose in the findings/report, not as the raw enum member.
    assert "| `insufficient` |" not in text
    assert "不充分" in text


def planned_scopes(board, *, ids: bool = False):
    """The scopes the run opened work for -- i.e. everything it dispatched discovery to."""
    return [item.scope_id for item in board.work] if ids else len(board.work)


def test_a_rejected_candidate_reaches_the_report_with_its_reason(tmp_path: Path) -> None:
    """Rejected candidates are part of the answer, so the reason has to survive into the report."""
    reason = "the sort value is checked against a fixed column allow-list before the query"
    counter = CallCounter()
    client = two_scope_client(counter)
    client.by_agent[(agents.DISCOVERY, SERVICE_SCOPE)] = [
        discovery_answer(),
        discovery_answer(),
    ]
    client.script(
        agents.VALIDATION,
        SERVICE_SCOPE,
        validation_answer("rejected", confidence=0.2, reasons=[reason]),
    )
    client.script(
        agents.VALIDATION,
        WEB_SCOPE,
        validation_answer("rejected", confidence=0.2, reasons=["the web scope found nothing"]),
    )

    result = pipeline(tmp_path, client, config=HarnessConfig(max_rounds=2)).run()
    text = result.report_path.read_text(encoding="utf-8")

    verdict = bb.find_verdict(result.blackboard, result.blackboard.candidates[0].candidate_id)
    assert verdict is not None and verdict.verdict is VerdictKind.REJECTED
    assert reason in text, "the rejection reason must be in the report, not only in the blackboard"
    assert "被排除的候选" in text
    assert result.blackboard.findings == [], "a rejected candidate must not become a finding"


def test_validation_carries_the_tool_dataflow_evidence_into_the_verdict(tmp_path: Path) -> None:
    """When the validator calls `dataflow_verify`, the tool's own answer travels with the verdict."""
    recorded_evidence = DataflowEvidence(
        derived=True,
        source="request.args.get",
        sink="cursor.execute",
        path=["handler(request)", "cursor.execute(query)"],
        methods=["handle_request", "run_query"],
    )

    module = make_fake_tools(
        answers={
            ToolName.DATAFLOW_VERIFY.value: ToolResult(
                tool=ToolName.DATAFLOW_VERIFY,
                ok=True,
                summary="path found",
                data={"derived": True, "evidence": recorded_evidence.model_dump()},
            )
        }
    )
    import sys as _sys

    _sys.modules["services.harness.tools"] = module
    react.clear_tool_layer_cache()
    try:
        client = ScriptedClient()
        client.script(agents.VALIDATION, "C-1", turn(
            "dataflow_verify",
            file="src/main/java/com/example/service/UserService.java",
            line=3,
        ))
        client.script(agents.VALIDATION, "C-1", validation_answer("confirmed", kind="dataflow"))

        run = agents.run(
            agent=agents.VALIDATION,
            scope_id="C-1",
            task="decide",
            context=module.ToolContext(tmp_path),
            client=client,
            max_steps=4,
        )
        verdict = run.parsed
        verdict.candidate_id = "C-1"

        assert verdict.evidence_kind is EvidenceKind.DATAFLOW
        assert verdict.dataflow is not None
        assert verdict.dataflow.derived is True
        assert verdict.dataflow.path == recorded_evidence.path
        assert verdict.dataflow.sink == "cursor.execute"
        # The model was asked the dataflow question and the tool actually ran.
        assert module.recorded and module.recorded[0].tool is ToolName.DATAFLOW_VERIFY
    finally:
        react.clear_tool_layer_cache()


def test_a_forced_prefetch_reaches_the_verdict_without_the_model_asking(tmp_path: Path) -> None:
    """The harness's own `dataflow_verify` must end up in the verdict.

    The first version of the forced trace prepended the step to the run *after* `agents.run`
    returned -- but the verdict is parsed inside that call, so a run that had just paid for a real
    trace still reported `evidence_kind=semantic` with no dataflow attached. Measured on a live run:
    24 verdicts, every one semantic, while the tool had derived a sink for eight of them. The step
    therefore has to be seeded as an initial step, and the model's own opinion about which evidence
    kind it used does not get to override a path the engine actually returned.
    """
    recorded = DataflowEvidence(
        derived=True,
        source="query_user(user_id)",
        sink="execute",
        path=["repo.py:4 user_id", "repo.py:7 cursor.execute(sql)"],
        methods=["query_user"],
    )
    module = make_fake_tools(
        answers={
            ToolName.DATAFLOW_VERIFY.value: ToolResult(
                tool=ToolName.DATAFLOW_VERIFY,
                ok=True,
                summary="path found",
                data={"derived": True, "evidence": recorded.model_dump()},
            )
        }
    )
    import sys as _sys

    _sys.modules["services.harness.tools"] = module
    react.clear_tool_layer_cache()
    try:
        candidate = Candidate(
            candidate_id="C-1",
            scope_id="scope-a",
            title="concatenated query",
            vulnerability_type="sql_injection",
            file="repo.py",
            line=6,
        )
        assert agents.is_taint_candidate(candidate) is True

        context = module.ToolContext(tmp_path)
        prefetched = agents.verify_taint_candidate(candidate, context)
        assert prefetched is not None, "a taint candidate must get a trace attempt"
        # No sink is ever sent: the engine derives it from the hit's position.
        assert "sink" not in prefetched.call.arguments

        client = ScriptedClient()
        # The model neither calls the tool nor claims a dataflow basis.
        client.script(agents.VALIDATION, "C-1", validation_answer("rejected", kind="semantic"))

        outcome = agents.run(
            agent=agents.VALIDATION,
            scope_id="C-1",
            task=agents.validation_task(
                bb.new_blackboard("run-1", tmp_path), candidate, prefetched=prefetched
            ),
            context=context,
            client=client,
            max_steps=2,
            initial_steps=[prefetched],
        )
        verdict = outcome.parsed
        assert verdict.evidence_kind is EvidenceKind.DATAFLOW, (
            "a derived path outranks the model's own label for the evidence"
        )
        assert verdict.dataflow is not None and verdict.dataflow.derived is True
        assert verdict.dataflow.sink == "execute"
    finally:
        _sys.modules.pop("services.harness.tools", None)
        react.clear_tool_layer_cache()


def test_a_failed_dataflow_verification_is_not_read_as_no_path(tmp_path: Path) -> None:
    """The failure text travels with the verdict: "we never asked" is not "there is no path"."""
    module = make_fake_tools(
        answers={
            ToolName.DATAFLOW_VERIFY.value: ToolResult(
                tool=ToolName.DATAFLOW_VERIFY,
                ok=False,
                error="数据流验证器未接入（ToolContext.dataflow 为空）",
                data={
                    "unavailable": "dataflow_verifier_absent",
                    "evidence": DataflowEvidence(error="数据流验证器未接入").model_dump(),
                },
            )
        }
    )
    import sys as _sys

    _sys.modules["services.harness.tools"] = module
    react.clear_tool_layer_cache()
    try:
        client = ScriptedClient()
        client.script(agents.VALIDATION, "C-1", turn("dataflow_verify", file="a.java", line=1))
        client.script(agents.VALIDATION, "C-1", validation_answer("rejected", kind="dataflow"))

        run = agents.run(
            agent=agents.VALIDATION,
            scope_id="C-1",
            task="decide",
            context=module.ToolContext(tmp_path),
            client=client,
            max_steps=4,
        )
        verdict: CandidateVerdict = run.parsed

        assert verdict.dataflow is not None and verdict.dataflow.error, (
            "a failed verification must be carried, not silently dropped"
        )
        assert any("数据流" in reason for reason in verdict.reasons)
    finally:
        react.clear_tool_layer_cache()


# ─────────────────────────────────────────────────────────── the CLI


def test_dry_run_makes_no_model_calls_and_writes_a_report(tmp_path: Path) -> None:
    """`--dry-run` is the plumbing check, and its whole value is that it spends nothing.

    No client is installed anywhere here -- not into the coordinator, not into the environment --
    so a dry run that tried to call a model would fail rather than pass quietly.
    """
    root = workspace(tmp_path)

    code = main([
        "run",
        "--workspace", str(root),
        "--out", str(tmp_path / "out"),
        "--dry-run",
    ])

    assert code == 0
    run_dirs = list((tmp_path / "out").iterdir())
    assert run_dirs, "the dry run must still persist a run directory"
    report_path = run_dirs[0] / "report.md"
    assert report_path.is_file()
    text = report_path.read_text(encoding="utf-8")
    assert "dry run" in text
    assert "没有调用模型" in text or "未调用任何模型" in text
    blackboard = bb.load(run_dirs[0])
    assert blackboard is not None and blackboard.rounds_run >= 1
    # The claim of coverage is honest: every signal is recorded as unjudged, never confirmed.
    assert all(
        verdict.verdict is VerdictKind.REJECTED for verdict in blackboard.verdicts
    )
    # And the run is watchable after the fact: the CLI attaches the trail unconditionally, so even
    # a run that calls no model leaves a record of what it decided and why.
    trail_path = run_dirs[0] / trail.TRAIL_NAME
    assert trail_path.is_file(), "every run leaves a trail, dry runs included"
    events = list(trail.iter_events(trail_path))
    assert [event["kind"] for event in events if event["kind"] == "stage"]
    assert events[-1]["kind"] == "summary"
    assert events[-1]["dry_run"] is True


def test_the_cli_refuses_an_unconfigured_ai_stage(tmp_path: Path, monkeypatch, capsys) -> None:
    """A run that silently produces nothing is the failure this refusal exists to prevent."""
    monkeypatch.setattr("aegis_core.config.get_settings", lambda: _settings(enabled=False))

    code = main(["run", "--workspace", str(workspace(tmp_path))])

    assert code == EXIT_NOT_CONFIGURED
    err = capsys.readouterr().err
    assert "AEGIS_AI__ENABLED" in err, "the message must name the variable to set"
    assert "拒绝启动" in err


def test_the_cli_refuses_when_the_key_is_missing(tmp_path: Path, monkeypatch, capsys) -> None:
    """Enabled but no credentials is a *different* problem and gets a different message."""
    settings = _settings(enabled=True, api_key_env="AEGIS_HARNESS_TEST_KEY")
    monkeypatch.setattr("aegis_core.config.get_settings", lambda: settings)
    monkeypatch.delenv("AEGIS_HARNESS_TEST_KEY", raising=False)

    code = main(["run", "--workspace", str(workspace(tmp_path))])

    assert code == EXIT_NOT_CONFIGURED
    err = capsys.readouterr().err
    assert "AEGIS_HARNESS_TEST_KEY" in err


def _settings(*, enabled: bool, api_key_env: str = "API_KEY"):
    from aegis_core.config import Settings

    settings = Settings(
        ai={
            "enabled": enabled,
            "base_url": "https://example.invalid/v1" if enabled else "",
            "model": "test-model" if enabled else "",
            "api_key_env": api_key_env,
        }
    )
    return settings.resolve()


# ─────────────────────────────────────────────────────────── the report


def test_the_report_contains_the_trail_the_coverage_table_and_the_rejections(tmp_path: Path) -> None:
    """One document, three questions answered: what happened, what is covered, what was dismissed."""
    board = Blackboard(run_id="run-x", workspace=str(tmp_path))
    candidate = Candidate(
        candidate_id="C-abc",
        scope_id="scope-a",
        title="query built by concatenation",
        vulnerability_type="sql_injection",
        file="a.java",
        line=7,
        rationale="the sort parameter reaches the query",
    )
    board.candidates.append(candidate)
    board.verdicts.append(
        CandidateVerdict(
            candidate_id="C-abc",
            verdict=VerdictKind.REJECTED,
            evidence_kind=EvidenceKind.SEMANTIC,
            reasons=["the column name is validated against an allow-list"],
            confidence=0.3,
        )
    )
    board.runs.append(
        AgentRun(
            run_id="discovery:scope-a:r0",
            agent="discovery",
            scope_id="scope-a",
            stop_reason="budget",
            steps=[
                AgentStep(
                    index=1,
                    thought="read the service",
                    call=ToolCall(tool=ToolName.READ, arguments={"path": "a.java"}, reason="look"),
                    result=ToolResult(tool=ToolName.READ, ok=True, summary="1\tabc"),
                )
            ],
        )
    )
    board.work.append(
        WorkItem(work_id="W-a", scope_id="scope-a", title="service", rationale="the query lives here")
    )
    board.coverage.append(
        CoverageEntry(
            scope_id="scope-a",
            title="service",
            state=CoverageState.INSUFFICIENT,
            reason="discovery did not finish",
        )
    )

    text = report.render(board)

    assert "the column name is validated against an allow-list" in text
    assert "预算" in text or "budget" in text
    assert "discovery:scope-a:r0" in text
    assert "read the service" in text
    assert "discovery did not finish" in text
    assert "the query lives here" in text
    assert "提前结束" in text


def test_severity_comes_from_reachability_not_from_the_weakness_class() -> None:
    """A confirmed-but-unreachable issue is not the same claim as a reachable one."""
    assert _severity(AttackPath(candidate_id="C", reachable=False)) == "low"
    assert _severity(AttackPath(candidate_id="C", reachable=True)) == "high"
    assert (
        _severity(AttackPath(candidate_id="C", reachable=True, auth_conditions=["admin role"]))
        == "medium"
    )
    assert (
        _severity(AttackPath(candidate_id="C", reachable=True, auth_conditions=["anonymous"]))
        == "high"
    )


# ─────────────────────────────────────────────────────────── against the real tool layer


def test_the_real_tool_layer_satisfies_the_frozen_surface(tmp_path: Path) -> None:
    """The surface the orchestrator imports, checked against the real package.

    Skipped rather than failed when the tool package is absent: the promise is that planning and a
    dry run work without it, so the orchestration test-suite must not itself depend on it existing.
    """
    try:
        import services.harness.tools as tools
    except ImportError as exc:  # pragma: no cover - depends on the tool layer being landed
        pytest.skip(f"tool layer not installed: {exc}")

    for name in ("TOOLS", "schemas", "invoke", "ToolContext", "ToolLimits"):
        assert hasattr(tools, name), f"the frozen surface is missing {name}"
    assert set(tools.TOOLS) == set(ToolName)

    # `resolve()` on the workspace, because the tool layer resolves before comparing containment:
    # under pytest's tmp_path the unresolved and resolved forms differ on Windows, and a listing
    # from the unresolved root would come back empty for reasons that have nothing to do with this
    # code. That mismatch is worth knowing about, and the tools' own tests are where it belongs.
    root = workspace(tmp_path).resolve()
    context = tools.ToolContext(workspace=root)
    result = tools.invoke(
        context, ToolCall(tool=ToolName.LIST_FILES, arguments={"pattern": "**/*.java"}, reason="t")
    )
    assert result.ok, result.error
    assert result.data["count"] >= 1, result.summary

    # `dataflow_verify` with no verifier must fail loudly rather than return an empty-but-ok path.
    verify = tools.invoke(
        context,
        ToolCall(
            tool=ToolName.DATAFLOW_VERIFY,
            arguments={"file": "src/main/java/com/example/service/UserService.java", "line": 3},
            reason="t",
        ),
    )
    assert verify.ok is False
    assert verify.data.get("evidence", {}).get("error"), (
        "an absent verifier must be reported as an error, not as an empty result"
    )


def test_the_pipeline_runs_against_the_real_tool_layer_with_a_scripted_model(tmp_path: Path) -> None:
    """End to end: real coordinator, real tools, scripted model. Nothing else is a double.

    This is the test that catches a contract mismatch between the two halves of the harness -- the
    tool layer being called with the wrong context, a `ToolResult` shape the orchestrator misreads,
    `dataflow_verify` being reported as a positive result when no verifier exists. The unit tests
    above cannot see any of that, because there the tools are a fake that agrees with whatever the
    orchestrator expects.
    """
    try:
        import services.harness.tools as tools
    except ImportError as exc:  # pragma: no cover - depends on the tool layer being landed
        pytest.skip(f"tool layer not installed: {exc}")

    root = workspace(tmp_path).resolve()
    client = two_scope_client()
    # Discovery reads a file for real, then answers. The real `read` result has to come back through
    # the loop as an observation, which is what proves the context and the dispatch both work.
    client.by_agent[(agents.DISCOVERY, SERVICE_SCOPE)] = [
        turn("read", path="src/main/java/com/example/service/UserService.java"),
        final(candidates=[candidate_payload()], notes=[]),
    ]
    client.script(agents.VALIDATION, SERVICE_SCOPE, turn(
        "dataflow_verify",
        file="src/main/java/com/example/service/UserService.java",
        line=3,
    ))
    client.script(agents.VALIDATION, SERVICE_SCOPE, validation_answer("confirmed", kind="dataflow"))
    client.script(agents.VALIDATION, WEB_SCOPE, validation_answer("rejected", reasons=["empty"]))
    client.script(agents.ATTACK_PATH, SERVICE_SCOPE, final(
        reachable=True, entry_points=["GET /users"], impact="full table read", confidence=0.6,
    ))
    client.script(agents.ATTACK_PATH, WEB_SCOPE, final(
        reachable=False, impact="none", confidence=0.9,
    ))

    coordinator = HarnessCoordinator(
        workspace=root,
        config=HarnessConfig(max_rounds=1),
        client=client,
        out_dir=tmp_path / "out",
        run_id="run-real-tools",
        context=tools.ToolContext(workspace=root),  # the real context, no verifier injected
    )
    result = coordinator.run()
    board = result.blackboard

    discovery_run = next(
        run
        for run in board.runs
        if run.agent == agents.DISCOVERY and run.scope_id == SERVICE_SCOPE
    )
    read_step = next(step for step in discovery_run.steps if step.call is not None)
    assert read_step.result is not None and read_step.result.ok, (
        "the real `read` tool must succeed through the real context"
    )
    assert "UserService" in read_step.result.summary
    assert read_step.result.data["path"].endswith("UserService.java")
    assert discovery_run.reused_files == [], (
        "this run is the first reader, so nothing came out of the blackboard for it"
    )

    # `dataflow_verify` has no verifier here, so it must report unavailable -- and the verdict must
    # carry that failure rather than an empty path that reads like "the engine proved no flow".
    verdict = next(v for v in board.verdicts if v.candidate_id.startswith("C-"))
    assert verdict.dataflow is not None and verdict.dataflow.error
    assert any("数据流" in reason or "dataflow" in reason for reason in verdict.reasons)
    assert result.report_path is not None
    assert "数据流" in result.report_path.read_text(encoding="utf-8")


def test_a_scope_reaches_discovery_with_its_lite_skill(tmp_path: Path, fake_tools) -> None:
    """The lite skill is chosen from the architecture map and lands in the agent's prompt."""
    board = bb.new_blackboard("run-1", tmp_path)
    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[{"id": "scope-web-route-x", "name": "controllers", "kind": "web-route"}]
        ),
    )

    skill = agents.lite_skill_for_scope(board, "scope-web-route-x")

    assert "web-route scope" in skill
    assert "trace the request parameters" in skill
    assert agents.lite_skill_for_scope(board, "scope-unknown") == agents.DEFAULT_LITE_SKILL


def test_the_specialty_follows_the_files_not_the_scope_name(tmp_path: Path) -> None:
    """The skill an agent gets is decided by what its files are, not by what the planner called it.

    The previous selection looked the scope id up in the architecture map, and the planner invents ids
    -- `scope-route-orders-sql`, `scope-coverage-3` -- that never appear there. Measured on the Java
    benchmark: all fourteen scopes got the "no specialisation" default, so the clause that tells an
    auditor to look for actuator or debug endpoints left enabled never reached the agent holding
    `application.yml`. That agent found the two hardcoded credentials in the file and missed the three
    one-line switches in it.
    """
    assert agents.skill_kinds_for_files(["src/main/resources/application.yml"]) == ["config"]
    assert agents.skill_kinds_for_files(
        ["src/main/resources/mapper/ProductMapper.xml"]
    ) == ["data-access"]
    assert agents.skill_kinds_for_files(
        ["src/main/java/com/example/service/UserService.java"]
    ) == ["service-layer"]
    # A group that spans layers gets every specialty it needs, and none of them twice.
    assert agents.skill_kinds_for_files(
        [
            "src/main/java/com/example/controller/A.java",
            "src/main/java/com/example/service/B.java",
            "src/main/resources/application.yml",
        ]
    ) == ["web-route", "service-layer", "config"]

    # And it reaches the prompt of a coverage group, which is the case that failed: those scope ids
    # are never in the architecture map, so every one of them used to get the default block.
    board = bb.new_blackboard("run-1", tmp_path)
    block = agents.discovery_extra_system(
        board,
        f"{coverage.COVERAGE_SCOPE_PREFIX}0",
        index=0,
        files=["src/main/resources/application.yml"],
    )
    assert "actuator" in block and "debug" in block, "the config clause must reach the agent"
    assert "credentials" in block
    # A group with no recognised kind still gets the honest default rather than an empty block.
    bare = agents.discovery_extra_system(
        board, f"{coverage.COVERAGE_SCOPE_PREFIX}1", index=1, files=["notes.xyz"]
    )
    assert agents.DEFAULT_LITE_SKILL in bare


def test_candidate_ids_are_stable_so_a_second_round_deduplicates(tmp_path: Path) -> None:
    """The id is derived from the site, not generated: that is what makes a re-run idempotent."""
    first = agents.stable_candidate_id("scope-a", "a.java", 7, "sql_injection")
    second = agents.stable_candidate_id("scope-a", "a.java", 7, "sql_injection")
    other = agents.stable_candidate_id("scope-a", "a.java", 8, "sql_injection")
    other_type = agents.stable_candidate_id("scope-a", "a.java", 7, "ssrf")

    assert first == second
    assert first != other and first != other_type
    assert first.startswith("C-") and "sql-injection" in first


def test_work_items_close_with_a_bounded_step_count(tmp_path: Path) -> None:
    """`steps_used` is a maximum, not a sum: two rounds report the longest, not their total."""
    board = bb.new_blackboard("run-1", tmp_path)
    board.work.append(
        WorkItem(work_id="W-1", scope_id="s", title="t", rationale="r", steps_used=5)
    )

    assert bb.close_work(board, "W-1", state=WorkItemState.DONE, steps_used=3) is True
    assert board.work[0].steps_used == 5
    assert board.work[0].state is WorkItemState.DONE
    assert board.work[0].closed_at is not None
    assert bb.close_work(board, "W-1", state=WorkItemState.DONE, steps_used=9) is True
    assert board.work[0].steps_used == 9
    assert bb.close_work(board, "missing") is False


# ─────────────────────────────────────────── the closed type vocabulary


def test_the_type_vocabulary_maps_what_models_write_onto_one_name_per_class() -> None:
    """Free text in, one of 35 ids out -- and the specific rule beats the general one.

    The order matters and is the reason this is tested at all: `nosql` has to be tried before `sql`
    and `template` before the bare `inject`, or every injection family collapses into `sql_injection`
    or `code_injection` and the labels stop carrying information.
    """
    assert skills.normalize_type("SQL Injection") == "sql_injection"
    assert skills.normalize_type("sql-injection") == "sql_injection"
    assert skills.normalize_type("NoSQL injection") == "nosql_injection"
    assert skills.normalize_type("Server-Side Template Injection") == "template_injection"
    assert skills.normalize_type("OS command injection via Runtime.exec") == "command_injection"
    assert skills.normalize_type("XML External Entity") == "xxe"
    assert skills.normalize_type("") == "other"


def test_every_vocabulary_entry_is_its_own_fixed_point() -> None:
    """A canonical id must survive normalisation unchanged, or the list rewrites its own output.

    Without the identity check first, `idor` would fall through the rules and come back as
    `insecure direct object reference` -- a *different string* for the same class, which is how a
    deduplication key stops matching itself between rounds.
    """
    assert len(set(skills.VULNERABILITY_TYPES)) == len(skills.VULNERABILITY_TYPES)
    for name in skills.VULNERABILITY_TYPES:
        assert skills.normalize_type(name) == name


def test_a_type_outside_the_vocabulary_is_kept_rather_than_flattened() -> None:
    """The list is a reporting aid, not an authority: an unknown class stays readable.

    Rewriting it to `other` would hide the class *and* merge it with every other unknown, so the
    value surviving verbatim is the signal that the vocabulary is missing an entry.
    """
    assert skills.normalize_type("business-logic-flaw") == "business_logic_flaw"
    assert skills.normalize_type("Business Logic Flaw") == "business_logic_flaw"


# ─────────────────────────────────────────── deduplicating one claim


def _claim(
    scope_id: str, *, file: str = "a.java", line: int = 7, kind: str = "sql_injection", **overrides
) -> Candidate:
    payload = {
        "candidate_id": agents.stable_candidate_id(scope_id, file, line, kind),
        "scope_id": scope_id,
        "title": "concat",
        "vulnerability_type": kind,
        "file": file,
        "line": line,
        "rationale": "r",
    }
    payload.update(overrides)
    return Candidate(**payload)


def test_the_group_key_separates_two_claims_that_share_a_file_or_a_line() -> None:
    """What the key must *not* merge, pinned next to what it must.

    Both rejected variants are real shapes in a Java repository: four sibling command-injection call
    sites inside one service class, and one route line that is both a SQL injection and an IDOR. A
    `(file, type)` key answers all four siblings with one verdict; a type-family key conflates the
    two vulnerabilities on the single line.
    """
    same = _claim("scope-a")
    # `_claim` stamps `discovered_at`, so two calls built in the same expression are only equal when
    # they happen to land in the same microsecond -- which this assertion relied on, and which flaked
    # (532µs apart) the first time the machine was busy. Build the peer once and compare that object.
    peer = _claim("scope-b")
    assert agents.validation_groups([same, peer]) == {
        agents.validation_group_key(same): [same, peer]
    }
    siblings = [_claim("scope-a", line=33), _claim("scope-a", line=41)]
    assert len(agents.validation_groups(siblings)) == 2, "a different call site is a different claim"
    two_kinds = [_claim("scope-a"), _claim("scope-a", kind="idor")]
    assert len(agents.validation_groups(two_kinds)) == 2, "two vulnerabilities, one line, one group"


def test_the_representative_is_the_instance_with_the_most_to_say() -> None:
    """Merging must not cost the group its best evidence -- that is the whole risk of the saving."""
    thin = _claim("scope-a", rationale="looks concatenated")
    rich = _claim("scope-b", rationale="the sort parameter reaches the query", evidence=["l1", "l2"])

    chosen = agents.group_representative([thin, rich])

    assert chosen is rich
    assert agents.group_representative([rich, thin]) is rich, "order must not decide it"


def test_the_validator_is_told_which_other_instances_it_speaks_for() -> None:
    """A verdict that silently covers five candidates is a decision whose scope nobody can see."""
    only = _claim("scope-a")
    assert agents.group_note([only]) == ""
    note = agents.group_note([only, _claim("scope-b"), _claim("scope-c")])

    assert "3 separately recorded instances" in note
    assert _claim("scope-b").candidate_id in note
    assert "a verdict here covers all of them" in note


def test_two_scopes_filing_one_site_get_one_validation_and_one_finding(tmp_path: Path) -> None:
    """Overlap must not multiply the bill, the report, or the coverage ledger.

    The service scope and the web scope both file the *same* `UserService.java:3` SQL injection --
    which is what overlapping scopes do, and what made a measured run report 99 findings over 50
    distinct positions. The properties below are exactly the ones the change is allowed to alter:
    one validation run instead of two, one finding instead of two. Everything else is not allowed to
    move -- both candidates stay in the ledger, both carry a verdict (a candidate with none would
    hold its scope INSUFFICIENT forever), and the finding keeps the second location visible.
    """
    counter = CallCounter()
    client = two_scope_client(counter)
    # The same site, filed from the other scope. The payload is identical on purpose: two agents
    # that disagree on nothing are the case a dedup key must recognise.
    client.by_agent[(agents.DISCOVERY, WEB_SCOPE)] = [discovery_answer()]
    client.script(agents.VALIDATION, WEB_SCOPE, validation_answer("confirmed"))
    client.script(agents.VALIDATION, SERVICE_SCOPE, validation_answer("confirmed"))
    client.script(agents.ATTACK_PATH, WEB_SCOPE, final(
        reachable=True, entry_points=["GET /users"], impact="full table read", confidence=0.7,
    ))
    client.script(agents.ATTACK_PATH, SERVICE_SCOPE, final(
        reachable=True, entry_points=["GET /users"], impact="full table read", confidence=0.7,
    ))

    result = pipeline(tmp_path, client, config=HarnessConfig(max_rounds=1)).run()
    board = result.blackboard

    assert len(board.candidates) == 2, "the ledger keeps every instance; only the *decision* merges"
    assert len(board.verdicts) == 2, (
        "a merged verdict must be copied to every member, or its scope never closes"
    )
    assert {v.candidate_id for v in board.verdicts} == {c.candidate_id for c in board.candidates}
    assert all(
        v.verdict is VerdictKind.CONFIRMED for v in board.verdicts
    ), "the copy carries the decision, not just a placeholder"
    assert any("由同一位置" in reason for v in board.verdicts for reason in v.reasons)

    validation_calls = [call for call in counter.calls if call[0] == agents.VALIDATION]
    assert len(validation_calls) == 1, "one site is paid for once"
    assert "separately recorded instances" in validation_calls[0][2], (
        "the validator must be told the verdict covers two instances"
    )
    assert len([call for call in counter.calls if call[0] == agents.ATTACK_PATH]) == 1

    assert len(board.findings) == 1
    finding = board.findings[0]
    assert finding.vulnerability_type == "sql_injection"
    assert len(finding.affected_locations) == 2
    assert {location["candidate_id"] for location in finding.affected_locations} == {
        candidate.candidate_id for candidate in board.candidates
    }
    assert "合并为一条发现" in finding.summary

    rendered = report.render(board)
    assert "同位点实例" in rendered
    assert all(location["candidate_id"] in rendered for location in finding.affected_locations)


# ─────────────────────────────────────────── watching a run while it runs


def test_attaching_a_trail_again_starts_a_new_file(tmp_path: Path) -> None:
    """A re-run must not append to the previous attempt's trail.

    A redriven job keeps its id, and the run directory is derived from that id -- so the second
    attempt writes into the same place. Appending there would interleave two runs whose `seq` both
    start at 1, and the console pages by `seq`: it would show some of attempt one, then jump into
    attempt two, with no way to tell. Measured on a canceled audit that was resubmitted.
    """
    coordinator = pipeline(tmp_path, two_scope_client(), config=HarnessConfig(max_rounds=1))
    first = coordinator.attach_trail()
    first.emit("stage", stage="recon", state="start")
    path = coordinator.run_dir / trail.TRAIL_NAME
    assert len(trail.read_events(path)["events"]) == 1

    # The same coordinator, the same run directory: what a redrive does.
    second = coordinator.attach_trail()
    second.emit("stage", stage="plan", state="start")

    events = trail.read_events(path)["events"]
    assert len(events) == 1, "the second attach starts a new file, it does not append"
    assert events[0]["stage"] == "plan"
    assert second.seq == 1


def test_the_trail_records_each_agents_conversation_as_it_happens(tmp_path: Path) -> None:
    """The observability contract: the run is readable *while* it runs, not only after it ends.

    Two properties, and neither is about formatting. First, every agent run that the blackboard ends
    up holding was announced and closed in the trail -- a screen that missed an agent would show a
    run with a hole in it. Second, each event is on disk before the next one is written: the sink
    order puts the JSONL first, and this checks the promise from a *callback* sink, which can only
    see the file as it is at that instant.
    """
    coordinator = pipeline(tmp_path, _one_candidate_client(), config=HarnessConfig(max_rounds=1))
    path = coordinator.run_dir / trail.TRAIL_NAME
    durable_at: list[tuple[int, int]] = []

    def spy(event: dict) -> None:
        # Called after the JSONL sink, so the file must already contain this event.
        on_disk = trail.read_events(path, after_seq=0, limit=10**9)
        durable_at.append((event["seq"], on_disk["last_seq"]))

    trail_obj = coordinator.attach_trail(trail.CallbackSink(spy))
    result = coordinator.run()
    board = result.blackboard

    events = list(trail.iter_events(path))
    kinds = [event["kind"] for event in events]
    assert set(kinds) >= {"stage", "agent_start", "agent_step", "agent_end", "summary"}
    assert kinds[-1] == "summary"

    # Every run in the ledger was announced and closed, in that order, exactly once.
    announced = [event["run_id"] for event in events if event["kind"] == "agent_start"]
    closed = [event["run_id"] for event in events if event["kind"] == "agent_end"]
    assert len(announced) == len(board.runs), "an agent run the ledger has must be in the trail too"
    assert sorted(announced) == sorted(closed), "every start has its end"

    steps = [event for event in events if event["kind"] == "agent_step"]
    recorded_steps = sum(len(run.steps) for run in board.runs)
    assert len(steps) == recorded_steps, "one event per step, no more and no fewer"
    # The dialogue, not just a count: a step event names the tool and keeps the model's thought.
    assert any(event["tool"] for event in steps), "a run against the fake tool layer calls tools"
    assert all("thought" in event for event in steps)
    assert durable_at and all(on_disk >= seq for seq, on_disk in durable_at), (
        "nothing was buffered: the file already held each event when the observer was told"
    )
    assert trail_obj.seq > 0


def test_a_scope_closes_in_the_same_round_that_read_its_files(tmp_path: Path, monkeypatch) -> None:
    """Convergence, pinned end to end: read + judged + a thin round = closed, no extra round.

    Two changes are both needed for this and neither is observable without the other:

    * validation now runs **before** the coverage decision, so the decision sees verdicts for the
      candidates this round just found. Run afterwards, every round left them undecided and forced
      another round -- which is why the fixture ran to `max_rounds` every time;
    * a round must add at least `min_new_places_per_round` new places to justify another round. One
      line per round is a reviewer annotating, not an unreviewed scope.
    """
    service_file = "src/main/java/com/example/service/UserService.java"
    root = workspace(tmp_path)
    lines = (root / service_file).read_text(encoding="utf-8").count("\n") + 1
    # A tool layer that reports a full read of the service file, so the "files never opened" clause
    # does not hold the scope open for a reason that has nothing to do with this test.
    module = make_fake_tools(
        answers={
            "read": ToolResult(
                tool=ToolName.READ,
                ok=True,
                summary=f"读到 {service_file}",
                data={
                    "path": service_file,
                    "offset": 1,
                    "total_lines": lines,
                    "returned_lines": lines,
                    "truncated": False,
                },
            )
        }
    )
    monkeypatch.setitem(sys.modules, "services.harness.tools", module)
    react.clear_tool_layer_cache()

    client = two_scope_client()
    client.by_agent[(agents.DISCOVERY, SERVICE_SCOPE)] = [
        json.dumps({"thought": "先读文件", "tool": "read", "arguments": {"path": service_file}}),
        discovery_answer(),
    ]
    client.stub_agent(agents.VALIDATION, validation_answer("confirmed"))
    client.script(agents.ATTACK_PATH, SERVICE_SCOPE, final(reachable=True, impact="x", confidence=0.5))
    client.script(agents.ATTACK_PATH, WEB_SCOPE, final(reachable=False, impact="x", confidence=0.5))

    coordinator = HarnessCoordinator(
        workspace=root,
        config=HarnessConfig(max_rounds=3, min_new_places_per_round=2),
        client=client,
        out_dir=tmp_path / "out",
        run_id="run-test",
        context=FakeToolContext(tmp_path),
    )
    coordinator.attach_trail()
    result = coordinator.run()
    board = result.blackboard
    events = list(trail.iter_events(coordinator.run_dir / trail.TRAIL_NAME))

    decisions = [
        event for event in events if event["kind"] == "coverage" and event["scope"] == SERVICE_SCOPE
    ]
    assert decisions, "one coverage decision per scope per round"
    assert decisions[0]["state"] == "sufficient", (
        "the scope closed in the round it was read and judged: " + decisions[0]["reason"]
    )
    assert "低于阈值 2" in decisions[0]["reason"], (
        "and the reason says why a round that found something still closed: " + decisions[0]["reason"]
    )
    dispatches = [
        event
        for event in events
        if event["kind"] == "agent_start"
        and event["agent"] == agents.DISCOVERY
        and event["scope"] == SERVICE_SCOPE
    ]
    assert len(dispatches) == 1, (
        f"this scope was dispatched once, not {len(dispatches)} times -- that is the whole saving"
    )
    # The candidate is still reported -- closing early must not mean losing the finding.
    assert board.candidates and board.findings, "the finding survives the early close"
    # The loop itself still runs for the *other* scopes (their files were never read), which is the
    # round bound doing its job rather than a failure of this one to converge.
    assert board.rounds_run > 1


def test_a_round_that_finds_enough_new_places_still_re_dispatches(tmp_path: Path) -> None:
    """The threshold must not become a way to stop looking. Two new places is still "keep going"."""
    counter = CallCounter()
    client = two_scope_client(counter)
    client.by_agent[(agents.DISCOVERY, SERVICE_SCOPE)] = [
        discovery_answer(
            candidate_payload(file="src/main/java/com/example/service/A.java", line=1),
            candidate_payload(file="src/main/java/com/example/service/B.java", line=2),
        ),
        discovery_answer(
            candidate_payload(file="src/main/java/com/example/service/A.java", line=1),
            candidate_payload(file="src/main/java/com/example/service/B.java", line=2),
        ),
    ]
    client.stub_agent(agents.VALIDATION, validation_answer("confirmed"))
    client.script(agents.ATTACK_PATH, SERVICE_SCOPE, final(reachable=True, impact="x", confidence=0.5))
    client.script(agents.ATTACK_PATH, WEB_SCOPE, final(reachable=False, impact="x", confidence=0.5))

    coordinator = pipeline(
        tmp_path, client, config=HarnessConfig(max_rounds=2, min_new_places_per_round=2)
    )
    coordinator.attach_trail()
    result = coordinator.run()

    # The *first* decision for this scope is the one under test: by the last round the same two
    # places are already known, so it is the unread-files clause that keeps it open -- which is the
    # behaviour of the previous test, not this one.
    decisions = [
        event
        for event in trail.iter_events(coordinator.run_dir / trail.TRAIL_NAME)
        if event["kind"] == "coverage" and event["scope"] == SERVICE_SCOPE
    ]
    assert decisions, "the trail records one coverage decision per scope per round"
    first = decisions[0]
    assert "本轮在 2 个此前没见过位置发现了候选" in first["reason"], first["reason"]
    assert first["state"] == "insufficient"
    assert result.blackboard.rounds_run > 1, (
        "two new places in a round still justify another round -- the threshold must not become a "
        "way to stop looking"
    )


def test_the_validator_is_handed_the_source_instead_of_being_sent_to_read_it(
    tmp_path: Path,
) -> None:
    """The material packet reaches the prompt, and turning it off is a real mode.

    Measured on a five-file project: 471 of 823 model round trips were `read` calls, every agent
    reading the same six files from scratch. The packet is what removes those round trips, so it has
    to be visible in the task the agent actually receives -- not merely built and dropped on the floor.
    """
    enabled = CallCounter()
    client = _one_candidate_client(enabled)
    coordinator = pipeline(
        tmp_path / "on",
        client,
        config=HarnessConfig(max_rounds=1, material_budget=12_000),
    )
    coordinator.run()
    validation_prompts = [call[2] for call in enabled.calls if call[0] == agents.VALIDATION]
    assert validation_prompts, "the run validated something"
    assert "已为你取出的材料" in validation_prompts[0]
    assert "不必再为了这些行调用 read" in validation_prompts[0]
    assert 'String q = "SELECT * FROM users ORDER BY " + sort;' in validation_prompts[0], (
        "the hit's own line is inlined, with its line number"
    )

    off = CallCounter()
    disabled = pipeline(
        tmp_path / "off",
        _one_candidate_client(off),
        config=HarnessConfig(max_rounds=1, material_budget=0),
    )
    disabled.run()
    assert all(
        "已为你取出的材料" not in call[2] for call in off.calls if call[0] == agents.VALIDATION
    ), "budget 0 switches the packet off, which is how its value gets measured"


def test_candidate_material_cannot_read_outside_the_workspace(tmp_path: Path) -> None:
    """`file` is model-written: the packet must not become a file-disclosure tool."""
    from services.harness.material import candidate_material

    outside = tmp_path / "secret.py"
    outside.write_text("token = 'do-not-inline'\n", encoding="utf-8")
    root = workspace(tmp_path)
    candidate = Candidate(
        candidate_id="C-1",
        scope_id="s",
        title="t",
        vulnerability_type="sql_injection",
        file="../secret.py",
        line=1,
        rationale="r",
    )

    material = candidate_material(root, candidate)

    assert material.empty
    assert "do-not-inline" not in material.render()


def test_a_redispatched_scope_is_handed_its_files_instead_of_refetching_them(
    tmp_path: Path, monkeypatch
) -> None:
    """A fresh agent has never seen the code, so "you already read this" cannot be acted on.

    Measured on a real audit: 88 runs, 471 `read` calls, six files in the repository, and *every* run
    read all six (`repo.py` was opened by 88 distinct runs). Rounds 1-3 read more per run than round 0
    (5.9 vs 4.7 files) because the unread-subset narrowing is empty by then -- everything is read, so
    the task carries no file list and the agent fetches the repository again. 110 of the 143 discovery
    reads came from those rounds.

    So the harness reads them first, through the real tool, and seeds the results as turn-0 steps.
    Three things follow, and this test pins all three: the content is in the transcript, the steps are
    genuine `read` results (so the coverage ledger counts them), and a second pass is told what to do
    instead of re-reading.
    """
    service_file = "src/main/java/com/example/service/UserService.java"
    lines = len((workspace(tmp_path) / service_file).read_text(encoding="utf-8").splitlines())
    read_answer = ToolResult(
        tool=ToolName.READ,
        ok=True,
        summary=f"{service_file} 第 1-{lines} 行（共 {lines} 行）：\n1\tpublic class UserService {{",
        data={
            "path": service_file,
            "offset": 1,
            "total_lines": lines,
            "returned_lines": lines,
            "next_offset": None,
            "truncated": False,
        },
    )
    module = make_fake_tools(answers={"read": read_answer})
    monkeypatch.setitem(sys.modules, "services.harness.tools", module)
    react.clear_tool_layer_cache()

    counter = CallCounter()
    client = two_scope_client(counter)
    # Round 0 finds a candidate; round 1 finds nothing new, so the scope closes there.
    # Round 0 first `read`s the file so a complete read lands on the blackboard for round 1 to reuse.
    client.by_agent[(agents.DISCOVERY, SERVICE_SCOPE)] = [
        turn("read", path=service_file),
        discovery_answer(),
        final(candidates=[], notes=["没有新的"]),
    ]
    client.stub_agent(agents.VALIDATION, validation_answer("confirmed"))
    client.script(agents.ATTACK_PATH, SERVICE_SCOPE, final(reachable=True, impact="x", confidence=0.5))
    client.script(agents.ATTACK_PATH, WEB_SCOPE, final(reachable=False, impact="x", confidence=0.5))

    coordinator = pipeline(
        tmp_path / "run",
        client,
        config=HarnessConfig(max_rounds=1, min_new_places_per_round=1, material_budget=12_000),
    )
    result = coordinator.run()

    prompts = [call[2] for call in counter.calls if call[0] == agents.DISCOVERY]
    round_one = [prompt for prompt in prompts if "discovery round 2" in prompt]
    assert round_one, "the scope was re-dispatched, which is the case under test"
    service_round_one = [p for p in round_one if SERVICE_SCOPE in p]
    assert service_round_one, (
        "SERVICE_SCOPE is the case under test -- a scope another round already read the file for"
    )
    prompt = service_round_one[0]
    assert "已读入" in prompt, "the files are named as already read"
    assert "do not read them again" in prompt
    assert "Your job is the second look" in prompt, (
        "and the pass is given a job other than re-reading"
    )
    assert "1\tpublic class UserService" in prompt, (
        "the content itself is in the transcript as a seeded step"
    )

    # The seeded steps are real reads: the coverage ledger sees them, so the scope can close.
    seeded = [
        step
        for run in result.blackboard.runs
        if run.run_id == f"discovery:{SERVICE_SCOPE}:r1"
        for step in run.steps
        if step.call is not None and step.call.tool is ToolName.READ
    ]
    assert seeded, "the harness's own reads are recorded in the run"
    entry = next(row for row in result.blackboard.coverage if row.scope_id == SERVICE_SCOPE)
    assert "从未被完整读取" not in (entry.reason or ""), (
        "the ledger counts the harness's reads exactly as it counted the model's, so the scope is no "
        f"longer held open for an unread file -- got: {entry.reason}"
    )


def test_the_prefetch_is_off_at_budget_zero_and_skips_what_does_not_fit(
    tmp_path: Path, monkeypatch
) -> None:
    """Two guards on the same mechanism: off means off, and a file too big is skipped whole."""
    from services.harness.agents import prefetch_scope_files
    from services.harness.tools.base import ToolContext, ToolLimits

    root = workspace(tmp_path / "prefetch")
    service_file = "src/main/java/com/example/service/UserService.java"
    lines = len((root / service_file).read_text(encoding="utf-8").splitlines())
    big = ToolResult(
        tool=ToolName.READ,
        ok=True,
        summary="x" * 5000,
        data={"path": service_file, "offset": 1, "total_lines": lines,
              "returned_lines": lines, "next_offset": None, "truncated": False},
    )
    module = make_fake_tools(answers={"read": big})
    monkeypatch.setitem(sys.modules, "services.harness.tools", module)
    react.clear_tool_layer_cache()
    context = ToolContext(workspace=root, limits=ToolLimits())

    off, _reused, read, skipped = prefetch_scope_files([service_file], context, budget=0)
    assert (off, read, skipped) == ([], [], []), "budget 0 disables the prefetch entirely"

    steps, _reused, read, skipped = prefetch_scope_files([service_file], context, budget=1000)
    assert steps == [] and read == [] and skipped == [service_file], (
        "a file that does not fit the budget is skipped whole, never cut in half: half a file counted "
        "as covered would be a false coverage claim"
    )

    steps, _reused, read, skipped = prefetch_scope_files([service_file], context, budget=20_000)
    assert steps == [] and read == [] and skipped == [service_file], (
        "the default is blackboard-only: without a blackboard that has the file, it is named as skipped"
        "and the agent reads it itself"
    )

    steps, _reused, read, skipped = prefetch_scope_files(
        [service_file], context, budget=20_000, from_disk=True
    )
    assert len(steps) == 1 and read == [service_file] and skipped == []


def test_a_file_the_run_already_read_is_taken_from_the_blackboard_not_the_disk(
    tmp_path: Path, monkeypatch
) -> None:
    """The sharing that was missing was not data, it was a reader.

    Measured on a real audit: the blackboard held 471 complete `read` results -- 220 KB of file text,
    `repo.py` alone stored 88 times -- and `coverage.from_runs` was the only thing that ever looked at
    them. So the second re-dispatch of a scope should not touch the disk at all: the bytes are already
    in the run's own transcript, and re-reading them is what made 88 agents open the same six files.
    """
    from services.harness.agents import prefetch_scope_files, stored_read
    from services.harness.tools.base import ToolContext, ToolLimits

    root = workspace(tmp_path / "reuse")
    service_file = "src/main/java/com/example/service/UserService.java"
    lines = (root / service_file).read_text(encoding="utf-8").splitlines()
    module = make_fake_tools(
        answers={
            "read": ToolResult(
                tool=ToolName.READ,
                ok=True,
                summary="\n".join(lines),
                data={
                    "path": service_file,
                    "offset": 1,
                    "total_lines": len(lines),
                    "returned_lines": len(lines),
                    "next_offset": None,
                    "lines": lines,
                    "truncated": False,
                },
            )
        }
    )
    monkeypatch.setitem(sys.modules, "services.harness.tools", module)
    react.clear_tool_layer_cache()
    context = ToolContext(workspace=root, limits=ToolLimits())

    board = bb.new_blackboard("run-reuse", root)
    first, _reused, read, _skipped = prefetch_scope_files(
        [service_file], context, budget=20_000, from_disk=True
    )
    assert read == [service_file] and len(module.recorded) == 1
    for step in first:  # what a real run does with them
        run = AgentRun(run_id="discovery:s:r0", agent="discovery", scope_id="s")
        run.steps.append(step)
        bb.add_run(board, run)
    assert stored_read(board, service_file) is not None

    module.recorded.clear()
    second, reused, read, _skipped = prefetch_scope_files(
        [service_file], context, budget=20_000, blackboard=board
    )

    assert reused == [service_file], "the second dispatch reuses what the run already read"
    assert read == [] and module.recorded == [], "and does not touch the disk to do it"
    assert len(second) == 1 and second[0].result.summary == "\n".join(lines), (
        "the bytes handed over are the ones the run already saw"
    )
    assert second[0].thought == agents.SCOPE_REUSE_THOUGHT, (
        "and the transcript says where they came from"
    )


def test_an_incomplete_read_is_not_reused_as_if_it_were_the_file(tmp_path: Path) -> None:
    """`returned_lines == total_lines` or nothing: a partial read handed over as the file is a false
    coverage claim, which is the one thing this ledger exists to prevent."""
    from services.harness.agents import stored_read

    board = bb.new_blackboard("run-partial", tmp_path)
    run = AgentRun(run_id="discovery:s:r0", agent="discovery", scope_id="s")
    run.steps.append(
        AgentStep(
            index=1,
            thought="读了一半",
            call=ToolCall(tool=ToolName.READ, arguments={"path": "big.py"}),
            result=ToolResult(
                tool=ToolName.READ,
                ok=True,
                summary="前 200 行",
                data={
                    "path": "big.py",
                    "offset": 1,
                    "total_lines": 900,
                    "returned_lines": 200,
                    "next_offset": 201,
                    "lines": ["x"] * 200,
                    "truncated": True,
                },
            ),
        )
    )
    bb.add_run(board, run)

    assert stored_read(board, "big.py") is None


def test_replayable_reads_only_looks_at_the_blackboard(tmp_path: Path, monkeypatch) -> None:
    """`replayable_reads` never touches the tool layer: it only reads what the board already holds."""
    from services.harness.agents import replayable_reads

    module = make_fake_tools()
    monkeypatch.setitem(sys.modules, "services.harness.tools", module)
    react.clear_tool_layer_cache()
    board = bb.new_blackboard("run-empty", tmp_path)
    steps, reused, missing = replayable_reads(board, ["a.py", "b.py"], budget=10_000)
    assert steps == [] and reused == [] and missing == ["a.py", "b.py"]
    assert module.recorded == [], "replayable_reads makes no tool calls at all"


def test_replayable_reads_returns_what_the_board_has_and_names_what_it_does_not(
    tmp_path: Path,
) -> None:
    """A file with a complete read on the board is replayed; a file without one is named missing."""
    from services.harness.agents import replayable_reads

    board = bb.new_blackboard("run-replay", tmp_path)
    run = AgentRun(run_id="discovery:s:r0", agent="discovery", scope_id="s")
    run.steps.append(
        AgentStep(
            index=1,
            thought="读到了",
            call=ToolCall(tool=ToolName.READ, arguments={"path": "a.py"}),
            result=ToolResult(
                tool=ToolName.READ, ok=True, summary="a.py 全文",
                data={
                    "path": "a.py", "offset": 1, "total_lines": 5,
                    "returned_lines": 5, "next_offset": None, "lines": ["x"] * 5,
                },
            ),
        )
    )
    bb.add_run(board, run)

    steps, reused, missing = replayable_reads(board, ["a.py", "b.py"], budget=10_000)
    assert len(steps) == 1 and reused == ["a.py"] and missing == ["b.py"]
    assert steps[0].thought == agents.SCOPE_REUSE_THOUGHT


def test_replayable_reads_is_a_no_op_for_an_empty_file_list(tmp_path: Path) -> None:
    """An empty list shares nothing -- an agent with no files is handed nothing (decision D2)."""
    from services.harness.agents import replayable_reads

    board = bb.new_blackboard("run-noop", tmp_path)
    steps, reused, missing = replayable_reads(board, [], budget=10_000)
    assert steps == [] and reused == [] and missing == []


def test_a_partially_read_file_is_not_replayable(tmp_path: Path) -> None:
    """`returned_lines == total_lines` or nothing: a half-read file is named missing, not reused."""
    from services.harness.agents import replayable_reads

    board = bb.new_blackboard("run-partial-replay", tmp_path)
    run = AgentRun(run_id="discovery:s:r0", agent="discovery", scope_id="s")
    run.steps.append(
        AgentStep(
            index=1, thought="读了一半",
            call=ToolCall(tool=ToolName.READ, arguments={"path": "big.py"}),
            result=ToolResult(
                tool=ToolName.READ, ok=True, summary="前 200 行",
                data={
                    "path": "big.py", "offset": 1, "total_lines": 900,
                    "returned_lines": 200, "next_offset": 201,
                    "lines": ["x"] * 200, "truncated": True,
                },
            ),
        )
    )
    bb.add_run(board, run)

    steps, reused, missing = replayable_reads(board, ["big.py"], budget=10_000)
    assert steps == [] and reused == [] and missing == ["big.py"]


def test_discovery_round_zero_reuses_a_file_another_scope_already_read(
    tmp_path: Path, monkeypatch
) -> None:
    """Round 0 now reuses: a file another scope read completely is not re-read from disk."""
    from services.harness.agents import prefetch_scope_files

    root = workspace(tmp_path / "round0")
    service_file = "src/main/java/com/example/service/UserService.java"
    lines = (root / service_file).read_text(encoding="utf-8").splitlines()
    module = make_fake_tools(
        answers={
            "read": ToolResult(
                tool=ToolName.READ, ok=True, summary="\n".join(lines),
                data={
                    "path": service_file, "offset": 1, "total_lines": len(lines),
                    "returned_lines": len(lines), "next_offset": None, "lines": lines,
                    "truncated": False,
                },
            )
        }
    )
    monkeypatch.setitem(sys.modules, "services.harness.tools", module)
    react.clear_tool_layer_cache()
    context = FakeToolContext(tmp_path)

    board = bb.new_blackboard("run-reuse-r0", root)
    # Scope A reads the file first (from_disk=True model the old path).
    first, _reused, read, _skipped = prefetch_scope_files(
        [service_file], context, budget=20_000, from_disk=True
    )
    assert read == [service_file]
    for step in first:
        run = AgentRun(run_id="discovery:a:r0", agent="discovery", scope_id="a")
        run.steps.append(step)
        bb.add_run(board, run)

    module.recorded.clear()
    # Scope B owns the same file: round 0 now reuses it out of the board instead of reading the disk.
    second, reused, read2, _skipped2 = prefetch_scope_files(
        [service_file], context, budget=20_000, blackboard=board
    )
    assert reused == [service_file], "round 0 reuses what another scope already read"
    assert read2 == [] and module.recorded == [], "no disk read for the second scope's same file"
    # The run that received the reused step carries its file in `reused_files`.
    run_b = AgentRun(run_id="discovery:b:r0", agent="discovery", scope_id="b")
    run_b.steps.extend(second)
    run_b.reused_files = agents._reused_files(second)
    assert run_b.reused_files == [service_file]


def test_opening_pass_two_does_not_re_read_what_pass_one_read(tmp_path: Path) -> None:
    """A pass-2 recon gets its files out of the blackboard, not off the disk."""
    from services.harness.agents import replayable_reads

    root = workspace(tmp_path / "opening")
    inventory = coverage.inventory(root)
    board = bb.new_blackboard("run-opening", root)
    # Pretend pass 1 read every file: put a complete read on the board for each.
    run = AgentRun(run_id="recon:workspace:p1", agent="recon", scope_id="workspace")
    for i, f in enumerate(inventory):
        run.steps.append(
            AgentStep(
                index=i + 1, thought="pass1",
                call=ToolCall(tool=ToolName.READ, arguments={"path": f}),
                result=ToolResult(
                    tool=ToolName.READ, ok=True, summary=f"读到 {f}",
                    data={
                        "path": f, "offset": 1, "total_lines": 10,
                        "returned_lines": 10, "next_offset": None, "lines": ["x"] * 10,
                    },
                ),
            )
        )
    bb.add_run(board, run)

    steps, reused, _missing = replayable_reads(board, inventory, budget=10_000_000)
    assert len(steps) == len(inventory), "pass 2 reuses every file pass 1 read"
    assert len(reused) == len(inventory)


def test_a_planner_created_scope_carries_the_files_the_planner_named(
    tmp_path: Path, monkeypatch
) -> None:
    """The planner's `files` answer is written back into `_scope_files` (before: silently dropped)."""
    from services.harness.tools.base import ToolContext, ToolLimits

    root = workspace(tmp_path / "plannerfiles")
    service_file = "src/main/java/com/example/service/UserService.java"
    module = make_fake_tools(
        answers={
            "read": ToolResult(
                tool=ToolName.READ, ok=True, summary="stub", data={"stub": True},
            )
        }
    )
    monkeypatch.setitem(sys.modules, "services.harness.tools", module)
    react.clear_tool_layer_cache()
    context = ToolContext(workspace=root, limits=ToolLimits())

    scopes = [
        survey.Scope(
            scope_id="scope-survey-1", title="survey", kind="service-layer",
            path="src/main/java/com/example/service", rationale="survey",
            files=[service_file],
        )
    ]
    client = ScriptedClient()
    client.script(
        agents.PLANNER, "plan",
        final(
            scopes=[
                {
                    "scope_id": "scope-planner-1",
                    "title": "planner scope",
                    "kind": "service-layer",
                    "rationale": "created by the planner",
                    "files": [service_file, "nonexistent.py"],
                }
            ],
            excluded=[],
        ),
    )
    coordinator = HarnessCoordinator(
        workspace=root,
        config=HarnessConfig(),
        client=client,
        out_dir=tmp_path / "out",
        run_id="run-planner",
        context=context,
    )
    coordinator._planner_call(scopes)
    assert coordinator._scope_files.get("scope-planner-1") == [service_file], (
        "the planner's files are written back, filtered against the real inventory"
    )


def test_the_round_zero_reuse_text_asks_for_a_first_look_not_a_second(tmp_path: Path) -> None:
    """Round-0 reuse says \"first analysis\", not \"second look\": the agent is not suppressing findings."""
    board = bb.new_blackboard("run-text1", tmp_path)
    item = WorkItem(work_id="W-1", scope_id="scope-x", title="x", rationale="test")
    first = agents.discovery_task(board, item, attempt=1, files=["a.py"], reused=["a.py"])
    assert "*first* analysis" in first
    assert "second look" not in first
    second = agents.discovery_task(board, item, attempt=2, files=["a.py"], reused=["a.py"])
    assert "second look" in second


def test_the_round_zero_reuse_text_does_not_also_demand_a_read(tmp_path: Path) -> None:
    """When every owned file is already in the transcript, the text does not also say \"read them\"."""
    board = bb.new_blackboard("run-text2", tmp_path)
    item = WorkItem(work_id="W-2", scope_id="scope-y", title="y", rationale="test")
    text = agents.discovery_task(board, item, attempt=1, files=["a.py"], reused=["a.py"])
    assert "read each one end to end" not in text, (
        "the same task text must not both say \"already read\" and \"read each one\""
    )


def test_reading_a_trail_is_incremental_and_survives_a_damaged_line(tmp_path: Path) -> None:
    """`after_seq` pages, and a torn last line is counted rather than raised.

    The torn line is not hypothetical: the whole reason the trail is flushed per line is that the
    process can die mid-run, and a kill between two writes is exactly how a half-written line gets
    there. A reader that raised on it would refuse to show the 400 events before it.
    """
    path = tmp_path / "trail.jsonl"
    sink = trail.JsonlSink(path)
    writer = trail.Trail([sink], base={"run_id": "R-1"})
    for index in range(5):
        writer.emit("candidate", candidate_id=f"C-{index}")
    writer.close()
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"seq": 99, "kind": "cand')  # killed here

    first = trail.read_events(path, after_seq=0, limit=2)
    assert [event["candidate_id"] for event in first["events"]] == ["C-0", "C-1"]
    assert first["more"] is True and first["last_seq"] == 2

    rest = trail.read_events(path, after_seq=first["last_seq"], limit=10)
    assert [event["candidate_id"] for event in rest["events"]] == ["C-2", "C-3", "C-4"]
    assert rest["more"] is False
    assert rest["damaged"] == 1
    assert rest["events"][0]["run_id"] == "R-1", "the base fields ride on every event"

    missing = trail.read_events(tmp_path / "nope.jsonl")
    assert missing["exists"] is False and missing["events"] == []


def test_an_abort_stops_the_fan_out_instead_of_the_whole_stage(tmp_path: Path) -> None:
    """Cancellation has to land *inside* a stage, not after it.

    `_bounded` submits every work item to the pool up front, so an abort check placed once before
    the pool would let all 14 discovery scopes and all 56 validations run and only then stop --
    which is a cancel button that does nothing for the half hour it matters. Checked per item, the
    already-running agents finish (at most `concurrency`) and the queued ones never start.
    """
    counter = CallCounter()
    client = _one_candidate_client(counter)

    def abort() -> bool:
        # True as soon as one discovery agent has been paid for. The abort is only consulted
        # between units of work, so this asks for exactly one scope's worth and no more.
        return any(call[0] == agents.DISCOVERY for call in counter.calls)

    coordinator = pipeline(tmp_path, client, config=HarnessConfig(max_rounds=1, concurrency=1))
    coordinator._abort = abort
    coordinator.attach_trail()
    with pytest.raises(CanceledAbort):
        coordinator.run()

    discovery = [call for call in counter.calls if call[0] == agents.DISCOVERY]
    assert len(discovery) == 1, (
        "the abort must land between scopes, not after every scope has been paid for"
    )
    # And the trail says where it stopped, so a reader of a canceled run is not left guessing.
    events = list(trail.iter_events(coordinator.run_dir / trail.TRAIL_NAME))
    assert any(event["kind"] == "stage" and event["state"] == "failed" for event in events)


# ─────────────────────────────────────── the opening: prep, concurrency, records


def _events(coordinator) -> list[dict]:
    return list(trail.iter_events(coordinator.run_dir / trail.TRAIL_NAME))


def _user_task(counter: CallCounter, agent: str) -> str:
    """The task text the coordinator handed `agent`, read back off the model traffic."""
    return next(user for which, _scope, user in counter.calls if which == agent)


def test_the_prep_survey_is_on_the_board_before_the_first_model_call(tmp_path: Path) -> None:
    """The deterministic facts are written first, so the opening agents verify instead of invent.

    Both halves are the point. *Before* any model call, because a board populated afterwards is a board
    the opening stage never used; and *on the board* rather than in a local variable, because recon's
    architecture is merged into it as a union -- the survey's components used to be recorded only as a
    fallback when recon produced none, so a model-written map replaced the orchestrator's counted one.
    """
    counter = CallCounter()
    coordinator = pipeline(
        tmp_path, _one_candidate_client(counter), config=HarnessConfig(max_rounds=1)
    )
    coordinator.attach_trail()
    result = coordinator.run()
    events = _events(coordinator)

    prep_end = next(
        event
        for event in events
        if event["kind"] == "stage" and event.get("stage") == "prep" and event["state"] == "end"
    )
    first_agent = next(event for event in events if event["kind"] == "agent_start")
    assert prep_end["seq"] < first_agent["seq"], "prep must finish before any agent starts"
    # And it is a stage of its own in the table, not the first line of the opening stage. Measured in
    # the deployed image: with the survey inside `_recon_and_threat_model`, the stage table read
    # 仓库勘察 → 预扫描, i.e. it claimed recon had started while the tree was still being walked.
    stage_starts = [
        event["stage"] for event in events if event["kind"] == "stage" and event["state"] == "start"
    ]
    assert stage_starts[:2] == ["prep", "recon"], f"stages started in the wrong order: {stage_starts}"

    board = result.blackboard
    assert board.project is not None and board.project.languages.get("java") == 2
    assert board.project.build_systems == ["maven"]
    components = {component["id"] for component in board.architecture.components}
    assert SERVICE_SCOPE in components and WEB_SCOPE in components, (
        "the survey's scopes must be on the board, not only the model's components"
    )
    assert any("survey:" in note for note in board.architecture.notes), (
        "the report has to be able to tell the counted components from the inferred ones"
    )

    recon_task = _user_task(counter, agents.RECON)
    assert "pre-scan" in recon_task, "recon must be told what was already established"
    assert SERVICE_SCOPE in recon_task, "and shown the scopes it is meant to verify"
    assert "record" in recon_task, "and told to write as it goes"
    assert "record" in _user_task(counter, agents.THREAT_MODEL)


def test_the_pre_scans_route_markers_reach_recon_as_leads_but_not_the_board(
    tmp_path: Path,
) -> None:
    """A grep hit per *file* is a lead, not an entry point, and the board's list means one thing.

    Measured on the 51-file Spring benchmark: the pre-scan contributed 13 file-level hits ("this file
    registers REST controllers") and recon itself produced 42 route-level entries; both landed in
    `project.entry_points`, nothing could merge them (a file is not a file:line), and the reader got 55
    entries for 42 routes -- with the 13 useless ones being exactly the ones that do not answer "which
    requests can arrive". They are still handed to recon, in its task text, under a name that says what
    they are; what changed is that the board's `entry_points` only ever holds what an agent read.

    It is also the cheaper arrangement: the threat model's task is built from the board and re-sent every
    turn, so those 1,633 characters were being paid for on each of the run's 60 threat turns (~24k input
    tokens) to carry text that made the list wrong.
    """
    counter = CallCounter()
    coordinator = pipeline(
        tmp_path, _one_candidate_client(counter), config=HarnessConfig(max_rounds=1)
    )
    coordinator.attach_trail()
    coordinator.run()

    # The fixture has an `@GetMapping`, so the pre-scan found a marker.
    markers = coordinator._snapshot["project"].entry_points
    assert markers and any("GetMapping" in marker or "controller" in marker.lower() for marker in markers)

    board = coordinator.blackboard
    assert board.project is not None
    assert all(marker not in board.project.entry_points for marker in markers), (
        "the pre-scan's file-level hits must not be on the board as if they were routes"
    )

    recon_task = _user_task(counter, agents.RECON)
    assert "route_markers_in_code" in recon_task, "but recon still gets them, named as markers"
    assert '"entry_points"' not in recon_task.split("route_markers_in_code")[0], (
        "and the payload no longer calls them entry_points"
    )
    assert "enumerate the actual routes" in recon_task, "with the instruction to verify them"

    # The threat model's task is built from the board, so it never sees them at all.
    assert "route_markers_in_code" not in _user_task(counter, agents.THREAT_MODEL)


class BarrierClient(ScriptedClient):
    """A model that will not answer an opening agent until *both* opening agents have asked.

    That is the observable difference between "the two stages run concurrently" and "they run one after
    the other". Sequentially, the first agent waits on a barrier the second never reaches; the barrier
    breaks and the run fails loudly rather than passing slowly, which is what a timing assertion would
    have done -- flakily.
    """

    def __init__(self, counter: CallCounter | None = None) -> None:
        super().__init__(counter)
        self.barrier = threading.Barrier(2, timeout=10)
        #: How many model calls got *through* the barrier. Two means both opening agents were inside
        #: `complete` at the same moment; a sequential pipeline leaves this at zero or breaks the
        #: barrier, which is why the count -- not the absence of an exception -- is the assertion.
        self.waited = 0

    def complete(self, system: str, user: str) -> ChatResult:
        if _which_agent(system) in (agents.RECON, agents.THREAT_MODEL):
            self.barrier.wait()
            self.waited += 1
        return super().complete(system, user)


def test_recon_and_threat_modelling_actually_overlap(tmp_path: Path) -> None:
    """Both opening agents run at the same time -- in every pass the stage makes.

    Concurrency is not a speed tweak: the blackboard is the only channel between them, so an overlap is
    what lets one see the other's facts while both are still working. Both passes are checked, because
    the second pass is the *normal* shape of this stage: an agent can only read the peer's final answer
    after that answer was merged, and one of the two runs always ends last.
    """
    counter = CallCounter()
    client = BarrierClient(counter)
    for agent, answer in opening_answers().items():
        client.script(agent, "workspace", answer, answer)
    client.script(
        agents.PLANNER, "plan", final(scopes=[], excluded=[], rationale="nothing further")
    )
    client.stub_agent(agents.DISCOVERY, final(candidates=[], notes=[]))

    coordinator = pipeline(tmp_path, client, config=HarnessConfig(max_rounds=1))
    coordinator.attach_trail()
    result = coordinator.run()

    assert not client.barrier.broken, (
        "a broken barrier means one opening agent never reached the model while the other waited"
    )
    assert client.waited == 4, (
        "both opening agents must have been inside the model call at the same time, in both passes"
    )
    ran = {run.agent for run in result.blackboard.runs}
    assert {agents.RECON, agents.THREAT_MODEL} <= ran
    assert all(run.stop_reason == "finished" for run in result.blackboard.runs)

    events = _events(coordinator)
    opening = {agents.RECON, agents.THREAT_MODEL}

    def pass_seqs(index: int) -> tuple[list[int], list[int]]:
        """The start and end sequence numbers of one pass's opening runs, read off their ledger ids."""
        suffix = "" if index == 1 else f":p{index}"
        ids = {f"{agent}:workspace{suffix}" for agent in opening}
        starts = sorted(
            e["seq"] for e in events if e["kind"] == "agent_start" and e["run_id"] in ids
        )
        ends = sorted(
            e["seq"] for e in events if e["kind"] == "agent_end" and e["run_id"] in ids
        )
        return starts, ends

    for index in (1, 2):
        starts, ends = pass_seqs(index)
        assert len(starts) == len(ends) == 2, f"pass {index} must have run both opening agents"
        assert max(starts) < min(ends), (
            f"pass {index}'s two agents did not overlap; sequential stages interleave"
        )


def test_the_overlap_assertion_would_notice_a_sequential_opening(
    tmp_path: Path, monkeypatch
) -> None:
    """The barrier above has teeth: run the opening stages one after the other and it breaks.

    Without this, "the two stages overlap" could pass because the instrument never fired -- a barrier
    nobody waits on is not broken either. Only the opening stage is driven here; the rest of the
    pipeline is not what this is about.
    """
    def sequential(self) -> None:
        self._prepare()
        self._run_recon()
        self._run_threat_model()

    monkeypatch.setattr(HarnessCoordinator, "_recon_and_threat_model", sequential)
    client = BarrierClient()
    client.barrier = threading.Barrier(2, timeout=1)
    client.script(
        agents.RECON, "workspace",
        final(languages={}, build_systems=[], entry_points=[], components=[],
              trust_boundaries=[], notes=[]),
    )
    client.script(
        agents.THREAT_MODEL, "workspace",
        final(assets=[], actors=[], threats=[], out_of_scope=[], notes=[]),
    )

    coordinator = pipeline(tmp_path, client, config=HarnessConfig())
    with pytest.raises(threading.BrokenBarrierError):
        coordinator._recon_and_threat_model()

    assert client.waited == 0, "a sequential opening cannot get two agents through a two-party barrier"


def test_a_recorded_fact_lands_on_the_board_while_the_agent_is_still_investigating(
    tmp_path: Path,
) -> None:
    """An agent's `record` reaches the blackboard mid-run, and the final answer does not wipe it.

    Driven through the **real** tool layer: the property under test is that the tool reaches the
    coordinator's writer and that the writer's merges are additive, and a fake `invoke` would prove
    neither. The final recon payload deliberately carries `components=[]` -- the model's own answer is
    merged into the board, it does not replace what the model already recorded there.
    """
    root = workspace(tmp_path)
    component = {
        "id": "scope-svc-live",
        "name": "service layer",
        "kind": "service-layer",
        "path": "src/main/java/com/example/service",
    }
    client = ScriptedClient()
    client.script(
        agents.RECON,
        "workspace",
        turn("record", kind="component", text=json.dumps(component)),
        turn("record", kind="note", text="uses an in-memory database, there is no ORM"),
        final(
            languages={"java": 2},
            build_systems=["maven"],
            entry_points=["UserController"],
            components=[],
            trust_boundaries=[],
            notes=[],
        ),
    )
    client.script(
        agents.THREAT_MODEL,
        "workspace",
        turn("record", kind="asset", text="the users table"),
        final(assets=["the password hashes"], actors=[], threats=[], out_of_scope=[], notes=[]),
    )
    client.script(agents.PLANNER, "plan", final(scopes=[], excluded=[], rationale=""))
    client.stub_agent(agents.DISCOVERY, final(candidates=[], notes=[]))

    coordinator = HarnessCoordinator(
        workspace=root,
        config=HarnessConfig(max_rounds=1),
        client=client,
        out_dir=tmp_path / "out",
        run_id="run-records",
        # No context injected: the real tool layer, with the coordinator's own writer attached.
    )
    coordinator.attach_trail()
    result = coordinator.run()
    board = result.blackboard

    recorded = {component["id"] for component in board.architecture.components}
    assert "scope-svc-live" in recorded, "a recorded component must survive the staged answer"
    assert "the users table" in board.threats.assets, "and a recorded asset must survive"
    assert "the password hashes" in board.threats.assets, (
        "the staged answer is merged, not a replacement -- both must be there"
    )
    assert any("in-memory database" in note for note in board.project.notes), (
        "a recorded note has to be readable by the report, not only in the transcript"
    )

    events = _events(coordinator)
    records = [event for event in events if event["kind"] == "record"]
    kinds = [event["record_kind"] for event in records]
    # Two threads write here, so the order *between* the two agents is not asserted -- but within one
    # agent it is: recon records the component on its first turn and the note on its second.
    assert sorted(kinds) == ["asset", "component", "note"]
    assert kinds.index("component") < kinds.index("note")
    assert {event["agent"] for event in records} == {agents.RECON, agents.THREAT_MODEL}, (
        "two agents write concurrently; a write with no author is a write nobody can audit"
    )
    assert all(event["revision"] > 0 for event in records)

    # Each write happened *inside* the run that made it, not after it was collected.
    recon_start = next(
        event["seq"]
        for event in events
        if event["kind"] == "agent_start" and event["agent"] == agents.RECON
    )
    recon_end = next(
        event["seq"]
        for event in events
        if event["kind"] == "agent_end" and event["agent"] == agents.RECON
    )
    component_write = records[kinds.index("component")]["seq"]
    assert recon_start < component_write < recon_end


def test_every_record_kind_the_tool_offers_can_actually_be_written(tmp_path: Path) -> None:
    """All eight kinds, through the real writer. Two of them were broken and nothing said so.

    Measured on the first *real* audit: the `entry_point` branch built a `ProjectContext` without its
    required `workspace`, and the `lead` branch built a `CrossScopeLead` with a field that does not
    exist and without the `title` that is required. Every call of both kinds died inside the tool as a
    `ValidationError`; the model read "工具 record 执行失败: ..." and could do nothing with it.

    Neither the unit tests nor the stub smoke could see it: the fake tool layer never runs the writer,
    and the smoke script only used the three kinds it was scripted with. This is the test that closes
    that hole -- one call per kind, asserting each fact lands in the field the kind names.
    """
    from services.harness.tools.record import KINDS

    coordinator = pipeline(tmp_path, ScriptedClient(), config=HarnessConfig(max_rounds=1))
    board = coordinator.blackboard
    payloads = {
        "note": "uses sqlite3 directly, there is no ORM",
        "component": json.dumps({"id": "scope-a", "name": "service layer", "kind": "service-layer"}),
        "entry_point": "app.py @app.route('/search')",
        "trust_boundary": "HTTP query parameter q",
        "asset": "the items table",
        "actor": "anonymous internet user",
        "threat": json.dumps({"id": "T-1", "title": "SQLi in search", "asset": "items"}),
        "lead": json.dumps({"to_scope": "scope-b", "why": "the same query builder is reused there"}),
    }
    assert sorted(payloads) == sorted(KINDS), "a kind was added or removed: cover it here"

    for kind, text in payloads.items():
        outcome = coordinator._record({"kind": kind, "text": text, "scope": "scope-a"})
        assert outcome["recorded"] is True, f"{kind} was refused: {outcome}"
        assert "未被接受" not in (outcome.get("note") or ""), f"{kind} failed inside the writer: {outcome}"

    assert any("sqlite3" in note for note in board.project.notes)
    assert "app.py @app.route('/search')" in board.project.entry_points
    assert any(item["id"] == "scope-a" for item in board.architecture.components)
    assert "HTTP query parameter q" in board.architecture.trust_boundaries
    assert "the items table" in board.threats.assets
    assert "anonymous internet user" in board.threats.actors
    assert any(threat["id"] == "T-1" for threat in board.threats.threats)
    assert [lead.to_scope for lead in board.leads] == ["scope-b"]
    # The requirement the entry-point branch was missing: a fragment carries the run's workspace.
    assert board.project.workspace == str(coordinator.workspace)


def test_a_record_the_contract_cannot_hold_is_refused_with_a_reason(tmp_path: Path) -> None:
    """A bad payload comes back as a refusal the model can act on, not as a pydantic traceback.

    The distinction matters because the agent sees only the tool result: "lead 需要 to_scope" is one
    corrected call, while "ValidationError: 1 validation error for CrossScopeLead" is a dead end.
    """
    coordinator = pipeline(tmp_path, ScriptedClient(), config=HarnessConfig(max_rounds=1))

    prose_lead = coordinator._record({"kind": "lead", "text": "the other scope should look at this"})
    assert prose_lead["recorded"] is False
    assert "JSON" in prose_lead["reason"] and "lead" in prose_lead["reason"]

    targetless = coordinator._record(
        {"kind": "lead", "text": json.dumps({"why": "no target given"})}
    )
    assert targetless["recorded"] is False and "to_scope" in targetless["reason"]

    bad_component = coordinator._record({"kind": "component", "text": "not a json object"})
    assert bad_component["recorded"] is False and "JSON" in bad_component["reason"]

    unknown = coordinator._record({"kind": "vulnerability", "text": "SQLi here"})
    assert unknown["recorded"] is False and "unknown_kind" in unknown["reason"]

    empty = coordinator._record({"kind": "note", "text": "   "})
    assert empty["recorded"] is False and empty["reason"] == "empty_text"

    # A duplicate is still a landed write -- calling it a failure would make an agent retry it.
    first = coordinator._record({"kind": "asset", "text": "the items table"})
    second = coordinator._record({"kind": "asset", "text": "the items table"})
    assert first["recorded"] is True and second["recorded"] is True
    assert "重复" in second["note"]


def test_the_threat_model_reads_what_recon_recorded_beside_it(tmp_path: Path, monkeypatch) -> None:
    """The blackboard is a *shared* medium: the peer's mid-run write is readable while it is running.

    This is the half that the write-only version was missing. Each agent's task text is fixed when its
    run starts, so without a read the threat model could never see a component recon recorded one step
    later -- the fact would reach the planner and the report, which run afterwards, and never its peer.

    The gate makes the race deterministic: the threat model's first model call waits until recon's
    component is on the board, which is exactly the "one step behind" situation the tool exists for.
    Real tool layer, real writer, real `record` -- a fake `invoke` would prove none of it.
    """
    recorded = threading.Event()
    write = HarnessCoordinator._record

    def spying_record(self, record):
        outcome = write(self, record)
        if record.get("kind") == "component":
            recorded.set()
        return outcome

    monkeypatch.setattr(HarnessCoordinator, "_record", spying_record)

    component = {"id": "scope-svc-peer", "name": "service layer", "kind": "service-layer",
                 "path": "src/main/java/com/example/service"}

    class WaitingClient(ScriptedClient):
        def complete(self, system: str, user: str) -> ChatResult:
            if _which_agent(system) == agents.THREAT_MODEL and not recorded.is_set():
                assert recorded.wait(5), "recon's component never reached the blackboard"
            return super().complete(system, user)

    client = WaitingClient()
    client.script(
        agents.RECON, "workspace",
        turn("record", kind="component", text=json.dumps(component)),
        final(languages={"java": 2}, build_systems=["maven"], entry_points=[], components=[],
              trust_boundaries=[], notes=[]),
    )
    client.script(
        agents.THREAT_MODEL, "workspace",
        turn("board", section="components"),
        final(assets=[], actors=[], threats=[{"id": "T-1", "title": "SQLi", "asset": "users"}],
              out_of_scope=[], notes=[]),
    )
    client.script(agents.PLANNER, "plan", final(scopes=[], excluded=[], rationale=""))
    client.stub_agent(agents.DISCOVERY, final(candidates=[], notes=[]))

    coordinator = HarnessCoordinator(
        workspace=workspace(tmp_path),
        config=HarnessConfig(max_rounds=1),
        client=client,
        out_dir=tmp_path / "out",
        run_id="run-peer-read",
    )
    result = coordinator.run()

    threat_run = next(run for run in result.blackboard.runs if run.agent == agents.THREAT_MODEL)
    read_step = next(
        step for step in threat_run.steps if step.call is not None and step.call.tool is ToolName.BOARD
    )
    assert read_step.result is not None and read_step.result.ok, (
        "the board read must succeed through the real tool layer and the real view builder"
    )
    assert "scope-svc-peer" in read_step.result.summary, (
        "the peer's recorded component must be in what the threat model reads"
    )
    assert read_step.index < len(threat_run.steps), "it read the board before finishing"
    # And the final answer still went through as its own claim.
    assert "T-1" in [threat.get("id") for threat in result.blackboard.threats.threats]


def test_the_board_view_is_bounded_and_names_the_origin_of_each_component(tmp_path: Path) -> None:
    """The view is capped and says which components came from the pre-scan rather than from a model.

    Bounded because the result is spent out of the asking agent's context; labelled because an agent
    that cannot tell a directory-derived component from a verified one will treat both as facts.
    """
    coordinator = pipeline(tmp_path, ScriptedClient(), config=HarnessConfig(max_rounds=1))
    coordinator._prepare()
    for index in range(60):
        bb.set_context(
            coordinator.blackboard,
            architecture=ArchitectureMap(
                components=[{"id": f"extra-{index}", "name": f"x{index}", "kind": "other"}]
            ),
        )

    view = coordinator._board_view("components")

    assert view["count"] == len(coordinator.blackboard.architecture.components) > 40
    assert len(view["components"]) == coordinator.BOARD_COMPONENTS_LIMIT
    assert view["omitted"] == view["count"] - coordinator.BOARD_COMPONENTS_LIMIT > 0
    # Every component carries where it came from, because the map is a union of three producers and
    # "there is a directory called service" is a weaker claim than "recon read a service class".
    origins = {item["origin"] for item in view["components"]}
    assert origins == {"survey", "model"}
    assert view["components"][0]["origin"] == "survey", "the pre-scan's components come first"
    assert "origin=survey" in view["note"]

    summary = coordinator._board_view("summary")
    assert summary["counts"]["components"] == view["count"]
    assert summary["languages"], "the pre-scan's counts must be in the summary"
    assert set(summary["counts"]) >= {"components", "candidates", "confirmed", "scopes"}


def test_the_plan_reuses_the_prep_survey_instead_of_walking_the_tree_again(
    tmp_path: Path, monkeypatch
) -> None:
    """One survey per run. A second walk can disagree with the components already on the board.

    The planner used to call `discover_scopes` itself, after `_prepare` had already surveyed: two
    readings of the same tree, one in `architecture` and one in `work`, which is how a coverage table
    ends up naming scopes the plan does not have.
    """
    calls: list[Path] = []
    real = survey.discover_scopes

    def counted(root, **kwargs):
        calls.append(Path(root))
        return real(root, **kwargs)

    monkeypatch.setattr(survey, "discover_scopes", counted)
    coordinator = pipeline(
        tmp_path, _one_candidate_client(), config=HarnessConfig(max_rounds=1)
    )
    coordinator.run()

    assert len(calls) == 1, f"the tree was walked {len(calls)} times: {calls}"


def test_threat_modelling_still_runs_when_recon_produces_nothing(tmp_path: Path) -> None:
    """The pre-scan is the floor: the threat model no longer needs recon to succeed to have a map.

    The old guard skipped threat modelling whenever recon failed, because the stage would otherwise
    have had nothing to reason about. With the survey written before the model calls, a repository the
    survey could read always has a map -- and a stage that stays skipped would waste the concurrency
    it was given.
    """
    client = ScriptedClient()
    client.script(agents.RECON, "workspace", "not json", "still not json", "nope")
    client.script(
        agents.THREAT_MODEL,
        "workspace",
        final(assets=["users"], actors=[], threats=[], out_of_scope=[], notes=[]),
    )
    client.script(agents.PLANNER, "plan", final(scopes=[], excluded=[], rationale=""))
    client.stub_agent(agents.DISCOVERY, final(candidates=[], notes=[]))

    coordinator = pipeline(tmp_path, client, config=HarnessConfig(max_rounds=1))
    result = coordinator.run()

    assert any(run.agent == agents.THREAT_MODEL for run in result.blackboard.runs)
    assert result.blackboard.threats is not None
    assert "users" in result.blackboard.threats.assets
    assert not any("skipped" in note for note in coordinator.dataflow_notes), (
        "the stage ran, so nothing may report it as skipped"
    )
    assert result.blackboard.project is not None
    assert result.blackboard.project.languages, "the survey's counts survive a failed recon"
    threat_task = _user_task(client.counter, agents.THREAT_MODEL)
    assert "survey:" in threat_task, "the threat model must be told which facts it can trust"


def test_record_is_given_to_the_opening_agents_and_to_nobody_else() -> None:
    """Writes go through one tool, held by the two agents that have no other channel.

    Discovery and validation report through their own schema, which the coordinator turns into ledger
    rows with dedup and coverage semantics. Handing them a second, unstructured write path would let an
    agent put facts on the board that the closure rule cannot read -- and the opening pair is exactly
    the case that needs it, because they run at the same time and cannot see each other's transcript.
    """
    assert ToolName.RECORD in agents.AGENTS[agents.RECON].tools
    assert ToolName.RECORD in agents.AGENTS[agents.THREAT_MODEL].tools
    for spec in agents.AGENTS.values():
        if spec.name in (agents.RECON, agents.THREAT_MODEL):
            continue
        assert ToolName.RECORD not in spec.tools, f"{spec.name} must not be able to write"


def test_the_shared_medium_is_writable_and_readable_by_the_same_two_agents() -> None:
    """`record` and `board` come as a pair, and only where the concurrency argument holds.

    A writer without a reader is a log, not sharing: the peer's task text is fixed when its run starts,
    so `board` is the only way one opening agent can see what the other recorded a step ago. The later
    stages get neither: they run against a board that is already populated and they spend on code, and
    a discovery agent handed the ability to read the whole board would ration its steps against state
    instead of against the repository.
    """
    for name in (agents.RECON, agents.THREAT_MODEL):
        spec = agents.AGENTS[name]
        assert ToolName.RECORD in spec.tools and ToolName.BOARD in spec.tools, name
    for spec in agents.AGENTS.values():
        if spec.name in (agents.RECON, agents.THREAT_MODEL):
            continue
        assert ToolName.BOARD not in spec.tools, f"{spec.name} has no peer to read"


# ─────────────────────── the opening converges on what each agent has actually read


def opening_convergence_client(client: ScriptedClient | None = None) -> ScriptedClient:
    """An opening pair whose second pass is the re-read the convergence rule asks for.

    Both agents publish a final answer in pass 1, and neither can have read the other's final while
    both were still running: a run ends at its `final`, so the peer's final always lands after at least
    one of them stopped looking. That is why pass 2 exists, and why the default `max_opening_passes` is
    2 rather than 1 -- one pass can publish the pair's answers, but only a second look can consume
    them. The second-pass answer is a `board` read followed by the same payload, which is exactly what
    a converged pair produces: nothing new to publish.
    """
    client = client or ScriptedClient()
    answers = opening_answers()
    client.script(
        agents.RECON,
        "workspace",
        answers[agents.RECON],
        turn("board", section="components"),
        answers[agents.RECON],
    )
    client.script(
        agents.THREAT_MODEL,
        "workspace",
        turn("board", section="components"),
        answers[agents.THREAT_MODEL],
        answers[agents.THREAT_MODEL],  # only used if the stage wrongly re-dispatches it
    )
    client.script(agents.PLANNER, "plan", final(scopes=[], excluded=[], rationale=""))
    client.stub_agent(agents.DISCOVERY, final(candidates=[], notes=[]))
    return client


def test_the_opening_converges_and_only_the_agent_that_was_behind_is_redispatched(
    tmp_path: Path, monkeypatch
) -> None:
    """The stage stops when both have read the peer's material, and re-runs only the one who has not.

    Real tool layer, because the whole rule is built on what a real `board` call reports: the watermark
    is the board revision the tool served, read back out of the ledger. A fake `invoke` returns no
    revision, so a test against the fake layer would prove the loop runs and nothing about whether it
    can ever converge.

    The gate makes the redispatched set exact rather than a race: the threat model's first model call
    waits until recon's final answer has been merged, so it ends pass 1 up to date while recon has read
    nothing at all.
    """
    gate = threading.Event()
    publish = HarnessCoordinator._publish

    def gated_publish(self, by, kinds, label):
        publish(self, by, kinds, label)
        if by == agents.RECON:
            gate.set()

    monkeypatch.setattr(HarnessCoordinator, "_publish", gated_publish)

    class WaitingClient(ScriptedClient):
        def complete(self, system: str, user: str) -> ChatResult:
            if _which_agent(system) == agents.THREAT_MODEL and not gate.is_set():
                assert gate.wait(5), "recon's final answer never reached the blackboard"
            return super().complete(system, user)

    client = opening_convergence_client(WaitingClient())
    coordinator = HarnessCoordinator(
        workspace=workspace(tmp_path),
        config=HarnessConfig(max_rounds=1, max_opening_passes=2),
        client=client,
        out_dir=tmp_path / "out",
        run_id="run-opened",
    )
    result = coordinator.run()

    opening = result.blackboard.opening
    assert opening is not None
    assert opening.converged is True, opening.note
    assert opening.unread == {}, "nothing may be left unread when the stage says it converged"
    assert opening.passes == 2

    ran = [
        (run.agent, run.run_id)
        for run in result.blackboard.runs
        if run.agent in (agents.RECON, agents.THREAT_MODEL)
    ]
    assert ran == [
        (agents.RECON, "recon:workspace"),
        (agents.THREAT_MODEL, "threat_model:workspace"),
        (agents.RECON, "recon:workspace:p2"),
    ], "only recon was behind after pass 1, so only recon is re-dispatched"


def test_a_pass_that_adds_nothing_new_ends_the_opening(tmp_path: Path) -> None:
    """The loop stops when a pass produces nothing substantive -- and it does not need a `board` call.

    The first version required each agent to *read* the peer's material through the tool, which measured
    willingness to call a tool rather than what the agent had been given: a model that ignored `board`
    stayed "behind" forever, so the stage always ran to its cap and reported "未收敛" on runs where
    nothing was wrong. Delivery is what the coordinator owns -- the re-dispatch task text *is* the delta
    -- so an agent counts as up to date once it has been handed the material or has read that far
    itself. Here neither agent ever calls `board` and the pair still converges: pass 2 re-states the same
    answers, publishes nothing new, and the stage stops at 2 passes out of a cap of 3.
    """
    client = ScriptedClient()
    for agent, answer in opening_answers().items():
        client.script(agent, "workspace", answer, answer)
    client.script(agents.PLANNER, "plan", final(scopes=[], excluded=[], rationale=""))
    client.stub_agent(agents.DISCOVERY, final(candidates=[], notes=[]))

    coordinator = HarnessCoordinator(
        workspace=workspace(tmp_path),
        config=HarnessConfig(max_rounds=1),
        client=client,
        out_dir=tmp_path / "out",
        run_id="run-converged",
    )
    result = coordinator.run()

    opening = result.blackboard.opening
    assert opening is not None
    assert opening.converged is True, opening.note
    assert opening.passes == 2, "the cap is 3; converging on 2 is the point"
    assert opening.unread == {}
    assert not [run for run in result.blackboard.runs if run.run_id.endswith(":p3")]

    # Counted too, so the screen and the report can show it without parsing prose.
    assert coordinator.trail.counters(result.blackboard)["opening_unread"] == 0


def test_an_opening_that_keeps_producing_new_material_hits_the_cap_and_says_so(
    tmp_path: Path,
) -> None:
    """Hitting the pass cap is a recorded gap, not a silent "done".

    Measured on the demo: recon's second pass recorded four trust boundaries (`request.args` reaching a
    concatenated query, `repo.connect` opening a cwd-relative `app.db`) that the threat model had not
    seen when the cap stopped the stage. A stage that could not tell that apart from a converged pair
    would report the same thing for both -- and the threat model would look like it had been written
    against recon's architecture map when it had not.
    """
    client = ScriptedClient()
    for pass_index in (1, 2):
        # Each pass publishes something *new*, which is what keeps the peer behind: an opening that never
        # runs out of things to say is exactly the case a cap exists for.
        client.script(
            agents.RECON,
            "workspace",
            final(
                languages={"java": 2},
                build_systems=["maven"],
                entry_points=[],
                components=[{"id": f"scope-new-{pass_index}", "name": f"area {pass_index}"}],
                trust_boundaries=[f"boundary {pass_index}"],
                notes=[],
            ),
        )
        client.script(
            agents.THREAT_MODEL,
            "workspace",
            final(
                assets=[],
                actors=[],
                threats=[{"id": f"T-{pass_index}", "title": f"threat {pass_index}", "asset": "x"}],
                out_of_scope=[],
                notes=[],
            ),
        )
    client.script(agents.PLANNER, "plan", final(scopes=[], excluded=[], rationale=""))
    client.stub_agent(agents.DISCOVERY, final(candidates=[], notes=[]))

    coordinator = HarnessCoordinator(
        workspace=workspace(tmp_path),
        config=HarnessConfig(max_rounds=1, max_opening_passes=2),
        client=client,
        out_dir=tmp_path / "out",
        run_id="run-unconverged",
    )
    result = coordinator.run()

    opening = result.blackboard.opening
    assert opening is not None
    assert opening.converged is False
    assert opening.passes == 2, "the cap is what stopped it"
    assert opening.unread, "the report has to be able to name what was never read"
    assert "未收敛" in opening.note and "上限" in opening.note
    assert coordinator.trail.counters(result.blackboard)["opening_unread"] > 0


def test_one_opening_pass_is_available_for_a_run_that_wants_it_cheap(tmp_path: Path) -> None:
    """The cap is a knob, and `1` means what it says: publish once, do not pair up afterwards."""
    client = ScriptedClient()
    for agent, answer in opening_answers().items():
        client.script(agent, "workspace", answer, answer)
    client.script(agents.PLANNER, "plan", final(scopes=[], excluded=[], rationale=""))
    client.stub_agent(agents.DISCOVERY, final(candidates=[], notes=[]))

    coordinator = HarnessCoordinator(
        workspace=workspace(tmp_path),
        config=HarnessConfig(max_rounds=1, max_opening_passes=1),
        client=client,
        out_dir=tmp_path / "out",
        run_id="run-one-pass",
    )
    result = coordinator.run()

    opening = result.blackboard.opening
    assert opening is not None and opening.passes == 1
    assert opening.converged is False, (
        "one pass cannot converge: an agent's final is published after its peer stopped looking"
    )
    assert not [run for run in result.blackboard.runs if run.run_id.endswith(":p2")]


def test_only_substantive_writes_make_the_peer_stale(tmp_path: Path) -> None:
    """What makes the other opening agent stale is what could change its reading of the code.

    Two sides, and the second one is the one a real run taught:

    * **In**: components, trust boundaries, entry points and threats. A new component or a new entry
      point can change what the peer concludes, so the peer is re-dispatched to look.
    * **Out**: notes, leads, assets and actors. Notes and leads are commentary. Assets and actors are
      *descriptions of the same few things*, so two agents writing them always produce more of them --
      measured on the demo, pass 2 published an asset, an actor, a note and a lead, all rephrasings, and
      the stage reported "未收敛" as if there were work waiting when nothing unread could have changed
      either answer. Those four are not dropped (the planner and the report read the final board); they
      just no longer buy another agent run.

    An agent is also never stale on its own writes: the point is to read the other one.
    """
    coordinator = pipeline(tmp_path, ScriptedClient(), config=HarnessConfig(max_rounds=1))
    seed = coordinator.blackboard.revision
    watermarks = {agents.RECON: seed, agents.THREAT_MODEL: seed}
    coordinator._current.agent = agents.THREAT_MODEL  # as if the threat model were writing

    for kind, text in (("note", "uses sqlite3 directly"), ("asset", "the users table"),
                       ("actor", "anonymous internet user")):
        coordinator._record({"kind": kind, "text": text, "scope": "workspace"})
    coordinator._record({
        "kind": "lead",
        "text": json.dumps({"to_scope": "scope-root", "why": "dead sqlite3 import lives there"}),
        "scope": "workspace",
    })
    assert coordinator._opening_backlog(watermarks)[agents.RECON] == [], (
        "commentary and descriptions must not make the peer stale"
    )

    for kind, text, expected in (
        ("component", json.dumps({"id": "scope-a", "name": "svc"}), ["components"]),
        ("trust_boundary", "HTTP query parameter q", ["trust_boundaries"]),
        ("entry_point", "GET /search (handler.py:6)", ["entry_points"]),
        (
            "threat",
            json.dumps({"id": "T-1", "title": "SQLi", "asset": "users"}),
            ["threats"],
        ),
    ):
        before = len(coordinator._opening_backlog(watermarks)[agents.RECON])
        coordinator._record({"kind": kind, "text": text, "scope": "workspace"})
        backlog = coordinator._opening_backlog(watermarks)[agents.RECON]
        assert len(backlog) == before + 1, f"{kind} must make the peer stale"
        assert backlog[-1]["kinds"] == expected

    assert coordinator._opening_backlog(watermarks)[agents.THREAT_MODEL] == [], (
        "an agent is never stale on its own writes"
    )

    # A duplicate publishes nothing, so a repeated fact cannot keep the loop alive either.
    coordinator._record({"kind": "entry_point", "text": "GET /search (handler.py:6)", "scope": "workspace"})
    assert len(coordinator._opening_backlog(watermarks)[agents.RECON]) == 4


def test_the_read_watermark_comes_from_the_tool_call_not_from_the_model() -> None:
    """The watermark is a ledger fact: the revision a real `board` call served, or nothing.

    Same rule as the coverage table, which counts real `read` calls rather than a model's claim to have
    looked. A run that says it read the board without calling the tool has a watermark of None, and the
    opening stage treats it as behind -- which is what "confirmation has to be evidence" means here.
    """
    from services.harness.coordinator import _board_revision_seen

    run = AgentRun(run_id="recon:workspace", agent=agents.RECON, scope_id="workspace")
    assert _board_revision_seen(run) is None

    run.steps.append(
        AgentStep(
            index=1,
            thought="读黑板",
            call=ToolCall(tool=ToolName.BOARD, arguments={"section": "components"}),
            result=ToolResult(
                tool=ToolName.BOARD,
                ok=True,
                summary="{}",
                data={"section": "components", "revision": 7},
            ),
        )
    )
    assert _board_revision_seen(run) == 7

    run.steps.append(
        AgentStep(
            index=2,
            thought="又一次",
            call=ToolCall(tool=ToolName.BOARD, arguments={"section": "threats"}),
            result=ToolResult(
                tool=ToolName.BOARD,
                ok=True,
                summary="{}",
                data={"section": "threats", "revision": 5},
            ),
        )
    )
    assert _board_revision_seen(run) == 7, "the highest revision read is the watermark"

    run.steps.append(
        AgentStep(
            index=3,
            thought="读失败",
            call=ToolCall(tool=ToolName.BOARD, arguments={"section": "components"}),
            result=ToolResult(
                tool=ToolName.BOARD,
                ok=False,
                summary="拒绝",
                error="board_reader_absent",
                data={},
            ),
        )
    )
    assert _board_revision_seen(run) == 7, "a refused read served nothing and must not count"


# ─────────────────────── one area, many places: nothing may be lost at one id


def test_five_routes_at_one_area_id_all_survive(tmp_path: Path) -> None:
    """An area id covers N places, and N grows over time. The old merge kept the first and dropped the rest.

    This is the failure that reasoning found before any run did: `scope-web-route` is an *area* (one per
    directory or module), while `GET /search (handler.py:6)` is a *place*. Merging the second by id
    copied its fields into the row the first had already filled, so with equal evidence ranks nothing
    moved and the site vanished -- silently, since a landed-but-empty merge still reported success. On
    the first real audit three of recon's six components went that way, and one of them was the row for
    `orders.py`, the file the demo's only real vulnerability lives in.

    The rule now: a place never overwrites an area's own fields, it accumulates in `sites`, keyed by its
    own identity. Five routes at one id are five sites, and a re-recorded one is still one site.
    """
    root = tmp_path / "repo"
    root.mkdir()
    for name in ("handler.py", "orders.py", "admin.py", "report.py", "health.py"):
        (root / name).write_text("def route():\n    return 1\n", encoding="utf-8")

    board = bb.new_blackboard("run-1", root)
    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[
                {
                    "id": "scope-web-route",
                    "name": "web-route（.）",
                    "kind": "web-route",
                    "path": ".",
                    "origin": "survey",
                }
            ]
        ),
    )

    for name, route in (
        ("handler.py", "GET /search"),
        ("orders.py", "GET /orders"),
        ("admin.py", "POST /admin"),
        ("report.py", "GET /report"),
        ("health.py", "GET /health"),
    ):
        bb.set_context(
            board,
            architecture=ArchitectureMap(
                components=[
                    {"id": "scope-web-route", "name": f"{name} handler", "path": name, "route": route}
                ]
            ),
        )

    assert len(board.architecture.components) == 1, "one row per area id, however many places it has"
    component = board.architecture.components[0]
    assert component["path"] == ".", "a place must not overwrite the area's path"
    assert component["name"] == "web-route（.）", "nor the area's name"
    sites = component["sites"]
    assert [site["path"] for site in sites] == [
        "handler.py", "orders.py", "admin.py", "report.py", "health.py",
    ]
    assert [site["route"] for site in sites] == [
        "GET /search", "GET /orders", "POST /admin", "GET /report", "GET /health",
    ]

    # Re-recording one of them (a second pass, a peer repeating it) is the same place, not a sixth.
    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[{"id": "scope-web-route", "path": "orders.py", "route": "GET /orders"}]
        ),
    )
    assert len(component["sites"]) == 5


def test_places_at_one_id_are_kept_even_when_no_area_row_came_first(tmp_path: Path) -> None:
    """A row created from a place lists *all* its places, itself included.

    Otherwise a reader would have to add the row and `len(sites)` to know how many places an id covers,
    and the arithmetic would be wrong for exactly the rows that never saw the pre-scan.
    """
    root = tmp_path / "repo"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    (root / "b.py").write_text("y = 2\n", encoding="utf-8")

    board = bb.new_blackboard("run-1", root)
    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[{"id": "mod", "name": "a", "path": "a.py", "route": "GET /a"}]
        ),
    )
    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[{"id": "mod", "name": "b", "path": "b.py", "route": "GET /b"}]
        ),
    )

    component = board.architecture.components[0]
    assert [site["route"] for site in component["sites"]] == ["GET /a", "GET /b"]


def test_an_area_updated_by_an_area_is_still_an_evidence_upgrade(tmp_path: Path) -> None:
    """The place/area split must not cost the upgrade it was introduced for.

    Two area rows for one id are the same claim at two strengths, and the agent's reading still wins --
    that is what the pre-scan must not shadow. Only a *place* is accumulated rather than merged.
    """
    root = tmp_path / "repo"
    root.mkdir()
    (root / "service").mkdir()

    board = bb.new_blackboard("run-1", root)
    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[
                {
                    "id": "scope-service-layer",
                    "name": "service-layer（.）",
                    "kind": "service-layer",
                    "path": ".",
                    "origin": "survey",
                }
            ]
        ),
    )
    bb.set_context(
        board,
        architecture=ArchitectureMap(
            components=[
                {
                    "id": "scope-service-layer",
                    "name": "orders domain service",
                    "kind": "service-layer",
                    "path": "service",
                    "description": "reads and writes orders",
                }
            ]
        ),
    )

    component = board.architecture.components[0]
    assert component["name"] == "orders domain service"
    assert component["path"] == "service"
    assert component["description"] == "reads and writes orders"
    assert component["origin"] == "model"
    assert "sites" not in component, "both sides are areas: nothing to accumulate"


def test_the_board_has_a_section_for_each_granularity(tmp_path: Path) -> None:
    """`components` is areas, `entry_points` is places, and a peer can read both.

    The sections are how an agent decides what to record: it is told the vocabulary, and the board shows
    it the two lists separately, so a repository with twenty endpoints does not turn into twenty
    components that the planner then plans one by one.
    """
    root = tmp_path / "repo"
    root.mkdir()
    (root / "handler.py").write_text("def route():\n    return 1\n", encoding="utf-8")
    coordinator = pipeline(tmp_path, ScriptedClient(), config=HarnessConfig(max_rounds=1))
    coordinator._prepare()
    bb.set_context(
        coordinator.blackboard,
        project=ProjectContext(
            workspace=str(root), entry_points=["GET /search (handler.py:6)"]
        ),
        architecture=ArchitectureMap(
            components=[
                {"id": "scope-web-route", "name": "web-route（.）", "kind": "web-route", "path": "."},
                {
                    "id": "scope-web-route-2",
                    "name": "handler",
                    "path": "handler.py",
                    "route": "GET /search",
                    "line": 6,
                },
            ]
        ),
    )

    components = coordinator._board_view("components")
    areas = {item["id"]: item for item in components["components"]}
    assert areas["scope-web-route-2"]["sites"] is None or areas["scope-web-route-2"]["sites"] == []
    assert "section=entry_points" in components["note"]

    points = coordinator._board_view("entry_points")
    assert "GET /search (handler.py:6)" in points["entry_points"]
    assert points["routes_from_components"] == [
        {"component": "scope-web-route-2", "route": "GET /search", "path": "handler.py", "line": 6}
    ]
    # The count is the two lists together, and the pre-scan's own entry points (the fixture's
    # `@GetMapping`) are in there too -- the deterministic pass already contributes to this list.
    assert points["count"] == len(points["entry_points"]) + len(points["routes_from_components"]) >= 2


def test_entry_points_dedupe_on_the_place_not_on_the_sentence(tmp_path: Path) -> None:
    """Four endpoints described three ways each are four endpoints, not twelve.

    Measured on the demo project, on a real run: the two opening agents each recorded the same four
    entry points -- once through `record`, once in the final answer, once rephrased -- and the list came
    out with twelve strings, because dedup was on the whole text and the prose differed every time. The
    place is the identity (that is what "which requests can reach this code" is asked about); the
    sentence after it is a description, and two agents never write the same one.
    """
    board = bb.new_blackboard("run-1", tmp_path)
    bb.set_context(
        board,
        project=ProjectContext(
            workspace="w",
            entry_points=[
                "order_report(request) (orders.py:15) — request.args['order_id'] 未转义",
                "order_report(request) - order lookup entry point, passes request.args['order_id'] "
                "(orders.py:15)",
                "order_report(request) — order lookup, concatenates into SQL (orders.py:15)",
                "GET /health (app.py:3)",
            ],
        ),
    )
    bb.set_context(
        board,
        project=ProjectContext(
            workspace="",
            entry_points=[
                "order_report(request) (orders.py:15) — yet another phrasing",
                "no location here at all",
                "NO LOCATION HERE AT ALL",
            ],
        ),
    )

    points = board.project.entry_points
    # Three places: `orders.py:15` (three phrasings), `app.py:3`, and the one with no location at all --
    # and the two case variants of that last one are one entry too.
    assert len(points) == 3, points
    assert sum(1 for point in points if "orders.py:15" in point) == 1
    assert "GET /health (app.py:3)" in points
    assert sum(1 for point in points if point.lower().startswith("no location")) == 1
    assert points[0].endswith("未转义"), "the first description of a place is the one kept"


def test_the_loop_tells_an_agent_when_its_turns_are_running_out() -> None:
    """A bounded loop has to say the bound out loud, because the model cannot infer it.

    Measured on the demo, on a real run: the threat model -- newly equipped with `record` -- spent all
    eight turns writing facts (nineteen `record` calls, most of them no-ops against facts already on the
    board) and stopped on `budget` with **no final answer at all**, so the stage produced no threat
    model. Turn count is a harness quantity: a turn can hold up to `MAX_CALLS_PER_TURN` tool calls, so an
    agent one turn from the end can believe it is halfway through.
    """
    from services.harness.react import WRAP_UP_TURNS, render_user_message, wrap_up_note

    assert wrap_up_note(1, 8) == "", "no nagging while there is room to work"
    assert wrap_up_note(8 - WRAP_UP_TURNS, 8) == "", "the warning starts two turns before the end"
    assert "1 turn(s) left out of 8" in wrap_up_note(7, 8)
    last = wrap_up_note(8, 8)
    assert "this is the LAST turn" in last
    assert "final" in last and "notes" in last
    assert "BUDGET" in last

    # A budget too small to wrap up in still gets no note: telling a model to stop before it can start
    # would turn a short run into an empty one.
    assert wrap_up_note(1, 2) == "" and wrap_up_note(2, 2) == ""

    rendered = render_user_message("do the thing", [], note=wrap_up_note(8, 8))
    assert "BUDGET" in rendered and "do the thing" in rendered


# ─────────────────────── what the model wrote, the harness has to be able to read


def test_a_bare_schema_payload_is_accepted_as_the_final_answer() -> None:
    """The answer without its envelope is still the answer.

    Measured on a real demo run: recon replied with the schema'd object itself -- `languages`,
    `build_systems`, `entry_points`, `components`, ... -- and no `{"final": ...}` around it, which the
    strict parse rejected as "missing `tool`, `calls` or `final`". One turn lost to a missing wrapper.
    The guard is what keeps this from accepting arbitrary objects: it must carry the agent's own
    required keys and none of the turn keys.
    """
    from services.harness.react import _parse_turn

    payload = {
        "languages": {"py": 5},
        "build_systems": [],
        "entry_points": ["handle_request(request) (handler.py:9)"],
        "components": [{"id": "scope-web-route", "name": "routes"}],
        "trust_boundaries": ["request.args"],
        "notes": [],
    }
    parsed, error, salvage = _parse_turn(json.dumps(payload), output_schema=agents.RECON_SCHEMA)
    assert error is None and salvage == ""
    assert parsed is not None and parsed["final"] == payload

    # An object that is not the agent's output is still refused, with the message that explains the
    # protocol -- accepting it would put a malformed `final` into the stage.
    stray, error, _ = _parse_turn('{"note": "thinking out loud"}', output_schema=agents.RECON_SCHEMA)
    assert stray is None and "final" in error

    # And with no schema to check against, nothing is guessed.
    assert _parse_turn(json.dumps(payload))[0] is None


def test_a_truncated_batch_of_calls_is_salvaged_instead_of_lost() -> None:
    """A cut-off answer used to execute none of its calls. The complete ones before the cut still run.

    This is the failure that cost the most on the demo: eight long `record` calls in one answer, cut off
    at the output limit, strict parse fails, **zero** calls execute, and every fact the agent had just
    verified is gone from the board. The calls before the truncation point are individually complete and
    the loop validates each one anyway, so recovering them is strictly better than dropping them.
    """
    from services.harness.react import _parse_turn

    answer = (
        '{"thought": "recording what I verified", "calls": ['
        '{"tool": "record", "arguments": {"kind": "note", "text": "first"}},'
        '{"tool": "record", "arguments": {"kind": "note", "text": "second"}},'
        '{"tool": "record", "arguments": {"kind": "note", "text": "cut off here'
    )
    parsed, error, salvage = _parse_turn(answer)
    assert error is None
    assert parsed is not None and len(parsed["calls"]) == 2
    assert [call["arguments"]["text"] for call in parsed["calls"]] == ["first", "second"]
    assert "截断" in salvage and "2" in salvage
    assert "text" in salvage, "the feedback has to say what to do differently"

    # Braces inside strings must not be mistaken for structure.
    nested = (
        '{"calls": [{"tool": "record", "arguments": {"kind": "note", "text": "a } brace {"}},'
        '{"tool": "record", "arguments": {"kind": "note", "text": "unfinished'
    )
    parsed, _, _ = _parse_turn(nested)
    assert parsed is not None and len(parsed["calls"]) == 1

    # Nothing complete to salvage: still the honest refusal.
    assert _parse_turn('{"calls": [{"tool": "record", "argum')[0] is None
    assert _parse_turn("I have read every source file; now I will summarise.")[0] is None


def test_the_provider_s_own_truncation_word_reaches_the_model() -> None:
    """The loop has to name the real cause: "Expecting ',' delimiter" tells a model nothing.

    The provider already said *why* generation stopped; the harness was throwing that away and reporting
    a JSON syntax error instead, so a model whose answer was cut off had no way to know that writing less
    is the fix.
    """
    from services.ai.client import ChatResult, finish_reason, truncated

    def result(body: dict) -> ChatResult:
        return ChatResult(text="", model="m", raw=body)

    assert truncated(result({"choices": [{"finish_reason": "length"}]})) is True
    assert truncated(result({"choices": [{"finish_reason": "stop"}]})) is False
    # Anthropic-shaped and gateway-shaped bodies are both recognised; an unknown word never is.
    assert truncated(result({"stop_reason": "max_tokens"})) is True
    assert truncated(result({"choices": [{"stop_reason": "max_output_tokens"}]})) is True
    assert truncated(result({})) is False
    assert finish_reason(result({"choices": [{"finish_reason": "length"}]})) == "length"
