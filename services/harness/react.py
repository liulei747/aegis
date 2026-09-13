"""The constrained ReAct loop one agent runs inside.

ReAct ("think, act, observe") is a good fit for a security review because the transcript is the
audit trail -- but an unconstrained loop is not something to point at an attacker-controlled
repository. Four constraints make it usable, and each of them is a decision rather than a
formality:

* **The tool allow-list is closed.** The tools passed in are the only ones callable; a call to
  anything else comes back to the model as a failed `ToolResult` instead of raising or being
  quietly dropped. The model gets to correct itself, and the transcript records that it tried.
* **A malformed answer is recorded, not raised.** This mirrors ``services/ai/parse.py``: the model
  is given the exact parse error and a bounded number of attempts to fix it, and the run stops
  with ``stop_reason="error"`` when it cannot. Silence here would be the worst outcome -- the
  stage would look like it ran and simply found nothing.
* **`max_steps` is a hard budget, not a target.** Hitting it keeps everything produced so far and
  sets ``stop_reason="budget"``, because the report must be able to say "this stopped early"
  rather than present a partial answer as a complete one.
* **Every turn is recorded.** ``AgentRun.steps`` carries the thought, the call and the result, so
  the report's reasoning trail is built from what actually happened rather than from a summary the
  model wrote about itself.

The client is injected for the same reason it is injectable in ``services/ai/client.py``: the
tests drive this with a scripted fake and no network, which is the only way to exercise a budget
stop and a parse failure deterministically.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from datetime import datetime, timezone
from functools import lru_cache
from typing import Any, Protocol

from aegis_contracts.harness import (
    AgentRun,
    AgentStep,
    DataflowEvidence,
    ToolCall,
    ToolName,
    ToolResult,
)
from aegis_core.logging import get_logger
from services.ai.client import AIError, AIUnavailable, truncated
from services.ai.parse import extract_json_object

log = get_logger(__name__)

#: Consecutive unparseable answers tolerated before the run stops with `error`. Three rather than
#: one because a model that wraps its JSON in prose or forgets a brace is worth correcting; more
#: than three because past that the failure is systematic, and repeating it only burns budget.
MAX_PARSE_ATTEMPTS = 3

#: How many tool calls one turn may carry. A turn is a round trip and the whole transcript is
#: re-sent on the next one, so batching is the difference between reading a six-file group in one
#: turn and in six -- measured at roughly 25 s per call on the Java benchmark, which is what made a
#: round take 35 minutes. The cap exists so a single turn cannot run away; eight is more than any
#: agent has needed and small enough to read.
MAX_CALLS_PER_TURN = 8

#: How many times a *retryable* client failure (unreachable, 5xx, 429) is attempted per step.
#: Deliberately small: the step budget is the real bound, and a retry here multiplies wall clock.
MAX_CLIENT_ATTEMPTS = 4

#: What the tool package must provide. Named in the error below so a missing layer is a one-line
#: fix rather than an archaeology exercise -- an ImportError from six frames down tells the reader
#: neither what is missing nor what it should have exported.
TOOL_LAYER_SURFACE = "TOOLS, ToolContext, ToolLimits, invoke, schemas"

class ToolLayerUnavailable(RuntimeError):
    """`services/harness/tools` is absent or does not export the frozen surface.

    Raised only when a stage genuinely needs a tool. Planning, coverage closure, `--dry-run` and
    report rendering all run without the tool layer, deliberately: the plumbing has to be
    exercisable while the tool layer is being written, and a dry run that needed it could not be
    used to check the plumbing at all.
    """


class ScriptedClient(Protocol):
    """What this loop needs from a client. `ChatClient` satisfies it; so does a test fake."""

    model: str

    def complete(self, system: str, user: str):  # -> ChatResult
        ...


def _now() -> datetime:
    return datetime.now(timezone.utc)


@lru_cache(maxsize=1)
def tool_layer():
    """The frozen tool surface, imported on first use rather than at module import.

    Two reasons. The import pulls in the tool implementations (and whatever they need on the
    machine) -- a dry run, a coverage pass or `--help` must not require them. And a test that
    injects a fake tool layer into ``sys.modules`` gets it picked up deterministically instead of
    depending on import order.

    Returns `(TOOLS, ToolContext, ToolLimits, invoke, schemas)`. Callers that want a fresh import
    (a test with a scripted fake) call `clear_tool_layer_cache()` first.
    """
    try:
        from services.harness.tools import TOOLS, ToolContext, ToolLimits, invoke, schemas
    except ImportError as exc:
        raise ToolLayerUnavailable(
            "工具层不可用：缺少 services.harness.tools。"
            f"该包必须导出 {TOOL_LAYER_SURFACE}；模型驱动的运行需要它，"
            "--dry-run 与覆盖率收敛不需要。"
            f"（原始错误：{exc}）"
        ) from exc

    return TOOLS, ToolContext, ToolLimits, invoke, schemas


def clear_tool_layer_cache() -> None:
    """Forget the imported tool layer. Used by tests that swap it for a scripted fake."""
    tool_layer.cache_clear()


def tool_schemas(tools: list[ToolName] | None = None) -> list[dict]:
    """The JSON schemas to show the model, narrowed to the tools this agent may call."""
    try:
        _, _, _, _, schemas = tool_layer()
    except ToolLayerUnavailable as exc:
        log.warning("react: prompting without tool schemas (%s)", exc)
        return []
    try:
        available = schemas()
    except Exception as exc:  # pragma: no cover - a broken tool layer is not worth a crash here
        log.warning("react: schemas() failed (%s)", exc)
        return []
    if not tools:
        return list(available)
    allowed = {_name(tool) for tool in tools}
    return [
        schema
        for schema in available
        if _name(schema.get("name") or (schema.get("function") or {}).get("name")) in allowed
    ]


def _name(value: Any) -> str:
    if hasattr(value, "value"):
        value = value.value
    return str(value or "").strip()


def _result_for_unknown_tool(tool: str, allowed: list[str]) -> ToolResult:
    """A refusal the model can read and act on. Never an exception.

    The `ToolName` enum is one of the four known tools, so a call to anything else cannot even be
    represented as a `ToolCall`; the honest representation is a failed result with `tool=None`
    naming what *is* allowed, which is what the next turn's transcript shows.
    """
    return ToolResult(
        tool=None,
        ok=False,
        summary="",
        error=(
            f"tool {tool!r} is not available to this agent; "
            f"callable tools are: {', '.join(allowed) or 'none'}"
        ),
    )


def _invoke(context, call: ToolCall) -> ToolResult:
    """Dispatch through the frozen `invoke`, turning any escape into a failed result.

    `invoke` is documented never to raise. This does not rely on that: a tool layer is new code
    and the loop's contract with the *model* is that a bad call is an observation, so the failure
    is converted here rather than allowed to abort the run.
    Raises `ToolLayerUnavailable` when the tool package itself is missing: that is a broken
    installation rather than a bad model call, and turning it into a failed observation would
    hide it behind an agent that "tried a tool and it did not work".
    """
    _, _, _, invoke, _ = tool_layer()
    try:
        return invoke(context, call)
    except Exception as exc:  # pragma: no cover - a well-behaved invoke does not raise
        log.warning("react: invoke(%s) raised %s: %s", call.tool, type(exc).__name__, exc)
        return ToolResult(
            tool=call.tool,
            ok=False,
            error=f"{type(exc).__name__}: {exc}",
        )


# ─────────────────────────────────────────────────────────── prompt rendering


REACT_CONTRACT = """\
You work in bounded turns. On every turn answer with ONE JSON object and nothing else.

To call one tool:
{"thought": "<why this call>", "tool": "<one of the callable tools>", "arguments": {...}}

To call several tools in the same turn -- prefer this whenever the calls do not depend on each
other, because a turn is a round trip and reading six files one per turn costs six of them:
{"thought": "<why>", "calls": [{"tool": "read", "arguments": {...}}, {"tool": "read", "arguments": {...}}]}

To finish:
{"thought": "<why you are done>", "final": {...}}

Rules:
* Use only the callable tools listed below. Any other name is refused and wastes a turn.
* `arguments` must match the tool's schema; every call needs a reason in `thought`.
* At most 8 calls per turn. Independent reads and searches belong in one turn; a call whose
  arguments depend on an earlier result does not.
* The `final` object must match the output schema below. No prose around the JSON, no code fence
  required, but a fence is tolerated.
"""


def render_system_prompt(
    *,
    system_prompt: str,
    tools: list[ToolName],
    output_schema: dict | None,
    extra: str = "",
) -> str:
    """The full system message: the agent's own prompt, the contract, the tools, the schema."""
    parts = [system_prompt.strip(), REACT_CONTRACT.strip()]
    if extra.strip():
        parts.append(extra.strip())
    schemas = tool_schemas(tools)
    if schemas:
        parts.append(
            "Callable tools (JSON schemas):\n" + json.dumps(schemas, ensure_ascii=False, indent=2)
        )
    elif tools:
        parts.append("Callable tools: " + ", ".join(_name(tool) for tool in tools))
    else:
        parts.append("No tools are callable in this task; answer with `final` directly.")
    if output_schema is not None:
        parts.append(
            "Output schema for `final`:\n" + json.dumps(output_schema, ensure_ascii=False, indent=2)
        )
    return "\n\n".join(part for part in parts if part)


def _render_step(step: AgentStep) -> str:
    """One recorded step as the model sees it again on the next turn."""
    lines = [f"Turn {step.index} thought: {step.thought or '(none)'}"]
    if step.call is not None:
        lines.append(
            f"Turn {step.index} call: {_name(step.call.tool)} "
            f"{json.dumps(step.call.arguments, ensure_ascii=False)}"
        )
    if step.result is not None:
        if step.result.ok:
            summary = step.result.summary or json.dumps(step.result.data, ensure_ascii=False)[:2000]
            lines.append(f"Turn {step.index} observation: {summary}")
            if step.result.truncated:
                lines.append(f"Turn {step.index} observation was truncated.")
        else:
            lines.append(f"Turn {step.index} observation (FAILED): {step.result.error or ''}")
    return "\n".join(lines)


def render_user_message(task: str, steps: list[AgentStep], *, note: str = "") -> str:
    """The user turn: the task, then everything that has happened so far.

    The whole transcript is re-sent rather than relying on server-side conversation state: the
    client is a single stateless round trip by design, and re-rendering means the loop cannot
    drift from what ``AgentRun.steps`` records.
    """
    parts = [f"TASK\n{task.strip()}"]
    if note:
        parts.append(note.strip())
    if steps:
        parts.append("TRANSCRIPT SO FAR\n" + "\n".join(_render_step(step) for step in steps))
    parts.append("Answer with one JSON object, as instructed.")
    return "\n\n".join(parts)


#: How many turns before the end the loop starts telling the model to wrap up. Two, because one is not
#: enough to write a schema'd answer after a tool call, and three would nag a run that is doing fine.
WRAP_UP_TURNS = 2

#: The nudge itself. A budget is not advice the model can infer: it counts its own tool calls, not the
#: harness's turns, and a turn may hold up to `MAX_CALLS_PER_TURN` of them -- so an agent can be one
#: turn from the end while believing it is halfway. Measured on the demo: the threat model, newly
#: equipped with `record`, spent all eight of its turns recording facts (nineteen `record` calls, most
#: of them no-ops against facts already on the board) and stopped on `budget` with no `final` at all --
#: so the stage produced no threat model, which is strictly worse than the smaller tool surface it had
#: before. Every framework that runs a bounded ReAct loop carries a reminder like this for that reason.
WRAP_UP_NOTE = (
    "BUDGET: {when}. Stop investigating now and answer with your `final` object. Anything you have not "
    "confirmed belongs in `notes`, not in another tool call -- a run that spends its last turns on tools "
    "produces NO answer, and this stage's answer is what the pipeline uses."
)


def wrap_up_note(index: int, max_steps: int) -> str:
    """The wrap-up reminder for turn `index`, or an empty string while there is room to work."""
    left = max_steps - index
    if left >= WRAP_UP_TURNS or max_steps <= WRAP_UP_TURNS:
        return ""
    when = "this is the LAST turn" if left == 0 else f"{left} turn(s) left out of {max_steps}"
    return WRAP_UP_NOTE.format(when=when)


# ─────────────────────────────────────────────────────────── the loop


def run_agent(
    *,
    agent: str,
    scope_id: str,
    system_prompt: str,
    task: str,
    tools: list[ToolName],
    context: Any,
    client: ScriptedClient,
    max_steps: int,
    run_id: str | None = None,
    output_schema: dict | None = None,
    extra_system: str = "",
    max_parse_attempts: int = MAX_PARSE_ATTEMPTS,
    initial_steps: list[AgentStep] | None = None,
    on_step: Callable[[AgentRun, AgentStep], None] | None = None,
) -> AgentRun:
    """Run one agent to a final answer, a budget stop, or an honest error.

    Returns an `AgentRun` in every case -- there is no exception path for "the model misbehaved",
    because a stage that raised would lose the transcript that explains why.

    `initial_steps` are steps the *harness* took before the model was involved (a forced
    `dataflow_verify`, for instance). They are seeded here rather than appended by the caller after
    the fact, because the final answer is parsed while the run is still inside this function: a step
    added afterwards is a step the verdict never saw. Seeding them also puts them in the first user
    message, which is the point -- the model is meant to read the tool's answer, not to be told
    afterwards that one exists.

    `on_step` is called for every step the instant it is recorded, including the seeded ones. It is
    how a run becomes watchable: the transcript in memory is the agent's whole conversation, and
    without this hook the only moment anybody could see it was after the run had finished. It is
    called *after* the append so a consumer can never see a step the run does not have.
    """
    started = _now()
    run = AgentRun(
        run_id=run_id or f"{agent}:{scope_id}",
        agent=agent,
        scope_id=scope_id,
        model=str(getattr(client, "model", "") or ""),
        started_at=started,
    )

    def record(step: AgentStep) -> None:
        """Append one step and tell the observer, in that order.

        Single choke point for `run.steps` so no branch can add a step the observer never hears
        about -- there are eight of them, and the one that forgot would be the one a reader needed.
        The observer runs after the append, and its own failure is swallowed: watching a run is not
        a reason to lose one.
        """
        run.steps.append(step)
        if on_step is None:
            return
        try:
            on_step(run, step)
        except Exception as exc:  # noqa: BLE001 - a broken observer must not kill the run
            log.warning("react: on_step observer failed (%s: %s)", type(exc).__name__, exc)

    if initial_steps:
        for step in initial_steps:
            record(step)
    system = render_system_prompt(
        system_prompt=system_prompt,
        tools=tools,
        output_schema=output_schema,
        extra=extra_system,
    )
    allowed = [_name(tool) for tool in tools]

    def finish(reason: str, output: dict[str, Any] | None = None) -> AgentRun:
        run.stop_reason = reason
        if output is not None:
            run.output = output
        run.finished_at = _now()
        return run

    if max_steps <= 0:
        # A budget of zero is a configuration choice, not a failure: it means "answer from what
        # you were given". Recording it as `budget` keeps the report honest about it.
        return finish("budget")

    parse_errors = 0
    note = ""
    for index in range(1, max_steps + 1):
        user = render_user_message(
            task,
            run.steps,
            # The wrap-up reminder rides with whatever the previous turn needed to be told; both are
            # things the model cannot work out from the transcript (a parse error it has not seen, and
            # how many turns the *harness* has left).
            note="\n".join(part for part in (note, wrap_up_note(index, max_steps)) if part),
        )
        note = ""
        try:
            result = _complete_with_retries(client, system, user, caller=f"{agent}:{scope_id}")
        except (AIUnavailable, AIError) as exc:
            # A model failure is a recorded result, never a lost run: the transcript keeps
            # whatever was already collected, and `stop_reason` says the stage did not finish.
            record(
                AgentStep(
                    index=index,
                    thought=f"model call failed: {type(exc).__name__}: {exc}",
                )
            )
            return finish("error")
        # `ChatResult.text` is the model's answer; the model that actually answered may differ
        # from the one configured (a gateway can route), so the run records what answered.
        if result.model:
            run.model = str(result.model)
        answer = result.text or ""

        payload, parse_error, salvage_note = _parse_turn(answer, output_schema=output_schema)
        if payload is None:
            parse_errors += 1
            record(AgentStep(index=index, thought=answer.strip()[:2000]))
            if parse_errors >= max_parse_attempts:
                log.warning("react: %s gave %d unparseable answers; stopping", agent, parse_errors)
                return finish("error")
            # The error goes back verbatim so the model can fix *this* mistake rather than guess --
            # plus, when the provider says the answer was cut off, *that*, because "could not be used:
            # Expecting ',' delimiter" tells a model nothing it can act on while "you hit the output
            # limit" tells it to write less. Measured on the demo: three such turns in a row ended a
            # recon run and the whole pass with it.
            note = f"Your last answer could not be used: {parse_error}\nAnswer again with one JSON object."
            if truncated(result):
                note += (
                    "\nYour answer hit the OUTPUT LIMIT and was cut off, so it was not valid JSON. "
                    "Send fewer tool calls and shorter `text` per call; split the work over turns."
                )
            continue
        parse_errors = 0
        if salvage_note:
            note = salvage_note

        thought = str(payload.get("thought") or "")
        if "final" in payload:
            final = payload.get("final")
            # `final` must be an object: a model that answers `"final": "done"` has not produced the
            # schema'd output the stage needs, and accepting it would push the failure downstream
            # where it is harder to explain.
            if not isinstance(final, dict):
                parse_errors += 1
                record(AgentStep(index=index, thought=thought))
                if parse_errors >= max_parse_attempts:
                    return finish("error")
                note = (
                    "`final` must be a JSON object, not "
                    f"{type(final).__name__}. Answer again with one JSON object."
                )
                continue
            record(AgentStep(index=index, thought=thought))
            return finish("finished", final)

        batch, batch_error = _turn_calls(payload)
        if batch_error:
            parse_errors += 1
            record(AgentStep(index=index, thought=thought or answer.strip()[:2000]))
            if parse_errors >= max_parse_attempts:
                return finish("error")
            note = f"Your last answer could not be used: {batch_error}\nAnswer again with one JSON object."
            continue
        if not batch:
            parse_errors += 1
            record(AgentStep(index=index, thought=thought or answer.strip()[:2000]))
            if parse_errors >= max_parse_attempts:
                return finish("error")
            note = "One turn needs a `tool`, a `calls` array, or a `final` key. Answer again."
            continue

        # Every call in the batch becomes its own recorded step, carrying the same turn number.
        # Batching is a transport optimisation -- one round trip instead of six -- and not a shortcut
        # in the record: the transcript a reviewer reads, the coverage ledger that counts `read`
        # windows, and the tool-usage accounting are all identical to what the model would have
        # produced one call per turn.
        for entry in batch:
            raw_tool = _name(entry.get("tool"))
            arguments = entry.get("arguments")
            if not isinstance(arguments, dict):
                arguments = {}
            call_reason = str(entry.get("thought") or thought)
            if raw_tool not in allowed:
                call = None
                result = _result_for_unknown_tool(raw_tool, allowed)
                log.info("react: %s/%s refused tool %r", agent, scope_id, raw_tool)
            else:
                call = ToolCall(tool=ToolName(raw_tool), arguments=arguments, reason=call_reason)
                result = _invoke(context, call)
            record(AgentStep(index=index, thought=call_reason, call=call, result=result))

    # The loop ran out of turns with work still possible. Whatever was produced is kept, and the
    # report is told the difference between "done" and "ran out".
    log.info("react: %s/%s hit the step budget (%d)", agent, scope_id, max_steps)
    return finish("budget")


def _complete_with_retries(
    client: ScriptedClient, system: str, user: str, *, caller: str = ""
):
    """One round trip, retried while the failure is an `AIUnavailable` (transient).

    Four attempts rather than two, because the measured failure is a gateway answering HTTP 504: on
    the Java benchmark 20 of 71 agent runs died that way, and each death loses a whole coverage group
    (or leaves a candidate unvalidated) rather than one call. A 504 is an overloaded intermediary and
    is usually gone by the next attempt, so the retry is the cheap side of that trade.

    This is also where the model traffic log is written, and it is the right place for it: the
    attempt number lives here (the client has no idea it is being retried) and so does the caller's
    identity. Recording inside `ChatClient` instead would have produced a log that could not say
    which agent was talking.
    """
    attempt = 0
    while True:
        attempt += 1
        started = time.monotonic()
        try:
            result = client.complete(system, user)
        except AIUnavailable as exc:
            _record_call(
                client=client, caller=caller, attempt=attempt, ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                prompt_chars=len(system) + len(user), error=f"{type(exc).__name__}: {exc}",
            )
            if attempt >= MAX_CLIENT_ATTEMPTS:
                raise
            time.sleep(min(1.5 * attempt, 8.0))
            continue
        except AIError as exc:
            # Not retryable, but still a call that happened and cost time: a log that only holds
            # successes would hide the failure mode a reader opens it to find.
            _record_call(
                client=client, caller=caller, attempt=attempt, ok=False,
                duration_ms=(time.monotonic() - started) * 1000,
                prompt_chars=len(system) + len(user), error=f"{type(exc).__name__}: {exc}",
            )
            raise
        _record_call(
            client=client, caller=caller, attempt=attempt, ok=True,
            duration_ms=(time.monotonic() - started) * 1000,
            prompt_chars=len(system) + len(user), answer_chars=len(result.text or ""),
            usage=getattr(result, "usage", None),
        )
        return result


def _record_call(*, client, caller: str, attempt: int, ok: bool, duration_ms: float,
                 prompt_chars: int, answer_chars: int = 0, usage=None, error: str | None = None):
    """Write one row of model traffic. Never raises -- see `services.ai.traffic`."""
    from services.ai import traffic

    traffic.record(
        caller=caller or "harness",
        kind="harness",
        model=str(getattr(client, "model", "") or ""),
        endpoint=str(getattr(client, "url", "") or ""),
        attempt=attempt,
        ok=ok,
        duration_ms=duration_ms,
        prompt_chars=prompt_chars,
        answer_chars=answer_chars,
        usage=usage,
        error=error,
    )


def _parse_turn(
    answer: str, *, output_schema: dict | None = None
) -> tuple[dict | None, str | None, str]:
    """`(payload, error, salvage_note)` for one model answer. `payload` is None when it cannot be used.

    The JSON object is located leniently -- fences and surrounding prose are tolerated, exactly as
    ``services/ai/parse.py`` does -- but what is inside it is checked strictly enough that the loop's
    next turn cannot be built from a half-understood answer.

    Two recoveries, both because the alternative is losing a whole turn's work. Measured on a real demo
    run: an agent batched eight long `record` calls into one answer, the answer was cut off at the
    output-token limit, the strict parse failed -- and **none** of the eight calls ran, so the facts it
    had just verified never reached the blackboard.

    * a **bare payload**: the schema'd output with no `{"final": ...}` envelope around it. It is the
      answer, missing only its wrapper, and it is recognised by carrying the schema's own required keys
      and none of the turn keys, so an unrelated object cannot be mistaken for one.
    * a **truncated `calls` batch**: the complete call objects before the cut are individually valid
      (the loop validates each one anyway), so they are salvaged and the model is told the tail was
      lost. `salvage_note` carries that, and the caller feeds it back on the next turn.
    """
    raw = extract_json_object(answer)
    syntax_error = ""
    payload: dict | None = None
    if raw is not None:
        try:
            parsed = json.loads(raw)
        except json.JSONDecodeError as exc:
            # A truncated batch lands here, not in the `raw is None` branch: the extractor's own scan
            # finds something object-shaped, and the JSON inside it is still incomplete. Fall through to
            # the salvage attempt rather than reporting a syntax error the model cannot act on.
            syntax_error = f"JSON 对象无法解析：{exc}"
        else:
            if isinstance(parsed, dict):
                payload = parsed
            else:
                return None, f"回答的类型是 {type(parsed).__name__}，不是对象", ""

    if payload is not None:
        if "tool" not in payload and "final" not in payload and "calls" not in payload:
            wrapped = _as_final(payload, output_schema)
            if wrapped is not None:
                return wrapped, None, ""
            return None, "回答缺少 `tool`、`calls` 或 `final` 键", ""
        return payload, None, ""

    salvaged = _salvage_calls(answer)
    if salvaged:
        return (
            {"thought": "（回答被截断，抢救出其中完整的调用）", "calls": salvaged},
            None,
            f"你上一条回答被截断了：只抢救出前 {len(salvaged)} 个完整的调用，后面的丢了。"
            "一次少写几个调用，`text` 也写短一点。",
        )
    if syntax_error:
        return None, syntax_error, ""
    return None, "回答中找不到 JSON 对象（需要 thought + tool/calls/final）", ""


def _as_final(payload: dict, output_schema: dict | None) -> dict | None:
    """Wrap a bare schema payload as `final`, or None when it does not look like one.

    Requires at least two of the schema's `required` keys (one when the schema requires only one) and no
    turn key at all: the point is to accept the answer the model obviously meant, not to guess at
    arbitrary objects. A wrong acceptance would put a malformed `final` into a stage; a wrong refusal
    costs one turn, and the feedback explains what was wrong with it.
    """
    if not output_schema:
        return None
    required = [key for key in (output_schema.get("required") or []) if isinstance(key, str)]
    if not required:
        required = [
            key
            for key, spec in (output_schema.get("properties") or {}).items()
            if isinstance(spec, dict)
        ]
    needed = 1 if len(required) <= 1 else 2
    if len([key for key in required if key in payload]) < needed:
        return None
    return {"thought": "（模型直接给出了最终结果，没有 final 外壳）", "final": payload}


def _salvage_calls(answer: str) -> list[dict]:
    """The complete tool calls in a truncated answer, in order, up to the per-turn cap.

    Scans the `"calls"` array for balanced `{...}` objects and keeps the ones that parse and name a
    tool. Everything after the truncation point is dropped -- that is the honest part: this recovers
    what the model actually finished saying and nothing more.

    The nesting bookkeeping is the whole difficulty, and getting it wrong is silent: an earlier version
    reset the object's start index on *every* closing brace, so a call containing an object (which every
    `record` call does -- `arguments` is one) was never recognised, and the scanner returned nothing
    while looking correct. Hence the test that asserts the salvaged calls, not just the count.
    """
    marker = answer.find('"calls"')
    if marker < 0:
        return []
    start = answer.find("[", marker)
    if start < 0:
        return []
    calls: list[dict] = []
    depth = 0
    opened = -1
    in_string = False
    escaped = False
    for index in range(start + 1, len(answer)):
        character = answer[index]
        if in_string:
            if escaped:
                escaped = False
            elif character == "\\":
                escaped = True
            elif character == '"':
                in_string = False
            continue
        if character == '"':
            in_string = True
        elif character == "{":
            if depth == 0:
                opened = index
            depth += 1
        elif character == "}":
            if depth > 0:
                depth -= 1
                if depth == 0:
                    # Only the brace that closes an outermost object ends a call. Anything nested
                    # inside it (the `arguments` object of every call) must leave `opened` alone.
                    if opened >= 0:
                        try:
                            entry = json.loads(answer[opened : index + 1])
                        except json.JSONDecodeError:
                            entry = None
                        if isinstance(entry, dict) and "tool" in entry:
                            calls.append(entry)
                            if len(calls) >= MAX_CALLS_PER_TURN:
                                break
                    opened = -1
        elif character == "]" and depth == 0:
            break
    return calls


def _turn_calls(payload: dict) -> tuple[list[dict], str | None]:
    """The tool calls one turn carries: one from `tool`, or several from `calls`.

    `(calls, error)`. An empty list with no error means the turn named no tool at all, which the loop
    reports as a protocol mistake rather than treating as "done".
    """
    raw = payload.get("calls")
    if raw is None:
        if "tool" not in payload:
            return [], None
        return [{"tool": payload.get("tool"), "arguments": payload.get("arguments")}], None
    if not isinstance(raw, list) or not raw:
        return [], "`calls` must be a non-empty array"
    if len(raw) > MAX_CALLS_PER_TURN:
        return [], f"`calls` has {len(raw)} entries; at most {MAX_CALLS_PER_TURN} per turn"
    for entry in raw:
        if not isinstance(entry, dict) or "tool" not in entry:
            return [], "every entry of `calls` needs a `tool` key"
    return list(raw), None


# ─────────────────────────────────────────────────────────── evidence extraction


def dataflow_evidence(run: AgentRun) -> DataflowEvidence | None:
    """The last `dataflow_verify` result in a run, as typed evidence -- success *or* failure.

    The tool always reports its answer in ``ToolResult.data["evidence"]``, including when it is
    unavailable or the engine could not derive a sink. Carrying that even on failure is the point:
    "the tool ran and could not answer" and "the tool was never asked" look identical to a reader
    of a verdict unless the failure travels with it, and the first one is a fact about the run.

    Returns None only when the tool was never reached at all.
    """
    for step in reversed(run.steps):
        if step.call is None or step.result is None:
            continue
        if _name(step.call.tool) != ToolName.DATAFLOW_VERIFY.value:
            continue
        data = step.result.data or {}
        raw = data.get("evidence")
        if isinstance(raw, dict):
            # The tool's own `DataflowEvidence`, verbatim. `derived` is trusted from the tool and
            # not recomputed here: only the tool knows whether the sink came from the code.
            return DataflowEvidence(
                derived=bool(raw.get("derived", False)),
                source=str(raw.get("source") or ""),
                sink=str(raw.get("sink") or ""),
                path=[str(item) for item in (raw.get("path") or [])],
                sanitizers=[str(item) for item in (raw.get("sanitizers") or [])],
                methods=[str(item) for item in (raw.get("methods") or [])],
                error=raw.get("error") or step.result.error,
            )
        # A tool layer that reported a failure without an evidence payload: keep the error, so the
        # verdict still says why no path was established.
        return DataflowEvidence(
            derived=bool(data.get("derived", False)),
            source=str(data.get("source") or ""),
            sink=str(data.get("sink") or ""),
            path=[str(item) for item in (data.get("path") or [])],
            error=step.result.error or "dataflow_verify returned no evidence",
        )
    return None


def dataflow_unavailable_reason(run: AgentRun) -> str | None:
    """Why dataflow was unusable in this run, when the tool said so.

    The orchestrator carries this into the report instead of swallowing it: a validation stage
    that fell back to semantic evidence because no worker could be reached is a materially weaker
    result, and the failure text already names the configuration that would fix it.
    """
    for step in reversed(run.steps):
        if step.call is None or step.result is None:
            continue
        if _name(step.call.tool) != ToolName.DATAFLOW_VERIFY.value:
            continue
        if step.result.ok:
            return None
        return step.result.error or step.result.summary or "dataflow_verify failed"
    return None


def used_tool(run: AgentRun, tool: ToolName) -> bool:
    """Whether a run actually called `tool` and got a usable answer."""
    return any(
        step.call is not None
        and step.result is not None
        and _name(step.call.tool) == tool.value
        and step.result.ok
        for step in run.steps
    )


def steps_used(run: AgentRun) -> int:
    return len(run.steps)
