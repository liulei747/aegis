"""The traceable summary a request carries in place of its older observations.

Batch 3 of `docs/HARNESS_RUNTIME_TODO.md`. When an agent's transcript no longer fits the configured
input budget, the request sent to the model keeps the task, the newest observations and every
recorded fact, and replaces the rest with the summary built here. What that summary is allowed to
say is the whole design:

* **Only what the steps prove.** Every line is derived from `AgentStep.call.arguments` and
  `ToolResult.data`: which file, which line window, whether the read was complete, which pattern
  matched how many times, which call failed and why. No prose is generated about *what the code
  meant* -- a model that wants that has to re-read the file, and the summary tells it exactly which
  window to ask for.
* **Reused evidence is labelled as such.** A read the harness seeded from the blackboard
  (`agents.SCOPE_REUSE_THOUGHT`) is listed under its own heading. The coverage ledger already
  refuses to count a summary as a read; this keeps the *model* from mistaking a colleague's
  earlier read for its own new one, which is the other way "we covered this file" goes wrong.
* **Every archived step stays addressable.** The step indices (or `tool_call_id`s) folded into
  each line are listed, so a reviewer holding `evidence/<run>.steps.jsonl` can open the original.

The summary is text. It is not stored in the blackboard and never replaces `AgentRun.steps`;
`react.render_user_message` and `react._native_context_messages` build it per request and throw
it away. The `ContextSummary` object exists so the trail event can carry the same structure.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aegis_contracts.harness import AgentStep, ToolName

#: The `thought` marker `agents.py` puts on a step that was seeded from the blackboard rather than
#: read by this agent. Imported lazily to avoid a cycle (`agents` imports `react` imports this).
_REUSE_MARKERS: tuple[str, ...] = ("harness（不是模型）：本文件本次运行已经完整读过",)


def _is_reused(step: AgentStep) -> bool:
    return any(step.thought.startswith(marker) for marker in _REUSE_MARKERS)


def _merge(windows: list[tuple[int, int]]) -> list[tuple[int, int]]:
    out: list[tuple[int, int]] = []
    for start, end in sorted(windows):
        if out and start <= out[-1][1] + 1:
            out[-1] = (out[-1][0], max(out[-1][1], end))
        else:
            out.append((start, end))
    return out


@dataclass
class FileDigest:
    path: str
    total_lines: int = 0
    windows: list[tuple[int, int]] = field(default_factory=list)
    refs: list[str] = field(default_factory=list)
    reused: bool = False
    truncated: bool = False

    @property
    def complete(self) -> bool:
        merged = _merge(self.windows)
        return self.total_lines > 0 and len(merged) == 1 and merged[0] == (1, self.total_lines)

    def line(self) -> str:
        spans = ", ".join(f"{a}-{b}" for a, b in _merge(self.windows)) or "?"
        status = "complete" if self.complete else "partial"
        if self.truncated:
            status += ", output clipped"
        total = f"/{self.total_lines}" if self.total_lines else ""
        source = "reused from blackboard" if self.reused else "read by this run"
        return f"- {self.path}: lines {spans}{total} ({status}; {source}; refs {', '.join(self.refs)})"


@dataclass
class ContextSummary:
    """What the compacted request says about the steps it no longer carries verbatim."""

    reads: dict[tuple[str, bool], FileDigest] = field(default_factory=dict)
    searches: list[str] = field(default_factory=list)
    other: list[str] = field(default_factory=list)
    failures: list[str] = field(default_factory=list)
    #: Which archived steps (text protocol) or call ids (native) each summary line refers to.
    refs: list[str] = field(default_factory=list)

    def render(self) -> str:
        parts = [
            "EARLIER OBSERVATIONS (SUMMARY). Original tool output was removed from this request to "
            "fit the input budget; it remains in the run's step archive and the files are in the "
            "workspace. Line windows and match counts below are the tool's own figures. Nothing here "
            "is a finding: re-read a window before citing it, and do not count a file as reviewed "
            "unless you (or a reused read) saw all its lines.",
        ]
        if self.reads:
            own = [d for d in self.reads.values() if not d.reused]
            reused = [d for d in self.reads.values() if d.reused]
            if own:
                parts.append("Files read by this run:\n" + "\n".join(d.line() for d in own))
            if reused:
                parts.append(
                    "Files seeded from earlier complete reads (not new evidence from this run):\n"
                    + "\n".join(d.line() for d in reused)
                )
        if self.searches:
            parts.append("Searches:\n" + "\n".join(self.searches))
        if self.other:
            parts.append("Other tool calls:\n" + "\n".join(self.other))
        if self.failures:
            parts.append("Failed calls (do not repeat unchanged):\n" + "\n".join(self.failures))
        return "\n".join(parts)

    def as_event(self) -> dict[str, Any]:
        """The structured half, for the `context_compaction` trail event. No source text."""
        return {
            "summary_files": [
                {"path": d.path, "windows": _merge(d.windows), "total_lines": d.total_lines,
                 "complete": d.complete, "reused": d.reused, "refs": d.refs}
                for d in self.reads.values()
            ],
            "summary_searches": len(self.searches),
            "summary_failures": len(self.failures),
            "summary_refs": list(self.refs),
        }


def _short(value: Any, limit: int = 160) -> str:
    text = json.dumps(value, ensure_ascii=False) if not isinstance(value, str) else value
    return text if len(text) <= limit else text[: limit - 1] + "…"


def summarize_steps(steps: list[AgentStep], *, ref_of=None) -> ContextSummary:
    """Fold the given (older) steps into a `ContextSummary`.

    `ref_of(step)` names the step in the summary -- `"turn 3"` for the text protocol, the
    `tool_call_id` for the native one. `record` steps are deliberately **not** folded: the caller
    keeps them verbatim because a confirmed fact must stay visible, not merely be receipted.
    """
    ref_of = ref_of or (lambda step: f"turn {step.index}")
    summary = ContextSummary()
    for step in steps:
        call, result = step.call, step.result
        if call is None:
            continue
        ref = ref_of(step)
        summary.refs.append(ref)
        args = call.arguments or {}
        data = (result.data if result is not None else None) or {}
        ok = bool(result is not None and result.ok)
        if not ok:
            error = (result.error if result is not None else "") or "no result"
            summary.failures.append(
                f"- {ref}: {call.tool.value} {_short(args, 120)} → {_short(error, 200)}"
            )
            continue
        if call.tool is ToolName.READ:
            path = str(data.get("path") or args.get("path") or "")
            if not path:
                continue
            reused = _is_reused(step)
            # A reused read and a new read of the same file have different provenance. Merging
            # their windows would falsely attribute the earlier agent's coverage to this run.
            digest = summary.reads.setdefault(
                (path, reused), FileDigest(path=path, reused=reused)
            )
            offset = int(data.get("offset") or args.get("offset") or 1)
            returned = int(data.get("returned_lines") or 0)
            if returned > 0:
                digest.windows.append((offset, offset + returned - 1))
            digest.total_lines = max(digest.total_lines, int(data.get("total_lines") or 0))
            digest.refs.append(ref)
            digest.truncated = digest.truncated or bool(
                result is not None and result.truncated and data.get("next_offset") is None
            )
        elif call.tool is ToolName.GREP:
            pattern = args.get("pattern", "")
            where = args.get("path") or args.get("include") or ""
            total = data.get("total_matched", data.get("count"))
            matches = [m for m in (data.get("matches") or []) if isinstance(m, dict)]
            files = sorted({
                str(m.get("path") or m.get("file") or "")
                for m in matches
            } - {""})
            hit = f"{total} match(es)" if total is not None else "matched"
            spread = f" in {len(files)} file(s): {', '.join(files[:6])}{'…' if len(files) > 6 else ''}" if files else ""
            # Preserve a bounded set of exact source locations. The result body and snippets are
            # archived, but a model needs line references to decide what to re-read next.
            locations = [
                f"{path}:{line}" for m in matches
                if (path := str(m.get("path") or m.get("file") or ""))
                and isinstance((line := m.get("line")), int) and line > 0
            ]
            pointers = f"; first locations {', '.join(locations[:8])}" if locations else ""
            if len(locations) > 8:
                pointers += f" (+{len(locations) - 8} more in archive)"
            summary.searches.append(f"- {ref}: grep {_short(pattern, 80)!r}"
                                    f"{f' under {where}' if where else ''} → {hit}{spread}{pointers}")
        else:
            head = (result.summary or "").split("\n", 1)[0] if result is not None else ""
            summary.other.append(
                f"- {ref}: {call.tool.value} {_short(args, 120)} → {_short(head, 160) or 'ok'}"
            )
    return summary
