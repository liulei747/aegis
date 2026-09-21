"""The tool layer: the only ways an agent can touch anything.

Six tools, deliberately few, and exactly one of them writes. Every tool is reach the model can abuse
-- the repository it is pointed at is content the harness did not write, and a comment inside it can be
an instruction -- so each one is written as a refusal-first design: what it will not do is the
interesting part, and it is documented at the point where the refusal happens (see ``read.py``,
``list_files.py``, ``shell.py``, ``dataflow.py``, ``record.py``, ``board.py``).

The names in __all__ are the frozen surface the orchestrator builds against. The dataclasses
and protocols live in ``base.py`` so a tool module can import them without importing the package
that imports the tool modules.

Two properties of this module are load-bearing:

* ``invoke`` never raises. Its caller is a model's ReAct loop, and a tool that throws turns one
  bad argument into a finished run -- the model can read an error message and try something
  else, but it cannot recover from a traceback that unwinds the step.
* everything a tool can do arrives through :class:`ToolContext`. There is no ambient filesystem,
  no ambient environment and no global registry of capabilities, which is what makes "what can
  this agent reach?" answerable by reading one dataclass.
"""

from __future__ import annotations

from typing import Any

from aegis_contracts.harness import (
    DataflowEvidence,
    ShellCommandPolicy,
    ToolCall,
    ToolName,
    ToolResult,
)
from services.harness.tools.base import (
    BoardReader,
    DataflowVerifier,
    RecordWriter,
    Tool,
    ToolContext,
    ToolLimits,
)
from services.harness.tools.board import SECTIONS, BoardTool
from services.harness.tools.dataflow import DataflowVerifyTool, WorkerDataflowVerifier
from services.harness.tools.grep import GrepTool
from services.harness.tools.list_files import ListFilesTool
from services.harness.tools.read import ReadTool
from services.harness.tools.record import KINDS, RecordTool
from services.harness.tools.shell import ShellCommandTool

#: Every tool, keyed by the name the model calls it by. Insertion order follows ``ToolName``,
#: so ``schemas()`` is stable across processes -- a system prompt that reshuffles between runs
#: makes two agents' transcripts harder to compare than they need to be.
TOOLS: dict[ToolName, Tool] = {
    ToolName.READ: ReadTool(),
    ToolName.LIST_FILES: ListFilesTool(),
    ToolName.SHELL: ShellCommandTool(),
    ToolName.GREP: GrepTool(),
    ToolName.DATAFLOW_VERIFY: DataflowVerifyTool(),
    ToolName.RECORD: RecordTool(),
    ToolName.BOARD: BoardTool(),
}


def schemas() -> list[dict[str, Any]]:
    """What the orchestrator puts in the system prompt: one description per tool."""
    return [tool.schema() for tool in TOOLS.values()]


def invoke(context: ToolContext, call: ToolCall) -> ToolResult:
    """Run one tool call. **Never raises**, whatever the model sent.

    Three failure modes are handled here rather than in the tools:

    * an unknown tool name (a hallucinated tool, or one this deployment did not register);
    * anything the tool raises -- a bad argument deep inside a library, a filesystem error, a
      verifier blowing up. It becomes ``ok=False`` with the exception's type and message, which
      is information the model can act on;
    * a tool that returns something other than a ``ToolResult`` (a test double, or a future
      tool that forgot the protocol). Returning it would put a non-result into the transcript
      and break every consumer downstream.

    ``BaseException`` is *not* caught: ``KeyboardInterrupt`` and the cancellation a queue
    terminate delivers must keep unwinding, or a cancelled job would be reported as a completed
    one. Everything that is an ordinary ``Exception`` is a tool failure, and tool failures are
    messages.
    """
    name = getattr(call, "tool", None)
    tool = TOOLS.get(name) if isinstance(name, ToolName) else None
    if tool is None:
        # `tool=None`, never one of the four: the model asked for something that is not in its
        # allow-list, and attributing that refusal to `read` would make the audit trail show
        # `read` being called and refused when it never ran. The name it did ask for is kept in
        # `data["requested_tool"]` and in the error, which is where a reviewer looks for it.
        requested = name.value if isinstance(name, ToolName) else str(name)
        return ToolResult(
            tool=None,
            ok=False,
            summary=f"未知工具：{requested}",
            error=f"未知工具 {requested}；可用工具：{', '.join(t.value for t in TOOLS)}",
            data={"requested_tool": requested},
        )

    try:
        result = tool.run(context, call.arguments or {})
    except Exception as exc:  # noqa: BLE001 - see the docstring: a tool failure is a message
        message = f"工具 {tool.name.value} 执行失败：{type(exc).__name__}: {exc}"
        return ToolResult(tool=tool.name, ok=False, summary=message, error=message)

    if not isinstance(result, ToolResult):
        message = f"工具 {tool.name.value} 返回了非 ToolResult 对象：{type(result).__name__}"
        return ToolResult(tool=tool.name, ok=False, summary=message, error=message)
    return result


__all__ = [
    "KINDS",
    "SECTIONS",
    "TOOLS",
    "BoardReader",
    "BoardTool",
    "DataflowEvidence",
    "DataflowVerifier",
    "DataflowVerifyTool",
    "GrepTool",
    "ListFilesTool",
    "ReadTool",
    "RecordTool",
    "RecordWriter",
    "ShellCommandPolicy",
    "ShellCommandTool",
    "Tool",
    "ToolCall",
    "ToolContext",
    "ToolLimits",
    "ToolName",
    "ToolResult",
    "WorkerDataflowVerifier",
    "invoke",
    "schemas",
]
