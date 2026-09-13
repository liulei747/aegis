"""The vocabulary the tool layer is built on: limits, context, and the two protocols.

These four names are re-exported by ``services.harness.tools`` (the frozen surface the
orchestrator imports). They are *defined* here rather than in that ``__init__`` for one
mechanical reason with a real consequence: a tool module has to name ``ToolContext`` and
``ToolResult``, and if it imported them from the package ``__init__`` that imports the tool
modules, the import graph would run through a half-initialised module. A tool that only works
when it is imported second is a tool that breaks the day someone imports it first.

Nothing here reaches the filesystem, spawns a process or talks to the dataflow fleet. Every
capability a tool has is handed to it through :class:`ToolContext`, which is what makes the
tool layer testable without a workspace, a JVM or a network -- and, more importantly, what
makes "what can this agent actually do?" answerable by reading one dataclass.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

from aegis_contracts.harness import (
    DataflowEvidence,
    ShellCommandPolicy,
    ToolName,
    ToolResult,
)


@dataclass
class ToolLimits:
    """Per-call caps the tools hold themselves to.

    Every one of these is a cap on what reaches the model's context, not on what the tool can
    read: a tool that quietly returns a 200 KB file does not fail, it just spends the budget of
    the agent that was supposed to be reasoning about security. The caps are per call so a
    model that genuinely needs more can ask again with an offset -- which is also how
    truncation stays visible instead of being a number nobody reads.
    """

    max_read_lines: int = 200          # per `read` call
    max_list_files: int = 200          # per `list_files` call
    max_output_chars: int = 8_000      # what one ToolResult.summary may carry


@dataclass
class ToolContext:
    """Everything a tool is allowed to touch.

    There is no global accessor behind this: a tool reaches the filesystem only through
    ``workspace``, runs a program only through ``shell_policy``, and asks the dataflow engine
    only through ``dataflow``. A tool that wanted to do more would have to be handed more,
    which is the point -- "the agent has shell access" is only a defensible statement if the
    shell it has is written down somewhere a reviewer can read.
    """

    workspace: Path
    shell_policy: ShellCommandPolicy = field(default_factory=ShellCommandPolicy)
    limits: ToolLimits = field(default_factory=ToolLimits)
    #: Injectable so the tool layer can be tested without a dataflow fleet. When None the
    #: dataflow tool must report unavailability honestly -- never invent a path.
    dataflow: DataflowVerifier | None = None
    #: The blackboard writer `record` uses, injected by the orchestrator. `dict -> dict`, where the
    #: result says whether the fact landed and at which revision. None means "there is nowhere to
    #: record", and the tool says so instead of pretending -- the same rule `dataflow` follows.
    record: RecordWriter | None = None
    #: The blackboard *reader* `board` uses. A section name in, that slice of the board out -- the
    #: read side of the same channel `record` writes to, and injected the same way so a tool still
    #: reaches nothing it was not handed.
    board: BoardReader | None = None


class BoardReader(Protocol):
    """What `board` reads: one named slice of the current shared state.

    Named slices rather than the board itself, for the same reason `RecordWriter` takes one record
    rather than the board: a tool that could see the whole run state would let an agent spend its
    budget reading the candidate ledger and the coverage table instead of the code, and the model's
    context is the resource this whole pipeline is rationing. The sections are the ones an
    investigating agent actually needs from a peer -- what the project is, which components exist,
    what is worth attacking, and what has been noted -- and nothing else.
    """

    def __call__(self, section: str) -> dict[str, Any]: ...


class RecordWriter(Protocol):
    """Where `record` puts a fact: the orchestrator's blackboard.

    Deliberately not "the blackboard" itself. The tool layer's rule is that a tool reaches nothing it
    was not handed, and handing it the whole board would give a model-writable object the run's entire
    state -- including the candidate ledger and the coverage table that other agents are being judged
    by. A callable that accepts one record and returns whether it landed is the whole capability.
    """

    def __call__(self, record: dict[str, Any]) -> dict[str, Any]: ...


class DataflowVerifier(Protocol):
    """The one thing ``dataflow_verify`` needs from the dataflow fleet.

    Note what is *not* in the signature: a sink. The caller says where the static hit was and,
    at most, a hint about where the value entered; which call the taint ends at is derived from
    the code by the engine, exactly as ``services/dataflow/worker.py`` does it.

    ``file`` is a workspace-relative path. It is relative on purpose: the same tree is mounted
    at different absolute paths in the gateway, the extractor and the worker, and an absolute
    path that is correct in one process is a "workspace not found" 404 in another.
    """

    def verify(self, *, file: str, line: int, source_hint: str | None) -> DataflowEvidence: ...


class Tool(Protocol):
    """What the registry holds and the model's prompt describes.

    ``schema()`` is part of the protocol rather than a module-level table because a tool's
    description and its implementation drift apart the moment they live in different files --
    and a model that is told about an argument that does not exist produces a call that cannot
    succeed, which reads in the transcript as the agent being bad at its job.
    """

    name: ToolName

    def schema(self) -> dict[str, Any]:
        """JSON-schema-ish description of this tool, for the orchestrator's system prompt."""
        ...

    def run(self, context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
        """Execute one call. May raise; ``invoke`` is what turns a raise into a ToolResult."""
        ...
