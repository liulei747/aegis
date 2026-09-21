"""One Joern worker: a resident `joern --server` plus a supervisor that owns it.

Deployment shape, and why it is this shape. The worker **runs inside its own container**
(`services/dataflow/Dockerfile`), and the Joern server is a **child process of the
supervisor in that same container**. An earlier version had the supervisor spawn *sibling*
containers with `docker run`, which was wrong in two independent ways:

* it needed access to the Docker socket, so a "worker" was really a privileged controller;
* it passed *container* paths to `-v`, which the Docker daemon reads as **host** paths, so
  the mounts pointed at directories that did not exist -- the same path-identity trap the
  compose file warns about between gateway, worker and extractor.

Running Joern as a local child removes both: no socket, and every path is inside one
filesystem. It also means the Dockerfile is the only place that knows how Joern is
installed.

Once the graph is resident, a query costs ~1 s instead of ~9 s for a cold
`joern --script` invocation. Each worker owns exactly one project at a time; a request for a
different project **restarts the server bound to that project's graph**, because the Joern build
in this image takes the graph on the command line and offers no way to swap it in a live session
(see `_spawn_server`). That is one server start per project switch, not per query.

Answers are read from a **file**, not from stdout: the server does not capture `println`
output (measured -- the result object has only `success` / `uuid` / `stdout`, and a
`println` query returns an empty `stdout`). Two fixes were tried before this one; the
last-expression display is captured but is ANSI-coloured and string-escaped, so a file is
both simpler and exact. Requests are serialised by a lock, which makes the file a message
channel rather than a race.
"""

from __future__ import annotations

import json
import os
import re
import signal
import subprocess
import threading
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from pathlib import Path

from aegis_core.config import DataflowConfig
from aegis_core.logging import get_logger
from aegis_core.workspace import dominant_suffix, suffix_census, workspace_digest

log = get_logger(__name__)

#: The query template. Anchor matching is deliberately broad, and **the three clauses are not
#: equivalent** -- measured on the demo, for `request.args.get("id")`:
#:
#:     cpg.call.name  = "get"                      <- the bare callee name
#:     cpg.call.code  = "request.args.get(\"id\")"  <- the whole expression lives here
#:
#: So an earlier note in this file ("Joern names a call node after the whole expression") was
#: wrong, and `name == needle` / `name.endsWith("." + needle)` match **nothing** for a
#: dotted source like `request.args.get`. Only the `code.contains` clause finds it, which makes
#: that clause load-bearing rather than a convenience. Matching on the bare name is also
#: unreliable in the other direction: `get` alone is far too generic to be a source anchor.
#:
#: An empty anchor is guarded: `anchored("")` would match every call in the program and turn
#: a targeted query into a full pairwise explosion.
#:
#: Python templates for Scala must **double the backslash** (`"\\t"`, `"\\n"`). A single one
#: is compiled by Python into a real tab/newline, and a real newline inside a Scala string
#: literal is a syntax error -- that shipped once and broke the query.
FLOW_QUERY = """\
import io.shiftleft.semanticcpg.language.*
import io.joern.dataflowengineoss.language.*
import io.shiftleft.codepropertygraph.generated.nodes.CfgNode

def anchored(needle: String): List[CfgNode] =
  if (needle.isEmpty) Nil
  else
    cpg.call
      .filter(c => c.name == needle || c.name.endsWith("." + needle) || c.code.contains(needle))
      .filterNot(_.name.startsWith("<"))
      .l

// The source end of a taint question is usually an ENTRY PARAMETER, not a call -- "the value
// arrives through handle_request's `request` argument". A parameter is a MethodParameterIn, so
// `anchored` can never reach it: it searches `cpg.call` only. Measured, handing the method NAME
// to `anchored` is not a workaround -- it matches the call site `handle_request(request)` inside
// `dispatch`, and a flow started from a call site's return value never reaches the sink
// (0 flows, reported as "the engine proved it is unreachable"). Hence a second anchor kind.
//
// `param` empty means "every parameter of the method", which is what an LSP caller walk can
// supply without reading the signature.
def anchoredParameter(method: String, param: String): List[CfgNode] =
  if (method.isEmpty) Nil
  else {
    val ms = cpg.method.nameExact(method)
    val ps = if (param.isEmpty) ms.parameter.l else ms.parameter.nameExact(param).l
    ps.map(p => p: CfgNode)
  }

// The source end when the caller did not commit to a kind -- which is the normal case for a
// finding: it says where the danger is and nothing about where the value entered.
//
// Decided **against the graph**, not against the file's text, so one rule serves every language a
// frontend can parse: a dotted expression is a call; a bare name that names a method *here* is
// that method's parameters; anything else is a call; and a finding inside a method falls back to
// that method's own parameters. This replaced a Python `ast` walk that could only ever answer for
// Python -- on a Java project it raised SyntaxError, the caller fell back to a configured string
// such as `request.args.get`, and every question returned "0 source candidates", which read as
// "the value cannot reach the sink" about a graph the engine had never been able to search.
def anchoredAuto(needle: String, method: String, param: String, fallback: String): List[CfgNode] =
  if (needle.nonEmpty) {
    if (needle.contains(".") || needle.contains("(") || needle.contains(")")) anchored(needle)
    else {
      val byParameter = anchoredParameter(needle, "")
      if (byParameter.nonEmpty) byParameter else anchored(needle)
    }
  }
  else if (method.nonEmpty) anchoredParameter(method, param)
  else if (fallback.nonEmpty) anchored(fallback)
  else Nil

val srcs = %SOURCE_ANCHOR%
val sinks = anchored("%SINK%")
val flows = sinks.reachableByFlows(srcs).l

// One line per element with a uniform prefix, so the report reads line by line. Code is
// scrubbed of tabs and newlines -- a multi-line literal would otherwise break the rows.
val body = flows.zipWithIndex.flatMap { case (flow, i) =>
  flow.elements.l.flatMap {
    case n: CfgNode =>
      Some(Seq(n.label, n.method.name, n.method.filename,
               n.lineNumber.map(_.toString).getOrElse(""),
               n.code.replace("\\t", " ").replace("\\n", " ")).mkString("\\t"))
    case _ => None
  }.map(elem => "ELEM\\t" + i + "\\t" + elem)
}

val report = Seq(
  "ANCHOR\\tSOURCE\\t" + srcs.size,
  "ANCHOR\\tSINK\\t" + sinks.size,
  "ANCHOR\\tKIND\\t%SOURCE_KIND%",
  "ANCHOR\\tEXPR\\t%SOURCE_EXPR%",
  "FLOW_COUNT\\t" + flows.size
) ++ body

java.nio.file.Files.write(
  java.nio.file.Paths.get("%OUTPUT%"),
  report.mkString("\\n").getBytes("UTF-8")
)
"""

#: Where the query writes its answer, relative to the project's cache directory.
REPORT_NAME = "report.txt"

#: The ways a caller can name the source end of a taint question.
ANCHOR_CALL = "call"
ANCHOR_PARAMETER = "parameter"
#: "You work out where the value enters" -- the caller names the sink and, optionally, a hint,
#: and the engine decides against the graph. This is the kind the harness uses, because a finding
#: says where the danger is and nothing about where the value came from, and *that* question is
#: answerable only by the graph.
ANCHOR_AUTO = "auto"

#: Parameters that are the receiver rather than data: taint does not enter through them, and an
#: anchor on one returns a path that proves nothing. A name list because it is the only thing the
#: CPG agrees on across frontends -- Java names it `this`, Python `self`/`cls`.
RECEIVER_PARAMETERS = frozenset({"self", "cls", "this"})


def _scala_literal(value: str) -> str:
    """Escape a value for the body of a Scala string literal.

    The query is assembled by substitution, so an unescaped `"` in a source string would end
    the literal early -- turning the query into a syntax error, or into a *different* query.
    Source strings come from configuration and (soon) from a rule or a language server, so
    this is not a hypothetical.
    """
    return value.replace("\\", "\\\\").replace('"', '\\"')


def _report_field(value: str) -> str:
    """Tab- and newline-free text, because the report rows are parsed by splitting on tabs."""
    return value.replace("\t", " ").replace("\n", " ").replace("\r", " ")


@dataclass(frozen=True)
class SourceAnchor:
    """The source end: either a call name, or a method's parameter(s).

    Two kinds because they are two different node types, and the difference is not cosmetic --
    measured, a method *name* handed to the call matcher resolves to the call site rather than
    the parameter, and a flow started there finds nothing.
    """

    kind: str = ANCHOR_CALL
    #: `kind=call`: matched against call nodes (name / dotted suffix / code substring).
    needle: str = ""
    #: `kind=parameter`: the method whose parameters are the source.
    method: str = ""
    #: `kind=parameter`: a specific parameter name; empty means every parameter of `method`.
    parameter: str = ""

    def __post_init__(self) -> None:
        if self.kind not in (ANCHOR_CALL, ANCHOR_PARAMETER, ANCHOR_AUTO):
            raise ValueError(f"unknown source anchor kind: {self.kind!r}")
        if self.kind == ANCHOR_CALL and not self.needle.strip():
            raise ValueError("a call anchor needs a non-empty name")
        if self.kind == ANCHOR_PARAMETER and not self.method.strip():
            raise ValueError("a parameter anchor needs the method it belongs to")
        # `auto` needs nothing: `needle` is an optional hint and the method/parameter come from
        # the graph. Requiring one here would push the caller back into guessing.

    @property
    def expr(self) -> str:
        """How the anchor reads in a report: `handle_request(request)`, or the call text."""
        if self.kind == ANCHOR_PARAMETER:
            return f"{self.method}({self.parameter or '*'})"
        if self.kind == ANCHOR_AUTO:
            return self.needle or "auto（由引擎从命中位置推导）"
        return self.needle

    def scala(self, *, auto_method: str = "", auto_param: str = "", fallback: str = "") -> str:
        """The Scala expression that resolves this anchor to nodes.

        `auto` needs the enclosing method and its chosen parameter, which only exist after the
        sink has been derived -- so they arrive as arguments rather than living on the anchor.
        """
        if self.kind == ANCHOR_PARAMETER:
            return (
                f'anchoredParameter("{_scala_literal(self.method)}", '
                f'"{_scala_literal(self.parameter)}")'
            )
        if self.kind == ANCHOR_AUTO:
            return (
                f'anchoredAuto("{_scala_literal(self.needle)}", '
                f'"{_scala_literal(auto_method)}", "{_scala_literal(auto_param)}", '
                f'"{_scala_literal(fallback)}")'
            )
        return f'anchored("{_scala_literal(self.needle)}")'


#: Locate the sink from a finding's own position.
#:
#: Why this exists rather than a configured anchor: the finding already says *where* the rule
#: fired, and that location is a far stronger constraint than a global call name. Measured on
#: the demo repo -- the finding sits on line 6 (the concatenation) while the execution is the
#: next plain call on line 7, so "first non-operator call at or after the finding line, inside
#: the method that contains it" resolves `execute` with no configuration at all.
#:
#: It is a heuristic and is treated as one: synthetic methods (`<module>`, `<body>`) are
#: excluded, because `<module>` spans the whole file and would put unrelated calls in range,
#: and the alternatives are reported so a reviewer can see the choice was not unique.
#:
#: Like the flow query, it writes a file rather than printing: the server does not capture
#: `println` output.
DERIVE_SINK_QUERY = """\
import io.shiftleft.semanticcpg.language.*
import io.shiftleft.codepropertygraph.generated.nodes.Call
import io.shiftleft.codepropertygraph.generated.nodes.Method

val findingFile = "%FILE%"
val findingLine = %LINE%

def isReal(m: Method): Boolean =
  m.name.nonEmpty && !m.name.startsWith("<") && !m.name.contains("<")

val method = cpg.method
  .filter(m => m.filename.endsWith(findingFile))
  .filter(isReal)
  .filter { m =>
    val lines = m.lineNumber.toList ++ m.lineNumberEnd.toList
    lines.size == 2 && lines.min <= findingLine && findingLine <= lines.max
  }
  .l
  .headOption

val candidates: List[Call] = method.toList.flatMap { m =>
  m.call
    .filterNot(_.name.startsWith("<operator>"))
    .filter(c => c.name.nonEmpty && !c.name.startsWith("<"))
    .filter(c => c.lineNumber.exists(_ >= findingLine))
    .sortBy(_.lineNumber.getOrElse(0))
    .l
}

val report = Seq("METHOD\\t" + method.map(_.name).getOrElse("")) ++
  method.toList.flatMap(_.parameter.map(p => "PARAM\\t" + p.name)) ++
  candidates.map(c => "CANDIDATE\\t" + c.name + "\\t" + c.lineNumber.getOrElse(-1)) ++
  Seq("CHOSEN\\t" + candidates.headOption.map(_.name).getOrElse(""))

java.nio.file.Files.write(
  java.nio.file.Paths.get("%OUTPUT%"),
  report.mkString("\\n").getBytes("UTF-8")
)
"""

#: Where the sink derivation writes its answer, relative to the project's cache directory.
SINK_REPORT_NAME = "sink.txt"

#: How many workers this deployment runs is a deployment fact, not a worker fact; the
#: worker only needs its own index. Kept here so the app modules agree on the variable name.
INDEX_ENV = "AEGIS_DATAFLOW__WORKER_INDEX"


class JoernUnavailable(RuntimeError):
    """Joern is not installed in this container, or is not runnable."""


class JoernError(RuntimeError):
    """The server ran and the query failed. Distinct from 'no flow found'."""


@dataclass
class SinkResolution:
    """Which sink anchor was used, and where it came from.

    The provenance travels with the answer because the derivation is a heuristic: a caller
    that cannot tell "the rule named this" from "we picked it" cannot judge the result. An
    empty `anchor` means nothing could be resolved, which is reported rather than guessed.
    """

    anchor: str = ""
    derived_from: str | None = None
    method: str = ""
    #: The enclosing method's parameters, in CPG order and including the receiver. Carried because
    #: an `auto` anchor needs one of them as the source end, and the same query already found the
    #: method -- asking again would be a second round trip for a fact we are holding.
    parameters: list[str] = field(default_factory=list)
    alternatives: list[str] = field(default_factory=list)


@dataclass
class FlowAnswer:
    flows: list[list[dict]] = field(default_factory=list)
    flow_count: int = 0
    source_candidates: int = 0
    sink_candidates: int = 0
    cold: bool = False
    #: When True this session had to load the project graph; the CPG itself may still have come
    #: from the on-disk cache, which `cpg_cached` distinguishes. `elapsed_s` covers the flow
    #: query **only** -- loading and sink derivation are timed separately because a caller
    #: reading `elapsed_s` as "the cost of the request" was wrong by a factor of two.
    cpg_cached: bool = False
    #: What the source anchor was, as the query saw it. Reported because "which anchor" is not
    #: reconstructible from the flow when the flow is empty -- and an empty flow caused by a
    #: mis-typed anchor must not be read as "the engine proved the value cannot reach the sink".
    source_kind: str = ""
    source_expr: str = ""
    #: Which CPG frontend built the graph this answer came from. Reported because "the anchor
    #: matched no node" has two very different causes -- a wrong anchor, and a graph built in the
    #: wrong language -- and only this field tells them apart after the fact.
    frontend: str = ""
    elapsed_s: float = 0.0
    load_s: float = 0.0
    sink_s: float = 0.0

    @property
    def total_s(self) -> float:
        """Everything the request spent inside the worker: load + derive + flow."""
        return self.load_s + self.sink_s + self.elapsed_s

    @property
    def method_names(self) -> list[str]:
        """Method names across all flows, first-seen order."""
        seen: list[str] = []
        for flow in self.flows:
            for item in flow:
                name = item.get("method", "")
                if name and name not in seen:
                    seen.append(name)
        return seen


def _parse_report(text: str) -> FlowAnswer:
    """Read the report the query writes.

    `ELEM` carries the flow index so several flows stay distinguishable -- flattening them
    made one path look like it repeated itself (measured on the demo, which yields two).
    """
    answer = FlowAnswer()
    grouped: dict[int, list[dict]] = {}
    for line in text.splitlines():
        line = line.rstrip("\r")
        if line.startswith("ANCHOR\tSOURCE\t"):
            answer.source_candidates = int(line.split("\t")[2] or 0)
        elif line.startswith("ANCHOR\tSINK\t"):
            answer.sink_candidates = int(line.split("\t")[2] or 0)
        elif line.startswith("ANCHOR\tKIND\t"):
            answer.source_kind = line.split("\t")[2]
        elif line.startswith("ANCHOR\tEXPR\t"):
            answer.source_expr = "\t".join(line.split("\t")[2:])
        elif line.startswith("FLOW_COUNT\t"):
            answer.flow_count = int(line.split("\t")[1] or 0)
        elif line.startswith("ELEM\t"):
            # 7 fields: ELEM <flowIndex> <label> <method> <file> <line> <code>
            parts = line.split("\t")
            if len(parts) >= 7 and parts[1].isdigit():
                grouped.setdefault(int(parts[1]), []).append({
                    "label": parts[2],
                    "method": parts[3],
                    "file": parts[4],
                    "line": parts[5],
                    "code": parts[6],
                })
    answer.flows = [grouped[key] for key in sorted(grouped)]
    return answer


def _parse_sink_report(text: str, *, finding_path: str, finding_line: int) -> SinkResolution:
    """Read the sink-derivation report.

    Separate from the query so the decision it encodes is testable without a JVM: exactly one
    anchor is chosen (the first candidate), the alternatives are kept so a non-unique choice is
    visible, and `derived_from` is set only when something was actually chosen.
    """
    method = ""
    chosen = ""
    others: list[str] = []
    parameters: list[str] = []
    for line in text.splitlines():
        parts = line.rstrip("\r").split("\t")
        if parts[0] == "METHOD" and len(parts) >= 2:
            method = parts[1]
        elif parts[0] == "PARAM" and len(parts) >= 2:
            if parts[1] and parts[1] not in parameters:
                parameters.append(parts[1])
        elif parts[0] == "CANDIDATE" and len(parts) >= 2:
            if parts[1] and parts[1] not in others:
                others.append(parts[1])
        elif parts[0] == "CHOSEN" and len(parts) >= 2:
            chosen = parts[1]
    return SinkResolution(
        anchor=chosen,
        derived_from=f"{finding_path}:{finding_line}" if chosen else None,
        method=method,
        parameters=parameters,
        alternatives=others,
    )


def _auto_source(anchor: SourceAnchor, resolution: SinkResolution) -> tuple[str, str]:
    """`(method, parameter)` for an `auto` anchor with no hint, or `("", "")` for anything else.

    The receiver is skipped: taint does not enter through `this`/`self`, and an anchor on one
    returns a path that proves nothing. When the method has no other parameter there is nothing to
    anchor on and the caller's configured default call anchor takes over -- the same last resort as
    before, minus the assumption that the default is a Python expression.
    """
    if anchor.kind != ANCHOR_AUTO or anchor.needle:
        return "", ""
    chosen = next(
        (name for name in resolution.parameters if name not in RECEIVER_PARAMETERS), ""
    )
    return (resolution.method, chosen) if chosen else ("", "")


@dataclass(frozen=True)
class Frontend:
    """The CPG frontend chosen for one workspace, and the evidence it was chosen on.

    A value object rather than a loose binary path because the choice travels: it decides the
    build argv, it keys the CPG cache, and it is what a reader needs in order to tell "the engine
    found nothing" from "we asked in a language this graph was never built in".
    """

    name: str
    suffix: str
    binary: Path
    #: Verbatim extra argv -- a Java classpath goes here. Kept on the value so the argv that built
    #: a graph is reconstructible from the thing that names the graph.
    extra_args: tuple[str, ...] = ()

    @property
    def key(self) -> str:
        """What the CPG cache directory and the session guard carry."""
        return self.name


class NoFrontend(JoernError):
    """No configured frontend covers this workspace's language.

    A named refusal rather than an empty graph, because the two are indistinguishable from every
    layer above this one: an empty graph makes every question come back "the anchor matches no
    node", which the validation stage reads as evidence about the code. The message carries the
    census and the configured suffixes, because the fix is an operator decision.
    """


class JoernWorker:
    """Owns one resident Joern server and answers flow queries against it.

    Single-threaded by contract: `flow()` takes a lock, because the Joern session holds one
    loaded graph and concurrent queries would interleave on it. Parallelism comes from many
    workers, not from concurrency inside one.
    """

    def __init__(
        self,
        config: DataflowConfig,
        *,
        workspace_root: Path,
        joern_bin: str = "joern",
        cpg_bin: str | None = None,
    ) -> None:
        self.config = config
        self.workspace_root = workspace_root
        self.joern_bin = joern_bin
        #: A forced frontend binary, or None. The deployment leaves it None and lets `frontend_for`
        #: decide per workspace from the suffix census -- a worker is routed a project by path, and
        #: its language is a fact about the tree rather than about the worker. Tests and one-off
        #: probes pin it.
        self.cpg_bin = cpg_bin
        self.index = worker_index()
        # Absolute inside the container; the mount point is the supervisor's own filesystem,
        # so no host/container translation is involved.
        self.cache_dir = Path(config.cache_dir).expanduser().resolve()
        # Two areas, on purpose. The CPG is a pure function of the workspace content **and the
        # frontend that built it**, so it is shareable across workers -- one worker can reuse what
        # another built, and resizing the fleet does not force a rebuild. Reports and Joern's own
        # project scratch are per-worker state, so they are keyed by index: two workers handling the
        # same project (which happens when the fleet is resized) would otherwise write the same file.
        self.shared_dir = self.cache_dir / "cpg"
        self.scratch_dir = self.cache_dir / f"worker-{self.index}"
        for path in (self.shared_dir, self.scratch_dir):
            path.mkdir(parents=True, exist_ok=True)
        self._server: subprocess.Popen | None = None
        #: `(workspace digest, frontend)` of the graph the live session holds. Both halves are
        #: needed: the same workspace has a different graph per frontend, and this guard decides
        #: whether the resident server has to be respawned.
        self._loaded: tuple[str, str] | None = None
        self._lock = threading.Lock()

    def frontend_for(self, workspace: Path) -> Frontend:
        """Which frontend builds this workspace's graph.

        Decided per workspace, not per worker: a worker is handed a project by path, and its
        language is a property of the tree. The choice is a **suffix census** rather than a
        configured answer, so adding a language is a config entry and not a code path.

        Two refusals, both deliberate. `NoFrontend` when nothing in the tree matches a configured
        suffix; `JoernUnavailable` when the frontend for the winning suffix is not installed.
        Neither may degrade to "build an empty graph": that is a wrong answer wearing the shape of
        a clean codebase. A missing *Java* frontend therefore does not take Python analysis down
        with it -- the check happens here, per workspace, not at startup.
        """
        if self.cpg_bin:
            binary = Path(self.cpg_bin)
            return Frontend(name=binary.name or "unknown", suffix="", binary=binary)

        census = suffix_census(workspace, set(self.config.cpg_frontends))
        suffix = dominant_suffix(census)
        if suffix is None:
            configured = ", ".join(sorted(self.config.cpg_frontends)) or "none configured"
            raise NoFrontend(
                f"nothing under {workspace} carries a suffix this deployment has a frontend for "
                f"({configured}); census={census or '{}'}. Refusing rather than building an empty "
                "graph, because an empty graph makes every question read as 'the value cannot "
                "reach the sink'"
            )
        name = self.config.cpg_frontends[suffix]
        binary = self.config.frontends_dir / name / "bin" / name
        if not binary.is_file():
            raise JoernUnavailable(
                f"frontend {name!r} for {suffix} is not installed at {binary} (census={census}). "
                "The worker image must ship it -- see services/dataflow/Dockerfile."
            )
        return Frontend(
            name=name,
            suffix=suffix,
            binary=binary,
            extra_args=tuple(self.config.cpg_frontend_args.get(suffix) or ()),
        )

    def graph_key(self, digest: str, frontend: Frontend) -> str:
        """Cache directory name for one workspace **under one frontend**.

        The frontend is part of the key, not decoration. `shared_dir` is shared by the whole fleet,
        and the key used to be a function of the workspace content alone -- so serving a second
        frontend, or merely reconfiguring one, would have answered from the graph the *previous*
        one built. A stale graph is a wrong answer while a needless rebuild is only slow, so the
        tie goes to the rebuild. `workspace_digest`'s own docstring records the same class of bug
        from when the digest hashed only `.py` files: two unrelated Java projects collided on
        `sha1("")` and the second was answered from the first one's graph.
        """
        return f"{digest}-{frontend.key}"

    # -- environment ---------------------------------------------------
    def check(self) -> None:
        """Confirm Joern is runnable. Raises JoernUnavailable, never a bare OSError."""
        import shutil

        if shutil.which(self.joern_bin) is None and not Path(self.joern_bin).is_file():
            raise JoernUnavailable(
                f"{self.joern_bin!r} is not executable in this container. The worker image "
                "must provide Joern; see services/dataflow/Dockerfile."
            )
        if self.cpg_bin is not None:
            if not Path(self.cpg_bin).is_file() and shutil.which(self.cpg_bin) is None:
                raise JoernUnavailable(
                    f"the forced frontend {self.cpg_bin!r} is missing. Unset it to let the worker "
                    "pick a frontend per workspace from the suffix census."
                )
            return
        # Per-frontend binaries are checked in `frontend_for`, not here: a deployment that has
        # configured a language whose frontend this image lacks must still be able to analyse the
        # languages it does have.
        if not self.config.frontends_dir.is_dir():
            raise JoernUnavailable(
                f"frontends directory {self.config.frontends_dir} does not exist. The worker image "
                "must ship Joern's frontends; see services/dataflow/Dockerfile."
            )

    # -- lifecycle -----------------------------------------------------
    @property
    def is_up(self) -> bool:
        return self._server is not None and self._server.poll() is None

    @property
    def loaded_project(self) -> str | None:
        """The digest of the workspace the live session holds, or None. Reported by `/health`."""
        return self._loaded[0] if self._loaded else None

    def start(self) -> float:
        """Confirm Joern is runnable. The server itself is started per project by `_load`.

        This used to spawn a throwaway "boot" server so that `/health` could report a live Joern
        before anyone had asked for a project. That was wasted work twice over: `/health` is answered
        by the supervisor and not by Joern, and the first real request then killed the boot server and
        started a second one immediately, paying two JVM starts for one answer. `check()` is the part
        that genuinely has to happen first, and it is cheap.
        """
        if self.is_up:
            return 0.0
        started = time.monotonic()
        self.check()
        return time.monotonic() - started

    def _spawn_server(self, graph: Path) -> None:
        """Start a Joern server whose session is bound to ``graph``.

        The graph goes on the **command line**, and that is the whole point. This Joern build
        (4.0.606) binds ``cpg`` from the graph the server was started with and does not provide
        ``importCpg`` in server mode at all. The previous implementation started the server on a
        throwaway graph and then called ``importCpg`` per request; in this build that call does not
        compile, and because the server still answers ``success: true`` with the compiler error on
        ``stdout``, the failure surfaced only as "the query finished but wrote no report" -- every
        dataflow answer was silently empty. Switching projects therefore means restarting the
        session: one server start per project instead of one per query.
        """
        port = self.config.worker_server_port
        log.info("dataflow: starting joern server on port %s with %s", port, graph,
                 extra={"stage": "dataflow"})
        self._server = subprocess.Popen(
            [self.joern_bin, "--server",
             "--server-host", "0.0.0.0",
             "--server-port", str(port),
             str(graph)],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            # Its own session, so `stop()` can signal the whole group. `joern` is a launcher script
            # that execs a JVM: killing only the child leaves the JVM holding the port.
            start_new_session=(os.name != "nt"),
            # Joern materialises project directories under its working directory. Giving each
            # worker its own keeps those artifacts out of the shared CPG area.
            cwd=str(self.scratch_dir),
        )
        if not self._wait_alive(timeout_s=self.config.worker_start_timeout_s):
            self.stop()
            raise JoernError("the Joern server did not answer within the start timeout")

    def stop(self) -> None:
        """Terminate the server **and everything it started**. Safe to call twice; never raises.

        The process *group* is what has to be signalled, not the child. `joern` is a launcher script
        that execs a JVM, so terminating the script left the JVM holding the server port and
        answering queries with whatever graph it had been started with. That was not hypothetical:
        it made a project switch look successful while every derived sink came back empty, because
        `_wait_alive` can only ask "does something answer on this port" and the survivor answered
        yes. `start_new_session` at spawn is what makes the group addressable here.
        """
        server, self._server = self._server, None
        self._loaded = None
        if server is None:
            return
        self._signal_server(server, signal.SIGTERM)
        try:
            server.wait(timeout=15)
        except Exception:  # noqa: BLE001
            self._signal_server(server, signal.SIGKILL)
            try:
                server.wait(timeout=10)
            except Exception:  # noqa: BLE001
                log.warning("the Joern server did not exit; the next start may not bind")
        self._await_port_released()

    @staticmethod
    def _signal_server(server: subprocess.Popen, signal_number: int) -> None:
        """Signal the whole process group where the platform has one, else just the child."""
        if hasattr(os, "killpg"):
            try:
                os.killpg(os.getpgid(server.pid), signal_number)
                return
            except OSError:
                pass  # already gone, or no group to signal
        try:
            server.kill()
        except Exception as exc:  # noqa: BLE001
            log.warning("failed to kill the Joern server: %s", exc)

    def _await_port_released(self, timeout_s: float = 20.0) -> None:
        """Wait until nothing answers on the server port.

        A restart is only a restart if the old session is gone. Because `_wait_alive` cannot tell a
        fresh server from a lingering one -- both answer HTTP on the same port -- waiting for the
        port to go quiet first turns "silently answered by the previous graph" into "slow".
        """
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self._post({"query": 'println("port probe")'}, timeout=3) is None:
                return
            time.sleep(0.5)
        log.warning("dataflow: port %s still answers after stop()", self._port())

    def _cpg_path(self, digest: str, frontend: Frontend) -> Path:
        return self.shared_dir / self.graph_key(digest, frontend) / "cpg.bin"

    def _run_cpg_builder(self, workspace: Path, out: Path, frontend: Frontend) -> None:
        """Build a CPG, then publish it by rename.

        The rename matters for a shared cache: two workers can be asked for the same project
        (the fleet was resized, or a worker restarted), and a reader must never see a
        half-written graph. Building into a temporary name and renaming makes the published
        file all-or-nothing, and both builders produce identical bytes anyway, so whichever
        wins is correct.

        `frontend.extra_args` is appended verbatim. For Java that is the type-information classpath
        (`--inference-jar-paths`), which is a refinement rather than a prerequisite: measured on a
        three-file fixture that references `HttpServletRequest` with no servlet jar available, the
        graph builds and a cross-file flow still comes out, because call nodes come from the source
        text whether or not their types resolve.
        """
        out.parent.mkdir(parents=True, exist_ok=True)
        staging = out.with_name(f"{out.name}.staging-{os.getpid()}")
        staging.unlink(missing_ok=True)
        argv = [str(frontend.binary), "-o", str(staging), str(workspace), *frontend.extra_args]
        log.info("dataflow: building CPG with %s (%s)", frontend.name, frontend.suffix or "forced")
        try:
            proc = subprocess.run(argv, capture_output=True, timeout=self.config.timeout_s)
        except subprocess.TimeoutExpired as exc:
            # A timeout is a *named* failure, not a 500. Measured reference so the message can say
            # whether the budget or the repository is the problem: 2341 Java files took 418 s and
            # produced a 15 MB graph, which fills 70% of the 600 s default -- so a bigger Java
            # project needs `AEGIS_DATAFLOW__TIMEOUT_S` raised before its first query, and the
            # message has to say that rather than dying as an unhandled exception.
            staging.unlink(missing_ok=True)
            raise JoernError(
                f"{frontend.name} did not finish building the graph within "
                f"{self.config.timeout_s:.0f}s (AEGIS_DATAFLOW__TIMEOUT_S). Reference measurement: "
                "2341 Java files -> 418s / 15 MB, so a repository this size is already at 70% of "
                "the default budget."
            ) from exc
        if proc.returncode != 0 or not staging.is_file():
            staging.unlink(missing_ok=True)
            tail = proc.stderr.decode("utf-8", "replace")[-400:]
            raise JoernError(f"{frontend.name} failed (rc={proc.returncode}): {tail}")
        os.replace(staging, out)

    # -- HTTP on localhost ---------------------------------------------
    def _port(self) -> int:
        return self.config.worker_server_port

    def _post(self, payload: dict, timeout: float = 120) -> dict | None:
        request = urllib.request.Request(
            f"http://127.0.0.1:{self._port()}/query",
            data=json.dumps(payload).encode("utf-8"),
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001
            log.debug("server POST failed: %s", exc)
            return None

    def _poll_result(self, uuid: str, *, timeout_s: float = 600) -> dict:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            request = urllib.request.Request(
                f"http://127.0.0.1:{self._port()}/result/{uuid}", method="GET")
            try:
                with urllib.request.urlopen(request, timeout=30) as response:
                    answer = json.loads(response.read().decode("utf-8"))
            except urllib.error.HTTPError as exc:
                answer = {"err": f"HTTP {exc.code}"}
            except Exception as exc:  # noqa: BLE001
                answer = {"err": str(exc)[:120]}
            if answer.get("success") is True:
                # Joern answers `success: true` even when the Scala failed to *compile*, with the
                # compiler output sitting in `stdout`. Believing the flag is what let a broken
                # `importCpg` call look like an empty graph: every query "succeeded" and wrote no
                # report, and the only symptom was a sink that could never be derived. Raising here
                # turns a silent empty answer into a named failure.
                self._raise_on_compiler_error(answer)
                return answer
            if answer.get("success") is False and "yet" not in str(answer.get("err")):
                raise JoernError(f"query failed: {answer.get('err')}")
            time.sleep(1.0)
        raise JoernError(f"query did not finish within {timeout_s:.0f}s")

    @staticmethod
    def _raise_on_compiler_error(answer: dict) -> None:
        """Fail loudly when the Scala did not compile, despite the server reporting success."""
        text = f"{answer.get('stdout') or ''}{answer.get('stderr') or ''}"
        if "error found" not in text and "Not found:" not in text:
            return
        clean = re.sub(r"\x1b\[[0-9;]*m", "", text)
        interesting = [
            line.strip() for line in clean.splitlines()
            if line.strip() and not line.strip().startswith("|")
        ]
        raise JoernError("the Joern query did not compile: " + " | ".join(interesting[:4])[:500])

    def _run_scala(self, scala: str, timeout_s: float = 600) -> None:
        posted = self._post({"query": scala}, timeout=120)
        if posted is None or not posted.get("uuid"):
            raise JoernError(f"the server did not accept the query: {posted}")
        self._poll_result(posted["uuid"], timeout_s=timeout_s)

    def _wait_alive(self, timeout_s: float) -> bool:
        deadline = time.monotonic() + timeout_s
        while time.monotonic() < deadline:
            if self._server is not None and self._server.poll() is not None:
                return False
            if self._post({"query": 'println("warmup")'}, timeout=10) is not None:
                return True
            time.sleep(2)
        return False

    # -- the public API -------------------------------------------------
    def analyse(
        self,
        *,
        workspace: Path,
        source: str = "",
        sink: str = "",
        finding_path: str | None = None,
        finding_line: int | None = None,
        anchor: SourceAnchor | None = None,
        timeout_s: float = 600,
    ) -> tuple[FlowAnswer, SinkResolution]:
        """Resolve the sink if needed, then run the flow query -- in **one** session lock.

        One lock on purpose: between deriving a sink and using it, another request could load a
        different project into the session, and the flow query would then run against the wrong
        graph. Deriving and querying under the same lock removes that window rather than
        narrowing it.

        `anchor` overrides `source`: it is how a caller says "the source is a *parameter* of a
        method" rather than "a call matching this text". Without one, `source` is used as a call
        anchor, which is what every existing caller does.
        """
        resolved_anchor = anchor or SourceAnchor(needle=source.strip())
        # Chosen outside the lock: the census only reads the filesystem, and holding the session
        # lock across a tree walk would block every other request for no reason. It can also
        # refuse -- `NoFrontend` / `JoernUnavailable` -- which is better raised before the lock.
        frontend = self.frontend_for(workspace)
        with self._lock:
            started = time.monotonic()
            digest, cold, cpg_cached = self._load(workspace, frontend)
            load_s = time.monotonic() - started
            scratch = self.scratch_dir / digest
            scratch.mkdir(parents=True, exist_ok=True)

            sink_s = 0.0
            resolution = SinkResolution(anchor=sink.strip())
            if not resolution.anchor:
                if finding_path and finding_line:
                    derive_started = time.monotonic()
                    resolution = self._derive_sink(
                        scratch, finding_path=finding_path, finding_line=finding_line
                    )
                    sink_s = time.monotonic() - derive_started
                else:
                    # No sink and no position to derive one from. Report it; do not guess.
                    return FlowAnswer(
                        cold=cold, cpg_cached=cpg_cached, load_s=load_s, frontend=frontend.name
                    ), resolution

            if not resolution.anchor:
                return FlowAnswer(
                    cold=cold, cpg_cached=cpg_cached, load_s=load_s, frontend=frontend.name
                ), resolution

            auto_method, auto_param = _auto_source(resolved_anchor, resolution)
            answer = self._run_flow(
                scratch,
                anchor=resolved_anchor,
                sink=resolution.anchor,
                timeout_s=timeout_s,
                auto_method=auto_method,
                auto_param=auto_param,
                fallback=self.config.source.strip(),
            )
            answer.cold = cold
            answer.cpg_cached = cpg_cached
            answer.load_s = load_s
            answer.sink_s = sink_s
            answer.frontend = frontend.name
            return answer, resolution

    def flow(self, *, source: str = "", sink: str, workspace: Path,
             anchor: SourceAnchor | None = None,
             timeout_s: float = 600) -> FlowAnswer:
        """Run one flow query with an explicit sink. Convenience for callers that have one."""
        answer, _ = self.analyse(
            workspace=workspace, source=source, sink=sink, anchor=anchor, timeout_s=timeout_s
        )
        return answer

    # -- internals (caller holds the lock) ------------------------------
    def _load(self, workspace: Path, frontend: Frontend) -> tuple[str, bool, bool]:
        """Make `workspace` the session's loaded project, built by `frontend`.

        Returns `(digest, was_cold, cpg_cached)`. `was_cold` is about **this session** -- it had
        to import the graph -- while `cpg_cached` is about the **CPG on disk**: a cold session
        over a cached CPG skips the build and only pays the import.

        The session guard is `(digest, frontend)`, not the digest alone: the same workspace has a
        different graph per frontend, so a digest-only guard would keep serving the old graph from
        a process that had been reconfigured -- or, worse, from one that had just been asked about
        a Java project after a Python one.
        """
        digest = workspace_digest(workspace)
        key = (digest, frontend.key)
        if self._loaded == key and self.is_up:
            return digest, False, True
        cpg = self._cpg_path(digest, frontend)
        cpg_cached = cpg.is_file()
        if not cpg_cached:
            self._run_cpg_builder(workspace, cpg, frontend)
        # Restart rather than import: see `_spawn_server` for why this build cannot swap the graph
        # in a live session. `stop()` clears the loaded key, so it is set only after the spawn.
        self.stop()
        self._spawn_server(cpg)
        self._loaded = key
        return digest, True, cpg_cached

    def _run_flow(self, workdir: Path, *, anchor: SourceAnchor, sink: str,
                  timeout_s: float, auto_method: str = "", auto_param: str = "",
                  fallback: str = "") -> FlowAnswer:
        """Run the flow query. `auto_method` / `auto_param` / `fallback` only matter for `auto`.

        They arrive as arguments because they are facts about the derived sink, not properties of
        the anchor the caller sent: the enclosing method of the hit and one of its parameters.
        """
        report_path = workdir / REPORT_NAME
        report_path.unlink(missing_ok=True)
        # Report what was *asked*, which for `auto` is the method and parameter the engine picked.
        # An empty flow has to be readable as "we asked this, and it matched nothing".
        source_expr = (
            f"{auto_method}({auto_param})"
            if anchor.kind == ANCHOR_AUTO and auto_method
            else anchor.expr
        )
        query = (
            FLOW_QUERY
            .replace(
                "%SOURCE_ANCHOR%",
                anchor.scala(auto_method=auto_method, auto_param=auto_param, fallback=fallback),
            )
            .replace("%SOURCE_KIND%", _report_field(anchor.kind))
            .replace("%SOURCE_EXPR%", _report_field(source_expr))
            .replace("%SINK%", _scala_literal(sink))
            .replace("%OUTPUT%", str(report_path))
        )
        started = time.monotonic()
        self._run_scala(query, timeout_s=timeout_s)
        if not report_path.is_file():
            raise JoernError(
                "the flow query finished but wrote no report; the Scala may not have run"
            )
        text = report_path.read_text(encoding="utf-8", errors="replace")
        report_path.unlink(missing_ok=True)
        answer = _parse_report(text)
        answer.elapsed_s = time.monotonic() - started
        return answer

    def _derive_sink(self, workdir: Path, *, finding_path: str,
                     finding_line: int) -> SinkResolution:
        report_path = workdir / SINK_REPORT_NAME
        report_path.unlink(missing_ok=True)
        query = (
            DERIVE_SINK_QUERY
            .replace("%FILE%", _scala_literal(Path(finding_path).name))
            .replace("%LINE%", str(int(finding_line)))
            .replace("%OUTPUT%", str(report_path))
        )
        self._run_scala(query)
        if not report_path.is_file():
            raise JoernError("the sink query finished but wrote no report")
        text = report_path.read_text(encoding="utf-8", errors="replace")
        report_path.unlink(missing_ok=True)

        resolution = _parse_sink_report(
            text, finding_path=finding_path, finding_line=finding_line
        )
        log.info(
            "dataflow: derived sink %r from %s:%s (method=%s, candidates=%s)",
            resolution.anchor, finding_path, finding_line, resolution.method,
            resolution.alternatives,
            extra={"stage": "dataflow"},
        )
        return resolution


def worker_index() -> int:
    """This worker's index, from the environment. The fleet sets it per container."""
    return int(os.getenv(INDEX_ENV, "0"))
