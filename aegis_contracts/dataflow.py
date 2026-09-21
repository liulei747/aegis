"""Dataflow contract: the complete inter-procedural flow, as produced by Joern.

Field names and semantics are fixed by ``docs/DATAFLOW_CONTRACT.md``, which was written from
real output rather than designed up front. Two details there are easy to get wrong and are
therefore encoded in the validators below:

* ``FlowElement.line`` is a **string** and may be empty -- Joern's ``lineNumber`` is optional,
  and ``BLOCK`` nodes belong to no method, so `method`/`file` can be empty too.
* An empty ``flow`` is a **valid answer** (the taint never reaches the sink), not a failure.
  It is how a correctly parameterised query comes back.

This module deliberately imports nothing from ``aegis_core``: the contracts -> core edge is
pinned at exactly one import site (``domain.estimate_tokens``), guarded by a test.
"""

from __future__ import annotations

from pydantic import BaseModel, Field


class FlowElement(BaseModel):
    """One vertex on the taint path. Order in the list is the propagation order."""

    label: str = Field(description="Joern vertex type, e.g. CALL, IDENTIFIER, METHOD_PARAMETER_IN.")
    code: str = Field(default="", description="Source text at this vertex, trimmed.")
    method: str = Field(default="", description="Owning method name. EMPTY for BLOCK vertices.")
    file: str = Field(default="", description="File basename. EMPTY when method is empty.")
    line: str = Field(
        default="",
        description=(
            "1-based line number AS A STRING, or empty when Joern has none. Kept as a string "
            "on purpose: the source value is Optional[Int], and coercing it to int here would "
            "force a sentinel that readers then have to special-case again."
        ),
    )

    @property
    def located(self) -> bool:
        """True when this element can be pointed at in a file."""
        return bool(self.method and self.file and self.line)

    @property
    def line_number(self) -> int | None:
        """The line as an int, or None when absent/unparseable. Never raises."""
        return int(self.line) if self.line.isdigit() else None


class FlowMethodBody(BaseModel):
    """The complete source of one method on the flow."""

    method: str
    file: str
    start_line: int = Field(ge=1, description="1-based, inclusive.")
    end_line: int = Field(ge=1, description="1-based, inclusive.")
    source: str = Field(description="Full body including the definition line; no line numbers.")


class TaintFlow(BaseModel):
    """One complete path from a source to a sink.

    Kept as a list of flows rather than one flat element list, because Joern legitimately
    returns several, and flattening them makes a single path look like it repeated itself: a
    reader must be able to tell "two candidate paths" from "one path with a loop".

    The original evidence was a demo run with `flow_count=2` (two paths, 16 and 20 elements).
    **That no longer reproduces** -- measured against the current fixture with four anchor forms
    (sink derived from `repo.py:6`, derived from `repo.py:7`, explicit `execute`, explicit
    `cursor.execute`), every run returns one 20-element flow across 4 files. So the shape is
    still required -- the engine *can* return several -- but this repo's demo is no longer an
    instance of it, and a test that expects two flows there would be asserting a memory.
    """

    index: int = Field(ge=0, description="Position in the engine's answer; stable ordering.")
    elements: list[FlowElement] = Field(default_factory=list)

    @property
    def methods(self) -> list[str]:
        """Method names on this path, first-seen order, deduped, blanks dropped."""
        seen: list[str] = []
        for element in self.elements:
            if element.method and element.method not in seen:
                seen.append(element.method)
        return seen

    @property
    def files(self) -> list[str]:
        seen: list[str] = []
        for element in self.elements:
            if element.file and element.file not in seen:
                seen.append(element.file)
        return seen


class FlowBundle(BaseModel):
    """What the extractor hands to the assembler."""

    source_anchor: str = Field(description="The requested start anchor (call name).")
    sink_anchor: str = Field(
        default="",
        description=(
            "The end anchor actually used. Empty means no sink could be resolved -- the query "
            "then finds nothing, and that is reported rather than filled in with a guess."
        ),
    )
    sink_derived_from: str | None = Field(
        default=None,
        description=(
            "`path:line` the sink was derived from, when it came from the finding rather than "
            "from configuration. The derivation is a heuristic, so where it came from is part "
            "of the evidence, not a debug detail."
        ),
    )
    sink_derivation_method: str = Field(
        default="",
        description="The method the derivation settled on, for auditing.",
    )
    sink_derivation_alternatives: list[str] = Field(
        default_factory=list,
        description=(
            "Other call names the derivation saw at or after the finding line, in line order. "
            "More than one means the choice was not unique and deserves a second look."
        ),
    )
    engine: str = Field(default="joern", description="Who produced this, for the audit trail.")
    #: Which CPG frontend built the graph this bundle came from. Carried because an empty flow has
    #: two causes a reader cannot otherwise separate: the anchor matched no node, and the graph was
    #: built in the wrong language. `source_candidates == 0` plus a frontend that does not match
    #: the workspace is the second case, and saying so is what keeps it from reading as
    #: "the value cannot reach the sink".
    frontend: str = Field(
        default="",
        description="CPG frontend that built the graph, e.g. `pysrc2cpg` / `javasrc2cpg`.",
    )
    source_kind: str = Field(
        default="call",
        description=(
            "How the source end was named: `call` (matched against call nodes) or `parameter` "
            "(a method's parameter, which is where an entry point actually receives input). "
            "Travels with the answer because an empty flow means something different for each."
        ),
    )
    source_expr: str = Field(
        default="",
        description=(
            "The source anchor as it read back from the engine, e.g. `handle_request(request)`. "
            "When `flows` is empty, this is the only evidence of whether it was empty because the "
            "anchor matched nothing or because the engine proved there is no path."
        ),
    )
    flows: list[TaintFlow] = Field(
        default_factory=list,
        description=(
            "Every source->sink path the engine found. EMPTY IS MEANINGFUL: it means the "
            "engine proved the value does not reach the sink, which is the answer for a "
            "parameterised query. It is not an extraction failure -- that raises instead."
        ),
    )
    source_candidates: int = Field(default=0, ge=0, description="How many start anchors matched.")
    sink_candidates: int = Field(default=0, ge=0, description="How many end anchors matched.")
    method_bodies: list[FlowMethodBody] = Field(default_factory=list)
    from_cache: bool = Field(default=False, description="True when the CPG was reused.")

    @property
    def reachable(self) -> bool:
        """False when the engine proved there is no taint path (not an extraction failure)."""
        return bool(self.flows)

    @property
    def path_methods(self) -> list[str]:
        """Union of method names across all flows, first-seen order."""
        seen: list[str] = []
        for flow in self.flows:
            for name in flow.methods:
                if name not in seen:
                    seen.append(name)
        return seen

    @property
    def element_count(self) -> int:
        return sum(len(flow.elements) for flow in self.flows)

    def located_elements(self) -> list[FlowElement]:
        return [e for flow in self.flows for e in flow.elements if e.located]
