"""HTTP surface of one Joern worker.

    POST /v1/query   {workspace, source, finding_path, finding_line}  ->  {flows, ...}
    GET  /health                                                      ->  {status, loaded, index}

`source` is required. The endpoint comes from **either** an explicit `sink` (a caller that
already has one, e.g. from a rule's `pattern-sinks`) **or** a finding position, which is what
the pipeline sends -- it never sends a sink, because naming the sink is naming the answer.
Neither is a 400, not a guess.

This service runs **inside the worker container**, next to the Joern install, and owns the
resident Joern server as a child process (see `worker.py` for why it is not a sibling
container). Requests are serialised internally; affinity -- which worker owns which project --
is the caller's job (`router.py`), so nothing here routes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from aegis_core.config import get_settings
from aegis_core.logging import get_logger, setup_logging
from aegis_core.workspace import workspace_digest
from services.dataflow.worker import (
    JoernError,
    JoernUnavailable,
    JoernWorker,
    SourceAnchor,
    worker_index,
)

log = get_logger(__name__)

app = FastAPI(title="Aegis Joern worker", version="0.1.0")
setup_logging(get_settings().log_level)

_INDEX = worker_index()
_config = get_settings().dataflow

#: One worker per container. The mount point is the container's own view of the workspace,
#: which is also what the Joern child process sees -- no path translation anywhere.
_worker = JoernWorker(_config, workspace_root=Path("/workspace"))


class QueryBody(BaseModel):
    workspace: str = Field(description="Repository path, as seen by this worker.")
    source: str = Field(
        default="",
        description=(
            "Start anchor: a call name. Ignored when `anchor_kind='parameter'`, where the source "
            "is a method's parameter instead -- see `anchor_method`."
        ),
    )
    anchor_kind: Literal["call", "parameter", "auto"] = Field(
        default="call",
        description=(
            "`call`: `source` is matched against call nodes. `parameter`: the source is a "
            "parameter of `anchor_method`, which is the node a caller-walk hands over -- and the "
            "one a call matcher cannot reach, because a parameter is not a call. `auto`: the "
            "engine decides against the graph, which is what a *finding* needs -- it says where the "
            "danger is and nothing about where the value entered."
        ),
    )
    anchor_method: str = Field(
        default="", description="Required when `anchor_kind='parameter'`."
    )
    anchor_parameter: str = Field(
        default="",
        description="Parameter name; empty means every parameter of `anchor_method`.",
    )
    sink: str = Field(
        default="",
        description=(
            "End anchor. Leave empty to derive it from the finding's position -- which is what "
            "the pipeline does, because the finding already says where the rule fired and an "
            "empty anchor is refused rather than guessed at."
        ),
    )
    finding_path: str | None = Field(
        default=None, description="Path of the finding, for sink derivation."
    )
    finding_line: int | None = Field(
        default=None, gt=0, description="1-based line of the finding, for sink derivation."
    )
    timeout_s: float = Field(default=600.0, gt=0, le=1800)


@app.get("/health")
def health() -> dict:
    """`status` is `ok` only when a Joern server is actually up and answering."""
    return {
        "status": "ok" if _worker.is_up else "cold",
        "loaded": _worker.loaded_project,
        "index": _INDEX,
        # Which languages this deployment can build a graph for, published the same way
        # `app/api/routes.py` publishes `deep_analysis.taint`: a client deciding whether to expect
        # a taint trace should not have to read this service's config to find out.
        "frontends": dict(sorted(_config.cpg_frontends.items())),
    }


@app.post("/v1/query")
def query(body: QueryBody) -> dict:
    if body.anchor_kind == "parameter" and not body.anchor_method.strip():
        raise HTTPException(
            status_code=400,
            detail="anchor_kind='parameter' needs anchor_method (which method the source enters)",
        )
    if body.anchor_kind == "call" and not body.source.strip():
        raise HTTPException(status_code=400, detail="source anchor must be non-empty")
    if body.anchor_kind == "auto" and not (body.finding_path and body.finding_line):
        raise HTTPException(
            status_code=400,
            detail=(
                "anchor_kind='auto' needs the finding position: that is what the enclosing method "
                "and its parameter are derived from. Without a hit there is nothing to derive from."
            ),
        )
    if not body.sink.strip() and not (body.finding_path and body.finding_line):
        raise HTTPException(
            status_code=400,
            detail=(
                "neither a sink anchor nor a finding position was given. This service will not "
                "guess a sink: an empty anchor matches every call in the program."
            ),
        )
    workspace = Path(body.workspace)
    if not workspace.is_dir():
        raise HTTPException(status_code=404, detail=f"workspace not found: {body.workspace}")

    try:
        anchor = SourceAnchor(
            kind=body.anchor_kind,
            needle=body.source.strip(),
            method=body.anchor_method.strip(),
            parameter=body.anchor_parameter.strip(),
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    try:
        start_s = _worker.start()
        answer, sink = _worker.analyse(
            workspace=workspace,
            sink=body.sink.strip(),
            anchor=anchor,
            finding_path=body.finding_path,
            finding_line=body.finding_line,
            timeout_s=body.timeout_s,
        )
    except JoernUnavailable as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except JoernError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc

    return {
        "workspace_digest": workspace_digest(workspace),
        "index": _INDEX,
        "cold": answer.cold,
        "cpg_cached": answer.cpg_cached,
        # Four numbers, not one. `elapsed_s` is the flow query alone, and reading it as the cost
        # of the request understated a warm query by half and a first query by eight times.
        "elapsed_s": round(answer.elapsed_s, 2),
        "load_s": round(answer.load_s, 2),
        "sink_elapsed_s": round(answer.sink_s, 2),
        "start_s": round(start_s, 2),
        "total_s": round(start_s + answer.total_s, 2),
        # Echo the anchor the query actually used, not what was asked for: when the flow is
        # empty, this is the only evidence of whether it was empty because of the anchor.
        "source_anchor": answer.source_expr or anchor.expr,
        "source_anchor_kind": answer.source_kind or anchor.kind,
        "sink_anchor": sink.anchor,
        "sink_derived_from": sink.derived_from,
        "sink_derivation_method": sink.method,
        "sink_derivation_alternatives": sink.alternatives,
        "source_candidates": answer.source_candidates,
        "sink_candidates": answer.sink_candidates,
        # Which frontend built the graph. An empty flow plus a frontend that does not match the
        # workspace is a different fact from an empty flow plus a matching one, and the caller
        # cannot compute this for itself -- only the worker did the census.
        "frontend": answer.frontend,
        "flows": answer.flows,
    }


@app.on_event("shutdown")
def shutdown() -> None:
    _worker.stop()
