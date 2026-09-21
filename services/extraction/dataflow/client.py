"""Dataflow over the worker fleet: affinity routing plus the contract the pipeline consumes.

The extraction pipeline never talks to Joern directly. It computes which worker owns the
project (`router.worker_for`, a pure function of the workspace content hash), sends that
worker one request, and gets back the flow. Two consequences worth naming:

* the extraction image stays free of Joern's 5.8 GB and its JVM;
* a worker crash cannot take the pipeline down, it only fails the request.

Method bodies are attached **here**, from the local filesystem, not returned by the worker.
The extraction service has the workspace mounted, and reading the bytes on disk is what makes
"the model sees the source as it is" true rather than aspirational.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path

from aegis_contracts.dataflow import FlowBundle, FlowElement, FlowMethodBody, TaintFlow
from aegis_core.config import DataflowConfig
from aegis_core.logging import get_logger
from aegis_core.workspace import PYTHON_SUFFIXES, iter_source_files
from services.dataflow.router import worker_for

log = get_logger(__name__)


class DataflowUnavailable(RuntimeError):
    """No worker could be reached for this project."""


class DataflowError(RuntimeError):
    """A worker answered and the analysis failed. Distinct from 'no flow found'."""


class WorkerDataflowClient:
    """`DataflowProvider` implementation backed by the worker fleet."""

    def __init__(self, config: DataflowConfig, *, workspace_root: Path) -> None:
        self.config = config
        self.workspace_root = workspace_root
        self._index = worker_for(workspace_root, config.worker_count)

    @property
    def url(self) -> str:
        return self.config.worker_url(self._index)

    @property
    def index(self) -> int:
        return self._index

    # -- transport ------------------------------------------------------
    def _request(self, path: str, *, payload: dict | None = None,
                 timeout: float = 60.0) -> dict:
        url = f"{self.url}{path}"
        data = json.dumps(payload).encode("utf-8") if payload is not None else None
        request = urllib.request.Request(
            url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST" if payload is not None else "GET",
        )
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                return json.loads(response.read().decode("utf-8"))
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:400]
            if exc.code in (502, 503):
                raise DataflowUnavailable(f"worker {self._index} could not analyse: {detail}") from exc
            raise DataflowError(f"worker {self._index} refused the request: {detail}") from exc
        except urllib.error.URLError as exc:
            raise DataflowUnavailable(
                f"worker {self._index} at {self.url} is unreachable: {exc.reason}"
            ) from exc

    def health(self) -> bool:
        """Is there a worker process that can serve this project?

        `cold` counts as reachable. The worker answers `cold` until its resident Joern server is
        up, and it starts that server *inside* the request that needs it -- so a `cold` worker
        will serve the query, just slower the first time (~11 s, see `docs/DATAFLOW_CONTRACT.md`
        §8.1). Requiring `ok` here turned that wait into "dataflow is unavailable, fall back to
        the crawl", which silently produced a bundle without the sanitizer: measured, the first
        extraction after a worker container started degraded even though the worker was healthy
        and answering.
        """
        try:
            body = self._request("/health", timeout=10.0)
        except (DataflowUnavailable, DataflowError):
            return False
        return body.get("status") in ("ok", "cold")

    # -- the provider protocol ------------------------------------------
    def extract(
        self,
        *,
        force_build: bool = False,
        finding_path: str | None = None,
        finding_line: int | None = None,
        source_kind: str = "call",
        source_method: str = "",
        source_parameter: str = "",
    ) -> FlowBundle:
        """Analyse the workspace this client is bound to.

        `force_build` is accepted for protocol compatibility and ignored: the worker caches the
        CPG by content hash, and a rebuild is triggered by the content changing, which is the
        only condition under which it is correct.

        `source_kind="parameter"` names the source as a **parameter of a method** instead of a
        call: that is what the builder's caller walk produces, and it is the only shape that
        reaches an entry point -- a method name sent as a call anchor resolves to the call site
        and returns no flow at all.
        """
        _ = force_build
        payload = {
            # The worker's view of the workspace, which is not necessarily this process's view.
            # Sending the local path when they differ is a 404 ("workspace not found"): compose
            # makes them agree, a host-side caller has to say so.
            "workspace": self.config.worker_workspace or str(self.workspace_root),
            "source": self.config.source,
            "anchor_kind": source_kind,
            "timeout_s": float(self.config.timeout_s),
            # No `sink`: the worker derives it from the finding position below. Sending a
            # configured one would be handing over the answer.
        }
        if source_kind == "parameter":
            payload["anchor_method"] = source_method
            payload["anchor_parameter"] = source_parameter
        if finding_path is not None:
            payload["finding_path"] = finding_path
        if finding_line is not None:
            payload["finding_line"] = int(finding_line)

        body = self._request("/v1/query", payload=payload,
                             timeout=self.config.timeout_s + 120)

        bundle = FlowBundle(
            source_anchor=str(body.get("source_anchor") or self.config.source),
            source_kind=str(body.get("source_anchor_kind") or source_kind),
            source_expr=str(body.get("source_anchor") or ""),
            sink_anchor=str(body.get("sink_anchor") or ""),
            sink_derived_from=body.get("sink_derived_from"),
            sink_derivation_method=str(body.get("sink_derivation_method") or ""),
            sink_derivation_alternatives=list(body.get("sink_derivation_alternatives") or []),
            engine=f"joern-worker/{body.get('index')}",
            frontend=str(body.get("frontend") or ""),
            source_candidates=int(body.get("source_candidates") or 0),
            sink_candidates=int(body.get("sink_candidates") or 0),
            from_cache=bool(body.get("cpg_cached")),
            flows=[
                TaintFlow(
                    index=index,
                    elements=[
                        FlowElement(
                            label=str(item.get("label", "")),
                            code=str(item.get("code", "")),
                            method=str(item.get("method", "")),
                            file=(
                                Path(str(item.get("file", ""))).name
                                if item.get("file")
                                else ""
                            ),
                            line=str(item.get("line", "")),
                        )
                        for item in elements
                    ],
                )
                for index, elements in enumerate(body.get("flows") or [])
            ],
        )
        bundle.method_bodies = attach_bodies(bundle, self.workspace_root)
        log.info(
            "dataflow: worker %s returned %d flow(s) across %d method(s) in %.1fs "
            "(load %.1fs, sink %.1fs, flow %.1fs)",
            self._index, len(bundle.flows), len(bundle.path_methods),
            float(body.get("total_s") or 0.0),
            float(body.get("load_s") or 0.0),
            float(body.get("sink_elapsed_s") or 0.0),
            float(body.get("elapsed_s") or 0.0),
            extra={"stage": "dataflow"},
        )
        return bundle


def attach_bodies(bundle: FlowBundle, workspace: Path) -> list[FlowMethodBody]:
    """Read the full source of every method named on the flow, from the workspace itself.

    The flow says which file each method lives on, so that is tried first; the fallback scan
    covers a flow element whose location the engine could not supply.
    """
    wanted = bundle.path_methods
    if not wanted:
        return []

    on_flow: dict[str, str] = {}
    for flow in bundle.flows:
        for element in flow.elements:
            if element.method and element.file and element.method not in on_flow:
                on_flow[element.method] = element.file

    bodies: list[FlowMethodBody] = []
    for name in wanted:
        candidates: list[Path] = []
        if name in on_flow:
            candidates.append(workspace / on_flow[name])
        candidates += [p for p in iter_source_files(workspace, PYTHON_SUFFIXES)
                       if p not in candidates]
        for path in candidates:
            if not path.is_file():
                continue
            found = _find_def(path, name)
            if found is not None:
                start, source = found
                bodies.append(FlowMethodBody(
                    method=name,
                    file=path.name,
                    start_line=start,
                    end_line=start + len(source.splitlines()) - 1,
                    source=source,
                ))
                break
    return bodies


def _find_def(path: Path, name: str) -> tuple[int, str] | None:
    """Locate ``def name(...)`` and return (1-based start line, body text)."""
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return None
    for index, line in enumerate(lines):
        stripped = line.lstrip()
        if not (stripped.startswith(f"def {name}(")
                or stripped.startswith(f"async def {name}(")):
            continue
        body = [line]
        for following in lines[index + 1:]:
            if following.strip() and not following.startswith((" ", "\t")):
                break
            body.append(following)
        while body and not body[-1].strip():
            body.pop()
        return index + 1, "\n".join(body)
    return None


__all__ = ["DataflowError", "DataflowUnavailable", "WorkerDataflowClient", "attach_bodies"]
