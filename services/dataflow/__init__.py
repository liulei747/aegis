"""Aegis dataflow worker fleet - the only place that knows how to invoke Joern.

One container per worker, each running a permanent `joern --server` as a **child process**
(`worker.py`) behind a small HTTP surface (`worker_app.py`):

    POST /v1/query   {workspace, source, finding_path, finding_line}
                  -> {flows[], source_candidates, sink_candidates, sink_anchor, ...}
    GET  /health                              -> {status, loaded, index}

There is **no `sink` in the pipeline's request**: the worker derives the anchor from the
finding's file and line, and reports what it chose. The field still exists on the API for a
caller that already has one (a rule's `pattern-sinks`), which is not the pipeline.

It never reads a bundle, never talks to a language server, and never writes to a repository.
Its inputs are a path and a start anchor; its output is the flow path.

Affinity -- which worker owns which project -- is the caller's job (`router.py`,
`worker_for(workspace, n)`), a pure function of the workspace content hash. Nothing here routes.

Why this is a service rather than a library call: Joern is a JVM inside a 5.9 GB image. Keeping
it behind HTTP means the extractor's image stays free of it, a project's graph stays resident
so queries answer in ~1 s instead of ~9 s, and a Joern crash cannot take the API down with it.
"""

from __future__ import annotations

from aegis_core.logging import get_logger

__all__ = ["__version__"]
log = get_logger(__name__)
__version__ = "0.1.0"
