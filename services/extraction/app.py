"""Aegis extraction service - LSP seam, call graph, assembly, packaging.

Split out of the API because it is the heavy, stateful, memory-hungry part:

* it holds a language server process per language (hundreds of MB, and a crashed
  server must not take the API down with it);
* one request can take minutes and is bounded by memory, not by request rate;
* it is the only component that needs the language-server toolchain installed.

Contract (see docs/SERVICE_TOPOLOGY.md):

    POST /v1/extract   {workspace, sarif_path?, rules, rule_config, budget, …}
                    -> {bundle_id, run_id, package_path, manifest, warnings}

The HTTP surface is the same as the gateway's `/v1/assemble`, minus the scan
service hop: extraction is told where the SARIF is and does the rest.
"""

from __future__ import annotations

import os

from fastapi import FastAPI

from aegis_core.logging import setup_logging

setup_logging(os.getenv("AEGIS_LOG_LEVEL", "INFO"))

app = FastAPI(
    title="Aegis extraction service",
    description="Locates methods via LSP, walks the call graph, assembles and packages bundles.",
    version="0.1.0",
)

# routes are registered by the router module below
from services.extraction.routes import router  # noqa: E402

app.include_router(router)
