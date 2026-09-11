"""Aegis scan service - the only place that knows how to invoke a scanner.

Contract (deliberately tiny, see docs/SERVICE_TOPOLOGY.md):

    POST /v1/scan   {workspace, rules, rule_config, include, exclude}
                 -> {engine, engine_version, findings[], sarif_path, scan_record, warnings}

It never reads a bundle, never talks to a language server, and never serves a page.
Its only inputs are a filesystem path and a rule configuration; its only output is
findings plus an honest record of how the scan was invoked.
"""

from __future__ import annotations

from aegis_core.logging import get_logger

__all__ = ["__version__"]
log = get_logger(__name__)
__version__ = "0.1.0"
