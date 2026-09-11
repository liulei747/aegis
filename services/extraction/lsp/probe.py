"""Which language servers can this process actually start?

Lives with the LSP capability rather than in the gateway, because it is *this*
capability that owns the language-server processes: asking the gateway would answer
about a different filesystem and a different set of installed servers.

It used to live in ``app/api/deps.py``, which is what made
``services.extraction.routes`` import the gateway package and turned the two
top-level packages into a cycle. ``tests/test_contracts.py`` now asserts that the
``services -> app`` edge count is zero, so moving it back would fail the suite.
"""

from __future__ import annotations

from pathlib import Path

from aegis_core.config import get_settings
from services.extraction.lsp.manager import LanguageServerManager, load_catalog


def probe_lsp(workspace: Path) -> tuple[LanguageServerManager, dict, dict]:
    """Spawn one client per configured server and report what answered.

    Returns ``(manager, available, missing)``. The manager is handed back (already
    stopped) so the caller can read ``manager.degradations``: a server that could not
    start is the interesting part of this answer, not the ones that could.
    """
    settings = get_settings()
    manager = load_catalog(
        settings.lsp_config_file,
        root=workspace,
        timeout_s=settings.lsp_request_timeout_s,
    )
    available: dict[str, object] = {}
    missing: dict[str, object] = {}
    try:
        for spec in manager.catalog:
            key = f"{spec.language}:{' '.join(spec.command)}"
            probe_file = workspace / f"__aegis_probe__{spec.extensions[0] if spec.extensions else '.txt'}"
            client = manager.client_for(probe_file)
            if client is None:
                missing[key] = {"extensions": spec.extensions}
            else:
                available[key] = {
                    "extensions": spec.extensions,
                    "server": client.server_info.get("name"),
                    "callHierarchy": client.supports("callHierarchyProvider"),
                    "documentSymbol": client.supports("documentSymbolProvider"),
                    "definition": client.supports("definitionProvider"),
                    "references": client.supports("referencesProvider"),
                    "implementation": client.supports("implementationProvider"),
                }
        return manager, available, missing
    finally:
        manager.stop_all()
