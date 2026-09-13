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

import shutil
from pathlib import Path

from aegis_core.config import get_settings
from services.extraction.lsp.manager import LanguageServerManager, load_catalog


def installable_languages() -> tuple[list[str], list[str]]:
    """(languages whose server binary is on PATH, languages the catalog lists without one).

    Cheap on purpose -- a PATH lookup per catalog entry, no process started -- so an endpoint
    can answer "what can this deployment actually analyse?" without spawning six servers. That
    distinction is the point: a catalog entry is an intention, and an image without ``jdtls``
    lists Java while being unable to serve it.
    """
    manager = load_catalog(
        get_settings().lsp_config_file,
        root=get_settings().workspace_root,
        timeout_s=get_settings().lsp_request_timeout_s,
    )
    return manager.installable()


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
        # One row per *language*, using the spec that will actually be chosen for it.
        #
        # This used to iterate every catalog entry and ask `manager.client_for(probe_file)`,
        # which resolves by extension -- so the second entry for a language silently reported
        # the first one's client. With pyright and jedi both in the catalog for python, the
        # probe answered "jedi-language-server: available" on an image where jedi is not
        # installed: a status page that could not be wrong in a way anyone would notice.
        seen: set[str] = set()
        for spec in manager.catalog:
            if spec.language in seen:
                continue
            seen.add(spec.language)
            key = f"{spec.language}:{' '.join(spec.command)}"
            if not spec.enabled:
                missing[key] = {"extensions": spec.extensions, "reason": "目录中已禁用"}
                continue
            binary = spec.command[0] if spec.command else ""
            if not binary or shutil.which(binary) is None:
                missing[key] = {
                    "extensions": spec.extensions,
                    "reason": f"镜像里没有 {binary or '(未指定命令)'}",
                }
                continue
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
