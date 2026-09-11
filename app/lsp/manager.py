"""Language server lifecycle + capability-gated queries.

Server processes are spawned lazily, one per configured language, and reused for
the whole run. Every query goes through :meth:`LanguageServerManager._call`,
which converts any LSP failure into an empty result plus a recorded degradation —
an analysis bundle is never aborted because one language server misbehaved.

NOTE: a catalog entry's ``command`` may contain the literal ``{root}`` placeholder,
which is substituted with the workspace root at load time. That makes catalog
entries portable between hosts and containers.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from app.core.logging import get_logger
from app.core.utils import to_uri
from app.lsp.client import LspClient
from app.lsp.protocol import ServerExited
from app.schemas.domain import Degradation

log = get_logger(__name__)


@dataclass
class LanguageServerSpec:
    language: str
    command: list[str]
    extensions: list[str] = field(default_factory=list)
    filenames: list[str] = field(default_factory=list)
    init_options: dict[str, Any] = field(default_factory=dict)
    settings: dict[str, Any] = field(default_factory=dict)
    enabled: bool = True

    def matches(self, path: Path) -> bool:
        if path.name in self.filenames:
            return True
        return path.suffix.lower() in {e.lower() for e in self.extensions}

    def language_id_map(self) -> dict[str, str]:
        mapping = {e.lower(): self.language for e in self.extensions}
        for name in self.filenames:
            mapping[name] = self.language
        return mapping


# Sensible, container-friendly defaults. Override with AEGIS_LSP_CONFIG_FILE.
DEFAULT_CATALOG: list[LanguageServerSpec] = [
    LanguageServerSpec(
        language="python",
        command=["pyright-langserver", "--stdio"],
        extensions=[".py", ".pyi"],
        init_options={"python": {"analysis": {"autoSearchPaths": True, "useLibraryCodeForTypes": True}}},
    ),
    LanguageServerSpec(
        language="python",
        command=["jedi-language-server"],
        extensions=[".py", ".pyi"],
    ),
    LanguageServerSpec(
        language="typescript",
        command=["typescript-language-server", "--stdio"],
        extensions=[".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"],
        init_options={"hostInfo": "aegis", "preferences": {"includeInlayParameterNameHints": "none"}},
    ),
    LanguageServerSpec(
        language="go",
        command=["gopls"],
        extensions=[".go"],
        settings={"gopls": {"ui": {"documentation": {"hoverKind": "NoDocumentation"}}}},
    ),
    LanguageServerSpec(
        language="rust",
        command=["rust-analyzer"],
        extensions=[".rs"],
    ),
    LanguageServerSpec(
        language="java",
        command=["jdtls"],
        extensions=[".java"],
    ),
    LanguageServerSpec(
        language="c",
        command=["clangd", "--log=error", "--background-index"],
        extensions=[".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh"],
    ),
    LanguageServerSpec(
        language="php",
        command=["intelephense", "--stdio"],
        extensions=[".php"],
    ),
    LanguageServerSpec(
        language="ruby",
        command=["solargraph", "stdio"],
        extensions=[".rb"],
    ),
]


class LanguageServerManager:
    def __init__(
        self,
        *,
        root: Path,
        catalog: list[LanguageServerSpec] | None = None,
        timeout_s: float = 20.0,
    ) -> None:
        self.root = root.resolve()
        self.catalog = catalog or DEFAULT_CATALOG
        self.timeout_s = timeout_s
        self._clients: dict[str, LspClient] = {}
        self._lock = threading.Lock()
        self.degradations: list[Degradation] = []
        self._missing: set[str] = set()

    # ------------------------------------------------------------------
    @classmethod
    def from_config_file(cls, path: Path, *, root: Path, timeout_s: float = 20.0):
        specs: list[LanguageServerSpec] = []
        doc = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        for entry in doc.get("servers") or []:
            command = [str(part).replace("{root}", str(root)) for part in entry["command"]]
            specs.append(
                LanguageServerSpec(
                    language=entry["language"],
                    command=command,
                    extensions=list(entry.get("extensions") or []),
                    filenames=list(entry.get("filenames") or []),
                    init_options=entry.get("init_options") or {},
                    settings=entry.get("settings") or {},
                    enabled=bool(entry.get("enabled", True)),
                )
            )
        return cls(root=root, catalog=specs, timeout_s=timeout_s)

    # ------------------------------------------------------------------
    def spec_for(self, path: Path) -> LanguageServerSpec | None:
        for spec in self.catalog:
            if spec.enabled and spec.matches(path):
                return spec
        return None

    def supported(self, path: Path) -> bool:
        spec = self.spec_for(path)
        if spec is None:
            return False
        return self._spec_key(spec) not in self._missing

    @staticmethod
    def _spec_key(spec: LanguageServerSpec) -> str:
        return f"{spec.language}:{' '.join(spec.command)}"

    def client_for(self, path: Path) -> LspClient | None:
        spec = self.spec_for(path)
        if spec is None:
            self._note_once(
                f"no-language-server:{path.suffix}",
                Degradation(
                    capability="lsp",
                    reason=f"no language server configured for '{path.suffix or path.name}'",
                    impact="method location and call graph fall back to syntax heuristics",
                    path=str(path),
                    language=path.suffix.lstrip(".") or None,
                ),
            )
            return None
        key = self._spec_key(spec)
        with self._lock:
            client = self._clients.get(key)
            if client is not None and client.alive:
                return client
            if key in self._missing:
                return None
            try:
                client = LspClient(
                    name=f"{spec.language}",
                    command=spec.command,
                    root=self.root,
                    language_id_map=spec.language_id_map(),
                    default_timeout_s=self.timeout_s,
                    init_options=spec.init_options,
                    settings=spec.settings,
                )
                client.start()
            except Exception as exc:
                self._missing.add(key)
                log.warning("language server unavailable (%s): %s", spec.language, exc)
                self._note_once(
                    f"server-failed:{key}",
                    Degradation(
                        capability="lsp",
                        reason=f"language server '{' '.join(spec.command)}' failed to start: {exc}",
                        impact="method location and call graph fall back to syntax heuristics",
                        language=spec.language,
                    ),
                )
                return None
            self._clients[key] = client
            return client

    def _note_once(self, key: str, degradation: Degradation) -> None:
        if any(d.reason == degradation.reason for d in self.degradations):
            return
        self.degradations.append(degradation)

    def stop_all(self) -> None:
        with self._lock:
            clients = list(self._clients.values())
            self._clients.clear()
        for client in clients:
            try:
                client.stop()
            except Exception:  # pragma: no cover - best effort teardown
                log.debug("failed to stop LSP client", exc_info=True)

    def capabilities(self) -> dict[str, Any]:
        out: dict[str, Any] = {}
        with self._lock:
            clients = dict(self._clients)
        for key, client in clients.items():
            out[key] = {
                "server": client.server_info.get("name"),
                "callHierarchy": client.supports("callHierarchyProvider"),
                "documentSymbol": client.supports("documentSymbolProvider"),
                "definition": client.supports("definitionProvider"),
                "references": client.supports("referencesProvider"),
                "implementation": client.supports("implementationProvider"),
            }
        return out

    # ------------------------------------------------------------------
    # capability-gated queries - all failures degrade to empty results
    # ------------------------------------------------------------------
    def _call(
        self,
        client: LspClient,
        method: str,
        params: Any,
        *,
        capability: tuple[str, ...] | None = None,
        requires_open: Path | None = None,
    ) -> Any:
        if capability is not None and not client.supports(*capability):
            return None
        try:
            if requires_open is not None:
                client.open_document(requires_open)
            return client.request(method, params, timeout=self.timeout_s, raise_on_error=True)
        except TimeoutError:
            log.warning("LSP %s timed out on %s", client.name, method)
            return None
        except ServerExited as exc:
            log.warning("LSP %s gone during %s: %s", client.name, method, exc)
            return None
        except Exception as exc:
            log.debug("LSP %s %s failed: %s", client.name, method, exc)
            return None

    def document_symbols(self, client: LspClient, path: Path, text: str | None = None) -> Any:
        uri = client.open_document(path, text)
        client.settle_document(path)
        return self._call(
            client,
            "textDocument/documentSymbol",
            {"textDocument": {"uri": uri}},
            capability=("documentSymbolProvider",),
        )

    def definition(self, client: LspClient, path: Path, pos: dict[str, int]) -> Any:
        return self._call(
            client,
            "textDocument/definition",
            {"textDocument": {"uri": to_uri(path)}, "position": pos},
            capability=("definitionProvider",),
        )

    def references(
        self, client: LspClient, path: Path, pos: dict[str, int], *, include_declaration: bool = False
    ) -> Any:
        return self._call(
            client,
            "textDocument/references",
            {
                "textDocument": {"uri": to_uri(path)},
                "position": pos,
                "context": {"includeDeclaration": include_declaration},
            },
            capability=("referencesProvider",),
        )

    def implementation(self, client: LspClient, path: Path, pos: dict[str, int]) -> Any:
        return self._call(
            client,
            "textDocument/implementation",
            {"textDocument": {"uri": to_uri(path)}, "position": pos},
            capability=("implementationProvider",),
        )

    def prepare_call_hierarchy(self, client: LspClient, path: Path, pos: dict[str, int]) -> Any:
        return self._call(
            client,
            "textDocument/prepareCallHierarchy",
            {"textDocument": {"uri": to_uri(path)}, "position": pos},
        )

    def incoming_calls(self, client: LspClient, item: dict[str, Any]) -> Any:
        return self._call(client, "callHierarchy/incomingCalls", {"item": item})

    def outgoing_calls(self, client: LspClient, item: dict[str, Any]) -> Any:
        return self._call(client, "callHierarchy/outgoingCalls", {"item": item})


def load_catalog(config_file: Path | None, *, root: Path, timeout_s: float) -> LanguageServerManager:
    if config_file is not None and Path(config_file).exists():
        log.info("loading LSP catalog from %s", config_file)
        return LanguageServerManager.from_config_file(Path(config_file), root=root, timeout_s=timeout_s)
    return LanguageServerManager(root=root, timeout_s=timeout_s)
