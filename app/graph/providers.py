"""Call-graph providers.

Provider ladder, best evidence first:

======================  ==================================================
provider                what it gives us
======================  ==================================================
LSP call hierarchy     true caller/callee edges with call-site ranges
LSP definition         callee resolution from lexical call sites
LSP implementation     abstract -> concrete dispatch targets
LSP references         caller candidates (any reference, filtered by scope)
syntax regex           best-effort, lowest confidence, never claims certainty
======================  ==================================================

Every edge carries its provider and a confidence, so downstream AI and humans
can weigh a ``gopls`` edge differently from a regex guess.
"""

from __future__ import annotations

import re
import threading
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from aegis_contracts.domain import (
    CallEdge,
    CodeRegion,
    EdgeDirection,
    MethodSymbol,
    Provider,
    SymbolKind,
)
from aegis_core.logging import get_logger
from aegis_core.utils import from_uri, normalize_snippet, sha1
from app.graph.resolver import SymbolIndex, Workspace
from app.lsp.manager import LanguageServerManager
from app.lsp.protocol import LspRange
from app.lsp.symbols import RawSymbol, find_enclosing

log = get_logger(__name__)

CONFIDENCE = {
    Provider.LSP_CALL_HIERARCHY: 1.0,
    Provider.LSP_DEFINITION: 0.9,
    Provider.LSP_IMPLEMENTATION: 0.8,
    Provider.LSP_REFERENCES: 0.6,
    Provider.SYNTAX_REGEX: 0.4,
    Provider.FILE_RANGE: 0.2,
}

_KIND_BY_LSP = {
    6: SymbolKind.METHOD,
    9: SymbolKind.CONSTRUCTOR,
    12: SymbolKind.FUNCTION,
    25: SymbolKind.METHOD,
    5: SymbolKind.CLASS,
    23: SymbolKind.CLASS,
    2: SymbolKind.MODULE,
    3: SymbolKind.MODULE,
    4: SymbolKind.MODULE,
}

# Used only when no language server owns the file type (degraded, syntax-only runs).
_LANGUAGE_BY_SUFFIX = {
    ".py": "python",
    ".pyi": "python",
    ".js": "javascript",
    ".jsx": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".kt": "kotlin",
    ".c": "c",
    ".h": "c",
    ".cc": "cpp",
    ".cpp": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".hh": "cpp",
    ".cs": "csharp",
    ".php": "php",
    ".rb": "ruby",
    ".swift": "swift",
    ".scala": "scala",
}


@dataclass
class Resolution:
    """A resolved method plus the provider that produced it."""

    method: MethodSymbol
    provider: Provider


class CallGraphResolver:
    """Shared, thread-safe. All LSP access is serialized per language server."""

    def __init__(
        self,
        workspace: Workspace,
        index: SymbolIndex,
        lsp: LanguageServerManager | None,
        *,
        timeout_s: float = 20.0,
    ) -> None:
        self.workspace = workspace
        self.index = index
        self.lsp = lsp
        self.timeout_s = timeout_s
        self._lock = threading.RLock()
        self._file_locks: dict[str, threading.Lock] = defaultdict(threading.Lock)
        self._def_cache: dict[tuple[str, int, int], MethodSymbol | None] = {}
        self._method_cache: dict[tuple[str, int, int], MethodSymbol | None] = {}
        self._impl_cache: dict[str, list[MethodSymbol]] = {}
        self._ref_cache: dict[str, list[MethodSymbol]] = {}
        self.degradations: list[str] = []

    # ------------------------------------------------------------------
    # helpers
    # ------------------------------------------------------------------
    def region_of(self, rel: str, rng: LspRange) -> CodeRegion:
        line_index = self.workspace.index(rel)
        end_line, end_char = self._trim_trailing_blank_lines(
            rel, rng.end.line, rng.end.character, start_line=rng.start.line
        )
        offsets: tuple[int | None, int | None] = (None, None)
        if line_index is not None:
            offsets = (
                line_index.offset_of(rng.start.line, rng.start.character),
                line_index.offset_of(end_line, end_char),
            )
        return CodeRegion(
            path=rel,
            start_line=rng.start.line,
            start_char=rng.start.character,
            end_line=end_line,
            end_char=end_char,
            start_offset=offsets[0],
            end_offset=offsets[1],
        )

    def _trim_trailing_blank_lines(
        self, rel: str, end_line: int, end_char: int, *, start_line: int
    ) -> tuple[int, int]:
        """Pull the range end back to the last line that is really ours.

        Language servers commonly define a symbol's range as "up to the next
        sibling symbol", which lands the end on the *next declaration's* first
        line (and swallows the blank lines between the two). That is not harmless:

        * the slice we hand to the model carries trailing blanks and a stray
          ``def ...:`` line belonging to the next method;
        * two providers locating the same function produce different extents, so
          their content hashes differ and content-based dedupe stops working;
        * ``method_id`` hashes the extent, so one function gets two ids depending
          on whether a language server was available.

        Two passes: drop trailing blank lines, then drop a trailing line that
        *starts another symbol* in this file. Only blanks and a foreign
        declaration are removed — never real code of ours.
        """
        line_index = self.workspace.index(rel)
        if line_index is None:
            return end_line, end_char

        last = min(end_line, line_index.line_count - 1)

        def is_blank(line: int) -> bool:
            return not line_index.line_text(line).strip()

        while last > start_line and is_blank(last):
            last -= 1

        if last > start_line:
            # A sibling symbol *starts* on this line (so the range ran one line
            # too far). Keying on the start line, not containment, is what makes
            # this correct: the next symbol's range also contains its own first
            # line, so a containment test would call it "ours".
            foreign = any(
                sym.range.start.line == last and sym.range.start.line != start_line
                for sym in self.index.symbols(rel)
            )
            if foreign or _looks_like_declaration(line_index.line_text(last).strip()):
                last -= 1
                while last > start_line and is_blank(last):
                    last -= 1

        if last >= end_line:
            return end_line, end_char
        return last, len(line_index.line_text(last))

    def symbol_from_raw(
        self,
        rel: str,
        raw: RawSymbol,
        *,
        provider: Provider,
        parent: str | None = None,
        language: str | None = None,
    ) -> MethodSymbol:
        region = self.region_of(rel, raw.range)
        kind = _KIND_BY_LSP.get(raw.kind, SymbolKind.FUNCTION)
        parent_path = raw.parent_path or ([parent] if parent else [])
        qualified = raw.qualified_name
        method_id = "M-" + sha1(rel, qualified, str(region.start_line), str(region.end_line), length=12)
        return MethodSymbol(
            method_id=method_id,
            name=raw.name,
            qualified_name=qualified,
            kind=kind,
            path=rel,
            region=region,
            language=language or self._language_of(rel),
            parent=".".join(parent_path) if parent_path else parent,
            provider=provider,
            detail=raw.detail,
            signature=raw.detail or raw.name,
        )

    def _language_of(self, rel: str) -> str | None:
        path = self.workspace.abs_path(rel)
        if self.lsp is not None:
            spec = self.lsp.spec_for(path)
            if spec is not None:
                return spec.language
        return _LANGUAGE_BY_SUFFIX.get(path.suffix.lower(), path.suffix.lstrip(".") or None)

    # ------------------------------------------------------------------
    # locate
    # ------------------------------------------------------------------
    def locate_method(self, rel: str, line: int, char: int = 0) -> tuple[MethodSymbol, Provider] | None:
        """Find the callable enclosing a hit. LSP documentSymbol first, syntax fallback."""
        key = (rel, line, char)
        with self._lock:
            if key in self._method_cache:
                cached = self._method_cache[key]
                return (cached, cached.provider) if cached else None

        result: tuple[MethodSymbol, Provider] | None = None

        raw = find_enclosing(self.index.symbols(rel), line, char, callable_only=True)
        if raw is not None:
            provider = self.index.provider_for(rel)
            symbol = self.symbol_from_raw(
                rel, raw, provider=provider or Provider.LSP_DOCUMENT_SYMBOL
            )
            result = (symbol, symbol.provider)
        else:
            parsed = self.workspace.parsed(rel)
            if parsed is not None:
                parser = self.workspace.syntax_parser(rel)
                scope = parser.method_at(parsed, line, char)
                if scope is not None:
                    # Same normalisation as the LSP path: stop at the last line
                    # that actually holds code, so both providers describe the
                    # same extent and therefore produce the same content hash.
                    end_line = scope.end_line
                    while end_line > scope.start_line and not parsed.line_text(end_line).strip():
                        end_line -= 1
                    region = CodeRegion(
                        path=rel,
                        start_line=scope.start_line,
                        start_char=0,
                        end_line=end_line,
                        end_char=len(parsed.line_text(end_line)),
                        # Byte offsets must be filled in: without them the reader
                        # falls back to a line slice and, with a missing upper
                        # bound, can hand over the whole file as this method body.
                        start_offset=parsed.line_starts[scope.start_line],
                        end_offset=(
                            parsed.line_starts[end_line + 1]
                            if end_line + 1 < len(parsed.line_starts)
                            else len(parsed.text)
                        ),
                    )
                    qualified = (
                        f"{scope.parent_hint}.{scope.name}" if scope.parent_hint else scope.name
                    )
                    symbol = MethodSymbol(
                        method_id="M-"
                        + sha1(
                            rel, qualified, str(region.start_line), str(region.end_line), length=12
                        ),
                        name=scope.name,
                        qualified_name=qualified,
                        kind=SymbolKind.FUNCTION,
                        path=rel,
                        region=region,
                        language=self._language_of(rel),
                        parent=scope.parent_hint,
                        provider=Provider.SYNTAX_REGEX,
                        signature=scope.signature,
                        detail="located by syntax heuristic",
                    )
                    result = (symbol, Provider.SYNTAX_REGEX)

        with self._lock:
            self._method_cache[key] = result[0] if result else None
        return result

    # ------------------------------------------------------------------
    # definition / implementation / references
    # ------------------------------------------------------------------
    def resolve_definition(self, rel: str, line: int, char: int) -> MethodSymbol | None:
        key = (rel, line, char)
        with self._lock:
            if key in self._def_cache:
                return self._def_cache[key]
        value = self._resolve_definition_uncached(rel, line, char)
        with self._lock:
            self._def_cache[key] = value
        return value

    def _resolve_definition_uncached(self, rel: str, line: int, char: int) -> MethodSymbol | None:
        if self.lsp is None:
            return None
        path = self.workspace.abs_path(rel)
        client = self.lsp.client_for(path)
        if client is None:
            return None
        payload = self.lsp.definition(client, path, {"line": line, "character": char})
        location = _first_location(payload)
        if location is None:
            return None
        return self._method_from_location(location, provider=Provider.LSP_DEFINITION)

    def implementations(self, method: MethodSymbol, *, limit: int = 5) -> list[MethodSymbol]:
        with self._lock:
            cached = self._impl_cache.get(method.method_id)
        if cached is not None:
            return cached[:limit]
        found: list[MethodSymbol] = []
        if self.lsp is not None:
            path = self.workspace.abs_path(method.path)
            client = self.lsp.client_for(path)
            if client is not None:
                pos = _selection_position(method, self.workspace)
                payload = self.lsp.implementation(client, path, pos)
                for location in _locations(payload):
                    symbol = self._method_from_location(
                        location, provider=Provider.LSP_IMPLEMENTATION
                    )
                    if symbol is not None and symbol.method_id != method.method_id:
                        found.append(symbol)
        found = _dedupe_symbols(found)
        with self._lock:
            self._impl_cache[method.method_id] = found
        return found[:limit]

    def references(self, method: MethodSymbol, *, limit: int = 50) -> list[MethodSymbol]:
        with self._lock:
            cached = self._ref_cache.get(method.method_id)
        if cached is not None:
            return cached[:limit]
        found: list[MethodSymbol] = []
        if self.lsp is not None:
            path = self.workspace.abs_path(method.path)
            client = self.lsp.client_for(path)
            if client is not None:
                pos = _selection_position(method, self.workspace)
                payload = self.lsp.references(client, path, pos, include_declaration=False)
                for location in _locations(payload):
                    caller = self._method_from_location(
                        location, provider=Provider.LSP_REFERENCES
                    )
                    if caller is not None and caller.method_id != method.method_id:
                        found.append(caller)
        found = _dedupe_symbols(found)
        with self._lock:
            self._ref_cache[method.method_id] = found
        return found[:limit]

    def _method_from_location(self, location: Any, *, provider: Provider) -> MethodSymbol | None:
        uri = location.get("uri") if isinstance(location, dict) else None
        rng_raw = location.get("range") if isinstance(location, dict) else None
        if not uri or not rng_raw:
            return None
        path = from_uri(uri)
        rel = self.workspace.rel(path)
        if self.workspace.read(rel) is None:
            return None
        rng = LspRange.from_wire(rng_raw)

        raw = find_enclosing(
            self.index.symbols(rel), rng.start.line, rng.start.character, callable_only=True
        )
        if raw is not None:
            symbol = self.symbol_from_raw(rel, raw, provider=provider)
            symbol.provider = provider
            return symbol

        # No symbols for that file: synthesize a method-shaped node from the
        # definition range itself (better than dropping the edge entirely).
        region = self.region_of(rel, rng)
        text = self.workspace.slice_lines(rel, region.start_line, region.end_line) or ""
        first_line = (text.splitlines() or [""])[0].strip()[:200]
        name = _guess_name(first_line) or Path(rel).stem
        method_id = "M-" + sha1(rel, name, str(region.start_line), str(region.end_line), length=12)
        return MethodSymbol(
            method_id=method_id,
            name=name,
            qualified_name=name,
            kind=SymbolKind.FUNCTION,
            path=rel,
            region=region,
            language=self._language_of(rel),
            provider=provider,
            signature=first_line,
            detail="synthesized from LSP definition range",
        )

    # ------------------------------------------------------------------
    # edges
    # ------------------------------------------------------------------
    def callees(
        self, method: MethodSymbol, *, limit: int
    ) -> tuple[list[tuple[MethodSymbol, CallEdge]], Provider]:
        """Edges method -> callee."""
        results: list[tuple[MethodSymbol, CallEdge]] = []
        provider = Provider.SYNTAX_REGEX

        hierarchy = self._call_hierarchy_children(method, direction=EdgeDirection.CALLEE)
        if hierarchy:
            provider = Provider.LSP_CALL_HIERARCHY
            for symbol, region, snippet in hierarchy[:limit]:
                results.append(
                    (symbol, self._edge(method, symbol, EdgeDirection.CALLEE, provider, region, snippet))
                )
            impls = self.implementations(method, limit=max(0, limit - len(results)))
            for impl in impls:
                results.append(
                    (
                        impl,
                        self._edge(
                            method,
                            impl,
                            EdgeDirection.CALLEE,
                            Provider.LSP_IMPLEMENTATION,
                            None,
                            "dispatch target",
                        ),
                    )
                )
            return results[:limit], provider

        # Fallback: lexical call sites + definition resolution.
        # LSP first (cross-file and accurate); a same-repository name match when
        # no server can answer, so a single-file repo still yields a real chain.
        parsed = self.workspace.parsed(method.path)
        if parsed is None:
            return [], Provider.NONE
        parser = self.workspace.syntax_parser(method.path)
        from app.parsers.syntax import Scope

        scope = Scope(
            name=method.name,
            start_line=method.region.start_line,
            end_line=method.region.end_line,
        )
        line_index = self.workspace.index(method.path)
        seen: set[str] = set()
        for site in parser.call_sites(parsed, scope):
            if len(results) >= limit:
                break
            if parser.local_definition(parsed, scope, site.name):
                continue
            target: MethodSymbol | None = None
            if self.lsp is not None and line_index is not None:
                target = self.resolve_definition(method.path, site.line, site.char)
            if target is None:
                target = self.workspace.find_local_method(site.name, near=method.path)
            if target is None:
                continue
            if target.method_id in seen or target.method_id == method.method_id:
                continue
            seen.add(target.method_id)
            region = CodeRegion(
                path=method.path,
                start_line=site.line,
                start_char=site.char,
                end_line=site.line,
                end_char=site.char + len(site.name),
            )
            resolved_by_lsp = target.provider is not Provider.SYNTAX_REGEX
            results.append(
                (
                    target,
                    self._edge(
                        method,
                        target,
                        EdgeDirection.CALLEE,
                        Provider.LSP_DEFINITION if resolved_by_lsp else Provider.SYNTAX_REGEX,
                        region,
                        site.snippet,
                    ),
                )
            )
            provider = Provider.LSP_DEFINITION if resolved_by_lsp else Provider.SYNTAX_REGEX
        return results[:limit], provider

    def callers(self, method: MethodSymbol, *, limit: int) -> tuple[list[tuple[MethodSymbol, CallEdge]], Provider]:
        """Edges caller -> method."""
        results: list[tuple[MethodSymbol, CallEdge]] = []
        provider = Provider.NONE

        hierarchy = self._call_hierarchy_children(method, direction=EdgeDirection.CALLER)
        if hierarchy:
            provider = Provider.LSP_CALL_HIERARCHY
            for symbol, region, snippet in hierarchy[:limit]:
                results.append(
                    (symbol, self._edge(symbol, method, EdgeDirection.CALLER, provider, region, snippet))
                )
            impls = self.implementations(method, limit=max(0, limit - len(results)))
            for impl in impls:
                for symbol, region, snippet in self._call_hierarchy_children(
                    impl, direction=EdgeDirection.CALLER
                )[: max(0, limit - len(results))]:
                    results.append(
                        (
                            symbol,
                            self._edge(
                                symbol, method, EdgeDirection.CALLER, provider, region, snippet
                            ),
                        )
                    )
            return _dedupe_edges(results)[:limit], provider

        # Fallback: raw references, keeping only references inside a callable.
        if self.lsp is None:
            return [], Provider.NONE
        refs = self.references(method, limit=limit)
        for ref in refs:
            results.append(
                (
                    ref,
                    self._edge(ref, method, EdgeDirection.CALLER, Provider.LSP_REFERENCES, None, "reference"),
                )
            )
        if results:
            provider = Provider.LSP_REFERENCES
        return results[:limit], provider

    def _call_hierarchy_children(
        self, method: MethodSymbol, *, direction: EdgeDirection
    ) -> list[tuple[MethodSymbol, CodeRegion | None, str]]:
        if self.lsp is None:
            return []
        path = self.workspace.abs_path(method.path)
        client = self.lsp.client_for(path)
        if client is None:
            return []
        if not client.supports("callHierarchyProvider"):
            self._note(f"language server for {method.language} has no callHierarchyProvider")
            return []
        pos = _selection_position(method, self.workspace)
        try:
            prepared = self.lsp.prepare_call_hierarchy(client, path, pos)
        except Exception:
            return []
        items = prepared if isinstance(prepared, list) else ([prepared] if prepared else [])
        if not items:
            return []
        item = items[0]
        payload = (
            self.lsp.incoming_calls(client, item)
            if direction is EdgeDirection.CALLER
            else self.lsp.outgoing_calls(client, item)
        )
        out: list[tuple[MethodSymbol, CodeRegion | None, str]] = []
        for entry in payload or []:
            target = entry.get("from") if direction is EdgeDirection.CALLER else entry.get("to")
            if not isinstance(target, dict):
                continue
            symbol = self._symbol_from_hierarchy_item(target)
            if symbol is None or symbol.method_id == method.method_id:
                continue
            region = None
            snippet = ""
            ranges = entry.get("fromRanges") or []
            if ranges:
                rng = LspRange.from_wire(ranges[0])
                region = self.region_of(symbol.path, rng)
                snippet = normalize_snippet(
                    self.workspace.slice_lines(symbol.path, rng.start.line, rng.start.line) or ""
                )
            out.append((symbol, region, snippet))
        return out

    def _symbol_from_hierarchy_item(self, item: dict[str, Any]) -> MethodSymbol | None:
        uri = item.get("uri")
        rng_raw = item.get("range")
        if not uri or not rng_raw:
            return None
        rel = self.workspace.rel(from_uri(uri))
        if self.workspace.read(rel) is None:
            return None
        rng = LspRange.from_wire(rng_raw)
        raw = find_enclosing(
            self.index.symbols(rel), rng.start.line, rng.start.character, callable_only=True
        )
        if raw is not None:
            symbol = self.symbol_from_raw(rel, raw, provider=Provider.LSP_CALL_HIERARCHY)
            if item.get("name") and raw.name != item.get("name"):
                symbol.name = item["name"]
                symbol.qualified_name = item["name"]
            return symbol
        region = self.region_of(rel, rng)
        name = item.get("name") or _guess_name(region.path) or "?"
        method_id = "M-" + sha1(rel, name, str(region.start_line), str(region.end_line), length=12)
        return MethodSymbol(
            method_id=method_id,
            name=name,
            qualified_name=name,
            kind=SymbolKind.FUNCTION,
            path=rel,
            region=region,
            language=self._language_of(rel),
            provider=Provider.LSP_CALL_HIERARCHY,
            detail=item.get("detail"),
        )

    def _edge(
        self,
        caller: MethodSymbol,
        callee: MethodSymbol,
        direction: EdgeDirection,
        provider: Provider,
        call_site: CodeRegion | None,
        snippet: str,
        *,
        confidence: float | None = None,
    ) -> CallEdge:
        return CallEdge(
            caller_id=caller.method_id,
            callee_id=callee.method_id,
            direction=direction,
            provider=provider,
            confidence=confidence if confidence is not None else CONFIDENCE.get(provider, 0.5),
            call_site=call_site,
            call_site_snippet=normalize_snippet(snippet, 160),
        )

    def _note(self, message: str) -> None:
        with self._lock:
            if message not in self.degradations:
                self.degradations.append(message)


_DECLARATION = re.compile(
    r"^(async\s+)?(def|class|function|func|fn|struct|interface|enum|impl|trait)\b"
)


def _looks_like_declaration(text: str) -> bool:
    """Cheap check: does this line start a new definition in any supported language?"""
    return bool(_DECLARATION.match(text))


def _declares_any(text: str, names: set[str]) -> bool:
    """True when this declaration line names one of ``names`` (i.e. it could be ours).

    A nested ``def`` inside the symbol we are trimming belongs to the symbol, so
    it must not be removed.
    """
    for name in names:
        if re.search(rf"\b{re.escape(name)}\s*\(", text) or re.search(
            rf"\b(def|class|function|func|fn|struct|interface|enum|impl|trait)\s+{re.escape(name)}\b",
            text,
        ):
            return True
    return False


# ----------------------------------------------------------------------
# module helpers
# ----------------------------------------------------------------------
def _first_location(payload: Any) -> dict[str, Any] | None:
    locations = _locations(payload)
    return locations[0] if locations else None


def _locations(payload: Any) -> list[dict[str, Any]]:
    if not payload:
        return []
    items = payload if isinstance(payload, list) else [payload]
    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        if "uri" in item and "range" in item:
            out.append({"uri": item["uri"], "range": item["range"]})
        elif "targetUri" in item:
            rng = item.get("targetSelectionRange") or item.get("targetRange")
            if rng:
                out.append({"uri": item["targetUri"], "range": rng})
        elif "location" in item and isinstance(item["location"], dict):
            loc = item["location"]
            if "uri" in loc and "range" in loc:
                out.append({"uri": loc["uri"], "range": loc["range"]})
    return out


def _selection_position(method: MethodSymbol, workspace: Workspace) -> dict[str, int]:
    """Smallest safe position for symbol queries: start of the identifier line."""
    line_index = workspace.index(method.path)
    line = method.region.start_line
    char = method.region.start_char
    if line_index is not None:
        text = line_index.line_text(line)
        idx = text.find(method.name)
        if idx >= 0:
            char = idx + max(1, len(method.name) // 2)
            return {"line": line, "character": char}
    return {"line": line, "character": char}


def _guess_name(text: str) -> str | None:
    import re

    match = re.search(r"\b([A-Za-z_$][\w$]*)\s*\(", text)
    return match.group(1) if match else None


def _dedupe_symbols(symbols: list[MethodSymbol]) -> list[MethodSymbol]:
    seen: set[str] = set()
    out: list[MethodSymbol] = []
    for symbol in symbols:
        if symbol.method_id in seen:
            continue
        seen.add(symbol.method_id)
        out.append(symbol)
    return out


def _dedupe_edges(items: list[tuple[MethodSymbol, CallEdge]]) -> list[tuple[MethodSymbol, CallEdge]]:
    seen: set[tuple[str, str]] = set()
    out: list[tuple[MethodSymbol, CallEdge]] = []
    for symbol, edge in items:
        key = (edge.caller_id, edge.callee_id)
        if key in seen:
            continue
        seen.add(key)
        out.append((symbol, edge))
    return out
