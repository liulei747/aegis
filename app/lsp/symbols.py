"""Symbol extraction from LSP documentSymbol responses, index-free.

The key insight used throughout Aegis: a documentSymbol's ``range`` *is* the
callable's full extent. So we can find "the method enclosing a hit" purely by
range containment — no symbol database, no per-language grammar, no build
requirements. ``selectionRange`` gives us the identifier for name/reference
queries.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from app.lsp.positions import LineIndex
from app.lsp.protocol import CALLABLE_KINDS, CONTAINER_KINDS, SYMBOL_KIND_NAMES, LspRange

_IDENT = re.compile(r"[A-Za-z_$][A-Za-z0-9_$]*$")


@dataclass
class RawSymbol:
    """One documentSymbol node, flattened but keeping the parent chain."""

    name: str
    kind: int
    kind_name: str
    range: LspRange
    selection: LspRange
    detail: str | None = None
    parent_path: list[str] = field(default_factory=list)
    children: list[RawSymbol] = field(default_factory=list)

    @property
    def qualified_name(self) -> str:
        return ".".join([*self.parent_path, self.name]) if self.parent_path else self.name

    @property
    def is_callable(self) -> bool:
        return self.kind in CALLABLE_KINDS

    @property
    def is_container(self) -> bool:
        return self.kind in CONTAINER_KINDS

    def contains(self, line: int, char: int) -> bool:
        return self.range.contains(line, char)


def parse_document_symbols(payload: Any) -> list[RawSymbol]:
    """Accept both DocumentSymbol[] and SymbolInformation[]/flat shapes."""
    if not payload:
        return []
    roots: list[RawSymbol] = []
    for node in payload:
        if not isinstance(node, dict):
            continue
        if "location" in node and "range" not in node:
            # SymbolInformation: synthesize a range from its location.
            loc = node.get("location") or {}
            rng = loc.get("range")
            if rng is None:
                continue
            node = {
                "name": node.get("name", "?"),
                "kind": node.get("kind", 0),
                "range": rng,
                "selectionRange": rng,
                "detail": node.get("containerName"),
            }
        roots.append(_convert(node, parent_path=[]))
    return roots


def _convert(node: dict[str, Any], parent_path: list[str]) -> RawSymbol:
    rng = LspRange.from_wire(node.get("range"))
    selection = LspRange.from_wire(node.get("selectionRange") or node.get("range"))
    kind = int(node.get("kind") or 0)
    children = [_convert(child, [*parent_path, node.get("name", "?")]) for child in node.get("children") or []]
    return RawSymbol(
        name=node.get("name") or "?",
        kind=kind,
        kind_name=SYMBOL_KIND_NAMES.get(kind, f"kind-{kind}"),
        range=rng,
        selection=selection,
        detail=node.get("detail"),
        parent_path=list(parent_path),
        children=children,
    )


def walk(symbols: list[RawSymbol]):
    for sym in symbols:
        yield sym
        yield from walk(sym.children)


def find_enclosing(
    symbols: list[RawSymbol],
    line: int,
    char: int,
    *,
    callable_only: bool = True,
) -> RawSymbol | None:
    """Innermost containing symbol (deepest wins)."""
    best: RawSymbol | None = None
    best_span: int | None = None
    for sym in walk(symbols):
        if callable_only and not sym.is_callable:
            continue
        if not sym.contains(line, char):
            continue
        span = _span(sym.range)
        if best is None or best_span is None or span < best_span:
            best, best_span = sym, span
    return best


def find_containing_callable_chain(
    symbols: list[RawSymbol], line: int, char: int
) -> list[RawSymbol]:
    """Every callable whose range contains the position, outermost first."""
    chain = [sym for sym in walk(symbols) if sym.is_callable and sym.contains(line, char)]
    chain.sort(key=lambda s: _span(s.range), reverse=True)
    return chain


def _span(rng: LspRange) -> int:
    return (rng.end.line - rng.start.line) * 100_000 + (rng.end.character - rng.start.character)


def enclosing_class_path(symbols: list[RawSymbol], target: RawSymbol) -> list[str]:
    """Container names enclosing ``target`` (for qualified names)."""
    path: list[str] = []
    for sym in walk(symbols):
        if sym is target:
            continue
        if not sym.is_container:
            continue
        if sym.range.contains_region(target.range):
            path.append(sym.name)
    return path


def identifier_at(text: str, line_index: LineIndex, line: int, char: int) -> tuple[str, LspRange] | None:
    """Word under a cursor position, with a range covering just that word.

    Used to resolve a *name reference* (``foo(...)``) into a symbol via
    textDocument/definition when call hierarchy is unavailable.
    """
    if line < 0 or line >= line_index.line_count:
        return None
    line_text = line_index.line_text(line)
    if not line_text:
        return None
    offset = line_index.offset_of(line, char)
    line_start = line_index.line_starts[line]
    col = max(0, min(offset - line_start, len(line_text)))
    start = col
    while start > 0 and (line_text[start - 1].isalnum() or line_text[start - 1] in "_$"):
        start -= 1
    end = col
    while end < len(line_text) and (line_text[end].isalnum() or line_text[end] in "_$"):
        end += 1
    word = line_text[start:end]
    if not word or not _IDENT.search(word):
        return None
    rng = LspRange.from_wire(
        {
            "start": line_index.position_of(line_start + start).to_wire(),
            "end": line_index.position_of(line_start + end).to_wire(),
        }
    )
    return word, rng
