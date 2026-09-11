"""Workspace file access + LSP document symbol caching (the shared hot path)."""

from __future__ import annotations

import threading
from pathlib import Path

from app.core.logging import get_logger
from app.core.utils import from_uri, rebase_path, sha1, strip_foreign_prefix
from app.lsp.manager import LanguageServerManager
from app.lsp.positions import LineIndex
from app.lsp.symbols import RawSymbol, parse_document_symbols
from app.parsers.syntax import ParsedFile, parse, parser_for
from app.schemas.domain import CodeRegion, Degradation, MethodSymbol, Provider, SymbolKind

log = get_logger(__name__)

# File types we are willing to lexically search when no language server can answer.
_SOURCE_SUFFIXES = frozenset(
    {
        ".py",
        ".pyi",
        ".js",
        ".jsx",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".go",
        ".rs",
        ".java",
        ".kt",
        ".c",
        ".h",
        ".cc",
        ".cpp",
        ".cxx",
        ".hpp",
        ".hh",
        ".cs",
        ".php",
        ".rb",
        ".swift",
        ".scala",
    }
)


class Workspace:
    """Reads files under ``root`` and caches text / line index / syntax parse."""

    def __init__(self, root: Path, *, max_file_bytes: int = 2_000_000) -> None:
        self.root = root.resolve()
        self.max_file_bytes = max_file_bytes
        self._text: dict[str, str] = {}
        self._index: dict[str, LineIndex] = {}
        self._parsed: dict[str, ParsedFile] = {}
        self._local_cache: dict[tuple[str, str], MethodSymbol | None] = {}
        self._files: list[Path] | None = None
        self._lock = threading.Lock()
        self.failures: dict[str, str] = {}

    def abs_path(self, rel: str) -> Path:
        """Resolve a finding/method path against the workspace root.

        SARIF and LSP URIs from another filesystem carry absolute paths
        (``/workspace/src/a.py`` or ``C:\\repo\\a.py``) that must be rebased onto
        our root, and relative paths must resolve against the root — not against
        the process CWD, which is what a bare ``Path(rel)`` would do.
        """
        if not rel:
            return self.root
        raw = rel.replace("\\", "/").strip()
        if raw.startswith("file://"):
            try:
                return from_uri(raw)
            except Exception:  # pragma: no cover - malformed URI
                return self.root
        path = Path(raw)
        if not path.is_absolute():
            return (self.root / raw).resolve()
        resolved = path.resolve()
        try:
            resolved.relative_to(self.root)
            return resolved
        except ValueError:
            pass
        rebased = strip_foreign_prefix(resolved, self.root)
        if rebased is not None:
            return (self.root / rebased).resolve()
        return resolved

    def rel(self, path: Path) -> str:
        return rebase_path(str(path), self.root)

    def read(self, rel: str) -> str | None:
        key = rel
        with self._lock:
            if key in self._text:
                return self._text[key]
            if key in self.failures:
                return None
        path = self.abs_path(rel)
        try:
            if not path.is_file():
                raise FileNotFoundError(rel)
            if path.stat().st_size > self.max_file_bytes:
                raise ValueError(f"file exceeds max_file_bytes ({self.max_file_bytes})")
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception as exc:
            with self._lock:
                self.failures[key] = str(exc)
            return None
        with self._lock:
            self._text[key] = text
        return text

    def index(self, rel: str) -> LineIndex | None:
        with self._lock:
            cached = self._index.get(rel)
        if cached is not None:
            return cached
        text = self.read(rel)
        if text is None:
            return None
        idx = LineIndex.build(text)
        with self._lock:
            self._index[rel] = idx
        return idx

    def parsed(self, rel: str) -> ParsedFile | None:
        with self._lock:
            cached = self._parsed.get(rel)
        if cached is not None:
            return cached
        text = self.read(rel)
        if text is None:
            return None
        parsed = parse(text)
        with self._lock:
            self._parsed[rel] = parsed
        return parsed

    def syntax_parser(self, rel: str):
        return parser_for(Path(rel).suffix)

    def find_local_method(self, name: str, *, near: str | None = None) -> MethodSymbol | None:
        """Locate a callable by name inside the workspace, without a language server.

        Used only as a last-resort callee resolution: when no language server can
        answer, a same-name ``def``/``function`` in the repository is far better
        evidence than dropping the edge. Prefers the file being analysed, then
        other files in stable order.
        """
        if not name or not name.isidentifier():
            return None
        key = (name, near or "")
        with self._lock:
            if key in self._local_cache:
                return self._local_cache[key]

        candidates: list[Path] = []
        if near:
            candidates.append(self.abs_path(near))
        others = [p for p in self.files() if near is None or self.rel(p) != near]
        candidates.extend(others[:200])

        found: MethodSymbol | None = None
        for path in candidates:
            rel = self.rel(path)
            text = self.read(rel)
            # One cheap substring check before any parsing: on a large repository
            # this is what keeps last-resort resolution affordable.
            if text is None or name not in text:
                continue
            parsed = self.parsed(rel)
            if parsed is None:
                continue
            scope = self.syntax_parser(rel).find_scope_named(parsed, name)
            if scope is None:
                continue
            region = CodeRegion(
                path=rel,
                start_line=scope.start_line,
                start_char=0,
                end_line=scope.end_line,
                end_char=len(parsed.line_text(scope.end_line)),
            )
            qualified = f"{scope.parent_hint}.{name}" if scope.parent_hint else name
            found = MethodSymbol(
                method_id="M-"
                + sha1(rel, qualified, str(region.start_line), str(region.end_line), length=12),
                name=name,
                qualified_name=qualified,
                kind=SymbolKind.FUNCTION,
                path=rel,
                region=region,
                language=Path(rel).suffix.lstrip("."),
                parent=scope.parent_hint,
                provider=Provider.SYNTAX_REGEX,
                signature=scope.signature,
                detail="resolved by same-repository name match (no language server)",
            )
        with self._lock:
            self._local_cache[key] = found
        return found

    def files(self) -> list[Path]:
        """Every candidate source file in the workspace, in stable order (cached)."""
        with self._lock:
            if self._files is not None:
                return self._files
        found: list[Path] = []
        skip_dirs = {".git", "node_modules", "__pycache__", ".venv", "venv", ".mypy_cache"}
        try:
            for path in self.root.rglob("*"):
                if len(found) >= 5000:
                    log.debug("workspace file scan truncated at 5000 files under %s", self.root)
                    break
                if not path.is_file() or path.suffix.lower() not in _SOURCE_SUFFIXES:
                    continue
                if skip_dirs.intersection(path.parts):
                    continue
                try:
                    if path.stat().st_size > self.max_file_bytes:
                        continue
                except OSError:  # pragma: no cover - racing deletion
                    continue
                found.append(path)
        except OSError:  # pragma: no cover - unreadable tree
            pass
        found.sort()
        with self._lock:
            self._files = found
        return found

    def slice_lines(self, rel: str, start_line: int, end_line: int) -> str | None:
        text = self.read(rel)
        if text is None:
            return None
        lines = text.splitlines()
        start = max(0, start_line)
        end = min(len(lines) - 1, end_line)
        if end < start:
            return ""
        return "\n".join(lines[start : end + 1])


class SymbolIndex:
    """Cache of ``documentSymbol`` results per file, from LSP with a syntax fallback."""

    def __init__(self, workspace: Workspace, lsp: LanguageServerManager | None) -> None:
        self.workspace = workspace
        self.lsp = lsp
        self._symbols: dict[str, list[RawSymbol]] = {}
        self._provider: dict[str, Provider] = {}
        self._lock = threading.Lock()
        self.degradations: list[Degradation] = []
        self.failures: dict[str, str] = {}

    def _record(self, degradation: Degradation) -> None:
        with self._lock:
            if any(d.reason == degradation.reason for d in self.degradations):
                return
            self.degradations.append(degradation)

    def symbols(self, rel: str) -> list[RawSymbol]:
        with self._lock:
            if rel in self._symbols:
                return self._symbols[rel]
            if rel in self.failures:
                return []

        text = self.workspace.read(rel)
        if text is None:
            with self._lock:
                self.failures[rel] = "unreadable"
            return []

        symbols: list[RawSymbol] = []
        provider = Provider.NONE
        if self.lsp is not None:
            path = self.workspace.abs_path(rel)
            client = self.lsp.client_for(path)
            if client is not None:
                payload = self.lsp.document_symbols(client, path, text)
                if payload:
                    symbols = parse_document_symbols(payload)
                    provider = Provider.LSP_DOCUMENT_SYMBOL
                else:
                    self._record(
                        Degradation(
                            capability="documentSymbol",
                            reason=f"language server returned no symbols for {rel}",
                            impact="method location falls back to syntax heuristics",
                            path=rel,
                            language=path.suffix.lstrip("."),
                        )
                    )
            else:
                self._record(
                    Degradation(
                        capability="lsp",
                        reason=f"no usable language server for {rel}",
                        impact="method location falls back to syntax heuristics",
                        path=rel,
                        language=Path(rel).suffix.lstrip("."),
                    )
                )

        with self._lock:
            self._symbols[rel] = symbols
            self._provider[rel] = provider
        return symbols

    def provider_for(self, rel: str) -> Provider:
        self.symbols(rel)
        with self._lock:
            return self._provider.get(rel, Provider.NONE)

    def has_symbols(self, rel: str) -> bool:
        return bool(self.symbols(rel))

    def provider_summary(self) -> dict[str, int]:
        with self._lock:
            summary: dict[str, int] = {}
            for provider in self._provider.values():
                summary[provider.value] = summary.get(provider.value, 0) + 1
            failures = list(self.failures.values())
        for reason in failures:
            key = f"failed:{reason}"
            summary[key] = summary.get(key, 0) + 1
        return summary
