"""Syntax-only fallback: lexical scope + call-site extraction.

This exists for two reasons:

1. When no language server is installed for a file type we still ship a usable
   (clearly labelled, lower-confidence) bundle instead of nothing.
2. Call hierarchy is optional in LSP and several servers never implement it.
   The lexical call-site list is what lets us resolve *callees* through
   ``textDocument/definition``, which nearly every server does support.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field


@dataclass
class CallSite:
    name: str
    line: int
    char: int
    snippet: str = ""
    receiver: str | None = None
    is_method_call: bool = False


@dataclass
class Scope:
    """A lexical method scope found without an LSP."""

    name: str
    start_line: int
    end_line: int
    decoration_lines: list[int] = field(default_factory=list)
    signature: str = ""
    parent_hint: str | None = None


@dataclass
class ParsedFile:
    text: str
    line_starts: list[int]

    def line_text(self, line: int) -> str:
        if line < 0 or line >= len(self.line_starts):
            return ""
        end = self.line_starts[line + 1] if line + 1 < len(self.line_starts) else len(self.text)
        return self.text[self.line_starts[line] : end].rstrip("\r\n")

    @property
    def line_count(self) -> int:
        return len(self.line_starts)


def parse(text: str) -> ParsedFile:
    starts = [0]
    for i, ch in enumerate(text):
        if ch == "\n":
            starts.append(i + 1)
    return ParsedFile(text=text, line_starts=starts)


class BaseSyntaxParser:
    """Regex-driven, language-agnostic base. Subclasses tune patterns."""

    name = "base"
    call_patterns: list[re.Pattern[str]] = [
        re.compile(r"(?:(?P<recv>[A-Za-z_$][\w$]*)\s*\.\s*)?(?P<name>[A-Za-z_$][\w$]*)\s*\(")
    ]
    keyword_blocklist: set[str] = {
        "if",
        "elif",
        "else",
        "for",
        "while",
        "switch",
        "catch",
        "return",
        "do",
        "try",
        "with",
        "assert",
        "print",
        "del",
        "in",
        "and",
        "or",
        "not",
        "is",
        "await",
        "yield",
        "raise",
        "lambda",
        "new",
        "sizeof",
        "typeof",
        "defined",
    }

    def __init__(self) -> None:
        self._local_defs: dict[str, re.Pattern[str]] = {}

    # -- method location ------------------------------------------------
    def method_at(self, parsed: ParsedFile, line: int, char: int = 0) -> Scope | None:
        scopes = self.methods(parsed, line)
        best: Scope | None = None
        for scope in scopes:
            if scope.start_line <= line <= scope.end_line:
                if best is None or (scope.end_line - scope.start_line) < (
                    best.end_line - best.start_line
                ):
                    best = scope
        return best

    def methods(self, parsed: ParsedFile, near_line: int, *, window: int = 400) -> list[Scope]:
        raise NotImplementedError

    def find_scope_named(self, parsed: ParsedFile, name: str) -> Scope | None:
        """Find a callable by name, scanning the whole file.

        Used as a last-resort callee resolution when no language server can answer.
        Cheap because it stops at the first match and the caller pre-filters on a
        substring hit.

        NOTE: the window must span the file. ``methods()`` bounds its scope search
        with ``[def_line + 1, horizon]``, so passing a small window yields a scope
        that ends on its own `def` line instead of at the end of the body.
        """
        for line in range(parsed.line_count):
            if name not in parsed.line_text(line):
                continue
            for scope in self.methods(parsed, line, window=parsed.line_count):
                if scope.name == name:
                    return scope
        return None

    def enclosing_parent(self, parsed: ParsedFile, scope: Scope) -> str | None:
        return None

    # -- call sites -----------------------------------------------------
    def call_sites(self, parsed: ParsedFile, scope: Scope) -> list[CallSite]:
        sites: list[CallSite] = []
        seen: set[tuple[int, int]] = set()
        for line in range(scope.start_line, min(scope.end_line, parsed.line_count - 1) + 1):
            text = parsed.line_text(line)
            if not text.strip():
                continue
            for pattern in self.call_patterns:
                for match in pattern.finditer(text):
                    name = match.group("name")
                    if not name or name in self.keyword_blocklist:
                        continue
                    # Skip the declaration line of the scope itself.
                    if line == scope.start_line:
                        continue
                    key = (line, match.start("name"))
                    if key in seen:
                        continue
                    seen.add(key)
                    recv = match.groupdict().get("recv")
                    sites.append(
                        CallSite(
                            name=name,
                            line=line,
                            char=match.start("name"),
                            snippet=text.strip()[:200],
                            receiver=recv,
                            is_method_call=bool(recv),
                        )
                    )
        return sites

    def local_definition(self, parsed: ParsedFile, scope: Scope, name: str) -> bool:
        """True when ``name`` looks locally defined (skip definition lookups)."""
        pattern = re.compile(rf"\b(?:def|function|class|var|let|const|struct|fn)\s+{re.escape(name)}\b")
        for line in range(scope.start_line, min(scope.end_line, parsed.line_count - 1) + 1):
            if pattern.search(parsed.line_text(line)):
                return True
        return False


# ----------------------------------------------------------------------
# Indentation-scoped languages (Python-like)
# ----------------------------------------------------------------------
class IndentParser(BaseSyntaxParser):
    name = "indent"
    def_patterns: list[re.Pattern[str]] = [
        re.compile(r"^(?P<indent>[ \t]*)(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*\("),
        re.compile(r"^(?P<indent>[ \t]*)(?:async\s+)?def\s+(?P<name>[A-Za-z_]\w*)\s*$"),
    ]
    class_pattern = re.compile(r"^(?P<indent>[ \t]*)class\s+(?P<name>[A-Za-z_]\w*)")
    decorator_pattern = re.compile(r"^[ \t]*@")

    def _indent_width(self, text: str) -> int:
        return len(text) - len(text.lstrip(" \t"))

    def methods(self, parsed: ParsedFile, near_line: int, *, window: int = 400) -> list[Scope]:
        scopes: list[Scope] = []
        start = max(0, near_line - window)
        end = min(parsed.line_count - 1, near_line + window)
        i = start
        while i <= end:
            text = parsed.line_text(i)
            match = next((p.match(text) for p in self.def_patterns if p.match(text)), None)
            if match is None:
                i += 1
                continue
            indent = self._indent_width(match.group("indent"))
            body_end = self._find_end(parsed, i, indent, end)
            decorations = self._decorations_above(parsed, i)
            scopes.append(
                Scope(
                    name=match.group("name"),
                    start_line=min(decorations) if decorations else i,
                    end_line=body_end,
                    decoration_lines=decorations,
                    signature=text.strip(),
                    parent_hint=self.enclosing_parent(parsed, Scope(match.group("name"), i, body_end)),
                )
            )
            i = body_end + 1
        return scopes

    def _find_end(self, parsed: ParsedFile, def_line: int, indent: int, horizon: int) -> int:
        end = def_line
        for line in range(def_line + 1, min(parsed.line_count, horizon + 1)):
            text = parsed.line_text(line)
            if not text.strip():
                continue
            if self._indent_width(text) <= indent:
                break
            end = line
        return end

    def _decorations_above(self, parsed: ParsedFile, def_line: int) -> list[int]:
        lines: list[int] = []
        i = def_line - 1
        while i >= 0:
            text = parsed.line_text(i)
            if not text.strip():
                i -= 1
                continue
            if self.decorator_pattern.match(text):
                lines.insert(0, i)
                i -= 1
                continue
            break
        return lines

    def enclosing_parent(self, parsed: ParsedFile, scope: Scope) -> str | None:
        """Nearest enclosing ``class`` above the scope."""
        needle = min(scope.decoration_lines) if scope.decoration_lines else scope.start_line
        for line in range(needle - 1, -1, -1):
            text = parsed.line_text(line)
            match = self.class_pattern.match(text)
            if match:
                return match.group("name")
        return None


# ----------------------------------------------------------------------
# Brace-scoped languages
# ----------------------------------------------------------------------
class BraceParser(BaseSyntaxParser):
    name = "brace"
    def_patterns: list[re.Pattern[str]] = [
        # TS/JS: function foo( / const foo = ( ) => / foo(a) {
        re.compile(
            r"^[ \t]*(?:(?:export|default|public|private|protected|static|async|final|override|synchronized)\s+)*"
            r"(?:function\*?\s+(?P<name>[A-Za-z_$][\w$]*)\s*\()"
        ),
        re.compile(
            r"^[ \t]*(?:(?:export|const|let|var|public|private|protected|static|final)\s+)*"
            r"(?P<name>[A-Za-z_$][\w$]*)\s*[:=]\s*(?:async\s*)?(?:function\b|\()"
        ),
        # Java/C#/C++/Go: modifiers + return type + name(
        re.compile(
            r"^[ \t]*(?:(?:public|private|protected|static|final|virtual|inline|extern|async|"
            r"override|synchronized|constexpr|unsigned|signed|long|short)\s+)*"
            r"(?:[A-Za-z_$][\w$:<>,\[\]\*&\s]*?\s+)?"
            r"(?P<name>[A-Za-z_$][\w$]*)\s*\([^;{]*\)\s*(?:const\s*)?(?:noexcept\s*)?(?:->\s*[\w:<>,\*&\s]+)?\s*\{?\s*$"
        ),
        # Go methods
        re.compile(r"^[ \t]*func\s+(?:\([^)]*\)\s*)?(?P<name>[A-Za-z_]\w*)\s*\("),
    ]
    class_pattern = re.compile(
        r"^[ \t]*(?:(?:export|default|public|private|protected|static|final|abstract)\s+)*"
        r"(?:class|interface|struct|enum|impl|trait|namespace)\s+(?P<name>[A-Za-z_$][\w$]*)"
    )

    def methods(self, parsed: ParsedFile, near_line: int, *, window: int = 600) -> list[Scope]:
        scopes: list[Scope] = []
        start = max(0, near_line - window)
        end = min(parsed.line_count - 1, near_line + window)
        for line in range(start, end + 1):
            text = parsed.line_text(line)
            stripped = text.strip()
            if not stripped or stripped.startswith(("//", "*", "/*", "#")):
                continue
            name = self._match_def(text)
            if name is None:
                continue
            end_line = self._find_block_end(parsed, line, end)
            scopes.append(
                Scope(
                    name=name,
                    start_line=line,
                    end_line=end_line,
                    signature=stripped[:240],
                    parent_hint=self.enclosing_parent(parsed, Scope(name, line, end_line)),
                )
            )
        return scopes

    def _match_def(self, text: str) -> str | None:
        for pattern in self.def_patterns:
            match = pattern.match(text)
            if match:
                name = match.group("name")
                if name and name not in self.keyword_blocklist and name not in {"class", "struct", "if", "for", "while", "switch", "catch"}:
                    return name
        return None

    def _find_block_end(self, parsed: ParsedFile, def_line: int, horizon: int) -> int:
        depth = 0
        started = False
        for line in range(def_line, min(parsed.line_count, horizon + 6)):
            text = _strip_strings(parsed.line_text(line))
            for ch in text:
                if ch == "{":
                    depth += 1
                    started = True
                elif ch == "}":
                    depth -= 1
            if started and depth <= 0:
                return line
        # Semicolon-terminated declaration (interface/abstract method)
        if ";" in parsed.line_text(def_line):
            return def_line
        return min(def_line + 60, horizon)

    def enclosing_parent(self, parsed: ParsedFile, scope: Scope) -> str | None:
        for line in range(scope.start_line - 1, -1, -1):
            match = self.class_pattern.match(parsed.line_text(line))
            if match:
                # crude but effective: a class header is followed by more indent
                return match.group("name")
        return None


def _strip_strings(text: str) -> str:
    out = []
    in_str: str | None = None
    i = 0
    while i < len(text):
        ch = text[i]
        if in_str:
            if ch == "\\":
                i += 2
                continue
            if ch == in_str:
                in_str = None
            i += 1
            continue
        if ch in "\"'`":
            in_str = ch
            i += 1
            continue
        if text.startswith("//", i) or text.startswith("#", i):
            break
        out.append(ch)
        i += 1
    return "".join(out)


_BY_EXTENSION: dict[str, type[BaseSyntaxParser]] = {}
_PARSER_CACHE: dict[type[BaseSyntaxParser], BaseSyntaxParser] = {}


def parser_for(suffix: str, override: type[BaseSyntaxParser] | None = None) -> BaseSyntaxParser:
    cls = override or _BY_EXTENSION.get(suffix.lower(), IndentParser)
    if cls not in _PARSER_CACHE:
        _PARSER_CACHE[cls] = cls()
    return _PARSER_CACHE[cls]


def register(suffixes: list[str], parser_cls: type[BaseSyntaxParser]) -> None:
    for suffix in suffixes:
        _BY_EXTENSION[suffix.lower()] = parser_cls


for _suffix in (".py", ".pyi", ".rb", ".yaml", ".yml"):
    register([_suffix], IndentParser)
for _suffix in (
    ".js",
    ".jsx",
    ".ts",
    ".tsx",
    ".mjs",
    ".cjs",
    ".go",
    ".java",
    ".c",
    ".h",
    ".cc",
    ".cpp",
    ".hpp",
    ".hh",
    ".cs",
    ".php",
    ".rs",
    ".kt",
    ".swift",
    ".scala",
):
    register([_suffix], BraceParser)
