"""LSP wire format: Content-Length framed JSON-RPC 2.0, and the type subset we use."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

HEADER_SEP = b"\r\n\r\n"

# LSP SymbolKind -> our SymbolKind names we care about
SYMBOL_KIND_NAMES: dict[int, str] = {
    1: "file",
    2: "module",
    3: "namespace",
    4: "package",
    5: "class",
    6: "method",
    7: "property",
    8: "field",
    9: "constructor",
    10: "enum",
    11: "interface",
    12: "function",
    13: "variable",
    14: "constant",
    15: "string",
    16: "number",
    17: "boolean",
    18: "array",
    19: "object",
    20: "key",
    21: "null",
    22: "enum_member",
    23: "struct",
    24: "event",
    25: "operator",
    26: "type_parameter",
}

CALLABLE_KINDS = {6, 9, 12, 25}  # method, constructor, function, operator
CONTAINER_KINDS = {2, 3, 4, 5, 10, 11, 23}  # module, namespace, package, class, ...


class LspError(RuntimeError):
    def __init__(self, code: int | None, message: str, data: Any = None) -> None:
        super().__init__(f"LSP error {code}: {message}")
        self.code = code
        self.message = message
        self.data = data


class ServerExited(RuntimeError):
    pass


@dataclass
class LspPosition:
    line: int = 0
    character: int = 0

    def to_wire(self) -> dict[str, int]:
        return {"line": self.line, "character": self.character}


@dataclass
class LspRange:
    start: LspPosition = field(default_factory=LspPosition)
    end: LspPosition = field(default_factory=LspPosition)

    @classmethod
    def from_wire(cls, raw: dict[str, Any] | None) -> LspRange:
        raw = raw or {}
        s = raw.get("start") or {}
        e = raw.get("end") or {}
        return cls(
            start=LspPosition(int(s.get("line", 0)), int(s.get("character", 0))),
            end=LspPosition(int(e.get("line", 0)), int(e.get("character", 0))),
        )

    def contains(self, line: int, char: int = 0) -> bool:
        if line < self.start.line or line > self.end.line:
            return False
        if line == self.start.line and char < self.start.character:
            return False
        return not (line == self.end.line and char > self.end.character)

    def contains_range(self, other: LspRange) -> bool:
        if other.start.line < self.start.line or other.end.line > self.end.line:
            return False
        if other.start.line == self.start.line and other.start.character < self.start.character:
            return False
        if other.end.line == self.end.line and other.end.character > self.end.character:
            return False
        return True


@dataclass
class LspLocation:
    uri: str
    range: LspRange

    @classmethod
    def from_wire(cls, raw: dict[str, Any]) -> LspLocation | None:
        uri = raw.get("uri") or raw.get("targetUri")
        if not uri:
            return None
        rng = raw.get("range") or raw.get("targetSelectionRange") or raw.get("targetRange")
        if rng is None:
            return None
        return cls(uri=uri, range=LspRange.from_wire(rng))


def encode_message(payload: dict[str, Any]) -> bytes:
    body = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    return b"Content-Length: %d\r\n\r\n%s" % (len(body), body)


def try_decode_message(buffer: bytearray) -> dict[str, Any] | None:
    """Pop one message from ``buffer`` in place. Returns None when incomplete."""
    idx = buffer.find(HEADER_SEP)
    if idx < 0:
        return None
    header = bytes(buffer[:idx]).decode("ascii", errors="replace")
    length: int | None = None
    for line in header.split("\r\n"):
        if ":" not in line:
            continue
        key, _, value = line.partition(":")
        if key.strip().lower() == "content-length":
            try:
                length = int(value.strip())
            except ValueError:
                length = None
    if length is None:
        # Corrupt header: drop it so the stream can resync.
        del buffer[: idx + len(HEADER_SEP)]
        return None
    start = idx + len(HEADER_SEP)
    end = start + length
    if len(buffer) < end:
        return None
    body = bytes(buffer[start:end])
    del buffer[:end]
    try:
        return json.loads(body.decode("utf-8", errors="replace"))
    except json.JSONDecodeError:
        return None
