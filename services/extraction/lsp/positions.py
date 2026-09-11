"""Position/offset conversion.

LSP positions are (line, character) where ``character`` is counted in the
encoding negotiated at initialize time — UTF-16 code units by default. Python
strings are UCS-4. Getting this wrong silently corrupts every method range, so
all conversion goes through here.
"""

from __future__ import annotations

from dataclasses import dataclass

from services.extraction.lsp.protocol import LspPosition, LspRange


@dataclass
class LineIndex:
    """Offsets of every line start, plus encodings supported by the server."""

    text: str
    line_starts: list[int]
    utf16: bool = True

    @classmethod
    def build(cls, text: str, *, utf16: bool = True) -> LineIndex:
        starts = [0]
        for i, ch in enumerate(text):
            if ch == "\n":
                starts.append(i + 1)
        return cls(text=text, line_starts=starts, utf16=utf16)

    # -- offsets ------------------------------------------------------
    def offset_of(self, line: int, character: int) -> int:
        if line < 0:
            return 0
        if line >= len(self.line_starts):
            return len(self.text)
        start = self.line_starts[line]
        end = self._line_end(line)
        if character <= 0:
            return start
        line_text = self.text[start:end]
        if self.utf16:
            return start + _utf16_units_to_index(line_text, character)
        return min(start + character, end)

    def _line_end(self, line: int) -> int:
        if line + 1 < len(self.line_starts):
            return self.line_starts[line + 1]
        return len(self.text)

    def position_of(self, offset: int) -> LspPosition:
        offset = max(0, min(offset, len(self.text)))
        lo, hi = 0, len(self.line_starts) - 1
        while lo < hi:
            mid = (lo + hi + 1) // 2
            if self.line_starts[mid] <= offset:
                lo = mid
            else:
                hi = mid - 1
        start = self.line_starts[lo]
        line_text = self.text[start : self._line_end(lo)]
        prefix = line_text[: offset - start]
        char = _utf16_len(prefix) if self.utf16 else len(prefix)
        return LspPosition(line=lo, character=char)

    # -- ranges -------------------------------------------------------
    def range_to_offsets(self, rng: LspRange) -> tuple[int, int]:
        return (
            self.offset_of(rng.start.line, rng.start.character),
            self.offset_of(rng.end.line, rng.end.character),
        )

    def offset_range(self, rng: LspRange) -> tuple[int, int]:
        start, end = self.range_to_offsets(rng)
        if end < start:
            start, end = end, start
        return start, end

    def slice(self, rng: LspRange) -> str:
        start, end = self.offset_range(rng)
        return self.text[start:end]

    def line_text(self, line: int) -> str:
        if line < 0 or line >= len(self.line_starts):
            return ""
        return self.text[self.line_starts[line] : self._line_end(line)].rstrip("\r\n")

    def location_of(self, offset: int) -> tuple[int, int]:
        pos = self.position_of(offset)
        return pos.line, pos.character

    @property
    def line_count(self) -> int:
        return len(self.line_starts)


def _utf16_len(text: str) -> int:
    return sum(2 if ord(ch) > 0xFFFF else 1 for ch in text)


def _utf16_units_to_index(line_text: str, units: int) -> int:
    """Convert a UTF-16 code-unit column into a Python string index."""
    count = 0
    for i, ch in enumerate(line_text):
        if count >= units:
            return i
        count += 2 if ord(ch) > 0xFFFF else 1
    return len(line_text)
