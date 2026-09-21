"""A tiny, dependency-free LSP server used by the test-suite.

It exists so the *entire* pipeline can be tested end to end — JSON-RPC framing,
documentSymbol ranges, definition resolution, call hierarchy — without installing
pyright/gopls/clangd in CI.

Supported methods:
    initialize / initialized / shutdown / exit
    textDocument/documentSymbol        (indentation-based Python scopes)
    textDocument/definition            (identifier -> enclosing function)
    textDocument/references            (identifier occurrences -> enclosing function)
    textDocument/implementation        (returns nothing: tests the degraded path)
    textDocument/prepareCallHierarchy
    callHierarchy/incomingCalls
    callHierarchy/outgoingCalls

Usage: python tests/fake_lsp_server.py --root <repo-root>
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.parse import unquote, urlparse

HEADER_SEP = b"\r\n\r\n"

DEF_RE = re.compile(r"^([ \t]*)(?:async\s+)?def\s+([A-Za-z_]\w*)\s*\(")
CLASS_RE = re.compile(r"^([ \t]*)class\s+([A-Za-z_]\w*)")
IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


class FakeServer:
    def __init__(self, root: Path) -> None:
        self.root = root
        self._buffer = bytearray()
        self._id = 0

    # -- wire ---------------------------------------------------------
    def run(self) -> None:
        stdin = sys.stdin.buffer
        while True:
            chunk = stdin.read1(65536) if hasattr(stdin, "read1") else stdin.read(65536)
            if not chunk:
                return
            self._buffer.extend(chunk)
            while True:
                msg = self._pop()
                if msg is None:
                    break
                self._handle(msg)

    def _pop(self) -> dict | None:
        idx = self._buffer.find(HEADER_SEP)
        if idx < 0:
            return None
        header = bytes(self._buffer[:idx]).decode("ascii", "replace")
        length = None
        for line in header.split("\r\n"):
            key, _, value = line.partition(":")
            if key.strip().lower() == "content-length":
                length = int(value.strip())
        if length is None:
            del self._buffer[: idx + len(HEADER_SEP)]
            return None
        start = idx + len(HEADER_SEP)
        if len(self._buffer) < start + length:
            return None
        body = bytes(self._buffer[start : start + length])
        del self._buffer[: start + length]
        return json.loads(body.decode("utf-8"))

    def _send(self, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        sys.stdout.buffer.write(b"Content-Length: %d\r\n\r\n%s" % (len(body), body))
        sys.stdout.buffer.flush()

    def _result(self, req_id, result) -> None:
        self._send({"jsonrpc": "2.0", "id": req_id, "result": result})

    def _error(self, req_id, code: int, message: str) -> None:
        self._send({"jsonrpc": "2.0", "id": req_id, "error": {"code": code, "message": message}})

    # -- dispatch -----------------------------------------------------
    def _handle(self, msg: dict) -> None:
        method = msg.get("method")
        req_id = msg.get("id")
        params = msg.get("params") or {}

        if method in {"initialized", "$/cancelRequest"}:
            return
        if method == "exit":
            raise SystemExit(0)
        if method is None:
            return  # a response to something we sent; irrelevant here

        try:
            handler = getattr(self, f"_m_{method.replace('/', '_')}", None)
            if handler is None:
                if req_id is not None:
                    self._error(req_id, -32601, f"method not found: {method}")
                return
            result = handler(params)
            if req_id is not None:
                self._result(req_id, result)
        except Exception as exc:  # pragma: no cover - surfaces in tests
            if req_id is not None:
                self._error(req_id, -32603, f"{type(exc).__name__}: {exc}")

    # -- helpers ------------------------------------------------------
    def _path(self, uri: str) -> Path:
        parsed = urlparse(uri)
        raw = unquote(parsed.path)
        if re.match(r"^/[A-Za-z]:", raw):
            raw = raw[1:]
        return Path(raw)

    def _lines(self, uri: str) -> list[str]:
        return self._path(uri).read_text(encoding="utf-8").splitlines()

    @staticmethod
    def _indent(text: str) -> int:
        return len(text) - len(text.lstrip(" \t"))

    def _scopes(self, uri: str) -> list[dict]:
        """Indentation-based scopes with nesting, mirroring real documentSymbol."""
        lines = self._lines(uri)
        nodes: list[dict] = []
        stack: list[dict] = []
        for index, text in enumerate(lines):
            def_match = DEF_RE.match(text)
            class_match = CLASS_RE.match(text)
            match = def_match or class_match
            if match is None:
                continue
            indent = self._indent(text)
            while stack and stack[-1]["_indent"] >= indent:
                stack.pop()
            selection_char = text.index(match.group(2))
            node = {
                "name": match.group(2),
                "kind": 5 if class_match else (12 if not stack or stack[-1]["kind"] != 5 else 6),
                "range": {"start": {"line": index, "character": 0}, "end": {"line": index + 1, "character": 0}},
                "selectionRange": {
                    "start": {"line": index, "character": selection_char},
                    "end": {"line": index, "character": selection_char + len(match.group(2))},
                },
                "children": [],
                "_indent": indent,
            }
            if stack:
                stack[-1]["children"].append(node)
            else:
                nodes.append(node)
            stack.append(node)

        def close(node: dict) -> None:
            for child in node["children"]:
                close(child)
            child_end = max((c["range"]["end"]["line"] for c in node["children"]), default=0)
            start = node["range"]["start"]["line"]
            # body runs until the first non-blank line at <= this indent
            bound = start + 1
            for line_no in range(start + 1, len(lines)):
                text = lines[line_no]
                if text.strip() and self._indent(text) <= node["_indent"]:
                    break
                bound = line_no + 1
            node["range"]["end"] = {"line": max(bound, child_end, start + 1), "character": 0}
            node.pop("_indent")

        for node in nodes:
            close(node)
        return nodes

    def _flat(self, uri: str) -> list[dict]:
        out: list[dict] = []

        def visit(nodes, parents):
            for node in nodes:
                entry = {
                    "name": node["name"],
                    "kind": node["kind"],
                    "range": node["range"],
                    "selectionRange": node["selectionRange"],
                    "parents": list(parents),
                }
                out.append(entry)
                visit(node["children"], [*parents, node["name"]])

        visit(self._scopes(uri), [])
        return out

    @staticmethod
    def _in(entry: dict, line: int, char: int) -> bool:
        start = entry["range"]["start"]
        end = entry["range"]["end"]
        if line < start["line"] or line > end["line"]:
            return False
        if line == start["line"] and char < start["character"]:
            return False
        return not (line == end["line"] and char > end["character"])

    def _innermost(self, uri: str, line: int, char: int) -> dict | None:
        matches = [e for e in self._flat(uri) if self._in(e, line, char)]
        if not matches:
            return None
        matches.sort(key=lambda e: (e["range"]["end"]["line"] - e["range"]["start"]["line"]))
        return matches[0]

    def _qualify(self, entry: dict) -> str:
        return ".".join([*entry["parents"], entry["name"]]) if entry["parents"] else entry["name"]

    def _item(self, uri: str, entry: dict) -> dict:
        return {
            "name": entry["name"],
            "kind": entry["kind"],
            "uri": uri,
            "range": entry["range"],
            "selectionRange": entry["selectionRange"],
            "detail": self._qualify(entry),
        }

    def _calls_in(self, uri: str, entry: dict) -> list[tuple[str, int, int]]:
        """(callee_name, line, char) for calls lexically inside ``entry``."""
        lines = self._lines(uri)
        calls: list[tuple[str, int, int]] = []
        start = entry["range"]["start"]["line"] + 1
        end = entry["range"]["end"]["line"]
        for line_no in range(start, min(end, len(lines) - 1) + 1):
            text = lines[line_no]
            for match in re.finditer(r"(?<![\w.])([A-Za-z_]\w*)\s*\(", text):
                name = match.group(1)
                if name in {"if", "for", "while", "return", "print", "len", "range", "str", "int"}:
                    continue
                calls.append((name, line_no, match.start(1)))
        return calls

    def _declaration(self, name: str) -> tuple[str, dict] | None:
        for path in sorted(self.root.rglob("*.py")):
            uri = path.resolve().as_uri()
            for entry in self._flat(uri):
                if entry["name"] == name:
                    return uri, entry
        return None

    # -- LSP methods --------------------------------------------------
    def _m_initialize(self, params: dict) -> dict:
        return {
            "capabilities": {
                "textDocumentSync": 1,
                "documentSymbolProvider": True,
                "definitionProvider": True,
                "referencesProvider": True,
                "callHierarchyProvider": True,
            },
            "serverInfo": {"name": "fake-lsp", "version": "0.1"},
        }

    def _m_shutdown(self, params: dict):
        return None

    def _m_textDocument_documentSymbol(self, params: dict) -> list:
        uri = params["textDocument"]["uri"]
        return self._scopes(uri)

    def _m_textDocument_definition(self, params: dict):
        uri = params["textDocument"]["uri"]
        pos = params["position"]
        lines = self._lines(uri)
        if pos["line"] >= len(lines):
            return None
        text = lines[pos["line"]]
        char = pos["character"]
        start, end = char, char
        while start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
            start -= 1
        while end < len(text) and (text[end].isalnum() or text[end] == "_"):
            end += 1
        word = text[start:end]
        if not word:
            return None
        found = self._declaration(word)
        if found is None:
            return None
        target_uri, entry = found
        return {
            "uri": target_uri,
            "range": entry["selectionRange"],
        }

    def _m_textDocument_references(self, params: dict):
        uri = params["textDocument"]["uri"]
        pos = params["position"]
        lines = self._lines(uri)
        text = lines[pos["line"]]
        char = pos["character"]
        start, end = char, char
        while start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"):
            start -= 1
        while end < len(text) and (text[end].isalnum() or text[end] == "_"):
            end += 1
        word = text[start:end]
        if not word:
            return []
        results = []
        for path in sorted(self.root.rglob("*.py")):
            target_uri = path.resolve().as_uri()
            for line_no, line_text in enumerate(path.read_text(encoding="utf-8").splitlines()):
                for match in IDENT_RE.finditer(line_text):
                    if match.group(0) != word:
                        continue
                    results.append(
                        {
                            "uri": target_uri,
                            "range": {
                                "start": {"line": line_no, "character": match.start()},
                                "end": {"line": line_no, "character": match.end()},
                            },
                        }
                    )
        return results

    def _m_textDocument_implementation(self, params: dict):
        return []

    def _m_textDocument_prepareCallHierarchy(self, params: dict):
        uri = params["textDocument"]["uri"]
        pos = params["position"]
        entry = self._innermost(uri, pos["line"], pos["character"])
        return [self._item(uri, entry)] if entry else []

    def _m_callHierarchy_incomingCalls(self, params: dict):
        item = params["item"]
        target_entry = self._innermost(
            item["uri"], item["range"]["start"]["line"], item["range"]["start"]["character"]
        )
        if target_entry is None:
            return []
        name = target_entry["name"]
        out = []
        for path in sorted(self.root.rglob("*.py")):
            uri = path.resolve().as_uri()
            for candidate in self._flat(uri):
                if candidate["name"] == name:
                    continue
                for callee, line_no, char in self._calls_in(uri, candidate):
                    if callee != name:
                        continue
                    out.append(
                        {
                            "from": self._item(uri, candidate),
                            "fromRanges": [
                                {
                                    "start": {"line": line_no, "character": char},
                                    "end": {"line": line_no, "character": char + len(name)},
                                }
                            ],
                        }
                    )
                    break
        return out

    def _m_callHierarchy_outgoingCalls(self, params: dict):
        item = params["item"]
        uri = item["uri"]
        entry = self._innermost(
            uri, item["range"]["start"]["line"], item["range"]["start"]["character"]
        )
        if entry is None:
            return []
        out = []
        seen: set[str] = set()
        for callee, line_no, char in self._calls_in(uri, entry):
            if callee in seen:
                continue
            found = self._declaration(callee)
            if found is None:
                continue
            seen.add(callee)
            target_uri, target_entry = found
            out.append(
                {
                    "to": self._item(target_uri, target_entry),
                    "fromRanges": [
                        {
                            "start": {"line": line_no, "character": char},
                            "end": {"line": line_no, "character": char + len(callee)},
                        }
                    ],
                }
            )
        return out


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", required=True)
    args = parser.parse_args()
    FakeServer(Path(args.root).resolve()).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
