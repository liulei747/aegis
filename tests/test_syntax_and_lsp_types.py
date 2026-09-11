from __future__ import annotations

from app.lsp.positions import LineIndex
from app.lsp.symbols import parse_document_symbols
from app.parsers.syntax import BraceParser, IndentParser, parse

PY = '''\
class Service:
    def handle(self, user_id):
        value = load(user_id)
        return query(value)

    def other(self):
        return 1


def load(user_id):
    return sanitize(user_id)


def query(value):
    return execute("select " + value)
'''

BRACE = """\
public class Controller {
    public String dispatch(Request request) {
        String id = request.id();
        return service.load(id);
    }

    private void unused() {
        log.info("x");
    }
}
"""


def test_line_index_handles_utf16_surrogate_pairs() -> None:
    text = 'x = "a\U0001f600b" + y\nnext = 1\n'
    index = LineIndex.build(text)
    # the emoji is one Python index but two UTF-16 code units
    offset = index.offset_of(0, len('x = "a') + 2)
    assert text[offset] == "b"
    assert index.offset_of(0, len('x = "a')) == text.index("\U0001f600")
    pos = index.position_of(text.index("+ y"))
    assert pos.line == 0
    assert pos.character == text.index("+ y") + 1  # +1 for the surrogate pair
    assert index.offset_of(0, pos.character) == text.index("+ y")


def test_line_index_offsets_roundtrip() -> None:
    index = LineIndex.build(PY)
    for line in range(index.line_count):
        text = index.line_text(line)
        for char in range(len(text) + 1):
            offset = index.offset_of(line, char)
            assert text[:char] == index.text[index.line_starts[line] : offset]


def test_indent_parser_finds_enclosing_method() -> None:
    parsed = parse(PY)
    parser = IndentParser()
    scope = parser.method_at(parsed, 2)  # inside Service.handle
    assert scope is not None
    assert scope.name == "handle"
    assert scope.start_line == 1
    assert scope.end_line == 3
    assert scope.parent_hint == "Service"


def test_indent_parser_call_sites_skip_keywords() -> None:
    parsed = parse(PY)
    parser = IndentParser()
    scope = parser.method_at(parsed, 2)
    assert scope is not None
    names = [site.name for site in parser.call_sites(parsed, scope)]
    assert names == ["load", "query"]
    assert "return" not in names


def test_indent_parser_detects_local_definitions() -> None:
    parsed = parse("def outer():\n    def inner():\n        pass\n    inner()\n")
    parser = IndentParser()
    scope = parser.method_at(parsed, 3)
    assert scope is not None
    assert parser.local_definition(parsed, scope, "pass") in {True, False}
    outer = parser.method_at(parsed, 0)
    assert outer is not None
    assert parser.local_definition(parsed, outer, "inner") is True


def test_brace_parser_finds_scope_and_calls() -> None:
    parsed = parse(BRACE)
    parser = BraceParser()
    scope = parser.method_at(parsed, 3)
    assert scope is not None
    assert scope.name == "dispatch"
    assert scope.end_line == 4
    names = [site.name for site in parser.call_sites(parsed, scope)]
    assert "load" in names
    assert "dispatch" not in names


def test_brace_parser_handles_multiline_blocks() -> None:
    text = "void a() {\n  if (x) {\n    b();\n  }\n}\n\nvoid c() {}\n"
    parsed = parse(text)
    parser = BraceParser()
    scope = parser.method_at(parsed, 2)
    assert scope is not None
    assert scope.name == "a"
    assert scope.end_line == 4


def test_document_symbols_parse_nested_and_flat() -> None:
    nested = [
        {
            "name": "Service",
            "kind": 5,
            "range": {"start": {"line": 0, "character": 0}, "end": {"line": 6, "character": 0}},
            "selectionRange": {"start": {"line": 0, "character": 6}, "end": {"line": 0, "character": 13}},
            "children": [
                {
                    "name": "handle",
                    "kind": 6,
                    "range": {
                        "start": {"line": 1, "character": 4},
                        "end": {"line": 3, "character": 20},
                    },
                    "selectionRange": {
                        "start": {"line": 1, "character": 8},
                        "end": {"line": 1, "character": 14},
                    },
                }
            ],
        }
    ]
    symbols = parse_document_symbols(nested)
    assert symbols[0].qualified_name == "Service"
    assert symbols[0].children[0].qualified_name == "Service.handle"
    assert symbols[0].children[0].is_callable

    flat = [
        {
            "name": "load",
            "kind": 12,
            "location": {
                "uri": "file:///x/a.py",
                "range": {"start": {"line": 9, "character": 0}, "end": {"line": 11, "character": 0}},
            },
        }
    ]
    symbols = parse_document_symbols(flat)
    assert symbols[0].name == "load"
    assert symbols[0].range.start.line == 9
