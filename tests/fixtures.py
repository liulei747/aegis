r"""Fixture repo for the test-suite: a realistic, tiny taint chain.

handler.py:handle_request  ->  service.py:load_user  ->  repo.py:query_user
                                              \->  util.py:safe_escape
"""

from __future__ import annotations

import json
from pathlib import Path

HANDLER = '''\
"""Request handler - untrusted entry point."""

import sqlite3

from service import load_user
from util import safe_escape


def handle_request(request):
    user_id = request.args.get("id")
    name = safe_escape(user_id)
    return load_user(name)


def unused_helper(value):
    return value


class Controller:
    def dispatch(self, request):
        return handle_request(request)
'''

SERVICE = '''\
"""Domain service."""

from repo import query_user


def load_user(user_id):
    return query_user(user_id)


def unused_service_helper():
    return 42
'''

REPO = '''\
"""Data access - the sink."""


def query_user(user_id):
    cursor = connect()
    sql = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(sql)
    return cursor


def connect():
    import sqlite3

    return sqlite3.connect("app.db")
'''

UTIL = '''\
"""Utilities."""


def safe_escape(value):
    return value.replace("'", "''")
'''


FILES: dict[str, str] = {
    "handler.py": HANDLER,
    "service.py": SERVICE,
    "repo.py": REPO,
    "util.py": UTIL,
}


def write_fixture(root: Path) -> Path:
    """Materialise the fixture repo, touching only the files that differ.

    Idempotent on purpose: `demo/repo` is checked into the repository (compose mounts
    it by default), so `scripts/demo.py` re-running over it must not rewrite
    identical files -- that churns mtimes and makes `git status` noisy for no reason.
    """
    root.mkdir(parents=True, exist_ok=True)
    for name, text in FILES.items():
        target = root / name
        if target.exists() and target.read_text(encoding="utf-8") == text:
            continue
        target.write_text(text, encoding="utf-8")
    return root


def write_two_hits_sarif(path: Path, *, workspace: Path | None = None) -> Path:
    """Two rules hitting the same method: exercises find-duplication, not loss."""
    base = json.loads(
        write_sarif(path.with_name("_base.sarif"), workspace=workspace).read_text(encoding="utf-8")
    )
    first = base["runs"][0]["results"][0]
    second = json.loads(json.dumps(first))
    second["ruleId"] = "python.lang.security.sql-injection-2"
    second["message"]["text"] = "second rule, same sink"
    second["locations"][0]["physicalLocation"]["region"]["startColumn"] = 20
    base["runs"][0]["results"] = [first, second]
    path.write_text(json.dumps(base, indent=2), encoding="utf-8")
    return path


def sink_line_in_fixture() -> int:
    """1-based line of the fixture's concatenation sink, derived from the source.

    This used to be a hardcoded `5` next to a hardcoded `snippet`. When the fixture's
    leading docstring and blank lines were added, the snippet moved to line 6 and the
    number did not, so `demo/scan.sarif` claimed a region on the `cursor = connect()`
    line while quoting the statement below it. Every downstream line number was then
    off by one -- the bundle looked self-consistent and the prompt still told the model
    "at repo.py:5" about a line 6 finding. Deriving it means the two cannot drift.
    """
    lines = FILES["repo.py"].splitlines()
    for index, line in enumerate(lines):
        if "SELECT * FROM users" in line:
            return index + 1
    raise AssertionError("the fixture no longer contains its concatenation sink")


def write_sarif(
    path: Path,
    *,
    sink_line: int | None = None,
    workspace: Path | None = None,
    region_line: int | None = None,
) -> Path:
    """A SARIF file that points at repo.py:query_user's string concatenation.

    `sink_line` only feeds the finding id; the *region* defaults to the real sink line, which
    keeps the document pointing at the snippet it quotes. Tests that need a deliberate
    position (a finding outside any method, say) pass `region_line` explicitly.
    """
    uri = "repo.py"
    if workspace is not None:
        uri = (workspace / "repo.py").resolve().as_uri()
    line = sink_line_in_fixture() if region_line is None else region_line
    doc = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "opengrep",
                        "rules": [
                            {
                                "id": "python.lang.security.sql-injection",
                                "shortDescription": {"text": "SQL injection"},
                                "defaultConfiguration": {"level": "error"},
                                "properties": {"tags": ["security", "CWE-89"]},
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": "python.lang.security.sql-injection",
                        "level": "error",
                        "message": {"text": "User input concatenated into a SQL statement"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": uri},
                                    "region": {
                                        "startLine": line,
                                        "startColumn": 12,
                                        "endLine": line,
                                        "endColumn": 60,
                                        "snippet": {
                                            "text": 'sql = "SELECT * FROM users WHERE id = \'" + user_id + "\'"'
                                        },
                                    },
                                }
                            }
                        ],
                        "fingerprints": {"matchBasedId/v1": "fixture-fingerprint-1"},
                    }
                ],
            }
        ],
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return path
