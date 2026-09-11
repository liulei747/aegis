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


def write_fixture(root: Path) -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "handler.py").write_text(HANDLER, encoding="utf-8")
    (root / "service.py").write_text(SERVICE, encoding="utf-8")
    (root / "repo.py").write_text(REPO, encoding="utf-8")
    (root / "util.py").write_text(UTIL, encoding="utf-8")
    return root


def write_two_hits_sarif(path: Path, *, workspace: Path | None = None) -> Path:
    """Two rules hitting the same method: exercises find-duplication, not loss."""
    base = json.loads(
        write_sarif(path.with_name("_base.sarif"), sink_line=5, workspace=workspace).read_text(
            encoding="utf-8"
        )
    )
    first = base["runs"][0]["results"][0]
    second = json.loads(json.dumps(first))
    second["ruleId"] = "python.lang.security.sql-injection-2"
    second["message"]["text"] = "second rule, same sink"
    second["locations"][0]["physicalLocation"]["region"]["startColumn"] = 20
    base["runs"][0]["results"] = [first, second]
    path.write_text(json.dumps(base, indent=2), encoding="utf-8")
    return path


def write_sarif(path: Path, *, sink_line: int = 5, workspace: Path | None = None) -> Path:
    """A SARIF file that points at repo.py:query_user's string concatenation."""
    uri = "repo.py"
    if workspace is not None:
        uri = (workspace / "repo.py").resolve().as_uri()
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
                                        "startLine": sink_line,
                                        "startColumn": 12,
                                        "endLine": sink_line,
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
