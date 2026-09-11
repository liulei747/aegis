from __future__ import annotations

import json
from pathlib import Path

import pytest

from app.core.utils import from_uri, to_uri
from app.scanner.sarif import SarifParser
from tests.fixtures import write_sarif


def test_parses_finding_with_severity_and_region(tmp_path: Path) -> None:
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5)
    parser = SarifParser(workspace_root=tmp_path)

    findings = parser.parse_file(sarif)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "python.lang.security.sql-injection"
    assert finding.severity.value == "error"
    assert finding.path == "repo.py"  # relative to the workspace root
    assert finding.region.start_line == 4  # SARIF is 1-based, we store 0-based
    assert finding.region.start_char == 11
    assert finding.snippet.startswith("sql =")
    assert finding.properties["rule_summary"] == "SQL injection"
    assert finding.fingerprint == "fixture-fingerprint-1"
    assert finding.finding_id.startswith("F-")


def test_absolute_file_uri_is_made_relative(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    workspace.mkdir()
    sarif = write_sarif(tmp_path / "scan.sarif", workspace=workspace)
    parser = SarifParser(workspace_root=workspace)

    findings = parser.parse_file(sarif)

    assert findings[0].path == "repo.py"
    assert not Path(findings[0].path).is_absolute()


def test_foreign_absolute_path_is_rebased_onto_the_workspace(tmp_path: Path) -> None:
    """SARIF produced in another container says /workspace/... - we must rebase it."""
    workspace = tmp_path / "ws"
    (workspace / "app").mkdir(parents=True)
    (workspace / "app" / "repo.py").write_text("x = 1\n", encoding="utf-8")
    sarif = write_sarif(tmp_path / "scan.sarif")
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = "/workspace/app/repo.py"
    foreign = tmp_path / "foreign.sarif"
    foreign.write_text(json.dumps(doc), encoding="utf-8")

    findings = SarifParser(workspace_root=workspace).parse_file(foreign)

    assert findings[0].path == "app/repo.py"
    assert (workspace / findings[0].path).is_file()


def test_windows_absolute_path_is_rebased(tmp_path: Path) -> None:
    workspace = tmp_path / "ws"
    (workspace / "pkg").mkdir(parents=True)
    (workspace / "pkg" / "repo.py").write_text("x = 1\n", encoding="utf-8")
    sarif = write_sarif(tmp_path / "scan.sarif")
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = r"D:\build\agent\_work\repo\repo\pkg\repo.py"
    foreign = tmp_path / "foreign.sarif"
    foreign.write_text(json.dumps(doc), encoding="utf-8")

    findings = SarifParser(workspace_root=workspace).parse_file(foreign)

    assert findings[0].path == "pkg/repo.py"


def test_unresolvable_foreign_path_falls_back_to_the_longest_non_scaffold_suffix(
    tmp_path: Path,
) -> None:
    """When nothing matches on disk we still produce a stable, non-absolute path."""
    workspace = tmp_path / "ws"
    (workspace / "app").mkdir(parents=True)
    sarif = write_sarif(tmp_path / "scan.sarif")
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = "/workspace/app/deleted.py"
    foreign = tmp_path / "foreign.sarif"
    foreign.write_text(json.dumps(doc), encoding="utf-8")

    findings = SarifParser(workspace_root=workspace).parse_file(foreign)

    assert findings[0].path == "app/deleted.py"


def test_missing_location_is_skipped_not_fatal(tmp_path: Path) -> None:
    doc = {
        "runs": [
            {
                "tool": {"driver": {"name": "opengrep", "rules": []}},
                "results": [
                    {"ruleId": "x", "message": {"text": "no location"}},
                    {
                        "ruleId": "y",
                        "message": {"text": "ok"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 2},
                                }
                            }
                        ],
                    },
                ],
            }
        ]
    }
    parser = SarifParser(workspace_root=tmp_path)
    findings = parser.parse(doc)
    assert [f.rule_id for f in findings] == ["y"]


def test_invalid_sarif_raises_value_error(tmp_path: Path) -> None:
    path = tmp_path / "bad.sarif"
    path.write_text("{not json", encoding="utf-8")
    with pytest.raises(ValueError):
        SarifParser().parse_file(path)


def test_uri_roundtrip(tmp_path: Path) -> None:
    target = tmp_path / "a b" / "c.py"
    target.parent.mkdir(parents=True)
    target.write_text("x = 1\n", encoding="utf-8")
    assert from_uri(to_uri(target)) == target.resolve()


def test_severity_from_tags_when_level_absent(tmp_path: Path) -> None:
    doc = json.loads(
        json.dumps(
            {
                "runs": [
                    {
                        "tool": {
                            "driver": {
                                "name": "opengrep",
                                "rules": [
                                    {
                                        "id": "r1",
                                        "properties": {"tags": ["security", "high"]},
                                    }
                                ],
                            }
                        },
                        "results": [
                            {
                                "ruleId": "r1",
                                "message": {"text": "m"},
                                "locations": [
                                    {
                                        "physicalLocation": {
                                            "artifactLocation": {"uri": "b.py"},
                                            "region": {"startLine": 1},
                                        }
                                    }
                                ],
                            }
                        ],
                    }
                ]
            }
        )
    )
    findings = SarifParser(workspace_root=tmp_path).parse(doc)
    assert findings[0].severity.value == "error"
