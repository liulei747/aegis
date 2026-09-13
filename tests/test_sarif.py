from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_core.utils import from_uri, to_uri
from services.scan.sarif import SarifParser
from tests.fixtures import FILES, sink_line_in_fixture, write_sarif


def test_the_sample_sarif_points_at_the_line_it_quotes(tmp_path: Path) -> None:
    """The demo fixture's region must agree with the snippet beside it.

    It did not: `sink_line` was a hardcoded 5 written next to a hardcoded `snippet`, and when
    the fixture gained a leading docstring and two blank lines the snippet moved to line 6
    while the number did not. Nothing failed, because the parser tests only assert the
    1-based-to-0-based conversion, so the wrong line survived all the way into
    `demo/scan.sarif`, the bundle, and every prompt built from it -- which would tell a model
    "at repo.py:5" about a statement on line 6. This test pins the two together.
    """
    sarif = write_sarif(tmp_path / "scan.sarif")

    finding = SarifParser(workspace_root=tmp_path).parse_file(sarif)[0]

    line = finding.region.start_line  # 0-based
    source = FILES["repo.py"].splitlines()
    assert finding.snippet in source[line], (
        f"the SARIF region points at line {line + 1} ({source[line]!r}) "
        f"but quotes {finding.snippet!r}"
    )
    assert line + 1 == sink_line_in_fixture()


def test_parses_finding_with_severity_and_region(tmp_path: Path) -> None:
    sarif = write_sarif(tmp_path / "scan.sarif")
    parser = SarifParser(workspace_root=tmp_path)

    findings = parser.parse_file(sarif)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.rule_id == "python.lang.security.sql-injection"
    assert finding.severity.value == "error"
    assert finding.path == "repo.py"  # relative to the workspace root
    assert finding.region.start_line == 5  # SARIF is 1-based, we store 0-based
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


def test_a_foreign_path_matches_a_file_at_the_workspace_root(tmp_path: Path) -> None:
    """The file the finding is about sits directly at the workspace root.

    Measured failure: `file:///E:/vib%20coding/aegis/demo/repo/repo.py` against a root holding
    `repo.py` resolved to `vib coding/aegis/demo/repo/repo.py` -- a path that does not exist --
    so every finding failed to locate and the bundle came out with **zero methods** while the
    run still reported success. Every candidate suffix kept at least one directory, so the only
    possible match (the bare file name) was never tried.
    """
    workspace = tmp_path / "ws"
    workspace.mkdir()
    (workspace / "repo.py").write_text("x = 1\n", encoding="utf-8")
    sarif = write_sarif(tmp_path / "scan.sarif")
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = "file:///E:/vib%20coding/aegis/demo/repo/repo.py"
    foreign = tmp_path / "foreign.sarif"
    foreign.write_text(json.dumps(doc), encoding="utf-8")

    findings = SarifParser(workspace_root=workspace).parse_file(foreign)

    assert findings[0].path == "repo.py"
    assert (workspace / findings[0].path).is_file()


def test_a_specific_suffix_wins_over_a_bare_name(tmp_path: Path) -> None:
    """`app/repo.py` beats `repo.py` when both exist: the longer match is the real one."""
    workspace = tmp_path / "ws"
    (workspace / "app").mkdir(parents=True)
    (workspace / "app" / "repo.py").write_text("x = 1\n", encoding="utf-8")
    (workspace / "repo.py").write_text("y = 2\n", encoding="utf-8")
    sarif = write_sarif(tmp_path / "scan.sarif")
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = "/workspace/app/repo.py"
    foreign = tmp_path / "foreign.sarif"
    foreign.write_text(json.dumps(doc), encoding="utf-8")

    findings = SarifParser(workspace_root=workspace).parse_file(foreign)

    assert findings[0].path == "app/repo.py"


def test_an_ambiguous_bare_name_is_refused_rather_than_guessed(tmp_path: Path) -> None:
    """Two files share the name, so the bare name identifies nothing.

    Guessing would attach the finding to the wrong file, which is worse than failing to locate
    it: the bundle would carry a confident, wrong location.
    """
    workspace = tmp_path / "ws"
    (workspace / "a").mkdir(parents=True)
    (workspace / "b").mkdir(parents=True)
    (workspace / "a" / "utils.py").write_text("x = 1\n", encoding="utf-8")
    (workspace / "b" / "utils.py").write_text("y = 2\n", encoding="utf-8")
    sarif = write_sarif(tmp_path / "scan.sarif")
    doc = json.loads(sarif.read_text(encoding="utf-8"))
    doc["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"][
        "uri"
    ] = "/build/agent/_work/repo/repo/src/utils.py"
    foreign = tmp_path / "foreign.sarif"
    foreign.write_text(json.dumps(doc), encoding="utf-8")

    findings = SarifParser(workspace_root=workspace).parse_file(foreign)

    assert findings[0].path not in ("a/utils.py", "b/utils.py")
    assert not (workspace / findings[0].path).is_file()


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
