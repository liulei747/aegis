"""Scan stage: the four ways it can end, and the guarantee that none of them raise.

A scanner that fails, a missing SARIF, an empty SARIF and a corrupt SARIF all have
to yield the same shape of result — zero findings plus a named failure mode — so
that "no findings" can never be confused with "the scan did not really happen".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_contracts.domain import Severity
from aegis_core.config import BudgetConfig, Settings
from app.pipeline.assemble import AssemblyPipeline, PipelineRequest
from tests.fixtures import write_sarif


def _pipeline(tmp_path: Path, workspace: Path, **overrides) -> AssemblyPipeline:
    settings = Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        budget=BudgetConfig(),
        lsp_enabled=False,
        **overrides,
    ).resolve()
    return AssemblyPipeline(settings)


# ----------------------------------------------------------------------
# Path A: an existing SARIF file
# ----------------------------------------------------------------------
def test_path_a_parses_sarif_and_records_the_invocation(tmp_path: Path, workspace: Path) -> None:
    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    pipeline = _pipeline(tmp_path, workspace)

    findings, path, engine, warnings, record = pipeline._collect_findings(
        PipelineRequest(workspace=workspace, sarif_path=sarif), "R-a"
    )

    assert engine == "sarif-input"
    assert path == sarif.resolve()
    assert warnings == []
    assert record.failure_mode is None
    assert record.configured is True
    assert record.zero_findings_is_suspicious is False
    assert record.returncode == 0
    assert record.rule_counts == {"python.lang.security.sql-injection": 1}
    assert record.severity_counts == {"error": 1}
    assert record.top_paths == [("repo.py", 1)]
    assert len(findings) == 1

    finding = findings[0]
    assert finding.severity is Severity.ERROR
    assert finding.path == "repo.py"
    assert finding.region.start_line == 4  # SARIF is 1-based, we store 0-based
    assert finding.snippet.startswith("sql =")
    assert finding.properties["rule_summary"] == "SQL injection"
    assert finding.fingerprint == "fixture-fingerprint-1"


def test_path_a_missing_sarif_raises_clearly(tmp_path: Path, workspace: Path) -> None:
    """A user-supplied path that does not exist is a request error, not a scan result."""
    pipeline = _pipeline(tmp_path, workspace)
    with pytest.raises(FileNotFoundError):
        pipeline._collect_findings(
            PipelineRequest(workspace=workspace, sarif_path=tmp_path / "nope.sarif"), "R-a"
        )


def test_path_a_corrupt_sarif_raises_value_error(tmp_path: Path, workspace: Path) -> None:
    bad = tmp_path / "bad.sarif"
    bad.write_text("{ this is not json", encoding="utf-8")
    pipeline = _pipeline(tmp_path, workspace)
    with pytest.raises(ValueError):
        pipeline._collect_findings(
            PipelineRequest(workspace=workspace, sarif_path=bad), "R-a"
        )


def test_path_a_finding_without_location_is_skipped_not_fatal(
    tmp_path: Path, workspace: Path
) -> None:
    doc = {
        "runs": [
            {
                "tool": {"driver": {"name": "opengrep", "rules": []}},
                "results": [
                    {"ruleId": "no-location", "message": {"text": "x"}},
                    {
                        "ruleId": "ok",
                        "message": {"text": "y"},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": "a.py"},
                                    "region": {"startLine": 3},
                                }
                            }
                        ],
                    },
                ],
            }
        ]
    }
    sarif = tmp_path / "mixed.sarif"
    sarif.write_text(json.dumps(doc), encoding="utf-8")
    pipeline = _pipeline(tmp_path, workspace)

    findings, _, _, _, record = pipeline._collect_findings(
        PipelineRequest(workspace=workspace, sarif_path=sarif), "R-a"
    )
    assert [f.rule_id for f in findings] == ["ok"]
    assert record.rule_counts == {"ok": 1}


# ----------------------------------------------------------------------
# Path B: the pipeline runs the scanner itself
# ----------------------------------------------------------------------
def test_path_b_missing_binary_degrades_to_empty_result_not_an_exception(
    tmp_path: Path, workspace: Path
) -> None:
    """No scanner on PATH is a *degraded result*, not an exception.

    The scan capability returns zero findings with a named failure mode, exactly as
    it does for any other scan failure. Raising here would have made "no scanner"
    the only scan outcome the pipeline had to special-case, and the only one that
    cannot be reported inside the bundle.
    """
    pipeline = _pipeline(
        tmp_path,
        workspace,
        opengrep_bin="definitely-not-installed-opengrep",
        opengrep_fallback_bin=None,
    )

    findings, _, engine, warnings, record = pipeline._collect_findings(
        PipelineRequest(workspace=workspace), "R-b"
    )
    assert findings == []
    assert engine == "definitely-not-installed-opengrep"
    assert record.failure_mode is not None
    assert "could not be started" in record.failure_mode
    assert record.zero_findings_is_suspicious is True
    assert warnings and "could not be started" in warnings[0]


def test_scan_service_probe_reports_a_missing_engine() -> None:
    """The scan service's /health depends on this staying non-raising."""
    from services.scan.runner import probe

    result = probe("definitely-not-installed-opengrep", fallback=None)
    assert result["available"] is False
    assert "reason" in result


@pytest.mark.parametrize("exit_code", [2, 127])
def test_path_b_bad_exit_code_yields_a_named_failure_mode(
    tmp_path: Path, workspace: Path, exit_code: int, monkeypatch
) -> None:
    """A scanner that exits non-zero must not crash the run, and must be nameable."""
    from services.scan import opengrep as opengrep_module
    from services.scan.opengrep import ScanOutcome

    sarif = tmp_path / "work" / "R-b" / "opengrep.sarif"

    def fake_scan(self, target, **kwargs):
        sarif.parent.mkdir(parents=True, exist_ok=True)
        sarif.write_bytes(b"")  # what a failed scanner leaves behind
        return ScanOutcome(
            engine="opengrep",
            returncode=exit_code,
            sarif_path=sarif,
            command=["opengrep", "scan"],
            stderr_tail="opengrep scan: unknown option '--nope'",
        )

    monkeypatch.setattr(opengrep_module.OpengrepRunner, "scan", fake_scan)
    pipeline = _pipeline(tmp_path, workspace)

    findings, _, engine, warnings, record = pipeline._collect_findings(
        PipelineRequest(workspace=workspace, rule_config="auto"), "R-b"
    )

    assert findings == []
    assert engine == "opengrep"
    assert record.returncode == exit_code
    assert record.failure_mode is not None
    assert f"rc={exit_code}" in record.failure_mode
    assert record.zero_findings_is_suspicious is True
    assert any("rc=" in w for w in warnings)


def test_path_b_empty_sarif_is_a_failure_mode_not_a_clean_result(
    tmp_path: Path, workspace: Path, monkeypatch
) -> None:
    from services.scan import opengrep as opengrep_module
    from services.scan.opengrep import ScanOutcome

    sarif = tmp_path / "work" / "R-b" / "opengrep.sarif"

    def fake_scan(self, target, **kwargs):
        sarif.parent.mkdir(parents=True, exist_ok=True)
        sarif.write_bytes(b"")
        return ScanOutcome(engine="opengrep", returncode=0, sarif_path=sarif)

    monkeypatch.setattr(opengrep_module.OpengrepRunner, "scan", fake_scan)
    pipeline = _pipeline(tmp_path, workspace)

    findings, _, _, _, record = pipeline._collect_findings(
        PipelineRequest(workspace=workspace, rule_config="auto"), "R-b"
    )
    assert findings == []
    assert "empty SARIF" in (record.failure_mode or "")
    assert record.zero_findings_is_suspicious is True


def test_path_b_corrupt_sarif_is_a_failure_mode_not_a_crash(
    tmp_path: Path, workspace: Path, monkeypatch
) -> None:
    from services.scan import opengrep as opengrep_module
    from services.scan.opengrep import ScanOutcome

    sarif = tmp_path / "work" / "R-b" / "opengrep.sarif"

    def fake_scan(self, target, **kwargs):
        sarif.parent.mkdir(parents=True, exist_ok=True)
        sarif.write_bytes(b"<html>not sarif at all</html>")
        return ScanOutcome(engine="opengrep", returncode=0, sarif_path=sarif)

    monkeypatch.setattr(opengrep_module.OpengrepRunner, "scan", fake_scan)
    pipeline = _pipeline(tmp_path, workspace)

    findings, _, _, _, record = pipeline._collect_findings(
        PipelineRequest(workspace=workspace, rule_config="auto"), "R-b"
    )
    assert findings == []
    assert "not valid SARIF" in (record.failure_mode or "")
    assert record.zero_findings_is_suspicious is True


def test_path_b_missing_sarif_file_is_a_failure_mode(
    tmp_path: Path, workspace: Path, monkeypatch
) -> None:
    from services.scan import opengrep as opengrep_module
    from services.scan.opengrep import ScanOutcome

    missing = tmp_path / "work" / "R-b" / "never-written.sarif"

    def fake_scan(self, target, **kwargs):
        return ScanOutcome(engine="opengrep", returncode=0, sarif_path=missing)

    monkeypatch.setattr(opengrep_module.OpengrepRunner, "scan", fake_scan)
    pipeline = _pipeline(tmp_path, workspace)

    findings, _, _, warnings, record = pipeline._collect_findings(
        PipelineRequest(workspace=workspace, rule_config="auto"), "R-b"
    )
    assert findings == []
    assert "no SARIF output" in (record.failure_mode or "")
    assert any("no SARIF output" in w for w in warnings)


def test_path_b_zero_findings_without_explicit_rules_is_flagged(
    tmp_path: Path, workspace: Path, monkeypatch
) -> None:
    """The dangerous case: a valid, empty, unconfigured scan looks like a clean repo."""
    from services.scan import opengrep as opengrep_module
    from services.scan.opengrep import ScanOutcome

    sarif = tmp_path / "work" / "R-b" / "opengrep.sarif"
    empty = json.dumps({"runs": [{"tool": {"driver": {"rules": []}}, "results": []}]})

    def fake_scan(self, target, **kwargs):
        sarif.parent.mkdir(parents=True, exist_ok=True)
        sarif.write_text(empty, encoding="utf-8")
        return ScanOutcome(engine="opengrep", returncode=0, sarif_path=sarif)

    monkeypatch.setattr(opengrep_module.OpengrepRunner, "scan", fake_scan)
    pipeline = _pipeline(tmp_path, workspace)

    findings, _, _, _, record = pipeline._collect_findings(
        PipelineRequest(workspace=workspace), "R-b"  # no rules, no config
    )
    assert findings == []
    assert record.failure_mode is None  # the scanner worked...
    assert record.configured is False
    assert record.zero_findings_is_suspicious is True  # ...but the result means nothing


def test_path_b_successful_scan_is_not_suspicious(
    tmp_path: Path, workspace: Path, monkeypatch
) -> None:
    from services.scan import opengrep as opengrep_module
    from services.scan.opengrep import ScanOutcome

    sarif = tmp_path / "work" / "R-b" / "opengrep.sarif"
    payload = json.loads(
        write_sarif(tmp_path / "src.sarif", sink_line=5, workspace=workspace).read_text(
            encoding="utf-8"
        )
    )

    def fake_scan(self, target, **kwargs):
        sarif.parent.mkdir(parents=True, exist_ok=True)
        sarif.write_text(json.dumps(payload), encoding="utf-8")
        return ScanOutcome(
            engine="opengrep", returncode=1, sarif_path=sarif, command=["opengrep", "scan"]
        )

    monkeypatch.setattr(opengrep_module.OpengrepRunner, "scan", fake_scan)
    pipeline = _pipeline(tmp_path, workspace)

    findings, _, engine, warnings, record = pipeline._collect_findings(
        PipelineRequest(workspace=workspace, rule_config="p/python"), "R-b"
    )
    assert engine == "opengrep"
    assert len(findings) == 1
    assert record.returncode == 1  # 1 means "findings present" for semgrep-family
    assert record.failure_mode is None
    assert record.zero_findings_is_suspicious is False
    assert record.configured is True
    assert warnings == []


# ----------------------------------------------------------------------
# A failed scan still produces an auditable bundle
# ----------------------------------------------------------------------
def test_failed_scan_still_produces_a_bundle_that_says_why(
    tmp_path: Path, workspace: Path, monkeypatch
) -> None:
    import asyncio

    from services.scan import opengrep as opengrep_module
    from services.scan.opengrep import ScanOutcome

    sarif = tmp_path / "work" / "R-b" / "opengrep.sarif"

    def fake_scan(self, target, **kwargs):
        sarif.parent.mkdir(parents=True, exist_ok=True)
        sarif.write_bytes(b"")
        return ScanOutcome(
            engine="opengrep",
            returncode=2,
            sarif_path=sarif,
            command=["opengrep", "scan", "--nope"],
            stderr_tail="opengrep scan: unknown option '--nope'.",
        )

    monkeypatch.setattr(opengrep_module.OpengrepRunner, "scan", fake_scan)
    pipeline = _pipeline(tmp_path, workspace)

    result = asyncio.run(
        pipeline.run(PipelineRequest(workspace=workspace, rule_config="auto", package_name="B-fail"))
    )

    assert result.bundle is not None
    manifest = result.bundle.manifest
    assert manifest.focus_count == 0
    assert manifest.findings == []
    scan = manifest.stats.scan
    assert scan is not None
    assert scan.failure_mode and "rc=2" in scan.failure_mode
    assert scan.command == ["opengrep", "scan", "--nope"]
    assert "unknown option" in scan.stderr_tail

    # the reviewer can see it in the derived views, not only in the raw manifest
    from app.observability import views

    overview = views.overview(manifest)
    assert any("zero findings" in flag for flag in overview.warning_flags)
    summary = views.scan_summary(manifest)
    assert summary and summary["failure_mode"]

    package = Path(result.package_path)
    assert (package / "manifest.json").exists()
    text = (package / "summary.md").read_text(encoding="utf-8")
    assert "Aegis bundle" in text
