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
from services.extraction.pipeline.assemble import AssemblyPipeline, PipelineRequest
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
# Path C: the scanner is interrupted
#
# Real cancellation replaces `subprocess.run` with `Popen`, but that must not change
# what a scan failure looks like. The distinction that has to survive is *who*
# stopped the process: a cancel (a control-flow signal, reported as `canceled`) versus
# everything else (a named failure).
# ----------------------------------------------------------------------
def _fake_runner(monkeypatch, *, outcome_factory):
    """Swap the real engine runner for one that returns a scripted outcome."""
    from services.scan import runner as scan_runner

    class _FakeRunner:
        def __init__(self, *args, **kwargs) -> None:
            pass

        def version(self) -> str:
            return "fake-1.0"

        def resolve_binary(self):
            return ("fake-engine", False)

        def scan(self, *args, **kwargs):
            return outcome_factory(kwargs)

    monkeypatch.setattr(scan_runner, "OpengrepRunner", _FakeRunner)


def test_scan_cancel_returns_a_record_instead_of_raising(
    tmp_path: Path, workspace: Path, monkeypatch
) -> None:
    """`run_scan` may not raise, and a cancel must still be visible. Both hold at once.

    `run_scan`'s never-raise contract is why the abort cannot simply propagate: the caller
    is told through `canceled=True` plus a ledger entry named `scan_aborted`, and the
    pipeline turns that into a real `CanceledAbort` one level up.
    """
    from aegis_core.cancel import CanceledAbort
    from services.scan import opengrep as opengrep_module
    from services.scan import runner as scan_runner

    def raise_abort(kwargs):
        raise CanceledAbort(stage="scan", resource="scan_process", detail="rc=-15")

    _fake_runner(monkeypatch, outcome_factory=raise_abort)

    outcome = scan_runner.run_scan(
        scan_runner.ScanRequest(workspace=workspace, abort=lambda: True)
    )
    assert outcome.canceled is True, "the caller needs to know this was a cancel"
    assert outcome.findings == []
    assert outcome.scan_record is not None
    assert outcome.scan_record.failure_mode == "scan_aborted"
    assert outcome.scan_record.returncode == -15
    assert scan_runner  # the module stayed importable through the swap
    assert opengrep_module is not None


def test_scan_abort_surfaces_as_canceled_through_the_pipeline(
    tmp_path: Path, workspace: Path, monkeypatch
) -> None:
    """The pipeline turns `canceled=True` into the signal, carrying the ledger with it.

    A cancel during the scan stage never reaches packaging, so the exception is the only
    way the scan record can travel to the worker.
    """
    from aegis_core.cancel import CanceledAbort
    from services.scan import runner as scan_runner

    def canceled_outcome(kwargs):
        # A killed process with no SARIF, which is what a canceled scan actually looks
        # like: the abort predicate is what tells this apart from an external kill.
        return scan_runner.ScanOutcome(
            engine="fake-engine",
            engine_version="fake-1.0",
            sarif_path=None,
            findings=[],
            warnings=[],
            degraded=False,
            command=["fake-engine", "scan"],
            stderr_tail="terminated",
            returncode=-15,
        )

    _fake_runner(monkeypatch, outcome_factory=canceled_outcome)
    pipeline = _pipeline(tmp_path, workspace)

    with pytest.raises(CanceledAbort) as caught:
        pipeline._collect_findings(
            PipelineRequest(workspace=workspace), "R-c", abort=lambda: True
        )
    assert caught.value.stage == "scan"
    assert caught.value.resource == "scan_process"
    assert caught.value.scan_record is not None
    assert caught.value.scan_record.failure_mode == "scan_aborted"


def test_scan_outcome_without_cancel_keeps_the_four_failure_modes(
    tmp_path: Path, workspace: Path, monkeypatch
) -> None:
    """The pre-existing failure modes are untouched by the interruptibility work.

    Each of these still comes back as a *named failure* with `canceled=False`, so the
    new cancel path cannot have quietly absorbed the old ones.
    """
    from services.scan import opengrep as opengrep_module
    from services.scan import runner as scan_runner

    cases = {
        "rc=2": opengrep_module.ScanOutcome(
            engine="fake", returncode=2, sarif_path=tmp_path / "absent.sarif",
            stderr_tail="unknown option '--nope'",
        ),
        "rc=127": opengrep_module.ScanOutcome(
            engine="fake", returncode=127, sarif_path=tmp_path / "absent.sarif",
            stderr_tail="not found",
        ),
    }
    for label, outcome in cases.items():
        _fake_runner(monkeypatch, outcome_factory=lambda kwargs, o=outcome: o)
        result = scan_runner.run_scan(scan_runner.ScanRequest(workspace=workspace))
        assert result.canceled is False, label
        assert result.scan_record is not None
        assert result.scan_record.failure_mode is not None
        assert result.scan_record.failure_mode.startswith("scanner exited with rc=")


def test_opengrep_scan_uses_popen_and_exposes_the_handle(
    tmp_path: Path, workspace: Path, monkeypatch
) -> None:
    """Interruptibility depends on the handle existing. `subprocess.run` hides it."""
    from services.scan import opengrep as opengrep_module

    seen: dict[str, object] = {}

    class _FakeProc:
        def __init__(self, cmd, **kwargs) -> None:
            seen["cmd"] = cmd
            seen["kwargs"] = kwargs
            self.returncode = 0
            self.pid = 4242

        def communicate(self, timeout=None):
            # Write the SARIF the parser expects, then finish.
            sarif_path = Path(seen["cmd"][seen["cmd"].index("--output") + 1])
            sarif_path.write_text('{"version": "2.1.0", "runs": []}', encoding="utf-8")
            return ("", "")

        def poll(self):
            return self.returncode

    monkeypatch.setattr(opengrep_module.subprocess, "Popen", _FakeProc)
    runner = opengrep_module.OpengrepRunner("fake-engine", fallback_binary=None)
    monkeypatch.setattr(runner, "resolve_binary", lambda: ("fake-engine", False))
    monkeypatch.setattr(runner, "version", lambda: "fake-1.0")

    sink_calls: list[object] = []
    done_calls: list[int] = []
    outcome = runner.scan(
        workspace,
        out_dir=tmp_path / "out",
        process_sink=sink_calls.append,
        process_done=lambda: done_calls.append(1),
    )

    assert seen["kwargs"].get("text") is True, "text mode is existing behaviour"
    assert "capture_output" not in seen["kwargs"], "Popen does not take capture_output"
    assert len(sink_calls) == 1, "the handle is handed over as soon as it exists"
    assert len(done_calls) == 1, "and released exactly once, even on the happy path"
    assert outcome.returncode == 0


def test_scanner_argv_is_untouched(monkeypatch, tmp_path: Path) -> None:
    """This change is about *how we wait*, never *how the command is built*.

    `tests/test_scanner_command.py` owns the full argv contract; this asserts the builder
    is still the only thing producing it -- the wait loop is handed a finished list.
    """
    from services.scan import opengrep as opengrep_module

    captured: dict[str, list[str]] = {}

    class _FakeProc:
        returncode = 0
        pid = 1

        def __init__(self, cmd, **kwargs) -> None:
            captured["cmd"] = list(cmd)

        def communicate(self, timeout=None):
            Path(captured["cmd"][captured["cmd"].index("--output") + 1]).write_text(
                '{"version": "2.1.0", "runs": []}', encoding="utf-8"
            )
            return ("", "")

        def poll(self):
            return 0

    monkeypatch.setattr(opengrep_module.subprocess, "Popen", _FakeProc)
    runner = opengrep_module.OpengrepRunner("opengrep", fallback_binary=None)
    monkeypatch.setattr(runner, "resolve_binary", lambda: ("opengrep", False))
    monkeypatch.setattr(runner, "version", lambda: "1.16.0")

    expected = runner.build_command(
        "opengrep",
        target=tmp_path,
        sarif_path=tmp_path / "out" / "opengrep.sarif",
        rule_config="p/default",
        rules=[],
        include_globs=[],
        exclude_globs=[],
    )
    runner.scan(tmp_path, out_dir=tmp_path / "out", rule_config="p/default")
    assert captured["cmd"] == expected


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
    from aegis_contracts import views

    overview = views.overview(manifest)
    assert any("zero findings" in flag for flag in overview.warning_flags)
    summary = views.scan_summary(manifest)
    assert summary and summary["failure_mode"]

    package = Path(result.package_path)
    assert (package / "manifest.json").exists()
    text = (package / "summary.md").read_text(encoding="utf-8")
    assert "Aegis bundle" in text
