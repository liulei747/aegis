"""Scanner command construction.

These tests exist because a wrong flag silently produces an empty bundle: the
runner records `rc=2` and the pipeline then reports "no findings". That already
happened once with `--metrics=off` (semgrep-only; opengrep rejects it).
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

from services.scan.opengrep import OpengrepRunner

TARGET = Path("/tmp/aegis-repo")
SARIF = Path("/tmp/aegis.sarif")


def _cmd(exe: str, **kwargs) -> list[str]:
    runner = OpengrepRunner(exe)
    return runner.build_command(
        exe,
        target=TARGET,
        sarif_path=SARIF,
        rule_config=kwargs.get("rule_config"),
        rules=kwargs.get("rules", []),
        include_globs=kwargs.get("include", []),
        exclude_globs=kwargs.get("exclude", []),
    )


def test_opengrep_never_gets_semgrep_only_metrics_flag() -> None:
    cmd = _cmd("/usr/local/bin/opengrep")
    assert "--metrics=off" not in cmd
    assert cmd[1] == "scan"


def test_semgrep_keeps_metrics_opt_out_and_no_subcommand() -> None:
    cmd = _cmd("/usr/local/bin/semgrep")
    assert "--metrics=off" in cmd
    assert cmd[1] != "scan"


@pytest.mark.parametrize("exe", ["/usr/local/bin/opengrep", "/usr/local/bin/semgrep"])
def test_common_flags_are_present_for_both_engines(exe: str) -> None:
    cmd = _cmd(exe, rule_config="auto", include=["src/**"], exclude=["vendor/**"])
    joined = " ".join(cmd)
    assert "--sarif" in cmd
    assert "--output" in cmd and str(SARIF) in cmd
    assert "--quiet" in cmd
    assert "--config auto" in joined
    assert "--include src/**" in joined
    assert "--exclude vendor/**" in joined
    assert cmd[-1] == str(TARGET)


def test_multiple_rules_and_a_config_are_all_forwarded() -> None:
    cmd = _cmd("/usr/local/bin/opengrep", rules=["p/default", "rules/local.yaml"], rule_config="auto")
    assert cmd.count("--config") == 3


def test_default_config_is_auto_when_nothing_is_given() -> None:
    cmd = _cmd("/usr/local/bin/opengrep")
    assert "--config" in cmd
    assert cmd[cmd.index("--config") + 1] == "auto"


# ----------------------------------------------------------------------
# Live check: only runs where a real scanner is installed.
#
# It asserts the *absence of a CLI misuse*, not that the scanner works: an
# installed-but-broken scanner must not fail this test. That already bit us on a
# Windows host where semgrep exits 2 with an empty stderr for unrelated reasons.
# ----------------------------------------------------------------------
def _run(cmd: list[str]) -> subprocess.CompletedProcess[bytes]:
    return subprocess.run(cmd, capture_output=True, timeout=300, check=False)


@pytest.mark.parametrize("binary", ["opengrep", "semgrep"])
def test_live_binary_rejects_none_of_our_flags(binary: str, tmp_path: Path) -> None:
    exe = shutil.which(binary)
    if exe is None:
        pytest.skip(f"{binary} not installed")

    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text(
        'def run(user_id):\n    return "SELECT * FROM t WHERE id = \'" + user_id + "\'"\n',
        encoding="utf-8",
    )
    sarif = tmp_path / "out.sarif"
    runner = OpengrepRunner(exe, timeout_s=300)
    cmd = runner.build_command(
        exe,
        target=repo,
        sarif_path=sarif,
        rule_config=None,
        rules=["p/python"],
        include_globs=[],
        exclude_globs=[],
    )
    proc = _run(cmd)
    stderr = (proc.stderr or b"").decode("utf-8", "replace")

    # A scanner telling us our flags are wrong is exactly the regression we guard.
    assert "unknown option" not in stderr.lower(), f"{binary}: {stderr[-400:]}"
    assert "unrecognized arguments" not in stderr.lower(), f"{binary}: {stderr[-400:]}"
    assert "--help" not in stderr, f"{binary} printed usage: {stderr[-400:]}"

