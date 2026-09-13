"""A fake `opengrep` on PATH, so process-level tests work without the real engine.

`tests/fake_scanner.py` is the implementation; this module puts an executable with the right
*name* in front of `PATH`, because the runner resolves the engine by name (`shutil.which` and
`Path(exe).stem.startswith("opengrep")` decide both availability and which argv dialect to
speak). A test double that cannot be found is not a test double.
"""

from __future__ import annotations

import os
import stat
from pathlib import Path

FAKE_SCANNER = Path(__file__).resolve().parent / "fake_scanner.py"


def install_fake_opengrep(
    tmp_path: Path, monkeypatch, *, name: str = "opengrep", sleep_s: float | None = None
) -> Path:
    """Create an executable named ``opengrep`` and put its directory first on PATH.

    ``sleep_s`` overrides how long the stand-in pretends to scan: a cancellation test needs
    it to outlive the test, while a test that wants a completed scan needs it to return
    immediately.
    """
    bindir = tmp_path / "bin"
    bindir.mkdir(parents=True, exist_ok=True)
    exe = bindir / name

    if os.name == "nt":
        # A .cmd shim: Windows cannot exec a Python file by name, and `shutil.which` looks
        # for PATHEXT matches.
        exe = bindir / f"{name}.cmd"
        exe.write_text(
            f'@echo off\r\n"{os.sys.executable}" "{FAKE_SCANNER}" %*\r\n', encoding="utf-8"
        )
    else:
        exe.write_text(
            f'#!/bin/sh\nexec "{os.sys.executable}" "{FAKE_SCANNER}" "$@"\n', encoding="utf-8"
        )
        exe.chmod(exe.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)

    monkeypatch.setenv("PATH", str(bindir) + os.pathsep + os.environ.get("PATH", ""))
    monkeypatch.setenv("AEGIS_OPENGREP_BIN", name)
    monkeypatch.setenv("AEGIS_OPENGREP_FALLBACK_BIN", "")
    if sleep_s is not None:
        monkeypatch.setenv("AEGIS_FAKE_SCANNER_SLEEP_S", str(sleep_s))
    return exe
