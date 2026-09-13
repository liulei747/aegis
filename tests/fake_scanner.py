"""A fake scanner process, so cancellation can be tested where no engine is installed.

Cancellation is about terminating a *process*. Without an engine on PATH the runner never
spawns one, so the tests would either be skipped (and prove nothing) or pass for the wrong
reason. This script stands in for opengrep: it accepts the same argv the real one does,
writes a minimal SARIF where `--output` says, and then sleeps long enough for a cancel to
land.

It lives in `tests/` because it is a test double, in the same spirit as
`tests/fake_lsp_server.py` -- and for the same reason: the behaviour under test is the
process lifecycle, not the scanner.
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

#: How long the stand-in pretends to scan. 120s makes cancellation tests deterministic
#: (an uncancelled run cannot finish inside a test); a test that wants a *completed* scan
#: sets `AEGIS_FAKE_SCANNER_SLEEP_S=0` so it does not wait for the pretense.
DEFAULT_SLEEP_S = 120.0


def main(argv: list[str]) -> int:
    if "--version" in argv:
        print("fake-opengrep 0.0.0")
        return 0

    out: Path | None = None
    if "--output" in argv:
        out = Path(argv[argv.index("--output") + 1])

    if out is not None:
        out.parent.mkdir(parents=True, exist_ok=True)
        # A valid, empty SARIF: the parser accepts it and the run stays auditable.
        out.write_text(
            json.dumps(
                {
                    "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
                    "version": "2.1.0",
                    "runs": [
                        {
                            "tool": {"driver": {"name": "fake-opengrep", "rules": []}},
                            "results": [],
                        }
                    ],
                }
            ),
            encoding="utf-8",
        )

    try:
        sleep_s = float(os.getenv("AEGIS_FAKE_SCANNER_SLEEP_S", str(DEFAULT_SLEEP_S)))
    except ValueError:  # pragma: no cover - bad env value
        sleep_s = DEFAULT_SLEEP_S

    # A grandchild, to mirror the real engine's shape: opengrep is a launcher, and the work
    # happens in `opengrep-core`. Terminating only the direct child leaves the core running --
    # that is not a hypothesis, it was measured (640% CPU still burning after a cancel that
    # reported success). A test double without a child cannot catch that class of bug.
    if os.getenv("AEGIS_FAKE_SCANNER_SPAWN_CHILD") == "1":
        import subprocess

        marker = os.getenv("AEGIS_FAKE_SCANNER_CHILD_MARKER", "")
        child = subprocess.Popen(
            [
                sys.executable,
                "-c",
                f"import time; time.sleep({max(1.0, sleep_s)}); open({marker!r}, 'w').close()",
            ]
        )
        try:
            child.wait(timeout=max(1.0, sleep_s))
        except subprocess.TimeoutExpired:  # pragma: no cover - the parent was killed first
            pass
        return 0

    # `--config auto` on a large tree is slow in reality; here it is slow on purpose.
    try:
        time.sleep(max(0.0, sleep_s))
    except KeyboardInterrupt:  # pragma: no cover - terminated instead
        pass
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
