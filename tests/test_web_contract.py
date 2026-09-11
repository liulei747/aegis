"""The Python suite runs the console's own tests, so one command covers the repository.

The console's checks live in `services/web/test/*.test.ts` (they need Node and the real Vite
build), and the repository has one documented way to verify itself: `python -m pytest -q`.
Leaving the front-end out of it would mean the suite could be green while the console called
an endpoint that no longer exists -- which is exactly the failure the console's contract test
is written to catch.

Skipped when Node is unavailable, so a Python-only checkout still runs everything else.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
WEB = ROOT / "services" / "web"

pytestmark = pytest.mark.skipif(
    shutil.which("npm") is None or not (WEB / "node_modules").is_dir(),
    reason="the console needs `npm ci` in services/web first",
)


def _npm() -> str:
    """`npm` is a shell script on POSIX and `npm.cmd` on Windows.

    `shutil.which("npm")` finds the right one on each platform, so asking it is more portable
    than naming the extension here -- and on Windows a bare "npm" raises FileNotFoundError.
    """
    found = shutil.which("npm.cmd") or shutil.which("npm")
    assert found, "npm is not on PATH"
    return found


def _run(*args: str, timeout: int = 900) -> subprocess.CompletedProcess:
    """Run an npm script and capture its output.

    `encoding="utf-8"` with `errors="replace"` is not optional on Windows: npm and Vite emit
    UTF-8 (box-drawing characters, mostly), and the platform default code page cannot decode
    it, which kills the reader thread and turns a passing build into a confusing failure.
    """
    return subprocess.run(
        [_npm(), *args],
        cwd=WEB,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def test_the_console_contract_tests_pass() -> None:
    """Endpoint existence, the no-computation rule, and the formatter checks."""
    result = _run("test")
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_console_typechecks_and_builds() -> None:
    """`tsc --noEmit` plus a real Vite build, which is what the nginx image serves.

    Both matter and neither is redundant: typechecking alone would not catch a build-time
    resolution problem, and building alone (`vite build`) skips type errors, because Vite
    strips types without checking them.
    """
    result = _run("run", "build")
    assert result.returncode == 0, result.stdout + result.stderr

    dist = WEB / "dist"
    assert (dist / "index.html").is_file(), "the build produced no index.html"
    assets = list((dist / "assets").glob("*.js"))
    assert assets, "the build produced no JavaScript bundle"
    html = (dist / "index.html").read_text(encoding="utf-8")
    # `src="/assets/..."` is what Vite emits: a root-relative script tag, not an API origin.
    # What must not appear is an absolute URL, because that would need a rebuild per
    # deployment and would put the gateway's host and port into front-end code.
    assert "http://" not in html and "https://" not in html, (
        f"an absolute origin is baked into the page:\n{html}"
    )


def test_the_console_does_not_bake_in_an_api_origin() -> None:
    """The gateway's address is nginx's business, not the bundle's.

    A hard-coded origin in the built assets would mean one image per deployment and would put
    a port number in front-end code. The dev server proxies and nginx proxies; the source only
    ever mentions relative paths.
    """
    dist = WEB / "dist"
    if not dist.is_dir():  # pragma: no cover - the build test above creates it
        pytest.skip("run the build first")
    for asset in (dist / "assets").glob("*.js"):
        text = asset.read_text(encoding="utf-8", errors="replace")
        assert "127.0.0.1:8100" not in text
        assert "localhost:8100" not in text
