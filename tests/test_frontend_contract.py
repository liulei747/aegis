"""The Python suite runs the front-end's own tests, so one command covers the repository.

The front-end's checks live in `frontend/test/*.test.ts` (they need Node), and the repository has
one documented way to verify itself: `python -m pytest -q`. Leaving the front-end out of it would
mean the suite could be green while the console called an endpoint that no longer exists -- which
is the failure the front-end's contract test is written to catch.

What is deliberately *not* here: any check that reads front-end source and compares it against
backend source. The front-end shares nothing with the backend, so its contract is checked over
HTTP against the gateway's published `/openapi.json` (see `frontend/test/contract.test.ts`).
This file only forwards, and checks the one property a build can violate on its own -- that no
API origin is baked into the assets.

Skipped when Node is unavailable, so a Python-only checkout still runs everything else.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
FRONTEND = ROOT / "frontend"

pytestmark = pytest.mark.skipif(
    shutil.which("npm") is None or not (FRONTEND / "node_modules").is_dir(),
    reason="the front-end needs `npm install` in frontend/ first",
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
        cwd=FRONTEND,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        check=False,
    )


def test_the_frontend_tests_pass() -> None:
    """The HTTP contract test and the arithmetic checks.

    The contract test compares the paths `src/api/client.ts` calls against the gateway's
    published OpenAPI document. It reads a stored snapshot so it runs with no backend; when
    `AEGIS_API_BASE` or `API_URL` is set it also compares that snapshot against the live
    gateway, which is what stops the stored copy going stale.
    """
    result = _run("test")
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_frontend_typechecks_and_builds() -> None:
    """`tsc --noEmit` plus a real Vite build, which is what the nginx image serves.

    Both matter and neither is redundant: typechecking alone would not catch a build-time
    resolution problem, and building alone (`vite build`) skips type errors, because Vite
    strips types without checking them.
    """
    result = _run("run", "build")
    assert result.returncode == 0, result.stdout + result.stderr

    dist = FRONTEND / "dist"
    assert (dist / "index.html").is_file(), "the build produced no index.html"
    assert list((dist / "assets").glob("*.js")), "the build produced no JavaScript bundle"

    html = (dist / "index.html").read_text(encoding="utf-8")
    # `src="/assets/..."` is what Vite emits: a root-relative script tag, not an API origin.
    # The only script tag that carries configuration is `/config.js`, which the container
    # rewrites at start-up.
    assert "http://" not in html and "https://" not in html, (
        f"an absolute origin is baked into the page:\n{html}"
    )


def test_the_frontend_does_not_bake_in_an_api_origin() -> None:
    """The gateway's address is configuration, not a build artefact.

    A hard-coded origin in the built assets would mean one image per deployment, which is
    precisely what the runtime `/config.js` exists to avoid. `VITE_API_BASE` is set in
    `.env.development` for `npm run dev` and is deliberately absent from a production build.
    """
    dist = FRONTEND / "dist"
    if not dist.is_dir():  # pragma: no cover - the build test above creates it
        pytest.skip("run the build first")

    offenders: list[str] = []
    for asset in (dist / "assets").glob("*.js"):
        text = asset.read_text(encoding="utf-8", errors="replace")
        for needle in ("127.0.0.1:8100", "localhost:8100", "127.0.0.1:8102"):
            if needle in text:
                offenders.append(f"{asset.name}: {needle}")

    assert offenders == [], (
        "an API origin is baked into the bundle; it must come from /config.js or "
        f"VITE_API_BASE at runtime: {offenders}"
    )
