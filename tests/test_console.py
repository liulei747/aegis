"""Extract and syntax-check the review console's inline script.

The console is a single static page with no build step, so a typo would only show
up at runtime in a browser. This parses it with node so CI catches it instead.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

PAGE = Path(__file__).resolve().parents[1] / "app" / "api" / "static" / "index.html"


def _inline_script() -> str:
    html = PAGE.read_text(encoding="utf-8")
    blocks = re.findall(r"<script>(.*?)</script>", html, flags=re.DOTALL)
    assert blocks, "index.html has no inline script"
    return "\n".join(blocks)


@pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed")
def test_inline_script_parses(tmp_path: Path) -> None:
    script = _inline_script()
    target = tmp_path / "console.mjs"
    target.write_text(script, encoding="utf-8")

    proc = subprocess.run(
        ["node", "--check", str(target)],
        capture_output=True,
        text=True,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr


def test_page_only_consumes_derived_endpoints() -> None:
    script = _inline_script()
    # every fetch target must be a view endpoint, never a raw artifact file
    for path in re.findall(r"api\(`([^`]+)`\)", script) + re.findall(r'api\("([^"]+)"\)', script):
        assert path.startswith("/v1/") or path == "/health", path
    assert "/manifest" not in script
    assert "blocks.jsonl" not in script


def test_page_has_no_dangling_element_ids() -> None:
    """Every $("id") lookup must exist in the markup, or the page silently no-ops."""
    html = PAGE.read_text(encoding="utf-8")
    script = _inline_script()
    ids = set(re.findall(r'id="([^"]+)"', html))
    looked_up = set(re.findall(r'\$\("([^"]+)"\)', script))
    created_dynamically = {"diffbox"}  # injected with the bundle detail
    missing = looked_up - ids - created_dynamically
    assert not missing, f"script looks up ids that the page never defines: {sorted(missing)}"
