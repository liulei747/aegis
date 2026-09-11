from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis_core.config import BudgetConfig, Settings  # noqa: E402
from aegis_core.logging import setup_logging  # noqa: E402
from tests.fixtures import write_fixture  # noqa: E402

setup_logging("WARNING")


@pytest.fixture()
def workspace(tmp_path: Path) -> Path:
    return write_fixture(tmp_path / "repo")


@pytest.fixture()
def budget() -> BudgetConfig:
    return BudgetConfig(max_depth=2, max_nodes=30, max_contexts=10)


@pytest.fixture()
def settings(tmp_path: Path, workspace: Path, budget: BudgetConfig) -> Settings:
    return Settings(
        workspace_root=workspace,
        output_dir=tmp_path / "packages",
        work_dir=tmp_path / "work",
        budget=budget,
        lsp_enabled=False,
    ).resolve()


@pytest.fixture()
def fake_lsp_config(tmp_path: Path) -> Path:
    """An LSP catalog whose only server is the in-repo fake, for .py files."""
    server = ROOT / "tests" / "fake_lsp_server.py"
    config = tmp_path / "lsp.yaml"
    config.write_text(
        "servers:\n"
        "  - language: python\n"
        f"    command: ['{sys.executable}', '{server.as_posix()}', '--root', '{{root}}']\n"
        "    extensions: ['.py']\n",
        encoding="utf-8",
    )
    return config
