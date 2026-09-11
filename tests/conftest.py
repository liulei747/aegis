from __future__ import annotations

import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from aegis_core.config import BudgetConfig, QueueConfig, Settings  # noqa: E402
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


# --- job queue ---------------------------------------------------------
#
# fakeredis rather than a hand-written double: the behaviour under test *is* Redis
# semantics (Streams consumer groups, XAUTOCLAIM, and the Lua compare-and-swap), so a
# fake of our own would only assert that we agree with ourselves.


@pytest.fixture()
def fake_redis():
    import fakeredis

    client = fakeredis.FakeStrictRedis()
    yield client
    client.flushall()


@pytest.fixture()
def queue_settings() -> QueueConfig:
    """Small, fast intervals: the tests should not wait 30 s for a reaper tick."""
    return QueueConfig(
        redis_url="redis://localhost:6379/0",
        visibility_timeout_s=60,
        heartbeat_interval_s=5,
        reaper_interval_s=5,
        block_ms=200,
        stream_maxlen=1000,
        job_ttl_s=600,
    )


@pytest.fixture()
def job_store(fake_redis, queue_settings):
    from services.queue.jobs import JobStore

    return JobStore(fake_redis, queue_settings)


@pytest.fixture()
def job_stream(fake_redis, queue_settings):
    from services.queue.streams import JobStream

    stream = JobStream(fake_redis, queue_settings)
    stream.ensure_group()
    return stream
