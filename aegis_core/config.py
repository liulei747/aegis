"""Runtime settings. Everything is env-overridable (prefix ``AEGIS_``)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class BudgetConfig(BaseModel):
    """Hard caps for call-graph expansion and bundle size.

    Nothing is ever silently dropped: every cap that bites is recorded in the
    ``PruneDecision`` list of the bundle manifest.
    """

    # --- graph shape -------------------------------------------------
    max_depth: int = Field(2, ge=0, le=6, description="How many call-graph hops from the sink.")
    max_nodes: int = Field(60, ge=1, description="Max distinct methods in one bundle.")
    max_callers_per_node: int = Field(8, ge=0)
    max_callees_per_node: int = Field(12, ge=0)
    max_implementations: int = Field(5, ge=0)

    # --- per-method size --------------------------------------------
    max_lines_per_method: int = Field(400, ge=10)
    max_chars_per_method: int = Field(24_000, ge=500)

    # --- package size ------------------------------------------------
    max_total_chars: int = Field(600_000, ge=1_000)
    max_contexts: int = Field(20, ge=1, description="Sinks per bundle (findings expanded).")

    # --- performance -------------------------------------------------
    expand_concurrency: int = Field(6, ge=1, le=64)
    lsp_timeout_s: float = Field(20.0, gt=0)
    read_timeout_s: float = Field(5.0, gt=0)


class QueueConfig(BaseModel):
    """Job queue settings. An absent ``redis_url`` means the queue is off.

    Same convention as ``AEGIS_SCAN_SERVICE_URL`` / ``AEGIS_EXTRACTION_SERVICE_URL``: the
    presence of a URL is what switches behaviour. With no Redis configured every route
    stays synchronous and the whole test-suite runs with no broker at all.

    The two grace windows are separate on purpose (see ``docs/QUEUE_PLAN.md`` §6.5):
    ``cancel_terminate_grace_s`` is how long a cooperative terminate gets before a hard
    kill, and ``cancel_kill_grace_s`` is how long after that we wait for the process to
    actually die before moving on and letting the reaper reconcile.
    """

    redis_url: str | None = Field(
        default=None,
        description="e.g. redis://redis:6379/0. Unset -> no queue, routes stay synchronous.",
    )
    stream: str = "aegis:q:jobs"
    group: str = "aegis-workers"
    block_ms: int = Field(1000, ge=100, le=5000, description="XREADGROUP block window.")
    max_attempts: int = Field(3, ge=1, le=10)
    heartbeat_interval_s: int = Field(15, ge=5, description="How often a worker refreshes its claim.")
    reaper_interval_s: int = Field(30, ge=5)
    #: How long a claim may go un-heartbeated before it is treated as abandoned. Must be
    #: comfortably larger than ``heartbeat_interval_s`` or a slow job is stolen mid-run.
    visibility_timeout_s: int = Field(1800, ge=60)
    reap_batch: int = Field(32, ge=1, le=256)
    job_ttl_s: int = Field(604_800, ge=300, description="7 days, applied only in a terminal state.")
    list_limit: int = Field(100, ge=1, le=500)
    #: Approximate cap on the stream. If this ever trims an un-ACKed entry, the job record
    #: still exists and the startup reconcile re-enqueues it -- but check the warning log.
    stream_maxlen: int = Field(10_000, ge=100)
    cancel_terminate_grace_s: float = Field(3.0, gt=0)
    cancel_kill_grace_s: float = Field(2.0, gt=0)
    cancel_poll_s: float = Field(0.05, gt=0, le=1.0, description="Abort-poll interval while waiting.")


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="AEGIS_",
        env_nested_delimiter="__",
        env_file=".env",
        extra="ignore",
    )

    app_name: str = "aegis"
    debug: bool = False
    log_level: str = "INFO"

    # --- scanning ----------------------------------------------------
    opengrep_bin: str = "opengrep"
    opengrep_fallback_bin: str | None = "semgrep"
    scan_timeout_s: int = 900

    # --- workspace ---------------------------------------------------
    workspace_root: Path = Path("./workspace")
    output_dir: Path = Path("./var/packages")
    work_dir: Path = Path("./var/work")
    max_file_bytes: int = 2_000_000

    # --- lsp ---------------------------------------------------------
    lsp_enabled: bool = True
    lsp_config_file: Path | None = None
    lsp_idle_shutdown_s: float = 300.0
    lsp_request_timeout_s: float = 20.0

    # --- budgets -----------------------------------------------------
    budget: BudgetConfig = Field(default_factory=BudgetConfig)

    # --- job queue (off when queue.redis_url is unset) ---------------
    queue: QueueConfig = Field(default_factory=QueueConfig)

    def resolve(self) -> Settings:
        """Make relative paths absolute against CWD for predictable container behaviour."""
        self.workspace_root = self.workspace_root.expanduser().resolve()
        self.output_dir = self.output_dir.expanduser().resolve()
        self.work_dir = self.work_dir.expanduser().resolve()
        if self.lsp_config_file is not None:
            self.lsp_config_file = self.lsp_config_file.expanduser().resolve()
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings().resolve()
