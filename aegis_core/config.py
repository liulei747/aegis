"""Runtime settings. Everything is env-overridable (prefix ``AEGIS_``)."""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import BaseModel, Field, SecretStr
from pydantic_settings import BaseSettings, SettingsConfigDict


class BudgetConfig(BaseModel):
    """Hard caps for call-graph expansion and bundle size.

    Nothing is ever silently dropped: every cap that bites is recorded in the
    ``PruneDecision`` list of the bundle manifest.
    """

    # --- graph shape -------------------------------------------------
    max_depth: int = Field(2, ge=0, le=8, description="How many call-graph hops from the sink.")
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


class AIConfig(BaseModel):
    """The AI stage: one model call per analysis context, over an OpenAI-compatible endpoint.

    Off by default, and off is the honest default: it needs credentials and it spends money. When
    it is off the bundle is still produced and still says so -- the AI verdicts are an *addition*
    to the artifact, never a precondition for it.

    Credentials are named, not stored: `api_key_env` is the *name* of an environment variable.
    A key that reaches a config file, a manifest or a log line is a key that leaks.
    """

    enabled: bool = False
    #: Base URL without the path; `/chat/completions` is appended. Both the plain
    #: `https://api.openai.com/v1` shape and a bare host work, because the path is added once.
    base_url: str = ""
    api_key_env: str = "API_KEY"
    # Set only by the runtime configuration store. SecretStr masks accidental repr/JSON output.
    api_key: SecretStr | None = None
    model: str = ""
    timeout_s: float = Field(default=180.0, gt=0)
    #: Calls in flight at once. Defaults to 1 because that is the setting the measurements
    #: support: behind a gateway with a ~60s ceiling, six concurrent calls returned 3 usable
    #: answers and six sequential calls returned 6. Raising it is a deliberate choice to trade
    #: reliability for wall-clock, and a per-call failure is recorded either way.
    concurrency: int = Field(default=1, ge=1, le=16)
    temperature: float = Field(default=0.0, ge=0.0, le=2.0)
    #: Output-token ceiling sent as `max_tokens`. Zero means "let the provider decide".
    #:
    #: 16384, and the number comes from two measurements rather than from taste. First, on
    #: `upp-module-infra`, 87 of 151 retry turns were answers the output limit had cut in half -- the
    #: model had written a `final`, the strict parse threw it away, and the retry re-emitted it.
    #: Second, a *batched* judging run needs N times a single answer: in the quick run over the file
    #: subtree, the `batch(4)` runs came back at exactly 8192 output tokens (73-102 s each) and looped
    #: on truncation until the run errored -- four verdicts do not fit in 8192. Pair it with
    #: `HarnessConfig.claim_batch_size`: 8192 covers one claim, 16384 covers up to four.
    #: `max_tokens = 0` restores "let the provider decide" for a gateway that rejects the key.
    max_tokens: int = Field(default=16384, ge=0, le=200_000)
    #: Cap on contexts analysed in one run, so a 200-context bundle cannot quietly become 200
    #: paid calls. Whoever raises it is choosing to spend.
    max_contexts: int = Field(default=25, ge=1)


class DataflowConfig(BaseModel):
    """Joern-backed dataflow extraction. See ``docs/DATAFLOW_CONTRACT.md``.

    Why this exists rather than more graph walking: the caller/callee crawl in
    ``graph/builder.py`` freezes the direction a node was discovered with, so a method the
    sink's *caller* calls (the classic sanitizer) is never visited. It also leaves no trace,
    so the bundle looks complete while it is not. Joern answers the same question with a real
    inter-procedural flow and crosses file boundaries, which the caller/callee walk cannot.

    Off by default: it needs a running worker fleet (a 5.9 GB image and a JVM per worker) and
    this process talks to it over HTTP.
    """

    enabled: bool = False
    #: THERE IS NO `image` / `image_tag` HERE ANY MORE. They named the image a one-shot
    #: container was started from (`docker run ... joern --script`). That path is gone: the
    #: pipeline now talks HTTP to the worker fleet, so the image is chosen at *deploy* time
    #: (`services/dataflow/Dockerfile`, `AEGIS_JOERN_IMAGE` in compose) and this process never
    #: starts a container. Leaving the fields would have kept a knob that changes nothing --
    #: pydantic ignores unknown keywords silently, so a stale `image=` would not even error.
    #: `cache_dir` stays: it is read *inside* the worker, for the shared CPG cache and scratch.
    cache_dir: Path = Path("./var/dataflow")
    #: Per Joern invocation -- **the CPG build included**, which is the one that bites: measured
    #: 2341 Java files -> 418 s and a 15 MB graph, i.e. 70% of this default. A larger Java
    #: repository needs it raised *before* its first query. The worker turns the timeout into a
    #: named `JoernError` naming this knob, rather than letting it escape as a 500.
    timeout_s: int = Field(600, gt=0, description="Per Joern invocation (build or query).")
    source: str = Field(
        default="request.args.get",
        description="Start anchor: a call name (or dotted suffix) where untrusted input enters.",
    )
    #: THERE IS NO `sink` KNOB, deliberately. Naming the sink in configuration meant writing
    #: down the answer the analysis was supposed to find, and the finding already carries a
    #: far stronger constraint: the exact file and line where the rule fired. The worker
    #: derives the sink from that position (first non-operator call at or after it, inside the
    #: enclosing method) and reports what it chose, or reports that it could not -- but it is
    #: never told. See `docs/DATAFLOW_CONTRACT.md` §1.1.
    # --- worker (this process) ----------------------------------------
    #: Port the resident Joern server listens on, inside the worker container.
    worker_server_port: int = Field(default=8099, ge=1024, le=65535)
    #: How long to wait for the server's HTTP surface to answer. Measured ~9 s cold; the
    #: margin is for a loaded machine, and a failure here is a hard error, not a slow start.
    worker_start_timeout_s: float = Field(default=120.0, gt=0)
    #: Port the worker's own HTTP API listens on, inside the container.
    worker_http_port: int = Field(default=8105, ge=1024, le=65535)

    # --- worker: which CPG frontend builds the graph -------------------
    #: Frontend per source suffix. The worker picks by a **suffix census** of the workspace rather
    #: than being told, because a workspace reaches it as a path and its language is a fact about
    #: the tree.
    #:
    #: Getting this wrong is not a slow answer, it is a wrong one: a graph built by the wrong
    #: frontend is empty, every question comes back "the anchor matches no node", and before
    #: `dataflow_source_unmatched` existed that was reported as "the value cannot reach the sink".
    #: `.java` is listed because the image ships all fifteen frontends -- measured,
    #: `ls /opt/joern/joern-cli/frontends/` -- so the only thing that ever limited this to Python
    #: was the single hardcoded `cpg_bin`. Override with JSON:
    #: `AEGIS_DATAFLOW__CPG_FRONTENDS={".py":"pysrc2cpg",".java":"javasrc2cpg"}`. Drop a suffix to
    #: have the worker refuse that language **by name** instead of building the wrong graph.
    cpg_frontends: dict[str, str] = Field(
        default_factory=lambda: {".py": "pysrc2cpg", ".java": "javasrc2cpg"}
    )
    #: Where a frontend name resolves from, inside the worker container. This is the Joern image's
    #: own layout; a name is looked up as `<frontends_dir>/<name>/bin/<name>`.
    frontends_dir: Path = Path("/opt/joern/joern-cli/frontends")
    #: Extra argv per suffix, appended verbatim after the frontend's own argv. For Java this is the
    #: **type-information** classpath, and the flag is `--inference-jar-paths` (a comma-separated
    #: list of jar paths) -- **not** `--classpath`, which `javasrc2cpg` does not have. Verified
    #: against `javasrc2cpg --help` in the worker image.
    #:
    #: It is a **refinement, not a prerequisite.** Measured on a three-file Java fixture that
    #: references `HttpServletRequest` with no servlet jar available: the graph builds (rc=0) and a
    #: cross-file flow still comes out, because a call node is created from the source text whether
    #: or not its type resolves -- so the source anchor matches by name, not by type. What the jars
    #: add is better type inference (interface dispatch, overload resolution), which is accuracy
    #: rather than reachability.
    #:
    #: A list rather than a string because an argument containing a space must not be split.
    #:
    #: Example:
    #: `AEGIS_DATAFLOW__CPG_FRONTEND_ARGS={".java":["--inference-jar-paths","/deps/a.jar,/deps/b.jar"]}`.
    cpg_frontend_args: dict[str, list[str]] = Field(default_factory=dict)

    # --- fleet (caller side) ------------------------------------------
    #: How many workers the deployment runs. Affinity divides the project hash by this, so
    #: the number must match the number of containers actually started -- a mismatch sends
    #: projects to a worker that is not there.
    worker_count: int = Field(default=1, ge=1, le=32)
    #: URL of worker `{index}`. Compose service names make this a constant per deployment.
    worker_url_template: str = "http://dataflow-{index}:8105"
    #: The path the worker knows this workspace by, when it differs from the one this process
    #: uses. Compose mounts the project at `/workspace` in every service, so the two agree and
    #: this stays empty. A caller running *outside* compose (a host-side script, a test) reads
    #: files at its own path while the worker sees the mount, and sending the local path is a
    #: 404: "workspace not found" -- measured. Set this to the container-side path in that case;
    #: method bodies are still read from the local path, so both keep working.
    worker_workspace: str | None = None

    def worker_url(self, index: int) -> str:
        return self.worker_url_template.format(index=index)


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


class CORSConfig(BaseModel):
    """Which origins may call this API from a browser (``AEGIS_CORS__ALLOW_ORIGINS``).

    A constant ``["*"]`` until the console became its own service. A front-end deployed
    independently is not same-origin with the gateway, so the set of origins that may read
    responses is a deployment decision -- the cookie/credential rules and the hostnames differ
    per installation -- and hardcoding it in ``app/main.py`` made every deployment either
    over-open or unfixable without a code change. Unset keeps the previous behaviour.
    """

    allow_origins: list[str] = Field(default_factory=lambda: ["*"])


class ProjectsConfig(BaseModel):
    """Where projects come from, and the limits they are held to.

    Every limit here exists because the alternative is "clone whatever someone asks for into a
    volume until the disk is full". The caps are not about politeness: a repository or an
    archive is attacker-controlled input, and the only unbounded resource in this feature is
    disk.
    """

    #: The projects root. Writable by the gateway, read-only everywhere that analyses code, and
    #: mounted at the *same* absolute path in every service -- the dataflow worker addresses a
    #: project by its path, so a path that differed between services would route a project to a
    #: worker that cannot see it.
    root: Path = Path("/data/projects")
    #: Lets a deployment turn the feature off without removing the volume.
    enabled: bool = True
    #: Escape hatch for a self-hosted GitLab/Gitea on a private network. Off by default, because
    #: "the server can be told to fetch any URL" is otherwise a way to reach the metadata
    #: service and everything else the gateway can route to.
    allow_private_hosts: bool = False
    #: Cap on the sources on disk, checked after a clone and while unpacking an archive.
    max_bytes: int = Field(512 * 1024 * 1024, gt=0)
    #: Cap on the number of files. A directory with millions of tiny files defeats the byte cap
    #: and then defeats the scanner.
    max_files: int = Field(200_000, gt=0)
    #: `git clone` has no size limit of its own, so time is what bounds it.
    clone_timeout_s: float = Field(300.0, gt=0)
    git_bin: str = "git"


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
    ai_runtime_dir: Path | None = None
    max_file_bytes: int = 2_000_000

    # --- lsp ---------------------------------------------------------
    lsp_enabled: bool = True
    lsp_config_file: Path | None = None
    lsp_idle_shutdown_s: float = 300.0
    lsp_request_timeout_s: float = 20.0

    # --- dataflow (Joern) --------------------------------------------
    # Off by default: it needs the Joern image and a JVM, so a checkout without either must
    # keep working. When it is on, the call-graph slice comes from Joern's complete flow
    # (see docs/DATAFLOW_CONTRACT.md); when it is off, `CallGraphBuilder` walks the graph.
    dataflow: DataflowConfig = Field(default_factory=DataflowConfig)

    # --- AI stage ----------------------------------------------------
    # Off by default: it costs money and needs credentials. See `AIConfig`.
    ai: AIConfig = Field(default_factory=AIConfig)

    # --- budgets -----------------------------------------------------
    budget: BudgetConfig = Field(default_factory=BudgetConfig)

    # --- job queue (off when queue.redis_url is unset) ---------------
    queue: QueueConfig = Field(default_factory=QueueConfig)

    # --- cross-origin access -----------------------------------------
    cors: CORSConfig = Field(default_factory=CORSConfig)
    projects: ProjectsConfig = Field(default_factory=ProjectsConfig)

    def resolve(self) -> Settings:
        """Make relative paths absolute against CWD for predictable container behaviour."""
        self.workspace_root = self.workspace_root.expanduser().resolve()
        self.output_dir = self.output_dir.expanduser().resolve()
        self.work_dir = self.work_dir.expanduser().resolve()
        if self.ai_runtime_dir is not None:
            self.ai_runtime_dir = self.ai_runtime_dir.expanduser().resolve()
        if self.lsp_config_file is not None:
            self.lsp_config_file = self.lsp_config_file.expanduser().resolve()
        self.dataflow.cache_dir = self.dataflow.cache_dir.expanduser().resolve()
        return self


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings().resolve()
