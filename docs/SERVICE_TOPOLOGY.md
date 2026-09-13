# Service topology

## Why this exists

The first version put four different responsibilities in one process. They have
different resource shapes, failure modes and scaling needs, and sharing an image
made ordinary work painful:

| responsibility | resource shape | failure mode | scaling need |
| --- | --- | --- | --- |
| **scan** — run opengrep / semgrep | CPU-bound child process, minutes, ~2 MB of SARIF | engine crash, bad rule config | one worker per concurrent scan |
| **extract** — LSP servers, call graph, assembly | memory-bound (a language server per language), seconds to minutes | LSP crash or hang, budget exhaustion | one worker per concurrent bundle |
| **api** — orchestrate, store, serve queries | almost stateless, milliseconds | — | N replicas behind a load balancer |
| **web** — the review console | static files | — | CDN |

Measured symptom of the old layout: editing one line of front-end HTML forced a
2 GB image rebuild that re-ran `pip install semgrep` (≈4 minutes). Layer reordering
fixed the *cost* of that, but not the *reason* it was necessary.

## Target topology

```
                       ┌──────────────────────┐
   browser ───────────►│  aegis-gateway       │  127.0.0.1:8100 (published)
                       │  orchestration       │  owns no scanner, no LSP
                       │  + query views       │
                       └───┬──────────────┬───┘
                  internal │              │ internal
              ┌────────────▼───┐   ┌──────▼────────────┐
              │  aegis-scan    │   │  aegis-extract    │  both reachable only on
              │  opengrep      │   │  LSP + graph +    │  the compose network
              │  → Finding[]   │   │  assemble→bundle  │  (expose, not ports)
              └───────┬────────┘   └──────┬────────────┘
                      │                   │
                      └────────┬──────────┘
                               ▼
                  ┌────────────────────────┐
                  │  shared volumes        │
                  │  /workspace  /data/…   │  (paths must match across services)
                  └────────────────────────┘
                      ▲                         ▲
   aegis-scan / ──────┘                         └────── aegis-dataflow-0 / -1
   aegis-extract                                        (one Joern server each,
                                                         resident CPG per project,
                                                         same /workspace mount)
                      ▲                         ▲
   aegis-scan / ──────┘                         └────── aegis-dataflow-0 / -1
   aegis-extract                                        (one Joern server each,
                                                         resident CPG per project,
                                                         same /workspace mount)

   browser ───────────►  aegis-frontend  127.0.0.1:8102 (published, static only)
                              │
                              └── cross-origin HTTP ──► gateway :8100
                                  (the address comes from /config.js, written at start-up
                                   from AEGIS_API_BASE; this image proxies nothing)
```

### Job flow

```
POST /v1/scans                       → api enqueues a scan job        → 202 {job_id}
GET  /v1/jobs/{job_id}               → status, progress, result ref

POST /v1/bundles                     → api enqueues:
                                        1. scan job (unless a SARIF is supplied)
                                        2. extract job, depends_on the scan job
                                     → 202 {job_id}
GET  /v1/jobs/{job_id}               → succeeded + {bundle_id}
GET  /v1/bundles/{id}/…              → the read-only views (unchanged contract)
```

Each worker claims a job, reports `running` with a progress note, and stores its
result. The API never does heavy work; the workers never talk to a browser.

## Ports and naming

Two rules, both about reducing what is exposed and making names say what a service does.

**Only user-facing services publish a port.** Compose puts every service on one
network and they resolve each other by service name (`http://scan:8101`), so
service-to-service calls need nothing published. `ports:` publishes to the host,
which on a laptop means the LAN:

| service | published | why |
| --- | --- | --- |
| `scan` | no (`expose: 8101`) | an endpoint that reads a mounted repository and runs a parser over it |
| `extract` | no (`expose: 8103`) | the same, plus it starts language-server processes |
| `dataflow-N` | no (`expose: 8105`) | a Joern server that reads the mounted repository and runs a taint query; the fleet is `dataflow-0`, `dataflow-1` (see `docs/DATAFLOW_CONTRACT.md` §8) |
| `redis` | no (`expose: 6379`) | job state; the queue is not a public API |
| `worker` | no (no HTTP surface at all) | its liveness is "Redis is reachable and my loop turns over" |
| `gateway` | yes, `127.0.0.1:8100` | the browser talks to it |
| `web` | yes, `127.0.0.1:8102` | the browser loads it |

The dataflow fleet is the one place where a service is **replicated by hand** rather than
scaled: affinity divides the project hash by `AEGIS_DATAFLOW__WORKER_COUNT`, so the number of
containers, their indices and the configured count have to agree. `tests/test_compose_policy.py`
asserts that they do, along with every worker mounting the same `/workspace` — a wrong affinity
guess must be slower, never a 404.

Bound explicitly to `127.0.0.1` rather than `0.0.0.0` for the same reason: a
development stack should not be reachable from the coffee-shop network.

To poke a worker while debugging, go through the network instead of publishing:

```bash
docker compose exec extract python -c \
  "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8103/health').read())"
```

**The gateway is called `gateway`, not `api`.** With five services, "api" stopped
identifying anything: every service has an HTTP API. `gateway` says what it is —
the single entry point that orchestrates and serves queries, while the workers do
the heavy lifting and are unreachable from outside.

## Shared contracts

Every service needs the same vocabulary (`Finding`, `MethodSymbol`, `CallEdge`,
`PruneDecision`, `ScanRecord`, `AnalysisBundleManifest`). Duplicating them would
guarantee drift, so they live in one package that services import and version:

```
aegis_contracts/         # data shapes only — no I/O, no FastAPI, no logic
  __init__.py
  domain.py              # moved from app/schemas/domain.py
  budget.py              # moved from app/core/config.py::BudgetConfig
```

Rule: **`aegis_contracts` must not import anything from a service.** It is the
bottom of the dependency graph. `tests/test_contracts.py` enforces that, because
the moment it grows a dependency the whole point is lost.

Transport is JSON over HTTP. The manifest is already a serializable contract, so
a service boundary costs one serialize/deserialize, not a new model.

## Layout

```
aegis_contracts/          shared shapes + derived views (imported by every service)
  domain.py               Finding / MethodSymbol / CallEdge / manifest / budget shapes
  views.py                pure "manifest -> funnel/timeline/provenance/diff" functions
aegis_core/               settings, logging, text + path helpers, workspace resolution
app/                      the gateway shell only: api/ schemas/ main.py cli.py
services/
  extraction/             LSP + call graph + assembly; reads SARIF, writes bundles
  scan/                   wraps opengrep/semgrep; SARIF in, Finding[] out
  queue/                  job records, Redis Streams, worker, reaper (shared by gateway
                          and worker — a capability package, not a deployed service)
  web/                    the console (own image: nginx + static assets)
infra/
  docker-compose.dev.yml  api + workers, in-process queue
  docker-compose.yml      api + n-workers + redis
```

## Migration plan (incremental, each step green)

| # | move | why this order | status |
| --- | --- | --- | --- |
| 1 | `aegis_contracts` + `aegis_core` | everything depends on them; do it while there is one consumer | **done** |
| 2 | split `_collect_findings` into "read SARIF" vs "run the scanner" | removes the only hard coupling, and extraction keeps working | **done** (`sarif_path` given -> `parse_sarif`; otherwise `run_scan_anywhere`) |
| 3 | `services/extraction` (moved `graph/ lsp/ parsers/ assembler/ pipeline/`) | biggest chunk, no behaviour change | **done** |
| 4 | `services/scan` (moved `scanner/`) | now trivially separable | **done** |
| 5 | `services/api` (the gateway; the job layer is `services/queue/`) | the gateway becomes thin | **next** |
| 6 | `frontend/` (the console) | front-end changes stop touching a Python image, and a static client stops needing the gateway's origin | **done** (React + TS, own image, `127.0.0.1:8102`, API base injected at run time) |
| 7 | queue: in-process → redis | keeps dev simple while making prod correct | **done** (`docs/QUEUE_PLAN.md`) |

Steps 1–2 are pure moves; 3–6 keep every existing test passing by pointing the
tests at the new module paths; 7 is the only step that adds infrastructure.

### Step 3, as executed — and the cycle it removed

The move was mechanical (the capability subpackages only ever imported their siblings
plus the shared packages), but it was worth more than tidiness: before it, `app` and
`services` imported each other. `app -> services` was six calls into the scan/extraction
clients; `services -> app` was `routes.py` reaching for `app.pipeline.assemble` **and**
for `app.api.deps::probe_lsp` / `resolve_workspace`.

Two things had to move for the reverse edges to reach zero:

* `probe_lsp` now lives in `services/extraction/lsp/probe.py` — it spawns language
  servers, so it belongs to the capability that owns them;
* `resolve_workspace`'s *policy* sank to `aegis_core/workspace.py`. Each service
  translates `WorkspaceNotFound` into its own protocol error (the gateway into a 400),
  which is the part that genuinely differs and therefore could not be shared.

`tests/test_contracts.py` asserts `services -> app` is exactly zero edges, and pins the
known `aegis_contracts -> aegis_core` exception to exactly one import.

### A known exception, recorded rather than hidden

`aegis_contracts/domain.py` imports `estimate_tokens` from `aegis_core.utils`. So the
line below — "contracts must not import anything from a service" — holds, but the
stronger claim that contracts sit at the very bottom of the graph does not: they sit on
`aegis_core`. That is a wording problem, not a layering disaster (the helper is pure),
and both fixes (duplicating the helper, or inverting the dependency) are separate
decisions. It is pinned by a test so a second such edge cannot appear unnoticed.

### Step 1, as executed

```
aegis_contracts/domain.py     <- app/schemas/domain.py      (289 lines, no I/O)
aegis_core/utils.py           <- app/core/utils.py
aegis_core/logging.py         <- app/core/logging.py
aegis_core/config.py          <- app/core/config.py
```

* imports rewritten in 38 files; `tests/test_contracts.py` now enforces that a
  shared package can never import `app`, `services`, or one another, and that the
  contracts carry no I/O framework.
* the review console was **removed from the API** (`app/api/static/` is gone,
  `GET /` is 404) and its service later built under `frontend/` — first as
  `services/web` (nginx proxying `/v1`), then rebuilt as an independently
  deployable client that proxies nothing and is told the API's address at run
  time. See `docs/HANDOVER.md` §11.3. Its early tests were deleted rather than
  adapted, because the page was being rebuilt in that service;
  `tests/test_observability.py` keeps the API side honest by asserting the API is
  headless while still publishing every view the console consumes.
* `docker/Dockerfile` copies all three packages as sources and the build asserts
  they import, so a missing package fails the build instead of the runtime.
* verified in the container: `aegis_contracts`, `aegis_core`, `app` all import,
  a real scan + pyright run produces 4 methods with no degradation.

Still to do for step 1: nothing. `app/core/` and `app/schemas/domain.py` are gone.


## Costs of doing this (so nobody is surprised)

* **More moving parts.** Five services means five health checks, five logs, a queue and a
  broker to operate, and network failure modes that did not exist in-process.
* **No more in-process shortcuts.** `PipelineRequest(sarif_path=…)` looked like one
  call; it becomes a job that can fail between stages.
* **Version skew becomes possible.** A worker on an old image can emit a manifest
  the gateway cannot validate. `schema_version` exists for exactly this and must be
  checked at the boundary.
* **Debugging spans processes.** A failing bundle is now traced across at least the
  gateway and one worker, so `run_id` has to travel in headers and logs.

Two costs are specific to the queue and were accepted with open eyes:

* **A job can be `running` with nobody working on it** if every worker is dead at once; the
  state moves when one comes back (the startup reconcile), not before. This is the design's
  one silent window, and the reaper's heartbeat check is what keeps it from being worse --
  the alternative failure, declaring a *live* slow job dead, is the one that invents results.
* **Cancelling a *remote* scan stops the wait, not the work.** The worker answers immediately,
  but the scanner in the `scan` container runs to completion because its handle lives there.
  Cancelling an extraction is not affected: the worker runs extraction in-process, which is
  precisely why it does.

These are accepted deliberately: the alternative is a service that cannot be
scaled, restarted or released independently.

## What does *not* change

The bundle contract. `manifest.json`, the derived views, the block layout and the
finding/method/edge shapes stay byte-compatible, because they are what the
observability work already validated. Splitting services must be invisible to a
consumer of a bundle.
