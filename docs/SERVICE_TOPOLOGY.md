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

   browser ───────────►  aegis-web  127.0.0.1:8102 (published, static only)
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
| `gateway` | yes, `127.0.0.1:8100` | the browser talks to it |
| `web` | yes, `127.0.0.1:8102` | the browser loads it |

Bound explicitly to `127.0.0.1` rather than `0.0.0.0` for the same reason: a
development stack should not be reachable from the coffee-shop network.

To poke a worker while debugging, go through the network instead of publishing:

```bash
docker compose exec extract python -c \
  "import urllib.request;print(urllib.request.urlopen('http://127.0.0.1:8103/health').read())"
```

**The gateway is called `gateway`, not `api`.** With four services, "api" stopped
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
aegis_contracts/          shared shapes (imported by every service)
app/                      → becomes services/extraction/
services/
  extraction/             LSP + call graph + assembly; reads SARIF, writes bundles
  scan/                   wraps opengrep/semgrep; SARIF in, Finding[] out
  api/                    gateway: jobs, queue, queries, no heavy lifting
  web/                    the console (own image: nginx + static assets)
infra/
  docker-compose.dev.yml  api + workers, in-process queue
  docker-compose.yml      api + n-workers + redis
```

## Migration plan (incremental, each step green)

| # | move | why this order | status |
| --- | --- | --- | --- |
| 1 | `aegis_contracts` + `aegis_core` | everything depends on them; do it while there is one consumer | **done** |
| 2 | split `_collect_findings` into "read SARIF" vs "run the scanner" | removes the only hard coupling, and extraction keeps working | next |
| 3 | `services/extraction` (moves `graph/ lsp/ parsers/ assembler/ observability/ pipeline/`) | biggest chunk, no behaviour change | |
| 4 | `services/scan` (moves `scanner/`) | now trivially separable | |
| 5 | `services/api` (moves `api/`, adds the job layer) | the gateway becomes thin | |
| 6 | `services/web` (moves the console out of `app/api/static`) | front-end changes stop touching a Python image | scaffolded |
| 7 | queue: in-process → redis | keeps dev simple while making prod correct | |

Steps 1–2 are pure moves; 3–6 keep every existing test passing by pointing the
tests at the new module paths; 7 is the only step that adds infrastructure.

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
  `GET /` is 404) and its service scaffolded under `services/web/`. Its tests were
  deleted rather than adapted, because the page is being rebuilt in that service;
  `tests/test_observability.py` keeps the API side honest by asserting the API is
  headless while still publishing every view the console consumes.
* `docker/Dockerfile` copies all three packages as sources and the build asserts
  they import, so a missing package fails the build instead of the runtime.
* verified in the container: `aegis_contracts`, `aegis_core`, `app` all import,
  a real scan + pyright run produces 4 methods with no degradation.

Still to do for step 1: nothing. `app/core/` and `app/schemas/domain.py` are gone.


## Costs of doing this (so nobody is surprised)

* **More moving parts.** Four services means four health checks, four logs, a
  queue to operate, and network failure modes that did not exist in-process.
* **No more in-process shortcuts.** `PipelineRequest(sarif_path=…)` looked like one
  call; it becomes a job that can fail between stages.
* **Version skew becomes possible.** A worker on an old image can emit a manifest
  the gateway cannot validate. `schema_version` exists for exactly this and must be
  checked at the boundary.
* **Debugging spans processes.** A failing bundle is now traced across at least the
  gateway and one worker, so `run_id` has to travel in headers and logs.

These are accepted deliberately: the alternative is a service that cannot be
scaled, restarted or released independently.

## What does *not* change

The bundle contract. `manifest.json`, the derived views, the block layout and the
finding/method/edge shapes stay byte-compatible, because they are what the
observability work already validated. Splitting services must be invisible to a
consumer of a bundle.
