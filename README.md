# Aegis

Static-scan hits plus an LSP-resolved call graph, assembled into **analysis
packages** that an AI can reason over — one package per sink, with the full
source of every method on the call chain and the provenance of every edge.

This repository implements the **first deliverable only**: the assembly stage.

```
opengrep hit
    -> LSP locates the enclosing method + its exact range
    -> LSP walks callers, callees and implementations
    -> read every method in full (by byte range)
    -> dedupe, bound, keep provenance
    -> assemble analysis packages for the AI
```

Threat modelling, sub-agent fan-out and provider-side prompt caching are
deliberately **out of scope here** — but the bundle layout is designed so they
drop in without touching this stage (see [Design decisions](#design-decisions)).

---

## 1. Why the LSP is the seam

A static scanner tells you *where a pattern matched*. It cannot tell you which
method that line belongs to, who calls that method, or what it calls — and those
are exactly the facts an analyst needs.

The trick that makes this work without an index, a build system, or a per-language
parser: **a language server's `documentSymbol` range is the callable's full
extent.** So "which method contains this hit" is pure range containment, and
`selectionRange` gives the identifier needed for call-hierarchy queries.

That means one implementation works for Python, TypeScript, Go, C/C++, Rust,
Java… for as long as a language server exists for the language.

## 2. Pipeline

| stage | module | what it does |
| --- | --- | --- |
| scan | `app/scanner/opengrep.py`, `app/scanner/sarif.py` | runs opengrep (falls back to semgrep), parses SARIF into `Finding` |
| locate | `app/graph/providers.py::locate_method` | innermost enclosing callable via `documentSymbol`, else syntax heuristic |
| expand | `app/graph/providers.py`, `app/graph/builder.py` | BFS both directions (callers ^ / callees v), capability-gated, budgeted |
| read | `app/assembler/reader.py` | slices full method bodies from file bytes by LSP offsets, concurrently |
| assemble | `app/assembler/contexts.py` | dedupes, groups by focus, builds one self-contained context per sink |
| render | `app/assembler/render.py` | prompt blocks in cache-friendly order, with a provider legend |
| package | `app/assembler/package.py` | writes a reviewable directory tree + zip |

### Provider ladder (never lose the provenance)

| provider | confidence | meaning |
| --- | --- | --- |
| `lsp_call_hierarchy` | 1.00 | server-resolved caller/callee |
| `lsp_definition` | 0.90 | callee resolved from a lexical call site |
| `lsp_implementation` | 0.80 | abstract → concrete dispatch target |
| `lsp_references` | 0.60 | a reference, call-ness unproven |
| `syntax_regex` | 0.40 | no language server: lexical approximation |
| `file_range` | 0.20 | last resort |

Call hierarchy is optional in LSP and several servers never implement it. When
it is missing, callees are recovered from lexical call sites resolved through
`textDocument/definition` — which nearly every server does support.

## 3. The output is the contract

One directory per run (`var/packages/<bundle_id>/`), plus a `.zip`:

```
manifest.json          the machine-readable contract (this is the API)
bundle.json            findings + methods + edges + contexts (no bodies)
methods/<id>.txt       one full method body per file
contexts/<id>.md       one rendered analysis package per sink
ai/prompt.md           ordered prompt blocks
ai/blocks.jsonl        one block per line (streaming / caching)
ai/blocks_meta.json    block order + which blocks are cacheable
graph/callgraph.dot    the slice as a graph (edge colour = provider)
summary.md             human review entry point
scan/original.sarif    raw scanner output, for audit
```

A context looks like this (trimmed):

```markdown
## Analysis context C-7c970898538a
- focus: `M-568641cc8bfb` query_user (repo.py:4-11)
- focus located by: `lsp_document_symbol`

### Static-scan findings
- `F-8385d9903e16` rule=`python.lang.security.sql-injection` severity=error at repo.py:5

### Call chain slice
- d0 == `M-568641cc8bfb` query_user (repo.py:4-11) [lsp_document_symbol] **FOCUS**
- d1 v `M-61de505c2db2` connect (repo.py:11-15) [lsp_call_hierarchy] via `cursor = connect()`
- d1 ^ `M-d7bc9ab449d6` load_user (service.py:6-10) [lsp_call_hierarchy] via `return query_user(user_id)`
- d2 ^ `M-37ded04827c0` handle_request (handler.py:9-15) [lsp_call_hierarchy] via `return load_user(name)`

### Edges
- handle_request -> load_user at handler.py:12 [lsp_call_hierarchy conf=1.00]

### Method sources
#### `M-568641cc8bfb` query_user
repo.py:4-11 | kind=function | provider=lsp_document_symbol | language=python
```python
def query_user(user_id):
    cursor = connect()
    sql = "SELECT * FROM users WHERE id = '" + user_id + "'"
    cursor.execute(sql)
    return cursor
```
```

Note what the boundary between the request and the AI looks like: the sink, the
entry side (`^` callers), the sink side (`v` callees), every body, and every
limitation. The model never has to choose or call a tool to get this.

## 4. Nothing is dropped silently

Every cap that bites emits a `PruneDecision` (`rule`, `detail`, location), and
every unavailable capability emits a `Degradation`. Both are in the manifest, in
the prompt, and in the console, so a reader can report incomplete coverage
instead of guessing.

### Observability: the funnel

`GET /v1/bundles/{id}/observability` returns the pipeline's own account of what
it did. Each step is in the same unit as the previous one, so `lost` is always
meaningful, and any loss carries the prune rules that caused it plus the concrete
items where they are known:

```
findings from the scanner                         1        —     0
findings resolved to an enclosing method          1     100%     0
distinct methods carrying findings                1     100%     0
contexts built (one per focus method)             1     100%     0
call-graph slices expanded                        1     100%     0
methods proposed by walking the graph (gross)     4     100%     0   ← the walk
methods kept in the bundle (net, after every cap) 4     100%     0      max_depth
method bodies read from disk                      4     100%     0
method bodies actually inlined into a context     4     100%     0
```

Alongside it: per-stage timings, a provider histogram with trust levels
(`fact` / `strong` / `weak` / `guess`), the **exact scanner invocation** (engine,
version, argv, rule hit distribution, stderr), all prunes, all degradations, and a
per-context explanation where every method carries its origin chain —
`query_user → load_user → handle_request` — so "why is this method in the bundle?"
has a literal answer.

Two warning signals are computed rather than left for the reader to notice:

* a scan that returned zero findings from an unconfigured run is flagged as
  suspicious (a no-op scan looks identical to a clean repository otherwise);
* a bundle where no language server contributed is flagged, because then every
  edge is a heuristic at confidence 0.40.

### Review console

`GET /` serves a read-only console for a running service. It is a pure renderer:
it only consumes the endpoints above, never re-derives a number and never reads
raw artifact files, so the page and the JSON cannot disagree. It shows the bundle
list with trust mix, the funnel, timings, providers, the scanner invocation, the
call chain with provenance per method, the edges with their evidence, all prunes
and degradations, and a diff against another run.

Budget (`AEGIS_BUDGET__*`, see `.env.example`):

| knob | default | meaning |
| --- | --- | --- |
| `max_depth` | 2 | call-graph hops from the sink |
| `max_nodes` | 60 | distinct methods per bundle |
| `max_callers_per_node` / `max_callees_per_node` | 8 / 12 | fan-out per hop |
| `max_lines_per_method` / `max_chars_per_method` | 400 / 24k | per-body clamp |
| `max_total_chars` | 600k | whole-bundle cap (drops lowest-value bodies first) |
| `max_contexts` | 20 | sinks expanded per run |
| `expand_concurrency` | 6 | parallel slice expansion |

## 5. Run it

The fastest way to see the whole thing work, with no language server installed:

```bash
python scripts/demo.py
```

It builds a small fixture repo containing a real taint chain
(`handle_request -> load_user -> query_user(sql sink)`), runs the scanner input
through the LSP seam using the in-repo fake language server, and prints the
resulting call chain and package paths.

### Local (no Docker)

```bash
python -m pip install -e ".[dev]"

# optional: point at a language-server catalog
export AEGIS_LSP_CONFIG_FILE=./docker/lsp.yaml

# assemble from an existing SARIF
python -m app.cli assemble --workspace ./demo/repo --sarif ./demo/scan.sarif

# or let opengrep find the findings itself
python -m app.cli assemble --workspace ./demo/repo --rule-config p/default

# degraded, syntax-only run (no language servers needed)
python -m app.cli assemble --workspace ./demo/repo --sarif scan.sarif --no-lsp

# what language servers are usable here?
python -m app.cli probe --workspace ./demo/repo
```

### Server

```bash
uvicorn app.main:app --reload
# docs at http://127.0.0.1:8000/docs
```

| method | path | purpose |
| --- | --- | --- |
| GET | `/health` | scanner version, LSP flag, effective budget |
| POST | `/v1/scan` | scan only, returns the SARIF path |
| POST | `/v1/assemble` | scan-or-SARIF → bundle |
| POST | `/v1/assemble/upload` | multipart SARIF + workspace → bundle |
| GET | `/v1/bundles` | list bundles, with trust mix and engine |
| GET | `/v1/bundles/{id}/observability` | funnel, timeline, providers, scan record, prunes |
| GET | `/v1/bundles/{id}/contexts` | per-context explanation: findings, chain, edges |
| GET | `/v1/bundles/{id}/methods` | per-method provenance ("why is this here?") |
| GET | `/v1/bundles/{id}/diff/{other}` | compare two runs |
| GET | `/v1/bundles/{id}/manifest` | the contract |
| GET | `/v1/bundles/{id}/summary` | human summary |
| GET | `/v1/bundles/{id}/blocks` | block order + cacheability |
| GET | `/v1/bundles/{id}/blocks/{block_id}` | one prompt block |
| GET | `/v1/bundles/{id}/graph` | Graphviz DOT |
| GET | `/v1/bundles/{id}/archive` | the zip |
| GET | `/v1/lsp/probe` | which servers work for a workspace |

### Docker

```bash
cp .env.example .env
cp docker/lsp.yaml docker/lsp.local.yaml     # optional catalog override

# scan a repo on the host
AEGIS_SCAN_TARGET=/path/to/repo docker compose -f docker/docker-compose.yml up --build

# the host port defaults to 8001 (8000 is commonly already taken; set
# AEGIS_HOST_PORT in .env to change it)
#   http://127.0.0.1:8001/          bundle list, contexts, prunes, prompt blocks
#   http://127.0.0.1:8001/docs      OpenAPI

# or run the CLI inside the container
docker compose -f docker/docker-compose.yml run --rm aegis \
    assemble --workspace /workspace --rule-config p/default
```

Equivalent without compose:

```bash
docker run -d --name aegis -p 127.0.0.1:8001:8000 \
  -v "$PWD/demo/repo:/workspace:ro" \
  -v "$PWD/var/packages:/data/packages" \
  -v "$PWD/var/work:/data/work" \
  aegis:0.1.0
```

Note that `docker build` only produces the image — the service is a container, so
it appears under *Containers* in Docker Desktop once you `up`/`run` it, not after
a build. One-off calls such as `aegis probe` and `aegis assemble` are deliberately
`--rm` jobs that exit when done.

The image installs the **official opengrep release binary** (self-contained
Nuitka build, pinned via `--build-arg OPENGREP_VERSION=v1.16.0`), semgrep as a
fallback engine, and pyright / typescript-language-server / clangd (each
best-effort: a server that will not install becomes a recorded degradation, not
a build failure). Node comes from NodeSource because
`typescript-language-server` 6.x requires Node ≥ 22 and Debian bookworm ships
Node 18, which installs cleanly and then fails at runtime. The scanned repo is
mounted **read-only** — Aegis never writes to a repository.

Useful build args: `BASE_IMAGE`, `OPENGREP_VERSION`, `OPENGREP_DIST`
(`opengrep_manylinux_x86` / `opengrep_manylinux_aarch64` / `opengrep_musllinux_x86`),
`NODE_MAJOR`, `INSTALL_PYRIGHT`, `INSTALL_TYPESCRIPT_LSP`, `INSTALL_CLANGD`,
`INSTALL_GOPLS`, `INSTALL_SEMGREP_FALLBACK`.

#### Layer order is load-bearing

Docker invalidates a layer **and every layer after it** when that layer's inputs
change. The expensive installs (semgrep, the language servers) therefore sit
*above* `COPY app ./app`, so editing a `.py` file cannot rebuild them.

Measured on this project:

| scenario | before | after |
| --- | --- | --- |
| no change (all cached) | 9.3 s | 8.9 s |
| **one-line edit to a `.py` file** | **341 s** | **14.9 s** |
| build after a dependency (`pyproject.toml`) change | ~341 s | ~95 s |

The 341 s was `pip install semgrep` (230 s) plus a full `pip install .` (80 s)
re-running for a comment change. Two rules keep it fast:

1. **Nothing that depends on `app/` may sit above an expensive `RUN`.** Keep new
   dependencies above the `COPY pyproject.toml` line; keep new source files under
   it.
2. `pip install .` runs once, after `pyproject.toml` is copied, because that is
   what resolves the runtime dependency tree (fastapi, uvicorn, pydantic…). The
   following step then replaces the installed package with the copied sources, so
   a code edit costs a `cp` instead of a wheel rebuild plus reinstall. `aegis` is
   pure Python, so the two are equivalent.

`--mount=type=cache` on the pip/npm steps also cuts the cost of a genuine
dependency change, by keeping the wheel and package caches in the builder.

> Why not `FROM ghcr.io/opengrep/opengrep`? That registry rejects anonymous
> pulls on some networks (`403 Forbidden` fetching the anonymous token). The
> release binary is equally self-contained, so the base image stays a parameter.

<details>
<summary>Docker build troubleshooting (proxy / flaky network)</summary>

The image build touches three networks: Debian apt, PyPI and GitHub releases.
Behind a proxy, pass the standard build args — Docker forwards `HTTP_PROXY` /
`HTTPS_PROXY` to `RUN` steps automatically:

```bash
docker build -f docker/Dockerfile -t aegis:0.1.0 \
  --build-arg HTTP_PROXY=http://host.docker.internal:3128 \
  --build-arg HTTPS_PROXY=http://host.docker.internal:3128 .
```

If a proxy is bound to `127.0.0.1` on the host, containers cannot reach it
(`host.docker.internal` resolves to the host's bridge address, not its loopback).
Bind the proxy to `0.0.0.0`, or configure Docker Desktop under
*Settings → Resources → Proxies*.

On a slow link, `apt` can fail mid-download; the Dockerfile already sets
`Acquire::Retries "5"` and 120s timeouts. To build a minimal image without the
Node-based language servers and the semgrep fallback:

```bash
docker build -f docker/Dockerfile -t aegis:slim \
  --build-arg INSTALL_PYRIGHT=false \
  --build-arg INSTALL_TYPESCRIPT_LSP=false \
  --build-arg INSTALL_CLANGD=false \
  --build-arg INSTALL_SEMGREP_FALLBACK=false .
```

That image still works end to end: missing language servers become recorded
`Degradation` entries and the bundle falls back to `syntax_regex` edges.

</details>

## 6. Tests

```bash
python -m pytest -q          # 36 tests, no language server required
```

The suite contains `tests/fake_lsp_server.py`: a dependency-free LSP server that
implements `documentSymbol`, `definition`, `references`, `implementation` and
`callHierarchy`. That lets the whole chain — JSON-RPC framing, range containment,
bidirectional graph expansion, dedupe, pruning, rendering, packaging and the HTTP
API — be tested end to end in CI without installing a real language server.

Beyond the unit suite, the container path is verified against the real tools, in
two languages, with the same code path:

| fixture | scanner | LSP seam | resulting chain |
| --- | --- | --- | --- |
| `demo/repo` (Python) | opengrep `--config auto` found the SQL-injection rule | pyright | `handle_request -> load_user -> query_user -> connect` |
| `.ts` fixture (TypeScript) | SARIF input | typescript-language-server | `handleRequest -> loadUser -> queryUser -> execute` |

All edges in both runs are `lsp_call_hierarchy` with confidence 1.00 and both runs
report **zero degradations**, which is the point of the design: the LSP is the
seam, so one implementation spans languages.

```bash
docker run --rm -v "$PWD/demo/repo:/workspace:ro" --entrypoint sh aegis:0.1.0 -c '
  opengrep scan --config auto --sarif --output /tmp/o.sarif /workspace &&
  aegis probe --workspace /workspace &&
  aegis assemble --workspace /workspace --sarif /tmp/o.sarif --json'
```

Two container gotchas worth knowing:

* **TypeScript must be 5.x.** `npm i -g typescript` now resolves to TypeScript 7,
  the native rewrite, whose `lib/` no longer ships `tsserver.js`; then
  `typescript-language-server` fails to initialize. The Dockerfile pins
  `typescript@5.9.3` and asserts the major version, so an upstream switch fails
  the build instead of silently degrading to syntax edges.
* **Node must be ≥ 22.** `typescript-language-server` 6.x requires it, and Debian
  bookworm ships Node 18 — which installs fine and then fails at runtime. The
  Dockerfile takes Node from NodeSource.

## 7. Design decisions

**Prompt layout is ordered for reuse.** Blocks are emitted as
`instructions → method_catalog → contexts` because consumers want a large static
prefix to prefill/cache and a small volatile suffix per sub-agent. Context ids are
content-derived, so a re-run reuses prefixes. `ai/blocks_meta.json` marks which
blocks are cacheable.

**One context = one self-contained analysis unit.** The catalogue block is also
inlined into each context, because a context must survive being handed to a
sub-agent on its own. The deliberate duplication is cheap next to a re-request.

**Tool surface is zero for the model.** The agent receives a finished bundle; it
does not choose tools, spawn language servers, or grep. All tool-ish work happens
here, deterministically, before the model is involved.

**Degrade, never fail.** Missing language server, missing scanner, unreadable
file, a server that dies mid-run: each becomes a `Degradation` and the run
continues. A bundle with fewer methods and an honest limitations section beats an
exception.

**Dedupe keeps the name.** Byte-identical bodies are inlined once and the other
symbols are recorded as aliases, so the reader still sees every symbol on the
chain while the model pays for the source once.

## 8. Next stages (not in this deliverable)

1. **Threat modelling / investigation sub-agents** — `ai/blocks_meta.json` plus
   the per-context blocks are the dispatch unit; the context block is
   self-contained on purpose.
2. **Prompt-cache-aware fan-out** — send `instructions.*` + `method_catalog` once
   as a cacheable prefix, then stream one `context.<id>` per worker.
3. **Tree-sitter fallback** — replace the regex `syntax_regex` provider with real
   parsing for languages without a server, keeping the same `Provider` contract.
4. **Cross-language + multi-repo assembly** — the `Edge.provider` ladder already
   tolerates mixed-quality evidence.

## 9. Layout

Deeper design notes — provider ladder, budget invariants, prompt-cache layout,
concurrency model, and where the next stages plug in — are in
[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

```
app/
  main.py                 FastAPI factory
  cli.py                  same pipeline, for review
  api/                    routes + dependency wiring
  core/                   settings, logging, hashing/token/URI helpers
  schemas/                domain + API contracts (the pipeline's public surface)
  scanner/                opengrep runner + SARIF parser
  lsp/                    JSON-RPC stdio client, position math, symbol extraction, server pool
  parsers/                syntax fallback (indent + brace) and call-site extraction
  graph/                  workspace/index caches, call-graph providers, budgeted BFS
  assembler/              body reader, context assembler, renderer, packager
  pipeline/               the wiring, with per-stage timing
docker/                   Dockerfile, compose, default LSP catalog
tests/                    pytest suite + the fake LSP server
```
