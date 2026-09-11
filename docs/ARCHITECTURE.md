# Architecture notes

Companion to `README.md`, aimed at a code reviewer: why the pieces are shaped
this way, what the contracts are, and where the next stages plug in.

## 1. The one idea everything rests on

A language server's `textDocument/documentSymbol` response gives, for every
callable, a `range` covering its **entire body** and a `selectionRange` covering
just its **name**. Therefore:

* "which method does this scanner hit belong to?" is range containment —
  `app/lsp/symbols.py::find_enclosing`, deepest match wins;
* "give me the whole method" is a byte slice of the file using
  `LineIndex.offset_range` — no re-request, no re-parse;
* "who calls this / what does it call?" is `callHierarchy/*`, and when the server
  lacks call hierarchy, `textDocument/definition` at each lexical call site.

No index, no build system, no per-language grammar. One implementation spans
every language that has a server.

### Position encoding is not optional

LSP positions are `(line, character)` with `character` counted in UTF-16 code
units (the default encoding). Python strings are UCS-4. Every conversion goes
through `app/lsp/positions.py::LineIndex`, and `test_line_index_handles_utf16_surrogate_pairs`
guards the emoji case. Getting this wrong silently corrupts every method range,
which is why it has its own module instead of living inline in the client.

## 2. Provider ladder and why provenance is mandatory

`Provider` (`app/schemas/domain.py`) is on every method, every edge and every
finding. `CallGraphResolver` tries the best available source first:

```
callHierarchyProvider?      -> lsp_call_hierarchy   (conf 1.00)
  else lexical call sites + definitionProvider
                            -> lsp_definition       (conf 0.90)
implementationProvider?     -> lsp_implementation   (conf 0.80)
referencesProvider?         -> lsp_references       (conf 0.60)
no server at all            -> syntax_regex         (conf 0.40)
```

The renderer prints the provider next to every claim, and the system prompt tells
the model how to weigh each one. A bundle that quietly mixed a heuristic guess
with a server fact would be worse than useless, so the distinction is a first
class field rather than a log line.

Call hierarchy is *optional* in LSP and several widely used servers never
implement it. That is exactly why the lexical call-site fallback exists: it turns
a capability gap into a recorded confidence drop instead of a missing call graph.

## 3. Budgeting: the reason a bundle can be trusted

`BudgetConfig` caps depth, breadth, per-body size and total size.
`CallGraphBuilder` (BFS, both directions) and `MethodReader` (global char cap)
enforce it. Two invariants hold:

1. **Nothing is dropped silently.** Every cap that bites appends a
   `PruneDecision(rule, detail, method_id, path, line, provider)`.
2. **The sink is never dropped.** `MethodReader._focus_ids` excludes focus bodies
   from the global character cap; if the cap still cannot be met, that is
   reported as `max_total_chars_exceeded` rather than quietly gutting the bundle.

Both are covered by tests in `tests/test_assembler.py`.

## 4. Dedupe with provenance

Two different things are deduplicated, at two levels:

* **Findings → context.** `AssemblyPipeline._locate` merges findings that resolve
  to the same enclosing method, so five rules hitting one function cost one
  context. The merge count is recorded in `Coverage.deduped`.
* **Methods → bodies.** `MethodReader` stores each distinct method once.
  `ContextAssembler._one` then inlines byte-identical bodies once per context and
  records the other symbols under `AssembledContext.aliases`, so the reader still
  sees every symbol on the chain while the model pays for the text once.

## 5. Why the prompt has a fixed block order

`BundleRenderer` emits blocks in this order:

```
bundle.header
instructions.system      <- byte-identical across runs of a version
instructions.legend
instructions.chunking
method_catalog           <- the big, stable, cacheable block
context.<id> ...         <- the small volatile part, one per sink
run.notes
```

Rationale: consumers of this bundle want (a) a large static prefix that can be
prefilled / cached provider-side, and (b) a small per-unit suffix. Context ids are
content-derived (`sha1(focus, method set, finding ids)`), so a re-run of the same
scan produces the same ids and reuses the same prefixes.
`ai/blocks_meta.json` marks each block `cacheable: true|false` so a caller does
not have to know the convention.

`method_catalog` overlaps with the "Method sources" section inside each
`context.<id>`. That duplication is deliberate: a context block must be
self-contained because the planned fan-out hands **one context per sub-agent**.
Cheap duplication beats a re-request.

## 6. Degrade, never fail

Every capability boundary records a `Degradation` and continues:

* no language server for a file type → syntax heuristics, `lsp` degradation;
* server fails to spawn → same, with the spawn error in the reason;
* server dies mid-run → `ServerExited` becomes an empty result for that query;
* scanner missing → `semgrep` fallback, or an empty audit bundle with a warning;
* unreadable file → `locate_failed` prune;
* budget exceeded → prunes.

`AssemblyPipeline._manifest` filters degradations down to the ones that actually
changed the outcome, so a Python-only run does not report "gopls missing".

## 7. Concurrency model

* One `LspClient` per language, spawned lazily, reused for the run, torn down in a
  `finally`.
* `LspClient` uses one reader thread and one writer thread over the subprocess's
  stdio, with a `threading.Event` per request. This avoids asyncio
  subprocess-transport portability traps while still allowing concurrent callers,
  and it is why the async pipeline can call blocking LSP methods via
  `asyncio.to_thread`.
* `AssemblyPipeline._expand` runs slices concurrently under a semaphore
  (`budget.expand_concurrency`); `MethodReader` reads bodies concurrently under
  the same bound. Per-file locks in `CallGraphResolver` keep duplicate
  definition queries from stampeding.

## 8. Where the next stage plugs in

| next stage | seam already in place |
| --- | --- |
| threat modelling / investigation sub-agents | `context.<id>` blocks are self-contained; `blocks_meta.json` lists them |
| prompt-cache-aware fan-out | fixed block order + `cacheable` flags + content-stable ids |
| tree-sitter fallback for serverless languages | implement a `BaseSyntaxParser` subclass and `register()` it; `Provider.SYNTAX_REGEX` stays the label, or add a new enum member |
| more languages | `docker/lsp.yaml` / `AEGIS_LSP_CONFIG_FILE` — no code change |
| per-finding LLM triage before assembly | `AssemblyPipeline._locate` is a single decision point that already ranks findings by severity |
| SARIF out / ticketing | `manifest.json` + `bundle.json` are the machine contract |

## 9. Observability is a view layer, not a second source of truth

`app/observability/views.py` is the only place that turns bundle facts into
something a human reads. It is pure: it takes an
`AnalysisBundleManifest` and returns derived views, never mutating it and never
inventing a number. That is asserted (`test_views_do_not_mutate_the_manifest`).

Consequences worth keeping:

* the JSON endpoints and the HTML console call the same builders, so they cannot
  disagree;
* the console is a *renderer*: it only consumes `/observability`, `/contexts` and
  `/diff`, never raw artifact files. A test enforces that;
* deleting the module or the console cannot change a bundle.

### The funnel contract

Losses are the interesting part, so the funnel is built so that every step is in
the same unit as the previous one and `lost` is always computable:

```
findings -> located -> focus methods -> contexts -> slices
         -> methods proposed (gross) -> methods kept (net) -> bodies read -> inlined
```

Two details that were bugs before they were features:

* **unit changes must be explicit.** An earlier version subtracted "slices" from
  "methods", which is meaningless; the step that changes unit now says so in its
  label (`methods proposed …`).
* **a dropped method never enters any collection.** A cap that refuses a node
  leaves no trace in `methods`, so `FocusSlice.methods_dropped` counts refusals
  explicitly. Without it, `max_nodes` looked like it never fired.

### Provenance per method

`MethodRef.origin_path` records the method ids from the focus down to that
method. It is set during the BFS (and for implementation edges), so the console
can answer "why is this method here?" with a literal chain
(`query_user → load_user → handle_request`) instead of an inferred one.

### Signals computed, not left to the reader

* a scan that produced zero findings from an unconfigured invocation is flagged
  (`ScanRecord.zero_findings_is_suspicious`); otherwise a no-op scan is
  indistinguishable from a clean repository;
* a bundle where no `lsp_*` provider contributed is flagged, because then every
  edge is a `syntax_regex` guess at confidence 0.40;
* the scanner's argv, version, rule-hit distribution and stderr tail are recorded,
  so "0 findings" can be diagnosed rather than believed.

## 10. Module map

| module | responsibility | key types |
| --- | --- | --- |
| `app/core/config.py` | env-driven settings + budget | `Settings`, `BudgetConfig` |
| `app/core/utils.py` | hashing, token estimate, URI/path, clamping | `LineIndex` helpers live next to LSP instead |
| `app/schemas/domain.py` | the pipeline's public data contract | `Finding`, `MethodSymbol`, `CallEdge`, `MethodContext`, `AnalysisBundleManifest` |
| `app/scanner/opengrep.py` | spawn opengrep/semgrep | `OpengrepRunner`, `ScanOutcome` |
| `app/scanner/sarif.py` | SARIF 2.1.0 → `Finding` | `SarifParser` |
| `app/lsp/protocol.py` | framing + wire types | `encode_message`, `try_decode_message`, `LspRange` |
| `app/lsp/client.py` | one server process | `LspClient` |
| `app/lsp/manager.py` | pool + capability gating | `LanguageServerManager`, `LanguageServerSpec` |
| `app/lsp/positions.py` | UTF-16 ↔ offset conversion | `LineIndex` |
| `app/lsp/symbols.py` | documentSymbol → scopes | `RawSymbol`, `find_enclosing`, `identifier_at` |
| `app/parsers/syntax.py` | serverless fallback | `IndentParser`, `BraceParser`, `CallSite` |
| `app/graph/resolver.py` | file/symbol caches | `Workspace`, `SymbolIndex` |
| `app/graph/providers.py` | the provider ladder | `CallGraphResolver` |
| `app/graph/builder.py` | budgeted bidirectional BFS | `CallGraphBuilder`, `FocusSlice` |
| `app/assembler/reader.py` | full-body reads + global cap | `MethodReader`, `BodySet`, `MethodBody` |
| `app/assembler/contexts.py` | dedupe + one context per sink | `ContextAssembler`, `AssembledContext` |
| `app/assembler/render.py` | prompt layout + legend | `BundleRenderer`, `SYSTEM_INSTRUCTIONS` |
| `app/assembler/package.py` | on-disk tree + zip + DOT | `BundlePackager` |
| `app/pipeline/assemble.py` | wiring, timing, degradation filtering | `AssemblyPipeline`, `PipelineRequest` |
| `app/observability/views.py` | pure derived views: funnel, timeline, providers, provenance, diff | `overview`, `funnel`, `context_views`, `method_index`, `diff` |
| `app/api/*` | HTTP surface + review console | `routes.py`, `static/index.html` |
