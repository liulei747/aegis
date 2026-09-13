# AI stage: contract, wiring, and what was measured

The pipeline's job ends when the bundle is on disk. This stage is what reads it back and asks a
model to judge it. It is deliberately an **addition** to the artifact: a bundle with no verdicts
is still a complete bundle, and nothing here can delete or invalidate one.

## Where it lives

| piece | file | job |
|---|---|---|
| contract | `aegis_contracts/ai.py` | `Verdict`, `AICall`, `AIReport`, `TokenUsage` |
| block reading | `services/ai/blocks.py` | `ai/blocks.jsonl` + `ai/cache_prefix.json` -> system/user messages |
| transport | `services/ai/client.py` | one OpenAI-compatible `/chat/completions` round trip |
| parsing | `services/ai/parse.py` | the answer -> `Verdict`, leniently and visibly |
| fan-out | `services/ai/runner.py` | one call per context, retries, and the report |
| job | `services/queue/worker.py` -> `_run_ai_fanout` | `JobKind.AI_FANOUT` |
| HTTP | `POST /v1/bundles/{id}/analyze`, `GET /v1/bundles/{id}/verdicts` | submit / read back |
| CLI | `scripts/feed_ai.py` | host-side convenience over the same service |

Configuration is `AIConfig` (`AEGIS_AI__*`): `enabled`, `base_url`, `model`, `api_key_env`,
`timeout_s`, `concurrency`, `temperature`, `max_contexts`. The stage is **off by default**.

## The four decisions worth knowing

1. **The key is named, never stored.** `api_key_env` holds the *name* of an environment variable.
   The service reads the environment only; the CLI adds a `.env` fallback because a checkout is
   not a container. Verified against the real credential: zero occurrences of it anywhere under
   the bundle.
2. **A model failure is a result.** Every call is recorded -- parsed or not, with the raw answer
   in `ai/answers/<context>.md`. A 504 from a gateway must not cost us the contexts that did
   answer, and it must not look like "the model found nothing".
3. **One call per context.** The prefix (instructions + legend + method catalog) goes as the
   `system` message and is byte-identical across bundles of the same workspace, which is what
   makes provider-side caching possible. Each `context.<id>` is its own call, so a 200-context
   bundle never arrives as one unreadable wall.
4. **`concurrency` defaults to 1.** Measured, behind a gateway with a ~60s ceiling: six concurrent
   calls returned 3 usable answers, six sequential calls returned 6. Raising it trades reliability
   for wall clock, and the choice is recorded in the config rather than assumed.

## What a run writes

```
ai/report.json            every call, including the failures and the reasons
ai/verdicts.jsonl         one verdict per line, one per context
ai/answers/<context>.md   the model's own words, verbatim
```

`GET /v1/bundles/{id}/verdicts` serves `ai/report.json`, not `verdicts.jsonl`: a client that only
saw the parsed verdicts would conclude that a context the model could not answer about had nothing
to report.

## Through the running stack (measured, 2026-09-12)

```
POST /v1/bundles/B-9a5317fb78/analyze?force=true   -> 202  J-54a73626...
       state=running stage=scan -> succeeded stage=done
GET  /v1/bundles/B-9a5317fb78/verdicts             -> 200
  context C-912eb79b73b2  parsed=True  22.0s  prompt=1824 completion=3115
    true_positive / critical / confidence 0.85
    data_flow: "...passed to sql_quote, which is an identity function returning v unchanged,
                so no sanitization or escape is applied"
```

The sample is `var/taint/controls/p1`, whose `sql_quote` is `return v` -- a no-op sanitizer. The
model read the body and called it critical, which is the discrimination the whole bundle design
exists for. It also asked, in `missing`, for the route registration that would prove `h` is
externally reachable -- the same reachability question the dataflow stage cannot answer alone.

### Four defects this exercise found, all only visible end to end

1. **`_job_request` crashed on `AnalyzeRequest`** (500): it read `rules` / `rule_config` / the
   globs directly, and an AI request has none of them. Every field is now read with `getattr`.
2. **`/v1/assemble` answered 500 whenever a queue was configured** -- pre-existing, and live in
   the shipped compose, which always sets `AEGIS_QUEUE__REDIS_URL`. The route declared
   `response_model=AssembleResponse` while the queued path returns a `JobAcceptedResponse`, and
   FastAPI validates the return value against the model. Both routes now use `response_model=None`
   with the shapes documented through `responses=`, which does not validate.
3. **The request fingerprint omitted `kind` and `bundle_id`**, so an `ai_fanout` job produced the
   same fingerprint as an earlier `scan` job on the same workspace: it was deduplicated onto that
   job, reused its id, and reported `succeeded` **without analysing anything**. A false success,
   found because the report on disk was 25 minutes older than the job claiming to have written it.
4. **A job whose every call failed reported `succeeded`.** That is a false success *and* it blocks
   retries, because `force=true` only re-runs failed jobs. All-failed is now a named failure
   (`ai_failed`); partial success stays `succeeded` with a warning.

A fifth was a spec/parser mismatch rather than a plumbing bug: the instructions tell the model to
put conditional reasoning **inside** `severity` ("if your severity depends on something unproven,
say so in `severity` itself"), while the parser demanded an exact enum value. A real answer of
`"high — impact could be critical if Controller.dispatch is externally exposed"` was thrown away as
`unknown severity`. The parser now reads the category off the front (longest match, word boundary)
and keeps the rest in `severity_qualifier`, so the model's own caveat survives.

### Operating notes

- **`force=true` now re-runs a finished job, including a successful one.** It used to reach only
  *failed* jobs, which meant an AI request whose answer was useless could never be asked again:
  the fingerprint does not change, so neither does the job id. Verified live -- a second
  `?force=true` on an already-analysed bundle answered 202 (not 200), rewrote the report, and
  produced a new verdict (40.4s, confidence 0.65 against 0.75 the first time). Re-running is
  meaningful for a model opinion in a way it is not for a content-addressed bundle, and the
  parameter is explicitly opt-in.
- **An AI job reports the `ai` stage.** `JobStage.AI` exists, and `first_stage(kind)` decides where
  a job's clock starts: `scan` for assemble, `ai` for a fan-out. Before, `handle()` pinned `SCAN`
  for every kind, so an AI job claimed to be scanning from start to finish. A finished job also
  now leaves **no stage pending**: stages that kind never reaches are `skipped` with a reason, so
  an assemble job's `ai` row reads "not part of this job" rather than "still to come".
- **Rebuilding `aegis:0.1.0` does not recreate the containers.** Compose compares the service
  config, not the image contents, so `docker compose up -d` leaves the old process running the old
  code from memory. Use `--force-recreate`; this cost an hour of misdiagnosis.
- compose does **not** read the checkout's `.env` (its project directory is `docker/`), so the
  credential arrives only via `docker compose --env-file .env ...`. Without it the stage is enabled
  with no key, refuses to call, and says so in `/health` (`capabilities.ai.api_key_present`).
- `AEGIS_AI__ENABLED=true` is set for `gateway` and `worker`: the gateway runs the stage on the
  synchronous path, the worker runs it for a queued job.

## Still open

| model | prompt | result |
|---|---|---|
| `glm-5.3-flash` | system 4,886 + user 3,170 chars | **HTTP 504 at ~67s per attempt**, 3 attempts, no verdict |
| `deepseek-v4-flash` | same | **33.2s**, usable verdict; `cached=2048 of 2320 prompt tokens (88% of input)` |

Both are reasoning models, and the reasoning is most of the output: `completion=3848` with
`reasoning_tokens=2930`. The gateway's own ceiling (~60s, openresty/APISIX) is therefore the
binding constraint on model choice, not our client timeout -- raising `timeout_s` cannot help,
because the 504 comes from the gateway.

The verdict itself, on the demo's SQL injection:

```
true_positive / high / confidence 0.8
data_flow: request.args.get('id') (handler.py:10) -> user_id -> safe_escape(value) (util.py:4-5)
           -> name -> load_user -> query_user -> sql = "SELECT * FROM users WHERE id = '" + ...
missing  : ['Route/framework registration proving Controller.dispatch is exposed to network
             requests; only lexical/dataflow evidence exists in the bundle',
            'The DBMS and driver used by connect() to determine whether single-quote doubling
             is a complete defence']
```

Two things worth noting in that answer. It **used the provenance we now attach**: it flagged that
`Controller.dispatch` was located by `syntax_regex` rather than the dataflow engine, and asked for
the route registration before it would call reachability proven -- which is exactly the
`dispatch`-vs-`handle_request` question, answered by the model rather than by us. And it asked for
`connect()`'s import to identify the DBMS, because quote-doubling is not a complete defence under
MySQL's backslash escaping -- a distinction no static rule in this stack makes.

## Still open

- `max_contexts` caps a run at 25 paid calls by default; a 200-context bundle is therefore
  analysed 25 contexts at a time. Deliberate, and visible in the report.
- The verdict schema is enforced leniently: a `verdict`/`severity`/`confidence` that cannot be read
  is an error, while an omitted non-decisive key is recorded in `missing_fields`. Whether an
  incomplete verdict should ever be treated as decisive is a policy question, not yet answered.
- Nothing consumes the verdicts yet: threat modelling across contexts, and any UI, are separate.
