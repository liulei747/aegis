# Aegis front-end

A separately deployable client of the gateway's HTTP API. It shares no source with the backend:
no import, no build step that reads a Python file, no generated client checked in from the
backend tree. The only thing connecting the two is `/openapi.json` and a base URL.

## Why it is separate, and what that costs

An earlier console lived behind an nginx that also reverse-proxied `/v1` to the gateway. That is
convenient -- the browser is same-origin, so there is no CORS and no API address anywhere -- but
it welds the two together: the static files can only be served by that one proxy, and the API's
port is part of the front-end's deployment.

This project pays the cost instead:

| concern | here |
| --- | --- |
| where the API is | `src/api/config.ts`: `/config.js` at runtime, `VITE_API_BASE` at build time |
| cross-origin | yes, so the gateway's `AEGIS_CORS__ALLOW_ORIGINS` must include this origin |
| one image, many gateways | yes: restart with a different `AEGIS_API_BASE`, no rebuild |
| display numbers | computed here (`src/format.ts`), not published by the API |

The Settings screen shows the configured base and whether the current origin is allowed, because
a CORS refusal looks nothing like a permissions problem in a browser console.

## Layout

    src/api/config.ts     the API base, resolved at runtime
    src/api/client.ts     every request; the only file that names a path
    src/api/types.ts      the API surface, hand-written
    src/format.ts         every number this app computes
    src/audit.ts          folds the audit trail's events into what the screen renders
    src/components.tsx    router, polling hook, shared UI
    src/screens/          one file per screen
    test/contract.test.ts the contract, checked over HTTP
    test/openapi.snapshot.json  a captured /openapi.json (data, not backend source)
    scripts/              regenerates that snapshot; checks a real trail against `src/audit.ts`

## Running it

    npm install
    cp .env.example .env.development     # then edit VITE_API_BASE
    npm run dev                          # http://127.0.0.1:5174

There is no dev proxy. The browser calls the gateway directly, so the gateway must allow this
origin -- it defaults to `*`, which is why this works out of the box.

Checks:

    npm run typecheck
    npm test
    API_URL=http://127.0.0.1:8100 npm run snapshot   # refresh the stored OpenAPI document

`npm test` runs offline against the stored snapshot. With `API_URL` set, it also compares the
snapshot against the live gateway, which is what stops the stored copy going stale.

## Screens

Overview, **AI audit**, Jobs, Bundles (and one bundle's detail), Compare, AI verdicts, Projects,
Traffic, Settings. The menu is in `src/App.tsx`.

### The audit screen and its trail

`#/audit` submits an autonomous audit and `#/audit/<job>` watches one. Watching is the hard part: a
run takes half an hour and dispatches ~150 agents, so the gateway appends one JSON event per thing
that happens to `<work_dir>/audit/<job_id>/trail.jsonl` and the screen polls it *incrementally* --
it keeps `last_seq` and asks only for what is newer.

Two levels of detail, and neither is decoration:

* **turn level** (`agent_step`): what one agent thought, which tool it called, with what arguments,
  and what came back. This is the whole conversation, and it is the finest granularity that means
  anything -- the ReAct loop must see a complete JSON object before it knows which tool to call, so
  token-level streaming would change nothing about what an agent does.
* **run level**: which scope each agent is on, how many steps it has taken, the coverage decision
  per scope with its reason, and the candidates, verdicts and findings as they are filed.

`scripts/trail-check.ts` folds a *real* trail file with the exact functions the screen uses, because
the wire shape is checked by nothing else: a field renamed on the Python side would show up as a
permanently empty section, which looks the same as "this run had no such events".

    node --experimental-strip-types scripts/trail-check.ts <run_dir>/trail.jsonl

Two of them are worth explaining:

* **Projects** is derived, not fetched. The backend has no project entity -- a project is a
  workspace path recorded on jobs and bundles -- so the grouping happens in `format.ts` from the
  two lists the screen already has. An endpoint would have meant inventing a registry that does
  not exist.
* **Traffic** reads the gateway's in-process request log. That log is a bounded ring buffer that
  starts empty on every restart and, in a multi-replica deployment, only covers one replica. The
  screen prints the API's own note saying so rather than paraphrasing it.

## Deploying

    docker build -f docker/frontend.Dockerfile -t aegis-frontend:0.1.0 .
    docker run -p 8102:8102 -e AEGIS_API_BASE=http://gateway.example:8000 aegis-frontend:0.1.0

`AEGIS_API_BASE` is read by `docker-entrypoint.d/10-api-base.sh`, which writes `/config.js` before
nginx starts. Leave it empty only if something in front of the container forwards `/v1` -- this
image does not.
