# aegis-web

The review console. It lives in its own service so a front-end change never rebuilds the
2 GB Python image, and so a route rename never rebuilds this one.

**It is a renderer.** Every number it shows arrives in an API response; it computes no
metric of its own. That is not a style preference: `aegis_contracts/views.py` is the single
place that turns bundle facts into numbers, and its tests assert the funnel's steps are all
in the same unit and that `lost` is always computable. A second implementation here would be
a second answer to the same question, free to drift, with nothing to catch the drift.

## What is here

    index.html          the shell; no API origin is named anywhere in it
    src/main.tsx        entry point
    src/App.tsx         routing (URL hash), the polling hook, shared badges
    src/api/client.ts   every request the console makes, and nothing else
    src/api/types.ts    the API's shapes, mirroring views.py and jobs.py
    src/format.ts       presentation only: values to strings, units, clocks
    src/screens/        the four screens from docs/VISUAL.md
    nginx.conf          static files + proxy /v1 to the gateway
    Dockerfile          node builds, nginx serves; the build stage is discarded

## Endpoints it consumes

    GET  /health
    GET  /v1/jobs                       GET /v1/jobs/{id}
    POST /v1/jobs                       POST /v1/jobs/{id}/cancel
    GET  /v1/bundles
    GET  /v1/bundles/{id}/observability
    GET  /v1/bundles/{id}/contexts
    GET  /v1/bundles/{id}/methods
    GET  /v1/bundles/{id}/methods/{method_id}/body
    GET  /v1/bundles/{id}/diff/{other}

Requests are same-origin: the dev server and nginx both proxy `/v1` and `/health` to the
gateway, so there is no API host in the bundle and no CORS in production. A build that
hard-coded an origin would need a rebuild per deployment and would put a port number into
front-end code; `tests/test_web_contract.py` fails if one appears.

## Running it

```bash
# development, against a gateway on 127.0.0.1:8100
npm ci
npm run dev            # http://127.0.0.1:5173

# the checks
npm test               # contract tests (needs Python on PATH)
npm run typecheck
npm run build          # tsc --noEmit && vite build

# the image
docker build -f services/web/Dockerfile -t aegis-web .
```

`python -m pytest -q` from the repository root runs the checks below too, via
`tests/test_web_contract.py` (skipped when Node or `node_modules` is missing).

## The contract tests

`test/contract.test.ts` is where this service's promises are written down:

1. **Every endpoint it calls exists.** Checked against `python -m app.cli routes`, which asks
   the FastAPI application itself. Grepping the route decorators, or keeping a list here, would
   both keep passing after a route is renamed.
2. **It computes nothing the API publishes.** A source scan, with an explicit allowlist, for
   arithmetic between two identifiers. The check *proves it can fail*: it is run against a
   synthetic `alpha - beta` that must be caught, and against the two shapes that made it hard
   to write (`scripts/demo.py`, `Static-scan findings`) which must not be.
3. **The formatters do not change a value**, exercised against a real bundle manifest from
   `var/packages/` rather than a fixture that goes stale.

## Notes for the next person

* `npm` on Windows is `npm.cmd`; a bare `"npm"` from Python raises `FileNotFoundError`.
* npm and Vite write UTF-8, and the Windows default code page cannot decode it. Capture their
  output with `encoding="utf-8"` or the reader thread dies and a passing build looks broken.
* `app.routes` no longer contains included routers (FastAPI 0.115 wraps them lazily), so any
  code that lists routes must go through `create_app().openapi()["paths"]`.
