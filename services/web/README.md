# aegis-web (placeholder)

The review console lives in its own service so that front-end changes never
rebuild a Python image. It is a pure renderer: it reads the API's derived views
and computes nothing itself.

Planned contents (see docs/SERVICE_TOPOLOGY.md):

    services/web/
      index.html          the console (moved out of app/api/static)
      app.js              rendering only; no pipeline arithmetic
      styles.css
      Dockerfile          nginx serving static files + proxying /v1 to the API

Endpoints it consumes (all published, all read-only):

    GET /health
    GET /v1/bundles
    GET /v1/bundles/{id}/observability
    GET /v1/bundles/{id}/contexts
    GET /v1/bundles/{id}/methods
    GET /v1/bundles/{id}/methods/{method_id}/body
    GET /v1/bundles/{id}/diff/{other}
    GET /v1/bundles/{id}/blocks/{block_id}

Contract tests for this service belong in tests/test_web_contract.py and should
assert the same three properties the old console tests did:

  1. the script parses (node --check);
  2. every endpoint it calls exists on the API (checked against the route table);
  3. it never derives a metric that the API already publishes.
