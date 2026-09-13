#
# Aegis dataflow worker: a resident Joern server plus the supervisor that owns it.
#
# WHY THIS BASE IMAGE. Joern is delivered as a 5.8 GB multi-language image, and the worker
# needs it plus a small Python HTTP supervisor. Two shapes were considered:
#
#   1. base on a Python image and copy Joern in -- needs a JRE, and this host cannot reach
#      Docker Hub or the Debian archives to install one;
#   2. base on the Joern image and add the supervisor -- what this does.
#
# The Joern image is AlmaLinux 9 and *already ships* Python 3.9 plus pip, so the only thing
# added is a handful of wheels. That is why this Dockerfile is short.
#
# PYTHON 3.9, AND THE ONE PACKAGE THAT MAKES IT WORK. The project declares
# `requires-python = ">=3.10"` and uses `X | None` in annotations. On 3.9 pydantic cannot
# evaluate those and fails at import with a precise message; `eval_type_backport` is the
# package pydantic itself names as the fix. Because of the version floor, `pip install .`
# is not usable here, so dependencies are installed by name and the source is put on
# PYTHONPATH instead. That is a real divergence from every other image in this repo and it
# is deliberate: the alternative was installing a second Python into AlmaLinux.
#
# NO `# syntax=docker/dockerfile:1` LINE, deliberately -- same reason as docker/Dockerfile:
# it makes BuildKit fetch that frontend from Docker Hub first, and the build then dies at
# line 1 on a host that cannot reach it.
#
# The base is a parameter because the official Joern image is not anonymously pullable from
# every network. On a host that already has it, either form works:
#     docker build -f services/dataflow/Dockerfile -t aegis-dataflow:0.1.0 .
#     docker build --build-arg JOERN_IMAGE=joern-local:probe ... .
ARG JOERN_IMAGE=ghcr.io/joernio/joern
FROM ${JOERN_IMAGE}

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    PYTHONPATH=/opt/aegis \
    AEGIS_WORKSPACE_ROOT=/workspace \
    AEGIS_DATAFLOW__ENABLED=true \
    AEGIS_DATAFLOW__CACHE_DIR=/data/dataflow \
    AEGIS_DATAFLOW__WORKER_SERVER_PORT=8099 \
    AEGIS_DATAFLOW__WORKER_HTTP_PORT=8105

# Dependencies first, sources second: an edit to a .py file must not re-download wheels.
# `eval_type_backport` is load-bearing on 3.9 (see the header), not a convenience.
RUN --mount=type=cache,target=/root/.cache/pip \
    set -eux; \
    pip3 install \
        eval_type_backport \
        "pydantic>=2.7" \
        "pydantic-settings>=2.3" \
        "fastapi>=0.115" \
        "uvicorn[standard]>=0.30" \
        "httpx>=0.27" \
        "pyyaml>=6.0"; \
    python3 -c "import fastapi, uvicorn, pydantic, pydantic_settings, eval_type_backport; print('deps ok')"

WORKDIR /opt/aegis
COPY aegis_contracts ./aegis_contracts
COPY aegis_core ./aegis_core
COPY services ./services

# Fails the build, not the first request. Importing the app also constructs the worker, which
# is intentionally cheap (no I/O until `start()`), so this assertion is about the wiring.
RUN python3 -c "\
import aegis_core.config, aegis_core.workspace, \
       services.dataflow.worker, services.dataflow.worker_app, services.dataflow.router; \
print('worker importable')"

# Joern writes project scratch next to its working directory, so the cache must be writable
# by whoever the supervisor runs as. Compose mounts a volume here.
RUN mkdir -p /workspace /data/dataflow

EXPOSE 8105
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${AEGIS_DATAFLOW__WORKER_HTTP_PORT}/health" || exit 1

# One worker per container; the fleet is compose's job (see docker/docker-compose.yml).
# `--no-access-log` matches the other services: access logs are noise next to the flow timing
# the worker reports in its response.
CMD ["sh", "-c", "exec uvicorn services.dataflow.worker_app:app --host 0.0.0.0 --port ${AEGIS_DATAFLOW__WORKER_HTTP_PORT} --no-access-log"]
