# syntax=docker/dockerfile:1
#
# Aegis scan service - one job: turn a repository into findings (+ an honest
# record of how the scan was invoked).
#
# Deliberately much smaller than the extraction image: no language servers, no
# Node, no clangd, no semgrep. Those belong to other services, and keeping them
# out means this container starts fast and scales on CPU alone.
#
# Proxy note: pass --build-arg HTTP_PROXY/HTTPS_PROXY if the build host needs one.
ARG BASE_IMAGE=python:3.12-slim-bookworm
FROM ${BASE_IMAGE}

ARG OPENGREP_VERSION=v1.16.0
ARG OPENGREP_DIST=opengrep_manylinux_x86
ARG INSTALL_SEMGREP_FALLBACK=false

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    AEGIS_LOG_JSON=1 \
    AEGIS_SCAN_HOST=0.0.0.0 \
    AEGIS_SCAN_PORT=8101 \
    AEGIS_WORKSPACE_ROOT=/workspace

RUN set -eux; \
    printf 'Acquire::Retries "5";\nAcquire::http::Timeout "120";\nAcquire::https::Timeout "120";\n' \
        > /etc/apt/apt.conf.d/99aegis-retries; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*

# The scanner: a self-contained Nuitka binary, pinned.
RUN set -eux; \
    curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors \
        -o /usr/local/bin/opengrep \
        "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${OPENGREP_DIST}"; \
    chmod 0755 /usr/local/bin/opengrep; \
    opengrep --version

WORKDIR /opt/aegis

# Dependencies first, application source last: an edit to a .py file must not
# re-download third-party packages. See the note in docker/Dockerfile.
COPY pyproject.toml README.md MANIFEST.in ./
COPY aegis_contracts ./aegis_contracts
COPY aegis_core ./aegis_core
COPY services ./services
RUN --mount=type=cache,target=/root/.cache/pip \
    set -eux; \
    pip install --upgrade pip; \
    # `.[api]` brings only fastapi/uvicorn: the service needs a web server and the
    # shared contract layer, nothing from the extraction stack.
    pip install ".[api]"; \
    if [ "$INSTALL_SEMGREP_FALLBACK" = "true" ]; then \
        pip install semgrep || echo "WARN: semgrep fallback unavailable"; \
    fi

# Fail the build if the service cannot import, rather than discovering it at runtime.
RUN python -c "\
import services.scan.app as a; \
from services.scan.runner import run_scan, probe; \
import aegis_contracts, aegis_core; \
print('scan service importable:', a.app.title)"

RUN set -eux; \
    useradd --create-home --shell /usr/sbin/nologin aegis; \
    mkdir -p /workspace /data/scans; \
    chown -R aegis:aegis /data
USER aegis

EXPOSE 8101
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${AEGIS_SCAN_PORT}/health" || exit 1

CMD ["sh", "-c", "uvicorn services.scan.app:app --host ${AEGIS_SCAN_HOST} --port ${AEGIS_SCAN_PORT} --no-access-log"]
