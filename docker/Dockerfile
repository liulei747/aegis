# syntax=docker/dockerfile:1
#
# Aegis container: opengrep (scanner) + language servers (the call-graph seam)
# + the FastAPI assembly service.
#
# Two environment notes that matter in practice:
#
# 1. The base image is a parameter because the official opengrep image on GHCR is
#    not anonymously pullable from every network/proxy. Opengrep itself ships as
#    a self-contained Nuitka binary, so we install the official release asset.
# 2. Behind a proxy, pass the standard build args; Docker forwards them to RUN
#    steps automatically (they are predefined build args):
#       docker build \
#         --build-arg HTTP_PROXY=http://host.docker.internal:3128 \
#         --build-arg HTTPS_PROXY=http://host.docker.internal:3128 .
#    If your proxy is only bound to loopback, `host.docker.internal` will not
#    reach it; bind it to 0.0.0.0 or use a registry mirror instead.
ARG BASE_IMAGE=python:3.12-slim-bookworm
FROM ${BASE_IMAGE}

ARG OPENGREP_VERSION=v1.16.0
ARG OPENGREP_DIST=opengrep_manylinux_x86
ARG INSTALL_PYRIGHT=true
ARG INSTALL_TYPESCRIPT_LSP=true
ARG TYPESCRIPT_VERSION=5.9.3
ARG INSTALL_CLANGD=true
ARG INSTALL_GOPLS=false
ARG INSTALL_SEMGREP_FALLBACK=true

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DEFAULT_TIMEOUT=120 \
    AEGIS_LOG_JSON=1 \
    AEGIS_HOST=0.0.0.0 \
    AEGIS_PORT=8000 \
    AEGIS_WORKSPACE_ROOT=/workspace \
    AEGIS_OUTPUT_DIR=/data/packages \
    AEGIS_WORK_DIR=/data/work \
    AEGIS_LSP_CONFIG_FILE=/opt/aegis/lsp.yaml \
    PATH="/home/aegis/.local/bin:/usr/local/bin:${PATH}"

RUN set -eux; \
    printf 'Acquire::Retries "5";\nAcquire::http::Timeout "120";\nAcquire::https::Timeout "120";\n' \
        > /etc/apt/apt.conf.d/99aegis-retries; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl git gnupg; \
    rm -rf /var/lib/apt/lists/*

# Node >= 22 is required by typescript-language-server 6.x; bookworm ships Node 18,
# which installs fine and then fails at runtime. Take Node from NodeSource.
ARG NODE_MAJOR=22
RUN set -eux; \
    mkdir -p /etc/apt/keyrings; \
    curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors \
        https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key \
        | gpg --dearmor -o /etc/apt/keyrings/nodesource.gpg; \
    printf 'deb [signed-by=/etc/apt/keyrings/nodesource.gpg] https://deb.nodesource.com/node_%s.x nodistro main\n' \
        "${NODE_MAJOR}" > /etc/apt/sources.list.d/nodesource.list; \
    apt-get update; \
    apt-get install -y --no-install-recommends nodejs; \
    rm -rf /var/lib/apt/lists/*; \
    node --version

# ---------------------------------------------------------------------------
# opengrep: the official release binary, pinned. A 404 here means the tag or the
# platform asset name changed; see https://github.com/opengrep/opengrep/releases.
# ---------------------------------------------------------------------------
RUN set -eux; \
    curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors \
        -o /usr/local/bin/opengrep \
        "https://github.com/opengrep/opengrep/releases/download/${OPENGREP_VERSION}/${OPENGREP_DIST}"; \
    chmod 0755 /usr/local/bin/opengrep; \
    opengrep --version

# ---------------------------------------------------------------------------
# Third-party runtime dependencies.
#
# ORDERING MATTERS, and it is the whole reason this section comes before the
# application code is copied in. Docker invalidates a layer and every layer after
# it when that layer's inputs change, so anything that depends on `app/` must sit
# BELOW the expensive installs. Otherwise a one-line edit to a .py file rebuilds
# semgrep + the language servers (~4 minutes) for nothing.
#
# Measured on this project: app change with the old ordering = 341 s, with this
# ordering = the `pip install .` step only.
# ---------------------------------------------------------------------------
WORKDIR /opt/aegis

# semgrep is the scanner fallback. Installed on its own (before the app exists)
# so it stays cached across application edits. BuildKit cache mounts keep the
# wheel downloads too, which is what makes a dependency change tolerable.
RUN --mount=type=cache,target=/root/.cache/pip \
    set -eux; \
    if [ "$INSTALL_SEMGREP_FALLBACK" = "true" ]; then \
        pip install semgrep || echo "WARN: semgrep fallback unavailable"; \
    fi

# Language servers, also independent of our source. Best-effort by design: a
# server that will not install degrades the bundle (lower-confidence syntax
# edges, recorded as a Degradation) instead of failing the image build.
RUN --mount=type=cache,target=/root/.npm \
    set -eux; \
    if [ "$INSTALL_PYRIGHT" = "true" ]; then \
        npm install -g --no-fund --no-audit pyright || echo "WARN: pyright unavailable"; \
    fi; \
    if [ "$INSTALL_TYPESCRIPT_LSP" = "true" ]; then \
        npm install -g --no-fund --no-audit "typescript@${TYPESCRIPT_VERSION}" typescript-language-server; \
        node -e "const p=require('/usr/lib/node_modules/typescript/package.json'); \
                 if(!p.version.startsWith('5.')) { console.error('unexpected typescript '+p.version); process.exit(1); }"; \
    fi; \
    if [ "$INSTALL_CLANGD" = "true" ]; then \
        apt-get update \
            && apt-get install -y --no-install-recommends clangd \
            && rm -rf /var/lib/apt/lists/* \
            || echo "WARN: clangd unavailable"; \
    fi; \
    if [ "$INSTALL_GOPLS" = "true" ]; then \
        ( curl -fsSL --retry 4 --retry-delay 3 --retry-all-errors \
              https://go.dev/dl/go1.23.4.linux-amd64.tar.gz -o /tmp/go.tgz \
          && tar -C /usr/local -xzf /tmp/go.tgz \
          && GOBIN=/usr/local/bin /usr/local/go/bin/go install golang.org/x/tools/gopls@latest \
          && rm -rf /tmp/go.tgz /usr/local/go ) \
          || echo "WARN: gopls unavailable"; \
    fi

# ---------------------------------------------------------------------------
# Aegis itself. Everything from here down is invalidated by a source edit, and
# nothing from here down is expensive: this is the fast path.
#
# `pip install .` resolves the dependency tree (fastapi, uvicorn, pydantic, ...).
# That must happen here, or the app has no runtime. It also installs a copy of
# the package, which the next step replaces with the sources we copied in — that
# way an edit costs a `cp`, not a wheel rebuild plus a reinstall.
#
# Net effect on the edit/build loop for this project: 341 s -> ~7 s.
# ---------------------------------------------------------------------------
COPY pyproject.toml README.md MANIFEST.in ./
# `[all]` is required here: since the service split, fastapi/uvicorn live in an
# extra (the scan service installs `[api]` only, so it does not carry the
# extraction stack). A bare `pip install .` would ship an image without a web
# framework — which is exactly how this line broke once.
RUN --mount=type=cache,target=/root/.cache/pip \
    pip install --upgrade pip && pip install ".[all]"

# The shared layers are copied as sources, like the app: they change as often and
# rebuilding a wheel for them on every edit is what made the loop slow.
# `services/` is included because extraction consumes the scan capability from it
# (in-process by default, over HTTP when AEGIS_SCAN_SERVICE_URL is set).
COPY aegis_contracts ./aegis_contracts
COPY aegis_core ./aegis_core
COPY services ./services
COPY app ./app
RUN set -eux; \
    target="$(python -c 'import site; print(site.getsitepackages()[0])')"; \
    for pkg in app aegis_contracts aegis_core services; do \
        rm -rf "${target}/${pkg}"; \
        cp -r "/opt/aegis/${pkg}" "${target}/${pkg}"; \
    done; \
    python -c "import app, aegis_contracts, aegis_core, services.scan.client, app.api.routes, app.main, fastapi, uvicorn; print('aegis', app.__version__, 'importable')"

COPY docker/lsp.yaml /opt/aegis/lsp.yaml
COPY docker/logging.json /opt/aegis/docker-logging.json
COPY docker/entrypoint.sh /usr/local/bin/aegis-entrypoint
RUN chmod 0755 /usr/local/bin/aegis-entrypoint

# Non-root runtime user. The scanned repo is mounted read-only; only /data is writable.
RUN set -eux; \
    useradd --create-home --shell /usr/sbin/nologin aegis; \
    mkdir -p /workspace /data/packages /data/work; \
    chown -R aegis:aegis /data /opt/aegis

USER aegis
WORKDIR /opt/aegis

EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=10s --start-period=25s --retries=3 \
    CMD curl -fsS "http://127.0.0.1:${AEGIS_PORT}/health" || exit 1

ENTRYPOINT ["/usr/local/bin/aegis-entrypoint"]
CMD ["serve"]
