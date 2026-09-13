"""FastAPI application factory."""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from aegis_core.config import get_settings
from aegis_core.logging import get_logger, setup_logging
from app import __version__
from app.api import traffic
from app.api.audit import router as audit_router
from app.api.jobs import router as jobs_router
from app.api.routes import router

log = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    settings = get_settings()
    setup_logging(settings.log_level)
    settings.workspace_root.mkdir(parents=True, exist_ok=True)
    settings.output_dir.mkdir(parents=True, exist_ok=True)
    settings.work_dir.mkdir(parents=True, exist_ok=True)
    log.info("aegis %s ready (workspace=%s)", __version__, settings.workspace_root)
    yield
    log.info("aegis shutting down")


def create_app() -> FastAPI:
    settings = get_settings()
    setup_logging(settings.log_level)
    app = FastAPI(
        title="Aegis",
        description=(
            "Static-scan hits + LSP call graph -> AI-ready analysis bundles. "
            "First deliverable: the assembly stage."
        ),
        version=__version__,
        lifespan=lifespan,
    )
    app.add_middleware(
        CORSMiddleware,
        # Configurable because the front-end is deployed independently now: it is not
        # same-origin with the gateway, so which origins may read responses is a deployment
        # decision (`AEGIS_CORS__ALLOW_ORIGINS`), not a constant compiled into the app.
        allow_origins=settings.cors.allow_origins,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    app.include_router(router)
    app.include_router(traffic.router)
    # Job routes are separate because they are a different contract: these answer 202 and
    # hand back an id, while everything in `router` is a synchronous request/response.
    app.include_router(jobs_router)
    # The audit's read side (trail, report) is its own router: submitting goes through the job
    # contract, but watching a 30-minute agent run is a different shape from reading a job.
    app.include_router(audit_router)
    # Last, so the request log wraps every other middleware and sees the status code the CORS
    # layer (or a handler) finally settled on.
    traffic.install(app)
    return app


app = create_app()
