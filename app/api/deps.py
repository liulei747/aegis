"""FastAPI dependency wiring."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from fastapi import HTTPException

from aegis_contracts.domain import AnalysisBundleManifest
from aegis_core.config import Settings, get_settings
from aegis_core.workspace import WorkspaceNotFound
from aegis_core.workspace import resolve_workspace as core_resolve_workspace
from services.extraction.lsp.probe import probe_lsp  # noqa: F401  (re-exported for routes)
from services.extraction.pipeline.assemble import AssemblyPipeline, ScanOnlyPipeline


def settings_dep() -> Settings:
    return get_settings()


@lru_cache(maxsize=1)
def _pipeline() -> AssemblyPipeline:
    return AssemblyPipeline(get_settings())


@lru_cache(maxsize=1)
def _scan_pipeline() -> ScanOnlyPipeline:
    return ScanOnlyPipeline(get_settings())


def get_pipeline() -> AssemblyPipeline:
    return _pipeline()


def get_scan_pipeline() -> ScanOnlyPipeline:
    return _scan_pipeline()


def clear_pipeline_cache() -> None:
    """Drop cached pipelines. Required whenever settings change (e.g. in tests),
    because a pipeline holds a Settings snapshot for the life of the process."""
    _pipeline.cache_clear()
    _scan_pipeline.cache_clear()


def resolve_workspace(raw: str | None) -> Path:
    """The shared resolver, with this service's error shape hung off it.

    The policy lives in `aegis_core.workspace` so the extraction service can ask the
    same question; turning "not a directory" into a 400 is the gateway's job.
    """
    try:
        return core_resolve_workspace(raw)
    except WorkspaceNotFound as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc


def bundle_dir(bundle_id: str, settings: Settings) -> Path:
    """Resolve a bundle directory from a user-supplied id, refusing traversal."""
    safe = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_.")
    if not bundle_id or any(ch not in safe for ch in bundle_id) or ".." in bundle_id:
        raise HTTPException(status_code=400, detail=f"unsafe bundle id: {bundle_id!r}")
    directory = settings.output_dir / bundle_id
    if not directory.is_dir():
        raise HTTPException(status_code=404, detail=f"bundle not found: {bundle_id}")
    return directory


def load_manifest(bundle_id: str, settings: Settings) -> AnalysisBundleManifest:
    """Prefer bundle.json (it carries the per-context provenance), fall back to manifest.json."""
    directory = bundle_dir(bundle_id, settings)
    for name in ("bundle.json", "manifest.json"):
        path = directory / name
        if not path.exists():
            continue
        try:
            doc = json.loads(path.read_text(encoding="utf-8"))
        except json.JSONDecodeError as exc:
            raise HTTPException(
                status_code=500, detail=f"{name} is not valid JSON: {exc}"
            ) from exc
        payload = doc.get("manifest", doc) if isinstance(doc, dict) else doc
        try:
            return AnalysisBundleManifest.model_validate(payload)
        except Exception as exc:
            raise HTTPException(
                status_code=500, detail=f"{name} does not match the manifest schema: {exc}"
            ) from exc
    raise HTTPException(status_code=404, detail=f"bundle has no manifest: {bundle_id}")


def load_method_body(bundle_id: str, method_id: str, settings: Settings) -> str:
    """Read one method body from the package: ``methods/<method_id>.txt``.

    The console renders bodies inline, so it needs them individually. Reading the
    file avoids shipping a second copy of every body inside bundle.json.
    """
    directory = bundle_dir(bundle_id, settings)
    if not method_id.startswith("M-") or any(
        ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_"
        for ch in method_id
    ):
        raise HTTPException(status_code=400, detail=f"unsafe method id: {method_id!r}")
    path = directory / "methods" / f"{method_id}.txt"
    if not path.is_file():
        raise HTTPException(status_code=404, detail=f"no body stored for {method_id}")
    return path.read_text(encoding="utf-8")


# ----------------------------------------------------------------------
# job queue
# ----------------------------------------------------------------------
_queue_client = None


def queue_enabled() -> bool:
    """Whether this deployment runs jobs asynchronously.

    Same convention as the scan and extraction service URLs: the presence of a configured
    URL switches behaviour. With no URL the synchronous path is used unchanged, which is
    what keeps the CLI, the test-suite and local development broker-free.
    """
    return get_settings().queue.redis_url is not None


def get_queue_client():
    """A lazily created Redis client, or None when the queue is off.

    Lazy on purpose: a gateway must not fail to start because Redis is down. It starts,
    serves the read-only bundle endpoints, and answers 503 on the queue endpoints -- a
    bundle already on disk stays readable with the queue gone.
    """
    global _queue_client
    url = get_settings().queue.redis_url
    if url is None:
        return None
    if _queue_client is None:
        import redis

        _queue_client = redis.Redis.from_url(url)
    return _queue_client


def set_queue_client(client) -> None:
    """Inject a client. Used by tests, and by an embedder that owns its connection."""
    global _queue_client
    _queue_client = client


def get_job_queue():
    """The store and stream pair the job routes need: one dependency, one connection."""
    from services.queue.jobs import JobStore
    from services.queue.keys import QueueKeys
    from services.queue.streams import JobStream

    settings = get_settings()
    client = get_queue_client()
    if client is None:
        raise HTTPException(status_code=503, detail="queue unavailable: no Redis configured")
    keys = QueueKeys(settings.queue.stream, settings.queue.group)
    return (
        JobStore(client, settings.queue, keys=keys),
        JobStream(client, settings.queue, keys=keys),
    )
