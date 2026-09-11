"""FastAPI dependency wiring."""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

from fastapi import HTTPException

from aegis_contracts.domain import AnalysisBundleManifest
from aegis_core.config import Settings, get_settings
from app.lsp.manager import LanguageServerManager, load_catalog
from app.pipeline.assemble import AssemblyPipeline, ScanOnlyPipeline


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
    settings = get_settings()
    if raw is None:
        return settings.workspace_root
    path = Path(raw)
    if not path.is_absolute():
        path = (settings.workspace_root / path).resolve()
    path = path.resolve()
    if not path.exists():
        raise HTTPException(status_code=400, detail=f"workspace does not exist: {path}")
    if not path.is_dir():
        raise HTTPException(status_code=400, detail=f"workspace is not a directory: {path}")
    return path


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


def probe_lsp(workspace: Path) -> tuple[LanguageServerManager, dict, dict]:
    settings = get_settings()
    manager = load_catalog(
        settings.lsp_config_file,
        root=workspace,
        timeout_s=settings.lsp_request_timeout_s,
    )
    available: dict[str, object] = {}
    missing: dict[str, object] = {}
    try:
        for spec in manager.catalog:
            key = f"{spec.language}:{' '.join(spec.command)}"
            probe_file = workspace / f"__aegis_probe__{spec.extensions[0] if spec.extensions else '.txt'}"
            client = manager.client_for(probe_file)
            if client is None:
                missing[key] = {"extensions": spec.extensions}
            else:
                available[key] = {
                    "extensions": spec.extensions,
                    "server": client.server_info.get("name"),
                    "callHierarchy": client.supports("callHierarchyProvider"),
                    "documentSymbol": client.supports("documentSymbolProvider"),
                    "definition": client.supports("definitionProvider"),
                    "references": client.supports("referencesProvider"),
                    "implementation": client.supports("implementationProvider"),
                }
        return manager, available, missing
    finally:
        manager.stop_all()
