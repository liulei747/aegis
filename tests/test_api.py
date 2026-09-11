from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.core.config import get_settings
from app.main import create_app


@pytest.fixture()
def client(tmp_path: Path, monkeypatch, workspace: Path) -> TestClient:
    monkeypatch.setenv("AEGIS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(tmp_path / "packages"))
    monkeypatch.setenv("AEGIS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AEGIS_LSP_ENABLED", "false")
    get_settings.cache_clear()
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()


def test_health_reports_scanner_and_budget(client: TestClient) -> None:
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert "opengrep" in body
    assert body["lsp_enabled"] is False
    assert "budget" in body["capabilities"]


def test_assemble_from_sarif_upload(client: TestClient, tmp_path: Path, workspace: Path) -> None:
    from tests.fixtures import write_sarif

    sarif = write_sarif(tmp_path / "scan.sarif", sink_line=5, workspace=workspace)
    with sarif.open("rb") as handle:
        response = client.post(
            "/v1/assemble/upload",
            files={"sarif": ("scan.sarif", handle, "application/json")},
            data={"workspace": str(workspace), "lsp": "false"},
        )
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["manifest"]["focus_count"] == 1
    bundle_id = body["bundle_id"]

    manifest = client.get(f"/v1/bundles/{bundle_id}/manifest")
    assert manifest.status_code == 200
    assert manifest.json()["bundle_id"] == bundle_id

    summary = client.get(f"/v1/bundles/{bundle_id}/summary")
    assert summary.status_code == 200
    assert "Aegis bundle" in summary.text

    blocks = client.get(f"/v1/bundles/{bundle_id}/blocks")
    assert blocks.status_code == 200
    ids = [b["block_id"] for b in blocks.json()]
    assert ids[0] == "bundle.header"
    assert "instructions.system" in ids
    assert "method_catalog" in ids

    block = client.get(f"/v1/bundles/{bundle_id}/blocks/instructions.system")
    assert block.status_code == 200
    assert "opengrep" in block.text

    graph = client.get(f"/v1/bundles/{bundle_id}/graph")
    assert graph.status_code == 200
    assert graph.text.startswith("digraph")

    archive = client.get(f"/v1/bundles/{bundle_id}/archive")
    assert archive.status_code == 200
    assert archive.headers["content-type"] == "application/zip"

    listing = client.get("/v1/bundles").json()["bundles"]
    assert any(b["bundle_id"] == bundle_id for b in listing)


def test_assemble_rejects_missing_workspace(client: TestClient) -> None:
    response = client.post("/v1/assemble", json={"workspace": "does-not-exist"})
    assert response.status_code == 400


def test_bundle_path_traversal_is_rejected(client: TestClient) -> None:
    response = client.get("/v1/bundles/..%2F..%2Fetc/manifest")
    assert response.status_code in (400, 404)


def test_review_ui_is_served(client: TestClient) -> None:
    response = client.get("/")
    assert response.status_code == 200
    assert "Aegis" in response.text
    assert "/v1/bundles" in response.text


def test_unknown_bundle_is_404(client: TestClient) -> None:
    assert client.get("/v1/bundles/nope/manifest").status_code == 404
