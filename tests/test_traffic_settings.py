"""The gateway's own operational surface: what it served, and how it is configured.

Both endpoints exist because the front-end is a separate deployment and the gateway has no page
of its own: without them, "is the API even being called?" and "what settings is this container
actually running?" could only be answered from a shell inside the container.

The traffic tests work against two layers on purpose. The ring's wrap-around is a property of one
object, so it is tested on a three-slot instance instead of by issuing 500 requests; the routes
are tested through the app, because "reading the log must not appear in the log" is a property of
the middleware and nothing smaller can show it.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_core.config import get_settings
from app.api.deps import clear_pipeline_cache
from app.api.traffic import TRAFFIC, TrafficLog
from app.main import create_app
from tests.fixtures import write_sarif


@pytest.fixture()
def client(tmp_path: Path, workspace: Path, monkeypatch) -> TestClient:
    monkeypatch.setenv("AEGIS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(tmp_path / "packages"))
    monkeypatch.setenv("AEGIS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AEGIS_LSP_ENABLED", "false")
    # Both caches must be dropped: the pipeline holds a Settings snapshot, so leaving it cached
    # makes this file share whichever tmp dir ran first.
    get_settings.cache_clear()
    clear_pipeline_cache()
    # The ring is process-wide, so a test that asserts on exact `seq`/`count` values needs a known
    # starting point rather than whatever the previous test left behind.
    TRAFFIC.clear()
    app = create_app()
    with TestClient(app) as test_client:
        yield test_client
    get_settings.cache_clear()
    clear_pipeline_cache()
    TRAFFIC.clear()


def _traffic(client: TestClient, limit: int = 200) -> dict:
    response = client.get("/v1/traffic", params={"limit": limit})
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------- the ring


def test_the_ring_keeps_the_newest_and_keeps_counting() -> None:
    """Once the ring wraps, `len(entries)` stops moving and `count` does not. That gap is the
    difference between "nothing happened" and "the buffer recycled", so it is the thing to pin.
    """
    ring = TrafficLog(capacity=3)

    for index in range(5):
        ring.record(method="GET", path=f"/v1/x/{index}", status=200, duration_ms=1.0)

    assert ring.count == 5
    assert [entry["path"] for entry in ring.snapshot(10)] == ["/v1/x/4", "/v1/x/3", "/v1/x/2"]
    assert [entry["seq"] for entry in ring.snapshot(10)] == [5, 4, 3]


def test_a_record_carries_the_whole_request() -> None:
    ring = TrafficLog(capacity=2)

    entry = ring.record(method="POST", path="/v1/assemble", status=202, duration_ms=1.239,
                        client="127.0.0.1")

    assert entry["seq"] == 1
    assert entry["method"] == "POST"
    assert entry["path"] == "/v1/assemble"
    assert entry["status"] == 202
    assert entry["duration_ms"] == 1.24
    assert entry["client"] == "127.0.0.1"
    assert entry["at"].endswith("+00:00"), "timestamps are UTC, not local"
    assert isinstance(entry["seq"], int)


# ---------------------------------------------------------------- the route


def test_traffic_is_newest_first_and_counts_everything(client: TestClient) -> None:
    client.get("/v1/bundles")          # a request that must appear in the log
    client.get("/v1/bundles/nope/manifest")  # a 404 that must appear too

    body = _traffic(client, limit=3)

    assert body["limit"] == 3
    assert body["count"] == 2
    assert body["note"]
    # A page never invents entries: the two requests above are the whole log for this test.
    assert [entry["seq"] for entry in body["entries"]] == [2, 1]
    assert [entry["path"] for entry in body["entries"]] == [
        "/v1/bundles/nope/manifest",
        "/v1/bundles",
    ]
    assert body["entries"][0]["status"] == 404
    assert isinstance(body["entries"][0]["duration_ms"], float)


def test_the_traffic_endpoint_does_not_log_itself(client: TestClient) -> None:
    """A polling console must not fill the buffer with its own polls.

    Not "does not list the one request being answered" -- that weaker rule still lets every
    earlier poll sit in the ring, which at the console's 5-second interval buries the real
    traffic within minutes. This asserts the endpoint is absent from the log *entirely*: three
    polls in a row leave the count where it was.
    """
    client.get("/v1/bundles")
    before = TRAFFIC.count

    for _ in range(3):
        body = _traffic(client)

    assert all(entry["path"] != "/v1/traffic" for entry in body["entries"])
    assert body["count"] == before, "polling this endpoint must not add records"
    assert TRAFFIC.count == before, "and it must not be recorded after the response either"


def test_a_small_limit_reports_a_count_larger_than_the_page(client: TestClient) -> None:
    for _ in range(6):
        client.get("/v1/bundles")

    body = _traffic(client, limit=2)

    assert len(body["entries"]) == 2
    assert body["count"] > len(body["entries"])
    # The page is a window on the total, not the total: the newest two requests are the last two.
    # `body["count"]` is the total *including* the newest entry, because reading the log is not
    # itself recorded -- so the newest seq equals the count, not one less than it.
    assert body["entries"][0]["seq"] == body["count"]


def test_the_limiting_is_enforced_by_the_route(client: TestClient) -> None:
    assert client.get("/v1/traffic", params={"limit": 0}).status_code == 422
    assert client.get("/v1/traffic", params={"limit": 501}).status_code == 422


# ---------------------------------------------------------------- settings


def _assemble(client: TestClient, workspace: Path, tmp_path: Path, name: str = "B-settings") -> str:
    sarif = write_sarif(tmp_path / f"{name}.sarif", workspace=workspace)
    with sarif.open("rb") as handle:
        response = client.post(
            "/v1/assemble/upload",
            files={"sarif": (f"{name}.sarif", handle, "application/json")},
            data={"workspace": str(workspace), "lsp": "false", "package_name": name},
        )
    assert response.status_code == 200, response.text
    return response.json()["bundle_id"]


def test_settings_publishes_the_effective_configuration(client: TestClient) -> None:
    body = client.get("/v1/settings").json()

    assert set(body) == {
        "workspace_root", "output_dir", "work_dir", "log_level",
        "budget", "queue", "dataflow", "ai", "cors", "note",
    }
    assert Path(body["workspace_root"]).is_dir()
    assert body["budget"]["max_depth"] >= 0
    assert body["queue"]["redis_url"] is None, "no broker is configured in the tests"
    assert body["dataflow"]["enabled"] is False
    assert body["ai"]["enabled"] is False
    assert body["ai"]["api_key_present"] is False
    assert body["cors"]["allow_origins"] == ["*"]
    # Read-only, and it says why: a value from the environment cannot be changed by a request.
    assert "重新部署" in body["note"]


def test_settings_carries_the_key_name_but_never_the_key(client: TestClient, monkeypatch) -> None:
    """The one field with a rule of its own.

    A sentinel is set as the credential and then hunted through the serialised response: the
    variable's *name* is part of the configuration, its *value* is not, and "we remembered not to
    include it" is not a guarantee -- this is.
    """
    monkeypatch.setenv("AEGIS_AI__API_KEY_ENV", "AEGIS_SENTINEL_KEY")
    monkeypatch.setenv("AEGIS_SENTINEL_KEY", "sk-sentinel-do-not-leak")
    get_settings.cache_clear()

    body = client.get("/v1/settings").json()
    dumped = json.dumps(body)

    assert body["ai"]["api_key_env"] == "AEGIS_SENTINEL_KEY"
    assert body["ai"]["api_key_present"] is True
    assert "sk-sentinel-do-not-leak" not in dumped
    assert "sk-sentinel" not in dumped


def test_a_missing_key_is_reported_as_absent_not_as_an_error(client: TestClient, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_AI__API_KEY_ENV", "AEGIS_NOT_SET_KEY")
    monkeypatch.delenv("AEGIS_NOT_SET_KEY", raising=False)
    get_settings.cache_clear()

    body = client.get("/v1/settings").json()

    assert body["ai"]["api_key_present"] is False
    assert body["ai"]["api_key_env"] == "AEGIS_NOT_SET_KEY"


def test_cors_origins_are_configurable(monkeypatch) -> None:
    """An independently deployed front-end is not same-origin, so this is a deployment decision.

    The env-var name is the assertion as much as the value: ``AEGIS_`` plus the nesting separator
    is the convention every other nested section follows, and a name that did not round-trip here
    would leave an operator setting a variable nothing reads.
    """
    monkeypatch.delenv("AEGIS_CORS__ALLOW_ORIGINS", raising=False)
    get_settings.cache_clear()
    assert get_settings().cors.allow_origins == ["*"], "unset keeps the old behaviour"

    monkeypatch.setenv("AEGIS_CORS__ALLOW_ORIGINS", '["https://console.example"]')
    get_settings.cache_clear()

    assert get_settings().cors.allow_origins == ["https://console.example"]


# ---------------------------------------------------------------- bundles list


def test_the_bundle_list_carries_workspace_and_ai_presence(
    client: TestClient, workspace: Path, tmp_path: Path
) -> None:
    """One request paints the table.

    Both fields are raw facts a project view needs per row: which repository the bundle describes,
    and whether there is anything to open. Fetching them per row is the fan-out this avoids, and
    a report that exists for a *failed* run still counts as present -- the viewer decides what it
    means.
    """
    bundle_id = _assemble(client, workspace, tmp_path)

    row = next(
        entry for entry in client.get("/v1/bundles").json()["bundles"]
        if entry["bundle_id"] == bundle_id
    )

    assert row["workspace"] == str(workspace.resolve())
    assert row["has_ai_report"] is False

    # The presence flag is the file, not a judgement about the run.
    (get_settings().output_dir / bundle_id / "ai").mkdir(parents=True, exist_ok=True)
    (get_settings().output_dir / bundle_id / "ai" / "report.json").write_text(
        json.dumps({"bundle_id": bundle_id, "calls": []}), encoding="utf-8"
    )
    row = next(
        entry for entry in client.get("/v1/bundles").json()["bundles"]
        if entry["bundle_id"] == bundle_id
    )
    assert row["has_ai_report"] is True
