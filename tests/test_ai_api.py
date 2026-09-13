"""The AI endpoints: a bundle goes out, a report comes back, and the failures come with it.

The model is a fake transport, because what is under test is the *route's* contract -- 404 for a
bundle that is not there, a report that includes the contexts the model could not answer about,
and a 404 on read-back rather than an empty object that looks like "nothing to report".
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from aegis_core.config import get_settings
from app.main import create_app

VERDICT = {
    "verdict": "true_positive",
    "severity": "high",
    "confidence": 0.8,
    "reachability": "reachable",
    "chain": ["handle_request", "query_user"],
    "data_flow": "request.args.get -> cursor.execute",
    "evidence": ["repo.py:6"],
    "missing": [],
    "fix": "parameterise the query",
}


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


@pytest.fixture()
def queued_client(tmp_path: Path, monkeypatch, workspace: Path, fake_redis):
    """A gateway whose queue is backed by fakeredis -- the path an AI job actually takes.

    A second copy of `test_jobs_api`'s fixture rather than an import: fixtures are resolved by
    name from the test's own module and conftest, and reaching across test modules couples two
    files that are otherwise independent. The cost is ten duplicated lines; the benefit is that
    changing one file's queue setup cannot silently change the other's.
    """
    from app.api import deps
    from services.queue.jobs import JobStore
    from services.queue.keys import QueueKeys
    from services.queue.streams import JobStream

    monkeypatch.setenv("AEGIS_WORKSPACE_ROOT", str(workspace))
    monkeypatch.setenv("AEGIS_OUTPUT_DIR", str(tmp_path / "packages"))
    monkeypatch.setenv("AEGIS_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("AEGIS_LSP_ENABLED", "false")
    monkeypatch.setenv("AEGIS_QUEUE__REDIS_URL", "redis://localhost:6379/0")
    get_settings.cache_clear()
    deps.set_queue_client(fake_redis)

    settings = get_settings()
    keys = QueueKeys(settings.queue.stream, settings.queue.group)
    store = JobStore(fake_redis, settings.queue, keys=keys)
    stream = JobStream(fake_redis, settings.queue, keys=keys)
    stream.ensure_group()

    app = create_app()
    with TestClient(app) as test_client:
        test_client.store = store  # type: ignore[attr-defined]
        yield test_client

    deps.set_queue_client(None)
    get_settings.cache_clear()


def bundle_with_blocks(client: TestClient, name: str = "B-ai") -> Path:
    root = Path(get_settings().output_dir) / name
    ai = root / "ai"
    ai.mkdir(parents=True, exist_ok=True)
    lines = [
        json.dumps({"block_id": "instructions.system", "title": "s", "content": "system"}),
        json.dumps({"block_id": "context.C-1", "title": "c", "content": "one context"}),
    ]
    (ai / "blocks.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (ai / "cache_prefix.json").write_text(
        json.dumps({"prefix_blocks": ["instructions.system"]}), encoding="utf-8"
    )
    return root


def test_a_queued_analyze_request_carries_the_bundle_id(queued_client, tmp_path: Path) -> None:
    """The queued path is a different code path from the synchronous one, and it broke first.

    `_job_request` read `rules`/`rule_config`/... directly, so an `AnalyzeRequest` -- which has
    none of them -- raised AttributeError and the route answered 500. The synchronous tests never
    noticed because they never call `submit`, and this test exists because a real HTTP call did.
    """
    root = bundle_with_blocks(queued_client, "B-queued")
    assert (root / "ai" / "blocks.jsonl").is_file()

    response = queued_client.post("/v1/bundles/B-queued/analyze", json={"bundle_id": "B-queued"})

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["job_id"].startswith("J-")

    job = queued_client.store.get(body["job_id"])  # type: ignore[attr-defined]
    assert job is not None
    submission = job.submission
    assert submission.kind.value == "ai_fanout"
    # The whole point: the request identifies the bundle, and the fields an AI job has no
    # business carrying are not invented on its behalf.
    assert submission.request.bundle_id == "B-queued"
    assert submission.request.rules == []
    assert submission.request.budget is None


def test_analysing_a_bundle_that_does_not_exist_is_a_404(client: TestClient) -> None:
    """'Nothing to analyse' must not look like 'the model found nothing'."""
    response = client.post("/v1/bundles/B-nope/analyze", json={"bundle_id": "B-nope"})
    assert response.status_code == 404
    assert "没有包含 AI 区块的分析包" in response.json()["detail"]


def test_reading_verdicts_before_any_run_is_a_404(client: TestClient) -> None:
    bundle_with_blocks(client, "B-unanalysed")
    response = client.get("/v1/bundles/B-unanalysed/verdicts")
    assert response.status_code == 404
    assert "尚未被分析" in response.json()["detail"]


def test_a_disabled_stage_answers_that_it_is_disabled(client: TestClient) -> None:
    """The honest answer for "AI is off" is a body that says so, not a 500 and not silence."""
    bundle_with_blocks(client, "B-off")
    response = client.post("/v1/bundles/B-off/analyze", json={"bundle_id": "B-off"})
    assert response.status_code == 200
    body = response.json()
    assert body["skipped"] and "已禁用" in body["skipped"]
    assert body["calls"] == []


def test_a_real_run_stores_the_report_and_serves_it_back(
    client: TestClient, monkeypatch
) -> None:
    """With a transport injected at the client layer, the whole route round trip is exercised."""
    from aegis_contracts.ai import AIReport
    from services.ai import runner as runner_module

    root = bundle_with_blocks(client, "B-ok")

    def fake_analyse(bundle, config, **kwargs):
        answer = json.dumps(VERDICT)
        report = AIReport(bundle_id=bundle.name, model="fake-model",
                          endpoint="https://example.invalid/v1/chat/completions")
        from datetime import datetime, timezone

        from aegis_contracts.ai import AICall
        from services.ai.parse import parse_verdict

        verdict, error, missing = parse_verdict(answer)
        report.calls = [AICall(context_id="context.C-1", model="fake-model", parsed=True,
                               error=error, missing_fields=missing, verdict=verdict,
                               raw_answer=answer)]
        report.finished_at = datetime.now(timezone.utc)
        return report

    monkeypatch.setattr(runner_module, "analyse_bundle", fake_analyse)
    monkeypatch.setattr("app.api.routes.analyse_bundle", fake_analyse, raising=False)

    response = client.post("/v1/bundles/B-ok/analyze", json={"bundle_id": "B-ok"})
    assert response.status_code == 200
    body = response.json()
    assert body["calls"][0]["context_id"] == "context.C-1"

    read_back = client.get("/v1/bundles/B-ok/verdicts")
    assert read_back.status_code == 200
    assert read_back.json()["calls"][0]["verdict"]["verdict"] == "true_positive"
    assert (root / "ai" / "verdicts.jsonl").is_file()


def test_the_verdicts_route_publishes_the_raw_report(client: TestClient, monkeypatch) -> None:
    """The route serves `ai/report.json` -- the `AIReport` shape -- and adds nothing to it.

    Field-by-field rather than "it parses", because the failure this guards against is additive:
    a computed `counts` (or a per-call `cache_hit_ratio`) would keep every assertion about the
    calls passing while putting a second, drifting implementation of "how many answered" back on
    the server. The front-end owns its own display numbers now.
    """
    from datetime import datetime, timezone

    from aegis_contracts.ai import AICall, AIReport, Verdict, VerdictKind, VerdictSeverity

    root = bundle_with_blocks(client, "B-raw")
    report = AIReport(
        bundle_id="B-raw",
        model="fake-model",
        endpoint="https://example.invalid/v1/chat/completions",
        started_at=datetime(2026, 1, 1, tzinfo=timezone.utc),
        finished_at=datetime(2026, 1, 1, 0, 1, tzinfo=timezone.utc),
        calls=[
            AICall(context_id="context.C-1", model="fake-model", parsed=True,
                   verdict=Verdict(verdict=VerdictKind.TRUE_POSITIVE,
                                   severity=VerdictSeverity.HIGH, confidence=0.8),
                   raw_answer=json.dumps(VERDICT)),
            AICall(context_id="context.C-2", model="fake-model", parsed=False,
                   error="AIUnavailable: HTTP 504", raw_answer="not json"),
        ],
    )
    (root / "ai" / "report.json").write_text(report.model_dump_json(), encoding="utf-8")

    body = client.get("/v1/bundles/B-raw/verdicts").json()

    # The raw `AIReport` shape, top to bottom.
    assert set(body) == {
        "bundle_id", "model", "endpoint", "started_at", "finished_at", "skipped", "calls"
    }
    assert body["bundle_id"] == "B-raw"
    assert body["model"] == "fake-model"
    assert body["endpoint"].startswith("https://example.invalid")
    assert body["started_at"] and body["finished_at"]
    assert body["skipped"] is None

    # Nothing is pre-computed: the caller counts what it displays.
    assert "counts" not in body

    first, failed = body["calls"]
    assert [call["context_id"] for call in body["calls"]] == ["context.C-1", "context.C-2"]
    for key in ("parsed", "error", "missing_fields", "usage", "verdict", "raw_answer"):
        assert key in first and key in failed, f"{key} is not published per call"
    assert first["verdict"]["verdict"] == "true_positive"
    assert first["raw_answer"] == json.dumps(VERDICT)
    # The context the model could not answer about is in the payload, with its reason.
    assert failed["parsed"] is False
    assert failed["verdict"] is None
    assert "504" in failed["error"]
    assert failed["raw_answer"] == "not json"
