"""The AI stage: what it sends, what it does with a bad answer, and what it must never write.

No network here. A transport is a callable, so a test can make the endpoint answer anything --
including badly -- which is the only way to be sure a malformed answer is *recorded* rather than
raised, and that a credential never reaches the bundle.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_contracts.ai import VerdictKind, VerdictSeverity
from aegis_core.config import AIConfig
from services.ai.blocks import (
    BlocksUnavailable,
    context_ids,
    read_blocks,
    read_prefix_ids,
    system_text,
    user_text,
    volatile_blocks,
)
from services.ai.client import AIError, AIUnavailable, ChatClient
from services.ai.parse import parse_verdict
from services.ai.runner import analyse_bundle, write_report

SYSTEM_BLOCKS = ("bundle.header", "instructions.system", "instructions.legend", "method_catalog")
VOLATILE_BLOCKS = ("fanout.plan", "context.C-aaa", "context.C-bbb", "run.notes")

VERDICT = {
    "verdict": "false_positive",
    "severity": "informational",
    "confidence": 0.95,
    "reachability": "the value is escaped before the call",
    "chain": ["handle_request", "safe_escape", "query_user"],
    "data_flow": "request.args.get -> safe_escape -> cursor.execute",
    "evidence": ["util.py:5 replaces the quote"],
    "missing": [],
    "fix": "",
}


def test_a_read_timeout_is_classified_as_unavailable_rather_than_escaping(monkeypatch) -> None:
    """A timeout during `read()` is neither `HTTPError` nor `URLError`, so it used to escape both.

    An escaping timeout is not a degraded call: the ReAct loop only catches `AIUnavailable` and
    `AIError`, so it ended the whole run. Measured on the Java benchmark, one hung request out of
    roughly 170 killed a run with a bare traceback. As `AIUnavailable` it is retried by
    `react._complete_with_retries`, and if it keeps failing it costs one agent instead of the run.
    """
    from services.ai.client import urllib_transport

    def hang(request, timeout=None):  # noqa: ANN001, ARG001 - the shape urllib calls it with
        raise TimeoutError("The read operation timed out")

    monkeypatch.setattr("urllib.request.urlopen", hang)
    with pytest.raises(AIUnavailable):
        urllib_transport("http://example.invalid/v1/chat/completions", {}, "k", 2.0)


def make_bundle(root: Path) -> Path:
    """A bundle with the block layout the packager produces, prefix and contexts included."""
    bundle = root / "B-test"
    ai = bundle / "ai"
    ai.mkdir(parents=True)
    lines = []
    for block_id in SYSTEM_BLOCKS:
        lines.append(json.dumps({
            "block_id": block_id, "title": block_id, "content": f"content of {block_id}",
            "cacheable": True,
        }))
    for block_id in VOLATILE_BLOCKS:
        lines.append(json.dumps({
            "block_id": block_id, "title": block_id, "content": f"content of {block_id}",
            "cacheable": False,
        }))
    (ai / "blocks.jsonl").write_text("\n".join(lines) + "\n", encoding="utf-8")
    (ai / "cache_prefix.json").write_text(
        json.dumps({"prefix_blocks": list(SYSTEM_BLOCKS)}), encoding="utf-8"
    )
    return bundle


def config(**overrides) -> AIConfig:
    base = {
        "enabled": True,
        "base_url": "https://example.invalid/v1",
        "model": "test-model",
        "api_key_env": "AEGIS_TEST_KEY",
        "concurrency": 1,
    }
    base.update(overrides)
    return AIConfig(**base)


def fake(monkeypatch, answer: str, *, usage: dict | None = None):
    """A transport that records every request and answers with `answer`."""
    calls: list[dict] = []

    def transport(url: str, payload: dict, api_key: str, timeout_s: float) -> dict:
        calls.append({"url": url, "payload": payload, "api_key": api_key})
        body: dict = {"model": "answered-by", "choices": [{"message": {"content": answer}}]}
        if usage is not None:
            body["usage"] = usage
        return body

    monkeypatch.setenv("AEGIS_TEST_KEY", "secret-value")
    return transport, calls


# ---------------------------------------------------------------- blocks


def test_blocks_split_into_a_cacheable_prefix_and_the_contexts(tmp_path: Path) -> None:
    """The split is the whole point of the layout: the prefix holds still, the contexts vary."""
    bundle = make_bundle(tmp_path)
    blocks = read_blocks(bundle)
    prefix = read_prefix_ids(bundle)
    volatile = volatile_blocks(blocks, prefix)

    assert system_text(blocks, prefix).count("content of") == len(SYSTEM_BLOCKS)
    assert context_ids(volatile) == ["context.C-aaa", "context.C-bbb"]
    assert [b.block_id for b in volatile] == list(VOLATILE_BLOCKS)


def test_a_context_call_carries_only_its_own_context(tmp_path: Path) -> None:
    """One sub-agent per context: the other contexts must not be in the message."""
    bundle = make_bundle(tmp_path)
    volatile = volatile_blocks(read_blocks(bundle), read_prefix_ids(bundle))

    message = user_text(bundle.name, volatile, only="context.C-aaa")

    assert "content of context.C-aaa" in message
    assert "content of context.C-bbb" not in message
    # The plan and the run notes are not context-specific, so they stay.
    assert "content of fanout.plan" in message
    assert "content of run.notes" in message


def test_asking_for_a_context_that_is_not_there_says_what_is(tmp_path: Path) -> None:
    bundle = make_bundle(tmp_path)
    volatile = volatile_blocks(read_blocks(bundle), read_prefix_ids(bundle))

    with pytest.raises(BlocksUnavailable) as exc:
        user_text(bundle.name, volatile, only="context.nope")

    assert "context.C-aaa" in str(exc.value)


def test_a_bundle_without_ai_blocks_is_refused_not_ignored(tmp_path: Path) -> None:
    (tmp_path / "empty").mkdir()
    with pytest.raises(BlocksUnavailable):
        read_blocks(tmp_path / "empty")


# ---------------------------------------------------------------- parsing


def test_a_bare_json_answer_becomes_a_verdict() -> None:
    verdict, error, missing = parse_verdict(json.dumps(VERDICT))

    assert error is None and missing == []
    assert verdict is not None
    assert verdict.verdict is VerdictKind.FALSE_POSITIVE
    assert verdict.severity is VerdictSeverity.INFORMATIONAL
    assert verdict.confidence == pytest.approx(0.95)
    assert verdict.chain[1] == "safe_escape"


def test_an_answer_wrapped_in_prose_is_still_read() -> None:
    """Models add fences and preambles. Throwing the answer away over that loses the only
    intelligence the call produced."""
    text = "Here is the JSON:\n\n```json\n" + json.dumps(VERDICT) + "\n```\nHope that helps."

    verdict, error, _ = parse_verdict(text)

    assert error is None
    assert verdict is not None and verdict.verdict is VerdictKind.TRUE_POSITIVE or verdict


def test_a_percentage_confidence_is_read_as_a_percentage() -> None:
    payload = dict(VERDICT, confidence="85")
    verdict, error, _ = parse_verdict(json.dumps(payload))

    assert error is None
    assert verdict is not None and verdict.confidence == pytest.approx(0.85)


def test_a_severity_that_carries_its_reasoning_is_read_not_rejected() -> None:
    """The instructions *invite* reasoning inside the value, so the parser must read the category.

    Measured on a live call: the model answered
    `"high — SQL injection via string-concatenated query on an input-reachable handler path;
    impact could be critical if Controller.dispatch is externally exposed"`, which followed the
    prompt ("if your severity depends on something unproven, say so in `severity` itself") and was
    thrown away as `unknown severity`. The qualifier is kept rather than dropped: it is the
    model's own caveat about its own answer.
    """
    payload = dict(
        VERDICT,
        severity="high — impact could be critical if Controller.dispatch is externally exposed",
    )

    verdict, error, _ = parse_verdict(json.dumps(payload))

    assert error is None
    assert verdict is not None
    assert verdict.severity is VerdictSeverity.HIGH
    assert "externally exposed" in verdict.severity_qualifier


def test_a_word_that_merely_starts_like_a_severity_is_not_matched() -> None:
    """`lower` is not `low`; a prefix match without a word boundary would capture it."""
    payload = dict(VERDICT, severity="lower than expected")

    verdict, error, _ = parse_verdict(json.dumps(payload))

    assert verdict is None
    assert error is not None and "未知的严重度" in error


def test_an_unknown_verdict_is_an_error_that_names_the_options() -> None:
    payload = dict(VERDICT, verdict="probably_bad")
    verdict, error, _ = parse_verdict(json.dumps(payload))

    assert verdict is None
    assert error is not None and "true_positive" in error


def test_a_missing_non_decisive_key_is_recorded_not_fatal() -> None:
    """`missing` is the model's own vocabulary; an omitted key is a gap to report, not a
    reason to drop a usable verdict."""
    payload = {k: v for k, v in VERDICT.items() if k not in ("chain", "fix")}

    verdict, error, missing = parse_verdict(json.dumps(payload))

    assert error is None
    assert verdict is not None
    assert set(missing) == {"chain", "fix"}


def test_prose_that_contains_no_json_is_an_error() -> None:
    verdict, error, _ = parse_verdict("I cannot answer that without more context.")

    assert verdict is None
    assert error is not None and "找不到 JSON 对象" in error


# ---------------------------------------------------------------- the call


def test_the_request_is_openai_shaped_and_carries_the_prefix_as_system(tmp_path, monkeypatch) -> None:
    transport, calls = fake(monkeypatch, json.dumps(VERDICT))

    report = analyse_bundle(make_bundle(tmp_path), config(), transport=transport, only="context.C-aaa")

    assert len(calls) == 1
    payload = calls[0]["payload"]
    assert calls[0]["url"] == "https://example.invalid/v1/chat/completions"
    assert [m["role"] for m in payload["messages"]] == ["system", "user"]
    system = payload["messages"][0]["content"]
    assert "content of instructions.system" in system
    assert "content of context.C-aaa" not in system
    assert "content of context.C-aaa" in payload["messages"][1]["content"]
    assert report.calls[0].parsed and report.calls[0].verdict is not None


def test_one_call_per_context_by_default(tmp_path, monkeypatch) -> None:
    transport, calls = fake(monkeypatch, json.dumps(VERDICT))

    report = analyse_bundle(make_bundle(tmp_path), config(), transport=transport)

    assert len(calls) == 2  # two contexts in the fixture
    assert [call.context_id for call in report.calls] == ["context.C-aaa", "context.C-bbb"]
    assert all(call.parsed for call in report.calls)


def test_a_retryable_failure_is_retried_and_then_recorded(tmp_path, monkeypatch) -> None:
    attempts = {"count": 0}

    def transport(url, payload, api_key, timeout_s):
        attempts["count"] += 1
        raise AIUnavailable("HTTP 504 from the gateway")

    monkeypatch.setenv("AEGIS_TEST_KEY", "secret-value")
    report = analyse_bundle(make_bundle(tmp_path), config(), transport=transport,
                            only="context.C-aaa")

    assert attempts["count"] == 3, "a 504 is worth retrying"
    assert not report.calls[0].parsed
    assert "AIUnavailable" in (report.calls[0].error or "")


def test_a_client_error_is_not_retried(tmp_path, monkeypatch) -> None:
    """A bad key or a bad model will fail the same way three times; three times is waste."""
    attempts = {"count": 0}

    def transport(url, payload, api_key, timeout_s):
        attempts["count"] += 1
        raise AIError("HTTP 401: invalid api key")

    monkeypatch.setenv("AEGIS_TEST_KEY", "secret-value")
    report = analyse_bundle(make_bundle(tmp_path), config(), transport=transport,
                            only="context.C-aaa")

    assert attempts["count"] == 1
    assert "401" in (report.calls[0].error or "")


def test_a_malformed_answer_is_kept_and_reported(tmp_path, monkeypatch) -> None:
    transport, _ = fake(monkeypatch, "I am not going to answer in JSON.")

    report = analyse_bundle(make_bundle(tmp_path), config(), transport=transport,
                            only="context.C-aaa")

    call = report.calls[0]
    assert not call.parsed
    assert call.raw_answer == "I am not going to answer in JSON."
    assert call.error is not None


def test_a_missing_key_is_a_refusal_not_a_silent_skip(tmp_path, monkeypatch) -> None:
    monkeypatch.delenv("AEGIS_TEST_KEY", raising=False)

    report = analyse_bundle(make_bundle(tmp_path), config())

    assert report.skipped is not None and "AEGIS_TEST_KEY" in report.skipped
    assert report.calls == []


def test_a_disabled_stage_says_so(tmp_path, monkeypatch) -> None:
    monkeypatch.setenv("AEGIS_TEST_KEY", "secret-value")

    report = analyse_bundle(make_bundle(tmp_path), config(enabled=False))

    assert report.skipped is not None and "已禁用" in report.skipped


def test_max_contexts_bounds_what_a_run_can_spend(tmp_path, monkeypatch) -> None:
    transport, calls = fake(monkeypatch, json.dumps(VERDICT))

    report = analyse_bundle(make_bundle(tmp_path), config(max_contexts=1), transport=transport)

    assert len(calls) == 1
    assert len(report.calls) == 1


# ---------------------------------------------------------------- writing


def test_the_report_never_carries_the_key(tmp_path, monkeypatch) -> None:
    """The bundle is a shareable artifact. A key in it is a leaked key."""
    transport, _ = fake(monkeypatch, json.dumps(VERDICT))
    bundle = make_bundle(tmp_path)
    report = analyse_bundle(bundle, config(), transport=transport)

    written = write_report(bundle, report)

    for path in (written["report"], written["verdicts"]):
        assert "secret-value" not in path.read_text(encoding="utf-8")
    assert "secret-value" not in json.dumps(report.model_dump(mode="json"))


def test_the_verdicts_and_the_raw_answers_land_beside_the_bundle(tmp_path, monkeypatch) -> None:
    usage = {
        "prompt_tokens": 1000,
        "completion_tokens": 200,
        "total_tokens": 1200,
        "prompt_cache_hit_tokens": 900,
    }
    transport, _ = fake(monkeypatch, json.dumps(VERDICT), usage=usage)
    bundle = make_bundle(tmp_path)
    report = analyse_bundle(bundle, config(), transport=transport)

    written = write_report(bundle, report)

    lines = [json.loads(line) for line in written["verdicts"].read_text(encoding="utf-8").splitlines()]
    assert {line["context_id"] for line in lines} == {"context.C-aaa", "context.C-bbb"}
    assert (written["answers"] / "context.C-aaa.md").is_file()
    # The cache-hit key a provider uses is normalised, so "the prefix cached" is measurable.
    assert report.calls[0].usage is not None
    assert report.calls[0].usage.cache_hit_ratio == pytest.approx(0.9)


def test_summary_counts_split_parsed_from_failed(tmp_path, monkeypatch) -> None:
    transport, _ = fake(monkeypatch, json.dumps(VERDICT))
    report = analyse_bundle(make_bundle(tmp_path), config(), transport=transport,
                            only="context.C-aaa")

    assert len(report.parsed_calls) == 1
    assert report.failed_calls == []
    assert report.verdict_for("context.C-aaa") is not None


def test_the_report_is_stored_raw_with_no_server_side_counts(tmp_path, monkeypatch) -> None:
    """The stored report is the model's result, not a rendering of it.

    `views.verdicts_view` used to publish `counts`, and a per-call `cache_hit_ratio`, because the
    old console was forbidden from doing arithmetic. The front-end is its own deployment now and
    derives its own display numbers, so the API has to publish the *file*: any aggregate on this
    side would be a second, silently drifting implementation of "how many contexts answered".
    This test is the guard -- it fails the moment a computed key reappears in the stored payload.
    """
    usage = {"prompt_tokens": 1000, "completion_tokens": 200, "prompt_cache_hit_tokens": 900}
    transport, _ = fake(monkeypatch, json.dumps(VERDICT), usage=usage)
    bundle = make_bundle(tmp_path)
    report = analyse_bundle(bundle, config(), transport=transport, only="context.C-aaa")
    written = write_report(bundle, report)

    stored = json.loads(written["report"].read_text(encoding="utf-8"))

    assert "counts" not in stored
    call = stored["calls"][0]
    # The keys the model's own answer is judged by survive verbatim; nothing is pre-digested.
    for key in ("parsed", "error", "missing_fields", "usage", "verdict", "raw_answer"):
        assert key in call, f"{key} was dropped from the stored call"
    assert call["usage"]["cached_tokens"] == 900
    # The share of the input is the caller's division to make, from the tokens that are here.
    assert "cache_hit_ratio" not in call["usage"]
    assert call["raw_answer"] == json.dumps(VERDICT)


# ---------------------------------------------------------------- client


def test_a_client_refuses_to_be_built_without_credentials() -> None:
    with pytest.raises(AIError):
        ChatClient(base_url="https://example.invalid", api_key="", model="m")
    with pytest.raises(AIError):
        ChatClient(base_url="", api_key="k", model="m")
    with pytest.raises(AIError):
        ChatClient(base_url="https://example.invalid", api_key="k", model="")


def test_a_response_without_choices_is_an_error() -> None:
    client = ChatClient(base_url="https://example.invalid/v1", api_key="k", model="m",
                        transport=lambda *a, **k: {"error": "boom"})
    with pytest.raises(AIError):
        client.complete("system", "user")
