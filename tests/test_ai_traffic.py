"""模型调用的流量记录：写、读、轮换，以及"记录失败不能让调用失败"。

这一层被两条路径共用（`services/ai/runner.call_with_retries` 与
`services/harness/react._complete_with_retries`），所以这里的每条断言都同时是那两条路径的契约。
"""

from __future__ import annotations

import json
from pathlib import Path

from aegis_contracts.ai import TokenUsage
from services.ai import runner, traffic


def _usage(prompt: int = 100, completion: int = 20, cached: int = 40) -> TokenUsage:
    return TokenUsage(prompt_tokens=prompt, completion_tokens=completion, cached_tokens=cached)


def test_a_recorded_call_says_who_asked_and_what_it_cost(tmp_path: Path) -> None:
    """一行里必须能读出"谁在问、问了多久、花了多少 token、成没成" —— 这是这张表的全部用途。"""
    path = tmp_path / "ai-traffic.jsonl"
    row = traffic.record(
        caller="discovery:scope-web",
        kind="harness",
        model="m",
        endpoint="https://example.invalid/chat/completions",
        attempt=2,
        ok=True,
        duration_ms=1234.6,
        prompt_chars=5000,
        answer_chars=120,
        usage=_usage(),
        path=path,
    )

    assert row is not None
    stored = json.loads(path.read_text(encoding="utf-8").strip())
    assert stored["caller"] == "discovery:scope-web"
    assert stored["attempt"] == 2, "第几次尝试是重试分析的关键，不能被抹平"
    assert stored["duration_ms"] == 1235
    assert stored["prompt_tokens"] == 100 and stored["cached_tokens"] == 40
    assert stored["ok"] is True and stored["error"] is None


def test_the_log_never_carries_the_prompt_or_the_answer(tmp_path: Path) -> None:
    """只记元数据。prompt 里有源码，回答里有模型输出，它们有更合适的家。"""
    path = tmp_path / "ai-traffic.jsonl"
    traffic.record(
        caller="context.C-1", kind="fanout", model="m", endpoint="e", attempt=1, ok=True,
        duration_ms=10, prompt_chars=999, answer_chars=12, path=path,
    )
    text = path.read_text(encoding="utf-8")

    assert "prompt_chars" in text and "answer_chars" in text
    # 只有长度，没有内容：连字段名都不该出现"prompt"这种会诱导人往里塞正文的名字。
    assert "prompt\":" not in text and "answer\":" not in text


def test_a_failure_is_recorded_with_its_reason(tmp_path: Path) -> None:
    path = tmp_path / "ai-traffic.jsonl"
    traffic.record(
        caller="harness", kind="harness", model="m", endpoint="e", attempt=3, ok=False,
        duration_ms=8000, prompt_chars=10, error="AIUnavailable: HTTP 504", path=path,
    )
    row = traffic.read_tail(path=path)["entries"][0]
    assert row["ok"] is False
    assert "504" in row["error"]


def test_recording_failure_does_not_raise(tmp_path: Path) -> None:
    """磁盘满、权限不对是运维问题，不是模型问题：记录写不进去也不能让调用失败。"""
    directory = tmp_path / "not-a-file"
    directory.mkdir()
    # 路径指向一个目录：open("a") 会抛 IsADirectoryError。
    assert traffic.record(
        caller="c", kind="harness", model="m", endpoint="e", attempt=1, ok=True,
        duration_ms=1, path=directory,
    ) is None


def test_the_tail_is_newest_first_and_counts_everything(tmp_path: Path) -> None:
    path = tmp_path / "ai-traffic.jsonl"
    for index in range(5):
        traffic.record(
            caller=f"c{index}", kind="harness", model="m", endpoint="e", attempt=1, ok=True,
            duration_ms=index, path=path,
        )
    page = traffic.read_tail(limit=2, path=path)

    assert [row["caller"] for row in page["entries"]] == ["c4", "c3"]
    assert page["count"] == 5, "总数是文件里的事实，与这一页取多少无关"
    assert page["exists"] is True


def test_a_torn_line_is_counted_and_skipped(tmp_path: Path) -> None:
    path = tmp_path / "ai-traffic.jsonl"
    traffic.record(caller="c1", kind="harness", model="m", endpoint="e", attempt=1, ok=True,
                   duration_ms=1, path=path)
    with path.open("a", encoding="utf-8") as handle:
        handle.write('{"caller": "c2", "kin')
    page = traffic.read_tail(path=path)

    assert [row["caller"] for row in page["entries"]] == ["c1"]
    assert page["damaged"] == 1


def test_missing_file_is_an_empty_page_not_an_error(tmp_path: Path) -> None:
    page = traffic.read_tail(path=tmp_path / "nope.jsonl")
    assert page["entries"] == [] and page["exists"] is False and page["count"] == 0


def test_the_file_rotates_so_it_cannot_grow_forever(tmp_path: Path, monkeypatch) -> None:
    """这是"最近发生了什么"，不是账本：留一代就够，否则一个长期部署会堆到几百 MB。"""
    path = tmp_path / "ai-traffic.jsonl"
    monkeypatch.setattr(traffic, "MAX_BYTES", 200)
    traffic.record(caller="a" * 120, kind="harness", model="m", endpoint="e", attempt=1, ok=True,
                   duration_ms=1, path=path)
    traffic.record(caller="b" * 120, kind="harness", model="m", endpoint="e", attempt=1, ok=True,
                   duration_ms=1, path=path)

    assert path.is_file()
    previous = path.with_suffix(path.suffix + ".1")
    assert previous.is_file(), "超过上限时第一代被保留为 .1"
    assert "a" * 120 not in path.read_text(encoding="utf-8"), "新文件里只有轮换后的记录"


def test_the_route_serves_the_tail_with_its_own_note(tmp_path: Path, monkeypatch) -> None:
    """两块流量各有各的保留策略，note 必须说清是哪一种 —— 否则读者会把网关那块当成全部。"""
    from fastapi.testclient import TestClient

    from aegis_core.config import get_settings
    from app.main import create_app

    monkeypatch.setenv("AEGIS_WORK_DIR", str(tmp_path))
    get_settings.cache_clear()
    try:
        traffic.record(caller="discovery:s1", kind="harness", model="m", endpoint="e", attempt=1,
                       ok=True, duration_ms=42, prompt_chars=7, answer_chars=3)
        with TestClient(create_app()) as client:
            body = client.get("/v1/ai/traffic", params={"limit": 10}).json()
    finally:
        get_settings.cache_clear()

    assert body["count"] == 1
    assert body["entries"][0]["caller"] == "discovery:s1"
    assert "不记" in body["note"] and "重启不丢" in body["note"]


def test_the_fanout_records_every_attempt_including_the_retry_that_succeeded(
    tmp_path: Path, monkeypatch
) -> None:
    """重试的那次是这张表最该看见的东西：一次调用花掉三次往返，不能只留最后一行的成功。"""

    class FlakyClient:
        model = "fake-model"
        url = "https://example.invalid/chat/completions"

        def __init__(self) -> None:
            self.calls = 0

        def complete(self, system: str, user: str):
            from services.ai.client import AIUnavailable, ChatResult

            self.calls += 1
            if self.calls < 2:
                raise AIUnavailable("HTTP 504")
            # A complete verdict, so the retry is shown to have produced a *usable* answer: the
            # parse contract is tested in `test_ai.py`, and a half-filled object here would make
            # this test fail for a reason that has nothing to do with the traffic log.
            return ChatResult(
                text=json.dumps(
                    {
                        "verdict": "true_positive",
                        "severity": "high",
                        "confidence": 0.7,
                        "severity_qualifier": "externally reachable",
                        "reachability": "GET /users",
                        "chain": ["controller", "dao"],
                        "data_flow": "sort -> query",
                        "evidence": ["ItemMapper.xml:36"],
                        "missing": [],
                        "fix": "parameterise",
                    }
                ),
                model=self.model,
                raw={},
            )

    monkeypatch.setattr(runner.time, "sleep", lambda _seconds: None)
    path = tmp_path / "ai-traffic.jsonl"
    monkeypatch.setattr(traffic, "traffic_path", lambda: path)

    call = runner.call_with_retries(FlakyClient(), "context.C-1", "sys", "usr")

    assert call.parsed is True
    rows = traffic.read_tail(path=path)["entries"]
    assert [row["attempt"] for row in rows] == [2, 1], "最新在前：先是成功那次，再是 504 那次"
    assert rows[0]["ok"] is True and rows[1]["ok"] is False
    assert rows[1]["caller"] == "context.C-1"
