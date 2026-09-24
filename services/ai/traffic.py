"""每一次模型往返的元数据，一行一条，落在所有容器都读得到的地方。

为什么不是网关那个内存环形缓冲：模型调用不发生在网关里。三条路径都会说话 —— 网关的同步
路径、worker 的 `ai_fanout`、以及 worker 里跑的审计（每个 agent 每一步一次往返）—— 而
`app/api/traffic.py` 那个 ring 只记得住网关自己进程内的请求，重启即空。要看"我们在跟模型聊
什么"，需要一个三个容器共享、且活过重启的落点，那就是 `work_dir`（网关、worker、extract 都
以同一路径挂载它），格式与运行轨迹一致：追加写 JSONL。

三条规矩：

* **只记元数据，不记正文。** prompt 里有源码，回答里有模型输出。把它们写进一个会被浏览器读
  的文件，等于把源码复制到另一个地方并扩大了它的可见范围 —— 而正文本来就有更合适的家：审计
  的对话在 `trail.jsonl`，快速研判的原始回答在分析包的 `ai/answers/`。这里回答的是"多少次、
  多久、多少 token、成没成、谁在问"。
* **记录失败绝不能让调用失败。** 和轨迹一样：写日志出问题（磁盘满、权限）是运维问题，不是
  模型问题，`record` 自己吞掉异常并记一条警告。
* **文件有上限。** 一个跑得多的部署会堆到几百 MB，所以超过 `MAX_BYTES` 就轮换成 `.1`。只保留
  一代是有意的：这是"最近发生了什么"，不是审计账本 —— 真正的账本在任务记录和运行轨迹里。
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from aegis_core.logging import get_logger

log = get_logger(__name__)

#: The file's name inside the shared work directory. Named here so the writer, the reader and the
#: API agree without repeating the literal.
AI_TRAFFIC_NAME = "ai-traffic.jsonl"

#: Where the recorder puts it: `<work_dir>/ai-traffic.jsonl`.
#:
#: `work_dir` and not `output_dir`: this is a runtime fact about *this deployment*, not a property
#: of any analysis bundle. Putting it under a bundle would make it disappear when the bundle is
#: cleaned up and appear once per bundle when several exist.
def traffic_path() -> Path:
    from aegis_core.config import get_settings

    return get_settings().work_dir / AI_TRAFFIC_NAME


#: Rotate at 4 MiB. At ~500 bytes a line that is roughly 8000 calls, which is more than a week of
#: normal use and still small enough for the API route to read and page in one go.
MAX_BYTES = 4 * 1024 * 1024

#: How much of a caller label / error text is kept. Long enough to identify, short enough that a
#: stack trace cannot turn one line into a megabyte.
TEXT_LIMIT = 300

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _clip(value: Any, limit: int = TEXT_LIMIT) -> str:
    text = " ".join(str(value or "").split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _rotate_if_needed(path: Path) -> None:
    """Keep one previous generation. Cheap stat, and the caller already holds the lock."""
    try:
        if path.is_file() and path.stat().st_size > MAX_BYTES:
            path.replace(path.with_suffix(path.suffix + ".1"))
    except OSError:  # pragma: no cover - a rotation that fails must not stop recording
        pass


def record(
    *,
    caller: str,
    kind: str,
    model: str,
    endpoint: str,
    attempt: int,
    ok: bool,
    duration_ms: float,
    prompt_chars: int = 0,
    answer_chars: int = 0,
    usage: Any = None,
    finish_reason: str | None = None,
    error: str | None = None,
    path: Path | None = None,
) -> dict | None:
    """Append one model round trip. Returns the row, or None if recording failed.

    `attempt` is the retry number *for this call*, not a request counter: the two retry wrappers
    (`services/ai/runner.call_with_retries` and `services/harness/react._complete_with_retries`)
    know it, `ChatClient` does not, and a retry is exactly the thing a reader wants to see -- one
    call that took three tries is one row per try, each with its own duration and error.
    """
    row = {
        "at": _now(),
        "caller": _clip(caller, 120),
        "kind": kind,
        "model": model,
        "endpoint": endpoint,
        "attempt": attempt,
        "ok": ok,
        "duration_ms": round(float(duration_ms)),
        "prompt_chars": int(prompt_chars),
        "answer_chars": int(answer_chars),
        "prompt_tokens": getattr(usage, "prompt_tokens", None) if usage is not None else None,
        "completion_tokens": getattr(usage, "completion_tokens", None) if usage is not None else None,
        "cached_tokens": getattr(usage, "cached_tokens", None) if usage is not None else None,
        "finish_reason": _clip(finish_reason, 80) if finish_reason else None,
        "error": _clip(error) if error else None,
    }
    target = path or traffic_path()
    try:
        with _lock:
            target.parent.mkdir(parents=True, exist_ok=True)
            _rotate_if_needed(target)
            # One `write` of one short line, appended with O_APPEND: several containers write this
            # file and a line under PIPE_BUF is not interleaved with another process's.
            with target.open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        return row
    except Exception as exc:  # noqa: BLE001 - a broken log must not fail a model call
        log.warning("ai traffic: could not record call (%s: %s)", type(exc).__name__, exc)
        return None


def read_tail(*, limit: int = 200, path: Path | None = None) -> dict:
    """The newest `limit` rows, newest first, plus how many there are in total.

    Newest first because that is the order a reader wants a log in, and doing the reversal here
    means the screen does not have to. `damaged` counts lines that do not parse, for the same
    reason the run trail does: a process killed mid-write leaves half a line, and refusing to show
    the other 5000 because of it would be the wrong trade.
    """
    target = path or traffic_path()
    if not target.is_file():
        return {"entries": [], "count": 0, "damaged": 0, "path": str(target), "exists": False}
    rows: list[dict] = []
    damaged = 0
    try:
        with target.open("r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                except json.JSONDecodeError:
                    damaged += 1
                    continue
                if isinstance(row, dict):
                    rows.append(row)
                else:
                    damaged += 1
    except OSError as exc:  # pragma: no cover - unreadable file
        return {"entries": [], "count": 0, "damaged": 0, "path": str(target), "exists": False,
                "error": str(exc)}
    count = len(rows)
    return {
        "entries": list(reversed(rows[-limit:])),
        "count": count,
        "damaged": damaged,
        "path": str(target),
        "exists": True,
        "size_bytes": target.stat().st_size if target.is_file() else 0,
    }


def note() -> str:
    """What a reader must know to read this table correctly. Sent with the payload, shown verbatim."""
    return (
        f"模型调用的元数据，追加写 JSONL（{AI_TRAFFIC_NAME}），三个容器共享同一份，重启不丢；"
        f"只记次数、耗时、token 与错误，不记 prompt 与回答正文。"
        f"超过 {MAX_BYTES // (1024 * 1024)} MB 时轮换为 .1，只保留一代。"
    )


def clear(path: Path | None = None) -> None:
    """Remove the log, both generations. For tests and for an operator starting from zero."""
    target = path or traffic_path()
    for candidate in (target, target.with_suffix(target.suffix + ".1")):
        try:
            os.remove(candidate)
        except FileNotFoundError:
            continue
        except OSError as exc:  # pragma: no cover
            log.warning("ai traffic: could not remove %s (%s)", candidate, exc)
