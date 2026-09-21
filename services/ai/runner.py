"""The fan-out: one call per analysis context, and a report that survives every failure.

Two rules decide the shape of this file.

1. **A model failure is a result, not an exception.** A bundle with no verdicts is still a
   bundle; a bundle that vanished because the endpoint returned 504 is a lost run. So every call
   is recorded -- parsed or not, with the raw answer -- and the runner returns a report either
   way.
2. **Nothing here may write a credential.** The bundle is a shareable artifact, so the report
   carries the model and the endpoint, never the key, and what is stored is the model's own words
   rather than the request that produced them.
"""

from __future__ import annotations

import json
import os
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

from aegis_contracts.ai import AICall, AIReport
from aegis_contracts.domain import PromptBlock
from aegis_core.config import AIConfig
from aegis_core.logging import get_logger
from services.ai import traffic
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

log = get_logger(__name__)

#: How many times a *retryable* failure (unreachable, 5xx, 429) is attempted.
MAX_ATTEMPTS = 3


class AINotConfigured(RuntimeError):
    """The stage was asked to run without the credentials or the endpoint to run with."""


def client_from(config: AIConfig, *, transport=None) -> ChatClient:
    """Build the client from configuration, reading the key from the named environment variable.

    A missing key is a refusal: calling anyway, or skipping silently, would both look like a
    successful run that produced no verdicts.
    """
    api_key = os.environ.get(config.api_key_env, "").strip()
    if not api_key:
        raise AINotConfigured(
            f"{config.api_key_env} 未设置：拒绝在没有密钥的情况下调用模型"
        )
    extra = {"transport": transport} if transport is not None else {}
    return ChatClient(
        base_url=config.base_url,
        api_key=api_key,
        model=config.model,
        temperature=config.temperature,
        timeout_s=config.timeout_s,
        max_tokens=config.max_tokens,
        **extra,
    )


def call_with_retries(client: ChatClient, context_id: str | None, system: str, user: str) -> AICall:
    """One logical call: retried while the failure is retryable, recorded whatever happens.

    Every attempt is written to the model traffic log as well as to the returned `AICall`, and the
    two are deliberately different records: `AICall` is the *verdict's* provenance and lands inside
    the bundle, while the traffic row is a deployment fact ("this process talked to that endpoint
    for 12 s and got a 504 first") that outlives the bundle and covers the harness's calls too.
    """
    started = time.monotonic()
    attempt = 0
    while True:
        attempt += 1
        attempt_started = time.monotonic()
        try:
            result = client.complete(system, user)
        except (AIUnavailable, AIError) as exc:
            traffic.record(
                caller=context_id or "bundle",
                kind="fanout",
                model=client.model,
                endpoint=client.url,
                attempt=attempt,
                ok=False,
                duration_ms=(time.monotonic() - attempt_started) * 1000,
                prompt_chars=len(system) + len(user),
                error=f"{type(exc).__name__}: {exc}",
            )
            if isinstance(exc, AIUnavailable) and attempt < MAX_ATTEMPTS:
                log.warning("ai: call for %s failed (%s); retrying", context_id, exc)
                time.sleep(min(2.0 * attempt, 8.0))
                continue
            return AICall(
                context_id=context_id,
                model=client.model,
                endpoint=client.url,
                elapsed_s=time.monotonic() - started,
                parsed=False,
                error=f"{type(exc).__name__}: {exc}",
            )
        break

    traffic.record(
        caller=context_id or "bundle",
        kind="fanout",
        model=result.model,
        endpoint=client.url,
        attempt=attempt,
        ok=True,
        duration_ms=(time.monotonic() - attempt_started) * 1000,
        prompt_chars=len(system) + len(user),
        answer_chars=len(result.text or ""),
        usage=result.usage,
    )
    verdict, error, missing = parse_verdict(result.text)
    return AICall(
        context_id=context_id,
        model=result.model,
        endpoint=client.url,
        elapsed_s=time.monotonic() - started,
        usage=result.usage,
        parsed=verdict is not None,
        error=error,
        missing_fields=missing,
        verdict=verdict,
        raw_answer=result.text,
    )


def write_report(bundle: Path, report: AIReport) -> dict[str, Path]:
    """Persist the report, the per-context verdicts and the raw answers beside the bundle.

    Layout, chosen so nothing has to be re-derived to be read:

        ai/report.json            the whole report, including the failures
        ai/verdicts.jsonl         one verdict per line, one per context
        ai/answers/<context>.md   the model's own words, verbatim
    """
    ai_dir = bundle / "ai"
    answers = ai_dir / "answers"
    answers.mkdir(parents=True, exist_ok=True)

    lines = []
    for call in report.calls:
        name = (call.context_id or "bundle").replace("/", "_")
        (answers / f"{name}.md").write_text(call.raw_answer, encoding="utf-8")
        if call.verdict is not None:
            lines.append(json.dumps(
                {
                    "context_id": call.context_id,
                    "verdict": call.verdict.model_dump(mode="json"),
                    "missing_fields": call.missing_fields,
                },
                ensure_ascii=False,
            ))
    verdicts = ai_dir / "verdicts.jsonl"
    verdicts.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    report_path = ai_dir / "report.json"
    report_path.write_text(report.model_dump_json(indent=2), encoding="utf-8")
    return {"verdicts": verdicts, "report": report_path, "answers": answers}


def _skipped(report: AIReport, reason: str) -> AIReport:
    report.skipped = reason
    report.finished_at = datetime.now(timezone.utc)
    return report


def analyse_bundle(
    bundle: Path,
    config: AIConfig,
    *,
    client: ChatClient | None = None,
    transport=None,
    only: str | None = None,
    whole_bundle: bool = False,
) -> AIReport:
    """Run the AI stage over one finished bundle.

    `only` narrows to a single context; `whole_bundle` sends the volatile remainder in one
    message instead of one call per context. The default is the fan-out: one call per context,
    which is what keeps a large bundle from arriving as a single unreadable wall.
    """
    report = AIReport(bundle_id=bundle.name, started_at=datetime.now(timezone.utc))

    if not config.enabled and client is None:
        return _skipped(report, "AI 阶段已禁用（AEGIS_AI__ENABLED 为 false）")

    try:
        blocks = read_blocks(bundle)
    except BlocksUnavailable as exc:
        return _skipped(report, str(exc))

    prefix_ids = read_prefix_ids(bundle)
    system = system_text(blocks, prefix_ids)
    volatile: list[PromptBlock] = volatile_blocks(blocks, prefix_ids)
    contexts = context_ids(volatile)
    if not contexts and not whole_bundle:
        return _skipped(report, "分析包没有可供研判的上下文块")

    try:
        active = client or client_from(config, transport=transport)
    except AINotConfigured as exc:
        return _skipped(report, str(exc))
    except AIError as exc:
        return _skipped(report, f"无法构建模型客户端：{exc}")

    report.model = active.model
    report.endpoint = active.url

    if whole_bundle:
        chosen: list[str | None] = [None]
    elif only is not None:
        chosen = [only]
    else:
        chosen = list(contexts[: config.max_contexts])

    def one(context_id: str | None) -> AICall:
        return call_with_retries(
            active, context_id, system, user_text(bundle.name, volatile, only=context_id)
        )

    # `map` preserves order, so `calls` lines up with the context order in the bundle no matter
    # how the threads interleave -- a report whose order depends on scheduling is not a report.
    with ThreadPoolExecutor(max_workers=max(1, config.concurrency)) as pool:
        report.calls = list(pool.map(one, chosen))
    report.finished_at = datetime.now(timezone.utc)
    return report
