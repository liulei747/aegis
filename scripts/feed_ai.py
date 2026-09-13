#!/usr/bin/env python
"""Feed a finished bundle to the model and store what comes back.

This is a thin CLI over `services.ai`: the stage itself lives in the service so the queue worker
and this script cannot drift into two implementations of the same contract. What the script adds
is host-side conveniences -- picking the newest bundle, a dry run, and a `.env` fallback for
credentials (the service reads the environment only, because a container is not a checkout).

It reads the bundle the way the contract says to read it -- `ai/blocks.jsonl` plus
`ai/blocks_meta.json`, never by re-parsing `prompt.md` -- and sends exactly two messages:

    system   : everything up to and including `method_catalog` (the reusable prefix)
    user     : the volatile remainder (fan-out plan, this bundle's contexts, run notes)

The split is the whole point of the layout: the prefix holds still across bundles from the same
workspace, so it is the part a provider can cache, and it is also the part that carries the
instructions. Nothing is rewritten or summarised on the way out.

    python scripts/feed_ai.py --bundle B-909bbbe468 --dry-run   # show the plan, send nothing
    python scripts/feed_ai.py --bundle B-909bbbe468             # one call per context
    python scripts/feed_ai.py --bundle B-909bbbe468 --whole     # one call for the whole bundle

Credentials come from the environment, falling back to the repo `.env`: `API_URL`, `API_KEY`,
`MODEL` (or the `AEGIS_AI__*` names). A missing key is a refusal, never a silent skip.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

sys.path.insert(0, str(ROOT))

from aegis_contracts.ai import REQUIRED_VERDICT_FIELDS  # noqa: E402
from aegis_core.config import AIConfig  # noqa: E402
from services.ai import runner  # noqa: E402
from services.ai.blocks import (  # noqa: E402
    BlocksUnavailable,
    context_ids,
    read_blocks,
    read_prefix_ids,
    system_text,
    user_text,
    volatile_blocks,
)


def load_env(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip()
    return values


def config_from(args: argparse.Namespace) -> AIConfig:
    """The stage's config, with this script's `.env` fallback applied to the *key*.

    The service reads the key from the environment by name and nothing else. A checkout is a
    different situation from a container, so the fallback lives here: this is the one place that
    reads `.env`, and it puts the value where the service expects to find it.
    """
    dotenv = load_env(ROOT / ".env")

    def pick(name: str, default: str = "") -> str:
        return (os.environ.get(name) or dotenv.get(name) or default).strip()

    key_name = pick("AEGIS_AI__API_KEY_ENV", "API_KEY")
    if not os.environ.get(key_name) and dotenv.get(key_name):
        os.environ[key_name] = dotenv[key_name]

    return AIConfig(
        enabled=True,
        base_url=pick("AEGIS_AI__BASE_URL", pick("API_URL")),
        model=pick("AEGIS_AI__MODEL", pick("MODEL")),
        api_key_env=key_name,
        temperature=args.temperature,
        timeout_s=args.timeout,
        concurrency=args.concurrency,
    )


def show_plan(bundle: Path, targets: list[str | None]) -> None:
    blocks = read_blocks(bundle)
    prefix_ids = read_prefix_ids(bundle)
    system = system_text(blocks, prefix_ids)
    volatile = volatile_blocks(blocks, prefix_ids)
    print(f"blocks      {len(blocks)} ({len(prefix_ids)} in the reusable prefix)")
    print(f"contexts    {', '.join(context_ids(volatile)) or '(none)'}")
    print(f"system msg  {len(system):,} chars (prefix: {', '.join(prefix_ids)})")
    for target in targets:
        message = user_text(bundle.name, volatile, only=target)
        print(f"\n--- would send (context={target or 'ALL'}) ---")
        print(f"  system: {len(system):,} chars")
        print(f"  user  : {len(message):,} chars")
        print("\n  --- system, first 600 chars ---")
        print("  " + system[:600].replace("\n", "\n  "))
        print("\n  --- user, first 900 chars ---")
        print("  " + message[:900].replace("\n", "\n  "))
        print("\n  --- user, last 400 chars ---")
        print("  " + message[-400:].replace("\n", "\n  "))
    print("\n(dry run: nothing was sent)")


def report_call(index: int, total: int, call) -> None:
    label = call.context_id or "ALL"
    print(f"\n=== context {index}/{total}: {label} ===")
    print(f"  elapsed      : {call.elapsed_s:.1f}s")
    if call.usage:
        cache = call.usage.cache_hit_ratio
        print(f"  tokens       : prompt={call.usage.prompt_tokens} "
              f"completion={call.usage.completion_tokens} "
              f"cached={call.usage.cached_tokens}"
              + (f" ({cache:.0%} of input)" if cache is not None else ""))
    if call.verdict is None:
        print(f"  NO VERDICT   : {call.error}")
        print("  raw answer kept in ai/answers/")
        return
    for field in REQUIRED_VERDICT_FIELDS:
        value = getattr(call.verdict, field, None)
        shown = str(value)
        if len(shown) > 220:
            shown = shown[:217] + "..."
        print(f"    {field:<13}: {shown}")
    if call.missing_fields:
        print(f"    MISSING     : {', '.join(call.missing_fields)}")


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--bundle", help="bundle id or path (default: newest under var/packages)")
    parser.add_argument("--context", help="only this context id")
    parser.add_argument("--whole", action="store_true", help="one call for the whole bundle")
    parser.add_argument("--dry-run", action="store_true", help="assemble and show, send nothing")
    parser.add_argument("--temperature", type=float, default=0.0)
    parser.add_argument("--timeout", type=float, default=180.0)
    parser.add_argument(
        "--concurrency", type=int, default=1,
        help="calls in flight at once (default 1: six sequential calls answered 6/6 where six "
             "concurrent ones answered 3/6 behind a gateway with a ~60s ceiling)",
    )
    args = parser.parse_args(argv)

    packages = ROOT / "var" / "packages"
    if args.bundle:
        candidate = Path(args.bundle)
        bundle = candidate if candidate.is_dir() else packages / args.bundle
    else:
        if not packages.is_dir():
            raise SystemExit("no var/packages directory: run `python scripts/demo.py` first")
        candidates = sorted(
            (p for p in packages.iterdir() if p.is_dir() and (p / "ai").is_dir()),
            key=lambda p: p.stat().st_mtime,
        )
        if not candidates:
            raise SystemExit("no bundles with an ai/ directory: run `python scripts/demo.py` first")
        bundle = candidates[-1]
    if not bundle.is_dir():
        raise SystemExit(f"no such bundle: {bundle}")

    try:
        blocks = read_blocks(bundle)
    except BlocksUnavailable as exc:
        raise SystemExit(str(exc)) from exc
    volatile = volatile_blocks(blocks, read_prefix_ids(bundle))
    available = context_ids(volatile)

    print(f"bundle      {bundle.name}")
    if args.dry_run:
        targets: list[str | None] = [args.context] if args.context else (
            [None] if args.whole else list(available)
        )
        show_plan(bundle, targets)
        return 0

    config = config_from(args)
    if not config.base_url or not config.model:
        raise SystemExit("API_URL / MODEL are not set (environment or .env): refusing to guess")
    print(f"endpoint    {config.base_url.rstrip('/')}/chat/completions")
    print(f"model       {config.model}")
    print(f"concurrency {config.concurrency}")

    report = runner.analyse_bundle(
        bundle, config, only=args.context, whole_bundle=args.whole
    )
    if report.skipped:
        raise SystemExit(f"the AI stage did not run: {report.skipped}")

    written = runner.write_report(bundle, report)
    for index, call in enumerate(report.calls, start=1):
        report_call(index, len(report.calls), call)
    print(f"\nverdicts     {written['verdicts'].relative_to(ROOT)}")
    print(f"report       {written['report'].relative_to(ROOT)}")
    print(f"raw answers  {written['answers'].relative_to(ROOT)}")
    failed = report.failed_calls
    print(f"\n{len(report.parsed_calls)}/{len(report.calls)} context(s) produced a verdict")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
