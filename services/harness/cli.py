"""`python -m services.harness run --workspace <path>` -- the orchestration layer's entry point.

Two decisions shape this file.

**It refuses to start when the AI stage is not configured.** A harness that silently produces
nothing is the failure this prevents: without credentials or an endpoint, every agent would stop on
its first call, the report would say "no findings", and a reader would have no way to tell that from
a clean repository. The refusal names the environment variable that is missing, because that is the
one thing the operator has to change.

**`--dry-run` is the plumbing check.** It reads the workspace, derives scopes, scans for signals,
walks the coverage ledger and writes a report -- with no model calls and no tool calls. It works on
a checkout where nothing is configured, which is what makes it usable before spending tokens, and
it is why the coordinator must not need the tool layer to plan.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from aegis_core.logging import setup_logging
from services.harness import trail as trail_mod
from services.harness.budget import LIMIT_FIELDS, environment_limits
from services.harness.coordinator import HarnessConfig, HarnessCoordinator

#: Exit code for "the AI stage is not configured". Distinct from 1 so a script can tell a
#: misconfiguration apart from a run that failed.
EXIT_NOT_CONFIGURED = 2
EXIT_ERROR = 1


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m services.harness",
        description="Aegis 多智能体安全评审编排层",
    )
    parser.add_argument("--log-level", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    run = sub.add_parser("run", help="对一个工作区执行完整的编排流程")
    _run_arguments(run)

    plan = sub.add_parser("plan", help="只做确定性计划与覆盖率遍历（等价于 run --dry-run）")
    _run_arguments(plan)
    plan.set_defaults(dry_run=True)
    return parser


def _run_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", required=True, help="被评审的仓库路径")
    parser.add_argument("--out", default=None, help="输出目录（默认 <workspace>/var/harness）")
    parser.add_argument("--model", default=None, help="覆盖 AEGIS_AI__MODEL")
    parser.add_argument("--max-rounds", type=int, default=None, help="discovery→closure 的最大轮数")
    parser.add_argument("--max-scopes", type=int, default=None, help="Discovery 派发批次大小；不丢弃待办")
    for name, convert in LIMIT_FIELDS.items():
        parser.add_argument("--" + name.replace("_", "-"), type=convert, default=None)
    parser.add_argument(
        "--candidates-per-scope", type=int, default=None, help="每个 scope 最多记录多少候选"
    )
    parser.add_argument("--steps-per-agent", type=int, default=None, help="每个 agent 的最大步数")
    parser.add_argument("--concurrency", type=int, default=None, help="并发模型/agent 数")
    parser.add_argument(
        "--claim-batch-size",
        type=int,
        default=None,
        help=(
            "一次判定 run 最多处理几条不同的 claim（默认 1 = 一条一 run），验证与攻击路径共用。"
            "每条 claim 仍有自己的 verdict/confidence/reasons；"
            "需要污点路径的 claim 会以 needs_dataflow 退回单跑。"
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只做计划与确定性扫描：不调用模型、不调用工具",
    )
    parser.add_argument(
        "--worker-workspace",
        default=None,
        help=(
            "数据流 worker 看到的项目路径。宿主机跑时必须设置"
            "（容器内跑时 worker 自己就能看见 /data/projects/<name>，不需要设置）。"
            "缺省时读 AEGIS_DATAFLOW__WORKER_WORKSPACE。"
        ),
    )
    parser.add_argument("--json", action="store_true", help="以 JSON 输出运行摘要")


def _config(args: argparse.Namespace, settings) -> HarnessConfig:
    """Build the run's bounds from the defaults, the settings file, then the CLI.

    Order matters: an explicit flag must beat the environment, and the environment must beat the
    built-in default. Anything else makes `--max-rounds` occasionally do nothing.
    """
    config = HarnessConfig(
        dry_run=bool(args.dry_run),
        concurrency=int(settings.ai.concurrency),
        **environment_limits(),
    )
    if getattr(args, "max_rounds", None) is not None:
        config.max_rounds = max(1, args.max_rounds)
    if getattr(args, "max_scopes", None) is not None:
        config.max_scopes_per_round = max(1, args.max_scopes)
    if getattr(args, "candidates_per_scope", None) is not None:
        config.candidates_per_scope = max(1, args.candidates_per_scope)
    if getattr(args, "steps_per_agent", None) is not None:
        config.steps_per_agent = max(1, args.steps_per_agent)
    if getattr(args, "concurrency", None) is not None:
        config.concurrency = max(1, args.concurrency)
    if getattr(args, "claim_batch_size", None) is not None:
        config.claim_batch_size = max(1, args.claim_batch_size)
    for name in LIMIT_FIELDS:
        if getattr(args, name, None) is not None:
            setattr(config, name, getattr(args, name))
    return config


def _client_for(args: argparse.Namespace, settings):
    """The model client, or a refusal naming what is missing.

    The refusal is the point of this function. `AIConfig.enabled` false and a missing key are two
    different problems with two different fixes, so they produce two different messages.
    """
    from services.ai.runner import AINotConfigured, client_from

    if args.model:
        settings.ai.model = args.model
    if not settings.ai.enabled:
        return None, (
            "AI 阶段未启用，拒绝启动：请设置 AEGIS_AI__ENABLED=true、AEGIS_AI__BASE_URL 与 "
            "AEGIS_AI__MODEL 后重试（或使用 --dry-run 只做计划，不调用模型）。"
        )
    try:
        return client_from(settings.ai), None
    except AINotConfigured as exc:
        return None, (
            f"AI 阶段缺少凭据，拒绝启动：{exc}。"
            f"请设置环境变量 {settings.ai.api_key_env}（AEGIS_AI__API_KEY_ENV 指定的名字）。"
        )


def _worker_workspace(args: argparse.Namespace, settings) -> str:
    """Resolve the worker-side workspace path, without silently defaulting to the local one.

    The two paths genuinely differ: the worker fleet sees `/data/projects/<name>` while a host-side
    run sees the checkout. Sending the local path is a 404 the worker reports as "workspace not
    found", which is *not* a dataflow result -- and if that were read as an empty path, a real
    finding would look unreachable. So the CLI carries the mapping explicitly, reads it from
    `AEGIS_DATAFLOW__WORKER_WORKSPACE` when not given as a flag, and records the decision in the
    report notes so a missing mapping is visible rather than implied.
    """
    import os

    chosen = args.worker_workspace or os.environ.get("AEGIS_DATAFLOW__WORKER_WORKSPACE") or ""
    if chosen:
        settings.dataflow.worker_workspace = chosen
    return chosen


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    from aegis_core.config import get_settings

    settings = get_settings()
    if args.log_level:
        settings.log_level = args.log_level
    setup_logging(settings.log_level)

    workspace = Path(args.workspace).expanduser()
    if not workspace.is_dir():
        print(f"工作区不存在或不是目录：{workspace}", file=sys.stderr)
        return EXIT_ERROR
    workspace = workspace.resolve()

    config = _config(args, settings)
    client = None
    notes: list[str] = []
    if not config.dry_run:
        client, refusal = _client_for(args, settings)
        if refusal:
            print(refusal, file=sys.stderr)
            return EXIT_NOT_CONFIGURED
        mapped = _worker_workspace(args, settings)
        notes.append(
            f"dataflow worker 工作区映射：{mapped}（来自 --worker-workspace 或 "
            "AEGIS_DATAFLOW__WORKER_WORKSPACE）"
            if mapped
            else (
                "dataflow worker 工作区映射未设置：本次把工作区路径原样交给 worker。"
                "容器内运行时这是正确的——两个进程看到的是同一个挂载；"
                "但若在宿主机上运行（worker 只认容器侧路径），就必须用 --worker-workspace 或 "
                "AEGIS_DATAFLOW__WORKER_WORKSPACE 指定映射，否则 dataflow_verify 会如实报不可用。"
            )
        )
    else:
        notes.append("dry run：未调用任何模型，未调用任何工具。")

    out_dir = Path(args.out).expanduser().resolve() if args.out else workspace / "var" / "harness"
    coordinator = HarnessCoordinator(
        workspace=workspace,
        config=config,
        client=client,
        out_dir=out_dir,
    )
    coordinator.dataflow_notes.extend(notes)
    # The trail is attached unconditionally, including for a dry run: it is the only thing that
    # makes a long run watchable while it is happening, and the run directory is the coordinator's
    # own knowledge, so there is no path for the caller to get wrong.
    coordinator.attach_trail()
    try:
        result = coordinator.run()
    except KeyboardInterrupt:  # pragma: no cover - operator cancellation
        # The blackboard is still not written -- a half-finished ledger read as a finished one is
        # worse than no ledger -- but the trail is already on disk, so the work that was done is
        # still inspectable instead of gone.
        print(
            f"已中断：blackboard 不会写出本次未完成的状态；"
            f"已完成的部分见 {coordinator.run_dir / trail_mod.TRAIL_NAME}",
            file=sys.stderr,
        )
        return EXIT_ERROR

    payload = {
        "run_id": result.blackboard.run_id,
        "run_dir": str(result.run_dir),
        "trail": str(result.run_dir / trail_mod.TRAIL_NAME),
        "report": str(result.report_path) if result.report_path else None,
        "dry_run": result.dry_run,
        "closed": result.blackboard.closed,
        "rounds": result.blackboard.rounds_run,
        "scopes": len(result.blackboard.coverage),
        "candidates": len(result.blackboard.candidates),
        "verdicts": len(result.blackboard.verdicts),
        "findings": len(result.blackboard.findings),
        "agent_runs": len(result.blackboard.runs),
        "coverage": payload_coverage(result.blackboard),
        "closure_note": result.blackboard.closure_note,
        "notes": result.notes,
    }
    if args.json:
        print(json.dumps(payload, ensure_ascii=False, indent=2))
    else:
        print(_human(payload))
    if result.fatal:
        print(result.fatal, file=sys.stderr)
        return EXIT_ERROR
    return 0


def payload_coverage(blackboard) -> dict[str, int]:
    """How many scopes are in each state. Counted per state rather than per entry, so a scope that
    appears twice (it cannot, but a loaded blackboard might) is not double-counted."""
    counts: dict[str, int] = {}
    for entry in blackboard.coverage:
        key = entry.state.value
        counts[key] = counts.get(key, 0) + 1
    return counts


def _human(payload: dict) -> str:
    lines = [
        f"run_id       {payload['run_id']}",
        f"run_dir      {payload['run_dir']}",
        f"report       {payload['report']}",
        f"dry_run      {payload['dry_run']}",
        f"closed       {payload['closed']}",
        f"rounds       {payload['rounds']}",
        f"scopes       {payload['scopes']}  {payload['coverage']}",
        f"candidates   {payload['candidates']}",
        f"verdicts     {payload['verdicts']}",
        f"findings     {payload['findings']}",
        f"agent_runs   {payload['agent_runs']}",
    ]
    if payload["closure_note"]:
        lines.append(f"closure      {payload['closure_note']}")
    for note in payload["notes"]:
        lines.append(f"note         {note}")
    return "\n".join(lines)


if __name__ == "__main__":  # pragma: no cover - `python -m` uses __main__.py
    sys.exit(main())
