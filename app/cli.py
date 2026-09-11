"""CLI: the same pipeline the API serves, usable directly for review.

    python -m app.cli assemble --workspace ./workspace/target --rule-config p/default
    python -m app.cli assemble --workspace ./ws --sarif ./scan.sarif --no-lsp
    python -m app.cli probe --workspace ./ws
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys

from app.core.config import BudgetConfig, get_settings
from app.core.logging import setup_logging
from app.pipeline.assemble import AssemblyPipeline, PipelineRequest, ScanOnlyPipeline


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegis", description="Aegis bundle assembler")
    parser.add_argument("--log-level", default=None)
    sub = parser.add_subparsers(dest="command", required=True)

    assemble = sub.add_parser("assemble", help="scan (or read SARIF) and build a bundle")
    _common(assemble)
    assemble.add_argument("--sarif", default=None, help="use an existing SARIF instead of scanning")
    assemble.add_argument("--rule", action="append", default=[], help="repeatable --rule")
    assemble.add_argument("--rule-config", default=None, help="opengrep --config value")
    assemble.add_argument("--include", action="append", default=[])
    assemble.add_argument("--exclude", action="append", default=[])
    assemble.add_argument("--max-findings", type=int, default=None)
    assemble.add_argument("--no-lsp", action="store_true", help="syntax-only degraded mode")
    assemble.add_argument("--max-depth", type=int, default=None)
    assemble.add_argument("--max-nodes", type=int, default=None)
    assemble.add_argument("--max-contexts", type=int, default=None)
    assemble.add_argument("--name", default=None, help="explicit bundle id")

    scan = sub.add_parser("scan", help="run only the static scanner")
    _common(scan)
    scan.add_argument("--rule", action="append", default=[])
    scan.add_argument("--rule-config", default=None)

    probe = sub.add_parser("probe", help="report LSP servers usable for a workspace")
    _common(probe)
    return parser


def _common(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--workspace", required=True, help="repository path to analyse")
    parser.add_argument("--json", action="store_true", help="machine-readable output")


def _budget(args: argparse.Namespace) -> BudgetConfig:
    base = get_settings().budget
    updates = {}
    if getattr(args, "max_depth", None) is not None:
        updates["max_depth"] = args.max_depth
    if getattr(args, "max_nodes", None) is not None:
        updates["max_nodes"] = args.max_nodes
    if getattr(args, "max_contexts", None) is not None:
        updates["max_contexts"] = args.max_contexts
    return base.model_copy(update=updates) if updates else base


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    settings = get_settings()
    if args.log_level:
        settings.log_level = args.log_level
    setup_logging(settings.log_level)
    workspace = settings.workspace_root if args.workspace == "." else None
    from pathlib import Path

    workspace_path = Path(args.workspace).resolve() if workspace is None else workspace

    if args.command == "assemble":
        pipeline = AssemblyPipeline(settings)
        result = asyncio.run(
            pipeline.run(
                PipelineRequest(
                    workspace=workspace_path,
                    sarif_path=Path(args.sarif).resolve() if args.sarif else None,
                    rules=args.rule,
                    rule_config=args.rule_config,
                    include_globs=args.include,
                    exclude_globs=args.exclude,
                    budget=_budget(args),
                    max_findings=args.max_findings,
                    lsp=not args.no_lsp,
                    package_name=args.name,
                )
            )
        )
        assert result.bundle is not None
        payload = {
            "bundle_id": result.bundle.manifest.bundle_id,
            "run_id": result.run_id,
            "package_path": str(result.package_path),
            "contexts": result.bundle.manifest.focus_count,
            "methods": len(result.bundle.methods),
            "coverage": result.bundle.manifest.coverage.model_dump(),
            "estimated_tokens": result.bundle.manifest.estimated_tokens,
            "prunes": len(result.bundle.manifest.prunes),
            "degradations": [d.reason for d in result.bundle.manifest.degradations],
            "warnings": result.warnings,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False) if args.json else _human(payload))
        return 0

    if args.command == "scan":
        scan_pipeline = ScanOnlyPipeline(settings)
        result = scan_pipeline.run(
            PipelineRequest(
                workspace=workspace_path,
                rules=args.rule,
                rule_config=args.rule_config,
            )
        )
        payload = {
            "run_id": result.run_id,
            "engine": result.scan_engine,
            "findings": len(result.findings),
            "sarif_path": str(result.sarif_path) if result.sarif_path else None,
            "warnings": result.warnings,
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    if args.command == "probe":
        from app.api.deps import probe_lsp

        manager, available, missing = probe_lsp(workspace_path)
        payload = {
            "workspace": str(workspace_path),
            "available": available,
            "missing": missing,
            "degradations": [d.reason for d in manager.degradations],
        }
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return 0

    return 2


def _human(payload: dict) -> str:
    lines = [
        f"bundle      {payload['bundle_id']}",
        f"package     {payload['package_path']}",
        f"contexts    {payload['contexts']}",
        f"methods     {payload['methods']}",
        f"coverage    {payload['coverage']}",
        f"tokens      ~{payload['estimated_tokens']}",
        f"prunes      {payload['prunes']}",
    ]
    if payload["warnings"]:
        lines.append("warnings:")
        lines += [f"  - {w}" for w in payload["warnings"]]
    if payload["degradations"]:
        lines.append("degradations:")
        lines += [f"  - {d}" for d in payload["degradations"]]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
