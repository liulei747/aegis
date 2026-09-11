#!/usr/bin/env python
"""End-to-end demo: build a fixture repo, assemble a bundle, print the result.

    python scripts/demo.py            # uses the in-repo fake LSP server (no installs)
    python scripts/demo.py --no-lsp   # degraded, syntax-only mode

The fake LSP server lives in tests/ and speaks the real protocol, so this demo
exercises exactly the same code path a real language server would.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from aegis_core.config import BudgetConfig, Settings  # noqa: E402
from aegis_core.logging import setup_logging  # noqa: E402
from services.extraction.pipeline.assemble import AssemblyPipeline, PipelineRequest  # noqa: E402
from tests.fixtures import write_fixture, write_sarif  # noqa: E402


def build_lsp_config(demo: Path) -> Path:
    server = (ROOT / "tests" / "fake_lsp_server.py").as_posix()
    config = demo / "lsp.yaml"
    config.write_text(
        "servers:\n"
        "  - language: python\n"
        f"    command: ['{sys.executable}', '{server}', '--root', '{{root}}']\n"
        "    extensions: ['.py']\n",
        encoding="utf-8",
    )
    return config


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--no-lsp", action="store_true")
    parser.add_argument("--depth", type=int, default=2)
    parser.add_argument("--demo-dir", default=str(ROOT / "demo"))
    args = parser.parse_args()

    setup_logging("INFO")
    demo = Path(args.demo_dir).resolve()
    workspace = write_fixture(demo / "repo")
    sarif = write_sarif(demo / "scan.sarif", sink_line=5, workspace=workspace)
    config = None if args.no_lsp else build_lsp_config(demo)

    settings = Settings(
        workspace_root=workspace,
        output_dir=(ROOT / "var" / "packages"),
        work_dir=(ROOT / "var" / "work"),
        lsp_enabled=config is not None,
        lsp_config_file=config,
        budget=BudgetConfig(max_depth=args.depth),
    ).resolve()

    result = asyncio.run(
        AssemblyPipeline(settings).run(
            PipelineRequest(workspace=workspace, sarif_path=sarif, lsp=config is not None)
        )
    )
    assert result.bundle is not None and result.package_path is not None

    manifest = result.bundle.manifest
    print(f"\nbundle      {manifest.bundle_id}")
    print(f"package     {result.package_path}")
    print(f"contexts    {manifest.focus_count}")
    print(f"methods     {len(result.bundle.methods)}")
    print(f"tokens      ~{manifest.estimated_tokens}")
    print(f"coverage    {manifest.coverage.model_dump()}")
    print(f"prunes      {[p.rule for p in manifest.prunes]}")
    print(f"degraded    {[d.capability for d in manifest.degradations]}")

    if result.assembly is not None and result.assembly.contexts:
        context = result.assembly.contexts[0]
        print("\ncall chain slice (from the assembled package):")
        for ref in context.refs:
            arrow = "==" if ref.is_focus else ("^" if str(ref.direction) .endswith("CALLER") else "v")
            print(
                f"  d{ref.depth} {arrow} {ref.method.qualified_name:<18}"
                f" {ref.method.path}:{ref.method.region.start_line + 1}"
                f" [{ref.provider.value}]"
            )

    print(f"\nreview it:  {result.package_path / 'summary.md'}")
    print(f"send this:  {result.package_path / 'ai' / 'prompt.md'}")
    print("\nmanifest capabilities:")
    print(json.dumps(manifest.capabilities, indent=2)[:1200])
    return 0


if __name__ == "__main__":
    sys.exit(main())
