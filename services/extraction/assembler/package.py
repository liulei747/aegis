"""Stage: package the bundle on disk.

Output layout (one directory per run, plus a zip for transport):

    <output_dir>/<bundle_id>/
        manifest.json        machine-readable contract (this is the API surface)
        bundle.json          findings + methods + edges + contexts, no bodies
        methods/<id>.txt     one full method body each
        contexts/<id>.md     one rendered analysis package each
        ai/prompt.md         ordered prompt blocks for the model
        ai/blocks.jsonl      one prompt block per line (streaming / caching)
        ai/blocks_meta.json  per-block id, title, tokens, cacheable
        ai/cache_prefix.json where the reusable prefix starts (see below)
        graph/callgraph.dot  the slice as a graph
        summary.md           human review entry point
        scan/original.sarif  raw scanner output, for audit
"""

from __future__ import annotations

import json
import os
import shutil
import zipfile
from pathlib import Path

from aegis_contracts.domain import (
    AnalysisBundle,
    CallEdge,
    Degradation,
    MethodSymbol,
    PromptBlock,
    RunStats,
)
from aegis_core.logging import get_logger, setup_logging
from services.extraction.assembler.contexts import AssemblyResult
from services.extraction.assembler.render import BundleRenderer

log = get_logger(__name__)


def export_dot(methods: dict[str, MethodSymbol], edges: list[CallEdge]) -> str:
    lines = ["digraph aegis {", '  rankdir="LR";', '  node [shape=box, fontname="monospace"];']
    for method_id, method in sorted(methods.items()):
        label = f"{method.qualified_name}\\n{method.path}:{method.region.start_line + 1}"
        style = "filled" if method.provider.value != "syntax_regex" else "dashed"
        lines.append(f'  "{method_id}" [label="{label}", style="{style}"];')
    for edge in edges:
        color = {
            "lsp_call_hierarchy": "black",
            "lsp_definition": "blue",
            "lsp_implementation": "darkgreen",
            "lsp_references": "gray",
            "syntax_regex": "orange",
        }.get(edge.provider.value, "gray")
        lines.append(
            f'  "{edge.caller_id}" -> "{edge.callee_id}" '
            f'[color="{color}", label="{edge.direction.value}"];'
        )
    lines.append("}")
    return "\n".join(lines)


def write_text(path: Path, text: str) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def _cache_prefix(prompts: list[PromptBlock]) -> dict:
    """Say where the reusable prefix starts, instead of leaving it to be inferred.

    The block at ``order == 0`` is ``bundle.header``, which carries the bundle id and
    therefore changes between any two bundles. A consumer that concatenates every
    ``cacheable`` block would prepend that header and never hit a cache, so the
    answer to "what may I prefill?" has to be published rather than guessed.
    """
    first = next((index for index, block in enumerate(prompts) if block.cacheable), None)
    if first is None:  # pragma: no cover - the renderer always emits instructions
        return {
            "prefix_start": None,
            "prefix_blocks": [],
            "stable_prefix_tokens": 0,
            "note": "no block declared itself reusable; nothing may be cached",
        }
    reusable = [block for block in prompts[first:] if block.cacheable]
    skipped = [block.block_id for block in prompts[:first]]
    note = (
        "Blocks before cache_prefix_start are volatile and must be sent per request. "
        "Everything from it onwards, while `cacheable` is true, is byte-identical "
        "across bundles assembled from the same workspace and rule set."
    )
    if skipped:
        note += f" Skipped ahead of the prefix: {', '.join(skipped)}."
    return {
        "prefix_start": first,
        "prefix_blocks": [block.block_id for block in reusable],
        "stable_prefix_tokens": sum(block.estimated_tokens for block in reusable),
        "note": note,
    }


def zip_dir(directory: Path, target: Path | None = None) -> Path:
    target = target or directory.with_suffix(".zip")
    with zipfile.ZipFile(target, "w", zipfile.ZIP_DEFLATED) as zf:
        for file in sorted(directory.rglob("*")):
            if file.is_file():
                zf.write(file, file.relative_to(directory).as_posix())
    return target


class BundlePackager:
    def __init__(self, output_dir: Path, renderer: BundleRenderer) -> None:
        self.output_dir = output_dir
        self.renderer = renderer

    def write(
        self,
        bundle: AnalysisBundle,
        result: AssemblyResult,
        *,
        sarif_source: Path | None = None,
        degradations: list[Degradation] | None = None,
        stats: RunStats | None = None,
        make_zip: bool = True,
        staging: bool = False,
    ) -> Path:
        manifest = bundle.manifest
        # Incremental writes mean a bundle directory exists before it is complete, and six
        # `write_text` calls happen after `manifest.json`. So an interrupted run would leave
        # a directory that looks like a bundle but is not one, and `GET /v1/bundles` would
        # list it. With `staging=True` the whole tree is built under a dot-prefixed sibling
        # and renamed into place only once it is finished; a cancel can then simply delete
        # the staging directory. Callers that are not interruptible keep `staging=False`,
        # for which the on-disk layout is byte-for-byte what it always was.
        final = self.output_dir / manifest.bundle_id
        root = self.output_dir / f".staging-{manifest.bundle_id}" if staging else final
        if root.exists():
            shutil.rmtree(root)
        root.mkdir(parents=True, exist_ok=True)

        if degradations:
            manifest.degradations = _merge_degradations(manifest.degradations, degradations)
        if stats is not None:
            manifest.stats = stats
        manifest.capabilities["prompt_blocks"] = [
            {"block_id": b.block_id, "tokens": b.estimated_tokens} for b in bundle.prompts
        ]

        write_text(root / "manifest.json", manifest.model_dump_json(indent=2))
        write_text(
            root / "bundle.json",
            json.dumps(
                {
                    "manifest": json.loads(manifest.model_dump_json()),
                    "contexts": [c.to_model().model_dump() for c in result.contexts],
                },
                indent=2,
                ensure_ascii=False,
            ),
        )

        for body in result.bodies.bodies.values():
            write_text(root / "methods" / f"{body.method.method_id}.txt", body.text)

        for context in result.contexts:
            block = next(
                (b for b in bundle.prompts if b.block_id == f"context.{context.context_id}"), None
            )
            if block is not None:
                write_text(root / "contexts" / f"{context.context_id}.md", block.content)

        ai_dir = root / "ai"
        write_text(
            ai_dir / "prompt.md",
            "\n\n---\n\n".join(block.content for block in bundle.prompts),
        )
        write_text(
            ai_dir / "blocks.jsonl",
            "\n".join(
                json.dumps(
                    {
                        "block_id": block.block_id,
                        "title": block.title,
                        "tokens": block.estimated_tokens,
                        "method_ids": block.method_ids,
                        "content": block.content,
                    },
                    ensure_ascii=False,
                )
                for block in bundle.prompts
            ),
        )
        write_text(
            ai_dir / "blocks_meta.json",
            json.dumps(
                [
                    {
                        "order": index,
                        "block_id": block.block_id,
                        "title": block.title,
                        "tokens": block.estimated_tokens,
                        # Declared by the renderer. It used to be re-derived here from
                        # the block id, which let the renderer and the contract drift
                        # apart silently -- see tests/test_prompt_prefix.py.
                        "cacheable": block.cacheable,
                    }
                    for index, block in enumerate(bundle.prompts)
                ],
                indent=2,
            ),
        )
        write_text(
            ai_dir / "cache_prefix.json",
            json.dumps(_cache_prefix(bundle.prompts), indent=2),
        )

        methods = {mid: sym for mid, sym in bundle.methods.items()}
        all_edges = [edge for context in result.contexts for edge in context.edges]
        write_text(root / "graph" / "callgraph.dot", export_dot(methods, all_edges))

        if sarif_source is not None and Path(sarif_source).exists():
            (root / "scan").mkdir(parents=True, exist_ok=True)
            shutil.copy2(sarif_source, root / "scan" / "original.sarif")

        write_text(root / "summary.md", render_summary(bundle, result))

        if make_zip:
            zip_dir(root)
        if staging:
            # Same volume, so this is a rename, not a copy. `output_dir` is where the
            # staging directory lives precisely to keep that true.
            if final.exists():
                shutil.rmtree(final)
            os.replace(root, final)
            if make_zip:
                staged_zip = root.with_suffix(".zip")
                if staged_zip.exists():
                    os.replace(staged_zip, final.with_suffix(".zip"))
        bundle.package_path = str(final)
        log.info("bundle written", extra={"stage": "package"})
        return final


def render_summary(bundle: AnalysisBundle, result: AssemblyResult) -> str:
    manifest = bundle.manifest
    lines = [
        f"# Aegis bundle {manifest.bundle_id}",
        "",
        f"- run: `{manifest.run_id}`",
        f"- workspace: `{manifest.workspace_root}`",
        f"- contexts: {len(result.contexts)} (findings bundled {manifest.coverage.bundled}/"
        f"{manifest.coverage.discoverable})",
        f"- unique methods: {len(result.bodies.bodies)}",
        f"- size: {manifest.total_chars:,} chars, ~{manifest.estimated_tokens:,} tokens",
        f"- truncated: {str(any(c.truncated for c in result.contexts)).lower()}",
        f"- scan ran: {manifest.stats.scan.location if manifest.stats.scan else 'unknown'}",
        "",
    ]
    run_warnings = list(manifest.capabilities.get("warnings") or [])
    if run_warnings:
        lines += ["## Run warnings", ""]
        lines += [f"- {w}" for w in run_warnings]
        lines.append("")

    lines += [
        "## Contexts",
        "",
        "| context | focus | providers | severity | methods | tokens |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for context in result.contexts:
        providers = sorted({ref.provider.value for ref in context.refs})
        block_tokens = next(
            (
                b.estimated_tokens
                for b in bundle.prompts
                if b.block_id == f"context.{context.context_id}"
            ),
            context.estimated_tokens,
        )
        lines.append(
            f"| `{context.context_id}` | {context.focus.method.qualified_name} "
            f"({context.focus.method.path}:{context.focus.method.region.start_line + 1}) "
            f"| {', '.join(providers)} | {context.worst_severity.value} "
            f"| {len(context.refs)} | {block_tokens} |"
        )
    if manifest.prunes:
        lines += ["", "## Pruned during assembly", ""]
        for prune in manifest.prunes:
            lines.append(f"- `{prune.rule}`: {prune.detail}")
    if manifest.degradations:
        lines += ["", "## Degradations", ""]
        for degradation in manifest.degradations:
            lines.append(f"- `{degradation.capability}`: {degradation.reason} -> {degradation.impact}")
    if manifest.stats.stage_ms:
        lines += ["", "## Stage timings", ""]
        for stage, ms in manifest.stats.stage_ms.items():
            lines.append(f"- {stage}: {ms} ms")
    return "\n".join(lines)


def _merge_degradations(
    existing: list[Degradation], incoming: list[Degradation]
) -> list[Degradation]:
    seen = {(d.capability, d.reason) for d in existing}
    merged = list(existing)
    for degradation in incoming:
        key = (degradation.capability, degradation.reason)
        if key in seen:
            continue
        seen.add(key)
        merged.append(degradation)
    return merged


def write_blocks_jsonl(path: Path, blocks: list[PromptBlock]) -> Path:
    return write_text(
        path,
        "\n".join(json.dumps(b.model_dump(), ensure_ascii=False) for b in blocks),
    )


__all__ = [
    "BundlePackager",
    "export_dot",
    "render_summary",
    "setup_logging",
    "write_text",
    "zip_dir",
]
