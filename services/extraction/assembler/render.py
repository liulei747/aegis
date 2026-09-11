"""Stage: render the bundle for humans and for the model.

Layout is deliberate, in this order, to maximize prefix reuse (both for
provider-side prompt caching and for the documented IAI-style prefill
acceleration where a big static input prefix is cheaper than streaming output):

1. ``instructions`` — byte-identical across every run of a given version.
2. ``method_catalog`` — every collected method body, in stable content order.
   This is the expensive, highly cacheable block.
3. ``context.<id>`` — the small, volatile part: one sink, its evidence, its slice.

A consumer can therefore send blocks 1-2 once and then stream only block 3 per
sub-agent, or fan out one ``context.<id>`` per worker.

Two kinds of stability live here and they are not the same claim:

* ``instructions.*`` is stable across **every** bundle of a prompt version.
* ``instructions.*`` + ``method_catalog`` is stable across bundles assembled from
  the **same workspace and rule set** — which is what a fan-out runs over.

``bundle.header`` is prepended for a human reader and is stable in neither sense: it
carries the bundle id and the bundle-level token count. So the reusable run does not
begin at index 0, and ``ai/cache_prefix.json`` publishes where it does begin. The
``cacheable`` flag on each :class:`PromptBlock` is set here, by the block's owner —
``tests/test_prompt_prefix.py`` asserts the run is contiguous *and* that its bytes
really are identical between two bundles that differ only in their volatile parts.
"""

from __future__ import annotations

from aegis_contracts.domain import (
    EdgeDirection,
    Finding,
    MethodRef,
    MethodSymbol,
    PromptBlock,
)
from aegis_core.config import BudgetConfig
from aegis_core.utils import estimate_tokens
from services.extraction.assembler.contexts import AssembledContext, AssemblyResult

PROMPT_VERSION = "2025-01-assemble-v1.1"

SYSTEM_INSTRUCTIONS = f"""\
You are a security analysis agent working on an evidence bundle assembled by Aegis
(bundle schema 1.0, prompt layout {PROMPT_VERSION}).

## What this bundle is
A static scanner (opengrep/semgrep rules) reported one or more findings. For each
finding, Aegis used a language server (LSP) to locate the enclosing method and to
walk the call graph. You are given the full source of the methods on that call
chain, not snippets, so you can reason about data flow instead of pattern matching.

## Evidence trust levels
Every symbol, edge and method carries a `provider` and, for edges, a `confidence`.
Weigh them accordingly, and never present a low-confidence edge as fact:

- `lsp_call_hierarchy` (1.00): server-resolved caller/callee. Treat as fact.
- `lsp_definition`      (0.90): callee resolved from a lexical call site. Strong.
- `lsp_implementation`  (0.80): abstract-to-concrete dispatch target. Strong, but
  only one of possibly many implementations.
- `lsp_references`      (0.60): a reference to the symbol was found, but we could
  not prove it is a call, nor that it is the immediate caller.
- `syntax_regex`        (0.40): no language server was available; scopes and call
  sites are lexical guesses. Treat boundaries as approximate.
- `file_range`          (0.20): last-resort fallback.

## Mandatory rules
1. Cite evidence for every claim: `path:line` plus the method id (`M-...`).
2. Distinguish "the bundle proves X" from "X is plausible but unproven". If a
   needed method is missing, say exactly which method you need and why.
3. `truncated: true` or a `prunes` entry means coverage is incomplete. State the
   impact on your confidence; do not silently compensate.
4. Reachability counts. A sink in a method with no callers and no exposed entry
   point is a different severity than one on an HTTP handler path.
5. Report uncertainty as a calibrated range, not a vibe.

## Required output (per analysis context)
- `verdict`: true_positive | false_positive | needs_more_context
- `severity`: critical | high | medium | low | informational
- `confidence`: 0.0-1.0
- `reachability`: is the sink reachable from an untrusted entry point? Say how.
- `chain`: the concrete call path you believe exists, as `path:line (M-...)` steps
- `data_flow`: untrusted source -> transformations -> sink, or why it is safe
- `evidence`: the specific lines that support the verdict
- `missing`: what would raise confidence
- `fix`: the minimal remediation, anchored to a specific method
"""


def provider_legend() -> PromptBlock:
    lines = [
        "## Provider legend",
        "| provider | meaning |",
        "| --- | --- |",
        "| lsp_call_hierarchy | true caller/callee from the language server |",
        "| lsp_definition | callee resolved from a call site |",
        "| lsp_implementation | dispatch target of an abstract/interface method |",
        "| lsp_references | symbol reference, call-ness unproven |",
        "| lsp_document_symbol | scope located via document symbols |",
        "| syntax_regex | lexical fallback, boundaries approximate |",
        "| opengrep | the original static-scan hit |",
    ]
    content = "\n".join(lines)
    return PromptBlock(
        block_id="instructions.legend",
        title="Provider legend",
        content=content,
        estimated_tokens=estimate_tokens(content),
        cacheable=True,
    )


def instructions_block() -> PromptBlock:
    return PromptBlock(
        block_id="instructions.system",
        title="System instructions",
        content=SYSTEM_INSTRUCTIONS,
        estimated_tokens=estimate_tokens(SYSTEM_INSTRUCTIONS),
        cacheable=True,
    )


class BundleRenderer:
    def __init__(self, budget: BudgetConfig) -> None:
        self.budget = budget
        self._canonical: dict[str, str] = {}
        self._method_by_id: dict[str, MethodSymbol] = {}

    def _canonical_for(self, context: AssembledContext, method_id: str) -> str | None:
        """Which method id owns the body that stands in for ``method_id``?"""
        canonical = self._canonical.get(method_id)
        if canonical is None:
            return None
        # Only point at it when that body is actually rendered somewhere.
        rendered = any(canonical in c.bodies for c in self._contexts)
        return canonical if rendered else None

    # ------------------------------------------------------------------
    def render(self, result: AssemblyResult, *, bundle_id: str, workspace_root: str) -> list[PromptBlock]:
        self._canonical = dict(result.bundle_aliases)
        self._contexts = result.contexts
        self._method_by_id = {
            ref.method.method_id: ref.method
            for context in result.contexts
            for ref in context.refs
        }
        blocks: list[PromptBlock] = [instructions_block(), provider_legend()]
        blocks.append(self._catalog(result))
        for context in result.contexts:
            blocks.append(self._context(context))
        blocks.append(self._run_notes(result))
        total = sum(b.estimated_tokens for b in blocks)
        blocks.append(
            PromptBlock(
                block_id="instructions.chunking",
                title="Chunking plan",
                content=self._chunking_plan(result),
                estimated_tokens=estimate_tokens(self._chunking_plan(result)),
                cacheable=True,
            )
        )
        # Keep the reusable blocks first: they are the identical prefix of every
        # request. The header is prepended below and is *volatile* (it carries the
        # bundle id and the bundle-level token count), so the cacheable run does not
        # start at index 0 -- `package.py` publishes where it does start.
        blocks.sort(key=_block_order)
        for block in blocks:
            if not block.estimated_tokens:
                block.estimated_tokens = estimate_tokens(block.content)
        header = (
            f"# Aegis analysis bundle {bundle_id}\n"
            f"workspace: {workspace_root}\n"
            f"contexts: {len(result.contexts)}\n"
            f"approx tokens (whole bundle): {total}\n"
        )
        blocks.insert(
            0,
            PromptBlock(
                block_id="bundle.header",
                title="Bundle header",
                content=header,
                estimated_tokens=estimate_tokens(header),
                # Not cacheable, deliberately and permanently: two different bundles
                # never share these bytes. See tests/test_prompt_prefix.py.
                cacheable=False,
            ),
        )
        return blocks

    # ------------------------------------------------------------------
    def _catalog(self, result: AssemblyResult) -> PromptBlock:
        lines = [
            "## Collected method sources",
            "",
            "Complete bodies of every method in this bundle, deduplicated across all",
            "contexts. Method ids are content-stable: the same method keeps its id",
            "across runs, and a context that refers to a body rendered here points at",
            "it rather than repeating it.",
            "",
        ]
        for body in sorted(
            result.inlined_bodies.values(),
            key=lambda b: (b.method.path, b.method.region.start_line, b.method.method_id),
        ):
            method = body.method
            lines.append(_method_header(method, body))
            lines.append("```" + _fence_lang(method.language))
            lines.append(body.text.rstrip())
            lines.append("```")
            lines.append("")
        content = "\n".join(lines)
        return PromptBlock(
            block_id="method_catalog",
            title="Collected method sources",
            content=content,
            estimated_tokens=estimate_tokens(content),
            method_ids=sorted(result.inlined_bodies),
            cacheable=True,
        )

    def _context(self, context: AssembledContext) -> PromptBlock:
        lines = [
            f"## Analysis context {context.context_id}",
            "",
        ]
        lines.append(
            f"- focus: `{context.focus.method.method_id}` "
            f"{context.focus.method.qualified_name} "
            f"({context.focus.method.path}:{context.focus.method.region.start_line + 1}"
            f"-{context.focus.method.region.end_line + 1})"
        )
        lines.append(f"- focus located by: `{context.focus.method.provider.value}`")
        lines.append(f"- methods in slice: {len(context.refs)} | edges: {len(context.edges)}")
        lines.append(f"- truncated: {str(context.truncated).lower()}")
        if context.focus.via:
            lines.append(f"- how the focus was reached: {context.focus.via}")
        lines.append("")

        lines.append("### Static-scan findings")
        if not context.findings:
            lines.append("_no finding attached (context kept for graph connectivity)_")
        for finding in context.findings:
            lines.append(_finding_line(finding))
        lines.append("")

        lines.append("### Call chain slice")
        by_id = {ref.method.method_id: ref for ref in context.refs}
        for ref in context.refs:
            arrow = _arrow(ref)
            lines.append(
                f"- d{ref.depth} {arrow} `{ref.method.method_id}` "
                f"{ref.method.qualified_name} "
                f"({ref.method.path}:{ref.method.region.start_line + 1}"
                f"-{ref.method.region.end_line + 1}) "
                f"[{ref.provider.value}]"
                + (f" via `{ref.via}`" if ref.via and not ref.is_focus else "")
                + (" **FOCUS**" if ref.is_focus else "")
            )
        lines.append("")
        lines.append("### Edges")
        for edge in context.edges:
            caller = by_id.get(edge.caller_id)
            callee = by_id.get(edge.callee_id)
            caller_name = caller.method.qualified_name if caller else edge.caller_id
            callee_name = callee.method.qualified_name if callee else edge.callee_id
            site = (
                f" at {edge.call_site.path}:{edge.call_site.start_line + 1}"
                if edge.call_site
                else ""
            )
            lines.append(
                f"- {caller_name} -> {callee_name}{site} "
                f"[{edge.provider.value} conf={edge.confidence:.2f}]"
                + (f" `{edge.call_site_snippet}`" if edge.call_site_snippet else "")
                + (f" ({edge.notes})" if edge.notes else "")
            )
        lines.append("")

        if context.aliases:
            lines.append("### Deduplicated aliases")
            for owner, alias_ids in context.aliases.items():
                owner_ref = by_id.get(owner)
                owner_name = owner_ref.method.qualified_name if owner_ref else owner
                lines.append(
                    f"- `{owner}` ({owner_name}) is byte-identical to: "
                    + ", ".join(f"`{a}`" for a in alias_ids)
                )
            lines.append("")

        lines.append("### Method sources")
        for ref in context.refs:
            method_id = ref.method.method_id
            body = context.bodies.get(method_id)
            if body is None:
                # Byte-identical to a body rendered elsewhere in this bundle: the
                # text lives in `method_catalog`, so point there instead of paying
                # for it a second time.
                canonical = self._canonical_for(context, method_id)
                lines.append(_method_header(ref.method, None))
                if canonical is None:
                    lines.append("_body not inlined (budget/prune); see `prunes`_")
                else:
                    owner = self._method_by_id.get(canonical)
                    name = owner.qualified_name if owner else canonical
                    location = (
                        f" ({owner.path}:{owner.region.start_line + 1})" if owner else ""
                    )
                    lines.append(
                        f"_body identical to `{canonical}` {name}{location}; "
                        "see `method_catalog`_"
                    )
                lines.append("")
                continue
            lines.append(_method_header(ref.method, body))
            lines.append("```" + _fence_lang(ref.method.language))
            lines.append(body.text.rstrip())
            lines.append("```")
            lines.append("")

        if context.prunes:
            lines.append("### Coverage limits for this context")
            for prune in context.prunes:
                lines.append(
                    f"- `{prune.rule}`: {prune.detail}"
                    + (f" (at {prune.path}:{(prune.line or 0) + 1})" if prune.path else "")
                )
            lines.append("")

        content = "\n".join(lines)
        return PromptBlock(
            block_id=f"context.{context.context_id}",
            title=f"Analysis context {context.context_id}",
            content=content,
            estimated_tokens=estimate_tokens(content),
            method_ids=[ref.method.method_id for ref in context.refs],
        )

    def _run_notes(self, result: AssemblyResult) -> PromptBlock:
        lines = ["## Bundle-level coverage and limitations", ""]
        coverage = result.coverage
        lines.append(
            f"- findings discoverable: {coverage.discoverable} | bundled: {coverage.bundled} | "
            f"rejected: {coverage.rejected} | collapsed duplicates: {coverage.deduped}"
        )
        lines.append(f"- unique method bodies inlined: {len(result.bodies.bodies)}")
        if result.prunes:
            lines.append("")
            lines.append("Every prune applied while assembling this bundle:")
            for prune in result.prunes:
                location = f" ({prune.path}:{(prune.line or 0) + 1})" if prune.path else ""
                lines.append(f"- `{prune.rule}`: {prune.detail}{location}")
        else:
            lines.append("- no pruning was necessary: the bundle is coverage-complete")
        content = "\n".join(lines)
        return PromptBlock(
            block_id="run.notes",
            title="Coverage and limitations",
            content=content,
            estimated_tokens=estimate_tokens(content),
        )

    def _chunking_plan(self, result: AssemblyResult) -> str:
        lines = [
            "## Chunking plan for fan-out",
            "",
            "These instructions and `method_catalog` are byte-identical between bundles",
            "assembled from the same workspace and rule set. Send them once as a cached",
            "prefix, then dispatch one `context.<id>` per sub-agent. The bundle header",
            "above them is not part of that prefix: it names this bundle. Contexts are",
            "independent: no context needs another to be analysed.",
            "",
            "| context | focus | worst severity | methods | approx tokens |",
            "| --- | --- | --- | --- | --- |",
        ]
        for context in result.contexts:
            lines.append(
                f"| `{context.context_id}` | {context.focus.method.qualified_name} |"
                f" {context.worst_severity.value} | {len(context.refs)} |"
                f" {context.estimated_tokens} |"
            )
        return "\n".join(lines)


# ----------------------------------------------------------------------
def _block_order(block: PromptBlock) -> tuple[int, str]:
    prefix_rank = {
        "bundle.header": 0,
        "instructions.system": 1,
        "instructions.legend": 2,
        "instructions.chunking": 3,
        "method_catalog": 4,
        "run.notes": 8,
    }
    if block.block_id in prefix_rank:
        return (prefix_rank[block.block_id], block.block_id)
    return (5, block.block_id)


def _method_header(method, body) -> str:
    flags = []
    if body is not None and body.truncated_chars:
        flags.append("truncated:chars")
    if body is not None and body.truncated_lines:
        flags.append("truncated:lines")
    suffix = f" [{', '.join(flags)}]" if flags else ""
    return (
        f"#### `{method.method_id}` {method.qualified_name}\n"
        f"{method.path}:{method.region.start_line + 1}-{method.region.end_line + 1} "
        f"| kind={method.kind.value} | provider={method.provider.value} "
        f"| language={method.language or '?'}{suffix}"
    )


def _finding_line(finding: Finding) -> str:
    return (
        f"- `{finding.finding_id}` rule=`{finding.rule_id}` severity={finding.severity.value} "
        f"at {finding.path}:{finding.region.start_line + 1}"
        + (f" — {finding.message}" if finding.message else "")
        + (f"\n  - snippet: `{finding.snippet}`" if finding.snippet else "")
    )


def _arrow(ref: MethodRef) -> str:
    if ref.is_focus:
        return "=="
    if ref.direction is EdgeDirection.CALLER:
        return "^"
    if ref.direction is EdgeDirection.CALLEE:
        return "v"
    return "-"


def _fence_lang(language: str | None) -> str:
    if not language:
        return ""
    mapping = {"python": "python", "typescript": "ts", "javascript": "js", "c": "c", "cpp": "cpp"}
    return mapping.get(language, language)
