"""Read-only views over a bundle manifest.

This module is the *only* place that turns raw bundle facts into something a
human reads. It is deliberately pure: it takes an
:class:`~app.schemas.domain.AnalysisBundleManifest` and returns derived views,
never mutating anything and never inventing a number that is not in the manifest.

Two consequences worth keeping:

* the JSON API and the HTML console render the exact same views, so they can
  never disagree;
* deleting this module (or the console) cannot change a bundle.

The central idea is the **funnel**: a pipeline that silently loses findings is
worse than one that fails, so every step from "scanner output" to "method inlined
in a bundle" is reported as an explicit count, and any step with losses carries
the prune rules that caused them plus the concrete items where they are known.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from app.schemas.domain import (
    AnalysisBundleManifest,
    EdgeDirection,
    MethodRef,
    MethodSymbol,
    Provider,
    ScanRecord,
)

# ----------------------------------------------------------------------
# Static knowledge about the providers: what a confidence score means and
# whether a human should trust it as fact.
# ----------------------------------------------------------------------
PROVIDER_NOTES: dict[str, dict[str, Any]] = {
    Provider.LSP_CALL_HIERARCHY.value: {
        "label": "LSP call hierarchy",
        "trust": "fact",
        "confidence": 1.0,
        "note": "the language server resolved this caller/callee directly",
    },
    Provider.LSP_DEFINITION.value: {
        "label": "LSP definition",
        "trust": "strong",
        "confidence": 0.9,
        "note": "callee resolved from a lexical call site via textDocument/definition",
    },
    Provider.LSP_IMPLEMENTATION.value: {
        "label": "LSP implementation",
        "trust": "strong",
        "confidence": 0.8,
        "note": "dispatch target of an abstract/interface method",
    },
    Provider.LSP_REFERENCES.value: {
        "label": "LSP references",
        "trust": "weak",
        "confidence": 0.6,
        "note": "a reference exists, but that it is a call is unproven",
    },
    Provider.LSP_DOCUMENT_SYMBOL.value: {
        "label": "LSP documentSymbol",
        "trust": "fact",
        "confidence": 1.0,
        "note": "method boundaries taken from the server's symbol ranges",
    },
    Provider.SYNTAX_REGEX.value: {
        "label": "syntax heuristic",
        "trust": "guess",
        "confidence": 0.4,
        "note": "no language server: scopes and call sites are lexical approximations",
    },
    Provider.OPENGREP.value: {
        "label": "static scanner",
        "trust": "fact",
        "confidence": 1.0,
        "note": "the original opengrep/SARIF hit",
    },
    Provider.FILE_RANGE.value: {
        "label": "file range fallback",
        "trust": "guess",
        "confidence": 0.2,
        "note": "last-resort range, treat the boundaries as approximate",
    },
    Provider.NONE.value: {
        "label": "none",
        "trust": "unknown",
        "confidence": 0.0,
        "note": "no provider recorded",
    },
}

TRUST_ORDER = {"fact": 0, "strong": 1, "weak": 2, "guess": 3, "unknown": 4}

STAGE_LABELS: dict[str, str] = {
    "scan": "static scan (opengrep/SARIF)",
    "setup": "workspace + language servers",
    "locate": "locate enclosing method",
    "expand": "expand call graph",
    "read": "read full method bodies",
    "assemble": "dedupe + assemble contexts",
    "package": "write package",
}


# ----------------------------------------------------------------------
# Views
# ----------------------------------------------------------------------
@dataclass
class FunnelStep:
    key: str
    label: str
    count: int
    of_previous: float | None
    of_first: float | None
    lost: int
    loss_reasons: list[str] = field(default_factory=list)
    lost_items: list[dict[str, Any]] = field(default_factory=list)
    note: str | None = None


@dataclass
class StageTiming:
    key: str
    label: str
    ms: int
    share: float
    cached: bool = False


@dataclass
class ProviderStat:
    provider: str
    label: str
    trust: str
    confidence: float
    note: str
    methods: int
    edges: int
    focus_methods: int


@dataclass
class ContextView:
    context_id: str
    focus_id: str
    focus_name: str
    focus_location: str
    focus_provider: str
    worst_severity: str
    findings: list[dict[str, Any]]
    methods: list[dict[str, Any]]
    edges: list[dict[str, Any]]
    estimated_tokens: int
    total_chars: int
    truncated: bool
    prunes: list[dict[str, Any]]
    depth_histogram: dict[str, int]
    provider_mix: dict[str, int]
    unreached_focus: bool


@dataclass
class BundleOverview:
    bundle_id: str
    run_id: str
    created_at: str
    workspace_root: str
    context_count: int
    method_count: int
    finding_count: int
    total_chars: int
    estimated_tokens: int
    duration_ms: int
    worst_trust: str
    trust_mix: dict[str, int]
    truncated_contexts: int
    prune_count: int
    degradation_count: int
    warning_flags: list[str]


# ----------------------------------------------------------------------
# Builders
# ----------------------------------------------------------------------
def overview(manifest: AnalysisBundleManifest) -> BundleOverview:
    trust_mix: Counter[str] = Counter()
    for method in manifest.methods:
        trust_mix[_trust_of(method.provider.value)] += 1
    worst = max(trust_mix, key=lambda t: TRUST_ORDER.get(t, 9)) if trust_mix else "unknown"

    flags: list[str] = []
    scan = manifest.stats.scan
    if scan is not None and scan.zero_findings_is_suspicious:
        flags.append("scanner returned zero findings from a scan that was not configured")
    if not manifest.findings:
        flags.append("no findings at all: nothing was analysed")
    if manifest.coverage.rejected:
        flags.append(f"{manifest.coverage.rejected} finding(s) never reached a bundle")
    if any(c.truncated for c in manifest.contexts):
        flags.append("at least one context was truncated")
    if any(d.capability == "lsp" for d in manifest.degradations):
        flags.append("no language server contributed: every edge is a heuristic")
    if scan is not None and scan.stderr_tail and not manifest.findings:
        flags.append("scanner wrote to stderr and produced no findings")

    return BundleOverview(
        bundle_id=manifest.bundle_id,
        run_id=manifest.run_id,
        created_at=manifest.created_at.isoformat(),
        workspace_root=manifest.workspace_root,
        context_count=len(manifest.contexts),
        method_count=len(manifest.methods),
        finding_count=len(manifest.findings),
        total_chars=manifest.total_chars,
        estimated_tokens=manifest.estimated_tokens,
        duration_ms=manifest.stats.duration_ms,
        worst_trust=worst,
        trust_mix=dict(trust_mix),
        truncated_contexts=sum(1 for c in manifest.contexts if c.truncated),
        prune_count=len(manifest.prunes),
        degradation_count=len(manifest.degradations),
        warning_flags=flags,
    )


def funnel(manifest: AnalysisBundleManifest) -> list[FunnelStep]:
    """Every step from scanner output to inlined bodies, with explicit losses.

    Each step's ``count`` is in the same unit as the previous step's, so
    ``of_previous`` and ``lost`` are always meaningful. Where the shape changes
    (findings -> methods -> bodies) that is stated in the label rather than
    smuggled into the arithmetic.
    """
    counts = manifest.stats.counts
    scan = manifest.stats.scan
    scanned = counts.get("findings_discovered", len(manifest.findings))
    located = counts.get("findings_located", scanned)
    distinct_focus = counts.get("distinct_focus_methods", len(manifest.contexts))
    contexts_built = len(manifest.contexts)
    slices = counts.get("slices_expanded", distinct_focus)
    collected = counts.get("methods_collected", len(manifest.methods))
    dropped_at_expand = counts.get("methods_dropped_at_expand", 0)
    proposed = counts.get("methods_proposed", collected + dropped_at_expand)
    kept = counts.get("methods_kept", len(manifest.methods))
    read = counts.get("bodies_read", len(manifest.methods))
    inlined = sum(len(context.methods) for context in manifest.contexts)

    steps: list[FunnelStep] = [
        FunnelStep(
            key="discovered",
            label="findings from the scanner",
            count=scanned,
            of_previous=None,
            of_first=1.0,
            lost=0,
            note=_scan_note(scan),
        )
    ]
    steps.append(
        _step(
            manifest,
            key="located",
            label="findings resolved to an enclosing method",
            count=located,
            previous=scanned,
            first=scanned,
            rules={"locate_failed", "max_contexts"},
        )
    )
    steps.append(
        _step(
            manifest,
            key="focus_methods",
            label="distinct methods carrying findings",
            count=distinct_focus,
            previous=located,
            first=scanned,
            rules=set(),
            note=(
                f"{counts.get('findings_merged_into_existing_method', 0)} finding(s) shared a "
                "method with another finding, so fewer methods than findings is normal"
            ),
        )
    )
    steps.append(
        _step(
            manifest,
            key="contexts",
            label="contexts built (one per focus method)",
            count=contexts_built,
            previous=distinct_focus,
            first=scanned,
            rules={"max_contexts"},
        )
    )
    steps.append(
        _step(
            manifest,
            key="slices",
            label="call-graph slices expanded",
            count=slices,
            previous=contexts_built,
            first=scanned,
            rules=set(),
        )
    )
    steps.append(
        _step(
            manifest,
            key="proposed",
            label="methods proposed by walking the graph (gross)",
            count=proposed,
            previous=kept,  # same unit: methods
            first=scanned,
            rules=set(),
            note=(
                f"{dropped_at_expand} node(s) were reached but their fan-out was refused by a "
                "cap, so the walk stopped earlier than the graph allowed"
            ),
        )
    )
    steps.append(
        _step(
            manifest,
            key="kept",
            label="methods kept in the bundle (net, after every cap)",
            count=kept,
            previous=proposed,
            first=scanned,
            rules={
                "max_nodes",
                "max_depth",
                "max_callers_per_node",
                "max_callees_per_node",
            },
        )
    )
    steps.append(
        _step(
            manifest,
            key="read",
            label="method bodies read from disk",
            count=read,
            previous=kept,
            first=scanned,
            rules={"unreadable", "max_total_chars"},
        )
    )
    steps.append(
        _step(
            manifest,
            key="inlined",
            label="method bodies actually inlined into a context",
            count=inlined,
            previous=read,
            first=scanned,
            rules={"max_total_chars", "max_chars_per_method"},
        )
    )
    return steps


def timeline(manifest: AnalysisBundleManifest) -> list[StageTiming]:
    stage_ms = manifest.stats.stage_ms or {}
    total = sum(stage_ms.values()) or 1
    out: list[StageTiming] = []
    for key, ms in stage_ms.items():
        out.append(
            StageTiming(
                key=key,
                label=STAGE_LABELS.get(key, key),
                ms=ms,
                share=ms / total,
                # The package write is excluded from the pre-write duration snapshot,
                # so its presence means the run reached the end.
                cached=False,
            )
        )
    out.sort(key=lambda s: -s.ms)
    return out


def providers(manifest: AnalysisBundleManifest) -> list[ProviderStat]:
    method_counts: Counter[str] = Counter()
    edge_counts: Counter[str] = Counter()
    focus_counts: Counter[str] = Counter()

    for method in manifest.methods:
        method_counts[method.provider.value] += 1
    for edge in manifest.edges:
        edge_counts[edge.provider.value] += 1
    for context in manifest.contexts:
        focus_provider = context.focus.provider.value
        focus_counts[focus_provider] += 1

    keys = set(method_counts) | set(edge_counts)
    out: list[ProviderStat] = []
    for key in sorted(keys, key=lambda k: (TRUST_ORDER.get(_trust_of(k), 9), k)):
        meta = PROVIDER_NOTES.get(key, {})
        out.append(
            ProviderStat(
                provider=key,
                label=meta.get("label", key),
                trust=meta.get("trust", "unknown"),
                confidence=meta.get("confidence", 0.0),
                note=meta.get("note", ""),
                methods=method_counts.get(key, 0),
                edges=edge_counts.get(key, 0),
                focus_methods=focus_counts.get(key, 0),
            )
        )
    return out


def context_views(manifest: AnalysisBundleManifest) -> list[ContextView]:
    findings_by_id = {f.finding_id: f for f in manifest.findings}
    methods_by_id = {m.method_id: m for m in manifest.methods}
    out: list[ContextView] = []

    for context in manifest.contexts:
        finding_rows = []
        for fid in context.finding_ids:
            finding = findings_by_id.get(fid)
            if finding is None:
                finding_rows.append({"finding_id": fid, "missing": True})
                continue
            finding_rows.append(
                {
                    "finding_id": finding.finding_id,
                    "rule_id": finding.rule_id,
                    "severity": finding.severity.value,
                    "location": f"{finding.path}:{finding.region.start_line + 1}",
                    "message": finding.message,
                    "snippet": finding.snippet,
                }
            )

        method_rows = []
        for ref in context.methods:
            method_rows.append(_method_row(ref, methods_by_id))
        method_rows.sort(key=lambda r: (r["depth"], r["name"]))

        edge_rows = []
        for edge in context.edges:
            caller = methods_by_id.get(edge.caller_id)
            callee = methods_by_id.get(edge.callee_id)
            edge_rows.append(
                {
                    "caller_id": edge.caller_id,
                    "callee_id": edge.callee_id,
                    "caller_name": caller.qualified_name if caller else edge.caller_id,
                    "callee_name": callee.qualified_name if callee else edge.callee_id,
                    "direction": edge.direction.value,
                    "provider": edge.provider.value,
                    "trust": _trust_of(edge.provider.value),
                    "confidence": edge.confidence,
                    "call_site": (
                        f"{edge.call_site.path}:{edge.call_site.start_line + 1}"
                        if edge.call_site
                        else None
                    ),
                    "snippet": edge.call_site_snippet,
                }
            )
        edge_rows.sort(key=lambda r: (r["caller_name"], r["callee_name"]))

        depth_histogram: Counter[str] = Counter()
        for ref in context.methods:
            depth_histogram[str(ref.depth)] += 1
        provider_mix: Counter[str] = Counter()
        for ref in context.methods:
            provider_mix[ref.provider.value] += 1

        focus = methods_by_id.get(context.focus_id, context.focus)
        severities = [
            findings_by_id[f].severity.value
            for f in context.finding_ids
            if f in findings_by_id
        ]
        focus_ref = next((r for r in context.methods if r.method.method_id == focus.method_id), None)

        out.append(
            ContextView(
                context_id=context.context_id,
                focus_id=focus.method_id,
                focus_name=focus.qualified_name,
                focus_location=f"{focus.path}:{focus.region.start_line + 1}-{focus.region.end_line + 1}",
                focus_provider=focus.provider.value,
                worst_severity=_worst_severity(severities),
                findings=finding_rows,
                methods=method_rows,
                edges=edge_rows,
                estimated_tokens=context.estimated_tokens,
                total_chars=context.total_chars,
                truncated=context.truncated,
                prunes=[
                    {
                        "rule": p.rule,
                        "detail": p.detail,
                        "method_id": p.method_id,
                        "location": f"{p.path}:{(p.line or 0) + 1}" if p.path else None,
                    }
                    for p in manifest.prunes
                    if p.method_id is None
                    or p.method_id in {r.method.method_id for r in context.methods}
                    or p.method_id == focus.method_id
                ],
                depth_histogram=dict(sorted(depth_histogram.items(), key=lambda kv: int(kv[0]))),
                provider_mix=dict(provider_mix),
                unreached_focus=focus_ref is None,
            )
        )
    return out


def scan_summary(manifest: AnalysisBundleManifest) -> dict[str, Any] | None:
    scan = manifest.stats.scan
    if scan is None:
        return None
    return {
        "engine": scan.engine,
        "engine_version": scan.engine_version,
        "sarif_path": scan.sarif_path,
        "command": scan.command,
        "command_line": " ".join(scan.command),
        "returncode": scan.returncode,
        "configured": scan.configured,
        "zero_findings_is_suspicious": scan.zero_findings_is_suspicious,
        "failure_mode": scan.failure_mode,
        "stderr_tail": scan.stderr_tail,
        "rule_counts": scan.rule_counts,
        "severity_counts": scan.severity_counts,
        "top_paths": scan.top_paths,
    }


def diff(left: AnalysisBundleManifest, right: AnalysisBundleManifest) -> dict[str, Any]:
    """Compare two runs: is this bundle a superset, a subset, or just different?"""
    left_ids = {m.method_id for m in left.methods}
    right_ids = {m.method_id for m in right.methods}
    left_findings = {f.finding_id for f in left.findings}
    right_findings = {f.finding_id for f in right.findings}

    def counters(manifest: AnalysisBundleManifest) -> dict[str, int]:
        return {
            "contexts": len(manifest.contexts),
            "methods": len(manifest.methods),
            "findings": len(manifest.findings),
            "edges": len(manifest.edges),
            "prunes": len(manifest.prunes),
            "degradations": len(manifest.degradations),
            "estimated_tokens": manifest.estimated_tokens,
            "duration_ms": manifest.stats.duration_ms,
        }

    left_counts, right_counts = counters(left), counters(right)
    return {
        "left": {"bundle_id": left.bundle_id, "run_id": left.run_id, **left_counts},
        "right": {"bundle_id": right.bundle_id, "run_id": right.run_id, **right_counts},
        "delta": {k: right_counts[k] - left_counts[k] for k in left_counts},
        "methods": {
            "only_left": sorted(left_ids - right_ids),
            "only_right": sorted(right_ids - left_ids),
            "shared": len(left_ids & right_ids),
        },
        "findings": {
            "only_left": sorted(left_findings - right_findings),
            "only_right": sorted(right_findings - left_findings),
            "shared": len(left_findings & right_findings),
        },
        "stage_delta_ms": {
            key: right.stats.stage_ms.get(key, 0) - left.stats.stage_ms.get(key, 0)
            for key in set(left.stats.stage_ms) | set(right.stats.stage_ms)
        },
    }


# ----------------------------------------------------------------------
def method_index(manifest: AnalysisBundleManifest) -> dict[str, Any]:
    """Where did each method come from? The provenance answer, per method."""
    findings_by_method: dict[str, list[str]] = defaultdict(list)
    contexts_by_method: dict[str, list[str]] = defaultdict(list)
    best_ref: dict[str, MethodRef] = {}
    for context in manifest.contexts:
        for ref in context.methods:
            method_id = ref.method.method_id
            contexts_by_method[method_id].append(context.context_id)
            if ref.is_focus:
                findings_by_method[method_id].extend(context.finding_ids)
            previous = best_ref.get(method_id)
            if previous is None or ref.depth < previous.depth:
                best_ref[method_id] = ref

    names = {m.method_id: m.qualified_name for m in manifest.methods}
    rows = []
    for method in manifest.methods:
        ref = best_ref.get(method.method_id)
        rows.append(
            {
                "method_id": method.method_id,
                "qualified_name": method.qualified_name,
                "location": f"{method.path}:{method.region.start_line + 1}-{method.region.end_line + 1}",
                "path": method.path,
                "start_line": method.region.start_line,
                "lines": method.region.line_span,
                "kind": method.kind.value,
                "language": method.language,
                "provider": method.provider.value,
                "trust": _trust_of(method.provider.value),
                "is_focus": bool(ref and ref.is_focus),
                "depth": ref.depth if ref else None,
                "direction": ref.direction.value if ref and ref.direction else None,
                "via": ref.via if ref else None,
                "origin_chain": [names.get(mid, mid) for mid in (ref.origin_path if ref else [])],
                "contexts": sorted(set(contexts_by_method.get(method.method_id, []))),
                "finding_ids": sorted(set(findings_by_method.get(method.method_id, []))),
            }
        )
    rows.sort(key=lambda r: (r["path"], r["start_line"]))
    return {"count": len(rows), "methods": rows}


def _method_row(ref: MethodRef, methods_by_id: dict[str, MethodSymbol]) -> dict[str, Any]:
    method = methods_by_id.get(ref.method.method_id, ref.method)
    names = {mid: mid for mid in ref.origin_path}
    return {
        "method_id": method.method_id,
        "name": method.name,
        "qualified_name": method.qualified_name,
        "location": f"{method.path}:{method.region.start_line + 1}-{method.region.end_line + 1}",
        "lines": method.region.line_span,
        "kind": method.kind.value,
        "language": method.language,
        "provider": ref.provider.value,
        "trust": _trust_of(ref.provider.value),
        "is_focus": ref.is_focus,
        "depth": ref.depth,
        "direction": ref.direction.value if ref.direction else None,
        "via": ref.via,
        # The client resolves these ids against the method table it already has.
        "origin_chain": [names[mid] for mid in ref.origin_path],
    }


def _step(
    manifest: AnalysisBundleManifest,
    *,
    key: str,
    label: str,
    count: int,
    previous: int,
    first: int,
    rules: set[str],
    note: str | None = None,
) -> FunnelStep:
    prunes = [p for p in manifest.prunes if p.rule in rules] if rules else []
    lost = max(0, previous - count)
    reasons: list[str] = []
    for prune in prunes:
        if prune.rule not in reasons:
            reasons.append(prune.rule)
    if lost and not reasons:
        reasons.append("not attributable to a recorded prune (see run notes)")
    return FunnelStep(
        key=key,
        label=label,
        count=count,
        of_previous=(count / previous) if previous else None,
        of_first=(count / first) if first else None,
        lost=lost,
        loss_reasons=reasons,
        lost_items=[
            {
                "rule": p.rule,
                "detail": p.detail,
                "method_id": p.method_id,
                "location": f"{p.path}:{(p.line or 0) + 1}" if p.path else None,
            }
            for p in prunes[:25]
        ],
        note=note,
    )


def _scan_note(scan: ScanRecord | None) -> str | None:
    if scan is None:
        return None
    parts = [f"engine={scan.engine}"]
    if scan.engine_version:
        parts.append(f"version={scan.engine_version}")
    parts.append("rules=explicit" if scan.configured else "rules=unconfigured")
    return ", ".join(parts)


def _trust_of(provider: str) -> str:
    return PROVIDER_NOTES.get(provider, {}).get("trust", "unknown")


def _worst_severity(severities: list[str]) -> str:
    order = {"error": 0, "warning": 1, "info": 2, "note": 3}
    if not severities:
        return "none"
    return min(severities, key=lambda s: order.get(s, 4))


def edge_direction_label(direction: EdgeDirection) -> str:
    return "caller (entry side)" if direction is EdgeDirection.CALLER else "callee (sink side)"
