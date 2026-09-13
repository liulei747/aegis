"""Read-only views over a bundle manifest.

This module is the *only* place that turns raw bundle facts into something a
human reads. It is deliberately pure: it takes an
:class:`~aegis_contracts.domain.AnalysisBundleManifest` and returns derived views,
never mutating anything and never inventing a number that is not in the manifest.

Two consequences worth keeping:

* the JSON API publishes these views, and anything that reads them renders the same
  numbers, so a page and its JSON cannot disagree about a bundle;
* deleting this module (or any reader of it) cannot change a bundle.

**What this module does not do is decide how to present.** It was once the only place
allowed to compute anything, on the theory that a front-end which computes will compute
differently from the API. The front-end is now a separate deployment that computes its own
counts, shares and totals (`frontend/src/format.ts`), so the rule is narrower and stated
where it belongs: this module derives what a *bundle* is, and the front-end derives what a
*screen* shows. `verdicts_view` used to sit on the wrong side of that line -- it aggregated
an AI report into display counts -- and was removed for it.

The central idea is the **funnel**: a pipeline that silently loses findings is
worse than one that fails, so every step from "scanner output" to "method inlined
in a bundle" is reported as an explicit count, and any step with losses carries
the prune rules that caused them plus the concrete items where they are known.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any

from aegis_contracts.domain import (
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
        "label": "LSP 调用层级",
        "trust": "fact",
        "confidence": 1.0,
        "note": "语言服务器直接解析出了这个调用方/被调用方",
    },
    Provider.LSP_DEFINITION.value: {
        "label": "LSP 定义",
        "trust": "strong",
        "confidence": 0.9,
        "note": "被调用方由词法调用点经 textDocument/definition 解析得到",
    },
    Provider.LSP_IMPLEMENTATION.value: {
        "label": "LSP 实现",
        "trust": "strong",
        "confidence": 0.8,
        "note": "抽象/接口方法的派发目标",
    },
    Provider.LSP_REFERENCES.value: {
        "label": "LSP 引用",
        "trust": "weak",
        "confidence": 0.6,
        "note": "引用确实存在，但无法证明它是一次调用",
    },
    Provider.LSP_DOCUMENT_SYMBOL.value: {
        "label": "LSP 文档符号",
        "trust": "fact",
        "confidence": 1.0,
        "note": "方法边界取自服务器返回的符号范围",
    },
    Provider.SYNTAX_REGEX.value: {
        "label": "语法启发式",
        "trust": "guess",
        "confidence": 0.4,
        "note": "没有语言服务器：作用域与调用点都是词法近似",
    },
    Provider.OPENGREP.value: {
        "label": "静态扫描器",
        "trust": "fact",
        "confidence": 1.0,
        "note": "opengrep/SARIF 的原始命中",
    },
    Provider.FILE_RANGE.value: {
        "label": "文件范围兜底",
        "trust": "guess",
        "confidence": 0.2,
        "note": "最后兜底的范围，边界只能视为近似",
    },
    Provider.NONE.value: {
        "label": "无",
        "trust": "unknown",
        "confidence": 0.0,
        "note": "没有记录任何来源",
    },
}

TRUST_ORDER = {"fact": 0, "strong": 1, "weak": 2, "guess": 3, "unknown": 4}

STAGE_LABELS: dict[str, str] = {
    "scan": "静态扫描（opengrep/SARIF）",
    "setup": "工作区 + 语言服务器",
    "locate": "定位所属方法",
    "expand": "扩展调用图",
    "read": "读取完整方法体",
    "assemble": "去重 + 组装上下文",
    "package": "写入分析包",
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
        flags.append("扫描器在一次未配置规则的扫描中返回了零命中")
    if not manifest.findings:
        flags.append("完全没有命中：没有任何内容被分析")
    if manifest.coverage.rejected:
        flags.append(f"{manifest.coverage.rejected} 个命中从未进入任何分析包")
    if any(c.truncated for c in manifest.contexts):
        flags.append("至少有一个上下文被截断")
    if any(d.capability == "lsp" for d in manifest.degradations):
        flags.append("没有任何语言服务器参与：每条边都是启发式的")
    if scan is not None and scan.stderr_tail and not manifest.findings:
        flags.append("扫描器向 stderr 写了输出，且没有产生任何命中")

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
    fanouts_skipped = counts.get("fanouts_skipped", 0)
    proposed = counts.get("methods_proposed", collected + dropped_at_expand)
    kept = counts.get("methods_kept", len(manifest.methods))
    read = counts.get("bodies_read", len(manifest.methods))
    inlined = sum(len(context.methods) for context in manifest.contexts)

    steps: list[FunnelStep] = [
        FunnelStep(
            key="discovered",
            label="扫描器产出的命中",
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
            label="命中定位到所属方法",
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
            label="带命中的去重方法",
            count=distinct_focus,
            previous=located,
            first=scanned,
            rules=set(),
            note=(
                f"有 {counts.get('findings_merged_into_existing_method', 0)} 个命中与另一个命中"
                "落在同一个方法上，因此方法数少于命中数是正常的"
            ),
        )
    )
    steps.append(
        _step(
            manifest,
            key="contexts",
            label="构建的上下文（每个焦点方法一个）",
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
            label="扩展出的调用图切片",
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
            label="沿调用图遍历提出的方法（毛数）",
            count=proposed,
            previous=kept,  # same unit: methods
            first=scanned,
            rules=set(),
            note=(
                f"{dropped_at_expand} 个已到达的方法被节点上限拒绝"
                if dropped_at_expand
                else None
            ),
        )
    )
    steps.append(
        _step(
            manifest,
            key="kept",
            label="最终保留在分析包中的方法（净数，已套用全部上限）",
            count=kept,
            previous=proposed,
            first=scanned,
            rules={
                "max_nodes",
                "max_depth",
                "max_callers_per_node",
                "max_callees_per_node",
            },
            note=(
                # The arithmetic above cannot see these: a fan-out we never looked
                # up contributes no count at all, only a prune. Say it out loud, or
                # a truncated walk reads as a complete one.
                f"遍历还跳过了 {fanouts_skipped} 次被上限拦下的扇出查找，"
                "这些方法从未被计数，就已经缺席"
                if fanouts_skipped
                else None
            ),
        )
    )
    steps.append(
        _step(
            manifest,
            key="read",
            label="从磁盘读取的方法正文",
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
            label="真正内联进上下文的方法正文",
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
        reasons.append("无法归因于任何已记录的裁剪（见运行说明）")
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
    parts = [f"引擎={scan.engine}"]
    if scan.engine_version:
        parts.append(f"版本={scan.engine_version}")
    parts.append("规则=显式" if scan.configured else "规则=未配置")
    return ", ".join(parts)


def _trust_of(provider: str) -> str:
    return PROVIDER_NOTES.get(provider, {}).get("trust", "unknown")


def _worst_severity(severities: list[str]) -> str:
    order = {"error": 0, "warning": 1, "info": 2, "note": 3}
    if not severities:
        return "none"
    return min(severities, key=lambda s: order.get(s, 4))


def edge_direction_label(direction: EdgeDirection) -> str:
    return "调用方（入口侧）" if direction is EdgeDirection.CALLER else "被调用方（汇聚侧）"
