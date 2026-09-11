"""Domain model for the pipeline.

Contract (v1)::

    Finding            -> a static-scan hit (opengrep/SARIF)
    MethodSymbol       -> the enclosing callable located for that hit
    CodeRegion         -> a byte/line range inside one file, provenance tagged
    CallEdge           -> caller -> callee with the evidence that produced it
    MethodRef          -> a symbol + the provider that found it
    MethodContext      -> one assembled analysis unit (sink + call-graph slice)
    AnalysisBundle     -> what gets handed to the AI
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field

from aegis_core.utils import estimate_tokens


def _now() -> datetime:
    return datetime.now(timezone.utc)


class Severity(str, Enum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"
    NOTE = "note"


class SymbolKind(str, Enum):
    FUNCTION = "function"
    METHOD = "method"
    CONSTRUCTOR = "constructor"
    CLASS = "class"
    MODULE = "module"
    UNKNOWN = "unknown"


class EdgeDirection(str, Enum):
    """Which way the call graph was walked for a given edge."""

    CALLER = "caller"  # who calls the sink (attack / taint entry side)
    CALLEE = "callee"  # what the sink calls (sink side)


class Provider(str, Enum):
    """How a piece of information was obtained. Never lose this - it is the trust level."""

    OPENGREP = "opengrep"
    LSP_CALL_HIERARCHY = "lsp_call_hierarchy"
    LSP_DOCUMENT_SYMBOL = "lsp_document_symbol"
    LSP_DEFINITION = "lsp_definition"
    LSP_REFERENCES = "lsp_references"
    LSP_IMPLEMENTATION = "lsp_implementation"
    SYNTAX_REGEX = "syntax_regex"
    FILE_RANGE = "file_range"
    MANUAL = "manual"
    NONE = "none"


class CodeRegion(BaseModel):
    """A 0-based LSP-style range plus absolute character offsets for cheap slicing."""

    path: str = Field(description="Path relative to the workspace root when possible.")
    start_line: int = Field(0, ge=0)
    start_char: int = Field(0, ge=0)
    end_line: int = Field(0, ge=0)
    end_char: int = Field(0, ge=0)
    start_offset: int | None = None
    end_offset: int | None = None

    @property
    def line_span(self) -> int:
        return max(0, self.end_line - self.start_line)

    def contains(self, line: int, char: int = 0) -> bool:
        if line < self.start_line or line > self.end_line:
            return False
        if line == self.start_line and char < self.start_char:
            return False
        if line == self.end_line and char > self.end_char:
            return False
        return True

    def contains_region(self, other: CodeRegion) -> bool:
        if other.start_line < self.start_line or other.end_line > self.end_line:
            return False
        if other.start_line == self.start_line and other.start_char < self.start_char:
            return False
        if other.end_line == self.end_line and other.end_char > self.end_char:
            return False
        return True


class Finding(BaseModel):
    """One opengrep/SARIF result."""

    finding_id: str
    rule_id: str
    message: str = ""
    severity: Severity = Severity.WARNING
    path: str
    region: CodeRegion
    snippet: str = ""
    properties: dict[str, Any] = Field(default_factory=dict)
    fingerprint: str | None = None
    provider: Provider = Provider.OPENGREP


class MethodSymbol(BaseModel):
    """A callable located in the workspace."""

    method_id: str
    name: str
    qualified_name: str
    kind: SymbolKind = SymbolKind.FUNCTION
    path: str
    region: CodeRegion
    language: str | None = None
    parent: str | None = Field(default=None, description="Enclosing class/module qualified name.")
    provider: Provider = Provider.LSP_DOCUMENT_SYMBOL
    detail: str | None = None
    signature: str | None = None


class MethodRef(BaseModel):
    """A method plus why we believe it belongs in the bundle."""

    method: MethodSymbol
    provider: Provider
    depth: int = 0
    direction: EdgeDirection | None = None
    via: str | None = Field(default=None, description="Call site snippet or edge evidence.")
    origin_path: list[str] = Field(
        default_factory=list,
        description=(
            "method_ids from the focus down to this method, inclusive of both ends. "
            "This is the provenance chain: it answers 'why is this method here?' "
            "without the reader having to re-walk the graph."
        ),
    )
    is_focus: bool = Field(default=False, description="True for the sink-containing method.")

    @property
    def hops(self) -> int:
        """Number of edges between the focus and this method."""
        return max(0, len(self.origin_path) - 1) if self.origin_path else self.depth


class CallEdge(BaseModel):
    caller_id: str
    callee_id: str
    direction: EdgeDirection
    provider: Provider
    confidence: float = Field(1.0, ge=0.0, le=1.0)
    call_site: CodeRegion | None = None
    call_site_snippet: str = ""
    notes: str | None = None


class PruneDecision(BaseModel):
    """Why something was cut. The AI and the human reviewer both need this."""

    rule: str
    detail: str
    method_id: str | None = None
    path: str | None = None
    line: int | None = None
    provider: Provider = Provider.NONE


class MethodContext(BaseModel):
    """One assembled analysis unit: sink + call-graph slice. This is the AI input atom."""

    context_id: str
    finding_ids: list[str] = Field(default_factory=list)
    focus_id: str
    focus: MethodSymbol
    methods: list[MethodRef] = Field(default_factory=list)
    edges: list[CallEdge] = Field(default_factory=list)
    total_chars: int = 0
    estimated_tokens: int = 0
    truncated: bool = False


class Coverage(BaseModel):
    discoverable: int = 0
    bundled: int = 0
    rejected: int = 0
    deduped: int = 0

    @property
    def ratio(self) -> float:
        return (self.bundled / self.discoverable) if self.discoverable else 1.0


class Degradation(BaseModel):
    """A capability that was requested but unavailable. Never fail the run for it."""

    capability: str
    reason: str
    impact: str
    path: str | None = None
    language: str | None = None


class ScanRecord(BaseModel):
    """What the scanner was actually asked to do. Observability needs the input, not just the output."""

    engine: str
    engine_version: str = ""
    sarif_path: str | None = None
    command: list[str] = Field(default_factory=list)
    location: str = Field(
        default="in-process",
        description=(
            "'in-process' or 'remote'. A remote record's `command` and `sarif_path` are "
            "real but name paths inside the scan service's filesystem, so whoever reads "
            "the bundle must not try to open them."
        ),
    )
    returncode: int = 0
    configured: bool = False
    zero_findings_is_suspicious: bool = False
    failure_mode: str | None = Field(
        default=None,
        description=(
            "Set when the scan could not yield findings at all (bad exit code, missing or "
            "empty SARIF, unparseable SARIF). Distinguishes 'the scanner broke' from "
            "'the repository is clean'."
        ),
    )
    stderr_tail: str = ""
    rule_counts: dict[str, int] = Field(default_factory=dict)
    severity_counts: dict[str, int] = Field(default_factory=dict)
    top_paths: list[tuple[str, int]] = Field(default_factory=list)


class RunStats(BaseModel):
    started_at: datetime = Field(default_factory=_now)
    finished_at: datetime | None = None
    duration_ms: int = 0
    stage_ms: dict[str, int] = Field(default_factory=dict)
    counts: dict[str, int] = Field(default_factory=dict)
    scan: ScanRecord | None = None


class AnalysisBundleManifest(BaseModel):
    schema_version: str = "1.0"
    bundle_id: str
    run_id: str
    created_at: datetime = Field(default_factory=_now)
    workspace_root: str
    focus_count: int = 0
    methods: list[MethodSymbol] = Field(default_factory=list)
    findings: list[Finding] = Field(default_factory=list)
    edges: list[CallEdge] = Field(default_factory=list)
    contexts: list[MethodContext] = Field(default_factory=list)
    prunes: list[PruneDecision] = Field(default_factory=list)
    degradations: list[Degradation] = Field(default_factory=list)
    coverage: Coverage = Field(default_factory=Coverage)
    stats: RunStats = Field(default_factory=RunStats)
    capabilities: dict[str, Any] = Field(default_factory=dict)
    total_chars: int = 0
    estimated_tokens: int = 0


class PromptBlock(BaseModel):
    """AI-facing rendering of one chunk of the bundle."""

    block_id: str
    title: str
    content: str
    estimated_tokens: int = 0
    method_ids: list[str] = Field(default_factory=list)


class AnalysisBundle(BaseModel):
    """In-memory result of the assembly stage."""

    manifest: AnalysisBundleManifest
    methods: dict[str, MethodSymbol] = Field(default_factory=dict)
    sources: dict[str, str] = Field(default_factory=dict, description="method_id -> full body")
    prompts: list[PromptBlock] = Field(default_factory=list)
    package_path: str | None = None

    def recompute_totals(self) -> None:
        chars = sum(len(s) for s in self.sources.values())
        self.manifest.total_chars = chars
        self.manifest.estimated_tokens = estimate_tokens("\n".join(self.sources.values()))
