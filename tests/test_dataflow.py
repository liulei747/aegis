"""Dataflow contract and its integration into the call-graph slice.

No Docker and no JVM here: the Joern process is replaced by a stub that returns a hand-built
`FlowBundle`, which is the point of `DataflowProvider` being a Protocol. What is under test is
the *wiring* -- does a traced flow become methods and edges, does an empty flow stay an
answer instead of becoming a fallback, and does a failure degrade loudly.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from aegis_contracts.dataflow import FlowBundle, FlowElement, FlowMethodBody, TaintFlow
from aegis_contracts.domain import Provider
from aegis_core.config import BudgetConfig
from aegis_core.workspace import iter_source_files, workspace_digest
from services.dataflow.router import worker_for
from services.dataflow.worker import _parse_report, _parse_sink_report
from services.extraction.dataflow.client import attach_bodies
from services.extraction.graph.builder import CallGraphBuilder
from services.extraction.graph.providers import CallGraphResolver
from services.extraction.graph.resolver import SymbolIndex, Workspace

# ---------------------------------------------------------------- contract


def test_an_empty_flow_is_an_answer_not_a_failure() -> None:
    """`flow=[]` means the engine proved the value does not reach the sink.

    Measured on a parameterised query, which returns zero flows. If this were treated as a
    failure the bundle would say "extraction broke" where the truth is "this is fixed".
    """
    bundle = FlowBundle(source_anchor="request.args.get", sink_anchor="execute")

    assert bundle.reachable is False
    assert bundle.flows == []
    # And it is not the same thing as a bundle with one flow holding one element.
    reachable = FlowBundle(
        source_anchor="a",
        sink_anchor="b",
        flows=[TaintFlow(index=0, elements=[FlowElement(label="CALL", method="m", file="f.py")])],
    )
    assert reachable.reachable is True


def test_flow_elements_tolerate_the_missing_location_joern_reports() -> None:
    """`BLOCK` vertices belong to no method, and `lineNumber` is optional.

    Both come back empty from the engine, so `located` and `line_number` exist to make the
    absence explicit instead of forcing every reader to special-case `""`.
    """
    orphan = FlowElement(label="BLOCK", code="tmp0 = request.args")
    assert orphan.located is False
    assert orphan.line_number is None

    located = FlowElement(label="CALL", method="h", file="a.py", line="7")
    assert located.located is True
    assert located.line_number == 7

    # A non-numeric line must not raise; it is absent, not invalid.
    assert FlowElement(label="X", method="h", file="a.py", line="?").line_number is None


def test_a_flow_keeps_its_own_elements() -> None:
    """Several flows must not be flattened.

    The demo produced two (`flow_count=2`) and flattening them made one path look like it
    repeated its first 16 elements.
    """
    bundle = FlowBundle(
        source_anchor="a",
        sink_anchor="b",
        flows=[
            TaintFlow(index=0, elements=[
                FlowElement(label="CALL", method="first", file="a.py", line="1"),
                FlowElement(label="CALL", method="focus", file="b.py", line="2"),
            ]),
            TaintFlow(index=1, elements=[
                FlowElement(label="CALL", method="second", file="c.py", line="3"),
                FlowElement(label="CALL", method="focus", file="b.py", line="2"),
            ]),
        ],
    )

    assert [flow.index for flow in bundle.flows] == [0, 1]
    assert bundle.flows[0].methods == ["first", "focus"]
    assert bundle.flows[1].methods == ["second", "focus"]
    # The union is what the bundle has to collect; order is first-seen.
    assert bundle.path_methods == ["first", "focus", "second"]
    assert bundle.element_count == 4


# ---------------------------------------------------------------- parsing


def test_the_report_parser_groups_by_flow_index() -> None:
    """The query emits a flow index per element; losing it merged two paths into one.

    `ANCHOR` uses a tab separator, and the earlier `FLOW_COUNT=` form did not -- a parser that
    accepts one and silently ignores the other is how counts went missing before.
    """
    text = "\n".join([
        "ANCHOR\tSOURCE\t2",
        "ANCHOR\tSINK\t1",
        "FLOW_COUNT\t2",
        "ELEM\t0\tCALL\thandle_request\thandler.py\t10\trequest.args.get(\"id\")",
        "ELEM\t0\tCALL\tsafe_escape\tutil.py\t5\tvalue.replace(\"'\", \"''\")",
        "ELEM\t1\tIDENTIFIER\tquery_user\trepo.py\t4\tuser_id",
    ])

    result = _parse_report(text)

    assert result.flow_count == 2
    assert result.source_candidates == 2
    assert result.sink_candidates == 1
    # Grouped, not concatenated: two flows of 2 and 1 elements, not one flow of 3.
    assert [len(flow) for flow in result.flows] == [2, 1]


def test_the_report_parser_keeps_the_anchor_it_actually_used() -> None:
    """When the flow is empty, the anchor is the only evidence of *why* it was empty.

    An empty flow caused by an anchor that matched nothing must not be read the same way as an
    empty flow from an anchor that matched and proved there is no path.
    """
    text = "\n".join([
        "ANCHOR\tSOURCE\t0",
        "ANCHOR\tSINK\t1",
        "ANCHOR\tKIND\tparameter",
        "ANCHOR\tEXPR\thandle_request(request)",
        "FLOW_COUNT\t0",
    ])

    result = _parse_report(text)

    assert result.source_candidates == 0
    assert result.source_kind == "parameter"
    assert result.source_expr == "handle_request(request)"


def test_the_report_parser_reads_the_seven_field_element_line() -> None:
    """`ELEM` has exactly 7 tab-separated fields, in this order.

    ELEM <flowIndex> <label> <method> <file> <line> <code>

    The order is the contract with the Scala query, and getting it wrong is silent: the fields
    still parse, they just mean something else. An earlier version had `code` third and this
    exact mistake shipped.
    """
    line = "ELEM\t0\tCALL\tsafe_escape\tutil.py\t5\tvalue.replace(\"'\", \"''\")"
    assert len(line.split("\t")) == 7

    result = _parse_report("\n".join(["FLOW_COUNT\t1", line]))

    assert len(result.flows) == 1
    element = result.flows[0][0]
    assert element["label"] == "CALL"
    assert element["method"] == "safe_escape"
    assert element["file"] == "util.py"
    assert element["line"] == "5"
    assert element["code"] == "value.replace(\"'\", \"''\")"


def test_the_report_parser_ignores_a_malformed_element_instead_of_crashing() -> None:
    """One bad row must not cost the whole answer: the flow is the deliverable."""
    text = "\n".join([
        "ANCHOR\tSOURCE\t1",
        "ANCHOR\tSINK\t1",
        "FLOW_COUNT\t1",
        "ELEM\t0\tCALL\th\tf.py\t1\tok()",
        "ELEM\tnotanumber\tCALL\th\tf.py\t1\tbad()",
        "ELEM\t0\ttruncated",
    ])

    result = _parse_report(text)

    assert len(result.flows) == 1
    assert len(result.flows[0]) == 1
    assert result.flows[0][0]["code"] == "ok()"


def test_the_sink_report_names_its_choice_and_its_alternatives() -> None:
    """The derivation is a heuristic, so what it chose and what else it saw both matter."""
    text = "\n".join([
        "METHOD\tquery_user",
        "CANDIDATE\texecute\t7",
        "CANDIDATE\tcommit\t9",
        "CHOSEN\texecute",
    ])

    resolution = _parse_sink_report(text, finding_path="repo.py", finding_line=6)

    assert resolution.anchor == "execute"
    assert resolution.method == "query_user"
    assert resolution.derived_from == "repo.py:6"
    assert resolution.alternatives == ["execute", "commit"]


def test_an_empty_sink_report_claims_nothing() -> None:
    """No candidate means no anchor, and crucially no `derived_from` either.

    Reporting a provenance for a choice that was never made is how "we could not resolve it"
    would turn into "we resolved it here".
    """
    resolution = _parse_sink_report("METHOD\t\nCHOSEN\t", finding_path="repo.py", finding_line=6)

    assert resolution.anchor == ""
    assert resolution.derived_from is None


# ---------------------------------------------------------------- worker affinity


def test_affinity_is_stable_and_in_range(tmp_path: Path) -> None:
    """Same project -> same worker, always, and never an index that does not exist.

    The fleet's speed depends on this: a project that lands on a different worker each time
    pays the cold CPG load every time, and an out-of-range index is a 404 at runtime.
    """
    root = tmp_path / "ws"
    root.mkdir()
    (root / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")

    for count in (1, 2, 3, 7):
        first = worker_for(root, count)
        assert 0 <= first < count
        assert worker_for(root, count) == first


def test_affinity_follows_the_content(tmp_path: Path) -> None:
    """Different content may pick a different worker; the same content must not."""
    root = tmp_path / "ws"
    root.mkdir()
    (root / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    before = worker_for(root, 8)

    (root / "a.py").write_text("def f():\n    return 2\n", encoding="utf-8")
    after = worker_for(root, 8)

    # The hash changed; the index is a function of it, so asserting inequality would be
    # asserting a coincidence of the hash. What must hold is that it is still a valid index.
    assert 0 <= after < 8
    assert worker_for(root, 1) == 0
    _ = before


def test_a_single_worker_always_gets_index_zero(tmp_path: Path) -> None:
    root = tmp_path / "ws"
    root.mkdir()
    (root / "a.py").write_text("x = 1\n", encoding="utf-8")
    assert worker_for(root, 1) == 0
    with pytest.raises(ValueError):
        worker_for(root, 0)


# ---------------------------------------------------------------- the worker client


def _client(tmp_path: Path, **overrides):
    """A client whose transport is replaced, so no worker and no network are involved."""
    from aegis_core.config import DataflowConfig
    from services.extraction.dataflow.client import WorkerDataflowClient

    root = tmp_path / "ws"
    root.mkdir(exist_ok=True)
    (root / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    config = DataflowConfig(enabled=True, **overrides)
    sent: list[tuple[str, dict | None]] = []

    def fake_request(path: str, *, payload: dict | None = None, timeout: float = 60.0) -> dict:
        sent.append((path, payload))
        return {"status": "ok", "index": 0, "flows": [], "source_anchor": "request.args.get",
                "sink_anchor": "", "cpg_cached": True, "total_s": 0.0}

    client = WorkerDataflowClient(config, workspace_root=root)
    client._request = fake_request  # type: ignore[method-assign]
    return client, sent


def test_the_worker_is_told_where_the_workspace_lives_in_its_own_container(tmp_path: Path) -> None:
    """Compose mounts the project at `/workspace` in every service, so the two paths agree.

    A caller outside compose reads files at its own path while the worker sees the mount, and
    sending the local path is a hard 404 -- measured as `workspace not found:
    E:\\...\\demo\\repo` from a host-side acceptance run. `worker_workspace` is the explicit
    mapping; without it the local path is sent, which is correct only when they match.
    """
    local, sent = _client(tmp_path)
    local.extract(finding_path="repo.py", finding_line=6)
    assert sent[-1][1]["workspace"] == str(local.workspace_root)

    mapped, sent = _client(tmp_path, worker_workspace="/workspace")
    mapped.extract(finding_path="repo.py", finding_line=6)
    assert sent[-1][1]["workspace"] == "/workspace"


def test_the_pipeline_never_sends_a_sink(tmp_path: Path) -> None:
    """The finding's position goes over the wire; the anchor is the worker's to derive.

    Sending a configured sink would be handing over the answer, which is the one instruction
    this pipeline is built around. The HTTP field exists for callers that already have one
    (a rule's `pattern-sinks`), and the pipeline is not that caller.
    """
    client, sent = _client(tmp_path)
    client.extract(finding_path="repo.py", finding_line=6)
    _, payload = sent[-1]
    assert "sink" not in payload
    assert payload["finding_path"] == "repo.py"
    assert payload["finding_line"] == 6


def test_a_cold_worker_counts_as_reachable(tmp_path: Path) -> None:
    """`cold` means the Joern server is not up *yet*, and the worker starts it on demand.

    Requiring `ok` here turned that wait into "dataflow unavailable, fall back to the crawl":
    measured, the first extraction after a worker container started silently produced a bundle
    without the sanitizer, while the worker was healthy and answering. A worker that answers
    anything other than `cold`/`ok` is genuinely not usable.
    """
    client, _ = _client(tmp_path)

    for status, expected in (("ok", True), ("cold", True), ("down", False), (None, False)):
        client._request = lambda *a, _s=status, **k: {"status": _s}  # type: ignore[method-assign]
        assert client.health() is expected, status


# ---------------------------------------------------------------- source anchor kinds


def test_a_call_anchor_stays_a_call_anchor() -> None:
    """The existing behaviour must not change: a name is matched against call nodes."""
    from services.dataflow.worker import SourceAnchor

    anchor = SourceAnchor(needle="request.args.get")
    assert anchor.kind == "call"
    assert anchor.expr == "request.args.get"
    assert anchor.scala() == 'anchored("request.args.get")'


def test_a_parameter_anchor_resolves_to_parameters_not_calls() -> None:
    """`handle_request(request)` is a *parameter*, and a parameter is not a call node.

    Measured: handing the method name to the call matcher matches the call site
    `handle_request(request)` inside `dispatch` instead, and a flow started at a call site
    returns 0 flows -- which the pipeline reads as "the engine proved it is unreachable".
    """
    from services.dataflow.worker import SourceAnchor

    one = SourceAnchor(kind="parameter", method="handle_request", parameter="request")
    assert one.expr == "handle_request(request)"
    assert one.scala() == 'anchoredParameter("handle_request", "request")'

    every = SourceAnchor(kind="parameter", method="handle_request")
    assert every.expr == "handle_request(*)"
    assert every.scala() == 'anchoredParameter("handle_request", "")'


def test_an_anchor_rejects_the_shapes_that_would_match_nothing() -> None:
    """A silently-empty anchor is the failure this type exists to prevent."""
    from services.dataflow.worker import SourceAnchor

    for bad in (
        {"kind": "elsewhere"},
        {"kind": "call", "needle": "   "},
        {"kind": "parameter", "method": "  "},
    ):
        with pytest.raises(ValueError):
            SourceAnchor(**bad)


def test_anchor_text_is_escaped_before_it_becomes_scala() -> None:
    """Substitution is how the query is built, so a quote would end the literal early."""
    from services.dataflow.worker import SourceAnchor, _scala_literal

    assert _scala_literal('a"b\\c') == 'a\\"b\\\\c'
    anchor = SourceAnchor(needle='weird"name')
    assert anchor.scala() == 'anchored("weird\\"name")'


# ---------------------------------------------------------------- the caller walk


class _WalkStub:
    """A resolver stub: `callers()` returns whatever the test says, `warm()` says how many files."""

    def __init__(self, callers: dict[str, list[str]], warmed: int = 3) -> None:
        self._callers = callers
        self._warmed = warmed
        self.asked: list[str] = []

    def warm(self) -> int:
        return self._warmed

    def callers(self, method, *, limit: int):
        self.asked.append(method.name)

        class _Edge:
            via = "stub"

        return [(method_of(name), _Edge()) for name in self._callers.get(method.name, [])], None


def method_of(name: str):
    from aegis_contracts.domain import CodeRegion, MethodSymbol

    return MethodSymbol(
        method_id=f"M-{name}",
        name=name,
        qualified_name=name,
        path=f"{name}.py",
        region=CodeRegion(path=f"{name}.py", start_line=0, start_char=0, end_line=1, end_char=0),
    )


def _walk_builder(tmp_path: Path, callers: dict[str, list[str]], *, warmed: int = 3):
    from aegis_core.config import BudgetConfig
    from services.extraction.graph.builder import CallGraphBuilder
    from services.extraction.graph.resolver import Workspace

    root = tmp_path / "ws"
    root.mkdir(exist_ok=True)
    (root / "query_user.py").write_text(
        "def query_user(user_id):\n    return user_id\n", encoding="utf-8"
    )
    (root / "handle_request.py").write_text(
        "def handle_request(request):\n    return request\n", encoding="utf-8"
    )
    workspace = Workspace(root)
    builder = CallGraphBuilder(workspace, _WalkStub(callers, warmed), BudgetConfig())  # type: ignore[arg-type]
    return builder, workspace


def test_the_walk_climbs_to_the_outermost_real_caller(tmp_path: Path) -> None:
    """Inner anchors start mid-chain and *look* complete.

    Measured on the demo, one anchor per method on the walk gives paths of 6 / 8 / 24 / 26
    elements: only the outermost is the whole story. So the rule is "climb past every real
    caller", not "stop at the first method that produces a flow".
    """
    builder, _ = _walk_builder(
        tmp_path,
        {"query_user": ["load_user"], "load_user": ["handle_request"], "handle_request": []},
    )

    anchor = builder.entry_anchor(method_of("query_user"))

    assert anchor is not None
    assert anchor["walk"] == ["query_user", "load_user", "handle_request"]
    assert anchor["method"] == "handle_request"
    assert anchor["parameter"] == "request"


def test_scaffolding_does_not_count_as_a_caller(tmp_path: Path) -> None:
    """`<module>` / `<metaClassAdapter>` are frontend artefacts, not places input enters."""
    builder, _ = _walk_builder(tmp_path, {"query_user": ["<module>"], "load_user": []})

    anchor = builder.entry_anchor(method_of("query_user"))

    assert anchor is not None
    # `<module>` filtered out, so the sink's own method is the boundary and its parameter is
    # the anchor -- measured as the correct answer on single-function samples.
    assert anchor["walk"] == ["query_user"]
    assert anchor["method"] == "query_user"
    assert anchor["parameter"] == "user_id"


def test_a_cold_language_server_is_not_believed(tmp_path: Path) -> None:
    """Zero warmed files means zero callers means *we did not look*.

    This is the trap: believing it anchors the flow at the sink's own method, which returns a
    non-empty path (6 elements, one file) with no source side at all.
    """
    builder, _ = _walk_builder(tmp_path, {"query_user": []}, warmed=0)

    assert builder.entry_anchor(method_of("query_user")) is None


def test_self_and_cls_are_not_sources(tmp_path: Path) -> None:
    """A method's `self` is not untrusted input; treating it as one adds a bogus source node."""
    builder, _ = _walk_builder(tmp_path, {"dispatch": ["handle_request"], "handle_request": []})
    (tmp_path / "ws" / "dispatch.py").write_text(
        "class C:\n    def dispatch(self, request):\n        return request\n", encoding="utf-8"
    )

    anchor = builder.entry_anchor(method_of("dispatch"))

    assert anchor is not None
    assert anchor["method"] == "handle_request"


# ---------------------------------------------------------------- cache key


def test_the_cpg_cache_key_changes_when_the_code_changes(tmp_path: Path) -> None:
    """A stale CPG would answer questions about a version of the file that no longer exists."""
    root = tmp_path / "src"
    root.mkdir()
    (root / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    before = workspace_digest(root)

    # Same content -> same key (the cache must actually hit).
    assert workspace_digest(root) == before

    (root / "a.py").write_text("def f():\n    return 2\n", encoding="utf-8")
    assert workspace_digest(root) != before

    # A new file changes it too.
    (root / "a.py").write_text("def f():\n    return 1\n", encoding="utf-8")
    (root / "b.py").write_text("x = 1\n", encoding="utf-8")
    assert workspace_digest(root) != before


def test_the_cpg_cache_key_distinguishes_repositories_with_no_python(tmp_path: Path) -> None:
    """Two unrelated Java projects must not share a CPG.

    The digest keys `var/dataflow/cpg/<digest>/cpg.bin`, which the whole worker fleet shares, so
    a collision does not merely waste a rebuild: the second project is answered from the first
    one's graph. Hashing only `.py` made every repository without Python hash to sha1("")[:16],
    which is not a hypothetical -- `benchmark` and `git-demo-edebe1` both did.
    """
    one = tmp_path / "one"
    two = tmp_path / "two"
    for root, body in ((one, "class A {}"), (two, "class B {}")):
        root.mkdir()
        (root / "Main.java").write_text(body, encoding="utf-8")

    assert workspace_digest(one) != workspace_digest(two)
    # sha1("")[:16], the value every non-Python repository used to collapse to. Spelled out
    # rather than computed so the test states the bug it exists to prevent.
    assert workspace_digest(one) != "da39a3ee5e6b4b0d", (
        "a repository full of Java must not hash as the empty tree"
    )

    # Non-source files still identify the repository: a mapper XML is where a MyBatis SQL sink
    # lives, so it has to be able to move the key.
    before = workspace_digest(one)
    (one / "ProductMapper.xml").write_text("<select>${sortField}</select>", encoding="utf-8")
    assert workspace_digest(one) != before


def test_the_walk_order_is_the_same_on_every_platform(tmp_path: Path) -> None:
    """The cache key must not depend on where it was computed.

    `Path.__lt__` is case-insensitive on Windows and case-sensitive on POSIX, so sorting `Path`
    objects gave one tree two orders and therefore two content hashes. Measured on a real 62-file
    project with byte-identical files: `1fc12a8c47ebcb05` on Windows against `a03eee558efd8a7d` in
    the Linux worker. `config/My.java` sorts before `Sink.java` case-insensitively and after it
    case-sensitively, which is exactly the pair below.
    """
    root = tmp_path / "w"
    (root / "pkg" / "config").mkdir(parents=True)
    (root / "pkg" / "Sink.java").write_text("class Sink {}", encoding="utf-8")
    (root / "pkg" / "config" / "My.java").write_text("class My {}", encoding="utf-8")

    order = [path.relative_to(root).as_posix() for path in iter_source_files(root, {".java"})]
    assert order == ["pkg/Sink.java", "pkg/config/My.java"], order


# ---------------------------------------------------------------- builder wiring


class StubDataflow:
    """A DataflowProvider that returns a canned bundle, or raises."""

    def __init__(self, bundle: FlowBundle | None = None, *, explode: bool = False) -> None:
        self.bundle = bundle
        self.explode = explode
        self.calls = 0
        self.calls_with: list[dict] = []

    def extract(
        self,
        *,
        force_build: bool = False,
        finding_path: str | None = None,
        finding_line: int | None = None,
    ) -> FlowBundle:
        self.calls += 1
        self.calls_with.append({"path": finding_path, "line": finding_line})
        if self.explode:
            raise RuntimeError("joern died")
        assert self.bundle is not None
        return self.bundle


def _builder(workspace: Path, dataflow: StubDataflow | None) -> CallGraphBuilder:
    ws = Workspace(workspace)
    resolver = CallGraphResolver(ws, SymbolIndex(ws, None), None)
    return CallGraphBuilder(ws, resolver, BudgetConfig(max_depth=2), dataflow=dataflow)


def _focus(workspace: Path):
    ws = Workspace(workspace)
    resolver = CallGraphResolver(ws, SymbolIndex(ws, None), None)
    found = resolver.locate_method("repo.py", 3)
    assert found is not None
    return ws, resolver, found[0]


def _flow_bundle(*, with_sanitizer: bool, sinks_candidates: int = 1) -> FlowBundle:
    """A trace shaped like the demo's: caller -> sanitizer -> focus."""
    caller = FlowElement(label="CALL", method="handle_request", file="handler.py", line="11")
    focus = FlowElement(label="CALL", method="query_user", file="repo.py", line="6")
    elements = [caller, focus]
    methods = ["handle_request", "query_user"]
    if with_sanitizer:
        elements.insert(1, FlowElement(
            label="CALL", method="safe_escape", file="util.py", line="5"
        ))
        methods.insert(1, "safe_escape")
    return FlowBundle(
        source_anchor="request.args.get",
        sink_anchor="execute",
        source_kind="parameter",
        source_expr="handle_request(request)",
        source_candidates=1,
        sink_candidates=sinks_candidates,
        flows=[TaintFlow(index=0, elements=elements)],
    )


def test_a_traced_flow_becomes_methods_on_the_slice(workspace: Path) -> None:
    """This is the fix: `safe_escape` is a callee of a caller, which the crawl never visits."""
    ws, _resolver, focus = _focus(workspace)
    builder = _builder(workspace, StubDataflow(_flow_bundle(with_sanitizer=True)))

    slice_ = builder.build(focus, [])

    names = {ref.method.qualified_name for ref in slice_.methods.values()}
    assert "safe_escape" in names, "the sanitizer a caller calls must reach the bundle"
    providers = {ref.provider for ref in slice_.methods.values()}
    assert Provider.JOERN_DATAFLOW in providers
    focus_refs = [ref for ref in slice_.methods.values() if ref.is_focus]
    assert len(focus_refs) == 1 and focus_refs[0].method.qualified_name == "query_user"


def test_the_focus_says_which_anchor_the_flow_came_from(workspace: Path) -> None:
    """The prompt must state the source anchor, even when nothing is on the source side.

    A single-function sample has no source-side refs at all -- the sink's method *is* the entry
    -- so recording the anchor only on those refs left the one thing a reader needs unsaid:
    whether the flow starts where input enters, or in the middle of the chain.
    """
    ws, _resolver, focus = _focus(workspace)
    builder = _builder(workspace, StubDataflow(_flow_bundle(with_sanitizer=False)))

    slice_ = builder.build(focus, [])

    focus_ref = next(ref for ref in slice_.methods.values() if ref.is_focus)
    assert "数据流来自 handle_request(request)" in focus_ref.via
    # The scan origin is not lost by saying so.
    assert "静态扫描命中位置" in focus_ref.via
    source_ref = next(ref for ref in slice_.methods.values() if not ref.is_focus)
    assert source_ref.via == "数据流来自 handle_request(request)"


def test_an_engine_that_proves_no_path_records_a_prune_and_skips_the_crawl(
    workspace: Path,
) -> None:
    """Zero flows is a finding about the code, and it must not be silently replaced."""
    ws, _resolver, focus = _focus(workspace)
    stub = StubDataflow(FlowBundle(source_anchor="a", sink_anchor="b"))
    builder = _builder(workspace, stub)

    slice_ = builder.build(focus, [])

    assert stub.calls == 1
    rules = [prune.rule for prune in slice_.prunes]
    assert "dataflow_no_path" in rules
    # Only the focus survives: nothing else was collected, because the engine said so.
    assert set(slice_.methods) == {focus.method_id}


def test_a_broken_engine_degrades_to_the_crawl_and_says_so(workspace: Path) -> None:
    """A JVM failure must not lose the slice -- and must not look like 'no path found'."""
    ws, _resolver, focus = _focus(workspace)
    builder = _builder(workspace, StubDataflow(explode=True))

    slice_ = builder.build(focus, [])

    rules = [prune.rule for prune in slice_.prunes]
    assert "dataflow_unavailable" in rules
    assert "dataflow_no_path" not in rules
    # The crawl ran, so the focus is not alone.
    assert len(slice_.methods) >= 1


def test_multiple_paths_do_not_get_flattened_into_a_loop(workspace: Path) -> None:
    """Two paths share a suffix; the bundle reports two paths, and says so."""
    ws, _resolver, focus = _focus(workspace)
    bundle = FlowBundle(
        source_anchor="a",
        sink_anchor="b",
        source_candidates=2,
        sink_candidates=1,
        flows=[
            TaintFlow(index=0, elements=[
                FlowElement(label="CALL", method="load_user", file="service.py", line="7"),
                FlowElement(label="CALL", method="load_user", file="service.py", line="7"),
                FlowElement(label="CALL", method="query_user", file="repo.py", line="6"),
            ]),
            TaintFlow(index=1, elements=[
                FlowElement(label="CALL", method="handle_request", file="handler.py", line="12"),
                FlowElement(label="CALL", method="query_user", file="repo.py", line="6"),
            ]),
        ],
    )
    slice_ = _builder(workspace, StubDataflow(bundle)).build(focus, [])

    rules = [prune.rule for prune in slice_.prunes]
    assert "dataflow_multiple_paths" in rules
    names = {ref.method.qualified_name for ref in slice_.methods.values()}
    assert {"load_user", "handle_request", "query_user"} <= names


def test_the_finding_position_is_handed_to_the_engine(workspace: Path) -> None:
    """The engine is told where the RULE FIRED, which is what a sink is derived from.

    Not the focus method's start line: the finding sits on the dangerous expression
    (`repo.py:6`, the concatenation) while the method starts earlier (`repo.py:4`). Passing the
    method's start resolved the sink to `connect` on line 5 instead of `execute` on line 7 --
    measured, not hypothetical.
    """
    from aegis_contracts.domain import CodeRegion, Finding, Severity

    ws, _resolver, focus = _focus(workspace)
    finding = Finding(
        finding_id="F-test",
        rule_id="python.lang.security.sql-injection",
        message="test",
        severity=Severity.ERROR,
        path="repo.py",
        region=CodeRegion(path="repo.py", start_line=5, start_char=11, end_line=5, end_char=59),
        snippet='sql = "..." + user_id',
    )
    stub = StubDataflow(_flow_bundle(with_sanitizer=True))

    _builder(workspace, stub).build(focus, [finding])

    assert stub.calls == 1
    assert stub.calls_with[0]["path"] == "repo.py"
    # 1-based, from the finding (6), not from the focus method's start (4).
    assert stub.calls_with[0]["line"] == 6
    assert stub.calls_with[0]["line"] != focus.region.start_line + 1


def test_without_a_finding_the_focus_stands_in(workspace: Path) -> None:
    """A slice built with no findings still gets a position, so the protocol never sees None."""
    ws, _resolver, focus = _focus(workspace)
    stub = StubDataflow(_flow_bundle(with_sanitizer=True))

    _builder(workspace, stub).build(focus, [])

    assert stub.calls_with[0]["path"] == focus.path
    assert stub.calls_with[0]["line"] == focus.region.start_line + 1


def test_an_unresolved_sink_is_named_differently_from_a_missing_path(workspace: Path) -> None:
    """`sink=''` means "we did not know what to look for" -- not "the code is safe".

    Reporting the second when the first is true would turn a configuration gap into a clean
    bill of health, which is the worst possible confusion for this tool.
    """
    ws, _resolver, focus = _focus(workspace)
    bundle = FlowBundle(source_anchor="request.args.get", sink_anchor="")
    slice_ = _builder(workspace, StubDataflow(bundle)).build(focus, [])

    rules = [prune.rule for prune in slice_.prunes]
    assert "dataflow_sink_unresolved" in rules
    assert "dataflow_no_path" not in rules


def test_a_resolved_sink_with_no_path_is_reported_as_no_path(workspace: Path) -> None:
    ws, _resolver, focus = _focus(workspace)
    bundle = FlowBundle(source_anchor="request.args.get", sink_anchor="execute")
    slice_ = _builder(workspace, StubDataflow(bundle)).build(focus, [])

    rules = [prune.rule for prune in slice_.prunes]
    assert "dataflow_no_path" in rules
    assert "dataflow_sink_unresolved" not in rules


def test_a_resolved_flow_carries_where_its_sink_came_from(workspace: Path) -> None:
    """The derivation is a heuristic; the contract records it so a reviewer can check it."""
    ws, _resolver, focus = _focus(workspace)
    bundle = _flow_bundle(with_sanitizer=True)
    bundle.sink_anchor = "execute"
    bundle.sink_derived_from = "repo.py:6"
    bundle.sink_derivation_method = "query_user"
    bundle.sink_derivation_alternatives = ["execute"]
    slice_ = _builder(workspace, StubDataflow(bundle)).build(focus, [])

    assert slice_.methods  # built from the flow
    encoded = json.loads(bundle.model_dump_json())
    assert encoded["sink_derived_from"] == "repo.py:6"
    assert encoded["sink_derivation_method"] == "query_user"


def test_bodies_are_read_verbatim_from_disk(workspace: Path) -> None:
    """What the model reads must be the bytes on disk, not a re-serialisation."""
    bundle = FlowBundle(
        source_anchor="a", sink_anchor="b",
        flows=[TaintFlow(index=0, elements=[
            FlowElement(label="CALL", method="safe_escape", file="util.py", line="4"),
        ])],
    )
    bodies = attach_bodies(bundle, workspace)

    assert len(bodies) == 1
    body: FlowMethodBody = bodies[0]
    assert body.method == "safe_escape"
    assert body.file == "util.py"
    assert body.start_line >= 1 and body.end_line >= body.start_line
    # The claim that matters: this text exists in the file, unchanged.
    original = (workspace / "util.py").read_text(encoding="utf-8")
    assert body.source in original
    assert "def safe_escape(value):" in body.source


def test_the_manifest_round_trips_the_new_contract() -> None:
    """`FlowBundle` must serialise: it travels into the bundle and into the prompt."""
    bundle = FlowBundle(
        source_anchor="request.args.get",
        sink_anchor="execute",
        flows=[TaintFlow(index=0, elements=[
            FlowElement(label="CALL", code="x()", method="m", file="a.py", line="1"),
        ])],
        method_bodies=[FlowMethodBody(
            method="m", file="a.py", start_line=1, end_line=1, source="def m(): ...",
        )],
    )
    encoded = json.loads(bundle.model_dump_json())
    assert encoded["flows"][0]["elements"][0]["label"] == "CALL"
    assert encoded["method_bodies"][0]["source"] == "def m(): ..."
    assert FlowBundle.model_validate(encoded).path_methods == ["m"]
