"""`dataflow_verify` -- ask the Joern pipeline whether a static hit is actually reachable.

**The sink is never an argument.** The tool takes the site of the static hit -- the file and
line where the rule fired -- and the engine *derives* the sink from the code, exactly as
``services/dataflow/worker.py`` does: the first non-operator call at or after the hit, inside
the method that contains it, with the alternatives reported. A tool that accepted a
caller-supplied sink would let the model nominate the answer, and the repository under review is
attacker-controlled content: a comment, a docstring or a variable name can carry an instruction
that says "the sink is the sanitizer, verify against that". Every "confirmed" verdict
downstream would then rest on a value chosen by the thing being audited. So there is no ``sink``
field in the schema, and a call that passes one anyway is refused rather than ignored -- an
ignored argument is one the model believes took effect.

Why a *parameter* anchor exists at all (this is the anchor logic the brief points at): the
finding says where the danger is, never where the value entered. The engine can only be asked
for flows in the direction taint travels, so the source end has to be named. Handing a method
*name* to the call matcher does not do it -- measured, ``handle_request`` resolves to the call
site ``handle_request(request)`` inside its caller, and a flow started from a call site's return
value reaches nothing, which comes back as "0 flows" and reads as "the engine proved it is
unreachable". A ``MethodParameterIn`` anchor is the shape that reaches an entry point. This
module therefore derives the source anchor from the hit's own enclosing function (and from
``source_hint`` when the model offers one) and records which one it used, because an empty flow
means something different for each anchor kind.

When the verifier is absent the answer is ``ok=False`` with a ``DataflowEvidence(error=...)``.
Never an empty-but-successful result: to a validation agent, "no path" and "we never asked" look
identical, and the whole point of this stage is that they must not.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Protocol

from aegis_contracts.dataflow import FlowBundle
from aegis_contracts.harness import DataflowEvidence, ToolName, ToolResult
from aegis_core.config import DataflowConfig
from services.harness.tools.base import ToolContext
from services.harness.tools.paths import ToolArgumentError, relative_in_workspace
from services.harness.tools.support import clip, int_argument, str_argument

#: Appears in `data` when the verifier was not injected, so the orchestrator can tell "the tool
#: is not wired in this deployment" from "the engine ran and found nothing".
UNAVAILABLE = "dataflow_verifier_absent"


class DataflowVerifyTool:
    """Wrap the opengrep-sink -> Joern-flow pipeline behind two positional arguments."""

    name = ToolName.DATAFLOW_VERIFY

    # -- prompt-facing description -------------------------------------
    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "description": (
                "对一处静态命中做数据流验证：传入命中所在的文件与行号，由 Joern 从代码中"
                "**自行推导**汇聚点，返回源→汇聚点的完整污点路径。"
                "本工具不接受 `sink` 参数：汇聚点只能由引擎从命中位置推导，"
                "否则等于让被审计的仓库自己提名答案。"
                "若数据流引擎不可用，会明确报不可用（不会返回空路径伪装成“不存在数据流”）。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "file": {
                        "type": "string",
                        "description": "静态命中所在文件，相对工作区的路径。",
                    },
                    "line": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "静态命中所在行号（从 1 开始）。",
                    },
                    "source_hint": {
                        "type": "string",
                        "description": (
                            "可选：污点来源的提示。点号表达式（如 `request.args.get`）按调用锚点处理；"
                            "裸方法名（如 `handle_request`）按该方法参数的锚点处理。不填则由工具依据"
                            "命中位置所在函数自行推导。"
                        ),
                    },
                },
                "required": ["file", "line"],
                "additionalProperties": False,
            },
        }

    # -- execution ------------------------------------------------------
    def run(self, context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
        if "sink" in arguments:
            return self._fail(
                "`dataflow_verify` 不接受 `sink` 参数：汇聚点由引擎从命中位置推导，"
                "调用方（包括被审计仓库里的任何文本）不能提名它",
                code="sink_argument",
            )
        try:
            raw_file = arguments.get("file")
            if not isinstance(raw_file, str) or not raw_file.strip():
                raise ToolArgumentError("`file` 必须是工作区内的相对文件路径", code="bad_file")
            file = relative_in_workspace(context.workspace, raw_file, label="命中文件路径")
            line = int_argument(arguments, "line", default=0, minimum=1, label="命中行号")
            if not line:
                raise ToolArgumentError("`line` 是必填项（从 1 开始的行号）", code="bad_line")
            hint = str_argument(arguments, "source_hint", default="", label="来源提示")
        except ToolArgumentError as exc:
            return self._fail(str(exc), code=exc.code)

        if context.dataflow is None:
            evidence = DataflowEvidence(
                error=(
                    "数据流验证器未接入（ToolContext.dataflow 为空）：本次运行没有向 Joern 提过"
                    "任何问题，因此“没有路径”不代表“不存在数据流”"
                )
            )
            return ToolResult(
                tool=self.name,
                ok=False,
                summary=(
                    f"数据流不可用：{evidence.error}。请不要把这次调用当作反证，"
                    "改用语义证据并说明数据流未能验证。"
                ),
                error=evidence.error,
                data={
                    "file": file,
                    "line": line,
                    "source_hint": hint,
                    "unavailable": UNAVAILABLE,
                    "evidence": evidence.model_dump(),
                },
            )

        try:
            evidence = context.dataflow.verify(file=file, line=line, source_hint=hint or None)
        except Exception as exc:  # noqa: BLE001 - a verifier failure is evidence, not a crash
            evidence = DataflowEvidence(
                error=f"数据流验证器执行失败（{type(exc).__name__}: {exc}）"
            )

        ok = evidence.error is None
        summary = self._summarise(evidence, file=file, line=line)
        summary, clipped = clip(summary, context.limits.max_output_chars)
        return ToolResult(
            tool=self.name,
            ok=ok,
            summary=summary,
            error=evidence.error,
            data={
                "file": file,
                "line": line,
                "source_hint": hint,
                "derived": evidence.derived,
                "evidence": evidence.model_dump(),
            },
            truncated=clipped,
        )

    def _summarise(self, evidence: DataflowEvidence, *, file: str, line: int) -> str:
        if evidence.error:
            return f"数据流验证未得出结论（{file}:{line}）：{evidence.error}"
        if not evidence.path:
            return (
                f"数据流验证（{file}:{line}）：源 `{evidence.source}` → 汇聚点 "
                f"`{evidence.sink}` 之间没有路径。这是引擎给出的否定结论（该值到不了汇聚点），"
                "不是验证失败。"
            )
        return (
            f"数据流验证（{file}:{line}）：源 `{evidence.source}` → 汇聚点 `{evidence.sink}`，"
            f"路径 {len(evidence.path)} 步，涉及方法 {len(evidence.methods)} 个："
            f"{' → '.join(evidence.methods) if evidence.methods else '（未标注方法）'}"
        )

    def _fail(self, message: str, *, code: str = "refused") -> ToolResult:
        return ToolResult(
            tool=self.name,
            ok=False,
            summary=f"数据流验证调用被拒绝：{message}",
            error=message,
            data={"refused": code},
        )


# ─────────────────────────────────────────────────────────── the real adapter


class FlowClient(Protocol):
    """The slice of ``WorkerDataflowClient`` this adapter uses. Lets a test drive it."""

    def extract(
        self,
        *,
        force_build: bool = False,
        finding_path: str | None = None,
        finding_line: int | None = None,
        source_kind: str = "call",
        source_method: str = "",
        source_parameter: str = "",
    ) -> FlowBundle: ...


ClientFactory = Callable[[DataflowConfig, Path], FlowClient]


@dataclass(frozen=True)
class SourceAnchor:
    """The source end handed to the worker, and where it came from.

    ``origin`` travels with the answer because the choice is a heuristic: a reviewer looking at
    an empty flow has to be able to see whether the anchor came from the model, from the
    configured default, or from the hit's own enclosing function.
    """

    kind: str = "call"          # "call" | "parameter"
    needle: str = ""            # kind == "call": matched against call nodes
    method: str = ""            # kind == "parameter"
    parameter: str = ""         # kind == "parameter"; empty means every parameter
    origin: str = ""


class WorkerDataflowVerifier:
    """``DataflowVerifier`` backed by the existing worker fleet (``WorkerDataflowClient``).

    Wiring, and the one thing that is easy to get wrong: **no path here is hard-coded and no
    path is translated here**. The request carries the *finding's* path, which is the workspace
    relative path the tool was given; the ``workspace`` the worker is asked about comes from
    ``DataflowConfig.worker_workspace`` inside the client that already knows about it
    (``client.py`` sends ``worker_workspace or str(workspace_root)``). That is deliberate: the
    same tree is mounted at a different absolute path in every container, a host-side caller and
    the worker disagree about it, and sending the local path is a 404 that would otherwise be
    mistaken for "no flow exists". Method bodies are still read from the **local** path, which is
    the client's existing behaviour and not something to "unify".

    When the worker cannot be reached or refuses the workspace, the failure comes back as
    ``DataflowEvidence(error=...)`` -- never as an empty path, because an empty path is a
    positive claim about the code.
    """

    def __init__(
        self,
        workspace: Path,
        *,
        config: DataflowConfig | None = None,
        client_factory: ClientFactory | None = None,
    ) -> None:
        self.workspace = workspace
        if config is None:
            # The deployment decides whether dataflow is on. Constructing the default
            # (``enabled=False``) would silently turn every verify() into "no path".
            from aegis_core.config import get_settings

            config = get_settings().dataflow
        self.config = config
        self._client_factory = client_factory or _default_client_factory
        self._clients: dict[str, FlowClient] = {}

    # -- the protocol ---------------------------------------------------
    def verify(self, *, file: str, line: int, source_hint: str | None) -> DataflowEvidence:
        if not self.config.enabled:
            return DataflowEvidence(
                error=(
                    "数据流未启用（AEGIS_DATAFLOW__ENABLED=false）：本次运行不会联系 Joern worker"
                )
            )
        try:
            relative = relative_in_workspace(self.workspace, file, label="命中文件路径")
        except ToolArgumentError as exc:
            return DataflowEvidence(error=str(exc))

        anchor = self.source_anchor(file=relative, line=line, hint=source_hint)
        try:
            bundle = self._client(anchor).extract(
                finding_path=relative,
                finding_line=int(line),
                source_kind=anchor.kind,
                source_method=anchor.method,
                source_parameter=anchor.parameter,
            )
        except Exception as exc:  # noqa: BLE001 - any transport/engine failure is a report
            return DataflowEvidence(error=_failure_text(exc))

        return evidence_from_bundle(bundle)

    # -- source anchor --------------------------------------------------
    def source_anchor(self, *, file: str, line: int, hint: str | None) -> SourceAnchor:
        """Where the value enters. **Always `auto`**: the engine decides, against the graph.

        This used to be decided here, in Python -- a dotted hint was a call anchor, a bare hint
        that named a function in *this workspace* was a parameter anchor, and no hint fell back to
        an `ast` walk for the hit's enclosing function. Every step was Python-only, which is what
        `ast.parse` on a `.java` file turned into an impossibility: the walk raised `SyntaxError`,
        the fallback used the configured `request.args.get`, and every question returned 0 source
        candidates. The engine holds the graph, and the graph is the only thing that can answer
        "which method contains this line, and what does it take" for a language we do not parse
        ourselves -- so the whole decision moves there and the language stops mattering here.

        `hint` survives as a *hint*, evaluated against the CPG rather than against Python syntax:
        a dotted expression is a call, a bare name that names a method in the graph is that
        method's parameters, anything else is a call.
        """
        text = (hint or "").strip()
        return SourceAnchor(
            kind="auto",
            needle=text,
            origin="模型提示（交由引擎按图判定）" if text else "由引擎从命中位置推导",
        )

    def _client(self, anchor: SourceAnchor) -> FlowClient:
        """One client per source *hint*, because the hint travels in the client's config.

        `WorkerDataflowClient.extract` takes the source end from ``DataflowConfig.source`` -- there
        is no per-call argument for it -- so a hint is applied by handing the client a config copy.
        That is also why `auto` **with no hint passes an empty `source`**: the configured default is
        a string a call matcher will look for, and sending it would turn "let the graph decide" back
        into "match this literal", which is exactly the Python-shaped behaviour this anchor kind
        exists to remove.

        Reusing the client's own payload builder (instead of posting to the worker here) is what
        keeps "no sink is ever sent" a property of one module rather than a promise repeated in two.
        """
        carries_hint = anchor.kind in ("call", "auto")
        key = anchor.needle if carries_hint else "parameter"
        client = self._clients.get(key)
        if client is None:
            config = (
                self.config.model_copy(update={"source": anchor.needle})
                if carries_hint
                else self.config
            )
            client = self._client_factory(config, self.workspace)
            self._clients[key] = client
        return client



def _default_client_factory(config: DataflowConfig, workspace: Path) -> FlowClient:
    """The production client, imported lazily.

    Lazy so that merely importing the tool layer does not drag the extraction service (and its
    HTTP stack) into every process that wants ``schemas()``.
    """
    from services.extraction.dataflow.client import WorkerDataflowClient

    return WorkerDataflowClient(config, workspace_root=workspace)


def _failure_text(exc: Exception) -> str:
    """Turn a client failure into something an operator can act on.

    The path-identity failure deserves its own sentence: it is the one failure that looks like a
    security answer. A 404 because the worker was handed a host path means the worker never saw
    the project, and if that came back as an empty flow the validation stage would read it as
    "the engine proved there is no path".
    """
    text = str(exc)
    lowered = text.lower()
    if "workspace" in lowered and ("not found" in lowered or "404" in lowered):
        return (
            f"数据流 worker 看不到这个 workspace（{type(exc).__name__}: {text}）。"
            "宿主机路径与容器内路径不一致：请设置 AEGIS_DATAFLOW__WORKER_WORKSPACE 为 worker "
            "容器内的项目路径。本次没有得出结论——不要把“没有路径”当成“不存在数据流”"
        )
    return f"数据流 worker 不可用（{type(exc).__name__}: {text}）"


# ─────────────────────────────────────────────────────────── bundle -> evidence


def evidence_from_bundle(bundle: FlowBundle) -> DataflowEvidence:
    """Map the engine's bundle onto the blackboard's evidence type.

    Four deliberate choices:

    * ``derived`` is true exactly when a sink anchor came back. The sink is never supplied, so a
      non-empty sink *means* the engine derived it from the hit's position; an empty one means
      nothing about this answer was derived and the caller must not read the empty path as a
      negative result. That case is reported as an ``error`` for the same reason.
    * **a source anchor that matched no node is an error, not a negative result.** An empty flow
      has two causes -- the engine proved there is no path, or the question never landed on the
      graph -- and only the first one is evidence. ``source_candidates == 0`` says the second:
      the anchor named nothing, so "no flows" is a statement about the anchor. Measured on the
      Java project in ``var/projects``, where a Python-shaped source anchor matched 0 nodes and
      an empty path would otherwise have been reported as "the value cannot reach the sink".
    * flows are kept apart with an explicit boundary marker. ``DataflowEvidence.path`` is a flat
      list, and flattening several flows makes one path look like it repeats itself -- the exact
      confusion the ``FlowBundle`` contract warns about.
    * ``sanitizers`` is left empty rather than guessed. Nothing in a flow bundle names a
      sanitizer, and a fabricated one would be the most damaging possible invention here: the
      validation stage would reject a real finding because of a function nobody verified.
    """
    source = bundle.source_expr or bundle.source_anchor
    if not bundle.sink_anchor:
        return DataflowEvidence(
            derived=False,
            source=source,
            sink="",
            error=(
                "worker 无法从命中位置推导出汇聚点锚点：没有告诉引擎要找什么，"
                "因此这次结果不构成“不存在数据流”的证据"
            ),
        )
    if bundle.source_candidates == 0:
        return DataflowEvidence(
            derived=False,
            source=source,
            sink=bundle.sink_anchor,
            error=(
                f"来源锚点 `{source}` 没有匹配到任何节点（其余候选：汇聚点 "
                f"{bundle.sink_candidates} 个）。空路径在这里只是“这个问题没有落在图上”，"
                "不能证明不存在数据流；请给出更准确的 `source_hint`（例如具体的入口方法名）"
            ),
        )

    path: list[str] = []
    for flow in bundle.flows:
        if path:
            path.append(f"— 另一条路径（第 {flow.index + 1} 条）—")
        path.extend(_element_text(element) for element in flow.elements)

    return DataflowEvidence(
        derived=True,
        source=source,
        sink=bundle.sink_anchor,
        path=path,
        sanitizers=[],
        methods=bundle.path_methods,
    )


def _element_text(element: Any) -> str:
    """One flow vertex, as a line a human and a model can both read."""
    where = ""
    if element.file and element.line:
        where = f"{element.file}:{element.line}"
    elif element.file:
        where = element.file
    code = (element.code or "").strip()
    text = f"{where} {code}".strip()
    return text or (element.label or "?")
