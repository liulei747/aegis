"""`record` -- the one tool that writes: a fact goes onto the blackboard the moment it is found.

Every other tool reads the repository. This one appends to the shared state, and that is the whole
reason it exists: recon and threat modelling run **concurrently**, and before this tool their findings
reached the blackboard only when their run finished. A second agent starting at the same moment
therefore reasoned against an empty board -- the race that made an earlier version of the coordinator
run those two stages one after the other, with a comment explaining that the threat model "saw an empty
blackboard".

Three rules, and each is a way this could go wrong:

* **A closed vocabulary of kinds.** `note`, `component`, `entry_point`, `trust_boundary`, `asset`,
  `actor`, `threat`, `lead` -- each maps onto an existing blackboard field through the *existing*
  merge helper, which unions and de-duplicates. A free-form writer would let a model invent state the
  report cannot render and the closure rule cannot read.
* **It cannot delete or rewrite.** Appends and merges only, exactly like the coordinator's own writes.
  An agent that could clear the candidate ledger could erase another agent's work; an agent that can
  only add is an agent whose worst case is noise in the report.
* **With no writer it refuses.** `ToolContext.record is None` (a unit test, a deployment without a
  board) reports that recording is unavailable rather than pretending to have recorded something --
  the same rule `dataflow_verify` follows when the verifier is absent.

The result carries the blackboard's revision, so the model can see that its write landed and that the
board changed under it.
"""

from __future__ import annotations

from typing import Any

from aegis_contracts.harness import ToolName, ToolResult
from services.harness.tools.base import ToolContext
from services.harness.tools.support import str_argument

#: The kinds a model may record, and what each one lands in. Kept as data because the tool's schema
#: and its dispatch have to agree, and two lists in two places is how a kind gets documented but not
#: implemented.
KINDS: dict[str, str] = {
    "gap": "当前任务缺口 JSON {kind: unread|basic_check|relationship|tool_failure,question,file,line,evidence_refs,state: pending|resolved,reason}；解决已分配缺口用 {gap_id,state: resolved,evidence_refs,reason}，需本任务源码事实证据",
    "evidence": "调查证据 JSON {file,line,text,category: source_fact|hypothesis,candidate_id?}；关联候选的新源码事实触发证据版本复核",
    "candidate": "候选 JSON，与最终 candidates 单项字段一致（不是验证结论）",
    "note": "自由文本事实，记在该 scope/项目的 notes 里（如“用的是 sqlite，没有 ORM”）",
    "component": (
        "架构**区域**：一个目录/模块/scope 一行，id 复用预扫描给的 `scope-…`；"
        "不要一条路由记一个组件（端点是 entry_point）"
    ),
    "entry_point": (
        "一条**具体**入口（外部输入第一次进入代码的地方：路由注册 / main / 服务器引导 / CLI），"
        "只写入口本身和位置，例如 `GET /search (handler.py:6)`——不要在后面写解释；"
        "内部工具函数、service/repo 方法**不算入口**；有几条就记几条（位置相同视为同一条）"
    ),
    "trust_boundary": "不可信数据进入可信代码的位置（字符串）",
    "asset": "被保护的资产，**一个短名词短语**（如 `users 表`），不要写成句子（解释放 threat 的 note）",
    "actor": "攻击者模型，**一个短名词短语**（如 `匿名互联网用户`），不要写成长句",
    "threat": "威胁：{id, title, asset, note}",
    "lead": "独立问题线索：{to_scope,question,file,line,evidence_refs,why}；当前问题所需跨文件追踪自行继续",
}


class RecordTool:
    """Append one fact to the blackboard. The writer is injected through `ToolContext`."""

    name = ToolName.RECORD

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "description": (
                "把一个**已经确认的事实**立刻记到共享黑板上，其他 agent（包括与你并发运行的）"
                "马上就能看到。用于开局勘察与威胁建模：不要等最后一次性汇报，边走边记。"
                "只能追加，不能删除或覆盖；重复的内容会被去重。"
            ),
            "parameters": {
                "type": "object",
                "required": ["kind", "text"],
                # Same rule as the read-only tools: the schema is closed, so a model that invents an
                # argument is told the argument does not exist instead of having it quietly ignored.
                "additionalProperties": False,
                "properties": {
                    "kind": {
                        "type": "string",
                        "enum": sorted(KINDS),
                        "description": "；".join(f"{name}={why}" for name, why in sorted(KINDS.items())),
                    },
                    "text": {
                        "type": "string",
                        "description": "要记录的内容。component/threat/lead 用 JSON 对象，其余用一句话。",
                    },
                    "scope": {
                        "type": "string",
                        "description": "可选：这条事实属于哪个 scope（默认记在整个工作区上）。",
                    },
                },
            },
        }

    def run(self, context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
        if context.record is None:
            return ToolResult(
                tool=self.name,
                ok=False,
                summary="record 不可用：本次运行没有接上黑板（没有可写的地方，不会假装记下了）",
                error="record_writer_absent",
                data={"refused": "record_writer_absent"},
            )
        kind = str_argument(arguments, "kind")
        text = str_argument(arguments, "text")
        if not text:
            # Refused here as well as in the writer. The writer's `empty_text` is the backstop for
            # callers that are not this tool; a model that sent nothing gets told so without a
            # round-trip onto the board, and the two checks cannot drift into disagreement about
            # whether an empty fact is a fact.
            #
            # The keys it *did* send are named, because that is what makes the refusal actionable:
            # measured on a real run, a model put the payload under a different key and repeated the
            # same call eight times in one turn, each time reading only "text 不能为空". Naming the
            # received keys turns that loop into a one-step correction.
            received = ", ".join(sorted(str(key) for key in arguments)) or "（没有参数）"
            return ToolResult(
                tool=self.name,
                ok=False,
                summary=(
                    f"record 需要非空的 text（实际收到的参数：{received}）。"
                    "内容必须放在 `text` 里：component/threat/lead 放 JSON 字符串，其余放一句话。"
                ),
                error="empty_text",
                data={"refused": "empty_text", "kind": kind, "received": sorted(arguments)},
            )
        if kind not in KINDS:
            return ToolResult(
                tool=self.name,
                ok=False,
                summary=f"不认识的 kind：{kind}；可用：{', '.join(sorted(KINDS))}",
                error="unknown_record_kind",
                data={"refused": "unknown_record_kind", "kind": kind},
            )
        scope = str(arguments.get("scope") or "").strip()
        outcome = context.record({"kind": kind, "text": text, "scope": scope})
        recorded = bool(outcome.get("recorded"))
        return ToolResult(
            tool=self.name,
            ok=recorded,
            summary=(
                f"已记入黑板（{kind}，revision={outcome.get('revision')}）：{outcome.get('note') or text[:120]}"
                if recorded
                else f"未记入（{outcome.get('reason') or '未知原因'}）：{text[:120]}"
            ),
            error=None if recorded else str(outcome.get("reason") or "record_failed"),
            data={"kind": kind, "scope": scope, **outcome},
        )
