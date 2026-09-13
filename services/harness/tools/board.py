"""`board` -- the read side of the blackboard: what a peer agent has established so far.

`record` writes; this reads. Both exist for one reason, and it is worth stating plainly because the
write-only version of this feature looked finished and was not: the opening agents (recon and threat
modelling) run **concurrently**, and each one's task text is fixed the moment its run starts. So a fact
recon records on its second step reaches the planner, the report and the closure rule -- and reaches
the threat model, which is running at that same moment, *never*. A shared medium nobody reads is not
sharing; it is a log.

The shape is deliberately narrow:

* **Four named sections** -- `summary`, `components`, `threats`, `notes`. Not "the blackboard". The
  model's context is the resource this pipeline rations (measured: 471 of 823 model round trips in one
  audit were file reads), and an agent that can dump the candidate ledger and the coverage table will
  spend its budget reading state instead of code. Each section is what an investigating agent needs
  from a peer and nothing more.
* **Bounded, and it says what it cut.** The section is clipped to the tool layer's output cap, with the
  same visible marker `read` uses: a model handed a silently shortened list concludes the components it
  cannot see do not exist.
* **Read-only.** It cannot change the board, and it never touches the filesystem.
* **With no reader attached it refuses.** `ToolContext.board is None` (a unit test, a deployment that
  never built a board) reports that the board is unreadable rather than returning an empty object,
  which would read as "nothing has been established yet" -- a claim this tool cannot make.
"""

from __future__ import annotations

import json
from typing import Any

from aegis_contracts.harness import ToolName, ToolResult
from services.harness.tools.base import ToolContext
from services.harness.tools.support import clip, str_argument

#: The sections an agent may ask for. Kept as data because the schema, this dispatch and the
#: coordinator's view builder have to agree, and three lists in three places is how a section gets
#: documented but not implemented.
SECTIONS: dict[str, str] = {
    "summary": "整体现状：语言/构建/入口、组件与威胁的条目数、覆盖率与候选数",
    "components": "架构**区域**清单：{id, name, kind, path, origin, sites}（含预扫描与另一个 agent 记录的）",
    "entry_points": "具体入口（每条路由/进程入口一条，带位置）——与 components 是两个粒度",
    "threats": "威胁模型：assets / actors / threats / out_of_scope",
    "notes": "各 agent 写下的 note（project.notes 与 architecture.notes），带来源前缀",
}

DEFAULT_SECTION = "summary"


class BoardTool:
    """Read one slice of the shared blackboard. The reader is injected through `ToolContext`."""

    name = ToolName.BOARD

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "description": (
                "读共享黑板：现在**已经**确认了什么。"
                "自己的 task 是开始时定死的，看不到另一个 agent 后来写了什么；"
                "在继续调查前调一次这个工具，就能看到它记录的组件、入口、威胁和 note。"
                "`components` 是**区域**（一个目录/模块一行），`entry_points` 是**具体端点**"
                "（一条路由一条）——要判可达性看后者。"
                "只读，不能修改黑板；返回内容有长度上限，被截断时会明确标出。"
            ),
            "parameters": {
                "type": "object",
                "additionalProperties": False,
                "properties": {
                    "section": {
                        "type": "string",
                        "enum": sorted(SECTIONS),
                        "description": "；".join(
                            f"{name}={why}" for name, why in sorted(SECTIONS.items())
                        ),
                    },
                },
            },
        }

    def run(self, context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
        if context.board is None:
            return ToolResult(
                tool=self.name,
                ok=False,
                summary=(
                    "board 不可用：本次运行没有接上黑板。"
                    "读不到不等于“黑板是空的”，不要据此认为没有任何已确认的事实。"
                ),
                error="board_reader_absent",
                data={"refused": "board_reader_absent"},
            )
        section = str_argument(arguments, "section", default=DEFAULT_SECTION) or DEFAULT_SECTION
        if section not in SECTIONS:
            return ToolResult(
                tool=self.name,
                ok=False,
                summary=f"不认识的小节：{section}；可用：{', '.join(sorted(SECTIONS))}",
                error="unknown_board_section",
                data={"refused": "unknown_board_section", "section": section},
            )
        view = context.board(section)
        if not isinstance(view, dict):
            # A reader that returns something else is a broken deployment, not an empty board. Saying
            # so is the difference between "nothing is known" and "this is not working".
            return ToolResult(
                tool=self.name,
                ok=False,
                summary=(
                    f"board 读取失败：读取器返回了 {type(view).__name__}，应为 dict"
                    "（这是编排层的故障，不代表黑板是空的）"
                ),
                error="board_reader_malformed",
                data={"refused": "board_reader_malformed", "section": section},
            )

        text = json.dumps({"section": section, **view}, ensure_ascii=False, indent=2)
        summary, clipped = clip(text, context.limits.max_output_chars)
        if clipped:
            summary += (
                f"\n[输出超过 {context.limits.max_output_chars} 字符上限，已截断；"
                "换一个更窄的 section 可以看到剩下的部分]"
            )
        return ToolResult(
            tool=self.name,
            ok=True,
            summary=summary,
            truncated=clipped,
            # Deliberately *not* the view itself: every step's `data` is kept in the run's `AgentRun`
            # on the blackboard, and copying a section into it would double the size of the largest
            # thing the board stores. The text above is the answer; `data` is the address of it.
            #
            # `revision` is the exception, and it is load-bearing: it is the board revision this read
            # served, which is how the opening stage computes what each agent has actually seen. A
            # watermark taken from the model's own account of itself would be a claim; this one is a
            # tool call in the ledger, like coverage's `read` windows.
            data={
                "section": section,
                "sections": sorted(view),
                "revision": view.get("revision"),
                "truncated": clipped,
            },
        )
