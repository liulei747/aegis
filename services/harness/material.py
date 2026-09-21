"""The evidence an agent is handed, taken out of the workspace instead of making it read.

Why this exists, measured on a real audit of a five-file Python project: 823 model round trips, of
which **471 were `read` calls**. Every agent read the same six files from scratch -- `repo.py` 88
times, `handler.py` 85, `orders.py` 84 -- because nothing carries what one agent learned to the next.
The blackboard keeps *which files were read* (that is the coverage ledger, and it must stay a derived
fact), but not what was in them, so a validator deciding one candidate pays the full "read the
project" cost again.

This module is the smallest useful half of the fix: **the material for one claim**. Given a candidate
and -- when the engine derived one -- its taint path, it assembles:

* the hit's own lines, with a little context;
* the function that contains the hit, so the reader sees the signature, the parameter names and the
  body rather than a floating statement;
* the other places the derived path visits, expanded to their enclosing functions where the language
  can be parsed for them.

Three rules keep it honest, and each exists because the alternative is a lie the reader cannot see:

* **A budget, and it says what it dropped.** Material that quietly ends at 6000 characters reads as
  "that is the whole story". Every truncation is recorded in `notes` and printed in the block.
* **Tools stay available.** This is material *in addition* to the tool layer, never instead of it: an
  agent that needs a file outside the packet can still read it, and the coverage ledger keeps counting
  exactly what it counted before.
* **Nothing is inferred from a name.** Path nodes carry `file:line`, and those lines are used as
  given. Method *names* are only used where the language can be parsed and the name resolves to one
  definition; guessing a function's extent from a regex is how a packet ends up showing the wrong
  body while looking authoritative.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from aegis_contracts.harness import Candidate, DataflowEvidence

#: A path node is rendered as `<file>:<line> <node text>`. The worker also inserts explanatory nodes
#: between concatenated flows (`… 另一条路径，共 N 步`), which are not locations.
_NODE = re.compile(r"^(?P<file>[^\s:]+):(?P<line>\d+)\b")

#: How much context to add around a path node, in lines. Two is enough to see the statement it is part
#: of without dragging in its neighbours' bodies.
NODE_PADDING = 2

#: Two windows closer than this are merged: inlining five overlapping fragments of one function wastes
#: more context than it saves, and a reader reads the same lines twice.
MERGE_GAP = 6

#: Default cap on the whole packet. 12000 characters is roughly 3000 tokens -- comparable to a handful
#: of `read` round trips, and small enough that the packet cannot crowd out the transcript.
DEFAULT_BUDGET = 12_000

#: Never inline a single block larger than this: one long function must not consume the packet. The
#: *byte* budget below still caps everything -- a 400-line block that does not fit `remaining` is
#: truncated by `_block` -- so this is a second, cruder guard rather than the real one.
#:
#: Raised from 160 after measuring the files that actually carry claims. On the `upp-module-infra`
#: audit the 98 claims sit in 38 files, every one of them ≤ 9,861 characters (median 3,628), and
#: **8 of the 38 are 194-239 lines** -- i.e. they fit the 12,000-character budget whole and were being
#: cut by this line cap instead. A validator that is handed the first 160 lines of `FileServiceImpl`
#: and told "use `read` for the rest" spends a turn doing it; the packet could have carried it.
MAX_BLOCK_LINES = 400


@dataclass
class Block:
    """One contiguous piece of source, with the reason it is there."""

    file: str
    start: int
    end: int
    text: str
    why: str
    truncated: bool = False

    @property
    def chars(self) -> int:
        return len(self.text)


@dataclass
class Material:
    """The packet for one claim, plus what was left out and why."""

    blocks: list[Block] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    @property
    def chars(self) -> int:
        return sum(block.chars for block in self.blocks) + sum(len(note) for note in self.notes)

    @property
    def files(self) -> list[str]:
        return sorted({block.file for block in self.blocks})

    @property
    def empty(self) -> bool:
        return not self.blocks

    def render(self) -> str:
        """The packet as prompt text. Empty string when there is nothing to hand over."""
        if self.empty:
            return ""
        out = [
            "## 已为你取出的材料（不必再为了这些行调用 read）",
            "",
            "下面是本次判断所需的源码片段，**行号取自文件本身**。它们来自 Joern 推导的污点"
            "路径（若有）与候选命中位置，不是模型摘要。需要看这些片段之外的东西时，工具仍然可用。",
        ]
        for block in self.blocks:
            out.append("")
            out.append(f"### `{block.file}` 第 {block.start}-{block.end} 行（{block.why}）")
            out.append("```")
            out.append(block.text)
            out.append("```")
            if block.truncated:
                out.append("（该片段被截断：完整内容见文件，或直接用 read 取剩余部分）")
        for note in self.notes:
            out.append("")
            out.append(f"> 注意：{note}")
        return "\n".join(out)


#: A file named inside free text (`evidence`, `rationale`): `path/to/Thing.java:41`, `Thing.java`,
#: `src/main/java/.../Thing.java (line 12)`. Deliberately conservative -- it must end in a source
#: suffix and contain no spaces -- because this feeds *scheduling* (which claims can share a run),
#: and a wrong file here only costs a shared packet, while a right one saves a whole run.
_NAMED_FILE = re.compile(
    r"(?P<file>[A-Za-z0-9_./\\-]+\.(?:java|py|js|ts|tsx|jsx|go|rb|php|cs|kt|scala|xml|yml|yaml|json|properties|sql))"
)


def files_for(candidate: Candidate, dataflow: DataflowEvidence | None = None) -> list[str]:
    """The files a candidate's evidence lives in, without building the packet.

    This is what makes batching by *material* possible instead of by file: a claim whose evidence
    names a controller, a service and a mapper needs all three, and two claims that share two of them
    can share one run's reads. Cheap by construction (no disk, no packet) because it runs for every
    pending claim on every round.
    """
    found: list[str] = []

    def add(name: str) -> None:
        text = str(name).strip().replace("\\", "/")
        if text and text not in found:
            found.append(text)

    add(candidate.file)
    if dataflow is not None:
        for step in dataflow.path:
            match = _NODE.match(str(step))
            if match:
                add(match.group("file"))
    for blob in (candidate.evidence or []) + ([candidate.rationale] if candidate.rationale else []):
        for match in _NAMED_FILE.finditer(str(blob)):
            add(match.group("file"))
    return found


def _read_lines(workspace: Path, file: str) -> list[str] | None:
    try:
        path = (workspace / file).resolve()
        # Confinement, not decoration: `file` comes from a model-written candidate, and a packet that
        # inlines `/etc/passwd` because a candidate named it would be a file-disclosure tool wearing
        # a reviewer's hat.
        if workspace.resolve() not in path.parents and path != workspace.resolve():
            return None
        return path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None


def lines_from_run(blackboard: Any, file: str) -> list[str] | None:
    """The lines of `file` out of a *complete* read this run already did, if there is one.

    The blackboard holds them: every `read` keeps its `lines`, and the audit that exposed this had
    471 complete reads -- 220 KB of file text, `repo.py` stored 88 times -- all of it consumed by
    `coverage.from_runs` and by nothing else. So material is taken from the run's own record first and
    from the disk second: re-reading a file to hand over bytes the run is already holding is how a
    shared state ends up written by everyone and read by no one.

    Complete only (`returned_lines >= total_lines`): a partial read handed over as the file would be a
    false claim about what the reader was shown.
    """
    if blackboard is None:
        return None
    for run in getattr(blackboard, "runs", []):
        for step in run.steps:
            result, call = step.result, step.call
            if call is None or result is None or not result.ok:
                continue
            if getattr(call.tool, "value", call.tool) != "read":
                continue
            data = result.data or {}
            if str(data.get("path") or "") != file:
                continue
            total = int(data.get("total_lines") or 0)
            returned = int(data.get("returned_lines") or 0)
            lines = data.get("lines")
            if not isinstance(lines, list) or total <= 0 or returned < total:
                continue
            return [str(line) for line in lines]
    return None


def _python_spans(lines: list[str]) -> list[tuple[int, int, str]]:
    """`(start, end, name)` for every function in a Python source, 1-based and inclusive.

    Only Python, and deliberately: `ast` is exact. A regex over `def`/`function`/braces would be
    wrong in ways a reader cannot detect -- a nested class, a lambda, a method split across lines --
    and a packet that shows the wrong body while naming the right function is worse than a packet that
    admits it only has the statement.
    """
    source = "\n".join(lines)
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return []
    spans: list[tuple[int, int, str]] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", None) or node.lineno
            spans.append((node.lineno, int(end), node.name))
    return spans


def _enclosing(spans: list[tuple[int, int, str]], line: int) -> tuple[int, int, str] | None:
    """The *innermost* function containing `line`, or None.

    Innermost matters: a helper nested inside another would otherwise return the outer function, and
    the packet would carry a hundred lines where fifteen would do.
    """
    hits = [span for span in spans if span[0] <= line <= span[1]]
    if not hits:
        return None
    return max(hits, key=lambda span: span[0])


def _merge(windows: list[tuple[int, int]], *, total: int, gap: int = MERGE_GAP) -> list[tuple[int, int]]:
    """Overlapping or near-adjacent windows, merged and clamped to the file."""
    ordered = sorted((max(1, start), min(total, end)) for start, end in windows)
    merged: list[tuple[int, int]] = []
    for start, end in ordered:
        if merged and start <= merged[-1][1] + gap:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged


def candidate_material(
    workspace: Path,
    candidate: Candidate,
    *,
    dataflow: DataflowEvidence | None = None,
    budget: int = DEFAULT_BUDGET,
    lines_of: Any = None,
) -> Material:
    """The source an agent needs to judge one candidate.

    Order of assembly is the order of importance, because the budget is spent in that order: the
    candidate's whole file first (which is what a validator reads today), then the enclosing functions
    of every place the derived path visits. When the budget runs out the packet says so -- a claim
    about a 40-step path that silently ends at step 12 is worse than one that admits it stopped.

    `lines_of(file) -> list[str] | None` is the material source and it is injectable for one reason:
    the run should read its own blackboard before it reads the disk (`lines_from_run`). The default is
    the disk, so this module stays usable stand-alone by the scripts that verify it.
    """
    material = Material()
    workspace = Path(workspace)
    source = lines_of or (lambda name: _read_lines(workspace, name))
    remaining = budget

    def fetch(name: str) -> list[str] | None:
        lines = source(name)
        if lines is None and lines_of is not None:
            # A file the run has not read yet still exists on disk; falling back keeps the packet
            # useful instead of silently shrinking to nothing.
            return _read_lines(workspace, name)
        return lines

    # -- the candidate's own file: the hit window and its enclosing function -------------
    own_lines = fetch(candidate.file)
    if own_lines is None:
        material.notes.append(
            f"候选所在的 `{candidate.file}` 无法读取（不存在或不在工作区内），"
            "因此本次判断只能依赖工具与已有证据"
        )
    else:
        total = len(own_lines)
        hit = int(candidate.line or 1)
        spans = _python_spans(own_lines)
        enclosing = _enclosing(spans, hit)
        windows: list[tuple[int, int]] = [(hit - NODE_PADDING, hit + NODE_PADDING)]
        why = "候选命中行"
        if enclosing is not None:
            windows.append((enclosing[0], enclosing[1]))
            why = f"候选命中行及其所在函数 `{enclosing[2]}`"
        elif spans:
            material.notes.append(
                f"`{candidate.file}`:{hit} 不在任何函数内（模块级语句），只给出命中行附近"
            )
        for start, end in _merge(windows, total=total):
            block = _block(own_lines, candidate.file, start, end, why=why, remaining=remaining)
            if block is None:
                material.notes.append(
                    f"预算不足：`{candidate.file}` 第 {start}-{end} 行未内联，请用 read 读取"
                )
                continue
            remaining -= block.chars
            material.blocks.append(block)
            if block.truncated:
                material.notes.append(
                    f"`{block.file}` 第 {block.start}-{block.end} 行因预算被截断；"
                    "这只是**开头**，不是全部内容"
                )

    # -- the rest of the derived path, function by function ------------------------------
    if dataflow is not None and dataflow.derived:
        seen: set[tuple[str, int, int]] = set()
        for step in dataflow.path:
            match = _NODE.match(str(step))
            if not match:
                continue
            file, line = match.group("file"), int(match.group("line"))
            lines = fetch(file)
            if lines is None:
                material.notes.append(f"路径上的 `{file}` 无法读取，已跳过")
                continue
            spans = _python_spans(lines)
            enclosing = _enclosing(spans, line)
            if enclosing is None:
                start, end = line - NODE_PADDING, line + NODE_PADDING
                why = "路径节点（该位置不在可解析的函数内）"
            else:
                start, end = enclosing[0], enclosing[1]
                why = f"路径上的函数 `{enclosing[2]}`（节点在第 {line} 行）"
            key = (file, start, end)
            if key in seen:
                continue
            seen.add(key)
            # A node inside what is already inline adds nothing -- but a node in a *different*
            # function of the same file does, and skipping the whole file (the first version) lost it:
            # `repo.py` holds both `query_user` and `query_order`, and a path that crosses from one to
            # the other said so in its nodes.
            if any(block.file == file and block.start <= line <= block.end for block in material.blocks):
                continue
            for block_start, block_end in _merge([(start, end)], total=len(lines)):
                block = _block(lines, file, block_start, block_end, why=why, remaining=remaining)
                if block is None:
                    material.notes.append(
                        f"预算不足：路径上的 `{file}` 第 {block_start}-{block_end} 行未内联，"
                        "请用 read 读取"
                    )
                    continue
                remaining -= block.chars
                material.blocks.append(block)
                if block.truncated:
                    material.notes.append(
                        f"`{block.file}` 第 {block.start}-{block.end} 行因预算被截断；"
                        "这只是**开头**，不是全部内容"
                    )

    if dataflow is None or not dataflow.derived:
        material.notes.append(
            "这条候选没有 Joern 推导的路径，因此材料只有命中位置所在函数；"
            "仓库级的结论（例如“整个仓库没有鉴权代码”）仍需自己搜索"
        )
    return material


def _block(
    lines: list[str], file: str, start: int, end: int, *, why: str, remaining: int
) -> Block | None:
    """One inlined range, with line numbers so the model can cite what it sees.

    Truncated rather than skipped when the range is longer than `MAX_BLOCK_LINES`: the beginning of a
    function is where its signature and its first statements are, and those are what a reader needs to
    decide whether the rest is worth asking for.
    """
    start = max(1, start)
    end = min(len(lines), end)
    if start > end:
        return None
    truncated = False
    if end - start + 1 > MAX_BLOCK_LINES:
        end = start + MAX_BLOCK_LINES - 1
        truncated = True
    numbered = "\n".join(f"{number:>5} | {lines[number - 1]}" for number in range(start, end + 1))
    if len(numbered) > remaining:
        # Keep the head: the signature and the first statements. Say so in the block itself.
        cut = max(0, remaining - 200)
        if cut < 200:
            return None
        numbered = numbered[:cut] + "\n…（本段因预算被截断）"
        truncated = True
    return Block(file=file, start=start, end=end, text=numbered, why=why, truncated=truncated)
