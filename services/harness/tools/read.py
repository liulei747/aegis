"""`read` -- numbered lines from one file inside the workspace.

Three refusals and one visible truncation, each of which exists because of a specific way this
tool would otherwise be believed about something it never showed:

* **outside the workspace** is refused rather than clamped (see ``paths``): a model that asked
  for ``../../etc/passwd`` and got ``etc/passwd`` would carry on as if it had read what it
  named.
* **a directory** is refused rather than expanded: an implicit listing makes the tool's output
  depend on the filesystem, and ``list_files`` is the tool whose output is *meant* to be a
  listing.
* **a binary** is refused, on a NUL byte in the first chunk. Decoding a compiled artefact or an
  archive with ``errors="replace"`` produces a wall of replacement characters that reads to a
  model like very strange source code, and the model will describe it as such.
* **a large file** is refused, at the same order of magnitude the extractor is willing to parse
  (``Settings.max_file_bytes``). ``read`` is not the way to grep a 40 MB log; ``shell_command``
  with ``sed -n`` is, because there the cap lands on the output rather than on the input.

Truncation is always stated in the summary and flagged in ``ToolResult.truncated``. A read that
stops silently at line 200 is how a model "proves" something about the 5 000 lines it did not
see -- the failure mode is not a missing file, it is confidence about the wrong slice.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from aegis_contracts.harness import ToolName, ToolResult
from services.harness.tools.base import ToolContext
from services.harness.tools.paths import (
    ToolArgumentError,
    relative_in_workspace,
    resolve_in_workspace,
)
from services.harness.tools.support import clip, int_argument

#: Size cap, in bytes. Mirrors the default of ``aegis_core.config.Settings.max_file_bytes``
#: rather than reading it: the tool layer must not depend on process-wide settings, and a test
#: that wants to exercise the cap should be able to patch this constant instead of writing a
#: genuinely 2 MB file.
MAX_FILE_BYTES = 2_000_000

#: How much of the file is sniffed for a NUL byte. Not the whole file: the point is to fail
#: fast on archives and executables, whose first block always contains one.
_BINARY_PROBE_BYTES = 4096


class ReadTool:
    """Numbered lines out of one workspace file."""

    name = ToolName.READ

    # -- prompt-facing description -------------------------------------
    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "description": (
                "读取工作区内某个文件的指定行范围，返回带行号的文本。只能读工作区内的相对路径；"
                "二进制文件、目录和过大的文件会被拒绝，超出上限的部分会明确标注为已截断。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "相对工作区的文件路径，例如 `services/scan/runner.py`。",
                    },
                    "offset": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "起始行号（从 1 开始）。默认从头读。",
                    },
                    "limit": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "最多返回的行数，超出每次调用的上限时会被截断并在结果中标注。",
                    },
                },
                "required": ["path"],
                "additionalProperties": False,
            },
        }

    # -- execution ------------------------------------------------------
    def run(self, context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
        raw_path = arguments.get("path")
        if not isinstance(raw_path, str) or not raw_path.strip():
            return self._fail("`path` 必须是工作区内的相对文件路径（字符串）")

        try:
            target = resolve_in_workspace(context.workspace, raw_path, label="读取路径")
            offset = int_argument(arguments, "offset", default=1, label="起始行号")
            requested = int_argument(
                arguments,
                "limit",
                default=context.limits.max_read_lines,
                label="行数上限",
            )
        except ToolArgumentError as exc:
            return self._fail(str(exc))
        limit = min(requested, context.limits.max_read_lines)

        refusal = self._refusal(target, raw_path)
        if refusal is not None:
            return refusal

        try:
            data = target.read_bytes()
        except OSError as exc:
            return self._fail(f"无法读取 {raw_path}：{exc}")

        text, lossy = _decode(data)
        lines = text.splitlines()
        total = len(lines)
        rel = relative_in_workspace(context.workspace, raw_path, label="读取路径")

        notes: list[str] = []
        if requested > limit:
            notes.append(f"`limit` 请求 {requested} 行，已按每次调用的上限 {limit} 行截断")
        if lossy:
            notes.append("文件含无法按 UTF-8 解码的字节，已用替换字符显示")

        start = offset - 1
        if total and start >= total:
            summary = (
                f"{rel} 共 {total} 行，第 {offset} 行超出文件末尾，未读到任何内容。"
                f"（文件行号范围 1-{total}）"
            )
            return ToolResult(
                tool=self.name,
                ok=True,
                summary=summary,
                data={
                    "path": rel,
                    "offset": offset,
                    "total_lines": total,
                    "returned_lines": 0,
                    "lines": [],
                    "truncated": False,
                },
            )

        window = lines[start:start + limit]
        last = start + len(window)
        remaining = total - last

        body = "\n".join(f"{start + index + 1}\t{line}" for index, line in enumerate(window))
        header = f"{rel} 第 {start + 1}-{last} 行（共 {total} 行）：" if window else f"{rel} 是空文件（0 行）："
        summary = "\n".join([header, body]) if body else header

        truncated = remaining > 0
        if truncated:
            notes.append(f"已截断：还有 {remaining} 行未显示，可用 offset={last + 1} 继续读取")
        for note in notes:
            summary += f"\n[{note}]"

        summary, clipped = clip(summary, context.limits.max_output_chars)
        if clipped:
            # The clip happens after the line window, so the count in `data` still describes
            # what the model asked for; only the *text* lost its tail.
            notes.append(f"输出超过 {context.limits.max_output_chars} 字符上限，文本尾部被截断")

        return ToolResult(
            tool=self.name,
            ok=True,
            summary=summary,
            data={
                "path": rel,
                "offset": offset,
                "total_lines": total,
                "returned_lines": len(window),
                "next_offset": last + 1 if truncated else None,
                "lines": window,
                "truncated": truncated,
                "notes": notes,
            },
            truncated=truncated or clipped,
        )

    # -- helpers --------------------------------------------------------
    def _refusal(self, target: Path, raw_path: str) -> ToolResult | None:
        """The reasons this path cannot be read, or None when it can."""
        if not target.exists():
            return self._fail(f"文件不存在：{raw_path}")
        if target.is_dir():
            return self._fail(f"{raw_path} 是一个目录；请用 `list_files` 列出其中的文件")
        if not target.is_file():
            return self._fail(f"{raw_path} 不是普通文件（可能是设备、套接字或损坏的链接）")
        try:
            size = target.stat().st_size
        except OSError as exc:
            return self._fail(f"无法读取 {raw_path} 的大小：{exc}")
        if size > MAX_FILE_BYTES:
            return self._fail(
                f"文件过大（{size} 字节 > 上限 {MAX_FILE_BYTES} 字节），`read` 不整体加载它；"
                "请用 `shell_command` 配合 `sed -n` 或 `head`/`tail` 读取需要的区间"
            )
        try:
            with target.open("rb") as handle:
                head = handle.read(_BINARY_PROBE_BYTES)
        except OSError as exc:
            return self._fail(f"无法读取 {raw_path}：{exc}")
        if is_binary(head):
            return self._fail(
                f"{raw_path} 看起来是二进制文件（首个数据块含 NUL 字节），`read` 只读文本；"
                "如果确实需要其中的字符串，请用 `shell_command` 配合 `file` 或 `strings` 之外"
                "的受限命令，并说明理由"
            )
        return None

    def _fail(self, message: str) -> ToolResult:
        return ToolResult(tool=self.name, ok=False, summary=message, error=message)


def _decode(data: bytes) -> tuple[str, bool]:
    """UTF-8 text plus whether any byte had to be replaced.

    Source files in a repository under review are usually UTF-8, sometimes Latin-1, and
    occasionally a mixture. Refusing the whole file over one bad byte would hide an entire
    module from the agent, so the bad byte is replaced -- but the caller is told, because a
    mojibake string is a claim about the code that the file does not support.
    """
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        return data.decode("utf-8", "replace"), True


def is_binary(data: bytes) -> bool:
    """A NUL byte in the first chunk means binary. Shared with the test-suite's expectations."""
    return b"\0" in data[:_BINARY_PROBE_BYTES]
