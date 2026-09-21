"""`grep` -- a regex search over the workspace, as a tool instead of a shell command.

Why this is not "just let them use `shell_command`": measured on the `upp-module-infra` audit, 1344
of 5198 agent steps were `shell_command`, and most were searches. A search through the shell costs
two round trips (build the command, then read its output) and returns whatever the binary printed --
unbounded, unnumbered, and different on every host. The same search as a tool is one call with a
bounded result whose shape the code decided.

Three refusals, and one visible truncation:

* **escaping the workspace** is refused rather than clamped, on the pattern, the path and the
  `include` glob -- the same rule ``read`` follows, for the same reason: a model that asked for
  ``../../`` and got the workspace would carry on as if it had searched the host.
* **a pattern that is not a regular expression** is refused with the interpreter's own message. A
  search that silently matched nothing because the pattern was malformed is the worst outcome here --
  it reads as "this repository does not contain that", which is exactly the claim a security review
  must never make by accident.
* **a binary file** is skipped, on a NUL byte in its first block, and the skip is counted and
  reported. `errors="replace"` over a compiled artefact produces matches in replacement characters.

Truncation is always stated: `total_matched` is counted past the cap, so a result that stopped early
says how much it did not show. The per-file size cap mirrors ``read.MAX_FILE_BYTES`` and exists for
the same reason.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from aegis_contracts.harness import ToolName, ToolResult
from aegis_core.workspace import SKIP_DIRS
from services.harness.tools.base import ToolContext
from services.harness.tools.paths import (
    ToolArgumentError,
    is_rooted,
    relative_in_workspace,
    resolve_in_workspace,
)
from services.harness.tools.read import MAX_FILE_BYTES, is_binary
from services.harness.tools.support import clip, int_argument, str_argument

#: Files per call, before the match cap. A search inside a directory with more files than this
#: reports that it stopped rather than walking a whole monorepo to answer "where is this string".
MAX_FILES = 4000


class GrepTool:
    """Regex search over the workspace's text files."""

    name = ToolName.GREP

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "description": (
                "用正则搜索工作区内的文本文件，返回 `路径:行号: 该行内容`。"
                "`path` 限定到某个子目录或文件，`include` 限定扩展名（如 `*.java`）。"
                "会跳过 .git/node_modules 等目录、隐藏目录和二进制文件；结果超过上限时会标注"
                "已截断并给出实际命中总数。搜索本身**不算**读取文件，覆盖率台账按 read 计算。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": "Python 正则表达式，例如 `getParameter\\(` 或 `(?i)password`。",
                    },
                    "path": {
                        "type": "string",
                        "description": "相对工作区的目录或文件，默认整个工作区。不接受绝对路径或 `..`。",
                    },
                    "include": {
                        "type": "string",
                        "description": "只搜匹配该 glob 的文件名，例如 `*.java`、`application*.yml`。",
                    },
                    "max": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "本次最多返回多少条命中，超出每次调用的上限时会被截断。",
                    },
                },
                "required": ["pattern"],
                "additionalProperties": False,
            },
        }

    def run(self, context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
        pattern_text = arguments.get("pattern")
        if not isinstance(pattern_text, str) or not pattern_text.strip():
            return self._fail("`pattern` 必须是非空的正则表达式字符串")
        try:
            expression = re.compile(pattern_text)
        except re.error as exc:
            return self._fail(f"`pattern` 不是合法正则：{exc}（模式：{pattern_text!r}）")

        try:
            include = str_argument(arguments, "include", default="") or ""
            _refuse_escaping("include", include)
            requested = int_argument(
                arguments, "max", default=context.limits.max_grep_matches, label="命中数上限"
            )
        except ToolArgumentError as exc:
            return self._fail(str(exc))
        limit = min(requested, context.limits.max_grep_matches)

        raw_path = arguments.get("path")
        if raw_path is None or str(raw_path).strip() in ("", "."):
            root = context.workspace.resolve()
            shown = "."
        else:
            try:
                root = resolve_in_workspace(context.workspace, str(raw_path), label="搜索路径")
                shown = relative_in_workspace(context.workspace, str(raw_path), label="搜索路径")
            except ToolArgumentError as exc:
                return self._fail(str(exc))
        if not root.exists():
            return self._fail(f"搜索路径不存在：{shown}")

        files, scanned, skipped_binary, listing_truncated = _walk(root, include)
        matches: list[dict[str, Any]] = []
        total = 0
        unreadable: list[str] = []
        for path in files:
            text = _text_of(path)
            if text is None:
                unreadable.append(path)
                continue
            for number, line in enumerate(text.splitlines(), start=1):
                if not expression.search(line):
                    continue
                total += 1
                if len(matches) < limit:
                    matches.append(
                        {
                            "path": _relative(context.workspace, path),
                            "line": number,
                            "text": line.strip()[:400],
                        }
                    )

        truncated = total > len(matches)
        notes: list[str] = []
        if requested > limit:
            notes.append(f"`max` 请求 {requested} 条，已按每次调用的上限 {limit} 条截断")
        if listing_truncated:
            notes.append(f"搜索在 {MAX_FILES} 个文件后停止，后面的文件没有搜")
        if skipped_binary:
            notes.append(f"跳过 {skipped_binary} 个二进制文件")
        if unreadable:
            notes.append(f"跳过 {len(unreadable)} 个无法解码的文件，例如 {unreadable[0]}")

        header = (
            f"在 `{shown}`（{scanned} 个文件"
            + (f"，include={include}" if include else "")
            + f"）匹配 `{pattern_text}`：共 {total} 条，显示 {len(matches)} 条。"
        )
        body = "\n".join(f"{m['path']}:{m['line']}: {m['text']}" for m in matches)
        summary = f"{header}\n{body}" if body else header
        if truncated:
            notes.append(f"已截断：还有 {total - len(matches)} 条命中未显示，可收窄 pattern 或 path")
        for note in notes:
            summary += f"\n[{note}]"

        summary, clipped = clip(summary, context.limits.max_output_chars)
        return ToolResult(
            tool=self.name,
            ok=True,
            summary=summary,
            data={
                "pattern": pattern_text,
                "path": shown,
                "include": include,
                "files_scanned": scanned,
                "total_matched": total,
                "count": len(matches),
                "matches": matches,
                "truncated": truncated,
                "notes": notes,
            },
            truncated=truncated or clipped or listing_truncated,
        )

    def _fail(self, message: str) -> ToolResult:
        return ToolResult(tool=self.name, ok=False, summary=message, error=message)


def _refuse_escaping(label: str, value: str) -> None:
    """Neither the path nor the `include` glob may name anything outside the workspace."""
    if not value:
        return
    if is_rooted(value):
        raise ToolArgumentError(f"`{label}` 必须是相对工作区的，不接受绝对路径：{value}")
    if ".." in Path(value).parts or ".." in value.replace("\\", "/").split("/"):
        raise ToolArgumentError(f"`{label}` 不得包含 `..`（会越出工作区）：{value}")


def _walk(root: Path, include: str) -> tuple[list[Path], int, int, bool]:
    """`(files to search, files scanned, binary files skipped, listing truncated)`.

    A directory walk rather than `Path.glob("**/*")` because the skip rules are the same ones
    `list_files` applies (hidden directories and ``SKIP_DIRS``), and applying them during the walk
    is what keeps a search under `node_modules/` from ever being considered.
    """
    if root.is_file():
        return ([root], 1, 0, False)
    found: list[Path] = []
    scanned = 0
    binary = 0
    truncated = False
    for path in sorted(root.rglob("*")):
        rel_parts = path.relative_to(root).parts
        if any(part.startswith(".") or part in SKIP_DIRS for part in rel_parts[:-1]):
            continue
        if not path.is_file() or path.is_symlink():
            continue
        if include and not path.match(include):
            continue
        scanned += 1
        if len(found) >= MAX_FILES:
            truncated = True
            continue
        try:
            if path.stat().st_size > MAX_FILE_BYTES:
                binary += 1
                continue
            with path.open("rb") as handle:
                if is_binary(handle.read(4096)):
                    binary += 1
                    continue
        except OSError:
            continue
        found.append(path)
    return found, scanned, binary, truncated


def _text_of(path: Path) -> str | None:
    try:
        return path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None


def _relative(workspace: Path, path: Path) -> str:
    try:
        return path.resolve().relative_to(workspace.resolve()).as_posix()
    except (ValueError, OSError):
        return path.as_posix()
