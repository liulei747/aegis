"""`list_files` -- the orientation tool: workspace-relative paths with sizes.

This is the cheapest tool and the one the model calls first, so its output has to be three
things at once: **complete for its bound** (the result says when it stopped early, because a
truncated listing that looks complete is how a model concludes a directory is empty),
**stable** (sorted, relative, POSIX separators -- the same tree must produce the same text in
every process, or two agents describing the same repository disagree), and **cheap** (bounded
per call, no file contents, and it never walks into a vendored tree).

Why ``Path.glob`` and not ``aegis_core.workspace.iter_source_files``. The frozen surface of this
tool takes a *glob pattern*, and ``iter_source_files`` pins the suffix set to the ones the Python
frontend parses -- reusing it here would make ``pattern`` a lie (``**/*.ts`` would return
nothing). What is reused is the part that actually encodes policy: ``SKIP_DIRS``, so "vendored
directory" has exactly one definition in this codebase. There is no second walker here: globbing
is the standard library's job, and the filtering on top of it is a filter, not a walk.

Hidden directories are skipped for the same reason ``SKIP_DIRS`` exists, and one more: ``.git``
is both, but a repository also carries ``.venv``, ``.tox``, ``.next`` and friends, and an
inventory dominated by a virtualenv is an inventory that hides the code under review.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath
from typing import Any

from aegis_contracts.harness import ToolName, ToolResult
from aegis_core.workspace import SKIP_DIRS
from services.harness.tools.base import ToolContext
from services.harness.tools.paths import ToolArgumentError, is_rooted
from services.harness.tools.support import clip, int_argument, str_argument

DEFAULT_PATTERN = "**/*"


class ListFilesTool:
    """Glob the workspace, returning relative paths and sizes."""

    name = ToolName.LIST_FILES

    def schema(self) -> dict[str, Any]:
        return {
            "name": self.name.value,
            "description": (
                "按 glob 模式列出工作区内的文件（相对路径 + 字节大小，已排序）。默认 `**/*`。"
                "会跳过 .git/__pycache__/node_modules 等目录和隐藏目录；结果超过上限时会在"
                "结果中标注已截断。用来先建立对仓库结构的认识。"
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": (
                            "相对工作区的 glob 模式，例如 `**/*.py`、`services/**/*.go`。"
                            "默认 `**/*`。不接受绝对路径或 `..`。"
                        ),
                    },
                    "max": {
                        "type": "integer",
                        "minimum": 1,
                        "description": "本次最多返回多少个文件，超出每次调用的上限时会被截断。",
                    },
                },
                "required": [],
                "additionalProperties": False,
            },
        }

    def run(self, context: ToolContext, arguments: dict[str, Any]) -> ToolResult:
        try:
            pattern = str_argument(arguments, "pattern", default=DEFAULT_PATTERN) or DEFAULT_PATTERN
            _refuse_escaping_pattern(pattern)
            requested = int_argument(
                arguments,
                "max",
                default=context.limits.max_list_files,
                label="文件数上限",
            )
        except ToolArgumentError as exc:
            return self._fail(str(exc))
        limit = min(requested, context.limits.max_list_files)

        root = context.workspace.resolve()
        files: list[tuple[str, int]] = []
        matched = 0
        try:
            entries = sorted(context.workspace.glob(pattern))
        except (ValueError, NotImplementedError, OSError) as exc:
            return self._fail(f"glob 模式无法使用：{pattern}（{type(exc).__name__}: {exc}）")

        for path in entries:
            rel = _relative_entry(root, path)
            if rel is None:
                continue
            if not path.is_file():
                continue
            # A symlink is how a repository reaches a file it does not contain. The listing is
            # a statement about *this* workspace, so a link out of it is not listed as one of
            # the repository's files -- the model would otherwise plan around code that is not
            # in scope (and `read` would refuse it a step later, which looks like a broken tool).
            try:
                path.resolve().relative_to(root)
            except (ValueError, OSError):
                continue
            matched += 1
            if len(files) >= limit:
                # Deliberately no stat() past the bound: the whole point of the cap is that a
                # call over a huge tree stays cheap. Counting the matches is enough to be able
                # to say "there were more".
                continue
            try:
                size = path.stat().st_size
            except OSError:
                size = -1
            files.append((rel, size))

        truncated = matched > len(files)
        notes: list[str] = []
        if requested > limit:
            notes.append(f"`max` 请求 {requested} 个，已按每次调用的上限 {limit} 个截断")

        body = "\n".join(f"{size:>9}\t{rel}" for rel, size in files)
        if files:
            header = f"工作区（模式 `{pattern}`）匹配 {matched} 个文件，显示 {len(files)} 个："
        else:
            header = f"工作区（模式 `{pattern}`）没有匹配到任何文件。"
        summary = f"{header}\n{body}" if body else header
        if truncated:
            notes.append(
                f"已截断：还有 {matched - len(files)} 个匹配未显示，可提高 `max` 或收窄 `pattern`"
            )
        for note in notes:
            summary += f"\n[{note}]"

        summary, clipped = clip(summary, context.limits.max_output_chars)
        return ToolResult(
            tool=self.name,
            ok=True,
            summary=summary,
            data={
                "pattern": pattern,
                "count": len(files),
                "total_matched": matched,
                "files": [{"path": rel, "size": size} for rel, size in files],
                "truncated": truncated,
                "notes": notes,
            },
            truncated=truncated or clipped,
        )

    def _fail(self, message: str) -> ToolResult:
        return ToolResult(tool=self.name, ok=False, summary=message, error=message)


def _refuse_escaping_pattern(pattern: str) -> None:
    """A glob may not name anything outside the workspace.

    ``Path.glob("../*")`` happily walks the parent directory -- measured, it lists the harness's
    own scratch files. Refusing the pattern is not a clamp: a pattern that reaches outside is
    either a mistake or an attempt to inventory the host, and both deserve the same answer.
    """
    if is_rooted(pattern):
        raise ToolArgumentError(f"glob 模式必须是相对工作区的，不接受绝对路径：{pattern}")
    if ".." in PurePosixPath(pattern).parts or ".." in Path(pattern).parts:
        raise ToolArgumentError(f"glob 模式不得包含 `..`（会越出工作区）：{pattern}")


def _relative_entry(root: Path, path: Path) -> str | None:
    """The workspace-relative POSIX path, or None when it is not one this listing reports.

    Hidden directories and ``SKIP_DIRS`` are skipped by *directory* part, so a file named
    ``.env`` at the top of the tree is still listed (it is part of the repository and often the
    point of the review) while anything under ``.git/`` or ``node_modules/`` is not.
    """
    try:
        rel = path.relative_to(root)
    except ValueError:
        return None
    parts = rel.parts[:-1]
    if any(part.startswith(".") or part in SKIP_DIRS for part in parts):
        return None
    return rel.as_posix()
