"""Which files this run actually read -- derived from the transcript, not self-reported.

`codex-security` asks each worker to return `fully_reviewed_files` and unions the answers. That is a
model's account of its own work, and it is worth having, but it is not checkable. This module takes
the same fact from evidence the harness already records: every `read` call carries `path`, `offset`,
`returned_lines` and `total_lines`, so the windows a run actually returned can be unioned and
compared against each file's length. A file counts as fully read only when those windows cover it
end to end. A listing entry, a grep hit, or a partial read does not count.

Why this is worth computing at all: on the Java benchmark every scope was judged SUFFICIENT while 21
of 30 known positives sat in files no agent had opened. A coverage signal that is a property of the
transcript cannot drift from what happened, and "nobody read this file" is exactly the fact that
scope-level judgement kept losing.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from aegis_contracts.harness import AgentRun, ToolName
from aegis_core.workspace import iter_source_files
from services.harness import survey

#: Files per coverage group. Six, not tuned to any repository: it is small enough that an agent can
#: read every file in its group end to end inside a normal step budget, and large enough that the
#: number of workers stays bounded on a repository of a few hundred files. The rule that matters is
#: the shape -- *coverage* decides how many workers there are -- and this constant only sets the
#: grain.
COVERAGE_GROUP_SIZE = 6

#: Prefix for the scope ids of coverage groups, so `discovery_extra_system` and the closure rule can
#: recognise them without a second registry.
COVERAGE_SCOPE_PREFIX = "scope-coverage-"


def inventory(workspace: Path) -> list[str]:
    """Every source file, workspace-relative and sorted.

    Same suffix set and skip rules as the survey, so the coverage accounting cannot disagree with
    the scope plan about what counts as a source file.
    """
    return sorted(
        path.relative_to(workspace).as_posix()
        for path in iter_source_files(workspace, set(survey.SOURCE_SUFFIXES))
    )


def chunk(files: list[str], *, size: int = COVERAGE_GROUP_SIZE) -> list[list[str]]:
    """Split an inventory into groups of at most `size`.

    Sequential rather than clustered by directory: a group that spans layers is what a vulnerability
    actually looks like (controller to service to mapper), and clustering by directory would rebuild
    the partitioning this exists to work around -- on the benchmark the directory split left a whole
    layer unassigned.

    Every file lands in exactly one group, which is the property the closure rule relies on: a file
    that no group names can never be reported as unread.
    """
    if size < 1:
        raise ValueError("chunk size must be positive")
    return [files[index:index + size] for index in range(0, len(files), size)]


@dataclass
class FileCoverage:
    """How much of one file the transcript accounts for."""

    path: str
    total_lines: int = 0
    #: Half-open line ranges `[start, end)` that some `read` call actually returned.
    windows: list[tuple[int, int]] = field(default_factory=list)
    reads: int = 0

    @property
    def covered_lines(self) -> int:
        return sum(end - start for start, end in _merge(self.windows))

    @property
    def fully_read(self) -> bool:
        if self.total_lines <= 0:
            # A zero-length file, or a read that returned nothing: "fully read" is true only for the
            # former, and an empty file has nothing to miss.
            return self.total_lines == 0 and self.reads > 0
        return self.covered_lines >= self.total_lines


def _merge(windows: list[tuple[int, int]]) -> list[tuple[int, int]]:
    """Union of half-open ranges, sorted. Adjacent ranges are joined so a file read in two
    consecutive calls is one window rather than two."""
    if not windows:
        return []
    ordered = sorted(windows)
    merged = [ordered[0]]
    for start, end in ordered[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def from_runs(runs: list[AgentRun]) -> dict[str, FileCoverage]:
    """Per-file coverage for every file any `read` call touched.

    Only `read` counts. `list_files` and `shell_command` can reveal a file's existence or a line in
    it, and a run that greps a file has not read it -- treating a hit as coverage is how a coverage
    number stops meaning anything.
    """
    found: dict[str, FileCoverage] = {}
    for run in runs:
        for step in run.steps:
            call, result = step.call, step.result
            if call is None or result is None or not result.ok:
                continue
            if getattr(call.tool, "value", call.tool) != ToolName.READ.value:
                continue
            data = result.data or {}
            path = str(data.get("path") or "")
            if not path:
                continue
            entry = found.setdefault(path, FileCoverage(path=path))
            entry.reads += 1
            total = int(data.get("total_lines") or 0)
            entry.total_lines = max(entry.total_lines, total)
            returned = int(data.get("returned_lines") or 0)
            if returned:
                offset = max(1, int(data.get("offset") or 1))
                entry.windows.append((offset, offset + returned))
    return found


def unread_ranges(files: list[str], covered: dict[str, FileCoverage]) -> dict[str, list[tuple[int, int | None]]]:
    """Missing inclusive line intervals; None is an unknown EOF for an unopened file."""
    result = {}
    for name in files:
        entry = covered.get(name)
        if entry is None:
            result[name] = [(1, None)]
            continue
        cursor, missing = 1, []
        for start, end in _merge(entry.windows):
            start, end = max(1, start), min(entry.total_lines + 1, end)
            if start > cursor:
                missing.append((cursor, min(start - 1, entry.total_lines)))
            cursor = max(cursor, end)
        if cursor <= entry.total_lines:
            missing.append((cursor, entry.total_lines))
        if missing:
            result[name] = missing
    return result


def unreviewed(workspace: Path, covered: dict[str, FileCoverage]) -> list[tuple[str, int]]:
    """Source files nobody read end to end, as `(relative_path, line_count)`.

    The inventory comes from the same suffix set and skip rules the survey uses, so this cannot
    disagree with the scope plan about what counts as a source file.
    """
    missing: list[tuple[str, int]] = []
    for path in iter_source_files(workspace, set(survey.SOURCE_SUFFIXES)):
        relative = path.relative_to(workspace).as_posix()
        entry = covered.get(relative)
        if entry is not None and entry.fully_read:
            continue
        try:
            lines = len(path.read_text(encoding="utf-8", errors="replace").splitlines())
        except OSError:
            lines = 0
        missing.append((relative, lines))
    return missing


def unread_in(files: list[str], covered: dict[str, FileCoverage]) -> list[str]:
    """Which of `files` nobody read end to end. The closure rule's input."""
    return [
        name
        for name in files
        if covered.get(name) is None or not covered[name].fully_read
    ]


def summarize(workspace: Path, runs: list[AgentRun], *, sample: int = 15) -> list[str]:
    """Report lines: measured coverage, then the files nobody read.

    The unreviewed list is the useful half. A percentage says how the run went; the list says where
    to look next, and it is the only part of this a reader can act on.
    """
    covered = from_runs(runs)
    files = inventory(workspace)
    full = [name for name in files if covered.get(name) is not None and covered[name].fully_read]
    never = [name for name in files if covered.get(name) is None]
    # `unread_in` is the union the closure rule wants; the report keeps the two apart, because
    # "opened but not finished" and "never opened" call for different next steps.
    partial = [
        name
        for name in unread_in(files, covered)
        if covered.get(name) is not None
    ]

    lines = [f"- 源文件总数：{len(files)}"]
    if files:
        lines.append(
            f"- 完整读过（按 read 调用台账计算，覆盖全部行）：**{len(full)}** / "
            f"{len(files)} = {len(full)/len(files):.0%}"
        )
    lines.append(f"- 只读过一部分或从未打开：**{len(partial)}**")
    lines.append(f"- 从未被打开：**{len(never)}**")
    if never:
        listed = sorted(never)[:sample]
        lines.append("")
        lines.append(f"从未被打开的文件（最多列 {sample} 个）：")
        lines.extend(f"  - {name}" for name in listed)
        if len(never) > sample:
            lines.append(f"  - …还有 {len(never) - sample} 个")
    if partial:
        lines.append("")
        lines.append("只读了片段的文件：")
        for name in sorted(partial)[:sample]:
            entry = covered[name]
            lines.append(
                f"  - {name}（读到 {entry.covered_lines}/{entry.total_lines} 行，"
                f"{entry.reads} 次调用）"
            )
    return lines
