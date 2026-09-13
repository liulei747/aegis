"""Path policy for the tools: nothing an agent asks for may leave the workspace.

The workspace is a repository the harness did **not** write and does not trust. It arrives
from a scan job, which means it is attacker-influenced content: its filenames, its symlinks and
its directory names are all things someone else chose. The one invariant that keeps that
irrelevant is that no tool ever touches a path outside the tree it was pointed at -- not
``read``, not ``list_files``, not ``shell_command``'s arguments.

Why refuse rather than clamp. Clamping ("you asked for ``../../etc/shadow``, here is
``etc/shadow``") silently answers a different question than the one asked, and the model then
reasons about a file it believes it saw. A refusal is a statement the model can act on; a clamp
is a fabrication.

Both Windows and POSIX forms are handled deliberately, because a POSIX-only check is wrong on a
developer's machine and a Windows-only check is wrong in the images the harness ships in. The
nasty case is a *rooted but drive-less* path: ``Path("/etc/passwd").is_absolute()`` is False on
Windows while ``Path("E:/ws") / "/etc/passwd"`` evaluates to ``E:/etc/passwd`` -- the join
itself escapes. So "rooted" is checked in both flavours before anything is joined.
"""

from __future__ import annotations

import re
from pathlib import Path, PurePosixPath, PureWindowsPath

#: A Windows drive-qualified path (`C:\x`, `c:/x`) or a UNC share (`\\host\share`).
_DRIVE_QUALIFIED = re.compile(r"^[A-Za-z]:")

#: A NUL byte cannot appear in a real filename, and it truncates a path inside the C library --
#: the classic way to make a check see one string while the filesystem opens another.
_NUL = "\0"


class ToolArgumentError(ValueError):
    """A tool argument the tool refuses to act on.

    The message is user-facing (Simplified Chinese): it is copied straight into
    ``ToolResult.error``, which is what the model reads and what ends up in the run transcript.
    ``code`` is the machine-readable half -- a short stable tag (``path_escape``,
    ``forbidden_subcommand``, ...) that lands in ``ToolResult.data["refused"]``, so the refusal
    can be counted and asserted on without matching prose.
    """

    def __init__(self, message: str, *, code: str = "refused") -> None:
        super().__init__(message)
        self.code = code


def is_rooted(text: str) -> bool:
    """True for a path that starts at a filesystem root or a drive, in either flavour.

    ``PurePosixPath`` catches ``/etc/passwd`` on Windows, where ``Path.is_absolute()`` does
    not; ``_DRIVE_QUALIFIED`` catches ``C:relative`` (drive but no root), which joins just as
    surprisingly as the rooted form.
    """
    return (
        text.startswith(("/", "\\"))
        or PurePosixPath(text).is_absolute()
        or PureWindowsPath(text).is_absolute()
        or bool(_DRIVE_QUALIFIED.match(text))
    )


def resolve_in_workspace(workspace: Path, raw: str, *, label: str = "路径") -> Path:
    """Resolve ``raw`` against the workspace, or refuse.

    Refused: an empty path, a NUL byte, a rooted path (absolute, drive-qualified or UNC), and
    any relative path whose *resolved* form escapes the workspace -- ``..``, or a symlink
    inside the tree that points out of it. Resolution is what makes the symlink case work:
    checking the text of the path would pass a symlink to ``/etc/passwd`` that the kernel
    then follows.

    Returns the resolved absolute path, which is inside ``workspace`` by construction.
    """
    if not isinstance(raw, str) or not raw.strip():
        raise ToolArgumentError(f"{label}不能为空", code="empty_path")
    text = raw.strip()
    if _NUL in text:
        raise ToolArgumentError(f"{label}含 NUL 字节，已拒绝：{text!r}", code="nul_byte")

    candidate = Path(text)
    resolved = candidate.resolve() if is_rooted(text) else (workspace / candidate).resolve()
    root = workspace.resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        raise ToolArgumentError(
            f"{label}越出工作区，已拒绝：{raw}。工作区内的路径必须相对工作区，"
            "不得使用 `..`，也不得指向外部（含指向外部的符号链接）",
            code="path_escape",
        ) from None
    return resolved


def relative_in_workspace(workspace: Path, raw: str, *, label: str = "路径") -> str:
    """The same check as :func:`resolve_in_workspace`, returning a POSIX relative path.

    Relative in POSIX form because that string is what travels to the dataflow worker: the
    worker matches a finding's file by suffix against its own view of the tree, and a Windows
    separator from a developer's machine would match nothing there.
    """
    resolved = resolve_in_workspace(workspace, raw, label=label)
    return resolved.relative_to(workspace.resolve()).as_posix()


def looks_like_path(text: str) -> bool:
    """Would a program read this argument as a filesystem path?

    Used by ``shell_command`` to decide which arguments must be checked against the workspace.
    A bare name (``repo.py``, ``pattern``, ``-n``) is not a path for this purpose: the working
    directory is the workspace, so a bare name can only ever reach inside it. Anything with a
    separator, a root, a drive or a leading ``~`` can reach somewhere else, so it is checked.
    """
    return (
        is_rooted(text)
        or "/" in text
        or "\\" in text
        or text.startswith("~")
        or text in (".", "..")
    )
