"""Turn a caller-supplied workspace string into a path, or explain why it is not one.

This is shared because *two* services ask the same question and must answer it the
same way: the gateway, before it accepts a request, and the extraction service, when it
is asked to probe language servers for a workspace it was handed by path.

It lives in ``aegis_core`` rather than in either service because it is pure policy:
config lookup plus a couple of path checks. Each service translates
:class:`WorkspaceNotFound` into its own protocol error -- that translation is the part
that could not be shared, and keeping it out of here is what lets the extraction
service stop importing the gateway package (see ``tests/test_contracts.py``).
"""

from __future__ import annotations

from pathlib import Path

from aegis_core.config import get_settings


class WorkspaceNotFound(ValueError):
    """The requested workspace is missing, or is not a directory.

    Carries the resolved path so each service can put it in its own error message --
    the path is the useful part of this failure, and re-deriving it in the caller
    invites the two sides to disagree about what was actually checked.
    """

    def __init__(self, path: Path, reason: str) -> None:
        super().__init__(f"workspace {reason}: {path}")
        self.path = path
        self.reason = reason


def resolve_workspace(raw: str | None) -> Path:
    """Relative paths resolve against the configured workspace root.

    The default (``raw is None``) is that root itself, which is what a request with no
    workspace argument means everywhere in this codebase.
    """
    settings = get_settings()
    if raw is None:
        return settings.workspace_root
    path = Path(raw)
    if not path.is_absolute():
        path = (settings.workspace_root / path).resolve()
    path = path.resolve()
    if not path.exists():
        raise WorkspaceNotFound(path, "does not exist")
    if not path.is_dir():
        raise WorkspaceNotFound(path, "is not a directory")
    return path
