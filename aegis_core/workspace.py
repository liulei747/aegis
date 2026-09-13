"""Turn a caller-supplied workspace string into a path, or explain why it is not one.

This is shared because *two* services ask the same question and must answer it the
same way: the gateway, before it accepts a request, and the extraction service, when it
is asked to probe language servers for a workspace it was handed by path.

It lives in ``aegis_core`` rather than in either service because it is pure policy:
config lookup plus a couple of path checks. Each service translates
:class:`WorkspaceNotFound` into its own protocol error -- that translation is the part
that could not be shared, and keeping it out of here is what lets the extraction
service stop importing the gateway package (see ``tests/test_contracts.py``).

It also owns :func:`workspace_digest`, the content hash used to key the CPG cache and to
route a project to a dataflow worker. That one *must* have a single implementation: the
worker and the caller both compute it, and if they ever disagreed the same code would get
two cache keys -- a silent rebuild at best, a stale graph at worst.
"""

from __future__ import annotations

import hashlib
from pathlib import Path

from aegis_core.config import get_settings

#: Extensions the Python frontend can parse. Kept narrow on purpose: handing Joern a
#: repository full of vendored code makes the CPG big and slow for no gain.
PYTHON_SUFFIXES = {".py"}

#: Directories never worth parsing.
SKIP_DIRS = {
    ".git", ".hg", ".svn", "__pycache__", ".venv", "venv", "node_modules",
    ".mypy_cache", ".pytest_cache", ".ruff_cache", "var", "dist", "build",
}


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


def _walk_files(root: Path, suffixes: set[str] | None) -> list[Path]:
    """Files under ``root`` in a stable order, skipping vendored directories.

    ``suffixes=None`` means *every* file.

    The order is pinned to the POSIX spelling of the *relative* path, and that is not fussiness.
    ``Path.__lt__`` compares case-insensitively on Windows and case-sensitively on POSIX, so sorting
    ``Path`` objects gave the same tree two different orders -- and therefore two different content
    hashes -- depending on which platform hashed it. Measured on one 62-file project: Windows
    produced ``1fc12a8c47ebcb05`` and the Linux worker produced ``a03eee558efd8a7d``, with every
    file's bytes identical; the only difference was that ``.../bench/config/My.java`` sorts before
    ``.../bench/Sink.java`` there and after it here. The cache key decides whether a graph is reused,
    so it must not depend on where it was computed.
    """
    found: list[Path] = []
    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if suffixes is not None and path.suffix.lower() not in suffixes:
            continue
        relative = path.relative_to(root)
        if any(part in SKIP_DIRS for part in relative.parts[:-1]):
            continue
        found.append(path)
    found.sort(key=lambda item: item.relative_to(root).as_posix())
    return found


def iter_source_files(root: Path, suffixes: set[str] | None = None) -> list[Path]:
    """Parsable files under ``root``, in a stable order, skipping vendored directories.

    Defaults to the Python set because that is the parse set of the only frontend wired up so
    far; a caller that parses another language passes its own set. For "every file" -- which is
    what a repository-identifying hash needs -- use :func:`workspace_digest`.
    """
    return _walk_files(root, PYTHON_SUFFIXES if suffixes is None else suffixes)


def workspace_digest(root: Path) -> str:
    """Content hash of a workspace: every file's relative path plus its bytes.

    The cache key must be a function of the code, or a stale CPG silently answers questions
    about a version of the file that no longer exists -- the same reason ``bundle_id`` is
    content-derived rather than time-derived.

    **Every file, not just the Python ones**, and that is load-bearing rather than incidental:
    this digest keys the CPG cache (``var/dataflow/cpg/<digest>/cpg.bin``, shared by the whole
    worker fleet) *and* routes a project to a worker. While it hashed only ``.py``, every
    repository containing no Python at all produced the same value -- ``sha1("")[:16]`` -- so two
    unrelated projects shared one cache entry and the second was answered from the first one's
    graph. Measured on the running stack: ``/data/projects/benchmark`` and
    ``/data/projects/git-demo-edebe1`` both hashed to ``da39a3ee5e6b4b0d``. A stale graph is a
    wrong answer while a needless rebuild is only slow, so the tie goes to the rebuild.
    """
    digest = hashlib.sha1()
    for path in _walk_files(root, None):
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()[:16]
