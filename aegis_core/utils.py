"""Small shared helpers: hashing, token estimates, path/URI conversion, text slicing."""

from __future__ import annotations

import hashlib
import os
import re
from pathlib import Path

_WS = re.compile(r"\s+")
_TRAILING_WS = re.compile(r"[ \t]+$", re.MULTILINE)


def sha1(*parts: str, length: int = 16) -> str:
    h = hashlib.sha1()
    for part in parts:
        h.update(part.encode("utf-8", errors="replace"))
        h.update(b"\x00")
    return h.hexdigest()[:length]


def content_hash(text: str) -> str:
    return hashlib.sha1(text.encode("utf-8", errors="replace")).hexdigest()[:20]


def estimate_tokens(text: str) -> int:
    """Cheap, model-agnostic estimate: CJK chars count double, else ~4 chars/token."""
    if not text:
        return 0
    cjk = sum(1 for ch in text if "\u2e80" <= ch <= "\u9fff" or "\uac00" <= ch <= "\ud7af")
    other = len(text) - cjk
    return int(cjk * 0.9 + other / 4) + 1


def normalize_snippet(text: str, limit: int = 240) -> str:
    return _WS.sub(" ", text).strip()[:limit]


def to_uri(path: Path) -> str:
    return path.resolve().as_uri()


def from_uri(uri: str) -> Path:
    if uri.startswith("file://"):
        raw = uri[len("file://") :]
        # Windows: file:///C:/x -> /C:/x
        if os.name == "nt" and raw.startswith("/") and len(raw) > 2 and raw[2] == ":":
            raw = raw[1:]
        from urllib.parse import unquote

        return Path(unquote(raw))
    from urllib.parse import unquote, urlparse

    return Path(unquote(urlparse(uri).path))


def relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def clamp_text(text: str, max_chars: int, max_lines: int) -> tuple[str, bool, bool]:
    """Return (text, truncated_by_chars, truncated_by_lines)."""
    by_lines = False
    by_chars = False
    lines = text.splitlines()
    if len(lines) > max_lines:
        text = "\n".join(lines[:max_lines])
        by_lines = True
    if len(text) > max_chars:
        text = text[:max_chars]
        by_chars = True
    return text, by_chars, by_lines


# ----------------------------------------------------------------------
# Path rebasing
#
# Scanner output travels between hosts: SARIF produced inside a container says
# "/workspace/src/a.py", a GitHub runner says
# "/home/runner/work/repo/repo/pkg/a.py", Windows says "D:\build\...\a.py".
# Everything downstream needs a path relative to *our* workspace root.
# ----------------------------------------------------------------------

# Leading directories that are container/CI scaffolding rather than project
# structure. When rebasing a foreign absolute path we drop these before matching.
SCAFFOLD_DIRS = frozenset(
    {"workspace", "workspaces", "work", "builds", "home", "root", "tmp", "mnt", "data"}
)

_DRIVE = re.compile(r"^[A-Za-z]:($|/)")


def _looks_absolute(raw: str) -> bool:
    """``Path.is_absolute`` is platform-dependent; scanner output is not."""
    return raw.startswith("/") or bool(_DRIVE.match(raw))


def _absolute_from_parts(raw: str) -> Path:
    """Build a Path from a possibly-foreign absolute string.

    On Windows a bare ``/workspace/x.py`` is *not* absolute to ``PurePath``, and
    ``//workspace/x.py`` becomes a UNC share. So anchor ``/``-rooted POSIX paths
    explicitly on the current drive.
    """
    if raw.startswith("/") and not raw.startswith("//"):
        anchor = Path.cwd().anchor or "/"
        return Path(anchor + raw.lstrip("/"))
    return Path(raw)


def _candidate_suffixes(path: Path) -> list[str]:
    """Directory-anchored suffixes of an absolute path, most specific first."""
    parts = [part for part in path.parts if part not in ("/", "\\")]
    out: list[str] = []
    for start in range(1, len(parts) - 1):  # skip the anchor and the file name
        out.append("/".join(parts[start:]))
    return out


def strip_foreign_prefix(path: Path, root: Path) -> Path | None:
    """Return the workspace-relative suffix of a foreign absolute path.

    ``/workspace/repo/repo.py`` -> ``repo/repo.py`` when that file exists under
    ``root``, dropping the ``workspace`` mount point so the real project path
    survives. Returns ``None`` when nothing sensible can be derived.
    """
    root = root.resolve()
    absolute_root = root.as_posix().rstrip("/")
    for candidate in _candidate_suffixes(path.resolve()):
        stripped = (
            candidate[len(absolute_root) + 1 :]
            if candidate.startswith(absolute_root + "/")
            else candidate
        )
        parts = [part for part in stripped.split("/") if part]
        if not parts or parts[0] in SCAFFOLD_DIRS:
            continue
        if root.joinpath(*parts).exists():
            return Path(*parts)
    return None


def rebase_path(rel: str, root: Path) -> str:
    """Normalise a scanner-reported path into one relative to ``root``.

    * relative URI -> kept as-is (SARIF artifact URIs are root-relative);
    * absolute path inside ``root`` -> made relative;
    * foreign absolute path -> the suffix that exists under ``root`` is used,
      else the best-effort non-scaffold suffix.
    """
    raw = rel.replace("\\", "/").strip()
    if not raw:
        return raw
    if raw.startswith("file://"):
        try:
            return rebase_path(str(from_uri(raw)), root)
        except Exception:  # pragma: no cover - malformed URI
            return raw
    if not _looks_absolute(raw):
        return Path(raw).as_posix()

    root = root.resolve()
    resolved = _absolute_from_parts(raw)
    try:
        return resolved.relative_to(root).as_posix()
    except ValueError:
        pass

    existed = strip_foreign_prefix(resolved, root)
    if existed is not None:
        return existed.as_posix()

    for candidate in _candidate_suffixes(resolved):
        parts = [part for part in candidate.split("/") if part]
        if parts and parts[0] not in SCAFFOLD_DIRS:
            return candidate
    return raw.lstrip("/")


def trim_trailing_whitespace(text: str) -> str:
    return _TRAILING_WS.sub("", text)
