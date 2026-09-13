"""The projects registry: `project.json` beside the sources, and the list built from them.

There is no separate index file, deliberately. An index would be a second place that can
disagree with what is on disk -- an entry pointing at a deleted directory, or a directory
with no entry -- and reconciling the two is work with no payoff. Writing the record *inside*
the project means the directory is the unit of truth: `rm -rf` a project and it is gone.
"""

from __future__ import annotations

from pathlib import Path

from aegis_contracts.projects import ProjectRecord
from services.projects.fetcher import STAGING_PREFIX

RECORD_NAME = "project.json"


def write_record(project_dir: Path, record: ProjectRecord) -> None:
    """Persist the record. Written whole and replaced, never appended to."""
    target = project_dir / RECORD_NAME
    temporary = target.with_suffix(".json.tmp")
    temporary.write_text(record.model_dump_json(indent=2), encoding="utf-8")
    temporary.replace(target)


def read_record(project_dir: Path) -> ProjectRecord | None:
    """The record for one project, or None.

    A missing or unparseable record returns None instead of raising: one damaged project must
    not make the whole list unreachable, and "no record" is exactly how a directory that was
    placed there by hand looks.
    """
    path = project_dir / RECORD_NAME
    if not path.is_file():
        return None
    try:
        return ProjectRecord.model_validate_json(path.read_text(encoding="utf-8"))
    except (ValueError, OSError):
        return None


def list_records(root: Path) -> list[ProjectRecord]:
    """Every registered project, newest first.

    Staging directories are skipped: one left behind by a crash is inert, and reporting it as
    a project would show the user something that does not exist.
    """
    if not root.is_dir():
        return []
    records: list[ProjectRecord] = []
    for entry in sorted(root.iterdir()):
        if not entry.is_dir() or entry.name.startswith(STAGING_PREFIX):
            continue
        record = read_record(entry)
        if record is not None:
            records.append(record)
    records.sort(key=lambda record: record.created_at, reverse=True)
    return records


def find_record(root: Path, name: str) -> ProjectRecord | None:
    """One project by name. The name is used as a single path component, never as a path."""
    if not name or "/" in name or "\\" in name or name in {".", ".."}:
        return None
    return read_record(root / name)
