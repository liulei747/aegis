"""Creating projects: fetch sources into the projects root, and register where they came from.

See `services/projects/fetcher.py` for the guards -- this package deliberately imports no web
framework, so the guards can be tested and reasoned about without FastAPI in the picture.
"""

from services.projects.fetcher import (
    ProjectError,
    ProjectExists,
    ProjectFetchFailed,
    ProjectRejected,
    ProjectTooLarge,
    detect_languages,
    extract_archive,
    fetch_git,
    name_from_url,
    slugify,
    validate_git_url,
)
from services.projects.registry import find_record, list_records, read_record, write_record

__all__ = [
    "ProjectError",
    "ProjectExists",
    "ProjectFetchFailed",
    "ProjectRejected",
    "ProjectTooLarge",
    "detect_languages",
    "extract_archive",
    "fetch_git",
    "find_record",
    "list_records",
    "name_from_url",
    "read_record",
    "slugify",
    "validate_git_url",
    "write_record",
]
