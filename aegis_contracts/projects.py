"""A project: a directory of source code that Aegis can analyse, and where it came from.

Every other service mounts **one** target read-only at ``/workspace``
(``${AEGIS_SCAN_TARGET}:/workspace:ro``). That cannot receive new code, so creating a
project writes into a separate *projects root* instead: writable by the gateway, readable
by everything that analyses code, at the same absolute path everywhere (the dataflow
worker addresses a project by its path, so a path that differs between services would
route a project to a worker that cannot see it).

The record below is what lands in ``<project>/project.json``. It is written **inside** the
project directory rather than into a separate index, so a project is one directory that can
be copied, archived or removed as a unit -- and ``os.replace`` publishes it atomically
along with its metadata.

Only public repositories are supported (``https://``, no credentials). A feature that never
handles a token has no token to leak into a log line or an error message, and that
trade-off is deliberate rather than unfinished: a private repository is brought in as an
uploaded archive instead.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class ProjectSource(str, Enum):
    """How the sources arrived. Kept as a value rather than a boolean because a third
    source (an object store, say) would otherwise be a breaking change."""

    GIT = "git"
    ARCHIVE = "archive"


class ProjectRecord(BaseModel):
    """One project, as registered on disk."""

    schema_version: str = "1.0"
    name: str
    #: Absolute path inside the container. This is what a job request passes as `workspace`.
    workspace: str
    source: ProjectSource
    #: The repository URL, or the uploaded file's name. Never a credential: there are none.
    origin: str
    #: The ref that was *asked* for; None means the remote's default branch.
    ref: str | None = None
    #: The commit actually checked out. Recorded because "the default branch" is not a
    #: version: a bundle built an hour later from the same project may be a different tree,
    #: and without this there is no way to tell which one an analysis saw.
    commit: str | None = None
    created_at: datetime = Field(default_factory=_utcnow)
    #: Size of the sources on disk, after extraction. The point of recording it is the cap:
    #: a reader can see how close a project came to the limit rather than only that it failed.
    bytes: int = 0
    files: int = 0
    #: Files per programming language, most first (e.g. ``{"java": 51, "sql": 2}``).
    #:
    #: Recorded because it predicts how much of the pipeline will work: a real call graph and
    #: taint flow are per-language, so this is what lets a reader learn *before* waiting for an
    #: analysis that the archive they just uploaded is mostly Java and will yield findings but
    #: no dataflow. Empty for a project registered before this field existed.
    languages: dict[str, int] = Field(default_factory=dict)
    #: The analysis job submitted at creation time, when `analyze` was requested.
    job_id: str | None = None
