"""Raw per-step evidence, written as each step is recorded and kept apart from the trail.

Why a second file next to `trail.jsonl`: the trail is for *watching* a run, so every `agent_step`
clips its thought and its tool summary to `TEXT_LIMIT` characters, and the blackboard's `AgentRun`
is written only when the run finishes. Between those two, a worker that dies mid-run leaves no
complete copy of what the agent actually read -- and the context compaction introduced in batch 3
makes that gap matter, because the *request* the model sees no longer carries the old observations
either. A summary is only honest if the thing it summarises can still be opened.

So this file is the third record, and its properties are the opposite of the trail's:

* **Complete.** A step is written with its full `ToolResult` (summary, `data`, error, truncation
  flag). Nothing here is clipped; the on-disk size is the price of being able to check a summary.
* **Immediate.** Written from the same `on_step` hook that feeds the trail, flushed per line, so
  the last thing on disk is the last thing the agent saw.
* **Passive.** Nothing in the run reads it back. The coverage ledger is still computed from
  `AgentRun.steps`, and a compaction summary is derived from the in-memory steps, not from here.
  Reading it is for a reviewer (or a later recovery pass) -- see `read_run_steps`.

One file per agent run rather than one per audit: concurrent agents would otherwise interleave, and
a reviewer asking "what did *this* run read" should not have to filter a shared stream. The run id
is sanitised into the filename; the original is kept inside every record.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import uuid
from pathlib import Path
from typing import Any

from aegis_contracts.harness import AgentRun, AgentStep
from aegis_core.logging import get_logger

log = get_logger(__name__)

#: Subdirectory of a run directory that holds the per-run evidence files.
EVIDENCE_DIR = "evidence"
SESSION_FILE = "current-session.txt"

_UNSAFE = re.compile(r"[^A-Za-z0-9._-]+")


def evidence_dir(run_dir: Path | str) -> Path:
    return Path(run_dir) / EVIDENCE_DIR


def step_file(run_dir: Path | str, run_id: str) -> Path:
    """An evidence path with a readable prefix and a collision-resistant run-id suffix."""
    safe = (_UNSAFE.sub("_", run_id).strip("_") or "run")[:100]
    digest = hashlib.sha256(run_id.encode("utf-8")).hexdigest()[:16]
    return evidence_dir(run_dir) / f"{safe}-{digest}.steps.jsonl"


class StepArchive:
    """Append-only writer for one audit's raw steps, one JSONL file per agent run.

    Thread-safe: the coordinator runs several agents on a pool and each calls the observer from
    its own thread. Handles are opened lazily and kept until `close`, so a run of eight steps does
    not open a file eight times. A write failure disables the archive for the rest of the audit and
    is logged once per run id -- losing evidence is bad, killing the audit over it is worse, and
    the trail still has the clipped record.
    """

    def __init__(self, run_dir: Path | str) -> None:
        self.run_dir = Path(run_dir)
        self.session_id = uuid.uuid4().hex
        self._lock = threading.Lock()
        self._handles: dict[str, Any] = {}
        self._failed: set[str] = set()
        self.written = 0
        try:
            directory = evidence_dir(self.run_dir)
            directory.mkdir(parents=True, exist_ok=True)
            marker = directory / SESSION_FILE
            pending = directory / f".{SESSION_FILE}.{self.session_id}"
            pending.write_text(self.session_id, encoding="ascii")
            pending.replace(marker)
        except OSError as exc:
            log.warning("evidence: cannot mark current session: %s", exc)

    def record(self, run: AgentRun, step: AgentStep) -> bool:
        """Write one step. Returns whether the complete step was flushed; never raises."""
        key = run.run_id
        with self._lock:
            if key in self._failed:
                return False
            try:
                handle = self._handles.get(key)
                if handle is None:
                    path = step_file(self.run_dir, key)
                    path.parent.mkdir(parents=True, exist_ok=True)
                    # `"a"`: a redriven job keeps its run directory; the trail is truncated by the
                    # coordinator on attach, but evidence from a previous attempt is evidence still
                    # and each record carries the run id and timestamp to tell attempts apart.
                    handle = path.open("a", encoding="utf-8")
                    self._handles[key] = handle
                record = {
                    "session_id": self.session_id,
                    "run_id": run.run_id,
                    "agent": run.agent,
                    "scope": run.scope_id,
                    "step": step.model_dump(mode="json"),
                }
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
                handle.flush()
                self.written += 1
                return True
            except Exception as exc:  # noqa: BLE001 - evidence must not take the run down
                self._failed.add(key)
                log.warning("evidence: archive disabled for %s after %s: %s",
                            key, type(exc).__name__, exc)
                return False

    def close(self) -> None:
        with self._lock:
            for handle in self._handles.values():
                try:
                    handle.close()
                except OSError:  # pragma: no cover - already gone
                    pass
            self._handles.clear()

    def __enter__(self) -> StepArchive:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def read_run_steps(run_dir: Path | str, run_id: str, *, session_id: str | None = None) -> list[AgentStep]:
    """Steps from the latest archive session of one run, in write order.

    A redriven job may reuse a run id and append another attempt to the same file. Older sessions
    remain on disk, but are not mixed into the latest transcript. Damaged lines are skipped.
    """
    path = step_file(run_dir, run_id)
    if not path.is_file():
        return []
    steps: list[AgentStep] = []
    latest_session: str | None = None
    damaged = 0
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
                if record.get("run_id") != run_id:
                    continue
                session = str(record.get("session_id") or "legacy")
                if session_id is not None and session != session_id:
                    continue
                if session != latest_session:
                    steps = []
                    latest_session = session
                steps.append(AgentStep.model_validate(record["step"]))
            except (ValueError, KeyError, TypeError):
                damaged += 1
    if damaged:
        log.warning("evidence: %d damaged line(s) skipped in %s", damaged, path)
    return steps


def current_session(run_dir: Path | str) -> str | None:
    """Session started by the current attempt, or None for older archives."""
    try:
        value = (evidence_dir(run_dir) / SESSION_FILE).read_text(encoding="ascii").strip()
    except OSError:
        return None
    return value or None


def list_runs(run_dir: Path | str) -> list[str]:
    """Run ids with an evidence file, read from the first record of each (not from the filename)."""
    directory = evidence_dir(run_dir)
    if not directory.is_dir():
        return []
    ids: list[str] = []
    for path in sorted(directory.glob("*.steps.jsonl")):
        try:
            with path.open("r", encoding="utf-8") as handle:
                first = handle.readline()
            run_id = json.loads(first).get("run_id")
            if isinstance(run_id, str) and run_id:
                ids.append(run_id)
        except (OSError, ValueError, AttributeError):
            continue
    return ids
