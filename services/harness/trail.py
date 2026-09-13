"""The run's event log: what the harness did, written down while it is doing it.

Before this module the coordinator wrote exactly once, in `_finish`. Everything else -- which
scope an agent was on, what it read, what the tool answered, which candidate it filed -- existed
only in memory until the run was over. Two consequences, both measured rather than imagined:

* a 30-minute run was *invisible*. There was no way to tell a slow run from a hung one, and the
  whole coordinator logged three lines.
* `cli.py` says it plainly on interrupt: "已中断：blackboard 不会写出本次未完成的状态". A Ctrl-C
  after 236 model calls and 3998 tool calls lost all of it, including the parts already paid for.

So every fact the blackboard ends up holding is emitted here at the moment it becomes true, as one
JSON line, flushed before the next step starts. That is the whole design. Three rules make it safe:

* **It is a record, never an input.** Nothing reads the trail back into a run. A trail that could
  change the decision it is describing would be a second source of truth, and the two would drift.
* **A broken sink must not sink the run.** A reporting failure is not a security-review failure, so
  a sink that raises is disabled once, logged, and the run continues. The alternative -- letting a
  full disk in the middle of an audit kill the audit -- is worse than losing the log.
* **A torn line is skipped, not fatal.** Append + flush means a kill -9 can leave a partial last
  line. `read_events` drops lines that do not parse and counts them, so a reader sees "one line was
  damaged" instead of a JSONDecodeError instead of a screen.

The vocabulary is closed and deliberately coarse: one event per *thing that happened*, not one per
field that changed. `agent_step` is the interesting one -- it carries the model's thought, the tool
it called, the arguments, and the tool's answer, which together are the agent's side of the
conversation.
"""

from __future__ import annotations

import json
import threading
from collections.abc import Callable, Iterable, Sequence
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Protocol

from aegis_core.logging import get_logger

log = get_logger(__name__)

#: The event kinds. Closed so the reader can switch exhaustively: an unrecognised kind is written
#: as `unknown` with the original under `raw_kind`, which shows up on the screen as a gap in this
#: file's contract rather than as a crash in the middle of a review.
EVENT_KINDS: tuple[str, ...] = (
    "stage",  # a coordinator stage started or finished
    "agent_start",  # one agent run began (which agent, which scope, which task)
    "agent_step",  # one turn: thought + tool call + arguments + tool result
    "agent_end",  # one agent run finished, with its stop reason and step count
    "candidate",  # a discovery result was appended to the ledger
    "verdict",  # a candidate got its decision
    "record",  # an agent wrote a fact onto the blackboard through the `record` tool
    "attack_path",  # a confirmed candidate got its reachability
    "coverage",  # one scope's coverage decision, with its reason
    "finding",  # a FinalFinding was emitted
    "summary",  # the run's closing counters
    "error",  # something failed in a way a reader must see
)

#: The coordinator's stage names. `JobStage` in the job contract is a different, coarser vocabulary
#: (scan/locate/.../ai) -- an audit job reports as one `ai` stage there and its real shape here,
#: because forcing the harness pipeline into a fixed eight-stage track would tell the reader that a
#: repository review is a bundle assembly.
STAGES: tuple[str, ...] = (
    "prep",
    "recon",
    "threat_model",
    "plan",
    "discovery",
    "validation",
    "attack_path",
    "findings",
    "close",
)

#: How much of a tool result / thought is kept per event. The trail is for watching a run, not for
#: reconstructing a file; the whole payload lives in the blackboard's `AgentRun` at the end.
TEXT_LIMIT = 600

#: The trail's filename inside a run directory. Named here so the writer and every reader agree.
TRAIL_NAME = "trail.jsonl"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def clip(text: Any, limit: int = TEXT_LIMIT) -> str:
    """One line, bounded. Newlines are folded so a JSONL reader never sees a fake line break."""
    collapsed = " ".join(str(text or "").split())
    if len(collapsed) <= limit:
        return collapsed
    return collapsed[: limit - 1] + "…"


class TrailSink(Protocol):
    """Somewhere an event goes. `write` receives the finished dict, `seq` and `at` included."""

    def write(self, event: dict) -> None: ...

    def close(self) -> None: ...


class JsonlSink:
    """Append-only JSONL, flushed per line. This is the durable one.

    Flushed per line on purpose: the point of the file is to survive the process dying, and a
    buffered writer that loses the last 4 KB loses exactly the events a reader is looking at when
    they notice the run stopped.

    `mode="w"` is what a *run* wants and `"a"` is what a test or an analysis pass wants. The
    difference matters because a re-run reuses its directory: a job that is redriven keeps its id, so
    an appending sink would write the second attempt's `seq` 1, 2, 3… after the first attempt's
    1, 2, 3… and every reader -- the console's paging, the damaged-line counter -- would be looking
    at two runs pretending to be one.
    """

    def __init__(self, path: Path, *, mode: str = "a") -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._handle = self.path.open(mode, encoding="utf-8")

    def write(self, event: dict) -> None:
        self._handle.write(json.dumps(event, ensure_ascii=False) + "\n")
        self._handle.flush()

    def close(self) -> None:
        try:
            self._handle.close()
        except OSError:  # pragma: no cover - the file is already gone
            pass

    def __enter__(self) -> JsonlSink:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


class CallbackSink:
    """Hands each event to a function. Used to mirror coarse progress into the job record.

    Synchronous, on the emitting thread: the callback is the worker's, and it is expected to be
    cheap. Anything slow belongs in the JSONL and in the screen that reads it, not here.
    """

    def __init__(self, fn: Callable[[dict], None]) -> None:
        self._fn = fn

    def write(self, event: dict) -> None:
        self._fn(event)

    def close(self) -> None:  # pragma: no cover - nothing to release
        pass


class Trail:
    """The fan-out of one event to N sinks, with order and thread safety.

    Thread-safe because discovery, validation and attack paths all run agents on a
    `ThreadPoolExecutor`: without the lock, two threads would interleave a `seq` and produce a log
    whose order contradicts its own numbering.
    """

    def __init__(self, sinks: Sequence[TrailSink] = (), *, base: dict | None = None) -> None:
        self._sinks = list(sinks)
        self._base = dict(base or {})
        self._lock = threading.Lock()
        self._seq = 0
        self._dead: set[int] = set()

    @property
    def seq(self) -> int:
        return self._seq

    @property
    def sinks(self) -> list[TrailSink]:
        return list(self._sinks)

    def emit(self, kind: str, **fields: Any) -> dict:
        """Record one event. Returns it, so a caller can assert on what it wrote."""
        if kind not in EVENT_KINDS:
            log.warning("trail: unknown event kind %r; recorded as `unknown`", kind)
            fields = {**fields, "raw_kind": kind}
            kind = "unknown"
        if kind == "stage" and fields.get("stage") not in STAGES:
            log.warning("trail: unknown stage %r", fields.get("stage"))
        with self._lock:
            self._seq += 1
            event = {"seq": self._seq, "at": _now(), "kind": kind, **self._base, **fields}
        for index, sink in enumerate(self._sinks):
            if index in self._dead:
                continue
            try:
                sink.write(event)
            except Exception as exc:  # noqa: BLE001 - a broken sink must not kill the run
                self._dead.add(index)
                log.warning(
                    "trail: %s disabled after %s: %s",
                    type(sink).__name__,
                    type(exc).__name__,
                    exc,
                )
        return event

    def counters(self, blackboard: Any) -> dict:
        """The run's counters, as a stage event carries them.

        Read from the blackboard rather than accumulated here: the ledger is the fact, and a
        running total kept by the reporting path is a second one that can disagree with it.
        """
        try:
            from services.harness import blackboard as bb

            opening = getattr(blackboard, "opening", None)
            return {
                "candidates": len(blackboard.candidates),
                "verdicts": len(blackboard.verdicts),
                "confirmed": len(bb.confirmed_candidates(blackboard)),
                "findings": len(blackboard.findings),
                "scopes": len(blackboard.coverage),
                "agent_runs": len(blackboard.runs),
                "rounds": getattr(blackboard, "rounds_run", 0),
                # The opening pair's convergence, in the same place as everything else a reader
                # watches: `opening_unread > 0` means the stage stopped with material one agent never
                # read, which the screen shows next to the counters rather than only in the report.
                "opening_passes": opening.passes if opening else 0,
                "opening_unread": sum(opening.unread.values()) if opening else 0,
            }
        except Exception:  # pragma: no cover - reporting must never break the run
            return {}

    def close(self) -> None:
        for sink in self._sinks:
            try:
                sink.close()
            except Exception:  # noqa: BLE001 - closing is best effort
                pass

    def __enter__(self) -> Trail:
        return self

    def __exit__(self, *exc_info: object) -> None:
        self.close()


def disabled() -> Trail:
    """A trail with nowhere to go: the default, so a caller that does not care pays nothing."""
    return Trail()


def read_events(path: Path, *, after_seq: int = 0, limit: int = 500) -> dict:
    """The events after `after_seq`, oldest first, plus whether there are more.

    `after_seq` is what makes the screen incremental: a poll re-reads the file but only returns what
    the reader has not seen, so the request is small and the client never has to merge or re-sort.
    Reading the file per poll is deliberate -- a trail is thousands of lines, not millions, and an
    index would be another thing to keep in sync with the append path.

    A damaged line (a kill between write and flush) is counted, not raised: the run that produced it
    is over, and refusing to show the rest of its record because of one bad byte is the wrong call.
    """
    collected: list[dict] = []
    last_seq = after_seq
    damaged = 0
    more = False
    if not path.is_file():
        return {"events": [], "last_seq": after_seq, "damaged": 0, "more": False, "exists": False}
    with path.open("r", encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                event = json.loads(line)
            except json.JSONDecodeError:
                damaged += 1
                continue
            seq = event.get("seq")
            if not isinstance(seq, int):
                damaged += 1
                continue
            if seq <= after_seq:
                last_seq = max(last_seq, seq)
                continue
            if len(collected) >= limit:
                # One past the page: `more` is a fact about the file, and the caller needs it to
                # decide whether to poll again immediately or wait.
                more = True
                break
            collected.append(event)
            last_seq = max(last_seq, seq)
    return {
        "events": collected,
        "last_seq": last_seq,
        "damaged": damaged,
        "more": more,
        "exists": True,
    }


def iter_events(path: Path) -> Iterable[dict]:
    """Every event in the file, for tests and offline analysis."""
    yield from read_events(path, after_seq=0, limit=10**9)["events"]
