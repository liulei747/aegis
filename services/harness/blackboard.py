"""The blackboard's persistence and its update rules.

One file, one root object, several writers. That is the whole design constraint, and it decides
everything here:

* **Every update is an append or a merge, never a replacement.** Discovery, validation and
  attack-path agents run at the same time and each of them owns a different slice of the
  blackboard. If a writer replaced the object it read, the other writer's rows would vanish with
  no error anywhere -- the run would simply report fewer candidates than it found, which is the
  one failure mode a security harness cannot make silently.
* **Every append is keyed on the child id.** A stage may be re-entered (a second discovery round
  over an `INSUFFICIENT` scope, a resumed run, a retried agent), and re-entering it must not
  duplicate what it already wrote. Keying on `candidate_id` / `verdict.candidate_id` /
  `work_id` / `run_id` / `scope_id` makes re-running a stage idempotent rather than additive.
* **A scalar context (project / architecture / threats) is merged field by field.** Two agents
  contribute different fields to the same object -- recon knows the languages, threat modelling
  knows the threats -- so the object is merged rather than overwritten, and list fields are
  unioned. The one exception is `ProjectContext.workspace`, which is an *identity*, not a
  finding: it must always name the workspace the run was opened on.

Nothing in this module calls a model or a tool. It is the piece the tests can drive directly.
"""

from __future__ import annotations

import json
import os
import re
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TypeVar

from aegis_contracts.harness import (
    AgentRun,
    ArchitectureMap,
    AttackPath,
    Blackboard,
    Candidate,
    CandidateVerdict,
    CoverageEntry,
    CoverageState,
    CrossScopeLead,
    ProjectContext,
    ThreatModel,
    WorkItem,
    WorkItemState,
)
from aegis_core.logging import get_logger

log = get_logger(__name__)

#: The blackboard's file name inside a run directory. A constant because the report, the CLI and
#: the tests all address the same run directory, and a second name would be a second truth.
BLACKBOARD_FILE = "blackboard.json"

#: Suffix used while writing. `os.replace` then makes the write atomic, so a reader (or a crashed
#: process) never sees half a JSON document. The suffix names the process, so two concurrent
#: writers cannot collide on it.
_TMP_SUFFIX = ".tmp"

T = TypeVar("T")


# ─────────────────────────────────────────────────────────── construction / IO


def new_blackboard(run_id: str, workspace: Path | str) -> Blackboard:
    """An empty blackboard for one run over one workspace.

    `workspace`, `created_at` and `updated_at` are the only things set: a blackboard with
    plausible-looking default content would be a blackboard no agent can tell apart from a filled
    one, and the report would claim coverage nothing produced.
    """
    return Blackboard(run_id=run_id, workspace=str(workspace))


def blackboard_path(run_dir: Path | str) -> Path:
    return Path(run_dir) / BLACKBOARD_FILE


def save(blackboard: Blackboard, run_dir: Path | str) -> Path:
    """Write the whole blackboard to `run_dir/blackboard.json`, atomically.

    Atomic because the blackboard is the only artifact a crashed run leaves behind that is worth
    reading: a reviewer must be able to open it after a kill and see how far the run got. A
    partial write would destroy exactly that evidence.

    `save` does not bump `revision`: revisions count *updates*, and a write that changed nothing
    must not look like one. Mutators bump it.

    **What goes to disk is not what is held in memory.** On the `upp-module-infra` audit the file was
    40 MB, and the parts a reader cannot use were almost all of it: every agent's `read` step carried
    the file body twice (once as the tool's `summary`, once as `data.lines`), 2902 times, for 203
    distinct files. The ledger needs four numbers per read (`path`, `offset`, `returned_lines`,
    `total_lines`); the material reuse needs the lines of a file the run has read *completely*, and one
    copy of those is enough. So the artifact keeps the newest complete read per file and drops the
    rest, and says so rather than looking complete -- see `_slim_for_disk`.
    """
    directory = Path(run_dir)
    directory.mkdir(parents=True, exist_ok=True)
    target = blackboard_path(directory)
    payload = blackboard.model_dump(mode="json")
    payload["runs"] = _slim_for_disk(payload.get("runs") or [])
    fd, tmp_name = tempfile.mkstemp(
        dir=str(directory), prefix=BLACKBOARD_FILE + ".", suffix=_TMP_SUFFIX, text=True
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            # Compact, not `indent=2`: on the module audit the indentation alone was ~3 MB of a 21 MB
            # file, and nobody reads a 21 MB JSON by eye -- the report is the human view of this, and
            # `jq` reads the compact form perfectly well.
            json.dump(payload, handle, ensure_ascii=False, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(tmp_name, target)
    except BaseException:
        # Leaving the temp file behind on failure would make the next `load` ambiguous.
        Path(tmp_name).unlink(missing_ok=True)
        raise
    return target


#: How much of a non-`read` tool result is kept in the artifact. The ledger and the report both read
#: the structured half (`data`); the summary is prose for a human, and past this much of it the
#: human is reading a file listing rather than an audit record. The tail is *dropped* rather than
#: kept aside: keeping it made the artifact 1.5 MB larger to hold text the tool can produce again.
KEPT_SUMMARY_CHARS = 1200

#: How many entries of a list-valued `data` field the artifact keeps (`list_files` returns up to 200
#: paths per call and the module audit made 345 of them; `grep` returns up to 200 matches). The count
#: that was dropped is recorded, so a reader knows the list is a prefix rather than the whole answer.
KEPT_DATA_ITEMS = 50


def _slim_for_disk(runs: list[dict]) -> list[dict]:
    """The run transcripts, with the redundant file bodies removed and every removal stated.

    Three rules, all of them about not lying:

    * a `read` step keeps its `data` (the coverage ledger is computed from exactly those fields) and
      loses its `summary`; the body is either in `data.lines` for the newest complete read of that
      file or reachable in the workspace;
    * older copies of the same file's lines are dropped, and each one records why;
    * a list in `data` is kept as a prefix with its full count beside it.

    Nothing here changes what the run *did*: the ledger fields, the tool names, the thoughts and the
    order are all untouched. What it removes is duplicated bytes.
    """
    newest_complete: dict[str, int] = {}
    for index, run in enumerate(runs):
        for step in run.get("steps") or []:
            call, result = step.get("call") or {}, step.get("result") or {}
            if (call.get("tool") or "") != "read" or not result.get("ok"):
                continue
            data = result.get("data") or {}
            path = str(data.get("path") or "")
            total = int(data.get("total_lines") or 0)
            returned = int(data.get("returned_lines") or 0)
            if path and total > 0 and returned >= total:
                newest_complete[path] = index

    for index, run in enumerate(runs):
        for step in run.get("steps") or []:
            call, result = step.get("call") or {}, step.get("result") or {}
            tool = call.get("tool") or ""
            data = result.get("data") or {}
            if tool == "read":
                path = str(data.get("path") or "")
                if isinstance(data.get("lines"), list):
                    if newest_complete.get(path) != index:
                        data["lines"] = []
                        data["lines_omitted"] = (
                            "同一文件另有更完整的读取记录，此处只保留台账字段（path/offset/"
                            "returned_lines/total_lines）"
                        )
                if result.get("summary"):
                    result["summary_chars"] = len(result["summary"])
                    result["summary"] = (
                        f"{path or '（未记录路径）'}：正文已从产物中省略（内容与工作区文件一致；"
                        "读取窗口见 data）"
                    )
            else:
                summary = result.get("summary")
                if isinstance(summary, str) and len(summary) > KEPT_SUMMARY_CHARS:
                    result["summary_chars"] = len(summary)
                    result["summary"] = (
                        summary[:KEPT_SUMMARY_CHARS]
                        + f"\n（产物中省略后 {len(summary) - KEPT_SUMMARY_CHARS} 字符；"
                        "完整输出在工作区与工具层，本文件只保留台账字段）"
                    )
            for key, value in list(data.items()):
                if isinstance(value, list) and len(value) > KEPT_DATA_ITEMS:
                    data[f"{key}_omitted"] = len(value) - KEPT_DATA_ITEMS
                    data[key] = value[:KEPT_DATA_ITEMS]
    return runs


def load(run_dir: Path | str) -> Blackboard | None:
    """The blackboard in `run_dir`, or None when there is not one.

    None rather than an empty blackboard: "this run has not started" and "this run started and
    found nothing" are different answers, and the coordinator has to be able to tell them apart
    before it decides whether it is resuming or opening.
    """
    path = blackboard_path(run_dir)
    if not path.is_file():
        return None
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        log.warning("blackboard: cannot read %s (%s); treating the run as unopened", path, exc)
        return None
    if not isinstance(payload, dict):
        log.warning("blackboard: %s is not a JSON object; treating the run as unopened", path)
        return None
    try:
        return Blackboard.model_validate(payload)
    except ValueError as exc:
        # A blackboard written by an older contract version is a real possibility; refusing to
        # load it loudly beats loading a half-validated one that silently loses fields.
        log.warning("blackboard: %s does not fit the contract (%s)", path, exc)
        return None


def _touch(blackboard: Blackboard, *, bump: bool = True) -> Blackboard:
    """Stamp an applied update. Every mutator goes through here so none can forget to."""
    if bump:
        blackboard.revision += 1
    blackboard.updated_at = _now()
    return blackboard


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _text(value: Any) -> str:
    """A stable key for an identity field: `ToolName.READ` and `"read"` must not be two keys."""
    if hasattr(value, "value"):
        value = value.value
    return str(value or "").strip()


def _append_unique(items: list[T], item: T, *, key: str | None = None) -> bool:
    """Append `item` unless something with the same key is already there. True when it was added.

    The key is read through `getattr` so a plain pydantic model works; an empty key means the id
    is missing, and a missing id is treated as "already present" rather than as a new row --
    a row nobody can address is a row nobody can deduplicate later either.
    """
    identity = _text(getattr(item, key, "")) if key else _text(item)
    if not identity:
        return False
    if any(_text(getattr(existing, key, "")) == identity for existing in items):
        return False
    items.append(item)
    return True


# ─────────────────────────────────────────────────────────── context merges


def _merge_context(blackboard: Blackboard, fragment: ProjectContext | None) -> bool:
    """Merge recon's findings into `project`. Returns changed."""
    if fragment is None:
        return False
    current = blackboard.project
    if current is None:
        # Adopted through the *merge* rather than by assignment, so that a first payload is normalized
        # exactly like every later one. Assigning it wholesale meant dedup never ran inside a producer's
        # own list: measured on the demo, one agent's first answer contained three phrasings of the same
        # two endpoints and all three landed, because "the board had nothing" and "so take this as it
        # is" were the same branch.
        current = blackboard.project = ProjectContext(workspace="")
    changed = False
    for language, count in fragment.languages.items():
        # A later count for the same language wins: it came from a fuller pass over the tree.
        if current.languages.get(language) != count:
            current.languages[language] = count
            changed = True
    for field in ("build_systems", "notes"):
        incoming = getattr(fragment, field)
        existing = getattr(current, field)
        for value in incoming:
            if value not in existing:
                existing.append(value)
                changed = True
    # Entry points dedupe on *where* they are, not on how they were described. Measured on the demo:
    # four real endpoints arrived as twelve strings -- each agent described each one three times (the
    # `record` call, the final answer, and a rephrasing), and the prose differs even when the place does
    # not. Twelve entry points where there are four is not "more information", it is inflation the
    # reader has to undo by hand, and the endpoint list is read for "what can reach this code", not for
    # a description of it (the first description of a place is kept; two descriptions are not merged).
    known_points = {_entry_point_key(value) for value in current.entry_points}
    for value in fragment.entry_points:
        key = _entry_point_key(value)
        if key and key not in known_points:
            current.entry_points.append(value)
            known_points.add(key)
            changed = True
    if fragment.workspace and not current.workspace:
        current.workspace = fragment.workspace
        changed = True
    return changed


#: The location suffix of an entry point, e.g. `(handler.py:9)` in `order_report(request) (orders.py:15)`.
_ENTRY_POINT_LOCATION = re.compile(r"\(([^()\s]+:\d+)\)")


def _entry_point_key(value: str) -> str:
    """What identifies an entry point: the place it names, else its normalized text.

    A location is the identity because that is what everything downstream needs ("where do requests
    enter"); the sentence after it is a description and two agents will not write the same one.
    """
    match = _ENTRY_POINT_LOCATION.search(value or "")
    if match:
        return match.group(1)
    return " ".join(str(value or "").split()).lower()


def _merge_architecture(blackboard: Blackboard, fragment: ArchitectureMap | None) -> bool:
    """Merge an architecture map. Components are keyed on `id` (then `name`), boundaries by text.

    Components are dicts rather than models because the shape genuinely varies by what the
    repository is; the key is therefore whatever the producer set, and a component without one is
    dropped rather than added twice under two generated names.

    **One row per id, and the row has to be able to hold what that id covers.** Two rules, both of
    which were arrived at by losing data first:

    * *Same key means merge, not drop.* This used to skip an incoming component whose key was already
      present, first writer wins -- and the first writer is the deterministic pre-scan, whose values are
      inferred from directory names. Measured on the first real audit: recon read the code and recorded
      its own version of three of the pre-scan's components, using the same ids as it was told to, and
      all three were discarded (`revision` did not move for those steps). One of them was the component
      for `orders.py`, which is where the demo's only real vulnerability lives.
    * *An id names a granularity, so the two sides of a merge have to agree on it.* A component id from
      the pre-scan (`scope-web-route`) is an **area** -- one per directory or module. A component that
      names a concrete **site** (a file, a route, a line) is one of N, and more of them arrive over time.
      Merging a site into an area by copying fields destroys one of the two: the site's `path` replaces
      the area's (so the row stops describing the area and starts describing one file), and a *second*
      site at the same id is dropped outright, because its fields are ones the row already has.

    So `_enrich_component` splits the incoming side by granularity: sites accumulate in the row's
    `sites` list, keyed by their own identity, and never overwrite the area's `name`/`kind`/`path`.
    Nothing is lost and nothing is invented; the row keeps saying "this area", and `sites` says "these
    places in it". Concrete endpoints have their own append-only channel on top of that
    (`record(kind="entry_point")` -> `project.entry_points`), which is where a route belongs: it is a
    string in a list, so the hundredth one costs nothing and collides with nothing.
    """
    if fragment is None:
        return False
    current = blackboard.architecture
    if current is None:
        # Same reason as `_merge_context`: a first payload has to be normalized too. A model that lists
        # one id twice in a single answer would otherwise put two rows on the board, and the planner
        # plans scopes by id -- one directory, two scopes, two coverage rows that can never agree.
        current = blackboard.architecture = ArchitectureMap()
    changed = False
    known = {_component_key(component) for component in current.components}
    by_key = {
        _component_key(component): component
        for component in current.components
        if isinstance(component, dict)
    }
    workspace = Path(str(blackboard.workspace or ""))
    for component in fragment.components:
        if not isinstance(component, dict):
            continue
        key = _component_key(component)
        if not key:
            continue
        if key not in known:
            current.components.append(component)
            known.add(key)
            by_key[key] = component
            changed = True
            continue
        changed = _enrich_component(by_key[key], component, workspace=workspace) or changed
    for value in fragment.trust_boundaries:
        if value not in current.trust_boundaries:
            current.trust_boundaries.append(value)
            changed = True
    for value in fragment.notes:
        if value not in current.notes:
            current.notes.append(value)
            changed = True
    return changed


#: Which producer's value wins when two components describe the same id. The pre-scan `survey` values
#: are inferred from directory and file names; anything an agent recorded is something it opened. The
#: rank is read off `origin`, and an unknown or missing origin ranks as an agent's reading -- the
#: conservative side is to prefer the value somebody actually looked at.
_ORIGIN_RANK = {"survey": 0}

#: Component fields the pre-scan guesses and an agent can verify. `id` is not here on purpose: it is
#: the identity every downstream consumer keys on (work items, coverage rows, skills), so it is
#: immutable once the row exists.
_UPGRADABLE_FIELDS = ("name", "kind", "path", "description")

#: Fields that only make sense for a *concrete place* rather than for an area: a route registration, an
#: endpoint, an HTTP method, a line. A component carrying one of these is telling us where something
#: happens, not which area it belongs to, and that is the signal the merge uses -- declared by the
#: producer instead of guessed from the string.
_SITE_FIELDS = ("route", "endpoint", "method", "line")


def _origin_rank(component: dict[str, Any]) -> int:
    return _ORIGIN_RANK.get(_text(component.get("origin")), 1)


def _is_site(component: dict[str, Any], workspace: Path) -> bool:
    """Whether this component describes a concrete place (a file, a route, a line) or an area.

    Two signals, in order of how much they prove:

    * it carries a field only a place has (`route`, `endpoint`, `method`, `line`) -- the producer said
      so; or
    * its `path` names a file that exists in the workspace -- checked, not inferred, and the reason
      this function needs the workspace at all.

    A `path` that is not a file (a directory, `.`, an absolute path outside the tree) leaves the
    component an area. That is the conservative direction: treating an area as a place would scatter
    its real content into `sites`, while treating a place as an area only loses the distinction between
    one file and the area containing it -- and the file is still on the row either way.
    """
    if any(_text(component.get(field)) for field in _SITE_FIELDS):
        return True
    path = _text(component.get("path"))
    if not path or not str(workspace):
        return False
    try:
        return (workspace / path).is_file()
    except OSError:  # pragma: no cover - a path that cannot even be stat'ed is not evidence
        return False


def _site_key(component: dict[str, Any]) -> str:
    """A site's identity: its route if it has one, else where it is, else what it is called."""
    for field in _SITE_FIELDS:
        value = _text(component.get(field))
        if value:
            return f"{field}:{value}"
    path = _text(component.get("path"))
    if path:
        return f"path:{path}"
    return f"name:{_text(component.get('name'))}"


def _site_payload(component: dict[str, Any]) -> dict[str, Any]:
    """The part of a component that describes the *place*, kept for `sites`."""
    return {
        field: component[field]
        for field in (*_UPGRADABLE_FIELDS, *_SITE_FIELDS, "origin")
        if field in component
    }


def _append_site(sites: list[Any], component: dict[str, Any]) -> bool:
    """Append a place to a component's `sites`, keyed by its own identity. True when it was new.

    Keyed on the place, not on the whole dict: the same route re-recorded with a better description is
    the same place, and this list is what makes "one area, many endpoints" survivable -- the second,
    third and hundredth route at one id accumulate instead of overwriting the first.
    """
    identity = _site_key(component)
    for entry in sites:
        if isinstance(entry, dict) and _site_key(entry) == identity:
            return False
    sites.append(_site_payload(component))
    return True


def _enrich_component(
    existing: dict[str, Any], incoming: dict[str, Any], *, workspace: Path
) -> bool:
    """Fold `incoming` into the row that already has its id. Returns changed.

    Same granularity, one row, fields taken by evidence strength. Different granularity (a place
    arriving at an area's id), the place goes into `sites` and the area's own fields are left alone --
    see `_merge_architecture` for what that cost when it was the other way round.
    """
    changed = False
    incoming_site = _is_site(incoming, workspace)
    existing_site = _is_site(existing, workspace)

    if incoming_site and not existing_site:
        # The row is the area; this is one of its places. Accumulate -- never overwrite the area.
        sites = existing.setdefault("sites", [])
        if not isinstance(sites, list):  # pragma: no cover - a hand-written blackboard
            sites = existing["sites"] = []
        changed = _append_site(sites, incoming) or changed
    elif incoming_site and existing_site and _site_key(incoming) != _site_key(existing):
        # The row was itself created from a place, and this is another one at the same id. `sites`
        # lists *all* of them, the row's own place included, so a reader never has to special-case
        # the first entry to know how many places the id covers.
        sites = existing.setdefault("sites", [])
        if not isinstance(sites, list):  # pragma: no cover - a hand-written blackboard
            sites = existing["sites"] = []
        if not sites:
            changed = _append_site(sites, existing) or changed
        changed = _append_site(sites, incoming) or changed
    else:
        # Same granularity: an agent's reading replaces the pre-scan's guess, and weak evidence never
        # undoes strong evidence.
        upgrade = _origin_rank(incoming) > _origin_rank(existing)
        for field in _UPGRADABLE_FIELDS:
            value = _text(incoming.get(field))
            if not value or value == _text(existing.get(field)):
                continue
            if upgrade or not _text(existing.get(field)):
                existing[field] = incoming[field]
                changed = True

    # Anything else the producer carried (`files`, a route on an area row, a future key) is kept when
    # the row has nothing under that name: filling holes is safe, overwriting is not.
    for field, value in incoming.items():
        if field in _UPGRADABLE_FIELDS or field in (*_SITE_FIELDS, "id", "origin", "sources", "sites"):
            continue
        if field not in existing:
            existing[field] = value
            changed = True
    for field in _SITE_FIELDS:
        # A route/line on the *area* row is still a fact about the area; keep it if the row lacks it.
        if _text(incoming.get(field)) and not _text(existing.get(field)):
            existing[field] = incoming[field]
            changed = True

    sources = list(existing.get("sources") or [])
    if existing.get("origin") and not sources:
        sources = [str(existing["origin"])]
    source = str(incoming.get("origin") or "model")
    if source not in sources:
        sources.append(source)
        changed = True
    if sources and existing.get("sources") != sources:
        existing["sources"] = sources
    if not incoming_site and _origin_rank(incoming) > _origin_rank(existing):
        # An incoming component with no `origin` came from an agent (the pre-scan always stamps
        # itself), which is exactly the label `board` shows for it. Naming it here keeps the row from
        # still claiming to be a directory-derived guess after an agent has verified it.
        strongest = str(incoming.get("origin") or "model")
        if existing.get("origin") != strongest:
            existing["origin"] = strongest
            changed = True
    return changed


def _component_key(component: dict[str, Any]) -> str:
    for field in ("id", "name", "scope_id", "title"):
        value = _text(component.get(field))
        if value:
            return f"{field}:{value}"
    return ""


def _merge_threats(blackboard: Blackboard, fragment: ThreatModel | None) -> bool:
    if fragment is None:
        return False
    current = blackboard.threats
    if current is None:
        # Normalized like every other merge -- see `_merge_context`.
        current = blackboard.threats = ThreatModel()
    changed = False
    for field in ("assets", "actors", "out_of_scope", "notes"):
        incoming = getattr(fragment, field)
        existing = getattr(current, field)
        for value in incoming:
            if value not in existing:
                existing.append(value)
                changed = True
    known = {_threat_key(threat) for threat in current.threats}
    for threat in fragment.threats:
        key = _threat_key(threat)
        if key and key not in known:
            current.threats.append(threat)
            known.add(key)
            changed = True
    return changed


def _threat_key(threat: dict[str, Any]) -> str:
    for field in ("id", "title", "name", "threat"):
        value = _text(threat.get(field))
        if value:
            return f"{field}:{value}"
    return ""


def set_context(
    blackboard: Blackboard,
    *,
    project: ProjectContext | None = None,
    architecture: ArchitectureMap | None = None,
    threats: ThreatModel | None = None,
) -> Blackboard:
    """Merge the recon / threat-model outputs. No-op-safe: an unchanged merge does not bump."""
    changed = False
    changed |= _merge_context(blackboard, project)
    changed |= _merge_architecture(blackboard, architecture)
    changed |= _merge_threats(blackboard, threats)
    return _touch(blackboard, bump=changed)


def set_security_inventory(blackboard: Blackboard, inventory: Any) -> Blackboard:
    """Persist deterministic leads without mixing them into model-established facts."""
    if blackboard.security_inventory == inventory:
        return blackboard
    blackboard.security_inventory = inventory
    return _touch(blackboard)


# ─────────────────────────────────────────────────────────── appends


def add_candidate(blackboard: Blackboard, candidate: Candidate) -> bool:
    """Append one discovery candidate, keyed on `candidate_id`. True when it was new."""
    if _append_unique(blackboard.candidates, candidate, key="candidate_id"):
        _touch(blackboard)
        _bump_coverage(blackboard, candidate.scope_id, candidates=1)
        return True
    return False


def add_verdict(blackboard: Blackboard, verdict: CandidateVerdict) -> bool:
    """Append one validation verdict, keyed on `candidate_id`.

    Keyed on the candidate, not on a verdict id, because a candidate has exactly one verdict --
    "validated twice" is a bug the ledger should not be able to spell.
    """
    if _append_unique(blackboard.verdicts, verdict, key="candidate_id"):
        _touch(blackboard)
        if verdict.verdict.value == "confirmed":
            candidate = find_candidate(blackboard, verdict.candidate_id)
            if candidate is not None:
                _bump_coverage(blackboard, candidate.scope_id, confirmed=1)
        return True
    return False


def add_attack_path(blackboard: Blackboard, path: AttackPath) -> bool:
    """Append one attack path, keyed on `candidate_id` (one path per confirmed candidate)."""
    if _append_unique(blackboard.attack_paths, path, key="candidate_id"):
        _touch(blackboard)
        return True
    return False


def add_lead(blackboard: Blackboard, lead: CrossScopeLead) -> bool:
    """Append one cross-scope lead, keyed on `lead_id`."""
    if _append_unique(blackboard.leads, lead, key="lead_id"):
        _touch(blackboard)
        return True
    return False


def add_run(blackboard: Blackboard, run: AgentRun) -> bool:
    """Append one agent run, keyed on `run_id`. This is the report's reasoning trail."""
    if _append_unique(blackboard.runs, run, key="run_id"):
        _touch(blackboard)
        return True
    return False


def add_work(blackboard: Blackboard, items: list[WorkItem]) -> int:
    """Open work items, keyed on `work_id`. Returns how many were new.

    Opening a work item also creates its coverage row as `UNSEEN`, so "we planned to look" and
    "we never planned to" cannot be confused in the coverage table later.
    """
    added = 0
    for item in items:
        if _append_unique(blackboard.work, item, key="work_id"):
            added += 1
        if item.kind.value in ("file_review", "investigation"):
            ensure_coverage(blackboard, item.scope_id, title=item.title)
    if added:
        _touch(blackboard)
    return added


def ensure_coverage(blackboard: Blackboard, scope_id: str, *, title: str = "") -> CoverageEntry:
    """The coverage row for `scope_id`, created as `UNSEEN` if the scope is new.

    Returns the entry so a caller can annotate it; creation alone does not bump the revision --
    `set_coverage` is what records a decision, and a revision for "a row exists" would make the
    revision count a poor proxy for progress.
    """
    for entry in blackboard.coverage:
        if entry.scope_id == scope_id:
            if title and not entry.title:
                entry.title = title
            return entry
    entry = CoverageEntry(scope_id=scope_id, title=title or scope_id, state=CoverageState.UNSEEN)
    blackboard.coverage.append(entry)
    return entry


def set_coverage(
    blackboard: Blackboard,
    scope_id: str,
    state: CoverageState,
    *,
    reason: str,
    title: str = "",
) -> CoverageEntry:
    """Record the decision about one scope. Always bumps: a closure decision is a new claim.

    Re-deciding the same scope overwrites the state *on purpose* -- closure is a judgement about
    the current evidence, and a second round that looked again is entitled to change it. The
    reason is replaced with it, so the table can never show a stale justification next to a new
    state.
    """
    entry = ensure_coverage(blackboard, scope_id, title=title)
    entry.state = state
    entry.reason = reason
    _touch(blackboard)
    return entry


def close_work(
    blackboard: Blackboard,
    work_id: str,
    *,
    state: WorkItemState = WorkItemState.DONE,
    steps_used: int = 0,
) -> bool:
    """Close a work item. True when a planned/running item moved to a terminal state.

    `steps_used` is a maximum, not a sum: two rounds that each report 5 steps used 5 steps of
    budget from this item's point of view (whichever was the longest), and summing them would
    inflate the ledger's account of what the run spent.
    """
    changed = False
    for item in blackboard.work:
        if item.work_id != work_id:
            continue
        if steps_used > item.steps_used:
            item.steps_used = steps_used
            changed = True
        if item.state in (WorkItemState.PLANNED, WorkItemState.RUNNING, WorkItemState.BLOCKED):
            item.state = state
            item.closed_at = _now()
            changed = True
    if changed:
        _touch(blackboard)
    return changed


def set_findings(blackboard: Blackboard, findings: list) -> int:
    """Record the final findings. Returns how many were new.

    Appended and keyed on `finding_id` rather than assigned, for the same reason as everything
    else here: two producers of findings must not erase each other.
    """
    added = 0
    for finding in findings:
        if _append_unique(blackboard.findings, finding, key="finding_id"):
            added += 1
    if added:
        _touch(blackboard)
    return added


def mark_closed(blackboard: Blackboard, note: str) -> Blackboard:
    """Close the run with the note the report prints as its closure statement."""
    blackboard.closed = True
    blackboard.closure_note = note
    return _touch(blackboard)


# ─────────────────────────────────────────────────────────── lookups / counters


def find_candidate(blackboard: Blackboard, candidate_id: str) -> Candidate | None:
    for candidate in blackboard.candidates:
        if candidate.candidate_id == candidate_id:
            return candidate
    return None


def find_verdict(blackboard: Blackboard, candidate_id: str) -> CandidateVerdict | None:
    for verdict in blackboard.verdicts:
        if verdict.candidate_id == candidate_id:
            return verdict
    return None


def find_attack_path(blackboard: Blackboard, candidate_id: str) -> AttackPath | None:
    for path in blackboard.attack_paths:
        if path.candidate_id == candidate_id:
            return path
    return None


def coverage_of(blackboard: Blackboard, scope_id: str) -> CoverageEntry | None:
    for entry in blackboard.coverage:
        if entry.scope_id == scope_id:
            return entry
    return None


def confirmed_candidates(blackboard: Blackboard) -> list[Candidate]:
    """Candidates with a `confirmed` verdict, in discovery order. The attack-path stage's input."""
    confirmed = {
        verdict.candidate_id
        for verdict in blackboard.verdicts
        if verdict.verdict.value == "confirmed"
    }
    return [c for c in blackboard.candidates if c.candidate_id in confirmed]


def rejected_candidates(blackboard: Blackboard) -> list[tuple[Candidate, CandidateVerdict]]:
    """`(candidate, verdict)` for everything validation dismissed.

    Kept as a first-class accessor because rejected candidates are part of the answer: the report
    has to say what was considered and dismissed, and a reader deciding whether to trust the
    findings is really asking that question.
    """
    rejected = {
        verdict.candidate_id: verdict
        for verdict in blackboard.verdicts
        if verdict.verdict.value != "confirmed"
    }
    return [(c, rejected[c.candidate_id]) for c in blackboard.candidates if c.candidate_id in rejected]


def scopes_in_state(blackboard: Blackboard, state: CoverageState) -> list[str]:
    return [entry.scope_id for entry in blackboard.coverage if entry.state == state]


def _bump_coverage(
    blackboard: Blackboard, scope_id: str, *, candidates: int = 0, confirmed: int = 0
) -> None:
    """Keep the coverage row's counters in step with the rows themselves.

    Counters are stored rather than derived because the coverage table is what a reviewer reads
    first, and recomputing it at read time would put the counting logic in the report renderer --
    where a scope renamed mid-run could silently drop its tally.
    """
    if not scope_id:
        return
    entry = coverage_of(blackboard, scope_id)
    if entry is None:
        entry = ensure_coverage(blackboard, scope_id)
    entry.candidates += candidates
    entry.confirmed += confirmed
