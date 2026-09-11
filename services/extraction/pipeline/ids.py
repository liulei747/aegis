"""Content-derived ids, in one place.

`bundle_id` is a *content* fingerprint: same workspace + same findings + same budget means
the same id, so a re-run overwrites instead of piling up, and a prompt prefix keyed on the
id stays valid. That property is used from two directions now:

* the pipeline names the bundle it is about to write (`run()`);
* the startup reconcile asks "is the artifact for this job already on disk?" without
  re-running anything -- and it has to ask the *same question* the pipeline answered.

Two copies of this formula would drift, and the visible symptom of that drift is the worst
kind: a job whose bundle is finished and sitting on disk, reported as lost and re-run. So
the formula lives here and both callers import it.
"""

from __future__ import annotations

from pathlib import Path

from aegis_contracts.domain import Finding
from aegis_core.utils import sha1


def compute_bundle_id(
    *,
    workspace_root: Path,
    findings: list[Finding],
    budget_json: str,
    rule_config: str | None,
    rules: list[str],
) -> str:
    """The content fingerprint of one bundle.

    `run_id` is deliberately not an input: it changes every attempt, and an id that
    changes every attempt makes every cache and diff useless. That mistake is recorded in
    `docs/HANDOVER.md` §5.1; this signature is the shape that prevents repeating it.
    """
    return "B-" + sha1(
        workspace_root.as_posix(),
        ",".join(sorted(f.finding_id for f in findings)),
        budget_json,
        rule_config or "",
        ",".join(rules),
        length=10,
    )
