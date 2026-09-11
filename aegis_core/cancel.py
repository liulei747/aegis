"""Cancellation: the signal, and the shape of the thing that can act on it.

Two design points carry this module, and both are easy to "simplify" into a bug:

**``CanceledAbort`` inherits ``BaseException``.** There are four places in this codebase
whose whole job is to swallow every ``Exception`` so that one bad node does not kill a
run: ``run_scan``'s "no engine at all" handler, ``LanguageServerManager._call``, and the
two per-item guards in the pipeline. A cancel must travel *through* all of them -- being
caught by "degrade and continue" is how a canceled job ends up finishing successfully.
That is exactly what ``BaseException`` buys, and it is why this is not an ``Exception``
subclass. It is a control-flow signal, not a failure: the rule that failures must be
named (:mod:`aegis_contracts.jobs`) applies to failures.

**``TeardownHandle`` is a protocol, and the pipeline only writes to it.** The worker owns
the implementation, so the pipeline never imports the queue package and the queue's
cancellation machinery cannot leak into the assembly code. What the pipeline needs is
narrow: a predicate to ask before each stage, and four registration points for resources
it creates but does not own the lifetime of.

``register_lsp`` takes ``Any`` rather than the manager's real type on purpose: naming it
would make this module import a service, and `aegis_core` is the bottom of the dependency
graph (`tests/test_contracts.py`). A type-only import would still be an edge in that
graph, and the graph is checked by reading imports, not by running them.
"""

from __future__ import annotations

import subprocess
from pathlib import Path
from typing import Any, Protocol, runtime_checkable


class CanceledAbort(BaseException):
    """Raised where a cancel was observed. Never caught by ``except Exception``.

    ``stage`` and ``resource`` are recorded so the worker can say *where* the run stopped
    ("canceled at slice 11/19") rather than just that it stopped. ``scan_record`` is
    carried because a cancel during the scan stage never reaches packaging, so the scan
    ledger attached to this exception is the only surviving record of that scan.
    """

    def __init__(
        self,
        *,
        stage: str,
        resource: str = "stage_boundary",
        detail: str = "",
        scan_record=None,
    ) -> None:
        super().__init__(f"canceled during {stage} ({resource})" + (f": {detail}" if detail else ""))
        self.stage = stage
        self.resource = resource
        self.detail = detail
        self.scan_record = scan_record


@runtime_checkable
class TeardownHandle(Protocol):
    """What the pipeline may ask of the thing that can terminate this run.

    Deliberately tiny. `register_*` calls are the pipeline handing over ownership of
    something it created; `aborted()` is the pipeline asking whether to stop. Nothing here
    reveals how the termination happens, which is what keeps the two packages apart.
    """

    def aborted(self) -> bool: ...

    def register_process(self, name: str, proc: subprocess.Popen) -> None: ...

    def unregister_process(self, name: str) -> None: ...

    def register_lsp(self, manager: Any) -> None: ...

    def register_artifact_dir(self, path: Path) -> None: ...
