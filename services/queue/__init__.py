"""The job queue's shared pieces.

Not a deployed service: the gateway needs the job records (to submit and to answer
status) and the worker needs the stream (to claim work), so this sits beside ``scan`` and
``extraction`` as a capability package rather than inside either of them. Putting it
under ``services/extraction`` would make the gateway depend on the worker's package,
which is the coupling the extraction move just removed.

Import submodules directly (``services.queue.streams``); this package deliberately
re-exports one name only, so importing the package does not drag in the stream layer.
"""

from __future__ import annotations

from services.queue.jobs import JobStore

__all__ = ["JobStore"]
