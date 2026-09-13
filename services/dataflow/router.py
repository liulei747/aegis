"""Project-affinity routing across a fleet of Joern workers.

The invariant that makes workers fast is: *the same project always lands on the same worker*,
so its graph stays resident and queries answer in ~2 s instead of ~9 s. Affinity is therefore
computed, never discovered: `worker_for(workspace) -> index` is a pure function of the
workspace's content hash, and the caller sends the request to exactly that worker.

N is a deployment decision (number of workers started), passed in explicitly. The default is
one worker, which is correct for a single-tenant checkout and a good test of the routing.

    from services.dataflow.router import worker_for
    index = worker_for(workspace_path, n_workers=3)
    url = f"http://127.0.0.1:{base_port + index}/v1/query"
"""

from __future__ import annotations

from pathlib import Path

from services.dataflow.worker import workspace_digest


def worker_for(workspace: Path, n_workers: int) -> int:
    """The worker index that owns this workspace. Stable across calls and processes.

    A content-hash modulo keeps affinity stable while the code is unchanged and remaps cleanly
    when the code changes (a new hash may pick a new worker; the old worker then drops that
    project on its next request, because the digest no longer matches its loaded graph).
    """
    if n_workers <= 0:
        raise ValueError("n_workers must be >= 1")
    if n_workers == 1:
        return 0
    return int(workspace_digest(workspace), 16) % n_workers
