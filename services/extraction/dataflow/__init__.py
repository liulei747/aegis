"""The extraction pipeline's view of dataflow: a thin client for the worker fleet.

The pipeline does not touch Joern, Docker, or a CPG. It asks the worker that owns this
project for a flow, and attaches method bodies from the local filesystem.

See ``docs/DATAFLOW_CONTRACT.md`` for the contract and ``var/joern/`` for the measurements
that fixed it, including why the flow is handed to a model rather than judged by the engine.
"""

from services.extraction.dataflow.client import (
    DataflowError,
    DataflowUnavailable,
    WorkerDataflowClient,
    attach_bodies,
)

__all__ = [
    "DataflowError",
    "DataflowUnavailable",
    "WorkerDataflowClient",
    "attach_bodies",
]
