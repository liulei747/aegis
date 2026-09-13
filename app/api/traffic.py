"""An in-process request log, so "what is this gateway actually serving?" is answerable.

Deliberately in-process and bounded: the gateway writes no request log anywhere else -- uvicorn's
access log is off in every deployment shape -- so without this the only way to see traffic was to
attach a debugger or a proxy. A file or a database would be a second source of truth with its own
rotation and permissions, and neither is needed to answer the question.

Two honest limits, stated here rather than discovered later: the buffer is memory, so a restart
starts empty, and a deployment with several replicas has one buffer per replica, so each answers
about its own traffic only. That is why the response carries a `note` instead of looking like a
complete audit trail.
"""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable
from datetime import datetime, timezone

from fastapi import APIRouter, Query, Request
from starlette.responses import Response

#: How many requests are kept. A screen shows tens; a debugging session compares two moments.
#: Bounded because an unbounded list in a long-lived process is a leak with a nice name.
RING_SIZE = 500

#: The one path that is never recorded. See `install` for why excluding only the *current*
#: request would not be enough.
TRAFFIC_PATH = "/v1/traffic"

#: The one honest sentence every response repeats. See the module docstring.
TRAFFIC_NOTE = (
    "进程内环形缓冲区，保存最近 500 个请求：重启后为空，多副本部署时每个副本只报告自己的"
    "流量。发往 /v1/traffic 的请求不会被记录，因此轮询的读取方不会把自己写满日志"
)

router = APIRouter()


class TrafficLog:
    """A fixed-size ring of request records plus a total count that outlives the ring.

    The count is the point: once the ring wraps, `len(entries)` stops changing while the total
    keeps climbing, which is how a caller can tell "nothing happened" apart from "the buffer
    recycled".
    """

    def __init__(self, capacity: int = RING_SIZE) -> None:
        self.capacity = capacity
        self._entries: list[dict] = []
        self._total = 0

    def record(
        self,
        *,
        method: str,
        path: str,
        status: int,
        duration_ms: float,
        client: str = "",
    ) -> dict:
        self._total += 1
        entry = {
            "seq": self._total,
            "at": datetime.now(timezone.utc).isoformat(),
            "method": method,
            "path": path,
            "status": status,
            # Two decimals: a request log is read for "which call was slow", and float noise
            # below a hundredth of a millisecond is not a fact about the request.
            "duration_ms": round(duration_ms, 2),
            "client": client,
        }
        self._entries.append(entry)
        if len(self._entries) > self.capacity:
            del self._entries[: len(self._entries) - self.capacity]
        return entry

    @property
    def count(self) -> int:
        """Requests recorded since process start, including the ones already recycled."""
        return self._total

    def clear(self) -> None:
        """Forget everything, including the total. For a fresh process, and for a test that needs
        a known starting point in a shared buffer."""
        self._entries.clear()
        self._total = 0

    def snapshot(self, limit: int = 200) -> list[dict]:
        """The newest ``limit`` records, newest first."""
        if limit <= 0:
            return []
        newest_first = self._entries[::-1]
        return newest_first[:limit]


#: Process-wide. A middleware and a route have to agree on the buffer, and an app-level
#: dependency would make `/v1/traffic` the one route whose own plumbing is visible in its body.
TRAFFIC = TrafficLog()


def install(app) -> None:
    """Log every request into :data:`TRAFFIC`.

    ``@app.middleware("http")`` rather than a raw ASGI wrapper, and the reason is streaming:
    ``GET /v1/bundles/{id}/archive`` hands back a ``FileResponse``, and a wrapper that buffered
    the body to measure it would hold the whole zip in memory. ``call_next`` returns as soon as
    the response *starts*, so this reads the status code and the elapsed time without ever
    touching the body. The trade-off is that a failure which happens mid-stream is not seen
    here: the record says what the gateway decided to send, not how the client received it.
    """
    log = TRAFFIC

    @app.middleware("http")
    async def _record(
        request: Request, call_next: Callable[[Request], Awaitable[Response]]
    ) -> Response:
        # Reading the log is not traffic. Excluding only the request being answered is not
        # enough, and this was the first version's mistake: the *previous* poll is still in the
        # ring when the next response is built, so a console polling every 5 seconds would fill
        # all 500 slots with its own polls within minutes and hide exactly what it was opened to
        # show. The cost is that a request to this endpoint is invisible here, which is the
        # intended trade: the log answers "what is this gateway serving", not "who is watching".
        if request.url.path == TRAFFIC_PATH:
            return await call_next(request)

        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            # A request that raised is traffic too, and the honest status for it is 500: the
            # exception handlers sit *inside* this middleware, so re-raising would otherwise
            # record nothing at all and make a crashing route invisible here.
            log.record(
                method=request.method,
                path=request.url.path,
                status=500,
                duration_ms=(time.perf_counter() - started) * 1000,
                client=_client_host(request),
            )
            raise
        log.record(
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=(time.perf_counter() - started) * 1000,
            client=_client_host(request),
        )
        return response


def _client_host(request: Request) -> str:
    """The peer host, or ``""``. Never inferred from ``X-Forwarded-For``.

    The header is caller-controlled, so trusting it would let anyone write any address into the
    log; behind a proxy the honest answer is therefore the proxy's address, and the raw socket
    peer is what this reports.
    """
    client = request.client
    return client.host if client is not None else ""


@router.get("/v1/traffic")
def traffic(limit: int = Query(200, ge=1, le=RING_SIZE)) -> dict:
    """The most recent requests, newest first.

    This endpoint is never itself recorded (see :data:`TRAFFIC_PATH`), so it cannot list itself
    and `count` counts real traffic only.
    """
    entries = TRAFFIC.snapshot(limit)
    return {
        "entries": entries,
        "count": TRAFFIC.count,
        "limit": limit,
        "note": TRAFFIC_NOTE,
    }


@router.get("/v1/ai/traffic")
def ai_traffic(limit: int = Query(200, ge=1, le=5000)) -> dict:
    """The model calls this deployment has made, newest first.

    A *different* kind of record from `/v1/traffic` above, and the reason it is a separate route
    rather than more rows in that one: this is written by whichever process talks to the provider
    (gateway, worker, extract), it lands in a file on the shared work volume, and it survives a
    restart. The gateway's ring is per-process and empty after a restart, so folding them into one
    payload would have to describe two retention policies in one note -- and a reader would take the
    shorter-lived one for the whole answer.

    Metadata only, never the prompt or the answer: see `services.ai.traffic` for why. The content
    lives where it belongs -- an audit's conversation in the run trail, a verdict's raw answer in
    the bundle's `ai/answers/`.
    """
    from services.ai import traffic as ai_traffic_log

    page = ai_traffic_log.read_tail(limit=limit)
    return {**page, "limit": limit, "note": ai_traffic_log.note()}
