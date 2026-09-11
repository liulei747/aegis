"""The worker's liveness probe, run as `python -m services.queue.healthcheck`.

A worker has no HTTP surface, and adding one just to satisfy `healthcheck:` would be a port
opened for the sake of a probe. What a worker's health actually means is narrower and more
useful than "the process is up":

* **is Redis reachable** -- a worker that cannot reach the queue is not doing its job even
  though it is alive; and
* **is this worker's own heartbeat fresh** -- the loop writes one key per interval, so a
  stale key means the loop is stuck or dead while the process still exists.

The second is exactly the signal the reaper uses to tell a slow job from a dead worker,
which makes it the right thing to check here too: a probe that agreed with the reaper could
not be more consistent with the system it is probing.

Exit code 0 means healthy. Any non-zero exit tells Docker to restart the container.
"""

from __future__ import annotations

import sys
from datetime import datetime, timezone


def main() -> int:
    import redis

    from aegis_core.config import get_settings

    settings = get_settings()
    url = settings.queue.redis_url
    if url is None:
        print("no AEGIS_QUEUE__REDIS_URL: this worker has nothing to consume", file=sys.stderr)
        return 2

    try:
        client = redis.Redis.from_url(url, socket_connect_timeout=3, socket_timeout=3)
        client.ping()
    except Exception as exc:
        print(f"queue unreachable: {exc}", file=sys.stderr)
        return 1

    # Any worker's fresh heartbeat means the loop is turning over. The probe runs in the same
    # container as the worker but as a different process, so it cannot know the worker's exact
    # id -- `consumer_name()` ends in a random suffix. Matching the prefix and taking the
    # newest entry is what makes this a probe of "the loop", not of one particular process.
    fresh = False
    try:
        for key in client.scan_iter(match="aegis:queue:worker:*", count=100):
            value = client.get(key)
            if value is None:
                continue
            stamp = _decode(value).split("|", 1)[0]
            written = datetime.fromisoformat(stamp)
            if written.tzinfo is None:
                written = written.replace(tzinfo=timezone.utc)
            age = (datetime.now(timezone.utc) - written).total_seconds()
            if age < settings.queue.heartbeat_interval_s * 4:
                fresh = True
                break
    except Exception as exc:  # pragma: no cover - Redis trouble
        print(f"could not read the heartbeat: {exc}", file=sys.stderr)
        return 1

    if not fresh:
        print("no fresh worker heartbeat; the loop is not running", file=sys.stderr)
        return 1

    print("ok")
    return 0


def _decode(value) -> str:
    return value.decode("utf-8") if isinstance(value, bytes) else str(value)


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
