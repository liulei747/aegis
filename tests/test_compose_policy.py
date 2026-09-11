"""Machine-checked rules about the compose file.

The port policy is the reason this file exists. "Only user-facing services publish a port,
and only on loopback" is a security rule stated in three documents, and the way it dies is a
debugging session where somebody adds a `ports:` entry to reach a worker and forgets to take
it out. A rule that only lives in prose is a rule that lasts until it is inconvenient.

The other assertions pin decisions that are invisible in the YAML and easy to undo by habit:
the gateway must not depend on the worker, the worker must not delegate extraction, and the
Redis policy must not be eviction.

Skipped if PyYAML is unavailable, so this file never blocks a minimal checkout.
"""

from __future__ import annotations

from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = ROOT / "docker" / "docker-compose.yml"

#: The only services allowed to be reachable from the host.
USER_FACING = {"gateway", "web"}


@pytest.fixture(scope="module")
def compose() -> dict:
    doc = yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))
    assert isinstance(doc, dict) and "services" in doc
    return doc


def test_only_user_facing_services_publish_ports(compose: dict) -> None:
    """Workers and Redis use `expose:`, which publishes nothing on the host.

    An exposed scanner or extractor is an endpoint that reads a mounted repository and runs
    a parser over it. The benefit of publishing it is convenience during debugging; the cost
    is that anyone who can reach the host gets that endpoint.
    """
    published = {name for name, service in compose["services"].items() if service.get("ports")}
    assert published <= USER_FACING, (
        f"these services publish host ports but are not user-facing: "
        f"{sorted(published - USER_FACING)}"
    )
    assert published, "at least the gateway must be reachable"


def test_every_published_port_is_bound_to_loopback(compose: dict) -> None:
    """`0.0.0.0` would put a development stack on the coffee-shop network."""
    for name, service in compose["services"].items():
        for mapping in service.get("ports") or []:
            text = str(mapping)
            assert text.startswith("127.0.0.1:"), (
                f"{name} publishes {text!r}; every port must be bound to 127.0.0.1"
            )


def test_workers_publish_nothing(compose: dict) -> None:
    """`expose:` only documents a port, but the worker does not even have one.

    It serves no HTTP: its liveness is "Redis is reachable and my loop is turning over"
    (`services/queue/healthcheck.py`). Keeping a decorative `expose: 8104` would be a
    statement about the container that is not true, and the next person would try to curl it.
    """
    services = compose["services"]
    for name in ("scan", "extract", "worker", "redis"):
        assert "ports" not in services[name], f"{name} must not publish a port"
    for name in ("scan", "extract", "redis"):
        assert "expose" in services[name], f"{name} should document its port with expose:"
    assert "expose" not in services["worker"], "the worker has no HTTP surface to expose"


def test_every_service_has_a_healthcheck_and_a_restart_policy(compose: dict) -> None:
    """Both are needed for the queue to recover: an unhealthy worker must be restarted, and
    a service nobody can probe cannot be part of `depends_on: condition: service_healthy`."""
    for name, service in compose["services"].items():
        assert service.get("healthcheck"), f"{name} has no healthcheck"
        assert service.get("restart"), f"{name} has no restart policy"


def test_dependencies_use_the_condition_form(compose: dict) -> None:
    """`condition: service_healthy` is what makes startup order meaningful; a bare list only
    waits for the container to exist, which for a scanner means "before it can scan"."""
    for name, service in compose["services"].items():
        depends = service.get("depends_on")
        if not depends:
            continue
        assert isinstance(depends, dict), (
            f"{name}.depends_on uses the short form; use condition: service_healthy"
        )
        for target, spec in depends.items():
            assert "condition" in spec, f"{name} -> {target} has no condition"


def test_the_gateway_does_not_depend_on_the_worker(compose: dict) -> None:
    """Read-only bundle queries need the filesystem, not a worker.

    Making the gateway wait for one would take the entire query surface down during a worker
    restart -- including for bundles that finished long ago.
    """
    depends = compose["services"]["gateway"].get("depends_on") or {}
    assert "worker" not in depends, "the gateway must start without a worker"


def test_the_worker_runs_extraction_in_process(compose: dict) -> None:
    """Three reasons, all fatal: no heartbeat during a blocking HTTP call, no progress or
    cancel channel, and the language-server handles live in the wrong container."""
    env = compose["services"]["worker"]["environment"]
    assert env.get("AEGIS_QUEUE__REDIS_URL"), "the worker needs the queue"
    assert env.get("AEGIS_SCAN_SERVICE_URL"), "scanning stays delegated to the small image"
    assert "AEGIS_EXTRACTION_SERVICE_URL" in env, (
        "the key must be present but empty: its absence would let it be re-added by habit"
    )
    assert not env["AEGIS_EXTRACTION_SERVICE_URL"], (
        "the worker must not delegate extraction; see the compose file header"
    )


def test_the_worker_and_gateway_share_one_image(compose: dict) -> None:
    """A second image would be a second copy of the extraction code, free to drift."""
    services = compose["services"]
    assert services["worker"]["image"] == services["gateway"]["image"]
    assert services["worker"]["entrypoint"] == ["aegis-worker"]


def test_redis_never_evicts(compose: dict) -> None:
    """`allkeys-lru` under memory pressure would silently delete job records.

    Losing a job record is losing progress, which is exactly the failure the queue is built
    to prevent. An OOM error that surfaces as a 503 is the better trade.
    """
    command = " ".join(compose["services"]["redis"]["command"])
    assert "noeviction" in command
    assert "--appendonly" in command and "no" in command, "no persistence: the bundle is the record"


def test_the_worker_healthcheck_can_actually_run(monkeypatch, capsys) -> None:
    """The probe in `healthcheck:` must be a command that exists and reports sensibly.

    A healthcheck naming a module that is missing, or that exits 0 when it cannot reach
    Redis, would mark a broken worker healthy -- and `depends_on: condition: service_healthy`
    would then let the gateway start on top of it.
    """
    from services.queue import healthcheck

    monkeypatch.setenv("AEGIS_QUEUE__REDIS_URL", "redis://127.0.0.1:1/0")  # nothing listens
    from aegis_core.config import get_settings

    get_settings.cache_clear()
    try:
        assert healthcheck.main() == 1, "an unreachable queue is not healthy"
        assert "unreachable" in capsys.readouterr().err

        monkeypatch.delenv("AEGIS_QUEUE__REDIS_URL", raising=False)
        get_settings.cache_clear()
        assert healthcheck.main() == 2, "no queue configured is its own failure"
    finally:
        get_settings.cache_clear()


def test_the_console_is_its_own_published_service(compose: dict) -> None:
    """`web` is the second and last service allowed to publish a port.

    Its inclusion in the port policy's allowlist was written before it existed; this is what
    holds the two together, so the day someone adds a `ports:` entry to make a worker
    reachable, the allowlist cannot quietly grow to cover it.
    """
    web = compose["services"]["web"]
    assert web["build"]["dockerfile"] == "services/web/Dockerfile"
    published = [str(entry) for entry in web.get("ports") or []]
    assert published == ["127.0.0.1:${AEGIS_WEB_PORT:-8102}:8102"], published
    # A console that will not start while the API restarts hides the outage from the reader.
    assert "gateway" not in (web.get("depends_on") or {}), (
        "the console must serve its page even when the gateway is unreachable"
    )


def test_shared_volumes_use_identical_container_paths(compose: dict) -> None:
    """A SARIF path produced by one service is handed to another, so the paths must match.

    This is the documented design debt until bytes (or object storage) replace shared
    volumes; until then, a mismatch shows up as "sarif not found from this service".
    """
    import re

    services = compose["services"]
    for name in ("extract", "worker", "gateway"):
        volumes = [str(volume) for volume in services[name].get("volumes") or []]
        for required in ("/workspace", "/data/packages", "/data/work"):
            # Match the container path, which is what follows the *last* colon before the
            # optional mode. Host paths may contain colons (Windows drives), so anchoring on
            # the container path is the only reliable way to read these strings.
            pattern = re.compile(re.escape(required) + r"(?::|$)")
            assert any(pattern.search(volume) for volume in volumes), (
                f"{name} does not mount {required}: {volumes}"
            )
