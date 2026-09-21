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
USER_FACING = {"gateway", "frontend"}


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
    a service nobody can probe cannot be part of `depends_on: condition: service_healthy`.

    Services behind `profiles:` are exempt, and not as a convenience. A profiled service is not
    started by `up`, cannot be a `depends_on` target, and is nothing the queue has to recover.
    `harness` is the one such entry: a one-shot CLI that reviews a workspace and exits, so a
    healthcheck would describe a long-lived process that does not exist and a restart policy
    would restart a batch job that had already finished.
    """
    for name, service in compose["services"].items():
        if service.get("profiles"):
            continue
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


def test_each_service_has_a_distinct_image_name(compose: dict) -> None:
    """Every service that runs the extraction toolchain gets its own image tag.

    The four callers of `docker/Dockerfile` (extract / worker / gateway / harness) used to
    share one `aegis:0.1.0` image, which made it impossible to rebuild and redeploy one of
    them (a language-server bump, say) without pulling the others along. They are now split
    into distinct tags -- same Dockerfile, separate deployable artifacts -- so a change to one
    never forces a rebuild of the rest. Distinct tags are what makes `docker compose build
    extract` touch only the extractor.
    """
    services = compose["services"]
    build_images = {
        name: svc["image"]
        for name, svc in services.items()
        if svc.get("build") and svc["build"].get("dockerfile") == "docker/Dockerfile"
    }
    expected = {"extract", "worker", "gateway", "harness"} <= set(build_images)
    assert expected, f"the four extraction callers must build from docker/Dockerfile: {sorted(build_images)}"
    assert len(build_images) == len(set(build_images.values())), (
        f"each service must have its own image tag so it can be deployed alone; got {build_images}"
    )
    # Every extraction caller that is not a profiled tool runs in-process and needs the worker
    # entrypoint; it also shares the exact same Dockerfile, so none of them can drift by
    # accident at the container level -- only the tag separates them.
    assert services["worker"]["image"] != services["gateway"]["image"]
    assert services["worker"]["image"] != services["extract"]["image"]
    assert services["worker"]["entrypoint"] == ["aegis-worker"]


def test_redis_never_evicts(compose: dict) -> None:
    """`allkeys-lru` under memory pressure would silently delete job records.

    Losing a job record is losing progress, which is exactly the failure the queue is built
    to prevent. An OOM error that surfaces as a 503 is the better trade.
    """
    command = " ".join(compose["services"]["redis"]["command"])
    assert "noeviction" in command
    assert "--appendonly" in command and "no" in command, "no persistence: the bundle is the record"


def test_the_dataflow_fleet_matches_the_configured_worker_count(compose: dict) -> None:
    """Affinity divides the project hash by `worker_count`, so the number is load-bearing.

    `worker_for(workspace, N) = hash % N` -- if the deployment starts fewer workers than `N`,
    the projects that hash to the missing index are not "slower", they are unreachable: the
    request goes to a hostname that does not resolve. And the names must be exactly
    `dataflow-<index>`, because that is what the default `worker_url_template`
    (`http://dataflow-{index}:8105`) expands to.
    """
    import re

    services = compose["services"]
    fleet = {name: svc for name, svc in services.items() if re.fullmatch(r"dataflow-\d+", name)}
    assert fleet, "the dataflow fleet is not in the compose file"

    indices = sorted(int(name.rsplit("-", 1)[1]) for name in fleet)
    assert indices == list(range(len(fleet))), (
        f"the fleet must be indexed 0..N-1 with no gaps; got {indices}"
    )

    for name in ("extract", "worker"):
        declared = services[name]["environment"].get("AEGIS_DATAFLOW__WORKER_COUNT")
        assert declared is not None, f"{name} runs extraction but does not size the fleet"
        assert int(declared) == len(fleet), (
            f"{name} says there are {declared} workers but the file starts {len(fleet)}"
        )
        assert services[name]["environment"].get("AEGIS_DATAFLOW__ENABLED"), (
            f"{name} would never use the fleet it just sized"
        )


def test_every_dataflow_worker_sees_the_same_workspace(compose: dict) -> None:
    """Identical mounts are what make a wrong affinity guess slower instead of fatal.

    Affinity is a policy -- keep a graph hot -- not a routing necessity. The moment the workers
    mount *different* projects, a request routed to the "wrong" worker hits a path it cannot see
    and 404s. It would also break the shared-volume contract: the extractor sends the workspace
    path it already has, with no translation anywhere (see `test_shared_volumes_...`).
    """
    import re

    sources = {}
    indices = {}
    for name, service in compose["services"].items():
        if not re.fullmatch(r"dataflow-\d+", name):
            continue
        mounts = [str(volume) for volume in service.get("volumes") or []]
        workspace = [m for m in mounts if re.search(r"/workspace(?::|$)", m)]
        assert len(workspace) == 1, f"{name} must mount exactly one /workspace: {mounts}"
        sources[name] = workspace[0].rsplit(":/workspace", 1)[0]
        indices[name] = service["environment"]["AEGIS_DATAFLOW__WORKER_INDEX"]
        assert "ports" not in service, f"{name} must not publish a host port"

    assert len(set(sources.values())) == 1, (
        f"every worker must mount the same project path; got {sources}"
    )
    assert len(set(indices.values())) == len(indices), (
        f"each worker needs its own scratch and its own index; got {indices}"
    )

    # ...and the same one the caller has, because the caller sends the path it already sees.
    caller_mounts = [str(v) for v in compose["services"]["extract"].get("volumes") or []]
    caller_workspace = next(
        (m for m in caller_mounts if re.search(r"/workspace(?::|$)", m)), None
    )
    assert caller_workspace is not None, "extract must mount /workspace"
    assert caller_workspace.rsplit(":/workspace", 1)[0] == next(iter(sources.values())), (
        "the extractor and the workers must mount the same host path at /workspace, or the "
        f"path the extractor sends will not exist in the worker: {caller_workspace} vs {sources}"
    )


def test_nothing_depends_on_a_dataflow_worker(compose: dict) -> None:
    """Both callers probe `/health` and fall back to the crawl with a recorded warning.

    Gating their startup on a 5.9 GB JVM would trade a degraded bundle for no bundle at all --
    the same trade the gateway already refuses to make with `worker`.
    """
    import re

    for name, service in compose["services"].items():
        if re.fullmatch(r"dataflow-\d+", name):
            continue
        depends = service.get("depends_on") or {}
        assert not any(re.fullmatch(r"dataflow-\d+", target) for target in depends), (
            f"{name} waits for the dataflow fleet; it must degrade instead"
        )


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
    """`frontend` is the second and last service allowed to publish a port.

    Its inclusion in the port policy's allowlist was written before it existed; this is what
    holds the two together, so the day someone adds a `ports:` entry to make a worker
    reachable, the allowlist cannot quietly grow to cover it.
    """
    frontend = compose["services"]["frontend"]
    assert frontend["build"]["dockerfile"] == "docker/frontend.Dockerfile"
    published = [str(entry) for entry in frontend.get("ports") or []]
    assert published == ["127.0.0.1:${AEGIS_FRONTEND_PORT:-8102}:8102"], published
    # A console that will not start while the API restarts hides the outage from the reader.
    assert "gateway" not in (frontend.get("depends_on") or {}), (
        "the console must serve its page even when the gateway is unreachable"
    )


def test_the_console_is_told_where_the_api_is_at_run_time(compose: dict) -> None:
    """The API's address is configuration, not something baked into the image.

    Two halves, and both are load-bearing. The compose service passes `AEGIS_API_BASE`, which the
    image's entrypoint turns into `/config.js`; and nginx in that image proxies nothing, so the
    browser's request goes to the gateway rather than back through this container. Drop either and
    the front-end becomes deployable only from behind one specific proxy -- which is what the
    preceding `aegis-web` service was, and why it was replaced.
    """
    frontend = compose["services"]["frontend"]
    environment = frontend.get("environment") or {}
    assert "AEGIS_API_BASE" in environment, (
        "without it the image has no address to serve and falls back to same-origin"
    )
    # It must be the gateway as the *browser* sees it: the published host port, not the compose
    # service name, because the browser is not on the compose network.
    assert "AEGIS_GATEWAY_PORT" in str(environment["AEGIS_API_BASE"]), (
        f"the address must be the published gateway port; got {environment['AEGIS_API_BASE']!r}"
    )

    nginx = (ROOT / "frontend" / "nginx.conf").read_text(encoding="utf-8")
    # Directives only. The file's own comment explains that there is no `proxy_pass` here, and a
    # substring search would trip over that sentence instead of over a directive.
    directives = [
        line.strip()
        for line in nginx.splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]
    assert not [line for line in directives if line.startswith("proxy_pass")], (
        "the console image must serve files only; proxying /v1 would weld it to the gateway again"
    )
    assert not [line for line in directives if line.startswith("resolver")], (
        "a resolver means something here is proxying; nothing should be"
    )
    entrypoint = ROOT / "frontend" / "docker-entrypoint.d" / "10-api-base.sh"
    assert entrypoint.is_file(), "the entrypoint that writes /config.js is what makes one image reusable"
    assert "AEGIS_API_BASE" in entrypoint.read_text(encoding="utf-8")


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
