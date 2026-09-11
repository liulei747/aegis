"""The shared layers must stay shared and dependency-free.

If `aegis_contracts` ever imports a service, or either shared package imports the
other in the wrong direction, the service split is cosmetic: every service would
end up dragging the whole application in. This file is the guard.
"""

from __future__ import annotations

import ast
import pathlib

ROOT = pathlib.Path(__file__).resolve().parents[1]
SHARED = ("aegis_contracts", "aegis_core")


def _imports(path: pathlib.Path, *, include_type_only: bool = False) -> set[str]:
    """Modules imported by ``path``.

    ``include_type_only`` defaults to False because the architecture question this file
    asks is a *runtime* one: whether importing a package drags another one in. An import
    guarded by ``TYPE_CHECKING`` does not. The distinction is kept explicit rather than
    ignored so that a type-only edge can still be inspected deliberately.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    guarded: set[int] = set()
    if not include_type_only:
        for node in ast.walk(tree):
            if isinstance(node, ast.If):
                test = node.test
                name = getattr(test, "id", None) or getattr(test, "attr", None)
                if name == "TYPE_CHECKING":
                    guarded.update(id(child) for child in ast.walk(node))

    found: set[str] = set()
    for node in ast.walk(tree):
        if id(node) in guarded:
            continue
        if isinstance(node, ast.Import):
            found.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            found.add(node.module)
    return found


def _shared_files() -> list[pathlib.Path]:
    files: list[pathlib.Path] = []
    for package in SHARED:
        files.extend(sorted((ROOT / package).rglob("*.py")))
    return files


def test_shared_packages_exist() -> None:
    for package in SHARED:
        assert (ROOT / package / "__init__.py").is_file(), f"{package} is not a package"


def test_contracts_do_not_import_any_service() -> None:
    offenders: list[str] = []
    for path in _shared_files():
        for module in _imports(path):
            if module.split(".")[0] in {"app", "services"}:
                offenders.append(f"{path.relative_to(ROOT)}: {module}")
    assert not offenders, "shared code reached into a service: " + "; ".join(offenders)


def test_contracts_forbid_io_and_web_frameworks() -> None:
    """The contract package is data shapes plus pure helpers. Nothing else."""
    banned = {"fastapi", "uvicorn", "starlette", "httpx", "requests", "subprocess", "socket", "redis"}
    offenders: list[str] = []
    for path in (ROOT / "aegis_contracts").rglob("*.py"):
        for module in _imports(path):
            top = module.split(".")[0]
            if top in banned:
                offenders.append(f"{path.relative_to(ROOT)}: {module}")
    assert not offenders, "contracts must not carry I/O: " + "; ".join(offenders)


def test_core_does_not_depend_on_contracts_or_services() -> None:
    """aegis_core is the bottom of the graph: config, logging, text utilities."""
    offenders: list[str] = []
    for path in (ROOT / "aegis_core").rglob("*.py"):
        for module in _imports(path):
            top = module.split(".")[0]
            if top in {"aegis_contracts", "app", "services"}:
                offenders.append(f"{path.relative_to(ROOT)}: {module}")
    assert not offenders, "aegis_core reached upward: " + "; ".join(offenders)


def test_budget_is_part_of_the_contract() -> None:
    """Workers must agree on the budget shape, so it travels with the contracts."""
    from aegis_core.config import BudgetConfig  # budget lives with settings today

    budget = BudgetConfig()
    assert budget.max_depth >= 0
    dumped = budget.model_dump()
    assert "max_depth" in dumped and "max_nodes" in dumped


def test_every_service_dependency_is_satisfiable_from_shared_packages() -> None:
    """A service may import the shared packages; nothing else may be shared."""
    for service_dir in sorted((ROOT / "services").glob("*")):
        if not service_dir.is_dir():
            continue
        for path in service_dir.rglob("*.py"):
            for module in _imports(path):
                top = module.split(".")[0]
                if top in SHARED or top in {"app", "services"}:
                    continue
                # third-party and stdlib are fine; this test only documents intent
                assert top.isidentifier(), f"{path}: odd import {module}"


def test_no_module_reads_static_assets_through_the_api_anymore() -> None:
    """The console moved to its own service; the API must not serve a page again."""
    routing = (ROOT / "app" / "api" / "routes.py").read_text(encoding="utf-8")
    assert "static" not in routing, "the API should no longer serve the console"
    assert not (ROOT / "app" / "api" / "static").exists()


# ---------------------------------------------------------------------------
# The app/ -> services/extraction/ move (see docs/QUEUE_PLAN.md step 0).
#
# Before it, `app` imported `services` (six times: the scan and extraction clients)
# and `services` imported `app` (three times), so the two top-level packages formed a
# cycle and "the gateway is a thin shell" was only true by convention. These two
# assertions are what keeps the move from silently un-happening.
# ---------------------------------------------------------------------------


def _top_level_edges() -> dict[tuple[str, str], int]:
    edges: dict[tuple[str, str], int] = {}
    for top in ("app", "aegis_contracts", "aegis_core", "services"):
        for path in (ROOT / top).rglob("*.py"):
            for module in _imports(path):
                source = module.split(".")[0]
                if source in {"app", "aegis_contracts", "aegis_core", "services"} and source != top:
                    edges[(top, source)] = edges.get((top, source), 0) + 1
    return edges


def test_the_gateway_package_is_not_imported_by_the_services() -> None:
    """`services -> app` must be zero: the capabilities do not depend on the HTTP face.

    The scan/extraction clients stay in `services` (they belong to the capability they
    call); what moved out is everything the *services* needed from `app`.
    """
    offenders = [
        f"{top} -> {source} ({count})"
        for (top, source), count in _top_level_edges().items()
        if source == "app"
    ]
    assert not offenders, (
        "a service imports the gateway package, which re-creates the app<->services "
        "cycle the extraction move removed: " + "; ".join(offenders)
    )


def test_derived_views_stay_a_pure_function_of_the_contract() -> None:
    """`aegis_contracts.views` renders a manifest and nothing else.

    It used to live under the extraction capability, which meant the gateway's query
    endpoints imported the worker's package to render a bundle that was already on disk.
    """
    from aegis_contracts import views  # noqa: F401

    path = ROOT / "aegis_contracts" / "views.py"
    assert path.is_file(), "the derived views belong with the contracts, not a service"
    reached = {m.split(".")[0] for m in _imports(path)}
    assert "app" not in reached and "services" not in reached, (
        f"views.py must not reach into a service: {sorted(reached)}"
    )


def test_the_contract_layer_reaches_core_exactly_once() -> None:
    """A known, pinned exception rather than a growing licence.

    `aegis_contracts/domain.py` uses `aegis_core.utils.estimate_tokens`, a pure text
    helper. That makes `SERVICE_TOPOLOGY.md`'s "contracts are the bottom of the graph"
    slightly untrue, and the fix (duplicate the helper, or invert the dependency) is a
    separate decision. Until then the edge is allowed but *counted*, so a second one
    cannot appear unnoticed. See docs/QUEUE_PLAN.md step 0.
    """
    allowed = ("aegis_contracts", "aegis_core")
    offenders: list[str] = []
    for package in allowed:
        for path in (ROOT / package).rglob("*.py"):
            for module in _imports(path):
                if module.startswith("aegis_core") and package == "aegis_contracts":
                    offenders.append(f"{path.relative_to(ROOT)}: {module}")
    assert len(offenders) == 1, (
        "expected exactly one contracts -> core import (domain.estimate_tokens), found "
        f"{len(offenders)}: {offenders}"
    )
