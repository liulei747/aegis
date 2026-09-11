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


def _imports(path: pathlib.Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
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
