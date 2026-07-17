"""Stage 3 projection dependency and cycle checks."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
SRC_ROOT = PROJECT_ROOT / "src"
WGPL_ROOT = SRC_ROOT / "wgpl"
PROJECTION_ROOT = WGPL_ROOT / "projection"

STAGE_3_ALLOWLIST = {
    "wgpl.projection.__init__": set(),
    "wgpl.projection.snapshots": set(),
    "wgpl.projection.contracts": {"wgpl.projection.snapshots"},
    "wgpl.projection.engine": {
        "wgpl.exceptions",
        "wgpl.projection.contracts",
        "wgpl.projection.snapshots",
    },
    "wgpl.projection.wireguard": {
        "wgpl.projection.contracts",
        "wgpl.projection.snapshots",
        "wgpl.wireformat",
    },
    "wgpl.projection.composition": {
        "wgpl.projection.contracts",
        "wgpl.projection.engine",
        "wgpl.projection.snapshots",
        "wgpl.projection.wireguard",
    },
}


def _module_name(path: Path) -> str:
    return ".".join(path.relative_to(SRC_ROOT).with_suffix("").parts)


def _parse(path: Path) -> ast.Module:
    return ast.parse(path.read_text(encoding="utf-8"), filename=str(path))


def _normalized_imports(path: Path) -> set[str]:
    module_name = _module_name(path)
    package_parts = module_name.split(".")[:-1]
    imports: set[str] = set()

    for node in ast.walk(_parse(path)):
        if isinstance(node, ast.Import):
            imports.update(alias.name for alias in node.names)
            continue
        if not isinstance(node, ast.ImportFrom):
            continue

        if node.level:
            keep_parts = len(package_parts) - (node.level - 1)
            base_parts = package_parts[:keep_parts]
            if node.module:
                imported = ".".join([*base_parts, node.module])
                imports.add(imported)
            else:
                imports.update(
                    ".".join([*base_parts, alias.name]) for alias in node.names
                )
        elif node.module:
            imports.add(node.module)

    return imports


def _projection_modules() -> dict[str, Path]:
    return {
        _module_name(path): path
        for path in sorted(PROJECTION_ROOT.glob("*.py"))
    }


def test_stage_3_projection_imports_match_allowlist() -> None:
    modules = _projection_modules()

    assert set(modules) == set(STAGE_3_ALLOWLIST)
    for module_name, path in modules.items():
        wgpl_imports = {
            imported
            for imported in _normalized_imports(path)
            if imported == "wgpl" or imported.startswith("wgpl.")
        }
        assert wgpl_imports <= STAGE_3_ALLOWLIST[module_name]


def test_snapshots_have_no_wgpl_imports() -> None:
    imports = _normalized_imports(PROJECTION_ROOT / "snapshots.py")

    assert not {
        imported
        for imported in imports
        if imported == "wgpl" or imported.startswith("wgpl.")
    }


def test_only_core_may_import_snapshots_or_composition() -> None:
    offenders: dict[str, set[str]] = {}
    for path in WGPL_ROOT.rglob("*.py"):
        if PROJECTION_ROOT in path.parents:
            continue
        imports = {
            imported
            for imported in _normalized_imports(path)
            if imported.startswith("wgpl.projection")
        }
        module_name = _module_name(path)
        allowed = (
            {
                "wgpl.projection.composition",
                "wgpl.projection.snapshots",
            }
            if module_name == "wgpl.core"
            else set()
        )
        forbidden = imports - allowed
        if forbidden:
            offenders[module_name] = forbidden

    assert offenders == {}


def test_package_initializers_export_no_projection_symbols() -> None:
    assert _parse(WGPL_ROOT / "__init__.py").body == []
    assert _parse(PROJECTION_ROOT / "__init__.py").body == []


def test_renderer_and_engine_do_not_know_each_other() -> None:
    wireguard_imports = _normalized_imports(PROJECTION_ROOT / "wireguard.py")
    engine_imports = _normalized_imports(PROJECTION_ROOT / "engine.py")

    assert "wgpl.projection.engine" not in wireguard_imports
    assert "wgpl.projection.composition" not in wireguard_imports
    assert "wgpl.projection.wireguard" not in engine_imports
    assert "wgpl.projection.composition" not in engine_imports


def test_stage_3_internal_import_graph_is_acyclic() -> None:
    modules = _projection_modules()
    graph = {
        module_name: {
            imported
            for imported in _normalized_imports(path)
            if imported in modules
        }
        for module_name, path in modules.items()
    }
    visiting: set[str] = set()
    visited: set[str] = set()

    def visit(module_name: str) -> None:
        if module_name in visiting:
            raise AssertionError(f"Projection import cycle found at {module_name}")
        if module_name in visited:
            return
        visiting.add(module_name)
        for dependency in graph[module_name]:
            visit(dependency)
        visiting.remove(module_name)
        visited.add(module_name)

    for module_name in graph:
        visit(module_name)


def test_stage_3_modules_smoke_import() -> None:
    for module_name in (
        "wgpl.core",
        "wgpl.projection.snapshots",
        "wgpl.projection.contracts",
        "wgpl.projection.engine",
        "wgpl.projection.wireguard",
        "wgpl.projection.composition",
    ):
        importlib.import_module(module_name)
