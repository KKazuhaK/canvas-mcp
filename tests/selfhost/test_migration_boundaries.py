"""Keep removable upgrade tooling out of application repositories and pools."""

import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2] / "src/canvas_mcp/core/selfhost"


def test_upgrade_ddl_and_alembic_remain_inside_the_migration_package():
    violations = []
    ddl = re.compile(r"^\s*(?:CREATE|ALTER|DROP)\s+(?:TABLE|INDEX|SEQUENCE)\b", re.I)
    for path in ROOT.rglob("*.py"):
        relative = path.relative_to(ROOT)
        if relative.parts[:2] == ("db", "migrations"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.ImportFrom)
                and (node.module or "").split(".")[0] == "alembic"
            ):
                violations.append(str(relative) + ": Alembic import")
            if isinstance(node, ast.Import) and any(
                alias.name.split(".")[0] == "alembic" for alias in node.names
            ):
                violations.append(str(relative) + ": Alembic import")
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"execute", "exec_driver_sql"}
            ):
                for argument in node.args:
                    for value in ast.walk(argument):
                        if (
                            isinstance(value, ast.Constant)
                            and isinstance(value.value, str)
                            and ddl.search(value.value)
                        ):
                            violations.append(str(relative) + ": upgrade DDL")
    assert violations == []


def test_old_upgrade_paths_and_pre_v1_runtime_adapters_are_removed():
    for name in (
        "migrate.py",
        "transfer.py",
        "baseline_v1.py",
        "baseline_v4.py",
        "accounts_v5.py",
    ):
        assert not (ROOT / "db" / name).exists()
    source = (ROOT / "token_store.py").read_text(encoding="utf-8")
    assert not any(
        name in source
        for name in (
            "def resolve_legacy_key(",
            "def legacy_key(",
            "def entra_principal_key(",
            "def split_entra_key(",
        )
    )
