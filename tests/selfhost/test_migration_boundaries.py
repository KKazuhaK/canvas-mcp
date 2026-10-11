"""Keep removable upgrade tooling out of application repositories and pools."""

import ast
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[2] / "src/canvas_mcp/core/selfhost"


def test_upgrade_ddl_and_alembic_remain_inside_the_migration_package():
    violations = []
    ddl = re.compile(
        r"^\s*(?:CREATE|ALTER|DROP)\s+(?:TABLE|INDEX|SEQUENCE)\b", re.I | re.M
    )
    for path in ROOT.rglob("*.py"):
        relative = path.relative_to(ROOT)
        if relative.parts[:2] == ("db", "migrations"):
            continue
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr in {"create_all", "drop_all"}
            ):
                violations.append(str(relative) + ": metadata DDL")
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


def test_only_documented_startup_and_cli_bridges_import_upgrade_tooling():
    allowed = {
        "app.py": {"db.migrations", "db.migrations.transfer"},
        "token_store.py": {"db.migrations"},
        "token_admin.py": {
            "db.migrations.cli",
            "canvas_mcp.core.selfhost.db.migrations.transfer",
        },
    }
    violations = []
    for path in ROOT.rglob("*.py"):
        relative = path.relative_to(ROOT)
        if relative.parts[:2] == ("db", "migrations"):
            continue
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            modules = (
                [node.module or ""]
                if isinstance(node, ast.ImportFrom)
                else [alias.name for alias in node.names]
                if isinstance(node, ast.Import)
                else []
            )
            for module in modules:
                if "migrations" in module.split("."):
                    if module not in allowed.get(relative.as_posix(), set()):
                        violations.append(str(relative) + ": " + module)
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


def test_frozen_revisions_do_not_import_runtime_schema_or_reencrypt_secrets():
    violations = []
    for path in (ROOT / "db/migrations/versions").glob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.ImportFrom):
                imported = set((node.module or "").split(".")) | {
                    item.name for item in node.names
                }
                if imported & {"schema", "repos", "token_store", "sealed"}:
                    violations.append(path.name + ": runtime persistence import")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
                if node.func.attr in {"encrypt", "decrypt", "rotate"}:
                    violations.append(path.name + ": secret re-encryption")
    assert violations == []
