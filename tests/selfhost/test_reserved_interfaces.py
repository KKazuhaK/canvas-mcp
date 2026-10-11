"""Reserved features remain absent from real native login and enrollment paths."""

import ast
from pathlib import Path

from sqlalchemy import func, select

from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.login.registry import EnvProviderConfigSource

from .account_fixture import (
    OID,
    _display_in_utc,  # noqa: F401 - close real fixture resources
    build_harness,
    put_row,
    sign_in,
)
from .authz.stack import User


def test_native_login_enrollment_and_grants_leave_reserved_tables_empty(tmp_path):
    h = build_harness(tmp_path)
    assert sign_in(h).status_code == 303
    put_row(h.store, OID, token="native-pat-value-1234567890", name="Student")
    assert h.stack.tokens_for(User("Student", OID))[1]["access_token"]
    assert isinstance(h.core.logins.providers, EnvProviderConfigSource)
    assert h.core.logins.providers.resolve("canvas") is None
    for path in (
        "/auth/connect/canvas/canvas.example.edu",
        "/auth/callback/canvas/canvas.example.edu",
    ):
        assert h.client.get(path, follow_redirects=False).status_code == 404
    with h.store.database.read() as conn:
        for table in (s.canvas_oauth_apps, s.web_sessions, s.account_quotas):
            assert (
                conn.execute(select(func.count()).select_from(table)).scalar_one() == 0
            )


def test_application_repositories_do_not_insert_or_update_reserved_tables():
    root = Path(__file__).resolve().parents[2] / "src/canvas_mcp/core/selfhost"
    reserved = {"canvas_oauth_apps", "web_sessions", "account_quotas"}
    violations = []
    for path in root.rglob("*.py"):
        relative = path.relative_to(root)
        if (
            relative.parts[:2] == ("db", "migrations")
            or relative.as_posix() == "db/sealed.py"
        ):
            continue  # Transfer and seal rotation cover future seeded values by registry.
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            target = None
            if isinstance(node.func, ast.Name) and node.func.id in {"insert", "update"}:
                target = node.args[0] if node.args else None
            elif isinstance(node.func, ast.Attribute) and node.func.attr in {
                "insert",
                "update",
            }:
                target = node.func.value
            if isinstance(target, ast.Attribute) and target.attr in reserved:
                violations.append(f"{relative.as_posix()}: {target.attr}")
    assert violations == []
