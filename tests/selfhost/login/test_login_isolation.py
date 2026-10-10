"""The provider configuration is stdlib-only; the relying-party modules load only when needed."""

from __future__ import annotations

import base64
import os
import subprocess
import sys
import textwrap
from pathlib import Path

SRC = Path(__file__).resolve().parents[3] / "src"

BLOCK = textwrap.dedent(
    """
    import importlib.abc, sys

    class Blocker(importlib.abc.MetaPathFinder):
        BLOCKED = ("sqlalchemy", "alembic", "psycopg", "mako", "joserfc")

        def find_spec(self, name, path=None, target=None):
            if name.split(".")[0] in self.BLOCKED:
                raise ImportError(f"{name} is blocked for this test")
            return None

    sys.meta_path.insert(0, Blocker())
    """
)


def _run(code: str) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, "PYTHONPATH": str(SRC), "PYTHON_DOTENV_DISABLED": "1", "PYTHONUTF8": "1"}
    return subprocess.run(
        [sys.executable, "-c", BLOCK + textwrap.dedent(code)],
        capture_output=True, text=True, env=env, timeout=120,
    )


def test_the_provider_config_and_settings_import_without_joserfc_or_the_data_layer() -> None:
    result = _run(
        """
        import canvas_mcp.core.selfhost.login.config
        import canvas_mcp.core.selfhost.accounts
        import canvas_mcp.core.selfhost.settings
        bad = [m for m in sys.modules if m.split(".")[0] in ("joserfc", "sqlalchemy")]
        assert not bad, bad
        assert "canvas_mcp.core.selfhost.login.jwks" not in sys.modules
        assert "canvas_mcp.core.selfhost.login.idtoken" not in sys.modules
        print("ok")
        """
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("ok")


def test_an_entra_only_start_never_imports_the_relying_party_modules() -> None:
    session = base64.b64encode(bytes(range(32))).decode()
    result = _run(
        f"""
        from canvas_mcp.core.selfhost.settings import load_selfhost_settings
        settings = load_selfhost_settings({{
            "PUBLIC_BASE_URL": "https://canvas.example.test",
            "ENTRA_TENANT_ID": "11111111-2222-3333-4444-555555555555",
            "ENTRA_CLIENT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
            "ENTRA_CLIENT_SECRET": "entra-secret-value-0123456789",
            "OAUTH_JWT_SIGNING_KEY": "k" * 48,
            "ACCOUNT_SESSION_SECRET": "{session}",
            "CANVAS_TOKEN_KEYS": "k1:" + "A" * 43 + "=",
            "FASTMCP_HOME": "/data/fastmcp",
        }})
        assert settings.login_providers.single
        loaded = [m for m in sys.modules if m.startswith("canvas_mcp.core.selfhost.login")]
        assert loaded == ["canvas_mcp.core.selfhost.login", "canvas_mcp.core.selfhost.login.config"], loaded
        print("ok")
        """
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("ok")


def test_the_account_pages_load_no_relying_party_module_by_themselves() -> None:
    env = {**os.environ, "PYTHONPATH": str(SRC), "PYTHON_DOTENV_DISABLED": "1", "PYTHONUTF8": "1"}
    code = textwrap.dedent(
        """
        import sys
        import canvas_mcp.core.selfhost.account_web
        import canvas_mcp.core.selfhost.login.ceremony
        loaded = sorted(m for m in sys.modules if m.startswith("canvas_mcp.core.selfhost.login"))
        heavy = {"flows", "registry", "jwks", "idtoken", "oidc", "github", "google", "http", "metadata", "linking"}
        assert not heavy & {m.rsplit(".", 1)[-1] for m in loaded}, loaded
        print("ok")
        """
    )
    result = subprocess.run(
        [sys.executable, "-c", code], capture_output=True, text=True, env=env, timeout=120
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip().endswith("ok")
