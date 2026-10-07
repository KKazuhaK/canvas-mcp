"""main() in entra-oauth mode fails closed, and legacy startup is not disturbed."""

import base64
import logging
from pathlib import Path
from typing import Any

import fastmcp
import pytest

from canvas_mcp import server as server_module
from canvas_mcp.core import config as config_module
from canvas_mcp.core.selfhost.app import validate_selfhost_startup
from canvas_mcp.core.selfhost.settings import load_selfhost_settings

from .conftest import CLIENT, TENANT

SECRETS = {
    "ENTRA_CLIENT_SECRET": "entra-client-secret-0123456789",
    "OAUTH_JWT_SIGNING_KEY": "jwt-signing-key-" + "z" * 40,
    "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
    "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(bytes(32)).decode(),
}
LEGACY_VARS = (
    "CANVAS_API_TOKEN", "MCP_ACCESS_KEYS", "ENTRA_AUTH_ENABLED", "MCP_ALLOW_UNAUTHENTICATED",
    "ACCESS_REQUEST_ENABLED", "EXECUTE_TYPESCRIPT_ENABLED", "ALLOWED_WRITE_TOOLS",
    "STUDENT_WRITE_TOOLS", "CANVAS_ROLE",
)


@pytest.fixture
def entra_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> dict[str, Any]:
    """A complete, valid entra-oauth environment rooted in tmp_path."""
    for name in LEGACY_VARS:
        monkeypatch.delenv(name, raising=False)
    home = tmp_path / "fastmcp"
    data = tmp_path / "data"
    values = {
        "MCP_AUTH_MODE": "entra-oauth",
        "PUBLIC_BASE_URL": "https://canvas.example.test",
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": CLIENT,
        "CANVAS_API_URL": "https://canvas.example.edu",
        "FASTMCP_HOME": str(home),
        "SELFHOST_DATA_DIR": str(data),
        **SECRETS,
    }
    for name, value in values.items():
        monkeypatch.setenv(name, value)
    # FastMCP reads FASTMCP_HOME once, when it is imported; mirror a process
    # that was started with the variable already set.
    monkeypatch.setattr(fastmcp.settings, "home", home)
    config_module.reset_config()
    return {"home": home, "data": data, "monkeypatch": monkeypatch}


def _run_main(monkeypatch: pytest.MonkeyPatch, *argv: str) -> SystemExit:
    monkeypatch.setattr("sys.argv", ["canvas-mcp-server", *argv])
    config_module.reset_config()
    try:
        with pytest.raises(SystemExit) as info:
            server_module.main()
    finally:
        config_module.reset_config()
    return info.value


HTTP = ("--transport", "streamable-http")


class TestRefusals:
    def test_stdio_is_refused(self, entra_env, caplog):
        assert _run_main(entra_env["monkeypatch"]).code == 1
        assert "streamable-http" in caplog.text

    @pytest.mark.parametrize("flag", [["--test"], ["--list-grants"], ["--revoke", "oid"]])
    def test_admin_and_test_commands_are_refused(self, entra_env, flag, caplog):
        assert _run_main(entra_env["monkeypatch"], *HTTP, *flag).code == 1
        assert "not available" in caplog.text

    def test_unknown_auth_mode(self, entra_env, caplog):
        entra_env["monkeypatch"].setenv("MCP_AUTH_MODE", "entra")
        assert _run_main(entra_env["monkeypatch"], *HTTP).code == 1
        assert "MCP_AUTH_MODE" in caplog.text

    @pytest.mark.parametrize("name", [
        "PUBLIC_BASE_URL", "ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "ENTRA_CLIENT_SECRET",
        "OAUTH_JWT_SIGNING_KEY", "ACCOUNT_SESSION_SECRET", "CANVAS_TOKEN_KEYS", "FASTMCP_HOME",
    ])
    def test_a_missing_required_variable(self, entra_env, name, caplog):
        entra_env["monkeypatch"].delenv(name)
        assert _run_main(entra_env["monkeypatch"], *HTTP).code == 1
        assert name in caplog.text

    def test_all_problems_are_logged_and_no_secret_appears(self, entra_env, caplog):
        mp = entra_env["monkeypatch"]
        mp.setenv("ENTRA_CLIENT_SECRET", "short")
        mp.setenv("PUBLIC_BASE_URL", "http://canvas.example.test")
        mp.delenv("CANVAS_TOKEN_KEYS")
        assert _run_main(mp, *HTTP).code == 1
        for name in ("ENTRA_CLIENT_SECRET", "PUBLIC_BASE_URL", "CANVAS_TOKEN_KEYS"):
            assert name in caplog.text
        assert "short" not in caplog.text.replace("shortly", "")
        assert SECRETS["OAUTH_JWT_SIGNING_KEY"] not in caplog.text

    @pytest.mark.parametrize(("name", "value"), [
        ("CANVAS_API_TOKEN", "a-server-side-canvas-token-1234567890"),
        ("MCP_ACCESS_KEYS", "shared-access-key-1234567890"),
        ("ENTRA_AUTH_ENABLED", "true"),
        ("MCP_ALLOW_UNAUTHENTICATED", "true"),
        ("ACCESS_REQUEST_ENABLED", "true"),
        ("EXECUTE_TYPESCRIPT_ENABLED", "true"),
        ("ALLOWED_WRITE_TOOLS", "execute_typescript"),
        ("CANVAS_API_URL", "http://canvas.example.edu"),
    ])
    def test_forbidden_legacy_settings(self, entra_env, name, value, caplog):
        mp = entra_env["monkeypatch"]
        mp.setenv(name, value)
        assert _run_main(mp, *HTTP).code == 1
        assert name in caplog.text
        if value.endswith("1234567890"):  # the secret-looking ones
            assert value not in caplog.text

    def test_a_missing_canvas_url(self, entra_env):
        mp = entra_env["monkeypatch"]
        mp.delenv("CANVAS_API_URL")
        assert _run_main(mp, *HTTP).code == 1

    def test_fastmcp_home_must_be_the_one_fastmcp_started_with(self, entra_env, tmp_path, caplog):
        mp = entra_env["monkeypatch"]
        mp.setattr(fastmcp.settings, "home", tmp_path / "somewhere-else")
        assert _run_main(mp, *HTTP).code == 1
        assert "FASTMCP_HOME" in caplog.text

    def test_a_relative_fastmcp_home(self, entra_env):
        mp = entra_env["monkeypatch"]
        mp.setenv("FASTMCP_HOME", "relative/dir")
        assert _run_main(mp, *HTTP).code == 1

    def test_an_unwritable_data_dir(self, entra_env, tmp_path, caplog):
        blocker = tmp_path / "a-file"
        blocker.write_text("x", encoding="utf-8")
        entra_env["monkeypatch"].setenv("SELFHOST_DATA_DIR", str(blocker / "sub"))
        assert _run_main(entra_env["monkeypatch"], *HTTP).code == 1
        assert "SELFHOST_DATA_DIR" in caplog.text

    def test_the_keyring_must_cover_every_key_id_in_use(self, entra_env, caplog):
        token_store = pytest.importorskip("canvas_mcp.core.selfhost.token_store")
        settings = load_selfhost_settings()
        store = token_store.TokenStore(settings.token_db_path, token_store.Keyring.parse(SECRETS["CANVAS_TOKEN_KEYS"]))
        store.initialize()
        store.put(
            tenant_id=TENANT, object_id="aaaaaaaa-0000-4000-8000-00000000000a",
            api_token="canvas-token-1234567890abcdef", canvas_user_id="1",
            canvas_user_name="A", entra_display_name="A", entra_upn="a@example.test",
        )
        other = "k2:" + base64.b64encode(bytes(range(32))).decode()
        entra_env["monkeypatch"].setenv("CANVAS_TOKEN_KEYS", other)
        assert _run_main(entra_env["monkeypatch"], *HTTP).code == 1
        assert "CANVAS_TOKEN_KEYS" in caplog.text
        assert "k1" in caplog.text
        assert other.split(":")[1] not in caplog.text

    def test_a_corrupt_token_database_is_a_logged_refusal_not_a_traceback(self, entra_env, caplog):
        pytest.importorskip("canvas_mcp.core.selfhost.token_store")
        db = load_selfhost_settings().token_db_path
        db.parent.mkdir(parents=True, exist_ok=True)
        db.write_bytes(b"this is not a database" * 100)
        # Any escape from main() other than SystemExit(1) fails this call.
        assert _run_main(entra_env["monkeypatch"], *HTTP).code == 1
        assert "token database" in caplog.text
        assert "not a valid database" in caplog.text

    def test_prepare_selfhost_reports_a_corrupt_database_as_a_config_error(self, entra_env):
        pytest.importorskip("canvas_mcp.core.selfhost.token_store")
        from canvas_mcp.core.selfhost.app import prepare_selfhost
        from canvas_mcp.core.selfhost.settings import SelfhostConfigError

        settings = load_selfhost_settings()
        settings.token_db_path.parent.mkdir(parents=True, exist_ok=True)
        settings.token_db_path.write_bytes(b"this is not a database" * 100)
        with pytest.raises(SelfhostConfigError) as info:
            prepare_selfhost(settings)
        assert info.value.problems == [
            "the Canvas token database cannot be opened or is not a valid database"
        ]

    def test_a_malformed_keyring(self, entra_env):
        pytest.importorskip("canvas_mcp.core.selfhost.token_store")
        entra_env["monkeypatch"].setenv("CANVAS_TOKEN_KEYS", "not a keyring")
        assert _run_main(entra_env["monkeypatch"], *HTTP).code == 1


class TestConfigCommand:
    def test_config_prints_a_summary_without_secrets(self, entra_env, capsys):
        assert _run_main(entra_env["monkeypatch"], *HTTP, "--config").code == 0
        out = capsys.readouterr().err
        assert "entra-oauth" in out
        assert "https://canvas.example.test/mcp" in out
        assert TENANT in out
        for secret in SECRETS.values():
            assert secret not in out

    def test_config_reports_problems_before_printing(self, entra_env):
        entra_env["monkeypatch"].delenv("PUBLIC_BASE_URL")
        assert _run_main(entra_env["monkeypatch"], *HTTP, "--config").code == 1


class TestValidateStartup:
    def test_a_valid_environment_has_no_problems(self, entra_env):
        config = config_module.get_config()
        assert validate_selfhost_startup(config, load_selfhost_settings()) == []
        assert entra_env["home"].is_dir() and entra_env["data"].is_dir()

    def test_legacy_flags_each_produce_a_problem(self, entra_env):
        mp = entra_env["monkeypatch"]
        mp.setenv("CANVAS_API_TOKEN", "tok-1234567890abcdef-1234")
        mp.setenv("MCP_ACCESS_KEYS", "key-1234567890abcdef-1234")
        mp.setenv("ENTRA_AUTH_ENABLED", "true")
        config_module.reset_config()
        problems = validate_selfhost_startup(config_module.get_config(), load_selfhost_settings())
        text = " ".join(problems)
        for name in ("CANVAS_API_TOKEN", "MCP_ACCESS_KEYS", "ENTRA_AUTH_ENABLED"):
            assert name in text
        assert "tok-1234567890" not in text and "key-1234567890" not in text


class TestHappyPath:
    def test_serves_through_the_selfhost_runner_with_the_gate_installed(self, entra_env, caplog):
        pytest.importorskip("canvas_mcp.core.selfhost.token_store")
        pytest.importorskip("canvas_mcp.core.selfhost.account_web")
        mp = entra_env["monkeypatch"]
        caplog.set_level(logging.INFO)
        captured: dict[str, Any] = {}

        def fake_runner(app, host, port):
            captured.update(app=app, host=host, port=port)

        def fail_legacy(*args, **kwargs):  # pragma: no cover - must not run
            raise AssertionError("the legacy HTTP runner must not be used")

        mp.setattr(server_module, "_run_selfhost_http_server", fake_runner)
        mp.setattr(server_module, "_run_http_server", fail_legacy)
        mp.setenv("CANVAS_ROLE", "student")
        mp.setattr("sys.argv", ["canvas-mcp-server", *HTTP, "--port", "9911"])
        config_module.reset_config()
        try:
            server_module.main()
        finally:
            config_module.reset_config()
        assert captured["port"] == 9911
        assert captured["app"] is not None
        assert "entra-oauth" in caplog.text
        assert TENANT in caplog.text and CLIENT in caplog.text
        for secret in SECRETS.values():
            assert secret not in caplog.text


class TestRunner:
    def test_uvicorn_does_not_trust_forwarded_headers(self, monkeypatch):
        import uvicorn

        captured: dict[str, Any] = {}

        class FakeConfig:
            def __init__(self, app, **kwargs):
                captured["app"] = app
                captured["kwargs"] = kwargs

        class FakeServer:
            def __init__(self, config):
                captured["config"] = config

            async def serve(self):
                captured["served"] = True

        monkeypatch.setattr(uvicorn, "Config", FakeConfig)
        monkeypatch.setattr(uvicorn, "Server", FakeServer)
        sentinel = object()
        server_module._run_selfhost_http_server(sentinel, "127.0.0.1", 8819)  # type: ignore[arg-type]
        assert captured["app"] is sentinel
        assert captured["kwargs"] == {
            "host": "127.0.0.1", "port": 8819, "log_level": "info", "access_log": False,
            "proxy_headers": False, "server_header": False,
        }
        assert captured["served"] is True


class TestLegacyUntouched:
    def test_create_server_defaults_to_no_auth(self):
        assert server_module.create_server().auth is None

    def test_legacy_http_still_requires_its_gate(self, monkeypatch):
        for name in ("MCP_AUTH_MODE", *LEGACY_VARS):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("CANVAS_API_URL", "https://canvas.example.edu")
        assert _run_main(monkeypatch, *HTTP, "--config").code == 1

    def test_explicit_legacy_mode_is_the_same_as_unset(self, monkeypatch):
        for name in LEGACY_VARS:
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv("MCP_AUTH_MODE", "legacy")
        monkeypatch.setenv("CANVAS_API_URL", "https://canvas.example.edu")
        monkeypatch.setenv("MCP_ALLOW_UNAUTHENTICATED", "true")
        assert _run_main(monkeypatch, *HTTP, "--config").code == 0
