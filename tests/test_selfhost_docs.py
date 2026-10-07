"""The deployment docs stay complete: every required setting is documented."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

SELFHOST = Path(__file__).resolve().parents[1] / "deploy" / "selfhost"

# Settings the server refuses to start without in entra-oauth mode. Mirrors the
# env_contract entries marked required.
REQUIRED_VARS = (
    "MCP_AUTH_MODE",
    "PUBLIC_BASE_URL",
    "ENTRA_TENANT_ID",
    "ENTRA_CLIENT_ID",
    "ENTRA_CLIENT_SECRET",
    "OAUTH_JWT_SIGNING_KEY",
    "ACCOUNT_SESSION_SECRET",
    "CANVAS_TOKEN_KEYS",
    "FASTMCP_HOME",
    "CANVAS_API_URL",
)

# Settings that must stay unset in this mode: they may appear in comments only.
MUST_BE_UNSET = (
    "CANVAS_API_TOKEN",
    "MCP_ACCESS_KEYS",
    "ENTRA_AUTH_ENABLED",
    "MCP_ALLOW_UNAUTHENTICATED",
    "ACCESS_REQUEST_ENABLED",
)

STUDENT_WRITE_TOOLS = (
    "submit_assignment",
    "comment_on_my_submission",
    "mark_module_item_done",
    "create_planner_note",
    "update_planner_note",
    "delete_planner_note",
    "mark_planner_item_complete",
    "create_personal_calendar_event",
    "delete_personal_calendar_event",
    "send_message",
    "reply_to_conversation",
)


@pytest.fixture(scope="module")
def env_text() -> str:
    return (SELFHOST / "env.example").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def readme() -> str:
    return (SELFHOST / "README.md").read_text(encoding="utf-8")


def _assignments(text: str) -> dict[str, str]:
    values = {}
    for line in text.splitlines():
        match = re.match(r"([A-Z][A-Z0-9_]*)=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


@pytest.mark.parametrize("name", REQUIRED_VARS)
def test_env_example_sets_every_required_variable(env_text, name):
    assert re.search(rf"^{name}=", env_text, re.MULTILINE), f"{name} is not set in env.example"


@pytest.mark.parametrize("name", REQUIRED_VARS)
def test_required_variables_are_marked_in_chinese(env_text, name):
    lines = env_text.splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(f"{name}="))
    block = "\n".join(lines[max(0, index - 8) : index])
    assert "必填" in block, f"{name} is not marked 必填"


def test_must_be_unset_variables_appear_only_in_comments(env_text):
    assignments = _assignments(env_text)
    for name in MUST_BE_UNSET:
        assert name not in assignments, f"{name} must stay unset"
        assert name in env_text, f"{name} should be documented in a comment"
    assert assignments.get("EXECUTE_TYPESCRIPT_ENABLED", "false") != "true"


def test_recommended_student_values(env_text):
    values = _assignments(env_text)
    assert values["MCP_AUTH_MODE"] == "entra-oauth"
    assert values["CANVAS_API_URL"] == "https://canvas.eee.uci.edu"
    assert values["CANVAS_ROLE"] == "student"
    assert values["TIMEZONE"] == "America/Los_Angeles"
    assert values["ALLOWED_WRITE_TOOLS"] == "all"
    assert values["COURSE_AGENT_POLICY_DEFAULT"] == "allow"
    assert values["MCP_MAX_RESULT_CHARS"] == "140000"
    assert tuple(values["STUDENT_WRITE_TOOLS"].split(",")) == STUDENT_WRITE_TOOLS


def test_env_example_ships_no_secret_values(env_text):
    values = _assignments(env_text)
    for name in (
        "ENTRA_CLIENT_SECRET",
        "OAUTH_JWT_SIGNING_KEY",
        "ACCOUNT_SESSION_SECRET",
        "CANVAS_TOKEN_KEYS",
        "ENTRA_TENANT_ID",
        "ENTRA_CLIENT_ID",
    ):
        assert values[name] == "", f"{name} must be blank in the template"


def test_readme_covers_the_entra_and_edge_setup(readme):
    for needle in (
        "https://canvas.mcp.kazuhahub.com/auth/callback",
        "https://canvas.mcp.kazuhahub.com/account/callback",
        "160.79.104.0/21",
        "requestedAccessTokenVersion",
        "accessTokenAcceptedVersion",
        "Assignment required",
        "Ask before using",
        "api://",
        "Canvas.Access",
        "Canvas.User",
        "Canvas.Owner",
        "https://canvas.mcp.kazuhahub.com/mcp",
        "claude mcp add --transport http canvas",
        "token_admin rotate",
        "Revoke sessions",
        "/account/admin",
    ):
        assert needle in readme, f"README.md is missing {needle!r}"


def test_proxy_examples_forward_the_host_header_and_do_not_buffer():
    nginx = (SELFHOST / "nginx.conf.example").read_text(encoding="utf-8")
    for directive in (
        "proxy_pass http://127.0.0.1:8819;",
        "proxy_set_header Host $host;",
        "proxy_buffering off;",
        "proxy_cache off;",
        "proxy_read_timeout 300s;",
        "client_max_body_size 10m;",
        "Strict-Transport-Security",
    ):
        assert directive in nginx
    caddy = (SELFHOST / "Caddyfile.example").read_text(encoding="utf-8")
    assert "reverse_proxy 127.0.0.1:8819" in caddy
    assert "flush_interval -1" in caddy


def test_smoke_test_script_is_wired_for_the_documented_contract():
    script = (SELFHOST / "smoke-test.sh").read_text(encoding="utf-8")
    for needle in (
        "set -euo pipefail",
        "trap cleanup EXIT",
        "MCP_AUTH_MODE=entra-oauth",
        "resource_metadata=",
        "oauth-protected-resource/mcp",
        "client_id_metadata_document_supported",
        "frame-ancestors 'none'",
        "Host: evil.example",
        "421",
        "MCP_ACCESS_KEYS",
    ):
        assert needle in script, f"smoke-test.sh is missing {needle!r}"


# --- drift guards: the docs and packaging must match what the code really reads/serves ---

SRC = Path(__file__).resolve().parents[1] / "src" / "canvas_mcp"
REPO = Path(__file__).resolve().parents[1]


def test_every_variable_the_selfhost_settings_read_is_documented(env_text):
    source = (SRC / "core" / "selfhost" / "settings.py").read_text(encoding="utf-8")
    read = set(re.findall(r'get\("([A-Z][A-Z0-9_]+)"\)', source))
    read |= {"ACCOUNT_SESSION_TTL_SECONDS", "OAUTH_ALLOWED_REDIRECT_URIS", "MCP_AUTH_MODE"}
    assert len(read) >= 12  # the regex still finds the settings
    for name in sorted(read):
        assert re.search(rf"^#? ?{name}=", env_text, re.MULTILINE), f"{name} is not in env.example"


def test_student_write_tools_match_the_registered_allowlist(env_text):
    from canvas_mcp.core.config import STUDENT_WRITE_TOOL_NAMES

    values = _assignments(env_text)
    assert set(values["STUDENT_WRITE_TOOLS"].split(",")) == set(STUDENT_WRITE_TOOL_NAMES)


def test_documented_redirect_uris_are_the_code_defaults(env_text):
    from canvas_mcp.core.selfhost.settings import DEFAULT_REDIRECT_URIS

    for uri in DEFAULT_REDIRECT_URIS:
        assert uri in env_text


def test_container_port_health_path_and_mcp_path_match_the_code():
    from canvas_mcp.core.selfhost.app import HEALTH_PATH
    from canvas_mcp.core.selfhost.settings import SelfhostSettings

    dockerfile = (REPO / "Dockerfile.selfhost").read_text(encoding="utf-8")
    compose = (SELFHOST / "docker-compose.yml").read_text(encoding="utf-8")
    assert "EXPOSE 8819" in dockerfile and '"--port", "8819"' in dockerfile
    assert f"127.0.0.1:8819{HEALTH_PATH}" in dockerfile
    assert "127.0.0.1:8819:8819" in compose
    assert SelfhostSettings.mcp_path == "/mcp"
    readme = (SELFHOST / "README.md").read_text(encoding="utf-8")
    for route in ("/mcp", "/account", "/account/admin", "/auth/callback", "/account/callback", HEALTH_PATH):
        assert route in readme, f"README.md does not mention {route}"


def test_token_admin_commands_in_the_docs_exist():
    readme = (SELFHOST / "README.md").read_text(encoding="utf-8")
    source = (SRC / "core" / "selfhost" / "token_admin.py").read_text(encoding="utf-8")
    for command in set(re.findall(r"token_admin (check|list|revoke|rotate)", readme)):
        assert f'add_parser("{command}"' in source
