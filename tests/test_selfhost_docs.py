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


def _commented_assignments(text: str) -> dict[str, str]:
    """``# NAME=value`` lines: settings that ship switched off."""
    values = {}
    for line in text.splitlines():
        match = re.match(r"#\s*([A-Z][A-Z0-9_]*)=(.*)$", line)
        if match:
            values[match.group(1)] = match.group(2)
    return values


def test_recommended_student_values(env_text):
    values = _assignments(env_text)
    assert values["MCP_AUTH_MODE"] == "entra-oauth"
    assert values["CANVAS_ROLE"] == "student"
    assert values["TIMEZONE"] == "America/Los_Angeles"
    assert values["MCP_MAX_RESULT_CHARS"] == "140000"


def test_the_template_is_read_only_until_the_operator_opts_in(env_text):
    """On a public multi-user server a secure setup must be opt-in, not opt-out:
    classmates and instructors can write Canvas content that carries prompt
    injection, and the confirmation tokens can be redeemed by the model itself."""
    values = _assignments(env_text)
    assert values.get("ALLOWED_WRITE_TOOLS", "") in ("", "none")
    assert values.get("COURSE_AGENT_POLICY_DEFAULT", "deny") != "allow"
    enabled = set(values.get("STUDENT_WRITE_TOOLS", "").split(","))
    for risky in ("send_message", "reply_to_conversation", "submit_assignment"):
        assert risky not in enabled, f"{risky} must not be enabled by default"
    assert not enabled - {""}, "no student write tool should be registered by default"


def test_the_opt_in_values_are_shown_commented_out_next_to_the_warning(env_text):
    commented = _commented_assignments(env_text)
    assert commented["ALLOWED_WRITE_TOOLS"] == "all"
    assert commented["COURSE_AGENT_POLICY_DEFAULT"] == "allow"
    assert tuple(commented["STUDENT_WRITE_TOOLS"].split(",")) == STUDENT_WRITE_TOOLS
    block = env_text[env_text.index("提示词注入") : env_text.index("# ALLOWED_WRITE_TOOLS=all")]
    assert "主动开启" in block


def test_the_template_ships_no_host_specific_live_values(env_text):
    """Copying the template and forgetting a value must fail closed, not point the
    server at somebody else's domain or Canvas."""
    values = _assignments(env_text)
    assert values["PUBLIC_BASE_URL"] == ""
    assert values["CANVAS_API_URL"] == ""
    assert "kazuhahub" not in env_text
    assert "uci.edu" not in env_text


def test_an_unedited_template_is_refused_at_startup(env_text):
    from canvas_mcp.core.selfhost.settings import (
        SelfhostConfigError,
        load_selfhost_settings,
    )

    env = dict(_assignments(env_text).items())
    with pytest.raises(SelfhostConfigError) as info:
        load_selfhost_settings(env)
    text = " ".join(info.value.problems)
    for name in ("PUBLIC_BASE_URL", "ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "OAUTH_JWT_SIGNING_KEY"):
        assert name in text


def test_the_audit_log_is_documented_as_opt_in(env_text, readme):
    block = env_text[env_text.index("审计日志默认是关闭的") :]
    assert "LOG_ACCESS_EVENTS=true" in block
    assert "/account" in block and "不写审计日志" in block
    assert "审计日志**默认是关闭的**" in readme
    assert "不写审计日志" in readme


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

    values = _commented_assignments(env_text)
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
    healthcheck = next(line for line in dockerfile.splitlines() if line.lstrip().startswith("CMD [\"python\""))
    assert HEALTH_PATH in healthcheck and "127.0.0.1" in healthcheck and "8819" in healthcheck
    assert "127.0.0.1:8819:8819" in compose
    assert SelfhostSettings.mcp_path == "/mcp"
    readme = (SELFHOST / "README.md").read_text(encoding="utf-8")
    for route in ("/mcp", "/account", "/account/admin", "/auth/callback", "/account/callback", HEALTH_PATH):
        assert route in readme, f"README.md does not mention {route}"


def test_token_admin_commands_in_the_docs_exist():
    readme = (SELFHOST / "README.md").read_text(encoding="utf-8")
    source = (SRC / "core" / "selfhost" / "token_admin.py").read_text(encoding="utf-8")
    for command in set(re.findall(r"token_admin (check|list|revoke|rotate)\b", readme)):
        assert f'add_parser("{command}"' in source


# --- findings from the integration review ---


def test_proxy_examples_rate_limit_the_unauthenticated_oauth_endpoints(readme):
    nginx = (SELFHOST / "nginx.conf.example").read_text(encoding="utf-8")
    assert "limit_req_zone $binary_remote_addr zone=canvas_oauth:10m rate=10r/m;" in nginx
    for path in ("/register", "/authorize"):
        block = nginx[nginx.index(f"location = {path} {{") :]
        block = block[: block.index("}")]
        assert "limit_req zone=canvas_oauth burst=5 nodelay;" in block
        assert "proxy_set_header Host $host;" in block
    assert "limit_req_zone" in readme and "location = /register" in readme
    caddy = (SELFHOST / "Caddyfile.example").read_text(encoding="utf-8")
    assert "caddy-ratelimit" in caddy
    assert "磁盘与滥用防护" in readme and "Cloudflare" in readme


def test_http2_directive_comes_with_the_nginx_version_note(readme):
    nginx = (SELFHOST / "nginx.conf.example").read_text(encoding="utf-8")
    assert "1.25.1" in nginx and "listen 443 ssl http2;" in nginx
    assert "1.25.1" in readme and "listen 443 ssl http2;" in readme


def test_backup_commands_use_the_volume_name_compose_really_creates(readme):
    yaml = pytest.importorskip("yaml")
    compose = yaml.safe_load((SELFHOST / "docker-compose.yml").read_text(encoding="utf-8"))
    volume_name = compose["volumes"]["canvas-mcp-data"]["name"]
    used = set(re.findall(r"-v ([A-Za-z0-9_.-]+):/data", readme))
    assert used == {volume_name}, "backup/restore must name the volume compose creates"
    assert "docker volume inspect canvas-mcp-data" in readme


def test_readme_never_tells_the_operator_to_just_restart_after_editing_env(readme):
    """`docker compose restart` does not re-read env_file."""
    assert "docker compose restart" in readme  # ...only to warn against it
    for line in readme.splitlines():
        if "docker compose restart" in line:
            assert "不会重新读取" in line or "不要用" in line, line
    secrets_table = readme[readme.index("### 其他密钥") : readme.index("## 备份与恢复")]
    for name in ("ENTRA_CLIENT_SECRET", "ACCOUNT_SESSION_SECRET", "OAUTH_JWT_SIGNING_KEY"):
        row = next(line for line in secrets_table.splitlines() if f"`{name}`" in line)
        assert "docker compose up -d" in row, row
    rotation = readme[readme.index("### Canvas token 密钥环") : readme.index("### 其他密钥")]
    assert rotation.count("docker compose up -d") >= 2


def test_readme_explains_the_first_stable_tag_the_default_image_needs(readme):
    yaml = pytest.importorskip("yaml")
    compose_text = (SELFHOST / "docker-compose.yml").read_text(encoding="utf-8")
    compose = yaml.safe_load(compose_text)
    assert compose["services"]["canvas-mcp"]["image"].endswith(":latest")
    assert "manifest unknown" in readme and "manifest unknown" in compose_text
    assert "git tag v1.13.0-uci.1" in readme
    assert ":edge" in readme


def test_setup_script_is_documented_generic_and_secret_safe(readme):
    script = (SELFHOST / "setup-env.sh").read_text(encoding="utf-8")
    assert "\r" not in script, "setup-env.sh must use LF line endings"
    assert script.startswith("#!/usr/bin/env bash\n")
    assert "set -euo pipefail" in script
    # Generic: the operator's host and Canvas come from prompts or the environment.
    assert "kazuhahub" not in script
    assert "uci.edu" not in script
    # The client secret is only read from the terminal, never from argv or env.
    assert 'read -r -s -p' in script
    assert "ENTRA_CLIENT_SECRET=\"\"" in script
    assert "set -o noclobber" in script and "umask 077" in script
    # The README points operators at it, with both opt-in flags.
    assert "setup-env.sh" in readme
    for flag in ("--enable-writes", "--real-names"):
        assert flag in readme and flag in script
    smoke = (SELFHOST / "smoke-test.sh").read_text(encoding="utf-8")
    assert "setup-env.sh" in smoke and "--env-file" in smoke


# --- multiple schools ---


def test_the_school_settings_ship_switched_off_and_documented(env_text):
    commented = _commented_assignments(env_text)
    assert "CANVAS_FEATURED_SCHOOLS" in commented
    assert commented["CANVAS_SCHOOL_SEARCH"] == "true"
    values = _assignments(env_text)
    assert "CANVAS_FEATURED_SCHOOLS" not in values
    assert "CANVAS_SCHOOL_SEARCH" not in values
    block = env_text[env_text.index("# CANVAS_FEATURED_SCHOOLS=") :]
    assert "canvas.instructure.com" in block and "Instructure" in block


def test_the_documented_featured_example_parses(env_text):
    from canvas_mcp.core.selfhost.settings import SelfhostConfigError, load_selfhost_settings

    example = _commented_assignments(env_text)["CANVAS_FEATURED_SCHOOLS"]
    env = {"CANVAS_FEATURED_SCHOOLS": example}
    with pytest.raises(SelfhostConfigError) as info:
        load_selfhost_settings(env)
    # Only the unrelated required settings are missing; the example itself is valid.
    assert "CANVAS_FEATURED_SCHOOLS" not in " ".join(info.value.problems)


def test_readme_documents_the_school_settings_and_the_privacy_note(readme):
    for needle in (
        "CANVAS_FEATURED_SCHOOLS",
        "CANVAS_SCHOOL_SEARCH",
        "canvas.instructure.com",
        "--school-search",
        "schema version 2",
    ):
        assert needle in readme, f"README.md is missing {needle!r}"
    assert "sent to Instructure" in readme


def test_the_setup_script_has_the_school_search_flag_and_the_readme_names_it(readme):
    script = (SELFHOST / "setup-env.sh").read_text(encoding="utf-8")
    assert "--school-search" in script and "--school-search" in readme
    assert "CANVAS_SCHOOL_SEARCH=true" in script and "CANVAS_FEATURED_SCHOOLS=" in script
