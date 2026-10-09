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
    "FASTMCP_SSRF_TRUST_PROXY",
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
def test_required_variables_are_marked_required(env_text, name):
    lines = env_text.splitlines()
    index = next(i for i, line in enumerate(lines) if line.startswith(f"{name}="))
    block = "\n".join(lines[max(0, index - 8) : index])
    assert "Required." in block, f"{name} is not marked Required."


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
    block = env_text[env_text.index("prompt injection") : env_text.index("# ALLOWED_WRITE_TOOLS=all")]
    assert "opt-in" in block


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
    block = env_text[env_text.index("The audit log is off by default") :]
    assert "LOG_ACCESS_EVENTS=true" in block
    assert "/account" in block and "does not write an audit log entry" in block
    assert "The audit log is **off by default**" in readme
    assert "does not write an audit log entry" in readme


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
        # The React account UI boot: the strict CSP, caching, deep link and API checks.
        "ACCOUNT_UI=react",
        "script-src 'self'",
        "/account/assets/",
        "immutable",
        "/account/token",
        "/account/api/providers",
        "not_authenticated",
        # ...and the fallback to the legacy pages when the build is not usable.
        "ACCOUNT_WEB_DIST=/nonexistent",
        "serving the legacy /account pages",
    ):
        assert needle in script, f"smoke-test.sh is missing {needle!r}"


# --- drift guards: the docs and packaging must match what the code really reads/serves ---

SRC = Path(__file__).resolve().parents[1] / "src" / "canvas_mcp"
REPO = Path(__file__).resolve().parents[1]


def test_every_variable_the_selfhost_settings_read_is_documented(env_text):
    source = (SRC / "core" / "selfhost" / "settings.py").read_text(encoding="utf-8")
    read = set(re.findall(r'get\("([A-Z][A-Z0-9_]+)"\)', source))
    read |= {
        "ACCOUNT_SESSION_TTL_SECONDS", "OAUTH_ALLOWED_REDIRECT_URIS", "MCP_AUTH_MODE", "SELFHOST_COURSE_STATE",
        "SELFHOST_DISABLED_TOOLS", "ACCOUNT_UI", "ACCOUNT_WEB_DIST",
    }
    # The admission settings are read by the pure module (settings.py hands it the environment).
    accounts_source = (SRC / "core" / "selfhost" / "accounts.py").read_text(encoding="utf-8")
    read |= set(re.findall(r'^[A-Z_]+_ENV = "([A-Z][A-Z0-9_]+)"$', accounts_source, re.MULTILINE))
    assert {"ACCESS_POLICY", "ACCESS_RULES", "OWNER_RULES", "SELFHOST_BOOTSTRAP_OWNER"} <= read
    assert len(read) >= 12  # the regex still finds the settings
    for name in sorted(read):
        assert re.search(rf"^#? ?{name}=", env_text, re.MULTILINE), f"{name} is not in env.example"


def test_the_account_ui_settings_are_documented_with_their_default_and_fallback(env_text, readme):
    commented = _commented_assignments(env_text)
    assert commented["ACCOUNT_UI"] == "legacy"
    assert commented["ACCOUNT_WEB_DIST"] == "/app/web-dist"
    assert "ACCOUNT_UI" not in _assignments(env_text)
    section = readme[readme.index("## Account UI (React or legacy)") : readme.index("## Accounts and admission")]
    for needle in (
        "ACCOUNT_UI",
        "ACCOUNT_WEB_DIST",
        "legacy",
        "serving the legacy /account pages",
        "script-src 'self'",
        "Cache-Control: no-store",
        "immutable",
        "/account/api",
        "X-CSRF-Token",
        "Origin",
        "Never cache",
    ):
        assert needle in section, needle
    assert "(#account-ui-react-or-legacy)" in readme


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
    for command in set(re.findall(r"token_admin (check|list|accounts|approve|promote-owner|revoke|remove|disable|enable|access|history|rotate|db)\b", readme)):
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
    assert "Disk and abuse protection" in readme and "Cloudflare" in readme


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
            assert "does not re-read" in line or "do not use" in line, line
    secrets_table = readme[readme.index("### Other secrets") : readme.index("## Backup and restore")]
    for name in ("ENTRA_CLIENT_SECRET", "ACCOUNT_SESSION_SECRET", "OAUTH_JWT_SIGNING_KEY"):
        row = next(line for line in secrets_table.splitlines() if f"`{name}`" in line)
        assert "docker compose up -d" in row, row
    rotation = readme[readme.index("### Canvas token key ring") : readme.index("### Other secrets")]
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
    from canvas_mcp.core.selfhost.settings import (
        SelfhostConfigError,
        load_selfhost_settings,
    )

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


def test_the_dns_recheck_limit_is_described_accurately() -> None:
    text = (SELFHOST / "README.md").read_text(encoding="utf-8")
    assert "does not re-resolve the school on every request" not in text
    assert "Addresses are checked only when a user enrolls" in text


def test_the_root_readme_does_not_call_the_selfhost_guide_chinese() -> None:
    text = (SELFHOST.parents[1] / "README.md").read_text(encoding="utf-8")
    assert "written in Chinese" not in text


def test_the_canvas_api_url_comment_does_not_contradict_itself() -> None:
    text = (SELFHOST / "env.example").read_text(encoding="utf-8")
    assert "All users can reach only this one Canvas" not in text


def test_every_operator_facing_write_tool_text_mentions_the_per_user_opt_in(readme) -> None:
    """ALLOWED_WRITE_TOOLS is a ceiling: no text may read as if it turns the tools on for users."""
    script = (SELFHOST / "setup-env.sh").read_text(encoding="utf-8")
    assert "ceiling" in script and '"Write tools" section of /account' in script
    assert script.count("/account") >= 2  # the --help text and the generated .env comment
    flat = " ".join(readme.split())
    for needle in (
        "`--enable-writes`: allow all the student write tools on the server. This is only the ceiling",
        "even after you enable tools here, each user still has to turn them on",
        "Once the operator has enabled them and a user has turned them on for themselves",
    ):
        assert needle in flat, f"README.md is missing {needle!r}"
    assert "Once enabled, the AI can do these things" not in flat
    assert flat.count("#write-tools-each-user-opts-in") >= 3


def test_readme_documents_the_credential_lifecycle(readme):
    assert "(#canvas-credential-lifecycle)" in readme
    section = readme.split("## Canvas credential lifecycle", 1)[1].split("\n## ", 1)[0]
    for needle in (
        "credential generation",
        "never confers any Canvas permission",
        "Pending write confirmations",
        "already dispatched",
        "never cancelled",
        "X-Canvas-Token",
    ):
        assert needle in section, f"credential lifecycle section is missing {needle!r}"
    assert "schema version 4" in readme
    assert "restart the server after a restore" in readme.lower()


def _custody_section(readme: str) -> str:
    return readme.split("## Custody and privacy boundary", 1)[1].split("\n## ", 1)[0]


def test_readme_inventories_every_secret_the_mode_holds(readme):
    section = _custody_section(readme)
    for item in (
        "Canvas personal access tokens",
        "CANVAS_TOKEN_KEYS",
        "Upstream Entra tokens",
        "OAUTH_JWT_SIGNING_KEY",
        "ACCOUNT_SESSION_SECRET",
        "ENTRA_CLIENT_SECRET",
        "Audit log",
    ):
        assert item in section, f"{item} is missing from the custody inventory"
    for column in (
        "Where it lives",
        "Who can read it",
        "Rotation",
        "Backup and restore",
        "Deletion and retention",
    ):
        assert column in section


def test_readme_states_the_real_privacy_boundary(readme):
    section = _custody_section(readme)
    assert "database-only leak" in section
    assert "compromised runtime" in section
    assert "operator" in section
    assert "not a cryptographic one" in section


def test_the_root_readme_states_the_opt_in_exception() -> None:
    root = (SELFHOST.parents[1] / "README.md").read_text(encoding="utf-8")
    assert "explicit opt-in" in root
    assert "deploy/selfhost/README.md#custody-and-privacy-boundary" in root
    assert "compromised runtime" in root


def test_nginx_example_logs_the_path_without_the_query_string():
    conf = (SELFHOST / "nginx.conf.example").read_text(encoding="utf-8")
    format_line = next(
        line for line in conf.splitlines() if line.startswith("log_format canvas_safe")
    )
    assert "$uri" in format_line
    for leaky in (
        "$request ",
        '$request"',
        "$request_uri",
        "$args",
        "$query_string",
        "$http_authorization",
        "$http_cookie",
        "$http_referer",
    ):
        assert leaky not in format_line
    assert re.search(r"^\s*access_log\s+\S+\s+canvas_safe;", conf, re.MULTILINE)


def test_caddy_example_blanks_oauth_query_values_and_credential_headers():
    conf = (SELFHOST / "Caddyfile.example").read_text(encoding="utf-8")
    active = "\n".join(
        line for line in conf.splitlines() if not line.lstrip().startswith("#")
    )
    assert "format filter" in active
    for needle in (
        "request>uri query",
        "replace code REDACTED",
        "replace state REDACTED",
        "request>headers>Authorization delete",
        "request>headers>Cookie delete",
    ):
        assert needle in active


def test_readme_documents_the_proxy_log_redaction(readme):
    assert "### Keep OAuth codes out of proxy logs" in readme
    assert "canvas_safe" in readme
    assert "replace code REDACTED" in readme


def test_env_example_no_longer_offers_revoking_enrollments():
    text = (SELFHOST / "env.example").read_text(encoding="utf-8")
    assert "revoke enrollments" not in text
    owner_line = next(line for line in text.splitlines() if "Operator role" in line)
    assert "disable" in owner_line and "remove" in owner_line


def test_readme_states_what_the_scrub_and_the_guards_do_not_cover(readme):
    # Third-party (FastMCP) log lines are scrubbed by shape only.
    assert "bare OAuth transaction id" in readme
    # The last-owner guard counts stored owner flags, which can be stale.
    assert "never comes back therefore still counts" in readme
    assert "owner_seen_at" in readme
    # Audit endpoints mask names, not only numbers.
    assert "page slugs" in readme


def test_readme_lists_every_setting_that_must_stay_unset(readme):
    marker = "Settings that must stay unset"
    assert marker in readme
    section = readme[readme.index(marker) : readme.index(marker) + 1500]
    for name in MUST_BE_UNSET:
        assert name in section, f"README does not list {name} among the settings that must stay unset"


def test_the_course_state_setting_ships_at_its_default_and_is_documented(env_text, readme):
    from canvas_mcp.core.selfhost.settings import COURSE_STATES, DEFAULT_COURSE_STATE

    assert _commented_assignments(env_text)["SELFHOST_COURSE_STATE"] == DEFAULT_COURSE_STATE
    assert "SELFHOST_COURSE_STATE" not in _assignments(env_text)
    for value in COURSE_STATES:
        assert value in env_text, f"env.example does not explain {value}"
    assert "## Course state: request-local or per user" in readme
    section = readme[readme.index("## Course state: request-local or per user") :]
    section = section[: section.index("\n## ", 5)]
    assert "SELFHOST_COURSE_STATE" in section
    for value in COURSE_STATES:
        assert f"`{value}`" in section, f"README does not explain {value}"
    assert "default" in section.lower() and "opt-in" in section.lower()


def test_the_disabled_tools_setting_ships_off_and_is_documented(env_text, readme):
    from canvas_mcp.core.selfhost.settings import DISABLED_TOOLS_ENV

    assert DISABLED_TOOLS_ENV == "SELFHOST_DISABLED_TOOLS"
    assert _commented_assignments(env_text)[DISABLED_TOOLS_ENV] == ""
    assert DISABLED_TOOLS_ENV not in _assignments(env_text)
    assert "## Disabling tools" in readme
    section = readme[readme.index("## Disabling tools") :]
    section = section[: section.index(chr(10) + "## ", 5)]
    assert DISABLED_TOOLS_ENV in section
    for text in ("read_course_file_text", "unknown", "only remove", "--config", "restart"):
        assert text in section, f"README no longer mentions {text!r} for disabling tools"


def test_readme_records_what_the_oauth_proxy_does_with_replayed_codes_and_refresh_tokens(readme):
    heading = "### How the OAuth proxy treats replayed codes and refresh tokens"
    assert heading in readme
    section = readme[readme.index(heading) :]
    section = section[: section.index("\n## ", 5)]
    for text in ("invalid_grant", "code_challenge", "S256", "family", "not** revoked", "Revoking a user"):
        assert text in section, f"the OAuth notes no longer mention {text!r}"


def test_the_docs_do_not_claim_request_local_equals_upstream_for_every_kind_of_state(env_text, readme):
    # Upstream keeps policy decisions, pseudonyms and discussion hints in process-wide
    # maps shared by all callers (keyed by course, user or topic id, not by caller);
    # only the course list and aliases are request-local there. request_local is
    # stricter, and the text may be quoted upstream, so it must not misdescribe upstream.
    root = Path(__file__).resolve().parents[1]
    changelog = (root / "CHANGELOG.md").read_text(encoding="utf-8")
    settings_py = (root / "src" / "canvas_mcp" / "core" / "selfhost" / "settings.py").read_text(encoding="utf-8")
    assert "This is how the upstream HTTP modes work." not in env_text
    assert "already work" not in readme[readme.index("`request_local` (default)") :][:1500]
    assert "like the upstream HTTP modes; tools" not in changelog
    assert "the default, like the upstream HTTP modes" not in settings_py
    for text in (env_text, readme, settings_py):
        flat = " ".join(text.replace("#", " ").split())
        assert "stricter than" in flat and "shared by all callers" in flat
        # Upstream does not key these caches by a token hash; never say it does.
        assert "process-wide by token hash" not in flat
    assert "stricter than upstream" in changelog


def test_the_credential_lifecycle_names_the_rows_that_follow_the_course_state_setting(readme):
    heading = "What is bound to the generation"
    sentence = readme[readme.index(heading) :].split("\n", 1)[0]
    assert "first three rows" in sentence and "first four rows" not in sentence
    table = readme[readme.index(heading) :].split("\n\n", 2)[1].splitlines()
    rows = [line for line in table if line.startswith("| ") and not line.startswith(("| State", "|---"))]
    # Rows 1-3 are course state; row 4 is the pending write confirmations, which
    # stay process-wide in every mode.
    assert rows[3].startswith("| Pending write confirmations")


def test_the_ssrf_proxy_refusal_lists_exactly_the_words_the_code_accepts_as_false(readme):
    from canvas_mcp.core.selfhost.app import _FALSE_WORDS

    paragraph = readme[readme.index("**Settings that must stay unset.**") :].split("\n", 1)[0]
    listed = re.search(r"explicit false \(([^)]*)\)", paragraph)
    assert listed, "README no longer lists the accepted false values"
    words = set(re.findall(r"`([^`]*)`", listed.group(1)))
    assert words == _FALSE_WORDS - {""}


def test_the_database_section_documents_every_database_setting_and_command(readme):
    section = readme[readme.index("\n## Database\n") :]
    section = section[: section.index("\n## Secret rotation\n")]
    for needle in (
        "DATABASE_URL",
        "DATABASE_AUTO_MIGRATE",
        "DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR",
        "SELFHOST_STATE_BACKEND",
        "postgresql+psycopg://",
        "docker-compose.postgres.yml",
        "token_admin db current",
        "token_admin db upgrade",
        "db import-sqlite",
        "pg_advisory_xact_lock",
        "READ COMMITTED",
        "FASTMCP_HOME",
        "Alembic",
        "reserved",
        "No downgrade",
        "sslmode=verify-full",
        "pgbouncer",
    ):
        assert needle in section, f"the Database section is missing {needle!r}"
    assert "[Database](#database)" in readme


def test_the_database_commands_in_the_docs_exist_in_the_cli():
    source = (SRC / "core" / "selfhost" / "token_admin.py").read_text(encoding="utf-8")
    for command in ("current", "upgrade", "import-sqlite"):
        assert re.search(rf'add_parser\(\s*"{command}"', source), command


# --- the account model ---


def test_the_readme_documents_accounts_admission_and_the_upgrade(readme):
    for needle in (
        "## Accounts and admission",
        "### Upgrading to the account model",
        "acct:<uuid>",
        "https://login.microsoftonline.com/<tenant id>/v2.0",
        "ACCESS_POLICY",
        "ACCESS_RULES",
        "ACCESS_FALLBACK",
        "OWNER_RULES",
        "SELFHOST_BOOTSTRAP_OWNER",
        "TRUSTED_PROXY_CIDRS",
        "/account/admin/audit",
        "db upgrade --dry-run",
        "pre-0002-accounts",
        "pg_dump",
        "token_admin approve",
        "token_admin promote-owner",
    ):
        assert needle in readme, f"README.md is missing {needle!r}"


def test_the_changelog_announces_the_account_model():
    changelog = (REPO / "CHANGELOG.md").read_text(encoding="utf-8")
    unreleased = changelog[changelog.index("## [Unreleased]") :].split("\n## [")[0]
    assert "acct:<uuid>" in unreleased and "0002_accounts" in unreleased


def test_the_documented_rule_kinds_are_the_ones_the_parser_accepts():
    from canvas_mcp.core.selfhost import accounts

    problems: list[str] = []
    tenant = "11111111-2222-3333-4444-555555555555"
    for rule in (
        "entra:role:Canvas.User",
        "entra:group:99999999-0000-4000-8000-000000000001",
        f"entra:tenant:{tenant}",
    ):
        accounts.parse_access_settings(
            {"ACCESS_RULES": rule}, tenant_id=tenant, required_role="Canvas.User",
            owner_role="Canvas.Owner", problems=problems,
        )
    assert problems == []
    for rule in ("google:role:x", "github:role:x", "oidc:role:x", "entra:magic:x", "other:role:x"):
        refused: list[str] = []
        accounts.parse_access_settings(
            {"ACCESS_RULES": rule}, tenant_id=tenant, required_role="Canvas.User",
            owner_role="Canvas.Owner", problems=refused,
        )
        assert refused, rule
