"""Validate deployable v1 configuration and operator/security documentation."""

from __future__ import annotations

import base64
import ipaddress
import re
from pathlib import Path
from urllib.parse import urlsplit

import pytest
from dotenv import dotenv_values

from canvas_mcp.core.config import STUDENT_WRITE_TOOL_NAMES
from canvas_mcp.core.selfhost.settings import (
    REMOVED_SETTINGS,
    SelfhostConfigError,
    load_selfhost_settings,
)

ROOT = Path(__file__).resolve().parents[1]
SELFHOST = ROOT / "deploy/selfhost"


def text(name):
    return (SELFHOST / name).read_text(encoding="utf-8")


def assignments():
    return {
        key: value or ""
        for key, value in dotenv_values(SELFHOST / "env.example").items()
    }


@pytest.mark.parametrize(
    "name",
    [
        "CANVAS_MCP_IMAGE",
        "MCP_AUTH_MODE",
        "PUBLIC_BASE_URL",
        "ENTRA_TENANT_ID",
        "ENTRA_CLIENT_ID",
        "ENTRA_CLIENT_SECRET",
        "ACCOUNT_SESSION_SECRET",
        "CANVAS_TOKEN_KEYS",
    ],
)
def test_required_active_template_values_exist_without_live_secrets(name):
    values = assignments()
    assert name in values
    assert values[name] == ("selfhost" if name == "MCP_AUTH_MODE" else "")


@pytest.mark.parametrize("name", tuple(REMOVED_SETTINGS))
def test_removed_settings_cannot_be_uncommented_from_the_template(name):
    template = text("env.example")
    assert not re.search(rf"^#? *{name}=", template, re.M)


def test_template_has_safe_read_only_defaults():
    values = assignments()
    assert values["CANVAS_ROLE"] == "student"
    assert values["MCP_MAX_RESULT_CHARS"] == "140000"
    assert (
        not {
            "ALLOWED_WRITE_TOOLS",
            "STUDENT_WRITE_TOOLS",
            "COURSE_AGENT_POLICY_DEFAULT",
            "CANVAS_API_TOKEN",
            "MCP_ACCESS_KEYS",
            "ENTRA_AUTH_ENABLED",
            "MCP_ALLOW_UNAUTHENTICATED",
            "ACCESS_REQUEST_ENABLED",
            "FASTMCP_SSRF_TRUST_PROXY",
        }
        & values.keys()
    )
    assert values.get("EXECUTE_TYPESCRIPT_ENABLED", "false") == "false"


def test_unedited_template_is_refused():
    with pytest.raises(SelfhostConfigError):
        load_selfhost_settings(assignments())


def test_filled_template_is_accepted_by_current_settings(tmp_path):
    values = assignments()
    secret = base64.b64encode(bytes(range(32))).decode()
    values.update(
        PUBLIC_BASE_URL="https://canvas.example.test",
        ENTRA_TENANT_ID="11111111-2222-3333-4444-555555555555",
        ENTRA_CLIENT_ID="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        ENTRA_CLIENT_SECRET="not-a-real-secret-0123456789",
        ACCOUNT_SESSION_SECRET=secret,
        CANVAS_TOKEN_KEYS="k1:" + secret,
        SELFHOST_DATA_DIR=str(tmp_path),
        CANVAS_MCP_IMAGE="canvas-mcp:selfhost-v1-local",
    )
    settings = load_selfhost_settings(values)
    assert settings.public_base_url == values["PUBLIC_BASE_URL"]
    assert settings.course_state == "request_local"


def test_commented_student_write_tools_match_the_server_allowlist():
    names = (
        re.search(r"^# STUDENT_WRITE_TOOLS=(.*)$", text("env.example"), re.M)
        .group(1)
        .split(",")
    )
    assert set(names) == set(STUDENT_WRITE_TOOL_NAMES)


def test_all_current_settings_reads_are_documented():
    source = (ROOT / "src/canvas_mcp/core/selfhost/settings.py").read_text(
        encoding="utf-8"
    )
    account_source = (ROOT / "src/canvas_mcp/core/selfhost/accounts.py").read_text(
        encoding="utf-8"
    )
    names = set(re.findall(r'get\("([A-Z][A-Z0-9_]+)"\)', source))
    names |= set(re.findall(r'^\w+_ENV = "([A-Z][A-Z0-9_]+)"', account_source, re.M))
    documented = text("env.example")
    assert len(names) >= 12
    assert not names - set(re.findall(r"\b[A-Z][A-Z0-9_]+\b", documented))


def test_deployment_examples_are_neutral_and_english():
    allowed = {
        "accounts.google.com",
        "canvas.instructure.com",
        "claude.ai",
        "claude.com",
        "ghcr.io",  # Published image references, not deployment-origin examples.
        "github.com",
        "learn.microsoft.com",
        "login.microsoftonline.com",
        "raw.githubusercontent.com",
        "smoke-not-real.apps.googleusercontent.com",
    }
    paths = [
        path
        for path in SELFHOST.iterdir()
        if path.is_file() and path.name not in {"DEVELOPMENT.md", "V1-DESIGN.md"}
    ]
    paths.append(ROOT / "web/README.md")
    for path in paths:
        content = path.read_text(encoding="utf-8")
        assert not re.search(r"[\u4e00-\u9fff]", content)
        hosts = set(
            re.findall(
                r"\b(?:[a-zA-Z0-9-]+\.)+(?:com|edu|org|net|io|ai|gov)\b", content
            )
        )
        for url in re.findall(r"https?://[^\s`\"'<>]+", content):
            if url.startswith(("https://[^", "http://[^")):
                continue  # The Bash setup script's URL validation regular expression.
            host = urlsplit(url).hostname
            if host and not any(char in host for char in "$}{"):
                hosts.add(host)
        for host in hosts:
            host = host.lower().rstrip(".,)")
            if (
                host in allowed
                or host == "localhost"
                or any(
                    host == root or host.endswith("." + root)
                    for root in ("example.com", "example.edu", "example.org")
                )
            ):
                continue
            try:
                assert ipaddress.ip_address(host).is_loopback
            except ValueError:
                pytest.fail(
                    f"non-neutral deployment host in {path.relative_to(ROOT)}: {host}"
                )


def test_independent_fork_notice_and_unclaimed_client_table():
    content = text("README.md")
    opening = content.split("## ")[0]
    assert "independent fork" in opening and "not endorsed" in opening
    assert "vishalsachdev/canvas-mcp" in opening and "small" in opening
    assert (
        "independent fork"
        in (ROOT / "README.md").read_text(encoding="utf-8").split("## ")[0]
    )
    table = content.split("### Tested clients", 1)[1].split(
        "### Staging acceptance", 1
    )[0]
    assert "Only `Passed` rows" in table
    results = {"Not tested", "Passed", "Partial", "Failed"}
    rows = [
        line
        for line in table.splitlines()
        if line.startswith("| claude.ai web") or line.startswith("| Claude ")
    ]
    assert len(rows) == 4
    for row in rows:
        columns = [value.strip() for value in row.strip("|").split("|")]
        assert len(columns) == 8 and columns[5] in results
        if columns[5] != "Not tested":
            assert all(columns[index] not in {"", "-"} for index in (1, 2, 3, 4, 6))
    assert "OPERATOR.md" in content
    assert "db/migrations/README.md" in text("OPERATOR.md")


def test_readme_explains_image_selection_and_recreation():
    content = text("README.md")
    for expected in (
        "CANVAS_MCP_IMAGE",
        "docker-compose.build.yml",
        "config --quiet",
        "up -d --build",
        "recreate",
        "Dockerfile.selfhost",
        "UID/GID",
        "10001",
        "one replica",
    ):
        assert expected in content
    assert "default `latest`" not in content


def test_upgrade_and_transfer_instructions_link_to_the_isolated_package():
    content = text("README.md")
    assert "db/migrations/README.md" in content
    assert "Pre-v1 files are refused" in content
    assert "DATABASE_URL" in content and "keyring" in content
    assert "pg_advisory_xact_lock" not in content


def test_operator_guide_covers_security_and_staging_limits():
    content = text("README.md")
    for expected in (
        "custody",
        "Admin > Settings",
        "directory search",
        "Instructure",
        "write tools",
        "course policy",
        "approval",
        "anonym",
        "last usable",
        "key rotation",
        "B2B",
        "consecutive",
        "staging",
        "Local unit tests",
        "logs",
        "cookies",
        "without buffering",
    ):
        assert expected.lower() in content.lower()


def test_setup_and_smoke_scripts_disable_tracing_and_preserve_secrets():
    setup, smoke = text("setup-env.sh"), text("smoke-test.sh")
    assert "set +x" in setup and "set +x" in smoke
    assert "umask 077" in setup and "set -o noclobber" in setup
    assert "read -r -s -p" in setup
    assert "OAUTH_JWT_SIGNING_KEY=" not in setup
    assert "CANVAS_API_URL=" not in setup
    assert "ACCOUNT_SESSION_SECRET" in setup and "CANVAS_TOKEN_KEYS" in setup
    assert "--read-only" in smoke and "--cap-drop ALL" in smoke
    assert "trap cleanup EXIT" in smoke
    assert "no code exchange or real sign-in" in smoke


def test_nginx_logs_paths_not_oauth_query_headers_or_cookies():
    content = text("nginx.conf.example")
    log = next(line for line in content.splitlines() if line.startswith("log_format "))
    assert "$uri" in log
    assert not any(
        name in log
        for name in (
            "$request_uri",
            "$request ",
            "$args",
            "$http_authorization",
            "$http_cookie",
        )
    )
    assert "proxy_buffering off" in content and "proxy_set_header Host $host" in content


def test_caddy_redacts_oauth_and_credential_values():
    content = text("Caddyfile.example")
    for expected in (
        "replace code",
        "replace state",
        "replace txn",
        "Authorization delete",
        "Cookie delete",
        "Set-Cookie delete",
        "Location delete",
        "flush_interval -1",
    ):
        assert expected in content


def test_custody_documentation_explains_the_operator_decryption_boundary():
    content = text("README.md")
    assert "## Custody and privacy boundary" in content
    assert "decrypt every" in content and "compromised" in content
    assert "plaintext SQL" in content and "audit history" in content
    assert "ACCOUNT_SESSION_SECRET" in content and "AES-256-GCM" in content
    root = (ROOT / "README.md").read_text(encoding="utf-8")
    assert "README.md#custody-and-privacy-boundary" in root
