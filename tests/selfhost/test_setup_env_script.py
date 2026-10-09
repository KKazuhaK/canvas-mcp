"""deploy/selfhost/setup-env.sh writes a .env the server accepts, and nothing else.

The script runs on the operator's Linux host, so these tests drive the real
script with bash and openssl. On Windows they use Git for Windows' bash (never
the WSL launcher in System32) and are skipped when it is missing.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

import pytest
from dotenv import dotenv_values

from canvas_mcp.core.config import STUDENT_WRITE_TOOL_NAMES
from canvas_mcp.core.selfhost.settings import load_selfhost_settings

from .conftest import CLIENT, TENANT

SCRIPT = Path(__file__).resolve().parents[2] / "deploy" / "selfhost" / "setup-env.sh"
SECRET = "Fake~Entra.Secret_value-0123456789"
BASE = "https://canvas.example.test"
CANVAS = "https://canvas.school.example"


def _find_bash() -> str | None:
    if sys.platform == "win32":
        for candidate in (
            Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Git" / "bin" / "bash.exe",
            Path(os.environ.get("ProgramW6432", r"C:\Program Files")) / "Git" / "bin" / "bash.exe",
        ):
            if candidate.is_file():
                return str(candidate)
        return None
    return shutil.which("bash")


BASH = _find_bash()

pytestmark = pytest.mark.skipif(BASH is None, reason="needs bash (Git for Windows bash on Windows)")


def run_script(
    cwd: Path,
    *args: str,
    stdin: str = SECRET + "\n",
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    base_env = {
        key: value
        for key, value in os.environ.items()
        if key not in {"PUBLIC_BASE_URL", "ENTRA_TENANT_ID", "ENTRA_CLIENT_ID", "CANVAS_API_URL"}
    }
    base_env.update(env or {})
    assert BASH is not None
    # Bytes in, so the input reaches the script exactly as written (text mode
    # would turn "\n" into "\r\n" on Windows).
    raw = subprocess.run(
        [BASH, str(SCRIPT), *args],
        cwd=cwd,
        input=stdin.encode("utf-8"),
        env=base_env,
        capture_output=True,
        timeout=60,
        check=False,
    )
    return subprocess.CompletedProcess(
        raw.args,
        raw.returncode,
        raw.stdout.decode("utf-8", errors="replace"),
        raw.stderr.decode("utf-8", errors="replace"),
    )


def preset(**overrides: str) -> dict[str, str]:
    values = {
        "PUBLIC_BASE_URL": BASE,
        "ENTRA_TENANT_ID": TENANT,
        "ENTRA_CLIENT_ID": CLIENT,
        "CANVAS_API_URL": CANVAS,
    }
    values.update(overrides)
    return values


def read_env(path: Path) -> dict[str, str]:
    return {key: value or "" for key, value in dotenv_values(path).items()}


def load(values: dict[str, str], tmp_path: Path) -> object:
    env = dict(values)
    # The container paths are not writable here; everything else is used as written.
    env["FASTMCP_HOME"] = str(tmp_path / "fastmcp")
    env["SELFHOST_DATA_DIR"] = str(tmp_path / "data")
    return load_selfhost_settings(env)


def test_generated_env_is_accepted_by_the_settings_loader(tmp_path):
    result = run_script(tmp_path, env=preset())
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")

    assert values["MCP_AUTH_MODE"] == "entra-oauth"
    assert values["PUBLIC_BASE_URL"] == BASE
    assert values["ENTRA_TENANT_ID"] == TENANT
    assert values["ENTRA_CLIENT_ID"] == CLIENT
    assert values["ENTRA_CLIENT_SECRET"] == SECRET
    assert values["CANVAS_API_URL"] == CANVAS
    assert values["FASTMCP_HOME"] == "/data/fastmcp"
    assert values["CANVAS_TOKEN_KEYS"].startswith("k1:")

    settings = load(values, tmp_path)
    assert settings.public_base_url == BASE


def test_defaults_are_read_only_and_anonymized(tmp_path):
    result = run_script(tmp_path, env=preset())
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")
    for name in (
        "ALLOWED_WRITE_TOOLS",
        "STUDENT_WRITE_TOOLS",
        "COURSE_AGENT_POLICY_DEFAULT",
        "ENABLE_DATA_ANONYMIZATION",
    ):
        assert name not in values, f"{name} must stay unset without an explicit flag"


def test_course_state_is_left_at_its_request_local_default_and_the_opt_in_is_shown_commented(tmp_path):
    assert run_script(tmp_path, env=preset()).returncode == 0
    path = tmp_path / ".env"
    assert "SELFHOST_COURSE_STATE" not in read_env(path)
    assert "# SELFHOST_COURSE_STATE=per_principal" in path.read_text(encoding="utf-8")
    assert load(read_env(path), tmp_path).course_state == "request_local"

    # Uncommenting the line is the whole opt-in.
    text = path.read_text(encoding="utf-8").replace(
        "# SELFHOST_COURSE_STATE=per_principal", "SELFHOST_COURSE_STATE=per_principal"
    )
    path.write_text(text, encoding="utf-8")
    assert load(read_env(path), tmp_path).course_state == "per_principal"


def test_read_only_file_turns_writes_on_by_uncommenting_not_regenerating(tmp_path):
    """Regenerating replaces CANVAS_TOKEN_KEYS and bricks enrolled tokens, so the
    file must offer the write lines in place and warn against rerunning."""
    assert run_script(tmp_path, env=preset()).returncode == 0
    text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "# ALLOWED_WRITE_TOOLS=all" in text
    assert "# COURSE_AGENT_POLICY_DEFAULT=allow" in text
    assert "Do not rerun setup-env.sh" in text
    uncommented = text.replace("# ALLOWED_WRITE_TOOLS", "ALLOWED_WRITE_TOOLS").replace(
        "# STUDENT_WRITE_TOOLS", "STUDENT_WRITE_TOOLS"
    ).replace("# COURSE_AGENT_POLICY_DEFAULT", "COURSE_AGENT_POLICY_DEFAULT")
    (tmp_path / "edited.env").write_text(uncommented, encoding="utf-8")
    values = read_env(tmp_path / "edited.env")
    assert values["ALLOWED_WRITE_TOOLS"] == "all"
    assert set(values["STUDENT_WRITE_TOOLS"].split(",")) == set(STUDENT_WRITE_TOOL_NAMES)
    assert values["COURSE_AGENT_POLICY_DEFAULT"] == "allow"


def test_refusing_to_overwrite_explains_the_key_loss(tmp_path):
    (tmp_path / ".env").write_text("X=1\n", encoding="utf-8")
    result = run_script(tmp_path, env=preset())
    assert result.returncode != 0
    assert "CANVAS_TOKEN_KEYS" in result.stderr
    assert "just edit" in result.stderr


def test_opt_in_flags_enable_every_student_write_tool_and_real_names(tmp_path):
    result = run_script(tmp_path, "--enable-writes", "--real-names", env=preset())
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")
    assert values["ALLOWED_WRITE_TOOLS"] == "all"
    assert set(values["STUDENT_WRITE_TOOLS"].split(",")) == set(STUDENT_WRITE_TOOL_NAMES)
    assert values["COURSE_AGENT_POLICY_DEFAULT"] == "allow"
    assert values["ENABLE_DATA_ANONYMIZATION"] == "false"
    load(values, tmp_path)


def test_the_enabled_writes_comment_and_help_say_each_user_still_opts_in(tmp_path):
    result = run_script(tmp_path, "--enable-writes", env=preset())
    assert result.returncode == 0, result.stderr
    text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "only the ceiling" in text
    flat_env = " ".join(text.replace("# ", " ").split())
    assert 'tool stays off for each user until that user turns it on in the "Write tools" section of /account' in flat_env
    help_result = run_script(tmp_path, "--help")
    flat = " ".join(help_result.stdout.split())
    assert "only the server ceiling" in flat
    assert 'turns it on in the "Write tools" section of /account' in flat


def test_values_can_be_answered_at_the_prompts(tmp_path):
    answers = "\n".join((BASE, TENANT, CLIENT, CANVAS, SECRET)) + "\n"
    result = run_script(tmp_path, stdin=answers)
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")
    assert values["ENTRA_CLIENT_SECRET"] == SECRET
    assert values["CANVAS_API_URL"] == CANVAS
    load(values, tmp_path)


def test_windows_line_endings_from_a_paste_are_stripped(tmp_path):
    answers = "\r\n".join((BASE, TENANT, CLIENT, CANVAS, SECRET)) + "\r\n"
    result = run_script(tmp_path, stdin=answers)
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")
    assert values["ENTRA_CLIENT_SECRET"] == SECRET
    assert values["PUBLIC_BASE_URL"] == BASE
    load(values, tmp_path)


def test_no_secret_is_printed(tmp_path):
    result = run_script(tmp_path, env=preset())
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")
    output = result.stdout + result.stderr
    for name in ("ENTRA_CLIENT_SECRET", "OAUTH_JWT_SIGNING_KEY", "ACCOUNT_SESSION_SECRET"):
        assert values[name] not in output, f"{name} leaked to the terminal"
    assert values["CANVAS_TOKEN_KEYS"].removeprefix("k1:") not in output


def test_every_run_generates_fresh_keys(tmp_path):
    first, second = tmp_path / "a", tmp_path / "b"
    first.mkdir()
    second.mkdir()
    assert run_script(first, env=preset()).returncode == 0
    assert run_script(second, env=preset()).returncode == 0
    a, b = read_env(first / ".env"), read_env(second / ".env")
    for name in ("OAUTH_JWT_SIGNING_KEY", "ACCOUNT_SESSION_SECRET", "CANVAS_TOKEN_KEYS"):
        assert a[name] != b[name]


def test_an_existing_env_is_never_overwritten(tmp_path):
    existing = tmp_path / ".env"
    existing.write_text("CANVAS_TOKEN_KEYS=k1:keep-me\n", encoding="utf-8")
    result = run_script(tmp_path, env=preset())
    assert result.returncode != 0
    assert existing.read_text(encoding="utf-8") == "CANVAS_TOKEN_KEYS=k1:keep-me\n"


def test_output_option_writes_elsewhere(tmp_path):
    result = run_script(tmp_path, "--output", "canvas.env", env=preset())
    assert result.returncode == 0, result.stderr
    assert (tmp_path / "canvas.env").is_file()
    assert not (tmp_path / ".env").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX file modes")
def test_the_file_is_private(tmp_path):
    assert run_script(tmp_path, env=preset()).returncode == 0
    mode = stat.S_IMODE((tmp_path / ".env").stat().st_mode)
    assert mode == 0o600


@pytest.mark.parametrize(
    ("overrides", "secret"),
    [
        ({"ENTRA_TENANT_ID": "common"}, SECRET),
        ({"ENTRA_CLIENT_ID": "not-a-guid"}, SECRET),
        ({"ENTRA_CLIENT_ID": TENANT}, SECRET),
        ({"PUBLIC_BASE_URL": "http://canvas.example.test"}, SECRET),
        ({"PUBLIC_BASE_URL": BASE + "/"}, SECRET),
        ({"PUBLIC_BASE_URL": BASE + "/mcp"}, SECRET),
        ({"PUBLIC_BASE_URL": BASE + "?x=1"}, SECRET),
        ({"PUBLIC_BASE_URL": BASE + ":65536"}, SECRET),
        ({"PUBLIC_BASE_URL": BASE + ":0"}, SECRET),
        ({"CANVAS_API_URL": "http://canvas.school.example"}, SECRET),
        ({"CANVAS_API_URL": CANVAS + ":99999"}, SECRET),
        ({"CANVAS_API_URL": CANVAS + "/courses/123"}, SECRET),
        ({"CANVAS_API_URL": "https://school.example/canvas"}, SECRET),
        ({}, "too-short"),
        ({}, "has space in the middle 0123456789"),
        ({}, "dollar$sign0123456789abcdef"),
        # The Secret ID column (a GUID) instead of the Value column.
        ({}, "3f2504e0-4f89-11d3-9a0c-0305e82c3301"),
        ({}, ""),
    ],
)
def test_invalid_input_is_refused_and_writes_nothing(tmp_path, overrides, secret):
    result = run_script(tmp_path, env=preset(**overrides), stdin=secret + "\n")
    assert result.returncode != 0
    assert "Error:" in result.stderr
    assert not (tmp_path / ".env").exists()
    if secret and len(secret) >= 16:
        assert secret not in result.stdout + result.stderr


@pytest.mark.parametrize(
    ("given", "written"),
    [
        (CANVAS + "/", CANVAS),
        (CANVAS + "/api/v1", CANVAS + "/api/v1"),
        (CANVAS + "/api/v1/", CANVAS + "/api/v1"),
        (CANVAS + ":8443", CANVAS + ":8443"),
    ],
)
def test_canvas_urls_the_server_understands_are_accepted(tmp_path, given, written):
    result = run_script(tmp_path, env=preset(CANVAS_API_URL=given))
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")
    assert values["CANVAS_API_URL"] == written
    load(values, tmp_path)


def test_highest_port_is_accepted(tmp_path):
    result = run_script(tmp_path, env=preset(PUBLIC_BASE_URL=BASE + ":65535"))
    assert result.returncode == 0, result.stderr


def test_an_unusable_output_path_fails_before_asking_for_the_secret(tmp_path):
    result = run_script(tmp_path, "--output", "missing-dir/.env", env=preset(), stdin="")
    assert result.returncode != 0
    assert "missing-dir" in result.stderr
    assert not (tmp_path / "missing-dir").exists()


def test_no_temporary_files_are_left_behind(tmp_path):
    assert run_script(tmp_path, env=preset()).returncode == 0
    bad = tmp_path / "bad"
    bad.mkdir()
    assert run_script(bad, env=preset(), stdin="short\n").returncode != 0
    leftovers = [p.name for p in (*tmp_path.iterdir(), *bad.iterdir()) if p.name.startswith(".setup-env.")]
    assert leftovers == []
    assert sorted(p.name for p in tmp_path.iterdir() if p.is_file()) == [".env"]


def test_xtrace_does_not_print_secrets(tmp_path):
    assert BASH is not None
    raw = subprocess.run(
        [BASH, "-x", str(SCRIPT)],
        cwd=tmp_path,
        input=(SECRET + "\n").encode("utf-8"),
        env={**os.environ, **preset()},
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert raw.returncode == 0, raw.stderr.decode("utf-8", "replace")
    values = read_env(tmp_path / ".env")
    output = (raw.stdout + raw.stderr).decode("utf-8", "replace")
    for name in ("ENTRA_CLIENT_SECRET", "OAUTH_JWT_SIGNING_KEY", "ACCOUNT_SESSION_SECRET"):
        assert values[name] not in output, f"{name} leaked through xtrace"


def test_help_works_when_the_script_is_piped_in(tmp_path):
    assert BASH is not None
    raw = subprocess.run(
        [BASH, "-s", "--", "--help"],
        cwd=tmp_path,
        input=SCRIPT.read_bytes(),
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert raw.returncode == 0
    assert b"--enable-writes" in raw.stdout


@pytest.mark.skipif(shutil.which("dash") is None, reason="needs dash")
def test_a_non_bash_shell_gets_a_clear_message(tmp_path):
    raw = subprocess.run(
        ["dash", str(SCRIPT)],
        cwd=tmp_path,
        input=b"",
        capture_output=True,
        timeout=60,
        check=False,
    )
    assert raw.returncode != 0
    assert "bash setup-env.sh" in raw.stderr.decode("utf-8", "replace")
    assert not (tmp_path / ".env").exists()


def test_unknown_options_are_refused(tmp_path):
    result = run_script(tmp_path, "--enable-everything", env=preset())
    assert result.returncode != 0
    assert not (tmp_path / ".env").exists()


def test_help_describes_the_options_and_writes_nothing(tmp_path):
    result = run_script(tmp_path, "--help")
    assert result.returncode == 0
    for option in ("--enable-writes", "--real-names", "--output"):
        assert option in result.stdout
    assert not (tmp_path / ".env").exists()


# -- --school-search ---------------------------------------------------------------------------


def test_schools_are_off_by_default_and_shown_commented_out(tmp_path):
    result = run_script(tmp_path, env=preset())
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")
    assert "CANVAS_FEATURED_SCHOOLS" not in values
    assert "CANVAS_SCHOOL_SEARCH" not in values
    text = (tmp_path / ".env").read_text(encoding="utf-8")
    assert "# CANVAS_FEATURED_SCHOOLS=canvas.school.example\n" in text
    assert "# CANVAS_SCHOOL_SEARCH=true\n" in text
    settings = load(values, tmp_path)
    assert settings.featured_schools == ()
    assert settings.school_search is False


def test_school_search_writes_the_featured_host_and_turns_search_on(tmp_path):
    result = run_script(tmp_path, "--school-search", env=preset())
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")
    assert values["CANVAS_SCHOOL_SEARCH"] == "true"
    assert values["CANVAS_FEATURED_SCHOOLS"] == "canvas.school.example"
    assert values["CANVAS_API_URL"] == CANVAS

    settings = load(values, tmp_path)
    assert settings.school_search is True
    assert [school.host for school in settings.featured_schools] == ["canvas.school.example"]
    assert "directory" in (tmp_path / ".env").read_text(encoding="utf-8")


@pytest.mark.parametrize(
    "given",
    [
        "https://Canvas.School.Example:8443",
        "https://CANVAS.school.example/api/v1/",
        "https://canvas.school.example:8443/api/v1",
    ],
)
def test_the_featured_host_has_no_port_path_or_capitals(tmp_path, given):
    result = run_script(tmp_path, "--school-search", env=preset(CANVAS_API_URL=given))
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")
    assert values["CANVAS_FEATURED_SCHOOLS"] == "canvas.school.example"
    settings = load(values, tmp_path)
    assert settings.featured_schools[0].host == "canvas.school.example"


def test_school_search_combines_with_the_other_flags(tmp_path):
    result = run_script(tmp_path, "--school-search", "--enable-writes", "--real-names", env=preset())
    assert result.returncode == 0, result.stderr
    values = read_env(tmp_path / ".env")
    assert values["CANVAS_SCHOOL_SEARCH"] == "true"
    assert values["ALLOWED_WRITE_TOOLS"] == "all"
    assert values["ENABLE_DATA_ANONYMIZATION"] == "false"
    load(values, tmp_path)


def test_the_summary_mentions_the_school_mode(tmp_path):
    plain = run_script(tmp_path, env=preset())
    assert "Single school" in plain.stderr
    (tmp_path / ".env").unlink()
    searched = run_script(tmp_path, "--school-search", env=preset())
    assert "directory search on" in searched.stderr


def test_help_lists_the_school_search_option(tmp_path):
    result = run_script(tmp_path, "--help")
    assert result.returncode == 0
    assert "--school-search" in result.stdout
    assert "CANVAS_SCHOOL_SEARCH" in result.stdout
