"""Dockerfile.selfhost: reproducible, non-root, and free of baked-in secrets."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile.selfhost"
ROOT_DOCKERFILE = ROOT / "Dockerfile"
DIGEST = "sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6"
WEB_PACKAGE = ROOT / "web" / "package.json"


def _instructions(path: Path) -> list[tuple[str, str]]:
    """(INSTRUCTION, arguments) pairs with comments and continuations resolved."""
    logical: list[str] = []
    buffer = ""
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.lstrip().startswith("#"):
            continue
        if not buffer and not raw.strip():
            continue
        if raw.rstrip().endswith("\\"):
            buffer += raw.rstrip()[:-1] + " "
            continue
        logical.append(buffer + raw)
        buffer = ""
    if buffer:
        logical.append(buffer)
    pairs = []
    for line in logical:
        name, _, args = line.strip().partition(" ")
        pairs.append((name.upper(), args.strip()))
    return pairs


@pytest.fixture(scope="module")
def instructions() -> list[tuple[str, str]]:
    return _instructions(DOCKERFILE)


def _env_names(instructions: list[tuple[str, str]]) -> list[str]:
    names = []
    for name, args in instructions:
        if name == "ENV":
            names.extend(re.findall(r"(?:^|\s)([A-Za-z_][A-Za-z0-9_]*)=", args))
    return names


def test_every_stage_is_pinned_by_digest(instructions):
    froms = [args for name, args in instructions if name == "FROM"]
    assert len(froms) == 3
    python = [args for args in froms if args.startswith("python:")]
    node = [args for args in froms if args.startswith("node:")]
    assert len(python) == 2 and len(node) == 1
    for args in python:
        assert f"@{DIGEST}" in args, args
    # Node: exact version tag (for humans and Dependabot) AND a digest (what is pulled).
    assert re.fullmatch(r"node:\d+\.\d+\.\d+-alpine@sha256:[0-9a-f]{64} AS web", node[0]), node[0]


def test_the_runtime_stage_is_python_not_node(instructions):
    froms = [args for name, args in instructions if name == "FROM"]
    assert froms[-1].startswith("python:")


def test_the_node_image_satisfies_the_web_projects_engines():
    import json

    engines = json.loads(WEB_PACKAGE.read_text(encoding="utf-8"))["engines"]["node"]
    assert engines.startswith(">="), engines
    minimum = int(engines[2:].split(".")[0])
    tag = re.search(r"node:(\d+)\.", DOCKERFILE.read_text(encoding="utf-8"))
    assert tag is not None and int(tag.group(1)) >= minimum


def test_the_web_stage_builds_from_the_lock_file_without_running_package_scripts(instructions):
    runs = [args for name, args in instructions if name == "RUN"]
    assert "npm ci --ignore-scripts" in runs
    # The dist that ships is checked in the same stage that builds it.
    assert "npm run build && npm run check:dist" in runs
    text = DOCKERFILE.read_text(encoding="utf-8")
    assert "npm install" not in text
    copies = [args for name, args in instructions if name == "COPY"]
    # The manifest and the lock file are copied before the sources, so the install
    # layer is cached until a dependency changes.
    assert "web/package.json web/package-lock.json ./" in copies
    assert copies.index("web/package.json web/package-lock.json ./") < copies.index("web/ ./")


def test_the_built_web_assets_land_in_app_web_dist(instructions):
    copies = [args for name, args in instructions if name == "COPY" and "--from=web" in args]
    assert copies == ["--from=web /web/dist /app/web-dist"]


def test_the_web_build_output_and_node_modules_stay_out_of_the_build_context():
    patterns = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    # `node_modules/` and `dist/` only match at the context root; a local `npm ci`
    # or build inside web/ would be copied over the image's own install.
    assert {"web/node_modules/", "web/dist/"} <= patterns


def test_digest_matches_the_root_dockerfile():
    assert DIGEST in ROOT_DOCKERFILE.read_text(encoding="utf-8")


def test_runs_as_a_non_root_user(instructions):
    users = [args for name, args in instructions if name == "USER"]
    assert users, "no USER instruction"
    assert users[-1] == "10001:10001"
    assert users[-1].split(":")[0] not in {"root", "0"}


def test_no_secret_is_baked_into_the_environment(instructions):
    names = _env_names(instructions)
    assert names, "ENV parsing found nothing"
    forbidden = [
        n
        for n in names
        if n == "CANVAS_API_TOKEN"
        or n.endswith(("_SECRET", "_KEY", "_KEYS", "_TOKEN", "_PASSWORD"))
    ]
    assert forbidden == []
    assert not any(name == "ARG" and "SECRET" in args.upper() for name, args in instructions)


def test_dependencies_come_from_the_lock_file(instructions):
    syncs = [args for name, args in instructions if name == "RUN" and "uv sync" in args]
    assert len(syncs) == 2
    for args in syncs:
        assert "--frozen" in args
        assert "--no-dev" in args
        # The data layer (SQLAlchemy, Alembic) and the PostgreSQL driver (psycopg's
        # binary wheel bundles libpq, so no system packages are needed).
        assert "--extra selfhost" in args and "--extra postgres" in args
    assert "uv pip install" not in DOCKERFILE.read_text(encoding="utf-8")


def test_uv_is_pinned_to_an_exact_version(instructions):
    installs = [args for name, args in instructions if name == "RUN" and "pip install" in args]
    assert installs and all(re.search(r"\buv==\d+\.\d+\.\d+\b", args) for args in installs)


def test_healthcheck_targets_healthz(instructions):
    checks = [args for name, args in instructions if name == "HEALTHCHECK"]
    assert len(checks) == 1
    assert "/healthz" in checks[0]
    assert "127.0.0.1" in checks[0] and "8819" in checks[0]


def test_healthcheck_treats_any_http_answer_below_500_as_alive(instructions):
    """Legacy access-key mode has no /healthz route and answers 401. urlopen raises
    on that and would report a working container unhealthy."""
    (check,) = [args for name, args in instructions if name == "HEALTHCHECK"]
    assert "urlopen" not in check
    assert "getresponse().status<500" in check


def test_the_oauth_state_directory_exists_in_the_image_so_a_volume_can_be_mounted_there(instructions):
    run = " ".join(args for name, args in instructions if name == "RUN")
    assert "/data/fastmcp" in run
    assert "chown 10001:10001 /data /data/fastmcp" in run


def test_dockerignore_keeps_env_and_key_files_out_at_any_depth():
    patterns = {
        line.strip()
        for line in (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.startswith("#")
    }
    # .env and *.env only match at the context root; a stray src/**/.env would be
    # copied into the image by the Dockerfile's `COPY src`.
    for needed in ("**/.env*", "**/*.env", "**/*.pem", "**/*.key"):
        assert needed in patterns, needed
    assert "uv.lock" not in patterns and "pyproject.toml" not in patterns and "src/" not in patterns


def test_data_volume_port_and_command(instructions):
    by_name = dict(instructions)
    assert by_name["VOLUME"] == '["/data"]'
    assert by_name["EXPOSE"] == "8819"
    assert '"streamable-http"' in by_name["CMD"] and '"0.0.0.0"' in by_name["CMD"]


def test_safe_defaults_are_set(instructions):
    env = " ".join(args for name, args in instructions if name == "ENV")
    for expected in (
        "EXECUTE_TYPESCRIPT_ENABLED=false",
        "ENABLE_DATA_ANONYMIZATION=true",
        "FASTMCP_HOME=/data/fastmcp",
        "SELFHOST_DATA_DIR=/data",
    ):
        assert expected in env


def test_the_data_directory_is_private_and_owned_by_the_service_user(instructions):
    run = " ".join(args for name, args in instructions if name == "RUN")
    assert "chown 10001:10001 /data" in run
    assert "chmod 0700 /data" in run
    assert "/usr/sbin/nologin" in run
