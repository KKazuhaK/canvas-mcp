"""Dockerfile.selfhost: reproducible, non-root, and free of baked-in secrets."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = ROOT / "Dockerfile.selfhost"
ROOT_DOCKERFILE = ROOT / "Dockerfile"
DIGEST = "sha256:cad9a2c871761c413caa6fdd6441c783451e740a48aaeba60ae62a8b53525ef6"


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
    assert len(froms) == 2
    for args in froms:
        assert f"@{DIGEST}" in args, args


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
    assert "uv pip install" not in DOCKERFILE.read_text(encoding="utf-8")


def test_uv_is_pinned_to_an_exact_version(instructions):
    installs = [args for name, args in instructions if name == "RUN" and "pip install" in args]
    assert installs and all(re.search(r"\buv==\d+\.\d+\.\d+\b", args) for args in installs)


def test_healthcheck_targets_healthz(instructions):
    checks = [args for name, args in instructions if name == "HEALTHCHECK"]
    assert len(checks) == 1
    assert "/healthz" in checks[0]
    assert "127.0.0.1:8819" in checks[0]


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
