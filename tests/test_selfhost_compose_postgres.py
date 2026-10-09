"""The optional PostgreSQL override keeps the database private and pinned."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

REPO = Path(__file__).resolve().parents[1]
SELFHOST = REPO / "deploy" / "selfhost"
OVERRIDE = SELFHOST / "docker-compose.postgres.yml"
WORKFLOW = REPO / ".github" / "workflows" / "canvas-mcp-testing.yml"

IMAGE_RE = re.compile(r"^postgres:(\d+\.\d+)-alpine@sha256:[0-9a-f]{64}$")


@pytest.fixture(scope="module")
def document() -> dict:
    return yaml.safe_load(OVERRIDE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def postgres(document) -> dict:
    return document["services"]["postgres"]


def test_the_main_compose_file_stays_a_single_service_without_postgres() -> None:
    text = (SELFHOST / "docker-compose.yml").read_text(encoding="utf-8")
    assert list(yaml.safe_load(text)["services"]) == ["canvas-mcp"]
    assert "image: postgres" not in text and "depends_on" not in text


def test_the_override_adds_exactly_the_database_and_wires_the_app(document) -> None:
    assert sorted(document["services"]) == ["canvas-mcp", "postgres"]
    app = document["services"]["canvas-mcp"]
    assert app["depends_on"] == {"postgres": {"condition": "service_healthy"}}
    assert app["networks"] == ["default", "canvas-mcp-db"]
    # Nothing but the database wiring is overridden: the hardening of the base file stays.
    assert set(app) == {"depends_on", "networks"}


def test_the_image_is_pinned_by_exact_tag_and_digest(postgres) -> None:
    match = IMAGE_RE.match(postgres["image"])
    assert match, postgres["image"]
    assert int(match.group(1).split(".")[0]) >= 18


def test_the_database_publishes_no_port_and_sits_on_an_internal_network(document, postgres) -> None:
    assert "ports" not in postgres
    assert "expose" not in postgres or postgres["expose"] == []
    assert postgres["networks"] == ["canvas-mcp-db"]
    assert document["networks"]["canvas-mcp-db"] == {"internal": True}


def test_the_password_comes_from_interpolation_never_from_the_file(postgres) -> None:
    password = postgres["environment"]["POSTGRES_PASSWORD"]
    assert re.fullmatch(r"\$\{POSTGRES_PASSWORD:\?[^}]+\}", password)
    lines = OVERRIDE.read_text(encoding="utf-8").splitlines()
    body = "\n".join(line for line in lines if not line.lstrip().startswith("#"))
    assert not re.search(r"^\s*POSTGRES_PASSWORD:\s*(?!\$\{)\S", body, re.MULTILINE)
    assert "env_file" not in postgres


def test_the_cluster_is_utf8_with_the_c_locale(postgres) -> None:
    args = postgres["environment"]["POSTGRES_INITDB_ARGS"]
    assert "--encoding=UTF8" in args and "--locale=C" in args


def test_there_is_a_real_healthcheck_and_the_app_waits_for_it(postgres) -> None:
    health = postgres["healthcheck"]
    assert health["test"][0] == "CMD-SHELL" and "pg_isready" in health["test"][1]
    assert "-U canvas" in health["test"][1] and "-d canvas_mcp" in health["test"][1]
    assert health["retries"] >= 3 and health["interval"].endswith("s")


def test_data_lives_on_a_named_volume_with_a_fixed_name(document, postgres) -> None:
    assert postgres["volumes"] == ["canvas-mcp-postgres:/var/lib/postgresql"]
    assert document["volumes"]["canvas-mcp-postgres"] == {"name": "canvas-mcp-postgres"}


def test_the_container_is_hardened_with_only_the_capabilities_its_entrypoint_needs(postgres) -> None:
    assert postgres["cap_drop"] == ["ALL"]
    assert set(postgres["cap_add"]) <= {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETGID", "SETUID"}
    assert "no-new-privileges:true" in postgres["security_opt"]
    assert postgres["restart"] == "unless-stopped"


def test_ci_tests_against_the_image_the_compose_override_deploys(postgres) -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["test-postgres"]
    assert job["services"]["postgres"]["image"] == postgres["image"]
    assert job["services"]["postgres"]["env"]["POSTGRES_INITDB_ARGS"].replace(" ", "") in (
        "--locale=C--encoding=UTF8",
        "--encoding=UTF8--locale=C",
    )


def test_the_env_template_documents_the_database_settings_without_values() -> None:
    env = (SELFHOST / "env.example").read_text(encoding="utf-8")
    for name in (
        "DATABASE_URL",
        "DATABASE_AUTO_MIGRATE",
        "DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR",
        "SELFHOST_STATE_BACKEND",
        "POSTGRES_PASSWORD",
    ):
        assert re.search(rf"^#? ?{name}=", env, re.MULTILINE), name
        assert not re.search(rf"^{name}=\S", env, re.MULTILINE), f"{name} must not ship a value"
    assert "reserved" in env.lower() and "redis" in env.lower()
