"""The zero-clone compose file for the self-hosted image keeps its hardening."""

from __future__ import annotations

import ipaddress
from pathlib import Path

import pytest

yaml = pytest.importorskip("yaml")

COMPOSE = Path(__file__).resolve().parents[1] / "deploy" / "selfhost" / "docker-compose.yml"


@pytest.fixture(scope="module")
def document() -> dict:
    return yaml.safe_load(COMPOSE.read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def service(document) -> dict:
    assert list(document["services"]) == ["canvas-mcp"], "exactly one service, one replica"
    return document["services"]["canvas-mcp"]


def test_image_and_pull_policy(service):
    assert service["image"].startswith("ghcr.io/kkazuhak/canvas-mcp:")
    assert service["pull_policy"] == "always"
    assert service["restart"] == "unless-stopped"


def test_ports_are_published_on_loopback_only(service):
    assert service["ports"], "the proxy needs a published port"
    for port in service["ports"]:
        host_ip = str(port).split(":")[0]
        assert ipaddress.ip_address(host_ip).is_loopback, f"{port!r} is not a loopback binding"


def test_configuration_comes_from_env_file_not_inline_environment(service):
    assert service["env_file"] == [".env"]
    assert "environment" not in service, "secrets and settings belong in .env"


def test_state_lives_on_the_data_volume(service, document):
    assert "canvas-mcp-data:/data" in service["volumes"]
    assert "canvas-mcp-data" in document["volumes"]


def test_container_is_hardened(service):
    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert "/tmp" in service["tmpfs"]


def test_not_scaled_beyond_one_replica(service):
    assert "scale" not in service
    assert "replicas" not in service.get("deploy", {})
