"""The OAuth state store this mode builds itself, and the dependency range behind it.

FastMCP's ``AzureProvider`` takes a public ``client_storage`` argument. The
self-hosted mode passes its own encrypted, lifetime-limited file store instead
of reaching into a private provider attribute. State written by earlier
releases (FastMCP's own default store) has to stay readable after an upgrade,
so the layout and key derivation are pinned against FastMCP itself here.
"""

from __future__ import annotations

import asyncio
import inspect
import json
import tomllib
from datetime import datetime
from importlib import metadata
from pathlib import Path
from typing import Any

import fastmcp
import pytest
from fastmcp.server.auth.providers.azure import AzureProvider
from packaging.requirements import Requirement
from packaging.version import Version

pytest.importorskip("canvas_mcp.core.selfhost.token_store")

from canvas_mcp.core.selfhost import oauth as oauth_module  # noqa: E402
from canvas_mcp.core.selfhost.oauth import (  # noqa: E402
    DCR_CLIENT_TTL_SECONDS,
    OAuthStorage,
    build_entra_auth_provider,
    cull_expired_oauth_state,
    oauth_storage_of,
)

from .test_oauth_wiring import _settings  # noqa: E402

REPO = Path(__file__).resolve().parents[2]
SIGNING_KEY = "jwt-signing-key-" + "z" * 40
COLLECTION = "mcp-upstream-tokens"
CLIENTS = "mcp-oauth-proxy-clients"


@pytest.fixture(autouse=True)
def _fastmcp_home(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(fastmcp.settings, "test_mode", True)  # cheap key stretching
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")


def _stock_provider() -> AzureProvider:
    """A provider with FastMCP's own default store, as earlier releases used."""
    return AzureProvider(
        client_id="aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        client_secret="entra-client-secret-0123456789",
        tenant_id="11111111-2222-3333-4444-555555555555",
        required_scopes=["Canvas.Access"],
        base_url="https://canvas.example.test",
        jwt_signing_key=SIGNING_KEY,
    )


def _record_files(root: Path) -> list[Path]:
    return [p for p in root.rglob("*.json") if not p.name.endswith("-info.json")]


class TestUpgradePath:
    """Data an older release left in FASTMCP_HOME keeps working."""

    async def test_records_written_by_fastmcps_default_store_are_readable(self, tmp_path):
        stock_store: Any = _stock_provider()._client_storage  # noqa: SLF001 - compat pin
        await stock_store.put(
            key="up-1", value={"access_token": "entra-at"}, collection=COLLECTION, ttl=3600
        )

        ours = OAuthStorage(tmp_path / "fastmcp", SIGNING_KEY)

        assert await ours.store.get(key="up-1", collection=COLLECTION) == {
            "access_token": "entra-at"
        }

    async def test_records_written_by_this_store_are_readable_by_fastmcps_default(self, tmp_path):
        ours = OAuthStorage(tmp_path / "fastmcp", SIGNING_KEY)
        await ours.store.put(key="up-2", value={"n": 2}, collection=COLLECTION, ttl=3600)

        stock_store: Any = _stock_provider()._client_storage  # noqa: SLF001 - compat pin
        assert await stock_store.get(key="up-2", collection=COLLECTION) == {"n": 2}

    def test_it_uses_the_same_directory_as_fastmcps_default(self, tmp_path):
        stock_home = tmp_path / "stock"
        fastmcp.settings.home = stock_home
        _stock_provider()
        (stock_fingerprint,) = [p.name for p in (stock_home / "oauth-proxy").iterdir()]

        ours = OAuthStorage(tmp_path / "fastmcp", SIGNING_KEY)

        assert ours.directory == tmp_path / "fastmcp" / "oauth-proxy" / stock_fingerprint

    async def test_a_registration_stored_without_a_lifetime_is_still_readable(self, tmp_path):
        """What FastMCP's default store did to client registrations."""
        stock_store: Any = _stock_provider()._client_storage  # noqa: SLF001 - compat pin
        await stock_store.put(key="c1", value={"n": 1}, collection=CLIENTS)

        ours = OAuthStorage(tmp_path / "fastmcp", SIGNING_KEY)

        assert await ours.store.get(key="c1", collection=CLIENTS) == {"n": 1}

    async def test_a_new_signing_key_is_a_clean_miss_not_a_crash(self, tmp_path):
        old = OAuthStorage(tmp_path / "fastmcp", SIGNING_KEY)
        await old.store.put(key="up-3", value={"n": 3}, collection=COLLECTION, ttl=3600)

        rotated = OAuthStorage(tmp_path / "fastmcp", "a-completely-different-key-" + "q" * 30)

        assert rotated.directory != old.directory
        assert await rotated.store.get(key="up-3", collection=COLLECTION) is None
        # The old state is untouched, so rolling the key back restores it.
        assert await old.store.get(key="up-3", collection=COLLECTION) == {"n": 3}

    async def test_a_record_sealed_under_another_key_is_a_miss(self, tmp_path):
        from cryptography.fernet import Fernet
        from key_value.aio.wrappers.encryption import FernetEncryptionWrapper

        ours = OAuthStorage(tmp_path / "fastmcp", SIGNING_KEY)
        stranger = FernetEncryptionWrapper(key_value=ours.files, fernet=Fernet(Fernet.generate_key()))
        await stranger.put(key="foreign", value={"v": 1}, collection=COLLECTION, ttl=3600)

        assert await ours.store.get(key="foreign", collection=COLLECTION) is None


class TestStorageProperties:
    async def test_values_are_encrypted_on_disk(self, tmp_path):
        ours = OAuthStorage(tmp_path / "fastmcp", SIGNING_KEY)
        await ours.store.put(
            key="up-4",
            value={"access_token": "very-secret-entra-token"},
            collection=COLLECTION,
            ttl=3600,
        )

        text = "".join(p.read_text(encoding="utf-8") for p in _record_files(ours.directory))
        assert text
        assert "very-secret-entra-token" not in text
        assert "access_token" not in text

    async def test_records_without_a_lifetime_get_the_registration_lifetime(self, tmp_path):
        ours = OAuthStorage(tmp_path / "fastmcp", SIGNING_KEY)
        await ours.store.put(key="k", value={"n": 1}, collection=CLIENTS)

        (record,) = _record_files(ours.directory)
        entry = json.loads(record.read_text(encoding="utf-8"))
        lifetime = datetime.fromisoformat(entry["expires_at"]) - datetime.fromisoformat(
            entry["created_at"]
        )
        assert lifetime.total_seconds() == pytest.approx(DCR_CLIENT_TTL_SECONDS, abs=5)

    async def test_records_that_bring_a_lifetime_keep_it(self, tmp_path):
        ours = OAuthStorage(tmp_path / "fastmcp", SIGNING_KEY)
        await ours.store.put(key="k", value={"n": 1}, collection=COLLECTION, ttl=900)

        (record,) = _record_files(ours.directory)
        entry = json.loads(record.read_text(encoding="utf-8"))
        lifetime = datetime.fromisoformat(entry["expires_at"]) - datetime.fromisoformat(
            entry["created_at"]
        )
        assert lifetime.total_seconds() == pytest.approx(900, abs=5)

    async def test_cull_deletes_expired_files_and_keeps_live_ones(self, tmp_path):
        ours = OAuthStorage(tmp_path / "fastmcp", SIGNING_KEY)
        await ours.store.put(key="old", value={"n": 1}, collection=COLLECTION, ttl=0.05)
        await ours.store.put(key="new", value={"n": 2}, collection=COLLECTION, ttl=3600)
        await asyncio.sleep(0.2)
        assert len(_record_files(ours.directory)) == 2

        await ours.cull()

        assert len(_record_files(ours.directory)) == 1
        assert await ours.store.get(key="new", collection=COLLECTION) == {"n": 2}


class TestProviderWiring:
    def test_the_provider_is_built_on_our_store(self, tmp_path):
        provider = build_entra_auth_provider(_settings(tmp_path))

        storage = oauth_storage_of(provider)

        assert isinstance(storage, OAuthStorage)
        assert storage.directory.parent == tmp_path / "fastmcp" / "oauth-proxy"
        # FastMCP was handed our store through the public parameter.
        assert provider._client_storage is storage.store  # noqa: SLF001 - compat pin

    def test_the_product_code_does_not_touch_provider_internals(self):
        source = Path(oauth_module.__file__).read_text(encoding="utf-8")
        assert "_client_storage" not in source
        assert "getattr(provider" not in source

    async def test_cull_goes_through_the_registered_store(self, tmp_path):
        provider = build_entra_auth_provider(_settings(tmp_path))
        storage = oauth_storage_of(provider)
        assert storage is not None
        await storage.store.put(key="old", value={"n": 1}, collection=COLLECTION, ttl=0.05)
        await asyncio.sleep(0.2)

        await cull_expired_oauth_state(provider)

        assert not _record_files(storage.directory)

    def test_a_provider_that_is_not_ours_has_no_storage(self):
        assert oauth_storage_of(object()) is None


def _requirement(name: str) -> Requirement:
    pyproject = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))
    for line in pyproject["project"]["dependencies"]:
        requirement = Requirement(line)
        if requirement.name == name:
            return requirement
    raise AssertionError(f"{name} is not a direct dependency")


def _locked_version(name: str) -> Version:
    lock = tomllib.loads((REPO / "uv.lock").read_text(encoding="utf-8"))
    (package,) = [p for p in lock["package"] if p["name"] == name]
    return Version(package["version"])


class TestSupportedDependencyRange:
    """``FileTreeStore.cull`` first shipped in py-key-value-aio 0.4.6; a lock that
    pins 0.4.5 passes every other test and then fails the cleanup at runtime."""

    def test_the_floor_is_the_version_that_has_cull(self):
        spec = _requirement("py-key-value-aio").specifier
        assert Version("0.4.5") not in spec
        assert Version("0.4.6") in spec
        assert Version("0.5.0") not in spec

    def test_the_fastmcp_floor_has_the_public_client_storage_parameter(self):
        spec = _requirement("fastmcp").specifier
        assert Version("4.0.3") in spec
        assert Version("4.0.0") not in spec
        assert Version("5.0.0") not in spec

    @pytest.mark.parametrize(
        ("locked", "direct"),
        [
            ("py-key-value-aio", "py-key-value-aio"),
            ("fastmcp", "fastmcp"),
            ("fastmcp-slim", "fastmcp"),
        ],
    )
    def test_the_lock_resolves_inside_the_range(self, locked, direct):
        assert _locked_version(locked) in _requirement(direct).specifier

    def test_the_lock_pins_a_py_key_value_with_cull(self):
        assert _locked_version("py-key-value-aio") >= Version("0.4.6")

    @pytest.mark.parametrize("name", ["py-key-value-aio", "fastmcp"])
    def test_the_installed_versions_are_inside_the_range(self, name):
        assert Version(metadata.version(name)) in _requirement(name).specifier

    def test_the_file_store_has_the_methods_this_mode_calls(self):
        from key_value.aio.stores.filetree import FileTreeStore

        assert callable(getattr(FileTreeStore, "cull", None))

    def test_the_provider_accepts_a_client_storage(self):
        assert "client_storage" in inspect.signature(AzureProvider.__init__).parameters

    def test_the_deployment_guide_states_the_range(self):
        guide = (REPO / "deploy" / "selfhost" / "README.md").read_text(encoding="utf-8")
        assert "`>=0.4.6,<0.5`" in guide
        assert "`>=4.0.3,<5`" in guide


class TestInstalledFastmcpSurface:
    """The floor in ``pyproject.toml`` only means something if the installed release
    (CI runs ``uv sync --locked``, so the locked one) really has what the code calls."""

    def test_azure_provider_accepts_the_public_client_storage_parameter(self):
        params = inspect.signature(AzureProvider.__init__).parameters
        assert "client_storage" in params
        assert "jwt_signing_key" in params

    def test_derive_jwt_key_takes_the_salt_and_both_key_materials(self):
        from fastmcp.server.auth.jwt_issuer import derive_jwt_key

        params = inspect.signature(derive_jwt_key).parameters
        assert {"low_entropy_material", "high_entropy_material", "salt"} <= set(params)
        key = derive_jwt_key(low_entropy_material="x" * 32, salt="canvas-mcp-test")
        assert isinstance(key, bytes) and len(key) == 44  # url-safe base64 of 32 bytes

    def test_the_installed_fastmcp_satisfies_the_declared_range(self):
        spec = _requirement("fastmcp").specifier
        assert Version(metadata.version("fastmcp")) in spec
