"""Two-file container setup must preserve identity keys across recreations."""

from __future__ import annotations

import base64
import concurrent.futures
import json
import os
from pathlib import Path

import pytest

from canvas_mcp.core.selfhost.runtime_secrets import (
    SECRETS_FILE,
    RuntimeSecretsError,
    initialize_secrets,
    with_saved_secrets,
)
from canvas_mcp.core.selfhost.settings import (
    SelfhostConfigError,
    load_selfhost_settings,
)
from canvas_mcp.core.selfhost.token_store import Keyring


def minimal(directory: Path) -> dict[str, str]:
    return {
        "MCP_AUTH_MODE": "selfhost",
        "PUBLIC_BASE_URL": "https://mcp.example.com",
        "ENTRA_TENANT_ID": "11111111-2222-3333-4444-555555555555",
        "ENTRA_CLIENT_ID": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee",
        "ENTRA_CLIENT_SECRET": "not-a-real-secret-0123456789",
        "SELFHOST_DATA_DIR": str(directory),
    }


def test_first_boot_and_recreation_use_the_same_distinct_keys(tmp_path):
    first = initialize_secrets(minimal(tmp_path))
    second = initialize_secrets(minimal(tmp_path))
    assert first == second
    key = first["CANVAS_TOKEN_KEYS"].removeprefix("k1:")
    assert len(base64.b64decode(key, validate=True)) == 32
    assert len(base64.b64decode(first["ACCOUNT_SESSION_SECRET"], validate=True)) == 32
    assert key != first["ACCOUNT_SESSION_SECRET"]
    Keyring.parse(first["CANVAS_TOKEN_KEYS"])
    sealed = Keyring.parse(first["CANVAS_TOKEN_KEYS"]).encrypt(
        b"private credential", b"test"
    )
    assert (
        Keyring.parse(second["CANVAS_TOKEN_KEYS"]).decrypt(*sealed, b"test")
        == b"private credential"
    )
    assert (
        load_selfhost_settings(minimal(tmp_path)).canvas_token_keys_raw
        == first["CANVAS_TOKEN_KEYS"]
    )
    assert with_saved_secrets(minimal(tmp_path)) == first
    if os.name == "posix":
        assert (tmp_path / SECRETS_FILE).stat().st_mode & 0o777 == 0o600


def test_concurrent_first_boots_choose_one_complete_key_pair(tmp_path):
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        values = list(
            pool.map(lambda _: initialize_secrets(minimal(tmp_path)), range(16))
        )
    assert all(value == values[0] for value in values)
    assert not list(tmp_path.glob(".runtime-secrets-*"))


def test_bad_infrastructure_configuration_writes_no_secret_file(tmp_path):
    env = minimal(tmp_path)
    env["PUBLIC_BASE_URL"] = "invalid"
    with pytest.raises(SelfhostConfigError):
        initialize_secrets(env)
    assert not (tmp_path / SECRETS_FILE).exists()


def test_file_in_place_of_data_directory_is_not_a_saved_secret_file(tmp_path):
    blocker = tmp_path / "not-a-directory"
    blocker.write_text("retained", encoding="utf-8")
    env = minimal(blocker)
    assert with_saved_secrets(env) == env
    with pytest.raises(RuntimeSecretsError, match="Cannot verify"):
        initialize_secrets(env)
    assert blocker.read_text(encoding="utf-8") == "retained"


def test_explicit_keys_are_preserved_and_blank_keys_are_not_replaced(tmp_path):
    secret = base64.b64encode(b"x" * 32).decode()
    env = {
        **minimal(tmp_path),
        "CANVAS_TOKEN_KEYS": "custom:" + secret,
        "ACCOUNT_SESSION_SECRET": secret,
    }
    assert initialize_secrets(env) == env
    assert not (tmp_path / SECRETS_FILE).exists()
    with pytest.raises(SelfhostConfigError):
        initialize_secrets({**env, "CANVAS_TOKEN_KEYS": ""})


@pytest.mark.parametrize("payload", ["not-json-secret", '{"version":1}', "[]"])
def test_damaged_file_is_refused_without_replacement_or_secret_output(
    tmp_path, payload
):
    path = tmp_path / SECRETS_FILE
    path.write_text(payload, encoding="utf-8")
    path.chmod(0o600)
    with pytest.raises(RuntimeSecretsError) as error:
        initialize_secrets(minimal(tmp_path))
    assert payload not in str(error.value)
    assert path.read_text(encoding="utf-8") == payload


def test_missing_keys_on_existing_sqlite_do_not_generate_a_new_identity(tmp_path):
    database = tmp_path / "canvas-mcp" / "tokens.sqlite3"
    database.parent.mkdir()
    database.write_bytes(b"existing database")
    with pytest.raises(RuntimeSecretsError, match="existing database"):
        initialize_secrets(minimal(tmp_path))
    assert database.read_bytes() == b"existing database"
    assert not (tmp_path / SECRETS_FILE).exists()


def test_inaccessible_sqlite_metadata_never_generates_keys(tmp_path, monkeypatch):
    database = tmp_path / "canvas-mcp" / "tokens.sqlite3"
    database.parent.mkdir()
    database.write_bytes(b"existing database")
    original_stat = os.stat
    original_exists = Path.exists

    def denied_stat(path, *args, **kwargs):
        if not isinstance(path, int) and Path(path) == database:
            raise PermissionError("private path must not be reported")
        return original_stat(path, *args, **kwargs)

    monkeypatch.setattr(os, "stat", denied_stat)
    # exists() treats an inaccessible path as absent; stat() must preserve the error.
    # Windows has a native exists implementation, so pin this portable contract.
    monkeypatch.setattr(
        Path,
        "exists",
        lambda path: False if path == database else original_exists(path),
    )
    with pytest.raises(RuntimeSecretsError, match="Cannot verify") as error:
        initialize_secrets(minimal(tmp_path))
    assert "private path" not in str(error.value)
    assert not (tmp_path / SECRETS_FILE).exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX directory permissions")
def test_real_inaccessible_sqlite_directory_preserves_the_original_database(tmp_path):
    if os.getuid() == 0:
        pytest.skip("root bypasses directory permission checks")
    directory = tmp_path / "canvas-mcp"
    directory.mkdir()
    database = directory / "tokens.sqlite3"
    database.write_bytes(b"existing database")
    directory.chmod(0o000)
    try:
        with pytest.raises(RuntimeSecretsError, match="Cannot verify"):
            initialize_secrets(minimal(tmp_path))
        assert not (tmp_path / SECRETS_FILE).exists()
    finally:
        directory.chmod(0o700)
    assert database.read_bytes() == b"existing database"


@pytest.mark.skipif(os.name != "posix", reason="POSIX FIFO database path")
def test_nonregular_database_path_never_generates_keys(tmp_path):
    database = tmp_path / "canvas-mcp" / "tokens.sqlite3"
    database.parent.mkdir()
    os.mkfifo(database, 0o600)
    with pytest.raises(RuntimeSecretsError, match="Cannot verify"):
        initialize_secrets(minimal(tmp_path))
    assert not (tmp_path / SECRETS_FILE).exists()


@pytest.mark.postgres
def test_postgres_first_boot_and_missing_keys_guard_use_real_metadata(tmp_path):
    import dbbackend
    from sqlalchemy import create_engine

    dbbackend.reset_public_schema()
    env = {**minimal(tmp_path), "DATABASE_URL": dbbackend.PG_URL}
    initialized = initialize_secrets(env)
    assert initialized["CANVAS_TOKEN_KEYS"]
    (tmp_path / SECRETS_FILE).unlink()
    engine = create_engine(dbbackend.PG_URL, hide_parameters=True)
    try:
        with engine.begin() as connection:
            connection.exec_driver_sql(
                "CREATE TABLE bootstrap_guard_probe (id integer)"
            )
        with pytest.raises(RuntimeSecretsError, match="existing database"):
            initialize_secrets(env)
        assert not (tmp_path / SECRETS_FILE).exists()
    finally:
        with engine.begin() as connection:
            connection.exec_driver_sql("DROP TABLE IF EXISTS bootstrap_guard_probe")
        engine.dispose()


def test_unreachable_database_never_writes_keys_or_prints_its_password(tmp_path):
    env = {
        **minimal(tmp_path),
        "DATABASE_URL": "postgresql+psycopg://test:super-private-secret@127.0.0.1:1/test?connect_timeout=1",
    }
    with pytest.raises(RuntimeSecretsError) as error:
        initialize_secrets(env)
    assert "super-private-secret" not in str(error.value)
    assert not (tmp_path / SECRETS_FILE).exists()


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode enforcement")
def test_fifo_secret_file_is_refused_without_blocking(tmp_path):
    os.mkfifo(tmp_path / SECRETS_FILE, 0o600)
    with pytest.raises(RuntimeSecretsError):
        with_saved_secrets(minimal(tmp_path))


@pytest.mark.skipif(os.name != "posix", reason="POSIX ownership and mode enforcement")
def test_symlink_and_world_readable_secret_files_are_refused(tmp_path):
    env = initialize_secrets(minimal(tmp_path))
    path = tmp_path / SECRETS_FILE
    path.chmod(0o644)
    with pytest.raises(RuntimeSecretsError):
        with_saved_secrets(minimal(tmp_path))
    path.chmod(0o600)
    moved = tmp_path / "original"
    path.rename(moved)
    path.symlink_to(moved)
    with pytest.raises(RuntimeSecretsError):
        with_saved_secrets(minimal(tmp_path))
    assert (
        json.loads(moved.read_text(encoding="utf-8"))["CANVAS_TOKEN_KEYS"]
        == env["CANVAS_TOKEN_KEYS"]
    )
