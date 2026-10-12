"""Private, persistent container defaults; never regenerate a database's keys."""

from __future__ import annotations

import base64
import json
import os
import secrets
import stat
import tempfile
from collections.abc import Mapping
from pathlib import Path

from .db.errors import TokenStoreError

SECRETS_FILE = "runtime-secrets.json"
SECRET_NAMES = ("CANVAS_TOKEN_KEYS", "ACCOUNT_SESSION_SECRET")
MAX_FILE_BYTES = 8192


class RuntimeSecretsError(TokenStoreError):
    """A fixed operator message that contains no keys, URLs or driver output."""


def _path(env: Mapping[str, str]) -> Path:
    return Path((env.get("SELFHOST_DATA_DIR") or "/data").strip()) / SECRETS_FILE


def _read(path: Path) -> dict[str, str] | None:
    try:
        fd = os.open(
            path,
            os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0),
        )
    except (FileNotFoundError, NotADirectoryError):
        return None
    except OSError:
        raise RuntimeSecretsError(
            "Cannot read the persistent runtime secrets file"
        ) from None
    try:
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_FILE_BYTES:
                raise ValueError
            if os.name == "posix" and (
                info.st_uid != os.getuid() or info.st_mode & 0o077
            ):
                raise ValueError
            payload = json.loads(stream.read(MAX_FILE_BYTES + 1))
        if (
            not isinstance(payload, dict)
            or set(payload) != {"version", *SECRET_NAMES}
            or payload["version"] != 1
            or any(
                not isinstance(payload[name], str) or not payload[name]
                for name in SECRET_NAMES
            )
        ):
            raise ValueError
        return {name: payload[name] for name in SECRET_NAMES}
    except (OSError, ValueError, TypeError):
        raise RuntimeSecretsError(
            "Persistent runtime secrets are damaged or not private; restore the original file"
        ) from None


def with_saved_secrets(env: Mapping[str, str]) -> dict[str, str]:
    """Read defaults for server and operator CLI, without writing or generating."""
    result = dict(env)
    if all(name in result for name in SECRET_NAMES):
        return result
    saved = _read(_path(result))
    if saved:
        for name, value in saved.items():
            result.setdefault(name, value)
    return result


def _refuse_existing_database(env: Mapping[str, str]) -> None:
    from .db.url import parse_database_url

    try:
        target = parse_database_url(
            env.get("DATABASE_URL", ""),
            _path(env).parent,
            allow_external_sqlite=env.get(
                "DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR", ""
            ).lower()
            in {"true", "1", "yes"},
        )
        if target.sqlite_path is not None:
            exists = (
                target.sqlite_path.exists() and target.sqlite_path.stat().st_size > 0
            )
        else:
            from sqlalchemy import inspect

            from .db.engine import Database

            database = Database(target)
            try:
                exists = bool(inspect(database.engine).get_table_names())
            finally:
                database.dispose()
    except Exception:
        raise RuntimeSecretsError(
            "Cannot verify that the database is empty; runtime secrets were not generated"
        ) from None
    if exists:
        raise RuntimeSecretsError(
            "Missing runtime secrets for an existing database; restore the original keys or runtime-secrets.json"
        )


def _publish(path: Path, values: Mapping[str, str]) -> dict[str, str]:
    """Publish a complete private pair without overwriting a concurrent winner."""
    temporary: str | None = None
    try:
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".runtime-secrets-", dir=path.parent)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(
                {"version": 1, **{name: values[name] for name in SECRET_NAMES}}, stream
            )
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, path)
        except FileExistsError:
            pass
        if os.name == "posix":
            directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        saved = _read(path)
        if saved is None:
            raise RuntimeSecretsError("Persistent runtime secrets could not be saved")
        return saved
    except OSError:
        raise RuntimeSecretsError(
            "Cannot save runtime secrets on the persistent data volume"
        ) from None
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def initialize_secrets(env: Mapping[str, str]) -> dict[str, str]:
    """Container first boot only: validate, guard existing state, and save once."""
    from .settings import load_selfhost_settings
    from .token_store import Keyring

    result = with_saved_secrets(env)
    missing = [name for name in SECRET_NAMES if name not in result]
    for name in missing:
        value = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        result[name] = ("k1:" if name == "CANVAS_TOKEN_KEYS" else "") + value
    load_selfhost_settings(result)
    Keyring.parse(result["CANVAS_TOKEN_KEYS"])
    if missing:
        _refuse_existing_database(result)
        saved = _publish(_path(result), result)
        for name in missing:
            result[name] = saved[name]
    return result
