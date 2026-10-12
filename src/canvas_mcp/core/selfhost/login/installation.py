"""Private, expiring first-install authority; never reopened by provider disablement."""

from __future__ import annotations

import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from sqlalchemy import select

from ..db import schema as s
from .provider_config import ProviderConfigurationError
from .provider_store import ProviderConfigStore

CODE_FILE = "installation-code.json"
CODE_TTL_S = 1800
MAX_CODE_FILE_BYTES = 2048
_CODE = re.compile(r"[A-Za-z0-9_-]{43}")


class InstallationAuthority:
    def __init__(
        self,
        providers: ProviderConfigStore,
        data_dir: Path,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.providers = providers
        self.path = data_dir / CODE_FILE
        self.clock = clock

    def _read(self) -> dict[str, Any] | None:
        try:
            info = self.path.lstat()
            if not stat.S_ISREG(info.st_mode):
                raise ValueError
            fd = os.open(
                self.path,
                os.O_RDONLY
                | getattr(os, "O_NOFOLLOW", 0)
                | getattr(os, "O_NONBLOCK", 0),
            )
            with os.fdopen(fd, "rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CODE_FILE_BYTES:
                    raise ValueError
                if os.name == "posix" and (
                    info.st_uid != getattr(os, "getuid", lambda: -1)()
                    or info.st_mode & 0o077
                ):
                    raise ValueError
                value = json.loads(stream.read(MAX_CODE_FILE_BYTES + 1))
            if (
                not isinstance(value, dict)
                or set(value) != {"database_id", "code", "expires_at"}
                or not isinstance(value["database_id"], str)
                or not isinstance(value["code"], str)
                or _CODE.fullmatch(value["code"]) is None
                or type(value["expires_at"]) is not int
            ):
                raise ValueError
            return value
        except FileNotFoundError:
            return None
        except (OSError, ValueError, TypeError):
            raise ProviderConfigurationError(
                "installation_authority_unavailable"
            ) from None

    def _write(self, value: dict[str, Any]) -> None:
        temporary = None
        try:
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            fd, temporary = tempfile.mkstemp(
                prefix=".installation-", dir=self.path.parent
            )
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(value, stream)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.path)
            if os.name == "posix":
                directory = os.open(
                    self.path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
                )
                try:
                    os.fsync(directory)
                finally:
                    os.close(directory)
        except OSError:
            raise ProviderConfigurationError(
                "installation_authority_unavailable"
            ) from None
        finally:
            if temporary is not None:
                Path(temporary).unlink(missing_ok=True)

    def issue(self) -> str | None:
        """Operator-only: issue/reuse a code while the DB is still uninitialized."""
        # Serialize file publication with initialization and other issue calls.
        with self.providers.database.write() as conn:
            if not self.providers.setup_available_in(conn):
                return None
            database_id = str(
                conn.execute(select(s.server_state.c.database_id)).scalar_one()
            )
            saved = self._read()
            now = int(self.clock())
            if (
                saved is not None
                and saved["database_id"] == database_id
                and saved["expires_at"] > now
            ):
                return str(saved["code"])
            value = {
                "database_id": database_id,
                "code": secrets.token_urlsafe(32),
                "expires_at": now + CODE_TTL_S,
            }
            self._write(value)
            return str(value["code"])

    def verify(self, code: object) -> bool:
        """No public operation generates or reveals the private authority."""
        if not isinstance(code, str) or _CODE.fullmatch(code) is None:
            return False
        with self.providers.database.read() as conn:
            if not self.providers.setup_available_in(conn):
                return False
            database_id = str(
                conn.execute(select(s.server_state.c.database_id)).scalar_one()
            )
        saved = self._read()
        return bool(
            saved is not None
            and saved["database_id"] == database_id
            and saved["expires_at"] > int(self.clock())
            and hmac.compare_digest(code, saved["code"])
        )
