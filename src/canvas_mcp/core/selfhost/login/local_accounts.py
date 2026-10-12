"""Governed local accounts, salted scrypt credentials and shared account epochs."""

from __future__ import annotations

import hashlib
import hmac
import secrets
import threading

from sqlalchemy import Connection, insert, select, update

from .. import accounts as acc
from ..config_store import ConfigStore
from ..db import schema as s
from ..db.rows import AccountRow
from ..db.types import new_id
from .account_policy import method_allowed, normalize_upn
from .provider_config import ProviderConfigurationError
from .provider_store import ProviderConfigStore

LOCAL_ISSUER = "urn:canvas-mcp:local"
_HASH_LOCK = threading.BoundedSemaphore(2)
_DUMMY_SALT = b"canvas-local-dummy-salt"


def username(value: object) -> str:
    try:
        return normalize_upn(value)
    except ValueError:
        raise ProviderConfigurationError("invalid_local_credentials") from None


def _password(value: object) -> str:
    if not isinstance(value, str) or not 15 <= len(value) <= 128:
        raise ProviderConfigurationError("invalid_local_credentials")
    try:
        value.encode("utf-8")
    except UnicodeEncodeError:
        raise ProviderConfigurationError("invalid_local_credentials") from None
    return value


def _derive(password: str, salt: bytes) -> bytes:
    # OWASP scrypt minimum: N=2**17, r=8, p=1. Bound simultaneous memory use.
    with _HASH_LOCK:
        return hashlib.scrypt(
            password.encode("utf-8"),
            salt=salt,
            n=2**17,
            r=8,
            p=1,
            maxmem=256 * 1024 * 1024,
            dklen=32,
        )


def password_hash(value: object) -> str:
    password = _password(value)
    salt = secrets.token_bytes(16)
    return "scrypt$131072$8$1$" + salt.hex() + "$" + _derive(password, salt).hex()


def verify_password(value: object, saved: str | None) -> bool:
    if not isinstance(value, str) or len(value) > 128:
        return False
    try:
        parts = saved.split("$") if saved else []
        if len(parts) != 6 or parts[:4] != ["scrypt", "131072", "8", "1"]:
            _derive(value, _DUMMY_SALT)
            return False
        salt, expected = bytes.fromhex(parts[4]), bytes.fromhex(parts[5])
        if len(salt) != 16 or len(expected) != 32:
            _derive(value, _DUMMY_SALT)
            return False
        return hmac.compare_digest(_derive(value, salt), expected)
    except (ValueError, TypeError):
        return False


class LocalAccounts:
    def __init__(self, providers: ProviderConfigStore) -> None:
        self.providers = providers
        self.database = providers.database
        self.repos = providers.repos

    def _insert(
        self,
        conn: Connection,
        name: str,
        hashed: str,
        *,
        owner: bool,
        actor: str | None,
        now: int,
    ) -> str:
        if conn.execute(
            select(s.accounts.c.id).where(s.accounts.c.upn == name)
        ).first():
            raise ProviderConfigurationError("local_username_taken")
        account_id = new_id()
        self.repos.accounts.insert(
            conn,
            account_id=account_id,
            status="active",
            role="owner" if owner else "user",
            role_source="bootstrap" if owner else None,
            admitted_via="bootstrap" if owner else "operator",
            display_name=name,
            upn=name,
            now=now,
            approved_by=actor,
        )
        self.repos.identities.insert(
            conn,
            account_id=account_id,
            provider_id="local",
            issuer=LOCAL_ISSUER,
            subject=account_id,
            username="",
            email=None,
            email_verified=False,
            now=now,
        )
        conn.execute(
            insert(s.local_credentials).values(
                account_id=account_id,
                password_hash=hashed,
                created_at=now,
                updated_at=now,
            )
        )
        ConfigStore._audit(
            conn,
            actor,
            now,
            "local_account_created",
            "account",
            account_id,
            {"owner": owner},
        )
        return account_id

    def initialize(
        self,
        *,
        name: object,
        password: object,
        revision: int,
        now: int,
        provider: dict | None = None,
    ) -> int:
        name, hashed = username(name), password_hash(password)
        with self.database.write() as conn:
            if not self.providers.setup_available_in(conn):
                raise ProviderConfigurationError("installation_already_initialized")
            revision = self.providers.save(
                "local",
                config={},
                client_secret=None,
                enabled=True,
                rank=0,
                revision=revision,
                actor=None,
                now=now,
                _initial=True,
                _connection=conn,
            )
            self._insert(conn, name, hashed, owner=True, actor=None, now=now)
            if provider is not None:
                revision = self.providers.save(
                    provider["id"],
                    config=provider["config"],
                    client_secret=provider["client_secret"],
                    enabled=True,
                    rank=1,
                    revision=revision,
                    actor=None,
                    now=now,
                    _connection=conn,
                )
            self.providers.validate_in(conn)
        return revision

    def create(
        self, *, name: object, password: object, actor: str, revision: int, now: int
    ) -> tuple[str, int]:
        name, hashed = username(name), password_hash(password)
        with self.database.write() as conn:
            revision = ConfigStore._authorize(conn, actor, revision, now)
            if not self._enabled(conn):
                raise ProviderConfigurationError("local_login_failed")
            return self._insert(
                conn, name, hashed, owner=False, actor=actor, now=now
            ), revision

    @staticmethod
    def _enabled(conn: Connection) -> bool:
        return bool(
            conn.execute(
                select(s.login_providers.c.configured).where(
                    s.login_providers.c.id == "local"
                )
            ).scalar_one_or_none()
        )

    def authenticate(self, name: object, password: object, *, now: int) -> AccountRow:
        try:
            name = username(name)
        except ProviderConfigurationError:
            name = "!invalid"
        with self.database.read() as conn:
            credential = (
                conn.execute(
                    select(s.local_credentials)
                    .join(s.accounts)
                    .where(s.accounts.c.upn == name)
                )
                .mappings()
                .one_or_none()
            )
        hashed = credential["password_hash"] if credential else None
        if not verify_password(password, hashed) or credential is None:
            raise ProviderConfigurationError("local_login_failed")
        with self.database.write() as conn:
            account = self.repos.accounts.get(conn, credential["account_id"])
            current = conn.execute(
                select(s.local_credentials.c.password_hash).where(
                    s.local_credentials.c.account_id == credential["account_id"]
                )
            ).scalar_one_or_none()
            identity = self.repos.identities.lookup(
                conn, "local", LOCAL_ISSUER, credential["account_id"]
            )
            if (
                not self._enabled(conn)
                or account is None
                or account.status != "active"
                or account.upn != name
                or not method_allowed(conn, account.id, "local")
                or current != hashed
                or identity != account.id
            ):
                raise ProviderConfigurationError("local_login_failed")
            self.repos.accounts.touch_login(
                conn, account.id, display_name=name, now=now
            )
            self.repos.identities.touch(
                conn, "local", LOCAL_ISSUER, account.id, username="", now=now
            )
            self.repos.auth_events.append(
                conn,
                now=now,
                account_id=account.id,
                provider_id="local",
                surface=acc.SURFACE_ACCOUNT,
                outcome=acc.OUTCOME_SUCCESS,
                reason=acc.REASON_OK,
                ua_hash=None,
            )
            return account

    def change_password(
        self,
        account_id: str,
        current_password: object,
        new_password: object,
        *,
        now: int,
    ) -> None:
        with self.database.read() as conn:
            saved = conn.execute(
                select(s.local_credentials.c.password_hash).where(
                    s.local_credentials.c.account_id == account_id
                )
            ).scalar_one_or_none()
        if not verify_password(current_password, saved):
            raise ProviderConfigurationError("local_login_failed")
        hashed = password_hash(new_password)
        with self.database.write() as conn:
            self.repos.codes.delete_unconsumed_for_account(conn, account_id)
            account = self.repos.accounts.get(conn, account_id, for_update=True)
            if not self._enabled(conn) or account is None or account.status != "active":
                raise ProviderConfigurationError("local_login_failed")
            changed = conn.execute(
                update(s.local_credentials)
                .where(
                    s.local_credentials.c.account_id == account_id,
                    s.local_credentials.c.password_hash == saved,
                )
                .values(password_hash=hashed, updated_at=now)
            )
            if changed.rowcount != 1:
                raise ProviderConfigurationError("local_login_failed")
            self.repos.accounts.end_sessions(conn, account_id, now)
            self.repos.grants.revoke_for_account(
                conn, account_id, reason="admission_lost", by="system", now=now
            )
            ConfigStore._audit(
                conn,
                account_id,
                now,
                "local_password_changed",
                "account",
                account_id,
                {},
            )

    def add_password(
        self, account_id: str, password: object, *, expected_epoch: int, now: int
    ) -> None:
        hashed = password_hash(password)
        with self.database.write() as conn:
            self.repos.codes.delete_unconsumed_for_account(conn, account_id)
            account = self.repos.accounts.get(conn, account_id, for_update=True)
            if (
                not self._enabled(conn)
                or account is None
                or account.status != "active"
                or account.session_epoch != expected_epoch
                or not account.upn
                or account.upn_required
                or not method_allowed(conn, account_id, "local", linking=True)
            ):
                raise ProviderConfigurationError("local_login_failed")
            if conn.execute(
                select(s.local_credentials.c.account_id).where(
                    s.local_credentials.c.account_id == account_id
                )
            ).first():
                raise ProviderConfigurationError("invalid_local_credentials")
            self.repos.identities.insert(
                conn,
                account_id=account_id,
                provider_id="local",
                issuer=LOCAL_ISSUER,
                subject=account_id,
                username="",
                email=None,
                email_verified=False,
                now=now,
            )
            conn.execute(
                insert(s.local_credentials).values(
                    account_id=account_id,
                    password_hash=hashed,
                    created_at=now,
                    updated_at=now,
                )
            )
            self.repos.accounts.end_sessions(conn, account_id, now)
            self.repos.grants.revoke_for_account(
                conn, account_id, reason="admission_lost", by=account_id, now=now
            )
            ConfigStore._audit(
                conn, account_id, now, "local_password_added", "account", account_id, {}
            )
