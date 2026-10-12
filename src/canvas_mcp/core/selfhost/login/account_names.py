"""The sole account login name; identity claims remain provider metadata."""

from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError

from ..config_store import ConfigStore
from ..db import schema as s
from ..db.engine import Database
from ..db.repos import Repositories
from .account_policy import normalize_upn
from .provider_config import ProviderConfigurationError


class AccountNames:
    def __init__(self, database: Database) -> None:
        self.database = database
        self.repos = Repositories(database.kind)

    def read(self, account_id: str) -> dict:
        with self.database.read() as conn:
            row = self.repos.accounts.get(conn, account_id)
            if row is None:
                raise ValueError("unknown account")
            local = (
                conn.execute(
                    select(s.local_credentials.c.account_id).where(
                        s.local_credentials.c.account_id == account_id
                    )
                ).first()
                is not None
            )
            return {
                "upn": row.upn,
                "upn_required": row.upn_required,
                "has_local_password": local,
            }

    def save(
        self,
        value: object,
        *,
        account_id: str,
        expected_epoch: int | None = None,
        now: int,
        actor: str | None = None,
        revision: int | None = None,
    ) -> bool:
        upn = normalize_upn(value)
        try:
            with self.database.write() as conn:
                # None is an operator call; browser writes must carry an owner and CAS revision.
                if revision is not None:
                    ConfigStore._authorize(conn, actor, revision, now)
                elif actor is not None:
                    raise ValueError("revision required")
                self.repos.codes.delete_unconsumed_for_account(conn, account_id)
                row = self.repos.accounts.get(conn, account_id, for_update=True)
                if row is None:
                    raise ProviderConfigurationError("not_found")
                if expected_epoch is not None and row.session_epoch != expected_epoch:
                    raise ProviderConfigurationError("local_login_failed")
                if conn.execute(
                    select(s.accounts.c.id).where(
                        s.accounts.c.upn == upn, s.accounts.c.id != account_id
                    )
                ).first():
                    raise ProviderConfigurationError("local_username_taken")
                if row.upn == upn and not row.upn_required:
                    return False
                conn.execute(
                    update(s.accounts)
                    .where(s.accounts.c.id == account_id)
                    .values(upn=upn, upn_required=False, updated_at=now)
                )
                if not row.upn_required:
                    self.repos.accounts.end_sessions(conn, account_id, now)
                self.repos.grants.revoke_for_account(
                    conn,
                    account_id,
                    reason="admission_lost",
                    by=actor or "operator",
                    now=now,
                )
                ConfigStore._audit(
                    conn,
                    actor,
                    now,
                    "account_upn_changed",
                    "account",
                    account_id,
                    {"old": row.upn, "new": upn},
                )
                return not row.upn_required
        except IntegrityError:
            raise ProviderConfigurationError("local_username_taken") from None
