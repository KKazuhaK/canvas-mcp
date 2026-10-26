"""Audited account login policy edits under the governance transaction."""

from typing import Any

from sqlalchemy import delete, select

from ..config_store import ConfigStore
from ..db import schema as s
from ..db.engine import Database
from ..db.repos import Repositories, _upsert_insert
from .account_policy import POLICY_KEY, account_policy_in, parse_policy, policy_in
from .provider_config import ProviderConfigurationError


class AccountPolicyStore:
    def __init__(self, database: Database) -> None:
        self.database = database
        self.repos = Repositories(database.kind)

    def read(self, account_id: str | None = None) -> dict[str, Any]:
        with self.database.read() as conn:
            revision: int = conn.execute(
                select(s.server_state.c.settings_revision)
            ).scalar_one()
            return {
                "revision": revision,
                "policy": policy_in(conn).public()
                if account_id is None
                else account_policy_in(conn, account_id),
            }

    def save(
        self,
        values: dict[str, Any],
        *,
        account_id: str | None = None,
        unlock: bool = False,
        revision: int,
        actor: str,
        now: int,
    ) -> int:
        if account_id is None:
            parsed = parse_policy(values)
        else:
            if unlock:
                if values != {}:
                    raise ValueError("invalid unlock")
            elif not isinstance(values, dict) or set(values) != {
                "allow_multiple",
                "allowed_providers",
            }:
                raise ValueError("invalid account login policy")
            elif (
                values["allow_multiple"] is not None
                and type(values["allow_multiple"]) is not bool
            ):
                raise ValueError("invalid account login policy")
            elif values["allowed_providers"] is not None and (
                not isinstance(values["allowed_providers"], list)
                or any(
                    not isinstance(item, str) for item in values["allowed_providers"]
                )
                or len(set(values["allowed_providers"]))
                != len(values["allowed_providers"])
            ):
                raise ValueError("invalid account login policy")
        with self.database.write() as conn:
            new_revision = ConfigStore._authorize(conn, actor, revision, now)
            active: list[str] = list(
                conn.execute(
                    select(s.login_providers.c.id).where(s.login_providers.c.configured)
                ).scalars()
            )
            owners_before = self.repos.accounts.count_usable_owners(conn, active)
            local_owners_before = self.repos.accounts.local_owner_ids(conn, active)
            affected = (
                list(
                    conn.execute(
                        select(s.accounts.c.id).order_by(s.accounts.c.id)
                    ).scalars()
                )
                if account_id is None
                else [account_id]
            )
            # Match code exchange's codes -> accounts -> grants lock ordering.
            for identifier in affected:
                self.repos.codes.delete_unconsumed_for_account(conn, identifier)
            for identifier in affected:
                if self.repos.accounts.get(conn, identifier, for_update=True) is None:
                    raise ValueError("unknown account")
            before = (
                policy_in(conn).public()
                if account_id is None
                else account_policy_in(conn, account_id)
            )
            if account_id is None:
                conn.execute(
                    _upsert_insert(self.database.kind, s.settings)
                    .values(
                        key=POLICY_KEY,
                        value=parsed.public(),
                        updated_at=now,
                        updated_by=actor,
                    )
                    .on_conflict_do_update(
                        index_elements=[s.settings.c.key],
                        set_={
                            "value": parsed.public(),
                            "updated_at": now,
                            "updated_by": actor,
                        },
                    )
                )
                action = "login_policy_changed"
            else:
                table = s.account_login_policy
                changes = (
                    {
                        "allow_multiple": True,
                        "sso_lock_provider": None,
                        "sso_lock_exempt": True,
                    }
                    if unlock
                    else {
                        "allow_multiple": values["allow_multiple"],
                        "restrict_providers": values["allowed_providers"] is not None,
                    }
                )
                conn.execute(
                    _upsert_insert(self.database.kind, table)
                    .values(account_id=account_id, **changes)
                    .on_conflict_do_update(
                        index_elements=[table.c.account_id], set_=changes
                    )
                )
                if not unlock:
                    allowed = values["allowed_providers"]
                    known: set[str] = set(conn.execute(select(s.login_providers.c.id)).scalars())
                    if allowed is not None and not set(allowed).issubset(known):
                        raise ValueError("unknown provider")
                    conn.execute(
                        delete(s.account_allowed_login_providers).where(
                            s.account_allowed_login_providers.c.account_id == account_id
                        )
                    )
                    for provider in allowed or []:
                        conn.execute(
                            s.account_allowed_login_providers.insert().values(
                                account_id=account_id, provider_id=provider
                            )
                        )
                action = (
                    "account_sso_unlocked" if unlock else "account_login_policy_changed"
                )
            if local_owners_before and not self.repos.accounts.local_owner_ids(
                conn, active
            ):
                raise ProviderConfigurationError("last_local_owner")
            if owners_before and not self.repos.accounts.count_usable_owners(
                conn, active
            ):
                raise ProviderConfigurationError("last_owner")
            for identifier in affected:
                self.repos.accounts.end_sessions(conn, identifier, now)
                self.repos.grants.revoke_for_account(
                    conn, identifier, reason="admission_lost", by=actor, now=now
                )
            conn.execute(delete(s.login_states))
            after = (
                policy_in(conn).public()
                if account_id is None
                else account_policy_in(conn, account_id)
            )
            ConfigStore._audit(
                conn,
                actor,
                now,
                action,
                "account" if account_id else "setting",
                account_id or POLICY_KEY,
                {
                    **{f"old_{key}": value for key, value in before.items()},
                    **{f"new_{key}": value for key, value in after.items()},
                },
            )
            return new_revision
