"""Canonical login names and governed account/method association policy."""

from __future__ import annotations

import re
from dataclasses import dataclass

from sqlalchemy import Connection, false, func, or_, select

from ..accounts import ExternalClaims
from ..db import schema as s

POLICY_KEY = "login.account_policy"
_UPN = re.compile(r"[a-z0-9][a-z0-9.@_+-]{2,253}")


def normalize_upn(value: object) -> str:
    if not isinstance(value, str) or not _UPN.fullmatch(value.strip().lower()):
        raise ValueError("invalid account UPN")
    result = value.strip().lower()
    if result.count("@") > 1 or result.endswith("@"):
        raise ValueError("invalid account UPN")
    return result


def email_name(value: object) -> str | None:
    try:
        name = normalize_upn(value)
    except ValueError:
        return None
    return name if name.count("@") == 1 and not name.startswith("@") else None


@dataclass(frozen=True)
class LoginPolicy:
    allow_multiple: bool = True
    lock_first_sso: bool = False
    block_conflicting_registration: bool = False

    def public(self) -> dict[str, bool]:
        return {
            "allow_multiple": self.allow_multiple,
            "lock_first_sso": self.lock_first_sso,
            "block_conflicting_registration": self.block_conflicting_registration,
        }


def parse_policy(value: object) -> LoginPolicy:
    fields = {"allow_multiple", "lock_first_sso", "block_conflicting_registration"}
    if (
        not isinstance(value, dict)
        or set(value) != fields
        or any(type(item) is not bool for item in value.values())
    ):
        raise ValueError("invalid login policy")
    return LoginPolicy(**value)


def policy_in(conn: Connection) -> LoginPolicy:
    row = conn.execute(
        select(s.settings.c.value).where(s.settings.c.key == POLICY_KEY)
    ).first()
    return parse_policy(row[0]) if row is not None else LoginPolicy()


def account_policy_in(conn: Connection, account_id: str) -> dict:
    row = (
        conn.execute(
            select(s.account_login_policy).where(
                s.account_login_policy.c.account_id == account_id
            )
        )
        .mappings()
        .one_or_none()
    )
    allowed: list[str] = list(
        conn.execute(
            select(s.account_allowed_login_providers.c.provider_id)
            .where(s.account_allowed_login_providers.c.account_id == account_id)
            .order_by(s.account_allowed_login_providers.c.provider_id)
        ).scalars()
    )
    return {
        "allow_multiple": None if row is None else row["allow_multiple"],
        "sso_lock_provider": None if row is None else row["sso_lock_provider"],
        "sso_lock_exempt": False if row is None else row["sso_lock_exempt"],
        "allowed_providers": allowed
        if row is not None and row["restrict_providers"]
        else None,
    }


def method_allowed(
    conn: Connection, account_id: str, provider_id: str, *, linking: bool = False
) -> bool:
    policy = policy_in(conn)
    account = account_policy_in(conn, account_id)
    allowed = account["allowed_providers"]
    if allowed is not None and provider_id not in allowed:
        return False
    locked = account["sso_lock_provider"]
    if provider_id != "local" and locked is not None and provider_id != locked:
        return False
    multiple = (
        policy.allow_multiple
        if account["allow_multiple"] is None
        else account["allow_multiple"]
    )
    if linking and not multiple:
        existing: list[str] = list(
            conn.execute(
                select(s.external_identities.c.provider_id).where(
                    s.external_identities.c.account_id == account_id
                )
            ).scalars()
        )
        if any(item != provider_id for item in existing):
            return False
    return True


def association_name(conn: Connection, ext: ExternalClaims) -> str | None:
    """Opt-in provider trust; no second mailbox challenge or pair matrix."""
    enabled: bool | None = conn.execute(
        select(s.login_providers.c.auto_link_email).where(
            s.login_providers.c.id == ext.provider_id, s.login_providers.c.configured
        )
    ).scalar_one_or_none()
    if not enabled or ext.provider_id == "local":
        return None
    return email_name(ext.email) or (
        email_name(ext.username) if ext.provider_id == "entra" else None
    )


def matching_accounts(conn: Connection, name: str) -> list[str]:
    """Match UPN or provider mail-style claims; never choose among duplicates."""
    claim_match = select(s.external_identities.c.account_id).where(
        or_(
            func.lower(s.external_identities.c.email) == name,
            (func.lower(s.external_identities.c.username) == name)
            if email_name(name) is not None
            else false(),
        )
    )
    return list(
        conn.execute(
            select(s.accounts.c.id)
            .where(or_(s.accounts.c.upn == name, s.accounts.c.id.in_(claim_match)))
            .order_by(s.accounts.c.id)
        ).scalars()
    )


def identity_owner(conn: Connection, ext: ExternalClaims) -> str | None:
    return conn.execute(
        select(s.external_identity_owners.c.account_id).where(
            s.external_identity_owners.c.issuer == ext.issuer,
            s.external_identity_owners.c.subject == ext.subject,
        )
    ).scalar_one_or_none()


def needs_sso_lock(conn: Connection, account_id: str | None, provider_id: str) -> bool:
    if provider_id == "local" or not policy_in(conn).lock_first_sso:
        return False
    current = account_policy_in(conn, account_id) if account_id else {}
    return (
        not current.get("sso_lock_exempt") and current.get("sso_lock_provider") is None
    )


def apply_sso_lock(conn: Connection, account_id: str, provider_id: str) -> None:
    from typing import cast

    from ..db.repos import Dialect, _upsert_insert

    table = s.account_login_policy
    conn.execute(
        _upsert_insert(cast(Dialect, conn.dialect.name), table)
        .values(account_id=account_id, sso_lock_provider=provider_id)
        .on_conflict_do_update(
            index_elements=[table.c.account_id], set_={"sso_lock_provider": provider_id}
        )
    )
