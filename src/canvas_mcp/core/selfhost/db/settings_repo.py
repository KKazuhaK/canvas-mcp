"""Typed setting saves under the caller's governance transaction.

The account standing check, global revision CAS, setting row and audit entry
share one transaction. The operator path uses a null actor UUID.
"""

from __future__ import annotations

import logging
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

from sqlalchemy import bindparam, text
from sqlalchemy.engine import Connection

from ..server_settings import SETTINGS, validate_setting
from .types import JsonDoc, Uuid

logger = logging.getLogger("canvas_mcp.selfhost.account")


class SettingsConflict(Exception):
    """The client edited an older global configuration revision."""


class SettingsAccessDenied(Exception):
    """The acting account is no longer an active owner."""


@dataclass(frozen=True)
class TypedSettings:
    values: Mapping[str, bool | int]

    def __getitem__(self, key: str) -> bool | int:
        return self.values[key]


_READ = text("SELECT key, value FROM settings").columns(value=JsonDoc())
_ACTOR = text("SELECT status, role FROM accounts WHERE id=:actor").bindparams(
    bindparam("actor", type_=Uuid())
)
_CAS = text("""
UPDATE server_state SET settings_revision=settings_revision+1, updated_at=:now
WHERE id=1 AND settings_revision=:revision RETURNING settings_revision
""")
_SAVE = text("""
INSERT INTO settings (key,value,updated_at,updated_by) VALUES (:key,:value,:now,:actor)
ON CONFLICT (key) DO UPDATE SET value=excluded.value,
updated_at=excluded.updated_at, updated_by=excluded.updated_by
""").bindparams(bindparam("value", type_=JsonDoc()), bindparam("actor", type_=Uuid()))
_AUDIT = text("""
INSERT INTO audit_log (at,actor_kind,actor_id,action,target_kind,target_id,detail)
VALUES (:now,:actor_kind,:actor,'setting_changed','setting',:key,:detail)
""").bindparams(bindparam("actor", type_=Uuid()), bindparam("detail", type_=JsonDoc()))


def read_settings(conn: Connection) -> TypedSettings:
    values = {key: spec.default for key, spec in SETTINGS.items()}
    for row in conn.execute(_READ).mappings():
        if row["key"] not in SETTINGS:
            # Do not log stored keys or values from a newer deployment.
            logger.warning("Ignoring an unknown server setting")
            continue
        values[row["key"]] = validate_setting(row["key"], row["value"])
    return TypedSettings(MappingProxyType(values))


def save_setting(
    conn: Connection,
    key: str,
    value: object,
    *,
    expected_revision: int,
    now: int,
    actor_id: str | None,
    reset: bool = False,
) -> int:
    """Save or reset one value; the caller commits only after successful return."""
    spec = SETTINGS.get(key)
    if spec is None:
        raise ValueError("unknown setting")
    new = (
        spec.default
        if reset
        else validate_setting(key, value, panel=actor_id is not None)
    )
    if type(expected_revision) is not int or expected_revision < 0:
        raise ValueError("invalid settings revision")
    if actor_id is not None:
        actor = conn.execute(_ACTOR, {"actor": actor_id}).mappings().one_or_none()
        if actor is None or actor["status"] != "active" or actor["role"] != "owner":
            raise SettingsAccessDenied
        if not spec.editable_in_panel:
            raise ValueError("setting is operator-only")
    old = read_settings(conn)[key]
    revision = conn.execute(
        _CAS, {"revision": expected_revision, "now": now}
    ).scalar_one_or_none()
    if revision is None:
        raise SettingsConflict
    if reset:
        conn.execute(text("DELETE FROM settings WHERE key=:key"), {"key": key})
    else:
        conn.execute(_SAVE, {"key": key, "value": new, "now": now, "actor": actor_id})
    conn.execute(
        _AUDIT,
        {
            "key": key,
            "now": now,
            "actor": actor_id,
            "actor_kind": "operator" if actor_id is None else "account",
            "detail": {} if spec.sensitive else {"old": old, "new": new},
        },
    )
    return int(revision)
