"""Build the schema 4 fixture with the code of release d40a2e1 (the last schema 4 server).

Run ONCE against a checkout of that commit; the output is committed as
``schema4_d40a2e1.json`` and is what the migration tests load. It must not be
re-run against a later checkout: it drives the TokenStore API of that release
(``tenant_id`` / ``object_id`` arguments, ``principal_status``), which the account
model removed.

    git checkout d40a2e1
    PYTHONPATH=src python tests/selfhost/fixtures/make_schema4_fixture.py OUT.json

The ring is mixed on purpose (``k2`` is the active key, ``k1`` the old one) and the
file holds every kind of row a real deployment can have: legacy rows without a
school (v1 layout), rows with a school (v2 layout) under both keys, rows that are
invalid for each reason (one with a genuinely corrupted ciphertext), disabled
principals with and without a token row (disabled by an owner and by the operator),
two owners, write-tool preferences, a credential generation whose token was
deleted, a full status history and one opaque, non-Entra principal key.
"""

from __future__ import annotations

import base64
import itertools
import json
import pathlib
import sqlite3
import sys
import tempfile

from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_ADMIN,
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    Keyring,
    TokenStore,
)

TID = "11111111-2222-3333-4444-555555555555"
HOST = "canvas.example.edu"
OIDS = {
    "legacy": "aaaaaaaa-0000-4000-8000-00000000000a",  # v1 layout, key k1
    "school_k1": "bbbbbbbb-0000-4000-8000-00000000000b",  # v2 layout, key k1
    "school_k2": "cccccccc-0000-4000-8000-00000000000c",  # v2 layout, key k2, expiry hint
    "rejected": "dddddddd-0000-4000-8000-00000000000d",  # invalid: canvas_token_rejected
    "revoked": "eeeeeeee-0000-4000-8000-00000000000e",  # invalid: revoked_by_admin
    "corrupt": "ffffffff-0000-4000-8000-00000000000f",  # invalid: decrypt_failed, bad bytes
    "owner_one": "01010101-0000-4000-8000-000000000001",  # owner with a token
    "owner_two": "02020202-0000-4000-8000-000000000002",  # owner without a token
    "disabled_row": "03030303-0000-4000-8000-000000000003",  # disabled by owner_one, has a token
    "disabled_bare": "04040404-0000-4000-8000-000000000004",  # disabled by the operator, no token
    "deleted": "05050505-0000-4000-8000-000000000005",  # token removed: generation only
    "legacy_k2": "06060606-0000-4000-8000-000000000006",  # v1 layout, sealed under k2
}
OTHER_KEY = "google:111"
OTHER_TOKEN = "9~" + "OTHERKEY" * 7


def _ring(*pairs: tuple[str, int]) -> Keyring:
    return Keyring.parse(
        ",".join(f"{kid}:{base64.b64encode(bytes([n]) * 32).decode()}" for kid, n in pairs)
    )


def _key(name: str) -> str:
    return f"entra:{TID}:{OIDS[name]}"


def _encode(value: object) -> object:
    if isinstance(value, bytes):
        return {"b64": base64.b64encode(value).decode()}
    return value


def build(path: pathlib.Path) -> dict[str, object]:
    ticks = itertools.count(1_700_000_000, 10)

    def clock() -> float:
        return float(next(ticks))

    tokens: dict[str, str] = {}

    def put(store: TokenStore, name: str, *, host: str | None = HOST, **extra: object) -> None:
        value = f"{len(tokens) + 1}~" + name.upper().replace("_", "")[:8].ljust(8, "X") * 7
        tokens[_key(name)] = value
        store.put(
            tenant_id=TID,
            object_id=OIDS[name],
            api_token=value,
            canvas_user_id=str(100 + len(tokens)),
            canvas_user_name=f"Canvas {name}",
            entra_display_name=f"Entra {name}",
            entra_upn=f"{name}@example.test",
            canvas_host=host,
            **extra,  # type: ignore[arg-type]
        )

    old_only = _ring(("k1", 1))
    mixed = _ring(("k2", 2), ("k1", 1))

    # Rows sealed under the old key.
    first = TokenStore(path, old_only, clock=clock)
    first.initialize()
    put(first, "legacy", host=None)
    put(first, "school_k1")
    put(first, "rejected")
    put(first, "revoked")
    put(first, "corrupt")
    put(first, "owner_one")

    # Rows sealed under the new key; the old key stays in the ring.
    store = TokenStore(path, mixed, clock=clock)
    store.initialize()
    put(store, "school_k2", expires_hint_at=4_000_000_000)
    put(store, "legacy_k2", host=None)
    put(store, "disabled_row")
    put(store, "deleted")
    store.put(
        principal_key=OTHER_KEY,
        api_token=OTHER_TOKEN,
        canvas_user_id="999",
        canvas_user_name="Opaque",
        entra_display_name="",
        entra_upn="",
        canvas_host=HOST,
    )
    tokens[OTHER_KEY] = OTHER_TOKEN

    # Health: each reason an invalid row can carry.
    store.mark_invalid(_key("rejected"), reason="canvas_token_rejected")
    store.mark_invalid(_key("revoked"), reason="revoked_by_admin")
    raw = sqlite3.connect(str(path))
    raw.execute(
        "UPDATE canvas_tokens SET ciphertext = x'00112233445566778899aabbccddeeff00'"
        " WHERE principal_key = ?",
        (_key("corrupt"),),
    )
    raw.commit()
    raw.close()
    store.mark_invalid(_key("corrupt"), reason="decrypt_failed")
    tokens.pop(_key("corrupt"))  # the plaintext is gone for good

    # Two owners.
    store.record_sign_in(_key("owner_one"), is_owner=True)
    store.record_sign_in(_key("owner_two"), is_owner=True)

    # Access decisions: an owner disables, enables and disables again; the operator
    # disables a principal that never enrolled.
    store.disable_principal(
        _key("disabled_row"), actor=_key("owner_one"), reason=DISABLE_REASON_ADMIN
    )
    store.enable_principal(_key("disabled_row"), actor=_key("owner_one"))
    store.disable_principal(
        _key("disabled_row"), actor=_key("owner_one"), reason=DISABLE_REASON_ADMIN
    )
    store.disable_principal(_key("disabled_bare"), actor=OPERATOR, reason=DISABLE_REASON_OPERATOR)
    # Delete a token: the credential generation outlives the row.
    store.delete(_key("deleted"))
    tokens.pop(_key("deleted"))
    # An owner loses the role on a later sign-in (history entry, flag cleared).
    store.record_sign_in(_key("owner_two"), is_owner=False)
    store.record_sign_in(_key("owner_two"), is_owner=True)

    store.set_tool_prefs(_key("owner_one"), ["send_message", "create_announcement"])

    dump: dict[str, object] = {}
    conn = sqlite3.connect(str(path))
    try:
        for name in (
            "meta",
            "canvas_tokens",
            "user_tool_prefs",
            "principal_status",
            "principal_status_events",
            "credential_generations",
        ):
            cursor = conn.execute(f"SELECT * FROM {name} ORDER BY 1, 2")
            columns = [d[0] for d in cursor.description]
            dump[name] = {
                "columns": columns,
                "rows": [[_encode(v) for v in row] for row in cursor.fetchall()],
            }
    finally:
        conn.close()
    return {
        "generated_with": "d40a2e1",
        "keys": {"k1": 1, "k2": 2},
        "active_key": "k2",
        "tenant_id": TID,
        "host": HOST,
        "principals": {name: _key(name) for name in OIDS},
        "other_key": OTHER_KEY,
        "plaintexts": tokens,
        "tables": dump,
    }


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: make_schema4_fixture.py OUT.json", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory() as tmp:
        result = build(pathlib.Path(tmp) / "tokens.sqlite3")
    pathlib.Path(sys.argv[1]).write_text(
        json.dumps(result, indent=1, sort_keys=True) + "\n", encoding="utf-8"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
