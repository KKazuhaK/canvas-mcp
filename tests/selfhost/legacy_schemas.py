"""Frozen builders for the token database as earlier releases wrote it (SQLite).

Schema versions 1 to 4 were created by the pre-Alembic code. Version 2 exists in
three shapes (taken from git history), so these builders do not share code with the
Alembic baseline on purpose: they are the independent description of what real
files look like, and the migration tests prove each one is adopted without losing
or changing a row.

Shapes:

* ``v1``   (24ad477)  twelve token columns, ``meta`` = 1
* ``v2a``  (3451ebd)  + ``canvas_host``, ``meta`` = 2
* ``v2b``  (29aaf33)  + ``principal_key`` and the status columns, the unique
                      index, ``meta`` = 2
* ``v2c``  (90550a6)  + ``user_tool_prefs``, ``meta`` = 2
* ``v3``   (51ed351)  + ``principal_status`` and its history, ``meta`` = 3
* ``v4``   (d91e7ca)  + ``credential_generations``, ``meta`` = 4 (no Alembic table)
"""

from __future__ import annotations

import json
import pathlib
import sqlite3
from dataclasses import dataclass

from canvas_mcp.core.selfhost.token_store import Keyring

SHAPES = ("v1", "v2a", "v2b", "v2c", "v3", "v4")

TID = "11111111-2222-3333-4444-555555555555"
OID_A = "aaaaaaaa-0000-4000-8000-00000000000a"
OID_B = "bbbbbbbb-0000-4000-8000-00000000000b"
OID_C = "cccccccc-0000-4000-8000-00000000000c"
KEY_A = f"entra:{TID}:{OID_A}"
KEY_B = f"entra:{TID}:{OID_B}"
KEY_C = f"entra:{TID}:{OID_C}"
KEY_OTHER = "google:111"
HOST = "canvas.example.edu"

TOKEN_A = "1~" + "A" * 62
TOKEN_B = "2~" + "B" * 62
TOKEN_C = "3~" + "C" * 62
TOKEN_OTHER = "4~" + "D" * 62

_META = "CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID"

_TOKENS_V1 = (
    "CREATE TABLE canvas_tokens ("
    " tenant_id TEXT NOT NULL, object_id TEXT NOT NULL, key_id TEXT NOT NULL,"
    " nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, canvas_user_id TEXT NOT NULL,"
    " canvas_user_name TEXT NOT NULL, entra_display_name TEXT NOT NULL DEFAULT '',"
    " entra_upn TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,"
    " updated_at INTEGER NOT NULL, last_used_at INTEGER,"
    " PRIMARY KEY (tenant_id, object_id)) WITHOUT ROWID"
)
_TOKENS_V2A = _TOKENS_V1.replace(
    " last_used_at INTEGER,", " last_used_at INTEGER, canvas_host TEXT,"
)
_TOKENS_V2B = _TOKENS_V1.replace(
    " last_used_at INTEGER,",
    " last_used_at INTEGER, canvas_host TEXT, principal_key TEXT,"
    " status TEXT NOT NULL DEFAULT 'active', invalid_reason TEXT, invalid_since INTEGER,"
    " last_verified_at INTEGER, expires_hint_at INTEGER,",
)
_UNIQUE_INDEX = "CREATE UNIQUE INDEX canvas_tokens_principal_key ON canvas_tokens (principal_key)"
_PREFS = (
    "CREATE TABLE user_tool_prefs (principal_key TEXT PRIMARY KEY,"
    " enabled_write_tools TEXT NOT NULL DEFAULT '[]', enabled_at TEXT NOT NULL DEFAULT '{}',"
    " updated_at INTEGER NOT NULL, updated_via TEXT NOT NULL DEFAULT 'account_web') WITHOUT ROWID"
)
_STATUS = (
    "CREATE TABLE principal_status (principal_key TEXT PRIMARY KEY,"
    " status TEXT NOT NULL DEFAULT 'active', disabled_reason TEXT, disabled_at INTEGER,"
    " disabled_by TEXT, display_name TEXT NOT NULL DEFAULT '', upn TEXT NOT NULL DEFAULT '',"
    " session_epoch INTEGER NOT NULL DEFAULT 0, is_owner INTEGER NOT NULL DEFAULT 0,"
    " owner_seen_at INTEGER, updated_at INTEGER NOT NULL) WITHOUT ROWID"
)
_EVENTS = (
    "CREATE TABLE principal_status_events (id INTEGER PRIMARY KEY AUTOINCREMENT,"
    " principal_key TEXT NOT NULL, action TEXT NOT NULL, actor TEXT, reason TEXT,"
    " session_epoch INTEGER NOT NULL, at INTEGER NOT NULL)"
)
_EVENTS_INDEX = (
    "CREATE INDEX principal_status_events_principal ON principal_status_events (principal_key, id)"
)
_GENERATIONS = (
    "CREATE TABLE credential_generations (principal_key TEXT PRIMARY KEY,"
    " generation INTEGER NOT NULL, reason TEXT NOT NULL DEFAULT '', updated_at INTEGER NOT NULL)"
    " WITHOUT ROWID"
)

_VERSION = {"v1": "1", "v2a": "2", "v2b": "2", "v2c": "2", "v3": "3", "v4": "4"}


def keyring() -> Keyring:
    import base64

    return Keyring.parse(
        f"k2:{base64.b64encode(bytes([2]) * 32).decode()},k1:{base64.b64encode(bytes([1]) * 32).decode()}"
    )


def _aad_v1(tenant: str, obj: str, kid: str) -> bytes:
    return b"canvas-mcp/canvas-token/v1\x1f" + f"{tenant}\x1f{obj}\x1f{kid}".encode()


def _aad_v2(principal: str, host: str, kid: str) -> bytes:
    return b"canvas-mcp/canvas-token/v2\x1f" + f"{principal}\x1f{host}\x1f{kid}".encode()


@dataclass(frozen=True)
class Seeded:
    """What a built file holds, for the assertions that follow adoption."""

    plaintexts: dict[str, str]  # principal key -> token
    has_status: bool


def _seal(ring: Keyring, kid: str, plaintext: str, aad: bytes) -> tuple[bytes, bytes]:
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = ring._aead[kid]  # type: ignore[attr-defined]
    assert isinstance(key, AESGCM)
    nonce = os.urandom(12)
    return nonce, key.encrypt(nonce, plaintext.encode(), aad)


def build(path: pathlib.Path, shape: str) -> Seeded:
    """Create ``path`` in the given historical shape with real encrypted rows."""
    assert shape in SHAPES
    ring = keyring()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path), isolation_level=None)
    plaintexts: dict[str, str] = {}
    try:
        conn.execute(_META)
        tokens_ddl = {"v1": _TOKENS_V1, "v2a": _TOKENS_V2A}.get(shape, _TOKENS_V2B)
        conn.execute(tokens_ddl)
        if shape not in ("v1", "v2a"):
            conn.execute(_UNIQUE_INDEX)
        if shape in ("v2c", "v3", "v4"):
            conn.execute(_PREFS)
        if shape in ("v3", "v4"):
            conn.execute(_STATUS)
            conn.execute(_EVENTS)
            conn.execute(_EVENTS_INDEX)
        if shape == "v4":
            conn.execute(_GENERATIONS)
        conn.execute("INSERT INTO meta (key, value) VALUES ('schema_version', ?)", (_VERSION[shape],))

        base = (
            "tenant_id, object_id, key_id, nonce, ciphertext, canvas_user_id, canvas_user_name,"
            " entra_display_name, entra_upn, created_at, updated_at, last_used_at"
        )
        marks = ",".join("?" * 12)

        # A legacy row without a host: sealed with the v1 layout under the old key.
        nonce, ct = _seal(ring, "k1", TOKEN_A, _aad_v1(TID, OID_A, "k1"))
        row_a = (TID, OID_A, "k1", nonce, ct, "11", "Ada", "Ada E", "ada@example.test", 1000, 1100, 1200)
        if shape in ("v1", "v2a"):
            conn.execute(f"INSERT INTO canvas_tokens ({base}) VALUES ({marks})", row_a)
        else:
            # Releases that have the column filled it in when they upgraded the file.
            conn.execute(
                f"INSERT INTO canvas_tokens ({base}, principal_key) VALUES ({marks}, ?)",
                (*row_a, KEY_A),
            )
        plaintexts[KEY_A] = TOKEN_A

        if shape != "v1" and shape != "v2a":
            # A row with a school: v2 layout, the newer key, an expiry hint.
            nonce, ct = _seal(ring, "k2", TOKEN_B, _aad_v2(KEY_B, HOST, "k2"))
            conn.execute(
                "INSERT INTO canvas_tokens (tenant_id, object_id, key_id, nonce, ciphertext,"
                " canvas_user_id, canvas_user_name, entra_display_name, entra_upn, created_at,"
                " updated_at, last_used_at, canvas_host, principal_key, status,"
                " last_verified_at, expires_hint_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (TID, OID_B, "k2", nonce, ct, "22", "Bob", "Bob E", "bob@example.test",
                 2000, 2100, 2200, HOST, KEY_B, "active", 2300, 4_000_000_000),
            )
            plaintexts[KEY_B] = TOKEN_B
            # An invalid row (keeps its ciphertext so a re-check can restore it).
            nonce, ct = _seal(ring, "k1", TOKEN_C, _aad_v2(KEY_C, HOST, "k1"))
            conn.execute(
                "INSERT INTO canvas_tokens (tenant_id, object_id, key_id, nonce, ciphertext,"
                " canvas_user_id, canvas_user_name, entra_display_name, entra_upn, created_at,"
                " updated_at, last_used_at, canvas_host, principal_key, status, invalid_reason,"
                " invalid_since, last_verified_at)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (TID, OID_C, "k1", nonce, ct, "33", "Cy", "Cy E", "cy@example.test",
                 3000, 3100, None, HOST, KEY_C, "invalid", "canvas_token_rejected", 3200, 3050),
            )
            plaintexts[KEY_C] = TOKEN_C
            # A principal that is not an Entra user: legacy columns ('' and the key).
            nonce, ct = _seal(ring, "k2", TOKEN_OTHER, _aad_v2(KEY_OTHER, HOST, "k2"))
            conn.execute(
                "INSERT INTO canvas_tokens (tenant_id, object_id, key_id, nonce, ciphertext,"
                " canvas_user_id, canvas_user_name, entra_display_name, entra_upn, created_at,"
                " updated_at, canvas_host, principal_key)"
                " VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)",
                ("", KEY_OTHER, "k2", nonce, ct, "44", "Gus", "", "", 4000, 4100, HOST, KEY_OTHER),
            )
            plaintexts[KEY_OTHER] = TOKEN_OTHER
        if shape == "v2a":
            # A row with a host on the v2a layout is not produced by any release that
            # sealed with today's layout; v2a files only hold legacy rows.
            pass
        if shape in ("v2c", "v3", "v4"):
            conn.execute(
                "INSERT INTO user_tool_prefs VALUES (?, ?, ?, ?, ?)",
                (KEY_B, json.dumps(["send_message"]), json.dumps({"send_message": 2500}), 2600, "account_web"),
            )
        if shape in ("v3", "v4"):
            conn.execute(
                "INSERT INTO principal_status VALUES (?, 'disabled', 'admin_disabled', 3500,"
                " ?, 'Cy E', 'cy@example.test', 3, 0, NULL, 3500)",
                (KEY_C, KEY_B),
            )
            conn.execute(
                "INSERT INTO principal_status VALUES (?, 'active', NULL, NULL, NULL, '', '', 0,"
                " 1, 3400, 3400)",
                (KEY_B,),
            )
            for action, actor, reason, epoch, at, key in (
                ("owner_gained", None, "sign_in", 0, 3400, KEY_B),
                ("disabled", KEY_B, "admin_disabled", 1, 3500, KEY_C),
                ("enabled", KEY_B, None, 2, 3600, KEY_C),
                ("disabled", KEY_B, "admin_disabled", 3, 3700, KEY_C),
            ):
                conn.execute(
                    "INSERT INTO principal_status_events (principal_key, action, actor, reason,"
                    " session_epoch, at) VALUES (?,?,?,?,?,?)",
                    (key, action, actor, reason, epoch, at),
                )
        if shape == "v4":
            for key, generation, reason in ((KEY_B, 2, "enrolled"), (KEY_C, 5, "disabled")):
                conn.execute(
                    "INSERT INTO credential_generations VALUES (?,?,?,?)",
                    (key, generation, reason, 3800),
                )
    finally:
        conn.close()
    return Seeded(plaintexts, shape in ("v3", "v4"))
