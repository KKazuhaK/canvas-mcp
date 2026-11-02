"""Storage of browser-extension bindings, pairing codes and sealed Canvas snapshots.

The extension holds an upload token (only its SHA-256 is stored) and pushes
snapshots of the student's own Canvas data. Snapshot bodies are sealed with the
server keyring; the row carries only what the server needs to find and age them.
See ``deploy/selfhost/BROWSER-SYNC-DESIGN.md``.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import time
from collections.abc import Callable, Collection, Mapping, Sequence
from dataclasses import dataclass
from typing import Any, cast

from sqlalchemy import and_, delete, func, insert, select, update
from sqlalchemy.engine import Connection

from ..browser_source import BrowserSnapshot
from .browser_plan import (
    course_source_keys,
    expected_resources,
    group_ids_of,
    resource_key,
    usable_course_ids,
)
from .db import schema as s
from .db.engine import Database
from .db.sealed import SEALED, SealKeys
from .db.types import new_id

PAIRING_TTL_SECONDS = 300
#: Per-binding quotas, so one browser cannot fill the database.
MAX_SNAPSHOT_ROWS = 3000
MAX_SEALED_BYTES = 64 * 1024 * 1024
#: Statuses that say "try again", not "no": 408, 429 and every 5xx (an extension
#: reports a network failure as 599).
TRANSIENT_STATUSES = frozenset({408, 429, *range(500, 600)})
_CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
_CODE_LENGTH = 12
_CODE_SHAPE = re.compile(rf"^[{_CODE_ALPHABET}]{{{_CODE_LENGTH}}}$")

_SEAL = next(entry for entry in SEALED if entry.table is s.browser_snapshots)


def new_pairing_code() -> str:
    """A random single-use code, grouped for reading aloud: ``ABCD-EFGH-JKLM``."""
    raw = "".join(secrets.choice(_CODE_ALPHABET) for _ in range(_CODE_LENGTH))
    return "-".join(raw[i : i + 4] for i in range(0, _CODE_LENGTH, 4))


def normalize_code(code: object) -> str | None:
    """The comparable form of a typed or pasted code, or None if it cannot be one."""
    if not isinstance(code, str) or len(code) > 64:
        return None
    cleaned = re.sub(r"[\s-]", "", code).upper()
    return cleaned if _CODE_SHAPE.fullmatch(cleaned) else None


def hash_code(normalized: str) -> str:
    return hashlib.sha256(("canvas-mcp/extension-code/v1:" + normalized).encode()).hexdigest()


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


@dataclass(frozen=True)
class Binding:
    id: str
    account_id: str
    canvas_host: str | None
    canvas_user_id: str | None
    created_at: int
    last_upload_at: int | None


@dataclass(frozen=True)
class StoredResource:
    key: str
    captured_at: int
    status: int


@dataclass(frozen=True)
class SnapshotItem:
    """One resource of an upload, already validated."""

    key: str
    path: str
    query: Mapping[str, Sequence[str]]
    captured_at: int
    status: int
    body: Any


class PinConflict(Exception):
    """The upload's Canvas host or user differs from the one the binding is pinned to."""


class QuotaExceeded(Exception):
    """The upload would take the binding over its snapshot row or sealed byte quota."""


class BindingGone(Exception):
    """The binding was revoked (or its account disabled) while the upload ran."""


def browser_decision(
    *,
    token_usable: bool,
    token_host: str | None,
    binding_host: str | None,
    school_offered: bool,
) -> tuple[bool, str | None]:
    """Whether tool calls are answered from browser data, and if not, why.

    A usable personal access token always wins. Otherwise the binding is used
    when its Canvas host is a school this server offers and, if the account
    already has a school (from an unusable token), the same one.
    """
    if token_usable:
        return False, "token_preferred"
    if binding_host is None or not school_offered:
        return False, "school_unknown"
    if token_host is not None and token_host != binding_host:
        return False, "school_unknown"
    return True, None


def drives_the_plan(key: str) -> bool:
    """Whether a resource's data decides which other resources the plan holds.

    The course lists name the courses every per-course resource and calendar chunk
    is expanded from, and the group list names the group calendars. One bad sync
    (a WAF or maintenance 403 while the rest works) must not empty them.
    """
    return key == "/users/self/groups" or key == "/courses" or key.startswith("/courses?")


def rejection_reason(
    prior: tuple[int, int] | None, captured_at: int, status: int, key: str = ""
) -> str | None:
    """Why a resource would not replace its stored row, or None when it would.

    ``prior`` is the stored ``(captured_at, canvas_status)``. The one decision used
    both when writing and when the upload is checked against the course cap.
    """
    if prior is None:
        return None
    if prior[0] > captured_at:
        return "older_than_stored"
    if prior[1] == 200 and status != 200 and drives_the_plan(key):
        # Only a 200 list can change the course or group set; any failure keeps it.
        return "kept_stored_data"
    if prior[1] == 200 and status in TRANSIENT_STATUSES:
        # A transient failure (rate limit, timeout, 5xx) must not wipe good data.
        # 401, 403 and 404 are answers: access lost or content gone.
        return "kept_stored_data"
    return None


def _binding(row: Mapping[Any, Any]) -> Binding:
    return Binding(
        id=row["id"],
        account_id=row["account_id"],
        canvas_host=row["canvas_host"],
        canvas_user_id=row["canvas_user_id"],
        created_at=row["created_at"],
        last_upload_at=row["last_upload_at"],
    )


def _under_path(path: str) -> Any:
    """Rows of one Canvas path: the bare key, or the key followed by a query."""
    key = s.browser_snapshots.c.resource_key
    return (key == path) | key.startswith(path + "?", autoescape=True)


class BrowserSyncStore:
    def __init__(
        self,
        database: Database,
        keys: SealKeys,
        *,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self.database = database
        self.keys = keys
        self.clock = clock

    def _now(self) -> int:
        return int(self.clock())

    # -- pairing --------------------------------------------------------------------

    def create_pairing_code(self, account_id: str) -> tuple[str, int]:
        """A new code for the account; its earlier unclaimed codes stop working."""
        code, now = new_pairing_code(), self._now()
        expires = now + PAIRING_TTL_SECONDS
        codes = s.extension_pairing_codes
        with self.database.write() as conn:
            conn.execute(
                delete(codes).where(
                    codes.c.account_id == account_id,
                    (codes.c.claimed_at.is_(None)) | (codes.c.expires_at < now),
                )
            )
            conn.execute(
                insert(codes).values(
                    code_hash=hash_code(normalize_code(code) or ""),
                    account_id=account_id,
                    created_at=now,
                    expires_at=expires,
                )
            )
        return code, expires

    def claim(self, code: object) -> tuple[str, str] | None:
        """Spend a pairing code: ``(upload_token, binding_id)``, or None if it is not valid.

        The code is consumed by one conditional update, so two racing claims
        cannot both win. A new binding replaces the account's earlier one and
        deletes its snapshots.
        """
        normalized = normalize_code(code)
        if normalized is None:
            return None
        now = self._now()
        codes, bindings = s.extension_pairing_codes, s.extension_bindings
        # A read-only lookup first: a junk code must not take the write lock (on SQLite
        # that serialises every writer on the server). The write below repeats the
        # conditions in its UPDATE, so two racing claims of a real code stay safe.
        with self.database.read() as conn:
            live = conn.execute(
                select(codes.c.account_id).where(
                    codes.c.code_hash == hash_code(normalized),
                    codes.c.claimed_at.is_(None),
                    codes.c.expires_at > now,
                )
            ).first()
        if live is None:
            return None
        token = secrets.token_urlsafe(32)
        binding_id = new_id()
        with self.database.write() as conn:
            spent = conn.execute(
                update(codes)
                .where(
                    codes.c.code_hash == hash_code(normalized),
                    codes.c.claimed_at.is_(None),
                    codes.c.expires_at > now,
                )
                .values(claimed_at=now)
                .returning(codes.c.account_id)
            ).first()
            if spent is None:
                return None
            account_id = spent[0]
            status: str | None = conn.execute(
                select(s.accounts.c.status).where(s.accounts.c.id == account_id)
            ).scalar_one_or_none()
            if status != "active":
                return None
            self._revoke_active(conn, account_id, now)
            conn.execute(
                insert(bindings).values(
                    id=binding_id,
                    account_id=account_id,
                    token_hash=hash_token(token),
                    created_at=now,
                )
            )
        return token, binding_id

    # -- bindings ---------------------------------------------------------------------

    def _revoke_active(self, conn: Connection, account_id: str, now: int) -> bool:
        bindings, snapshots = s.extension_bindings, s.browser_snapshots
        revoked = conn.execute(
            update(bindings)
            .where(bindings.c.account_id == account_id, bindings.c.revoked_at.is_(None))
            .values(revoked_at=now)
            .returning(bindings.c.id)
        ).all()
        for (binding_id,) in revoked:
            conn.execute(delete(snapshots).where(snapshots.c.binding_id == binding_id))
        return bool(revoked)

    def revoke_account(self, account_id: str) -> bool:
        """Revoke the account's binding and delete its snapshots; False if it had none."""
        now = self._now()
        codes = s.extension_pairing_codes
        with self.database.write() as conn:
            conn.execute(delete(codes).where(codes.c.account_id == account_id))
            return self._revoke_active(conn, account_id, now)

    def authenticate(self, token: str) -> Binding | None:
        """The live binding for an upload token, or None (unknown, revoked, account not active)."""
        digest = hash_token(token)
        bindings, accounts = s.extension_bindings, s.accounts
        with self.database.read() as conn:
            row = (
                conn.execute(
                    select(bindings, accounts.c.status)
                    .join(accounts, accounts.c.id == bindings.c.account_id)
                    .where(bindings.c.token_hash == digest)
                )
                .mappings()
                .first()
            )
        if (
            row is None
            or not hmac.compare_digest(row["token_hash"], digest)
            or row["revoked_at"] is not None
            or row["status"] != "active"
        ):
            return None
        return _binding(row)

    def active_binding(self, account_id: str) -> Binding | None:
        bindings = s.extension_bindings
        with self.database.read() as conn:
            row = (
                conn.execute(
                    select(bindings).where(
                        bindings.c.account_id == account_id,
                        bindings.c.revoked_at.is_(None),
                    )
                )
                .mappings()
                .first()
            )
        return None if row is None else _binding(row)

    def resources(self, binding_id: str) -> list[StoredResource]:
        snapshots = s.browser_snapshots
        with self.database.read() as conn:
            rows = conn.execute(
                select(
                    snapshots.c.resource_key,
                    snapshots.c.captured_at,
                    snapshots.c.canvas_status,
                )
                .where(snapshots.c.binding_id == binding_id)
                .order_by(snapshots.c.resource_key)
            ).all()
        return [
            StoredResource(cast(str, key), cast(int, at), cast(int, status))
            for key, at, status in rows
        ]

    # -- snapshots --------------------------------------------------------------------

    def _seal(self, binding_id: str, item: SnapshotItem) -> dict[str, Any]:
        plaintext = json.dumps(
            {"path": item.path, "query": {k: list(v) for k, v in item.query.items()}, "body": item.body},
            separators=(",", ":"),
            ensure_ascii=False,
        ).encode("utf-8")
        row = {
            "binding_id": binding_id,
            "resource_key": item.key,
            "key_id": self.keys.active_key_id,
        }
        key_id, nonce, ciphertext = self.keys.encrypt(plaintext, _SEAL.aad(row))
        return {
            "binding_id": binding_id,
            "resource_key": item.key,
            "captured_at": item.captured_at,
            "canvas_status": item.status,
            "key_id": key_id,
            "nonce": nonce,
            "ciphertext": ciphertext,
        }

    def _open(self, row: Mapping[Any, Any]) -> BrowserSnapshot:
        plaintext = self.keys.decrypt(
            row["key_id"], bytes(row["nonce"]), bytes(row["ciphertext"]), _SEAL.aad(row)
        )
        document = json.loads(plaintext)
        return BrowserSnapshot(
            path=document["path"],
            query={k: [str(v) for v in values] for k, values in document["query"].items()},
            captured_at=int(row["captured_at"]),
            status=int(row["canvas_status"]),
            body=document["body"],
        )

    def save(
        self,
        binding_id: str,
        *,
        canvas_host: str,
        canvas_user_id: str,
        items: Sequence[SnapshotItem],
    ) -> tuple[int, list[tuple[str, str]]]:
        """Store an upload; ``(accepted, [(resource_key, reason)])``.

        The binding row is updated first, in the same transaction: it pins the
        Canvas host and user on the first upload and refuses a different one, and
        it takes the row lock a concurrent revoke has to wait for.
        """
        now = self._now()
        sealed = [(item, self._seal(binding_id, item)) for item in items]
        bindings, snapshots = s.extension_bindings, s.browser_snapshots
        rejected: list[tuple[str, str]] = []
        accepted = 0
        with self.database.row_write() as conn:
            row = (
                conn.execute(
                    select(bindings, s.accounts.c.status)
                    .join(s.accounts, s.accounts.c.id == bindings.c.account_id)
                    .where(bindings.c.id == binding_id)
                )
                .mappings()
                .first()
            )
            if row is None or row["revoked_at"] is not None or row["status"] != "active":
                raise BindingGone
            if (row["canvas_host"] not in (None, canvas_host)) or (
                row["canvas_user_id"] not in (None, canvas_user_id)
            ):
                raise PinConflict
            changed = conn.execute(
                update(bindings)
                .where(
                    bindings.c.id == binding_id,
                    bindings.c.revoked_at.is_(None),
                    (bindings.c.canvas_host.is_(None)) | (bindings.c.canvas_host == canvas_host),
                    (bindings.c.canvas_user_id.is_(None))
                    | (bindings.c.canvas_user_id == canvas_user_id),
                )
                .values(
                    canvas_host=canvas_host,
                    canvas_user_id=canvas_user_id,
                    last_upload_at=now,
                )
            ).rowcount
            if changed != 1:
                raise BindingGone
            prior: dict[str, tuple[int, int, int]] = {
                cast(str, key): (cast(int, at), cast(int, status), cast(int, size))
                for key, at, status, size in conn.execute(
                    select(
                        snapshots.c.resource_key,
                        snapshots.c.captured_at,
                        snapshots.c.canvas_status,
                        func.length(snapshots.c.ciphertext),
                    ).where(
                        snapshots.c.binding_id == binding_id,
                        snapshots.c.resource_key.in_([item.key for item, _ in sealed]),
                    )
                ).all()
            }
            writes: list[tuple[SnapshotItem, dict[str, Any]]] = []
            for item, values in sealed:
                before = prior.get(item.key)
                reason = rejection_reason(
                    None if before is None else (before[0], before[1]),
                    item.captured_at,
                    item.status,
                    item.key,
                )
                if reason is not None:
                    rejected.append((item.key, reason))
                else:
                    writes.append((item, values))
            count, total = conn.execute(
                select(
                    func.count(),
                    func.coalesce(func.sum(func.length(snapshots.c.ciphertext)), 0),
                ).where(snapshots.c.binding_id == binding_id)
            ).one()
            rows = cast(int, count) + sum(1 for item, _ in writes if item.key not in prior)
            size = cast(int, total) + sum(
                len(values["ciphertext"]) - (prior[item.key][2] if item.key in prior else 0)
                for item, values in writes
            )
            if rows > MAX_SNAPSHOT_ROWS or size > MAX_SEALED_BYTES:
                raise QuotaExceeded
            for item, values in writes:
                if item.key in prior:
                    conn.execute(
                        update(snapshots)
                        .where(
                            and_(
                                snapshots.c.binding_id == binding_id,
                                snapshots.c.resource_key == item.key,
                            )
                        )
                        .values(
                            {
                                k: v
                                for k, v in values.items()
                                if k not in ("binding_id", "resource_key")
                            }
                        )
                    )
                else:
                    conn.execute(insert(snapshots).values(**values))
                accepted += 1
            if accepted:
                self._drop_stale(conn, binding_id, canvas_user_id)
        return accepted, rejected

    def _drop_stale(self, conn: Connection, binding_id: str, canvas_user_id: str) -> None:
        """Delete rows whose key the current plan can no longer hold.

        Computed from the course and group lists as they are after this upload, in the
        same transaction. A row is never deleted because an upload did not mention it
        (cold rows that are not due stay): only because its key left the plan, such as
        a calendar chunk naming a course that is now unpublished.
        """
        snapshots = s.browser_snapshots

        def rows(path: str) -> list[BrowserSnapshot]:
            found = conn.execute(
                select(snapshots).where(snapshots.c.binding_id == binding_id, _under_path(path))
            ).mappings()
            return [self._open(row) for row in found]

        sources = course_source_keys()
        courses: set[str] = set()
        listings = [
            snapshot
            for snapshot in rows("/courses")
            if resource_key(snapshot.path, snapshot.query) in sources
        ]
        group_rows = [
            snapshot
            for snapshot in rows("/users/self/groups")
            if resource_key(snapshot.path, snapshot.query) == "/users/self/groups"
        ]
        if any(snapshot.status != 200 for snapshot in [*listings, *group_rows]):
            # The lists the expected set would come from are not all good: prune nothing.
            return
        for snapshot in listings:
            courses |= usable_course_ids(snapshot.body)
        groups = self._groups_among(group_rows, courses)
        expected = expected_resources(courses, canvas_user_id, groups)
        held: list[str] = [
            cast(str, row[0])
            for row in conn.execute(
                select(snapshots.c.resource_key).where(snapshots.c.binding_id == binding_id)
            ).all()
        ]
        stale = [key for key in held if key not in expected]
        for start in range(0, len(stale), 500):
            conn.execute(
                delete(snapshots).where(
                    snapshots.c.binding_id == binding_id,
                    snapshots.c.resource_key.in_(stale[start : start + 500]),
                )
            )

    def load_path(self, binding_id: str, path: str) -> list[BrowserSnapshot]:
        """Every stored snapshot of one Canvas path, decrypted."""
        snapshots = s.browser_snapshots
        with self.database.read() as conn:
            rows = (
                conn.execute(
                    select(snapshots).where(
                        snapshots.c.binding_id == binding_id, _under_path(path)
                    )
                )
                .mappings()
                .all()
            )
        return [self._open(row) for row in rows]

    def stored_state(
        self, binding_id: str, keys: Collection[str]
    ) -> dict[str, tuple[int, int]]:
        """``{resource_key: (captured_at, canvas_status)}`` of the stored rows among ``keys``."""
        if not keys:
            return {}
        snapshots = s.browser_snapshots
        with self.database.read() as conn:
            rows = conn.execute(
                select(
                    snapshots.c.resource_key,
                    snapshots.c.captured_at,
                    snapshots.c.canvas_status,
                ).where(
                    snapshots.c.binding_id == binding_id,
                    snapshots.c.resource_key.in_(list(keys)),
                )
            ).all()
        return {cast(str, k): (cast(int, at), cast(int, st)) for k, at, st in rows}

    def course_ids(self, binding_id: str, *, excluding: Collection[str] = ()) -> set[str]:
        """Course ids of the binding's stored course-source ``/courses`` snapshots.

        ``excluding`` names resource keys whose rows are about to be replaced.
        """
        ids: set[str] = set()
        sources = course_source_keys()
        for snapshot in self.load_path(binding_id, "/courses"):
            key = resource_key(snapshot.path, snapshot.query)
            # Only the active enrollments expand: the unfiltered list also holds past
            # courses whose sub-resources Canvas usually refuses.
            if key not in sources or key in excluding:
                continue
            if snapshot.status == 200:
                ids |= usable_course_ids(snapshot.body)
        return ids

    def group_ids(self, binding_id: str) -> list[str]:
        """Group ids of the stored ``/users/self/groups`` snapshot (sorted), or []."""
        return self._groups_among(
            self.load_path(binding_id, "/users/self/groups"), self.course_ids(binding_id)
        )

    @staticmethod
    def _groups_among(snapshots: Sequence[BrowserSnapshot], courses: Collection[str]) -> list[str]:
        for snapshot in snapshots:
            if resource_key(snapshot.path, snapshot.query) == "/users/self/groups" and (
                snapshot.status == 200
            ):
                return group_ids_of(snapshot.body, courses)
        return []

    def expected_keys(self, binding_id: str, canvas_user_id: str | None) -> frozenset[str]:
        """Every resource key the binding's current plan can hold, from its stored lists."""
        return frozenset(
            expected_resources(
                self.course_ids(binding_id), canvas_user_id, self.group_ids(binding_id)
            )
        )
