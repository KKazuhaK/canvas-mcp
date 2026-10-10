"""The transactions of the authorization server, over the repositories.

Like :class:`~canvas_mcp.core.selfhost.token_store.TokenStore`, this class owns every
transaction boundary of its tables (the repositories never begin or commit), so the
race-sensitive reasoning is in one reviewable place. All methods are synchronous and
thread-safe (one connection per call); async callers use ``anyio.to_thread.run_sync``.

**Atomicity.** Every "consume" is one conditional ``UPDATE``/``DELETE`` whose ``WHERE``
holds the condition, and the code acts on ``rowcount == 1`` (see ``db.authz_repos``).
The hot transactions run in :meth:`Database.row_write` (no global PostgreSQL writer lock).
What makes that safe is the order inside them:

* **Authorization code**: the first statement is the conditional ``UPDATE`` that consumes
  the row. A second exchange blocks on the row, then finds it already consumed.
* **Refresh token**: the first statement locks the *grant* row (``lock_live``, an
  ``UPDATE`` of ``last_used_at`` that matches only a live grant). Every rotation of a
  family, every revocation of the grant and every disabling of the account write that
  row, so they serialise on it, and each of them re-evaluates "is the grant still live"
  after the wait. No decision in these transactions rests on a predicate over many rows.
  The replay of an already-consumed code takes the same grant lock before it looks at
  the family (the window decision reads many rows), so it serialises with rotations too.
* **First exchange**: the account row is read ``FOR UPDATE`` before the grant is inserted;
  disabling an account takes the same lock before it revokes the grants, so a grant is
  never created behind a disablement that has already looked for grants.

**Replays.** A code or refresh token that is presented again is usually not theft: a client
retries a slow ``/token`` call, or two workers refresh together. So a replay within
``REFRESH_REUSE_GRACE_S`` of the first use (at most twice per token) is answered with a
*sibling*: a new token on the same family, parent being the same token. Using a sibling
retires the others, so a stolen copy that a second party later presents is a reuse, and a
reuse revokes the whole grant. A replay outside the window, or of a token whose family
has moved on, revokes at once. ``REFRESH_REUSE_GRACE_S=0`` is strict.

Messages and results carry no secrets; no token, code or hash is ever logged here.
"""

from __future__ import annotations

import json
import time
from collections.abc import Callable
from typing import Any

from sqlalchemy.engine import Connection

from .. import accounts as acc
from ..db.engine import Database
from ..db.errors import StoreUnavailable
from ..db.repos import Repositories
from ..settings import AuthzSettings
from ..token_store import (
    AUDIT_GRANT_REVOKED,
    AUDIT_GRANTS_REVOKED_FOR_ACCOUNT,
    AUDIT_JWT_KEY_ROTATED,
    OPERATOR_ACTOR,
    SYSTEM_ACTOR,
    AccessActionRefused,
)
from .models import (
    BY_OPERATOR,
    BY_SYSTEM,
    CLIENT_KIND_DCR,
    CODE_TTL_SECONDS,
    MAX_GRACE_REPLAYS,
    REVOKE_ACCOUNT_DISABLED,
    REVOKE_ADMISSION_LOST,
    REVOKE_CLIENT,
    REVOKE_CODE_REPLAY,
    REVOKE_OPERATOR,
    REVOKE_OWNER,
    REVOKE_REASONS,
    REVOKE_REAUTH_REQUIRED,
    REVOKE_REFRESH_REUSE,
    REVOKE_USER,
    CimdSnapshot,
    ClientRecord,
    CodeRecord,
    ExchangeOutcome,
    ExchangeResult,
    GrantRecord,
    GrantStatus,
    RefreshView,
    RotateOutcome,
    RotateResult,
)

LAST_USED_GRANULARITY_SECONDS = 300
_DAY = 86400
CULL_CODES_AFTER = 3600
CULL_REFRESH_REVOKED_AFTER = 7 * _DAY
CULL_GRANTS_AFTER = 30 * _DAY


def _json(detail: dict[str, Any] | None) -> str:
    return json.dumps(detail or {}, separators=(",", ":"), sort_keys=True)


class AuthzStore:
    """Clients, codes, grants and refresh tokens, in one database."""

    def __init__(
        self,
        db: Database,
        *,
        clock: Callable[[], float] = time.time,
        settings: AuthzSettings | None = None,
        pause_hook: Callable[[str], None] | None = None,
    ) -> None:
        self._db = db
        self._repos = Repositories(db.kind)
        self._clock = clock
        self.settings = settings or AuthzSettings()
        # Test seam for deterministic race tests: called with a name at fixed points
        # inside a transaction. None in production.
        self.pause_hook = pause_hook

    # -- plumbing ---------------------------------------------------------------------

    @property
    def database(self) -> Database:
        return self._db

    def _now(self) -> int:
        return int(self._clock())

    def _pause(self, name: str) -> None:
        if self.pause_hook is not None:
            self.pause_hook(name)

    def _audit(
        self,
        conn: Connection,
        actor: str,
        action: str,
        *,
        target: str | None = None,
        reason: str | None = None,
        detail: dict[str, Any] | None = None,
        now: int,
    ) -> None:
        self._repos.audit.append(
            conn, now=now, actor=actor, action=action, target=target, reason=reason, detail=_json(detail)
        )

    def _event(
        self, conn: Connection, *, now: int, account_id: str | None, outcome: str, reason: str
    ) -> None:
        """A row of the ``oauth`` surface of ``auth_events`` (not shown in the sign-in history)."""
        if reason not in acc.AUTH_REASONS:  # pragma: no cover - the callers pass registered reasons
            reason = acc.REASON_PROVIDER_ERROR
        self._repos.auth_events.append(
            conn,
            now=now,
            account_id=account_id,
            provider_id="local",
            surface=acc.SURFACE_OAUTH,
            outcome=outcome,
            reason=reason,
            ip="unknown",
            ua_hash=None,
        )

    def _account_active(self, conn: Connection, account_id: str) -> bool:
        row = self._repos.accounts.get(conn, account_id)
        return row is not None and row[1] == acc.STATUS_ACTIVE

    # -- registered clients ---------------------------------------------------------

    def put_client(self, client_id: str, info_json: str, client_name: str, expires_at: int) -> None:
        with self._db.row_write() as conn:
            self._repos.clients.insert(
                conn,
                client_id=client_id,
                info_json=info_json,
                client_name=client_name,
                now=self._now(),
                expires_at=expires_at,
            )

    def get_client_record(self, client_id: str) -> ClientRecord | None:
        with self._db.read() as conn:
            row = self._repos.clients.get(conn, client_id)
        return None if row is None else ClientRecord.from_row(row)

    # -- client metadata documents --------------------------------------------------

    def cimd_snapshot(self, url: str) -> CimdSnapshot | None:
        with self._db.read() as conn:
            row = self._repos.cimd.get(conn, url)
        return None if row is None else CimdSnapshot.from_row(row)

    def upsert_cimd(self, url: str, doc_json: str, *, fetched_at: int, fresh_until: int) -> bool:
        """Store a validated document unless a newer one is stored; True if this call wrote."""
        with self._db.row_write() as conn:
            return self._repos.cimd.upsert(
                conn, url=url, doc_json=doc_json, fetched_at=fetched_at, fresh_until=max(fresh_until, fetched_at)
            )

    def record_cimd_error(self, url: str, code: str) -> None:
        """Note a failed refresh on the stored document (best effort; never raises)."""
        try:
            with self._db.best_effort_write(lock=False) as conn:
                self._repos.cimd.record_error(conn, url, now=self._now(), code=code)
        except Exception:  # noqa: BLE001 - bookkeeping must never change an answer
            return

    # -- authorization codes ----------------------------------------------------------

    def create_code(
        self,
        *,
        code_hash: str,
        client_id: str,
        client_kind: str,
        client_name: str,
        client_host: str | None,
        account_id: str,
        redirect_uri: str,
        redirect_uri_explicit: bool,
        redirect_host: str,
        code_challenge: str,
        scopes: tuple[str, ...],
        resource: str,
        upstream_auth_at: int,
    ) -> bool:
        """Store a code for an approved request; False if the account is not active.

        The status is read in the same transaction as the insert, so an approval can never
        produce a code for an account that was disabled before it. (The exchange checks
        again: this only keeps dead codes from being minted.)
        """
        now = self._now()
        with self._db.row_write() as conn:
            if not self._account_active(conn, account_id):
                return False
            self._repos.codes.insert(
                conn,
                code_hash=code_hash,
                client_id=client_id,
                account_id=account_id,
                redirect_uri=redirect_uri,
                redirect_uri_explicit=1 if redirect_uri_explicit else 0,
                code_challenge=code_challenge,
                scopes=" ".join(scopes),
                resource=resource,
                client_kind=client_kind,
                client_name=client_name,
                client_host=client_host,
                redirect_host=redirect_host,
                upstream_auth_at=upstream_auth_at,
                created_at=now,
                expires_at=now + CODE_TTL_SECONDS,
            )
            self._event(
                conn, now=now, account_id=account_id, outcome="success", reason=acc.REASON_CONSENT_GRANTED
            )
        return True

    def record_consent_denied(self, account_id: str) -> None:
        """Note that a user declined an app (best effort; never raises)."""
        try:
            with self._db.best_effort_write(lock=False) as conn:
                self._event(
                    conn,
                    now=self._now(),
                    account_id=account_id,
                    outcome="denied",
                    reason=acc.REASON_CONSENT_DENIED,
                )
        except Exception:  # noqa: BLE001
            return

    def load_code(self, code_hash: str) -> CodeRecord | None:
        with self._db.read() as conn:
            row = self._repos.codes.get(conn, code_hash)
        return None if row is None else CodeRecord.from_row(row)

    def exchange_code(
        self, *, code_hash: str, client_id: str, grant_id: str, refresh_hash: str | None
    ) -> ExchangeResult:
        """Redeem an authorization code: create the grant (and its first refresh token).

        ``grant_id`` and ``refresh_hash`` are fresh values chosen by the caller: they are
        used only if this call wins (or, for a benign duplicate, ``refresh_hash`` for the
        sibling token). ``refresh_hash`` is None for a client that cannot refresh. See the
        module docstring for the replay rules.
        """
        policy = self.settings
        now = self._now()
        with self._db.row_write() as conn:
            won = self._repos.codes.consume(conn, code_hash, client_id, grant_id=grant_id, now=now)
            self._pause("after_code_consume")
            row = self._repos.codes.get(conn, code_hash)
            if row is None:
                return ExchangeResult(ExchangeOutcome.DEAD)
            code = CodeRecord.from_row(row)
            if won:
                return self._first_exchange(conn, code, grant_id, refresh_hash, now)

            # Not consumed by this call: unknown for this client, expired, or a replay.
            if code.consumed_at is None or code.client_id != client_id or code.grant_id is None:
                return ExchangeResult(ExchangeOutcome.DEAD)
            # The grant row lock comes first, as on the refresh path: whether this replay is
            # inside the window depends on whether the family has rotated (``any_used``), and
            # a rotation (which also writes this row) must not slip in between that read and
            # the sibling insert below, or the family would end with two live branches.
            if not self._repos.grants.lock_live(conn, code.grant_id, now):
                return ExchangeResult(ExchangeOutcome.DEAD)
            self._pause("after_code_grant_lock")
            grant_row = self._repos.grants.get(conn, code.grant_id)
            if grant_row is None:  # pragma: no cover - the lock just matched it
                return ExchangeResult(ExchangeOutcome.DEAD)
            grant = GrantRecord.from_row(grant_row)
            inside_window = (
                policy.refresh_reuse_grace_s > 0
                and now - code.consumed_at <= policy.refresh_reuse_grace_s
                and not self._repos.refresh.any_used(conn, grant.id)
            )
            if not inside_window:
                self._revoke_for_replay(
                    conn, grant, now, reason=REVOKE_CODE_REPLAY, event=acc.REASON_CODE_REPLAY
                )
                return ExchangeResult(ExchangeOutcome.REPLAY_REVOKED, grant)
            if not self._repos.codes.bump_grace(conn, code_hash, MAX_GRACE_REPLAYS):
                return ExchangeResult(ExchangeOutcome.CAPPED, grant)
            if not self._account_active(conn, grant.account_id):
                return ExchangeResult(ExchangeOutcome.INACTIVE, grant)
            if refresh_hash is not None:
                self._repos.refresh.insert(
                    conn,
                    token_hash=refresh_hash,
                    grant_id=grant.id,
                    parent_hash=None,
                    now=now,
                    expires_at=grant.expires_at,
                )
            return ExchangeResult(ExchangeOutcome.GRACE, grant, refresh_issued=refresh_hash is not None)

    def _first_exchange(
        self,
        conn: Connection,
        code: CodeRecord,
        grant_id: str,
        refresh_hash: str | None,
        now: int,
    ) -> ExchangeResult:
        """The call that consumed the code: checks, then the grant and its first token."""
        policy = self.settings
        # The account row is read FOR UPDATE: disabling an account (and ``admission_lost``)
        # takes the same lock before it revokes the account's grants, so it either sees the
        # grant inserted below (and revokes it) or runs first (and this exchange is refused).
        account = self._repos.accounts.get(conn, code.account_id, for_update=True)
        if account is None or account[1] != acc.STATUS_ACTIVE:
            return ExchangeResult(ExchangeOutcome.INACTIVE)
        if now - code.upstream_auth_at > policy.max_upstream_auth_age:
            self._event(
                conn, now=now, account_id=code.account_id, outcome="denied",
                reason=acc.REASON_REAUTH_REQUIRED,
            )
            return ExchangeResult(ExchangeOutcome.REAUTH)
        expires_at = now + policy.refresh_absolute_ttl
        self._repos.grants.insert(
            conn,
            id=grant_id,
            account_id=code.account_id,
            client_id=code.client_id,
            client_kind=code.client_kind,
            client_name=code.client_name,
            client_host=code.client_host,
            redirect_host=code.redirect_host,
            scopes=" ".join(code.scopes),
            resource=code.resource,
            created_at=now,
            last_used_at=now,
            upstream_auth_at=code.upstream_auth_at,
            expires_at=expires_at,
        )
        if refresh_hash is not None:
            self._repos.refresh.insert(
                conn,
                token_hash=refresh_hash,
                grant_id=grant_id,
                parent_hash=None,
                now=now,
                expires_at=expires_at,
            )
        self._pause("after_grant_insert")
        if code.client_kind == CLIENT_KIND_DCR:
            # A registration lives as long as the longest connection made with it.
            self._repos.clients.extend(conn, code.client_id, expires_at)
        self._event(
            conn, now=now, account_id=code.account_id, outcome="success", reason=acc.REASON_GRANT_CREATED
        )
        row = self._repos.grants.get(conn, grant_id)
        assert row is not None
        return ExchangeResult(
            ExchangeOutcome.WON, GrantRecord.from_row(row), refresh_issued=refresh_hash is not None
        )

    def _revoke_for_replay(
        self, conn: Connection, grant: GrantRecord, now: int, *, reason: str, event: str
    ) -> None:
        if self._repos.grants.revoke(conn, grant.id, reason=reason, by=BY_SYSTEM, now=now):
            self._event(conn, now=now, account_id=grant.account_id, outcome="denied", reason=event)

    # -- refresh tokens -----------------------------------------------------------------

    def load_refresh(self, token_hash: str) -> RefreshView | None:
        """A refresh token and its grant's facts, without changing anything."""
        with self._db.read() as conn:
            row = self._repos.refresh.get_with_grant(conn, token_hash)
        return None if row is None else RefreshView.from_row(row)

    def rotate_refresh(self, *, token_hash: str, new_hash: str) -> RotateResult:
        """Exchange a refresh token for its successor (``new_hash``). See the module docstring."""
        policy = self.settings
        now = self._now()
        refresh = self._repos.refresh
        with self._db.row_write() as conn:
            row = refresh.get(conn, token_hash)
            if row is None:
                return RotateResult(RotateOutcome.DEAD)
            token = _TokenRow(row)
            # The grant row lock comes first: it serialises this family against every
            # other rotation, revocation and disabling.
            if not self._repos.grants.lock_live(conn, token.grant_id, now):
                return RotateResult(RotateOutcome.DEAD)
            self._pause("after_grant_lock")
            grant_row = self._repos.grants.get(conn, token.grant_id)
            if grant_row is None:  # pragma: no cover - the lock just matched it
                return RotateResult(RotateOutcome.DEAD)
            grant = GrantRecord.from_row(grant_row)
            if not self._account_active(conn, grant.account_id):
                return RotateResult(RotateOutcome.INACTIVE, grant)
            if now - grant.upstream_auth_at > policy.max_upstream_auth_age:
                if self._repos.grants.revoke(
                    conn, grant.id, reason=REVOKE_REAUTH_REQUIRED, by=BY_SYSTEM, now=now
                ):
                    self._event(
                        conn, now=now, account_id=grant.account_id, outcome="denied",
                        reason=acc.REASON_REAUTH_REQUIRED,
                    )
                return RotateResult(RotateOutcome.REAUTH, grant)

            if refresh.mark_used(conn, token_hash, replaced_by=new_hash, now=now):
                self._pause("after_refresh_mark")
                refresh.retire_siblings(
                    conn, grant_id=grant.id, parent_hash=token.parent_hash, keep=token_hash, now=now
                )
                refresh.insert(
                    conn,
                    token_hash=new_hash,
                    grant_id=grant.id,
                    parent_hash=token_hash,
                    now=now,
                    expires_at=token.expires_at,
                )
                return RotateResult(RotateOutcome.ROTATED, grant, refresh_issued=True)

            # Used already (by a concurrent call that finished first, or earlier): read it again.
            again = refresh.get(conn, token_hash)
            if again is None:
                return RotateResult(RotateOutcome.DEAD)
            used = _TokenRow(again)
            reuse = used.replaced_by is None or refresh.has_rotated_child(conn, token_hash)
            if not reuse and used.used_at is not None:
                inside_window = (
                    policy.refresh_reuse_grace_s > 0
                    and now - used.used_at <= policy.refresh_reuse_grace_s
                )
                if inside_window:
                    if not refresh.bump_grace(conn, token_hash, MAX_GRACE_REPLAYS):
                        return RotateResult(RotateOutcome.CAPPED, grant)
                    refresh.insert(
                        conn,
                        token_hash=new_hash,
                        grant_id=grant.id,
                        parent_hash=token_hash,
                        now=now,
                        expires_at=used.expires_at,
                    )
                    return RotateResult(RotateOutcome.GRACE, grant, refresh_issued=True)
            self._revoke_for_replay(
                conn, grant, now, reason=REVOKE_REFRESH_REUSE, event=acc.REASON_REFRESH_REUSE
            )
            return RotateResult(RotateOutcome.REUSE_REVOKED, grant)

    # -- grants -------------------------------------------------------------------------

    def get_grant(self, grant_id: str) -> GrantRecord | None:
        with self._db.read() as conn:
            row = self._repos.grants.get(conn, grant_id)
        return None if row is None else GrantRecord.from_row(row)

    def grant_status(self, grant_id: str) -> GrantStatus:
        """The grant and its account's status, read together (raises when unreadable)."""
        with self._db.read() as conn:
            return GrantStatus.from_row(self._repos.grants.status_row(conn, grant_id))

    def touch_grant(self, grant_id: str) -> None:
        """Note that a grant is in use (at most every five minutes). Best effort; never raises."""
        now = self._now()
        try:
            with self._db.best_effort_write(lock=False) as conn:
                self._repos.grants.touch_used(
                    conn, grant_id, now=now, older_than=now - LAST_USED_GRANULARITY_SECONDS
                )
        except Exception:  # noqa: BLE001 - last-used bookkeeping must never fail a request
            return

    def list_grants(self, account_key: str) -> list[GrantRecord]:
        """The live grants of an account, newest first."""
        account_id = acc.account_id_of(account_key)
        with self._db.read() as conn:
            rows = self._repos.grants.list_for_account(conn, account_id, self._now())
        return [GrantRecord.from_row(r) for r in rows]

    def list_all_grants(self, *, include_inactive: bool = False, limit: int = 500) -> list[GrantRecord]:
        with self._db.read() as conn:
            rows = self._repos.grants.list_all(
                conn, include_inactive=include_inactive, now=self._now(), limit=max(1, min(limit, 2000))
            )
        return [GrantRecord.from_row(r) for r in rows]

    def revoke_grant(self, grant_id: str, *, reason: str, by: str = BY_SYSTEM, event: str | None = None) -> bool:
        """Revoke one grant on behalf of the system (a client's ``/revoke``, a replay)."""
        assert reason in REVOKE_REASONS, reason
        now = self._now()
        with self._db.row_write() as conn:
            row = self._repos.grants.get(conn, grant_id)
            changed = self._repos.grants.revoke(conn, grant_id, reason=reason, by=by, now=now)
            if changed and event is not None and row is not None:
                self._event(
                    conn, now=now, account_id=str(row[1]), outcome="success", reason=event
                )
            return changed

    def revoke_own_grant(self, grant_id: str, account_key: str) -> bool:
        """A user ends one of their own connections. False if it is not theirs or is already over."""
        account_id = acc.account_id_of(account_key)
        now = self._now()
        with self._db.row_write() as conn:
            changed = self._repos.grants.revoke_own(
                conn, grant_id, account_id, reason=REVOKE_USER, by=account_key, now=now
            )
            if changed:
                self._audit(
                    conn, account_key, AUDIT_GRANT_REVOKED, target=account_key, reason=REVOKE_USER,
                    detail={"via": "account"}, now=now,
                )
            return changed

    def owner_revoke_grant(self, grant_id: str, actor_key: str) -> bool:
        """An owner ends any connection. The owner is re-checked inside the transaction."""
        now = self._now()
        actor_id = acc.account_id_of(actor_key)
        with self._db.write() as conn:
            actor = self._repos.accounts.get(conn, actor_id, for_update=True)
            if actor is None or actor[1] != acc.STATUS_ACTIVE or actor[2] != acc.ROLE_OWNER:
                raise AccessActionRefused(AccessActionRefused.NOT_OWNER)
            row = self._repos.grants.get(conn, grant_id)
            if row is None:
                return False
            changed = self._repos.grants.revoke(
                conn, grant_id, reason=REVOKE_OWNER, by=actor_key, now=now
            )
            if changed:
                self._audit(
                    conn, actor_key, AUDIT_GRANT_REVOKED, target=f"acct:{row[1]}", reason=REVOKE_OWNER,
                    detail={"via": "admin", "client_kind": str(row[3])}, now=now,
                )
            return changed

    def operator_revoke_grant(self, grant_id: str) -> bool:
        """The operator at the host ends any connection (``token_admin revoke-grant``)."""
        now = self._now()
        with self._db.write() as conn:
            row = self._repos.grants.get(conn, grant_id)
            if row is None:
                return False
            changed = self._repos.grants.revoke(
                conn, grant_id, reason=REVOKE_OPERATOR, by=BY_OPERATOR, now=now
            )
            if changed:
                self._audit(
                    conn, OPERATOR_ACTOR, AUDIT_GRANT_REVOKED, target=f"acct:{row[1]}",
                    reason=REVOKE_OPERATOR, detail={"via": "cli", "client_kind": str(row[3])}, now=now,
                )
            return changed

    def revoke_all_for_account(self, account_key: str, *, reason: str) -> int:
        """End every live connection of an account (``admission_lost``); returns how many.

        For ``admission_lost`` the account itself stays active, so this also ends its
        ``/account`` sessions (``session_epoch``) and deletes the codes it approved but
        nobody has redeemed: otherwise a browser that is still signed in could approve the
        app again without a round trip to the identity provider, or an approved code could
        still be exchanged for a new connection. (Disabling an account does both on its own.)
        """
        assert reason in (REVOKE_ADMISSION_LOST, REVOKE_ACCOUNT_DISABLED), reason
        account_id = acc.account_id_of(account_key)
        now = self._now()
        with self._db.row_write() as conn:
            lost = reason == REVOKE_ADMISSION_LOST
            # Codes first, then the account lock: an exchange takes its code row, then the
            # account row, and no transaction takes them in the other order.
            if lost:
                self._repos.codes.delete_unconsumed_for_account(conn, account_id)
            # Serialise with a first code exchange of the account (which reads the row FOR
            # UPDATE) so that a grant created concurrently is seen by the revocation below.
            self._repos.accounts.get(conn, account_id, for_update=True)
            if lost:
                self._repos.accounts.end_sessions(conn, account_id, now)
            count = self._repos.grants.revoke_for_account(
                conn, account_id, reason=reason, by=BY_SYSTEM, now=now
            )
            if count:
                self._audit(
                    conn, SYSTEM_ACTOR, AUDIT_GRANTS_REVOKED_FOR_ACCOUNT, target=account_key,
                    reason=reason, detail={"count": count}, now=now,
                )
            return count

    def revoke_client_grant(self, grant_id: str) -> bool:
        """A client's own ``/revoke``: end the connection and note it in the history."""
        return self.revoke_grant(
            grant_id, reason=REVOKE_CLIENT, by=BY_SYSTEM, event=acc.REASON_CLIENT_REVOKED
        )

    # -- the JWT epoch ------------------------------------------------------------------

    def jwt_epoch(self) -> int:
        with self._db.read() as conn:
            return self._repos.jwt_epoch.get(conn)

    def bump_jwt_epoch(self) -> int:
        """Invalidate every access token (running servers notice within 30 seconds)."""
        now = self._now()
        with self._db.write() as conn:
            epoch = self._repos.jwt_epoch.bump(conn)
            self._audit(
                conn, OPERATOR_ACTOR, AUDIT_JWT_KEY_ROTATED, detail={"epoch": epoch}, now=now
            )
            return epoch

    # -- housekeeping -------------------------------------------------------------------

    def cull(self, *, stale_max: int | None = None) -> dict[str, int]:
        """Delete expired rows, each class in its own best-effort transaction."""
        now = self._now()
        keep_documents = (self.settings.cimd_stale_max if stale_max is None else stale_max) + _DAY
        repos = self._repos
        steps: list[tuple[str, Callable[[Connection], int]]] = [
            ("login_states", lambda c: repos.login_states.delete_expired(c, now)),
            ("oauth_codes", lambda c: repos.codes.delete_expired_before(c, now - CULL_CODES_AFTER)),
            (
                "oauth_refresh_tokens",
                lambda c: repos.refresh.delete_dead(
                    c, now=now, revoked_before=now - CULL_REFRESH_REVOKED_AFTER
                ),
            ),
            ("oauth_grants", lambda c: repos.grants.delete_inactive_before(c, now - CULL_GRANTS_AFTER)),
            ("oauth_clients", lambda c: repos.clients.delete_expired(c, now)),
            ("cimd_clients", lambda c: repos.cimd.delete_fetched_before(c, now - keep_documents)),
        ]
        removed: dict[str, int] = {}
        for name, step in steps:
            try:
                with self._db.row_write() as conn:
                    removed[name] = step(conn)
            except StoreUnavailable:
                removed[name] = 0
        return removed


class _TokenRow:
    """Named access to a refresh-token row (see ``REFRESH_COLUMNS``)."""

    __slots__ = ("created_at", "expires_at", "grace_replays", "grant_id", "parent_hash",
                 "replaced_by", "token_hash", "used_at")

    def __init__(self, row: Any) -> None:
        self.token_hash = str(row[0])
        self.grant_id = str(row[1])
        self.parent_hash = None if row[2] is None else str(row[2])
        self.created_at = int(row[3])
        self.expires_at = int(row[4])
        self.used_at = None if row[5] is None else int(row[5])
        self.replaced_by = None if row[6] is None else str(row[6])
        self.grace_replays = int(row[7])
