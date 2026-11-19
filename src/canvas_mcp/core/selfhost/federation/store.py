"""The database side of trusted issuers: the issuer list, links, accounts and federated grants.

Request path (:meth:`FederationStore.resolve`): a verified ``(issuer, claim, subject)`` is looked
up in ``federated_identities``, a namespace of its own (never a sign-in identity). Every request
checks the account's standing and the *current* admission policy: an identity the operator linked
is admitted, one that was made at its first token is admitted only while the policy (``open``,
``rules`` with ``federated:any``, ``approval``) still admits it. An unknown subject gets an
account under that policy exactly like a first sign-in, and an active account gets one *federated
grant* per issuer so that the per-grant machinery (snapshot, usage, tool gate, Canvas token
binding) works unchanged. The grant is not ended by disabling the account or by losing
admission, because both are checked on every request; only an explicit revoke-grant, an unlink
or removing the issuer ends it. Everything that writes runs in one serialised write
transaction, so two first requests of the same person make one account and one grant.

Accounts are never matched by e-mail address or name: only the operator's explicit ``link``.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from sqlalchemy import and_, delete, insert, select, update
from sqlalchemy.engine import Connection, Row

from .. import accounts as acc
from ..accounts import AccessPolicy, AccountFacts, DecisionFacts, Denied, ExternalClaims
from ..db import schema as s
from ..db.engine import Database
from ..db.repos import Repositories
from ..db.types import new_id
from ..token_store import (
    AUDIT_ACCOUNT_ACTIVATED,
    AUDIT_ACCOUNT_CREATED,
    OPERATOR_ACTOR,
    SYSTEM_ACTOR,
)
from .config import GRANT_PREFIX, TrustedIssuer

AUDIT_ISSUER_ADDED = "trusted_issuer_added"
AUDIT_ISSUER_REMOVED = "trusted_issuer_removed"
AUDIT_FEDERATED_LINKED = "federated_identity_linked"
AUDIT_FEDERATED_UNLINKED = "federated_identity_unlinked"
AUDIT_FEDERATED_GRANT = "federated_grant_created"

DENY_GRANT_ENDED = "federated_grant_ended"
GRANT_ENDED_MESSAGE = (
    "This connection was ended by a server administrator. Ask them to restore it."
)

_t = s.trusted_issuers
_i = s.federated_identities
_g = s.oauth_grants


class IssuerExists(Exception):
    """An issuer with this exact string is already configured."""


class LinkRefused(Exception):
    """A link or unlink the rules do not allow; the message is safe to show."""


@dataclass(frozen=True)
class Resolved:
    account_id: str
    grant_id: str


def _row_issuer(row: Row[Any]) -> TrustedIssuer:
    m = row._mapping
    return TrustedIssuer(
        issuer=m["issuer"],
        audience=m["audience"],
        jwks_url=m["jwks_url"],
        algorithms=tuple(m["algorithms"].split()),
        require_typ_at_jwt=bool(m["require_typ_at_jwt"]),
        subject_claim=m["subject_claim"],
        read_scope=m["read_scope"],
        write_scope=m["write_scope"],
        name=m["name"],
    )


class FederationStore:
    def __init__(
        self,
        db: Database,
        *,
        api_scope: str = "",
        audience: str = "",
        max_auth_age: int = 14 * 86400,
        clock: Callable[[], float] = time.time,
    ) -> None:
        # ``api_scope`` and ``audience`` are what a new federated grant records; only the
        # request path creates one, so the operator commands leave them empty.
        self._db = db
        self._repos = Repositories(db.kind)
        self._api_scope = api_scope
        self._audience = audience
        #: A grant lives as long as an upstream sign-in may (``max_upstream_auth_age``); a request
        #: renews it in its second half. Admission is checked on every request regardless.
        self._ttl = max(2, max_auth_age)
        self._clock = clock

    def _now(self) -> int:
        return int(self._clock())

    # -- the issuer list ------------------------------------------------------------------

    def list_issuers(self) -> list[TrustedIssuer]:
        with self._db.read() as conn:
            rows = conn.execute(select(_t).order_by(_t.c.issuer)).all()
        return [_row_issuer(row) for row in rows]

    def add_issuer(self, issuer: TrustedIssuer) -> None:
        now = self._now()
        with self._db.write() as conn:
            if conn.execute(
                select(_t.c.issuer).where(_t.c.issuer == issuer.issuer)
            ).first():
                raise IssuerExists
            conn.execute(
                insert(_t).values(
                    issuer=issuer.issuer,
                    name=issuer.name,
                    audience=issuer.audience,
                    jwks_url=issuer.jwks_url,
                    algorithms=" ".join(issuer.algorithms),
                    require_typ_at_jwt=issuer.require_typ_at_jwt,
                    subject_claim=issuer.subject_claim,
                    read_scope=issuer.read_scope,
                    write_scope=issuer.write_scope,
                    created_at=now,
                    updated_at=now,
                )
            )
            self._audit(conn, OPERATOR_ACTOR, AUDIT_ISSUER_ADDED, issuer.issuer, now)

    def remove_issuer(self, issuer: str) -> bool:
        """Remove an issuer and delete its federated grants. The links to accounts stay."""
        now = self._now()
        with self._db.write() as conn:
            gone = conn.execute(delete(_t).where(_t.c.issuer == issuer)).rowcount == 1
            if gone:
                conn.execute(delete(_g).where(_g.c.client_id == GRANT_PREFIX + issuer))
                self._audit(conn, OPERATOR_ACTOR, AUDIT_ISSUER_REMOVED, issuer, now)
            return gone

    def _audit(
        self,
        conn: Connection,
        actor: str,
        action: str,
        target: str,
        now: int,
        *,
        account_id: str | None = None,
        detail: dict[str, object] | None = None,
    ) -> None:
        self._repos.audit.append(
            conn,
            now=now,
            actor=actor,
            action=action,
            target=account_id or target,
            target_kind="account" if account_id else "issuer",
            subject_account_id=account_id,
            reason=None,
            detail=({"issuer": target} if account_id else {}) | (detail or {}),
        )

    # -- links (operator) -----------------------------------------------------------------

    def link(self, account_id: str, issuer: str, subject: str) -> bool:
        """Attach ``subject`` of ``issuer`` to an existing account. False if it already was."""
        now = self._now()
        with self._db.write() as conn:
            claim = conn.execute(
                select(_t.c.subject_claim).where(_t.c.issuer == issuer)
            ).scalar_one_or_none()
            if claim is None:
                raise LinkRefused("no such trusted issuer; add it first")
            if self._repos.accounts.get(conn, account_id) is None:
                raise LinkRefused("no such account")
            row = conn.execute(
                select(_i.c.account_id, _i.c.operator_linked).where(
                    _i.c.issuer == issuer, _i.c.claim == claim, _i.c.subject == subject
                )
            ).one_or_none()
            if row is not None and row.account_id != account_id:
                raise LinkRefused("this identity already belongs to another account")
            if row is not None and row.operator_linked:
                return False
            if row is None:
                conn.execute(
                    insert(_i).values(
                        issuer=issuer,
                        claim=claim,
                        subject=subject,
                        account_id=account_id,
                        operator_linked=True,
                        created_at=now,
                    )
                )
            else:  # made at its first token, now explicitly the operator's
                conn.execute(
                    update(_i)
                    .where(
                        _i.c.issuer == issuer,
                        _i.c.claim == claim,
                        _i.c.subject == subject,
                    )
                    .values(operator_linked=True)
                )
            self._audit(
                conn,
                OPERATOR_ACTOR,
                AUDIT_FEDERATED_LINKED,
                issuer,
                now,
                account_id=account_id,
            )
            return True

    def unlink(self, issuer: str, subject: str) -> bool:
        """Detach ``subject`` of ``issuer`` and delete its federated grant."""
        now = self._now()
        with self._db.write() as conn:
            owners = {
                r.account_id
                for r in conn.execute(
                    select(_i.c.account_id).where(
                        _i.c.issuer == issuer, _i.c.subject == subject
                    )
                )
            }
            if not owners:
                return False
            conn.execute(
                delete(_i).where(_i.c.issuer == issuer, _i.c.subject == subject)
            )
            for owner in owners:
                conn.execute(
                    delete(_g).where(
                        _g.c.account_id == owner,
                        _g.c.client_id == GRANT_PREFIX + issuer,
                    )
                )
                self._audit(
                    conn,
                    OPERATOR_ACTOR,
                    AUDIT_FEDERATED_UNLINKED,
                    issuer,
                    now,
                    account_id=owner,
                )
            return True

    def links(self, account_id: str | None = None) -> list[tuple[str, str, str, str]]:
        """``(account, issuer, subject, "linked"|"created")`` for each trusted issuer's current claim."""
        stmt = (
            select(_i.c.account_id, _i.c.issuer, _i.c.subject, _i.c.operator_linked)
            .join(
                _t, and_(_t.c.issuer == _i.c.issuer, _t.c.subject_claim == _i.c.claim)
            )
            .order_by(_i.c.issuer, _i.c.subject)
        )
        if account_id is not None:
            stmt = stmt.where(_i.c.account_id == account_id)
        with self._db.read() as conn:
            return [
                (r[0], r[1], r[2], "linked" if r[3] else "created")
                for r in conn.execute(stmt)
            ]

    # -- the request path -----------------------------------------------------------------

    def resolve(
        self, issuer: TrustedIssuer, subject: str, policy: AccessPolicy
    ) -> Resolved | Denied:
        """The account and grant of a verified token, creating them when the policy admits."""
        ext = ExternalClaims(
            provider_id=acc.PROVIDER_FEDERATED,
            issuer=issuer.issuer,
            subject=subject,
            display_name="via " + issuer.label,
        )
        verdict = acc.evaluate_admission(ext, policy)
        now = self._now()
        with self._db.read() as conn:
            known = self._known(conn, issuer, subject)
        if known is not None:
            account, linked, grant = known
            refusal, activate = self._standing(account, linked, verdict, policy)
            if refusal is not None:
                return refusal
            if (
                not activate
                and grant is not None
                and grant.revoked_at is None
                and grant.expires_at - now > self._ttl // 2
            ):
                return Resolved(account.id, grant.id)
        return self._admit(issuer, subject, ext, verdict, policy)

    @staticmethod
    def _standing(
        account: Any, linked: bool, verdict: acc.Verdict, policy: AccessPolicy
    ) -> tuple[Denied | None, bool]:
        """``(refusal, activate)``: may this existing account be served now, under today's policy?"""
        if account.status == acc.STATUS_DISABLED:
            return acc.denied(acc.DENY_ACCESS_DISABLED), False
        facts = AccountFacts(account.status, admitted_via=account.admitted_via)
        if account.status == acc.STATUS_PENDING:
            decision = acc.decide(facts, verdict, policy, DecisionFacts(), "sign_in")
            if not decision.activate:
                return acc.denied(acc.DENY_PENDING_APPROVAL), False
            return None, True
        if not linked and not acc.link_admissible(facts, verdict, policy):
            return Denied(acc.DENY_ACCESS_DENIED, acc.NEUTRAL_ACCESS_DENIED), False
        return None, False

    def _known(
        self, conn: Connection, issuer: TrustedIssuer, subject: str
    ) -> tuple[Any, bool, Any] | None:
        row = conn.execute(
            select(_i.c.account_id, _i.c.operator_linked).where(
                _i.c.issuer == issuer.issuer,
                _i.c.claim == issuer.subject_claim,
                _i.c.subject == subject,
            )
        ).one_or_none()
        if row is None:
            return None
        account = self._repos.accounts.get(conn, row.account_id)
        if account is None:  # pragma: no cover - the identity cascades with its account
            return None
        grant = conn.execute(
            select(_g.c.id, _g.c.revoked_at, _g.c.expires_at).where(
                _g.c.account_id == row.account_id,
                _g.c.client_id == issuer.grant_client_id,
            )
        ).one_or_none()
        return account, bool(row.operator_linked), grant

    def _admit(
        self,
        issuer: TrustedIssuer,
        subject: str,
        ext: ExternalClaims,
        verdict: acc.Verdict,
        policy: AccessPolicy,
    ) -> Resolved | Denied:
        now = self._now()
        repos = self._repos
        with self._db.write() as conn:
            row = conn.execute(
                select(_i.c.account_id, _i.c.operator_linked).where(
                    _i.c.issuer == issuer.issuer,
                    _i.c.claim == issuer.subject_claim,
                    _i.c.subject == subject,
                )
            ).one_or_none()
            if row is None:
                decision = acc.decide(
                    None,
                    verdict,
                    policy,
                    DecisionFacts(pending_count=repos.accounts.count_pending(conn)),
                    "sign_in",
                )
                if decision.outcome == "deny" or not decision.create:
                    refusal = decision.denied or acc.denied(acc.DENY_ACCESS_DENIED)
                    if refusal.code == acc.DENY_ACCESS_DENIED:
                        return Denied(refusal.code, acc.NEUTRAL_ACCESS_DENIED)
                    return refusal
                account_id = self._create_account(conn, issuer, ext, decision, now)
                if decision.outcome == "pending":
                    return acc.denied(acc.DENY_PENDING_APPROVAL)
            else:
                account_id = row.account_id
                account = repos.accounts.get(conn, account_id, for_update=True)
                assert account is not None
                standing, activate = self._standing(
                    account, bool(row.operator_linked), verdict, policy
                )
                if standing is not None:
                    return standing
                if activate:
                    decision = acc.decide(
                        AccountFacts(account.status, admitted_via=account.admitted_via),
                        verdict,
                        policy,
                        DecisionFacts(),
                        "sign_in",
                    )
                    repos.accounts.activate(
                        conn,
                        account_id,
                        admitted_via=decision.admitted_via or acc.ADMITTED_RULES,
                        approved_by=None,
                        now=now,
                    )
                    self._audit(
                        conn,
                        SYSTEM_ACTOR,
                        AUDIT_ACCOUNT_ACTIVATED,
                        issuer.issuer,
                        now,
                        account_id=account_id,
                        detail={"admitted_via": decision.admitted_via or ""},
                    )
            grant = self._ensure_grant(conn, issuer, account_id, now)
            if grant is None:
                return Denied(DENY_GRANT_ENDED, GRANT_ENDED_MESSAGE)
            return Resolved(account_id, grant)

    def _create_account(
        self,
        conn: Connection,
        issuer: TrustedIssuer,
        ext: ExternalClaims,
        decision: acc.Decision,
        now: int,
    ) -> str:
        account_id = new_id()
        self._repos.accounts.insert(
            conn,
            account_id=account_id,
            status=decision.create_status or acc.STATUS_ACTIVE,
            role=acc.ROLE_USER,
            role_source=None,
            admitted_via=decision.admitted_via or acc.ADMITTED_RULES,
            display_name=ext.display_name[:200],
            now=now,
        )
        conn.execute(
            insert(_i).values(
                issuer=issuer.issuer,
                claim=issuer.subject_claim,
                subject=ext.subject,
                account_id=account_id,
                operator_linked=False,
                created_at=now,
            )
        )
        self._audit(
            conn,
            SYSTEM_ACTOR,
            AUDIT_ACCOUNT_CREATED,
            ext.issuer,
            now,
            account_id=account_id,
            detail={
                "status": decision.create_status or acc.STATUS_ACTIVE,
                "admitted_via": decision.admitted_via or "",
                "provider": acc.PROVIDER_FEDERATED,
            },
        )
        return account_id

    def _ensure_grant(
        self, conn: Connection, issuer: TrustedIssuer, account_id: str, now: int
    ) -> str | None:
        """The one federated grant of this account and issuer; None when it was ended."""
        row = conn.execute(
            select(_g.c.id, _g.c.revoked_at, _g.c.expires_at).where(
                _g.c.account_id == account_id, _g.c.client_id == issuer.grant_client_id
            )
        ).one_or_none()
        if row is not None:
            if row.revoked_at is not None:
                return None  # an explicit revoke-grant is final
            if row.expires_at - now <= self._ttl // 2:
                conn.execute(
                    update(_g)
                    .where(_g.c.id == row.id)
                    .values(expires_at=now + self._ttl, upstream_auth_at=now)
                )
            return str(row.id)
        grant_id = new_id()
        # Writers are serialised, and the unique index on (account, client) is the backstop.
        self._repos.grants.insert(
            conn,
            id=grant_id,
            account_id=account_id,
            client_id=issuer.grant_client_id,
            client_kind="dcr",
            client_name=issuer.label,
            client_host=None,
            redirect_host="",
            scopes=self._api_scope,
            resource=self._audience,
            created_at=now,
            last_used_at=now,
            upstream_auth_at=now,
            expires_at=now + self._ttl,
        )
        self._audit(
            conn,
            SYSTEM_ACTOR,
            AUDIT_FEDERATED_GRANT,
            issuer.issuer,
            now,
            account_id=account_id,
        )
        return grant_id
