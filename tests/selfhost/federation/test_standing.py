"""Admission is checked on every request; routine revocations do not end a federated grant;
keys are fetched only from where they may be; federated identities have a namespace of their own.
"""

from __future__ import annotations

from dataclasses import replace

from sqlalchemy import text

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.accounts import AccessRule
from canvas_mcp.core.selfhost.token_store import OPERATOR

from ..authz.stack import ALICE, AUDIENCE
from .issuer import ISSUER, FakeIssuer
from .test_accounts import refusal_of


def set_policy(hub, **changes):
    hub.federation.policy = replace(hub.federation.policy, **changes)


def grant_row(hub):
    with hub.stack.store.database.read() as conn:
        return conn.execute(
            text(
                "SELECT id, revoked_at, expires_at, upstream_auth_at FROM oauth_grants "
                "WHERE client_id LIKE 'federated:%'"
            )
        ).one()


class TestAdmissionIsRechecked:
    def test_a_person_the_policy_no_longer_admits_is_refused(self, open_hub):
        open_hub.trust()
        assert open_hub.status(open_hub.issuer.mint()) == 200
        set_policy(
            open_hub,
            mode=acc.POLICY_RULES,
            rules=(AccessRule("entra", "role", "Canvas.User"),),
        )
        assert "not allowed to use this server" in refusal_of(
            open_hub.call(open_hub.issuer.mint())
        )
        # A rule that names the issuer's people admits them again, with the same account.
        set_policy(open_hub, rules=(AccessRule("federated", "any", ""),))
        assert open_hub.status(open_hub.issuer.mint()) == 200
        assert len(open_hub.accounts()) == 1 and len(open_hub.grants()) == 1

    def test_a_linked_person_stays_admitted_whatever_the_rules_say(self, open_hub):
        open_hub.trust()
        alice = open_hub.stack.enroll(ALICE)
        open_hub.federation.store.link(alice, ISSUER, "hub-alice")
        set_policy(
            open_hub,
            mode=acc.POLICY_RULES,
            rules=(AccessRule("entra", "role", "Canvas.User"),),
        )
        assert open_hub.status(open_hub.issuer.mint(sub="hub-alice")) == 200

    def test_the_grant_is_bounded_by_the_upstream_auth_age_and_renewed(self, open_hub):
        open_hub.trust()
        assert open_hub.status(open_hub.issuer.mint()) == 200
        age = open_hub.stack.settings.authz.max_upstream_auth_age
        row = grant_row(open_hub)
        now = int(open_hub.stack.clock())
        assert row.expires_at - now <= age
        open_hub.stack.clock.advance(
            age * 0.6
        )  # past half of its life: a request renews it
        assert open_hub.status(open_hub.issuer.mint()) == 200
        renewed = grant_row(open_hub)
        assert (
            renewed.expires_at > row.expires_at
            and renewed.upstream_auth_at > row.upstream_auth_at
        )
        open_hub.stack.clock.advance(
            age * 3
        )  # a long silence: the next token still works
        assert open_hub.status(open_hub.issuer.mint()) == 200


class TestRoutineRevocationsDoNotEndIt:
    def test_losing_admission_and_disabling_leave_the_grant_in_place(self, open_hub):
        open_hub.trust()
        assert open_hub.status(open_hub.issuer.mint()) == 200
        (account,) = open_hub.accounts()
        authz = open_hub.stack.authz.store
        authz.revoke_all_for_account(account, reason="admission_lost")
        assert grant_row(open_hub).revoked_at is None
        assert (
            open_hub.status(open_hub.issuer.mint()) == 200
        )  # still admitted: nothing to redo
        open_hub.stack.store.disable_principal(
            account, actor=OPERATOR, reason="operator_disabled"
        )
        assert grant_row(open_hub).revoked_at is None
        assert "disabled by an administrator" in refusal_of(
            open_hub.call(open_hub.issuer.mint())
        )
        open_hub.stack.store.enable_principal(account, actor=OPERATOR)
        assert open_hub.status(open_hub.issuer.mint()) == 200

    def test_an_explicit_revoke_is_final_even_while_the_account_is_disabled(
        self, open_hub
    ):
        open_hub.trust()
        assert open_hub.status(open_hub.issuer.mint()) == 200
        (account,) = open_hub.accounts()
        grant = str(grant_row(open_hub).id)
        open_hub.stack.store.disable_principal(
            account, actor=OPERATOR, reason="operator_disabled"
        )
        assert open_hub.stack.authz.store.operator_revoke_grant(grant) is True
        open_hub.stack.store.enable_principal(account, actor=OPERATOR)
        assert "ended by a server administrator" in refusal_of(
            open_hub.call(open_hub.issuer.mint())
        )


class TestWhereKeysComeFrom:
    def test_a_remote_jwks_uri_is_never_followed_off_the_issuers_origin(self, open_hub):
        open_hub.trust()
        for uri in ("http://127.0.0.1:9/jwks", "https://other.example.test/jwks.json"):
            open_hub.issuer.jwks_uri = uri
            open_hub.stack.clock.advance(7200)  # past the metadata cache
            assert open_hub.status(open_hub.issuer.mint()) == 401
        assert not [path for path in open_hub.issuer.log if "jwks" in path]
        assert open_hub.accounts() == []

    def test_only_the_loopback_client_may_call_localhost(self, open_hub):
        assert open_hub.federation.http._allow_loopback is False
        assert open_hub.federation.verifier.loopback_http._allow_loopback is True

    def test_a_localhost_issuer_is_served_by_the_loopback_client_only(self, open_hub):
        local = FakeIssuer(
            open_hub.stack.clock, issuer="http://localhost:9099", audience=AUDIENCE
        )
        open_hub.federation.verifier.loopback_http._transport = local.transport
        from canvas_mcp.core.selfhost.federation.config import build_issuer

        open_hub.federation.store.add_issuer(build_issuer(local.issuer))
        open_hub.federation.reload()
        assert open_hub.status(local.mint()) == 200
        assert local.fetches() == 1
        # The ordinary client is not used for it.
        assert open_hub.issuer.log == []


class TestOwnNamespace:
    def test_a_subject_equal_to_a_sign_in_subject_does_not_reach_that_account(
        self, open_hub
    ):
        alice = open_hub.stack.enroll(ALICE)
        # An issuer whose iss and subject are exactly Alice's Entra sign-in identity.
        with open_hub.stack.store.database.read() as conn:
            issuer, subject = conn.execute(
                text(
                    "SELECT issuer, subject FROM external_identity_owners WHERE account_id = :a"
                ),
                {"a": alice},
            ).one()
        lookalike = FakeIssuer(open_hub.stack.clock, issuer=issuer, audience=AUDIENCE)
        open_hub.federation.http._transport = lookalike.transport
        from canvas_mcp.core.selfhost.federation.config import build_issuer

        open_hub.federation.store.add_issuer(build_issuer(issuer))
        open_hub.federation.reload()
        assert open_hub.status(lookalike.mint(sub=subject)) == 200
        ((owner, _),) = open_hub.grants()
        assert owner != alice  # a new account, not Alice's
        assert len(open_hub.accounts()) == 2

    def test_the_same_subject_in_another_claim_is_another_person(self, open_hub):
        open_hub.trust(subject_claim="uid")
        assert open_hub.status(open_hub.issuer.mint(uid="42")) == 200
        (first,) = open_hub.accounts()
        # The operator switches the claim: "42" under `sub` is not the person of `uid` 42.
        open_hub.federation.store.remove_issuer(ISSUER)
        open_hub.trust(subject_claim="sub")
        assert open_hub.status(open_hub.issuer.mint(sub="42")) == 200
        assert len(open_hub.accounts()) == 2 and first in open_hub.accounts()
