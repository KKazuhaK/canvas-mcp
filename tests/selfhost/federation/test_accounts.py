"""Who a verified token belongs to: account creation under each admission mode, links, standing."""

from __future__ import annotations

import json
import threading

import pytest
from sqlalchemy import text

from canvas_mcp.core.selfhost.federation.store import FederationStore
from canvas_mcp.core.selfhost.token_store import OPERATOR

from ..authz.stack import ALICE, BASE
from .issuer import ISSUER


def result_of(response):
    """``(is_error, text)`` of a tools/call answered with 200."""
    assert response.status_code == 200, response.text
    body = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        body = [ln[5:].strip() for ln in body.splitlines() if ln.startswith("data:")][
            -1
        ]
    result = json.loads(body)["result"]
    return bool(result.get("isError")), "".join(
        b.get("text", "") for b in result["content"]
    )


def refusal_of(response):
    assert response.status_code == 403, (response.status_code, response.text)
    return response.json()["error"]


def status_of(hub, account: str) -> str:
    with hub.stack.store.database.read() as conn:
        return str(
            conn.execute(
                text("SELECT status FROM accounts WHERE id = :id"), {"id": account}
            ).scalar_one()
        )


class TestAdmission:
    def test_open_creates_an_active_account_and_one_grant(self, open_hub):
        open_hub.trust()
        assert open_hub.status(open_hub.issuer.mint()) == 200
        (account,) = open_hub.accounts()
        assert status_of(open_hub, account) == "active"
        assert open_hub.grants() == [(account, "federated:" + ISSUER)]
        # The second request reuses both.
        assert open_hub.status(open_hub.issuer.mint()) == 200
        assert open_hub.accounts() == [account] and len(open_hub.grants()) == 1

    def test_rules_without_a_rule_for_it_admit_nobody_new(self, hub):
        hub.trust()
        message = refusal_of(hub.call(hub.issuer.mint()))
        assert "not allowed to use this server" in message
        assert "Microsoft" not in message
        assert hub.accounts() == [] and hub.grants() == []

    def test_a_federated_any_rule_admits_the_issuers_people(self, hub_factory):
        hub = hub_factory(
            {
                "ACCESS_POLICY": "rules",
                "ACCESS_RULES": "entra:role:Canvas.User,federated:any",
            }
        )
        hub.trust()
        assert hub.status(hub.issuer.mint()) == 200
        (account,) = hub.accounts()
        assert status_of(hub, account) == "active"

    def test_rules_with_the_approval_fallback_leave_it_pending(self, hub_factory):
        hub = hub_factory({"ACCESS_POLICY": "rules", "ACCESS_FALLBACK": "approval"})
        hub.trust()
        message = refusal_of(hub.call(hub.issuer.mint()))
        assert "waiting for approval" in message
        (account,) = hub.accounts()
        assert status_of(hub, account) == "pending" and hub.grants() == []

    def test_approval_mode_leaves_it_pending_until_approved(self, hub_factory):
        hub = hub_factory({"ACCESS_POLICY": "approval"})
        hub.trust()
        assert "waiting for approval" in refusal_of(hub.call(hub.issuer.mint()))
        (account,) = hub.accounts()
        # Asking again does not make a second account.
        assert "waiting for approval" in refusal_of(hub.call(hub.issuer.mint()))
        assert hub.accounts() == [account]
        assert hub.stack.store.approve_account(account, actor=OPERATOR)
        assert hub.status(hub.issuer.mint()) == 200
        assert hub.grants() == [(account, "federated:" + ISSUER)]

    def test_a_pending_account_of_an_open_server_is_activated(self, open_hub):
        open_hub.trust()
        # An account that was left pending (say under approval mode) and is now admitted.
        assert open_hub.status(open_hub.issuer.mint()) == 200
        (account,) = open_hub.accounts()
        with open_hub.stack.store.database.write() as conn:
            conn.execute(
                text("UPDATE accounts SET status = 'pending' WHERE id = :id"),
                {"id": account},
            )
        assert open_hub.status(open_hub.issuer.mint()) == 200
        assert status_of(open_hub, account) == "active"


class TestStanding:
    def test_a_suspended_account_is_refused_at_once_and_restored_on_enabling(
        self, open_hub
    ):
        open_hub.trust()
        assert open_hub.status(open_hub.issuer.mint()) == 200
        (account,) = open_hub.accounts()
        open_hub.stack.store.disable_principal(
            account, actor=OPERATOR, reason="operator_disabled"
        )
        message = refusal_of(open_hub.call(open_hub.issuer.mint()))
        assert "disabled by an administrator" in message
        assert open_hub.stack.store.enable_principal(account, actor=OPERATOR)
        assert open_hub.status(open_hub.issuer.mint()) == 200
        assert len(open_hub.grants()) == 1  # the same grant came back

    def test_a_grant_the_operator_ended_stays_ended(self, open_hub):
        open_hub.trust()
        assert open_hub.status(open_hub.issuer.mint()) == 200
        ((account, client),) = open_hub.grants()
        with open_hub.stack.store.database.write() as conn:
            grant = conn.execute(
                text("SELECT id FROM oauth_grants WHERE client_id = :c"), {"c": client}
            ).scalar_one()
        assert open_hub.stack.authz.store.operator_revoke_grant(str(grant))
        assert "ended by a server administrator" in refusal_of(
            open_hub.call(open_hub.issuer.mint())
        )
        assert open_hub.accounts() == [account]

    def test_removing_the_issuer_deletes_its_connections_and_keeps_the_links(
        self, open_hub
    ):
        open_hub.trust()
        assert open_hub.status(open_hub.issuer.mint()) == 200
        assert open_hub.federation.store.remove_issuer(ISSUER)
        open_hub.federation.reload()
        assert open_hub.status(open_hub.issuer.mint()) == 401
        assert open_hub.grants() == []
        assert (
            len(open_hub.federation.store.links()) == 0
        )  # not listed without the issuer
        # Trusting it again restores the person with a fresh connection, on the same account.
        (account,) = open_hub.accounts()
        open_hub.trust()
        assert open_hub.status(open_hub.issuer.mint()) == 200
        assert open_hub.accounts() == [account]
        assert [owner for owner, _ in open_hub.grants()] == [account]


class TestLinks:
    def test_a_linked_account_is_the_one_the_token_acts_for(self, open_hub):
        open_hub.trust()
        alice = open_hub.stack.enroll(ALICE)
        assert open_hub.federation.store.link(alice, ISSUER, "hub-alice")
        is_error, answer = result_of(
            open_hub.call(open_hub.issuer.mint(sub="hub-alice"))
        )
        assert not is_error and answer == alice
        assert open_hub.accounts() == [alice]  # no second account

    def test_an_email_address_never_finds_an_account(self, open_hub):
        open_hub.trust()
        alice = open_hub.stack.enroll(ALICE)
        token = open_hub.issuer.mint(
            sub="hub-stranger",
            email="alice@example.test",
            preferred_username="alice@example.test",
            name="Alice",
        )
        assert open_hub.status(token) == 200
        # A new account, which has no Canvas token yet; Alice's account has no federated grant.
        assert len(open_hub.accounts()) == 2
        ((owner, _),) = open_hub.grants()
        assert owner != alice

    def test_linking_twice_and_across_accounts(self, open_hub):
        open_hub.trust()
        store = open_hub.federation.store
        alice = open_hub.stack.enroll(ALICE)
        assert store.link(alice, ISSUER, "s-1") is True
        assert store.link(alice, ISSUER, "s-1") is False
        from ..authz.stack import BOB

        bob = open_hub.stack.enroll(BOB)
        from canvas_mcp.core.selfhost.federation.store import LinkRefused

        with pytest.raises(LinkRefused, match="another account"):
            store.link(bob, ISSUER, "s-1")
        with pytest.raises(LinkRefused, match="no such trusted issuer"):
            store.link(bob, "https://other.example", "s-1")
        with pytest.raises(LinkRefused, match="no such account"):
            store.link("11111111-1111-4111-8111-111111111111", ISSUER, "s-2")

    def test_unlinking_ends_the_connection_and_leaves_sign_in_methods_alone(
        self, open_hub
    ):
        open_hub.trust()
        store = open_hub.federation.store
        alice = open_hub.stack.enroll(ALICE)
        store.link(alice, ISSUER, "hub-alice")
        assert open_hub.status(open_hub.issuer.mint(sub="hub-alice")) == 200
        assert len(open_hub.grants()) == 1
        assert store.unlink(ISSUER, "hub-alice") is True
        assert store.unlink(ISSUER, "hub-alice") is False
        assert open_hub.grants() == []  # the connection went with the link
        # The subject is a stranger again: under the open policy it gets an account of its own.
        assert open_hub.status(open_hub.issuer.mint(sub="hub-alice")) == 200
        assert len(open_hub.accounts()) == 2
        assert open_hub.federation.store.links(alice) == []
        assert [owner for owner, _ in open_hub.grants()] != [alice]
        # Alice's Entra sign-in is intact.
        assert open_hub.stack.account_of(ALICE) == alice


class TestFirstTokenRace:
    def test_two_first_requests_make_one_account_and_one_grant(self, open_hub):
        issuer = open_hub.trust()
        stores = [
            open_hub.federation.store,
            FederationStore(
                open_hub.stack.store.database,
                api_scope=open_hub.stack.settings.api_scope,
                audience=open_hub.stack.settings.mcp_url,
                clock=open_hub.stack.clock,
            ),
        ]
        barrier = threading.Barrier(len(stores))
        results: list[object] = []

        def first(store):
            barrier.wait()
            results.append(store.resolve(issuer, "racer", open_hub.federation.policy))

        threads = [threading.Thread(target=first, args=(s,)) for s in stores]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert len(results) == 2
        assert {r.account_id for r in results} == set(open_hub.accounts())
        assert len(open_hub.accounts()) == 1
        assert len(open_hub.grants()) == 1
        assert len({r.grant_id for r in results}) == 1

    def test_two_first_tokens_over_http(self, open_hub):
        open_hub.trust()
        tokens = [open_hub.issuer.mint(sub="racer") for _ in range(2)]
        barrier = threading.Barrier(2)
        codes: list[int] = []

        def go(token):
            barrier.wait()
            codes.append(open_hub.status(token))

        threads = [threading.Thread(target=go, args=(t,)) for t in tokens]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert codes == [200, 200]
        assert len(open_hub.accounts()) == 1 and len(open_hub.grants()) == 1


class TestCanvasToken:
    def test_without_a_bound_canvas_token_every_tool_says_where_to_bind_it(
        self, open_hub
    ):
        open_hub.trust()
        is_error, answer = result_of(open_hub.call(open_hub.issuer.mint()))
        assert is_error
        assert "No Canvas access token is enrolled for your account" in answer
        assert f"{BASE}/account" in answer

    def test_with_a_bound_canvas_token_the_tool_runs(self, open_hub):
        open_hub.trust()
        alice = open_hub.stack.enroll(ALICE)
        open_hub.federation.store.link(alice, ISSUER, "hub-alice")
        is_error, answer = result_of(
            open_hub.call(open_hub.issuer.mint(sub="hub-alice"))
        )
        assert (is_error, answer) == (False, alice)
