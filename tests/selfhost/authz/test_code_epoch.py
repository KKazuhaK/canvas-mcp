"""An authorization code is bound to the session epoch of the /account session that approved it.

Disabling an account, enabling it again and ``admission_lost`` all raise ``session_epoch``, so a
code approved before any of them is dead, whenever it was approved and whatever the timing
(the races are in ``test_authz_races.py``). Store level first, then the whole stack on the
server-rendered pages and on the single-page UI's JSON API.
"""

from __future__ import annotations

import asyncio
from dataclasses import replace
from typing import Any

import pytest
from dbbackend import raw_sql

from canvas_mcp.core.selfhost.authz import tokens as tk
from canvas_mcp.core.selfhost.authz.consent import ConsentRedirect, ConsentRefusal
from canvas_mcp.core.selfhost.authz.models import ExchangeOutcome as X
from canvas_mcp.core.selfhost.authz.store import AuthzStore
from canvas_mcp.core.selfhost.db.authz_repos import SqlAuthCodeRepo
from canvas_mcp.core.selfhost.token_store import OPERATOR

from .helpers import CHALLENGE, CLIENT, REDIRECT, RESOURCE, SCOPE, Env, make_env
from .stack import (
    ALICE,
    AUDIENCE,
    CLAUDE_REDIRECT,
    Browser,
    Stack,
    pkce,
)
from .test_authz_flows import start_request


@pytest.fixture
def env(tmp_path, keyring, clock) -> Env:
    return make_env(tmp_path, keyring, clock)


def sql(env: Env, statement: str, **params: Any):
    return raw_sql(env.tokens, statement, params)


def disable_and_enable(env: Env) -> None:
    assert env.tokens.disable_principal(env.account_key, actor=OPERATOR, reason="operator_disabled")
    assert env.tokens.enable_principal(env.account_key, actor=OPERATOR)


def insert_code_directly(env: Env, *, session_epoch: int) -> str:
    """What a racing approval leaves behind: a code row, whatever the account's epoch is now."""
    raw = tk.new_auth_code()
    now = int(env.clock())
    with env.authz.database.row_write() as conn:
        env.authz._repos.codes.insert(
            conn, code_hash=tk.hash_secret(raw), client_id=CLIENT, account_id=env.account_id,
            redirect_uri=REDIRECT, redirect_uri_explicit=1, code_challenge=CHALLENGE, scopes=SCOPE,
            resource=RESOURCE, client_kind="dcr", client_name="App", client_host=None,
            redirect_host="claude.ai", upstream_auth_at=now, session_epoch=session_epoch,
            created_at=now, expires_at=now + 300,
        )
    return raw


class TestStore:
    def test_the_code_stores_the_epoch_of_the_session_that_approved_it(self, env: Env) -> None:
        epoch = env.epoch()
        record = env.authz.load_code(tk.hash_secret(env.new_code()))
        assert record is not None and record.session_epoch == epoch
        disable_and_enable(env)
        assert env.epoch() == epoch + 2
        later = env.authz.load_code(tk.hash_secret(env.new_code()))
        assert later is not None and later.session_epoch == epoch + 2

    def test_the_normal_flow_still_works(self, env: Env) -> None:
        result, refresh, _ = env.exchange(env.new_code())
        assert result.outcome is X.WON and result.refresh_issued and refresh is not None
        assert env.rotate(refresh)[0].outcome.value == "rotated"

    def test_a_stale_session_cannot_create_a_code(self, env: Env) -> None:
        old = env.epoch()
        disable_and_enable(env)
        with pytest.raises(AssertionError):  # the helper asserts that create_code said yes
            env.new_code(session_epoch=old)
        assert sql(env, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0
        assert sql(env, "SELECT COUNT(*) FROM auth_events WHERE reason = 'consent_granted'")[0][0] == 0
        env.new_code(session_epoch=env.epoch())  # a session signed in after the enablement can

    def test_a_session_that_ended_by_admission_lost_cannot_create_a_code_either(self, env: Env) -> None:
        old = env.epoch()
        env.authz.revoke_all_for_account(env.account_key, reason="admission_lost")
        with pytest.raises(AssertionError):
            env.new_code(session_epoch=old)
        assert sql(env, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0

    def test_a_session_from_the_future_cannot_create_a_code(self, env: Env) -> None:
        with pytest.raises(AssertionError):
            env.new_code(session_epoch=env.epoch() + 1)

    def test_approve_then_disable_then_enable_then_exchange_is_refused(self, env: Env) -> None:
        raw = env.new_code()
        disable_and_enable(env)
        # the account is active again, and the cleanup of admission_lost never ran
        assert sql(env, "SELECT status FROM accounts WHERE id = :a", a=env.account_id)[0][0] == "active"
        result, _, _ = env.exchange(raw)
        assert result.outcome is X.INACTIVE and result.grant is None
        assert sql(env, "SELECT COUNT(*) FROM oauth_grants")[0][0] == 0
        assert env.exchange(raw)[0].outcome is X.DEAD  # burned
        # a code approved after the enablement is fine
        assert env.exchange(env.new_code())[0].outcome is X.WON

    def test_approve_then_admission_lost_then_exchange_is_refused_even_if_the_cleanup_missed_it(
        self, env: Env
    ) -> None:
        raw = env.new_code()
        env.authz.revoke_all_for_account(env.account_key, reason="admission_lost")
        assert env.authz.load_code(tk.hash_secret(raw)) is None  # the cleanup removed it
        # a code that an approval inserted just after the cleanup, in the epoch before the loss
        late = insert_code_directly(env, session_epoch=env.epoch() - 1)
        assert env.authz.load_code(tk.hash_secret(late)) is not None
        assert sql(env, "SELECT status FROM accounts WHERE id = :a", a=env.account_id)[0][0] == "active"
        result, _, _ = env.exchange(late)
        assert result.outcome is X.INACTIVE and result.grant is None
        assert sql(env, "SELECT COUNT(*) FROM oauth_grants")[0][0] == 0
        assert env.exchange(env.new_code())[0].outcome is X.WON

    def test_a_code_of_the_current_epoch_inserted_directly_is_redeemable(self, env: Env) -> None:
        assert env.exchange(insert_code_directly(env, session_epoch=env.epoch()))[0].outcome is X.WON

    def test_a_replay_inside_the_window_does_not_mint_a_sibling_once_the_epoch_moved(self, env: Env) -> None:
        raw = env.new_code()
        first, refresh, _ = env.exchange(raw)
        assert first.outcome is X.WON and refresh is not None
        assert env.exchange(raw)[0].outcome is X.GRACE  # a benign duplicate gets its sibling
        tokens_before = sql(env, "SELECT COUNT(*) FROM oauth_refresh_tokens")[0][0]
        # The epoch moves without the grant being revoked: not something the application does
        # (disabling and admission_lost revoke the grants in the same transaction), forced here
        # to show that the replay path applies the same rule as the first exchange.
        sql(env, "UPDATE accounts SET session_epoch = session_epoch + 1 WHERE id = :a", a=env.account_id)
        result, again, _ = env.exchange(raw)
        assert result.outcome is X.INACTIVE and not result.refresh_issued
        assert sql(env, "SELECT COUNT(*) FROM oauth_refresh_tokens")[0][0] == tokens_before
        assert again is not None

    @pytest.mark.parametrize("via", ["disable", "disable_and_enable", "admission_lost"])
    def test_a_replay_after_the_session_ended_gets_nothing_because_the_grant_is_revoked(
        self, env: Env, via: str
    ) -> None:
        raw = env.new_code()
        grant = env.exchange(raw)[0].grant
        assert grant is not None
        if via == "admission_lost":
            env.authz.revoke_all_for_account(env.account_key, reason="admission_lost")
        else:
            assert env.tokens.disable_principal(env.account_key, actor=OPERATOR, reason="operator_disabled")
            if via == "disable_and_enable":
                assert env.tokens.enable_principal(env.account_key, actor=OPERATOR)
        tokens_before = sql(env, "SELECT COUNT(*) FROM oauth_refresh_tokens")[0][0]
        result, _, _ = env.exchange(raw)
        assert result.outcome is X.DEAD and not result.refresh_issued  # lock_live: the grant is revoked
        assert sql(env, "SELECT COUNT(*) FROM oauth_refresh_tokens")[0][0] == tokens_before
        assert not env.authz.grant_status(grant.id).usable(int(env.clock()))

    def test_what_does_not_move_the_epoch_does_not_kill_codes(self, env: Env) -> None:
        raw = env.new_code()
        epoch = env.epoch()
        with env.authz.database.write() as conn:  # a role change, as the rules or the CLI make it
            env.authz._repos.accounts.set_role(
                conn, env.account_id, role="owner", source="operator", seen_at=None, now=int(env.clock())
            )
        assert env.epoch() == epoch
        assert env.exchange(raw)[0].outcome is X.WON


# ---------------------------------------------------------------------------- the whole stack


@pytest.fixture(params=["html", "react"])
def any_stack(request: pytest.FixtureRequest) -> Stack:
    return request.getfixturevalue("stack" if request.param == "html" else "react_stack")  # type: ignore[no-any-return]


def redeem(stack: Stack, client_id: str, verifier: str, code: str):
    return stack.token(
        grant_type="authorization_code", code=code, client_id=client_id, redirect_uri=CLAUDE_REDIRECT,
        code_verifier=verifier, resource=AUDIENCE,
    )


def assert_invalid_grant(response: Any) -> None:
    assert response.status_code in (400, 401), response.text
    assert response.json()["error"] == "invalid_grant", response.text


def grants(stack: Stack) -> int:
    return int(raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_grants")[0][0])


def codes(stack: Stack) -> int:
    return int(raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_codes")[0][0])


class TestWholeStack:
    def test_approve_disable_enable_token_is_invalid_grant(self, any_stack: Stack) -> None:
        stack = any_stack
        key = stack.enroll(ALICE)
        client_id, verifier, code, _ = stack.code_for(ALICE)
        assert stack.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
        assert stack.store.enable_principal(key, actor=OPERATOR)
        assert stack.store.get_principal_status(key).active
        assert_invalid_grant(redeem(stack, client_id, verifier, code))
        assert grants(stack) == 0

    @pytest.mark.parametrize("cleanup", [True, False])
    def test_approve_admission_lost_token_is_invalid_grant(
        self, any_stack: Stack, monkeypatch: pytest.MonkeyPatch, cleanup: bool
    ) -> None:
        stack = any_stack
        key = stack.enroll(ALICE)
        if not cleanup:
            # The epoch alone must be enough: the delete of the unredeemed codes is only cleanup.
            monkeypatch.setattr(SqlAuthCodeRepo, "delete_unconsumed_for_account", lambda self, conn, a: 0)
        client_id, verifier, code, _ = stack.code_for(ALICE)
        epoch = stack.store.get_principal_status(key).session_epoch
        elsewhere = Browser(stack)
        refused = elsewhere.entra_login(replace(ALICE, roles=()), elsewhere.get("/account/login"))
        assert refused.status_code in (303, 403)  # the page, or the sign-in page of the single-page UI
        status = stack.store.get_principal_status(key)
        assert status.active and status.session_epoch == epoch + 1  # the loss of admission ended the sessions
        assert codes(stack) == (0 if cleanup else 1)
        assert_invalid_grant(redeem(stack, client_id, verifier, code))
        assert grants(stack) == 0

    @pytest.mark.parametrize("ending", ["disable_and_enable", "admission_lost", "disable"])
    def test_a_session_that_ends_between_its_check_and_the_insert_gets_the_right_refusal(
        self, any_stack: Stack, monkeypatch: pytest.MonkeyPatch, ending: str
    ) -> None:
        """The session is valid when the decision is read, then ends before the code is stored.

        No code exists and the app gets nothing. An account that is active again (or never lost
        access) is told the request is no longer valid, not that its access is disabled.
        """
        stack = any_stack
        key = stack.enroll(ALICE)
        browser = Browser(stack, react=stack.react)
        browser.sign_in(ALICE)
        _, txn, _ = start_request(stack, browser)
        if stack.react:
            csrf = browser.csrf_token()
            assert browser.api("GET", f"/consent?txn={txn}").status_code == 200
        else:
            page = browser.get(f"/account/consent?txn={txn}")
            assert page.status_code == 200

        original = AuthzStore.create_code

        def create_after_the_session_ended(self: AuthzStore, **kwargs: Any) -> bool:
            if ending == "admission_lost":
                self.revoke_all_for_account(key, reason="admission_lost")
            else:
                assert stack.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
                if ending == "disable_and_enable":
                    assert stack.store.enable_principal(key, actor=OPERATOR)
            return original(self, **kwargs)

        monkeypatch.setattr(AuthzStore, "create_code", create_after_the_session_ended)
        expected = "access_disabled" if ending == "disable" else "authorization_invalid"
        if stack.react:
            response = browser.api("POST", "/consent", body={"txn": txn, "decision": "approve"}, csrf=csrf)
            assert response.status_code == (403 if ending == "disable" else 400), response.text
            assert response.json()["error"]["code"] == expected
            assert "redirect_to" not in response.text
        else:
            response = browser.decide(page, "approve")
            assert response.status_code == (403 if ending == "disable" else 400), response.text
            assert "location" not in response.headers
            assert ("Access disabled" in response.text) == (ending == "disable")
            assert ("Request expired" in response.text) == (ending != "disable")
        assert codes(stack) == 0

    def test_the_normal_flow_works_and_so_does_a_session_signed_in_again_after_the_enablement(
        self, any_stack: Stack
    ) -> None:
        stack = any_stack
        key = stack.enroll(ALICE)
        _, tokens = stack.tokens_for(ALICE)
        assert stack.whoami(tokens["access_token"]) == key
        # a browser with a session from before the disablement
        browser = Browser(stack, react=stack.react)
        browser.sign_in(ALICE)
        assert stack.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
        assert stack.store.enable_principal(key, actor=OPERATOR)
        client_id = stack.register(CLAUDE_REDIRECT)
        verifier, challenge = pkce()
        # the old session is gone: the request goes through the identity provider again
        start = browser.start(stack.authorize_params(client_id, challenge))
        login = browser.get(start.headers["location"])
        assert login.status_code == 302 and "login.microsoftonline.com" in login.headers["location"]
        landed = browser.connect(stack.authorize_params(client_id, challenge), ALICE)
        response = redeem(stack, client_id, verifier, landed.query["code"])
        assert response.status_code == 200, response.text
        assert stack.whoami(response.json()["access_token"]) == key

    def test_a_session_that_ended_between_the_page_and_the_decision_creates_no_code(
        self, any_stack: Stack
    ) -> None:
        stack = any_stack
        key = stack.enroll(ALICE)
        browser = Browser(stack, react=stack.react)
        browser.sign_in(ALICE)
        _, txn, _ = start_request(stack, browser)
        if stack.react:
            csrf = browser.csrf_token()
            assert browser.api("GET", f"/consent?txn={txn}").status_code == 200
        else:
            page = browser.get(f"/account/consent?txn={txn}")
            assert page.status_code == 200
        assert stack.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
        assert stack.store.enable_principal(key, actor=OPERATOR)
        if stack.react:
            response = browser.api("POST", "/consent", body={"txn": txn, "decision": "approve"}, csrf=csrf)
            assert response.status_code in (401, 403) and "redirect_to" not in response.text
        else:
            response = browser.decide(page, "approve")
            assert response.status_code == 303 and "code=" not in response.headers.get("location", "")
        assert codes(stack) == 0

    def test_a_decision_whose_session_ended_after_it_was_read_creates_no_code(self, stack: Stack) -> None:
        """The window between reading the session and the insert: the service itself refuses."""
        key = stack.enroll(ALICE)
        session_epoch = stack.store.get_principal_status(key).session_epoch

        def decide(epoch: int) -> ConsentRedirect | ConsentRefusal:
            browser = Browser(stack)
            browser.sign_in(ALICE)
            _, txn, _ = start_request(stack, browser)
            binding = browser.client.cookies.get(stack.authz.binding_cookie)
            return asyncio.run(
                stack.authz.consent.decide(
                    txn, binding, account_key=key, session_iat=int(stack.clock()), session_epoch=epoch,
                    account_pending=False, decision="approve",
                )
            )

        assert stack.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
        assert stack.store.enable_principal(key, actor=OPERATOR)
        refused = decide(session_epoch)  # the epoch of the session before the disablement
        # the account is active again: the person is not told that access is disabled
        assert isinstance(refused, ConsentRefusal) and refused.code == "authorization_invalid"
        assert codes(stack) == 0
        # while an account that is still disabled keeps the "access disabled" refusal
        assert stack.store.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
        disabled = decide(session_epoch)
        assert isinstance(disabled, ConsentRefusal) and disabled.code == "access_disabled"
        assert codes(stack) == 0
        assert stack.store.enable_principal(key, actor=OPERATOR)
        approved = decide(stack.store.get_principal_status(key).session_epoch)
        assert isinstance(approved, ConsentRedirect) and approved.approved
        assert codes(stack) == 1
