"""/token, /revoke, /register and the MCP endpoint, driven in-process over the whole stack."""

from __future__ import annotations

import time
from typing import Any

import pytest
from dbbackend import raw_sql
from fastmcp.server.auth.jwt_issuer import JWTIssuer, derive_jwt_key

from canvas_mcp.core.selfhost.authz import tokens as tk
from canvas_mcp.core.selfhost.db.errors import StoreUnavailable
from canvas_mcp.core.selfhost.token_store import OPERATOR

from .stack import (
    ALICE,
    AUDIENCE,
    BOB,
    CLAUDE_REDIRECT,
    ISSUER,
    LOOPBACK_REDIRECT,
    SCOPE,
    Browser,
    Stack,
    local_stack,
    pkce,
)


def exchange(stack: Stack, client_id: str, verifier: str, code: str, **overrides: str | None) -> Any:
    form: dict[str, str | None] = {
        "grant_type": "authorization_code", "code": code, "client_id": client_id,
        "redirect_uri": CLAUDE_REDIRECT, "code_verifier": verifier, "resource": AUDIENCE,
    }
    form.update(overrides)
    return stack.token(**{k: v for k, v in form.items() if v is not None})


def grant_rows(stack: Stack) -> list[tuple]:
    return raw_sql(stack.store, "SELECT id, revoked_reason, expires_at FROM oauth_grants")


@pytest.fixture
def alice(stack: Stack) -> str:
    return stack.enroll(ALICE)


# ------------------------------------------------------------------------------------ /register


class TestRegistration:
    def test_a_registration_is_a_public_client_and_the_echo_says_so(self, stack: Stack) -> None:
        response = stack.client.post(
            "/register",
            json={
                "redirect_uris": [CLAUDE_REDIRECT], "client_name": "Claude",
                "token_endpoint_auth_method": "client_secret_post",
                "grant_types": ["authorization_code", "refresh_token"],
                "jwks_uri": "https://evil.example/jwks", "contacts": ["a@b.c"],
            },
        )
        assert response.status_code == 201
        body = response.json()
        assert body["token_endpoint_auth_method"] == "none" and body.get("client_secret") is None
        assert body.get("client_secret_expires_at") is None
        assert body["scope"] == SCOPE and body["redirect_uris"] == [CLAUDE_REDIRECT]
        assert "jwks_uri" not in body and "contacts" not in body
        stored = raw_sql(stack.store, "SELECT info_json, expires_at, created_at FROM oauth_clients")[0]
        assert "client_secret" not in stored[0] or '"client_secret":null' in stored[0].replace(" ", "")
        assert stored[1] - stored[2] == 30 * 86400

    def test_without_a_method_the_stock_default_secret_is_not_kept(self, stack: Stack) -> None:
        response = stack.client.post("/register", json={"redirect_uris": [CLAUDE_REDIRECT]})
        assert response.status_code == 201
        assert response.json()["token_endpoint_auth_method"] == "none"
        assert response.json().get("client_secret") is None

    @pytest.mark.parametrize(
        "redirect",
        [
            "javascript:alert(1)",
            "data:text/html,x",
            "http://evil.example/cb",
            "https://evil.example/cb",
            "ftp://claude.ai/cb",
            "https://claude.ai/api/mcp/auth_callback#frag",
            "https://claude.ai/*",
            "https://*.claude.ai/api/mcp/auth_callback",
            "https://user@claude.ai/api/mcp/auth_callback",
            "https://claude.ai/api/mcp/auth_callback?x=1",
            "https://claude.ai/api/mcp/%2e%2e/other",
            "https://claude.ai/api/mcp/../other",
            "http://localhost/other",
            "https://localhost/callback",
            "http://localhost.evil.example/callback",
        ],
    )
    def test_evil_and_unlisted_redirect_uris_are_refused(self, stack: Stack, redirect: str) -> None:
        response = stack.client.post("/register", json={"redirect_uris": [redirect], "client_name": "x"})
        assert response.status_code == 400 and response.json()["error"] in ("invalid_redirect_uri", "invalid_client_metadata")
        assert raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_clients")[0][0] == 0

    def test_dot_segments_are_collapsed_by_the_url_parser_so_only_the_normal_form_is_ever_stored(
        self, stack: Stack
    ) -> None:
        response = stack.client.post(
            "/register", json={"redirect_uris": ["https://claude.ai/api/mcp/../mcp/auth_callback"]}
        )
        assert response.status_code == 201 and response.json()["redirect_uris"] == [CLAUDE_REDIRECT]

    @pytest.mark.parametrize(
        "uri",
        [CLAUDE_REDIRECT, "https://claude.com/api/mcp/auth_callback", "http://localhost/callback",
         "http://localhost:53682/callback", "http://127.0.0.1:39211/callback"],
    )
    def test_the_default_allowlist_entries_are_accepted(self, stack: Stack, uri: str) -> None:
        assert stack.client.post("/register", json={"redirect_uris": [uri]}).status_code == 201

    def test_too_many_redirect_uris_and_a_long_name_are_refused(self, stack: Stack) -> None:
        many = [f"http://localhost:{5000 + i}/callback" for i in range(11)]
        assert stack.client.post("/register", json={"redirect_uris": many}).status_code == 400
        assert stack.client.post("/register", json={"redirect_uris": [CLAUDE_REDIRECT], "client_name": "n" * 201}).status_code == 400

    def test_grant_types_must_be_the_two_we_support(self, stack: Stack) -> None:
        for grants in (["implicit"], ["authorization_code", "password"], ["refresh_token"]):
            response = stack.client.post("/register", json={"redirect_uris": [CLAUDE_REDIRECT], "grant_types": grants})
            assert response.status_code == 400, grants

    def test_the_web_application_type_cannot_use_loopback(self, stack: Stack) -> None:
        response = stack.client.post(
            "/register", json={"redirect_uris": ["http://localhost/callback"], "application_type": "web"}
        )
        assert response.status_code == 400

    def test_a_narrowed_allowlist_takes_effect_for_clients_registered_before(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        stack.authz.clients._allowlist = ("https://other.example/cb",)
        _, challenge = pkce()
        response = stack.client.get("/authorize", params=stack.authorize_params(client_id, challenge))
        assert response.status_code == 400 and "location" not in response.headers

    def test_an_expired_registration_is_unknown(self, stack: Stack) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        raw_sql(stack.store, "UPDATE oauth_clients SET expires_at = 1")
        _, challenge = pkce()
        assert stack.client.get("/authorize", params=stack.authorize_params(client_id, challenge)).status_code == 400
        assert stack.token(grant_type="refresh_token", refresh_token="cmcp_rt_" + "A" * 43, client_id=client_id).status_code == 401

    def test_registration_survives_a_database_outage_as_a_503(self, stack: Stack, monkeypatch) -> None:
        def failing(*a: Any, **k: Any) -> None:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(stack.authz.store, "put_client", failing)
        response = stack.client.post("/register", json={"redirect_uris": [CLAUDE_REDIRECT]})
        assert response.status_code == 503 and response.json()["error"] == "temporarily_unavailable"


# ------------------------------------------------------------------------------------- /token


class TestTokenEndpoint:
    def test_the_response_has_the_oauth_shape(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        assert set(tokens) == {"access_token", "token_type", "expires_in", "scope", "refresh_token"}
        assert tokens["token_type"] == "Bearer" and tokens["scope"] == SCOPE
        assert 3500 < tokens["expires_in"] <= 3600
        claims = stack.authz.codec.decode(tokens["access_token"])
        assert claims["client_id"] == client_id and claims["acct"] == alice and claims["aud"] == AUDIENCE
        assert tk.REFRESH_RE.fullmatch(tokens["refresh_token"])
        rows = raw_sql(stack.store, "SELECT token_hash FROM oauth_refresh_tokens")
        assert rows == [(tk.hash_secret(tokens["refresh_token"]),)]

    def test_a_foreign_resource_is_invalid_target_and_a_missing_one_is_fine(self, stack: Stack, alice: str) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)
        response = exchange(stack, client_id, verifier, code, resource="https://other.example/mcp")
        assert response.status_code == 400 and response.json()["error"] == "invalid_target"
        assert response.headers["cache-control"] == "no-store"
        assert exchange(stack, client_id, verifier, code, resource=None).status_code == 200  # code not burned

    def test_the_resource_may_be_spelled_differently(self, stack: Stack, alice: str) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)
        assert exchange(stack, client_id, verifier, code, resource=AUDIENCE + "/").status_code == 200

    def test_a_wrong_verifier_is_invalid_grant_and_does_not_burn_the_code(self, stack: Stack, alice: str) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)
        response = exchange(stack, client_id, "x" * 60, code)
        assert response.status_code == 401 and response.json()["error"] == "invalid_grant"
        assert grant_rows(stack) == []
        assert exchange(stack, client_id, verifier, code).status_code == 200

    def test_a_wrong_redirect_uri_is_invalid_request(self, stack: Stack, alice: str) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)
        response = exchange(stack, client_id, verifier, code, redirect_uri="https://claude.com/api/mcp/auth_callback")
        assert response.status_code == 400 and response.json()["error"] == "invalid_request"
        assert exchange(stack, client_id, verifier, code, redirect_uri=None).status_code == 400

    def test_another_clients_code_looks_like_an_unknown_code(self, stack: Stack, alice: str) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)
        other = stack.register(CLAUDE_REDIRECT)
        response = exchange(stack, other, verifier, code)
        assert response.status_code == 401 and response.json()["error"] == "invalid_grant"
        assert exchange(stack, client_id, verifier, code).status_code == 200

    def test_an_unknown_client_is_invalid_client(self, stack: Stack) -> None:
        response = exchange(stack, "nobody", "v" * 50, "cmcp_ac_" + "A" * 43)
        assert response.status_code == 401 and response.json()["error"] == "invalid_client"
        assert exchange(stack, "https://client.example/none.json", "v" * 50, "x").status_code == 401

    def test_an_expired_code_is_refused(self, stack: Stack, alice: str) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)
        raw_sql(stack.store, "UPDATE oauth_codes SET expires_at = :t", {"t": int(time.time()) - 10})
        response = exchange(stack, client_id, verifier, code)
        assert response.status_code == 401 and response.json()["error"] == "invalid_grant"

    def test_malformed_codes_and_unknown_grant_types(self, stack: Stack, alice: str) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        for code in ("", "short", "cmcp_ac_" + "A" * 42, "x" * 5000):
            assert exchange(stack, client_id, "v" * 50, code).status_code in (400, 401)
        response = stack.token(grant_type="password", client_id=client_id, username="a", password="b")
        assert response.status_code == 400
        response = stack.token(grant_type="client_credentials", client_id=client_id)
        assert response.status_code == 400

    def test_a_client_that_did_not_ask_for_refresh_tokens_gets_none(self, stack: Stack, alice: str) -> None:
        client_id = stack.register(CLAUDE_REDIRECT, grant_types=["authorization_code"])
        _, tokens = stack.tokens_for(ALICE, client_id=client_id)
        assert "refresh_token" not in tokens
        assert raw_sql(stack.store, "SELECT COUNT(*) FROM oauth_refresh_tokens")[0][0] == 0

    def test_a_replay_inside_the_window_gets_a_sibling_and_the_connection_survives(self, stack: Stack, alice: str) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)
        first = exchange(stack, client_id, verifier, code)
        second = exchange(stack, client_id, verifier, code)
        assert first.status_code == second.status_code == 200
        assert first.json()["refresh_token"] != second.json()["refresh_token"]
        assert stack.mcp_status(first.json()["access_token"]) == 200
        assert grant_rows(stack)[0][1] is None

    def test_a_replay_after_the_window_revokes_everything_at_once(self, stack: Stack, alice: str) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)
        first = exchange(stack, client_id, verifier, code).json()
        assert stack.mcp_status(first["access_token"]) == 200
        stack.clock.advance(31)
        replay = exchange(stack, client_id, verifier, code)
        assert replay.status_code == 401 and replay.json()["error"] == "invalid_grant"
        assert grant_rows(stack)[0][1] == "code_replay"
        assert stack.mcp_status(first["access_token"]) == 401  # in-process: no cache delay
        assert stack.refresh(client_id, first["refresh_token"]).status_code == 401

    def test_the_replay_of_a_used_code_with_a_wrong_verifier_changes_nothing(self, stack: Stack, alice: str) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)
        assert exchange(stack, client_id, verifier, code).status_code == 200
        stack.clock.advance(60)
        assert exchange(stack, client_id, "x" * 60, code).status_code == 401  # fails PKCE: never reaches the rules
        assert grant_rows(stack)[0][1] is None

    def test_a_database_outage_while_exchanging_is_a_503_not_a_500(self, stack: Stack, alice: str, monkeypatch) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)

        def failing(*a: Any, **k: Any) -> None:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(stack.authz.store, "exchange_code", failing)
        response = exchange(stack, client_id, verifier, code)
        assert response.status_code == 503 and response.json()["error"] == "temporarily_unavailable"
        assert response.headers["retry-after"] == "5" and response.headers["cache-control"] == "no-store"

    def test_a_database_outage_while_loading_the_code_is_a_503(self, stack: Stack, alice: str, monkeypatch) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)

        def failing(*a: Any, **k: Any) -> None:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(stack.authz.store, "load_code", failing)
        assert exchange(stack, client_id, verifier, code).status_code == 503

    def test_an_outage_while_looking_the_client_up_is_not_invalid_client(self, stack: Stack, alice: str, monkeypatch) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)

        def failing(*a: Any, **k: Any) -> None:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(stack.authz.store, "get_client_record", failing)
        response = exchange(stack, client_id, verifier, code)
        assert response.status_code == 503  # a registered client must not be told it is unknown

    def test_an_account_disabled_between_consent_and_exchange_gets_no_tokens(self, stack: Stack, alice: str) -> None:
        client_id, verifier, code, _ = stack.code_for(ALICE)
        stack.store.disable_principal(alice, actor=OPERATOR, reason="operator_disabled")
        response = exchange(stack, client_id, verifier, code)
        assert response.status_code == 401 and response.json()["error"] == "invalid_grant"
        assert grant_rows(stack) == []

    def test_a_sign_in_that_is_too_old_forces_a_new_one(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"MAX_UPSTREAM_AUTH_AGE": "1h"}) as stack:
            stack.enroll(ALICE)
            client_id, verifier, code, _ = stack.code_for(ALICE)
            stack.clock.advance(3601)
            response = exchange(stack, client_id, verifier, code)
            assert response.status_code == 401 and response.json()["error"] == "invalid_grant"
            assert grant_rows(stack) == []


class TestRefresh:
    def test_rotation_issues_a_new_pair_and_keeps_the_absolute_cap(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        cap = grant_rows(stack)[0][2]
        stack.clock.advance(120)
        refreshed = stack.refresh(client_id, tokens["refresh_token"])
        assert refreshed.status_code == 200
        new = refreshed.json()
        assert new["refresh_token"] != tokens["refresh_token"] and new["access_token"] != tokens["access_token"]
        assert {r[0] for r in raw_sql(stack.store, "SELECT expires_at FROM oauth_refresh_tokens")} == {cap}
        assert stack.mcp_status(new["access_token"]) == 200

    def test_downscoping_to_the_granted_scope_works_and_escalation_burns_nothing(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        refreshed = stack.refresh(client_id, tokens["refresh_token"], scope=SCOPE)
        assert refreshed.status_code == 200 and refreshed.json()["scope"] == SCOPE
        again = refreshed.json()["refresh_token"]
        escalated = stack.refresh(client_id, again, scope=f"{SCOPE} admin")
        assert escalated.status_code == 400 and escalated.json()["error"] == "invalid_scope"
        assert stack.refresh(client_id, again).status_code == 200  # the token was not consumed

    def test_another_clients_refresh_token_is_refused(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        other = stack.register(CLAUDE_REDIRECT)
        response = stack.refresh(other, tokens["refresh_token"])
        assert response.status_code == 401 and response.json()["error"] == "invalid_grant"
        assert stack.refresh(client_id, tokens["refresh_token"]).status_code == 200

    def test_a_reused_token_after_the_window_revokes_the_family(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        newest = stack.refresh(client_id, tokens["refresh_token"]).json()
        stack.clock.advance(31)
        assert stack.refresh(client_id, tokens["refresh_token"]).status_code == 401
        assert grant_rows(stack)[0][1] == "refresh_reuse"
        assert stack.refresh(client_id, newest["refresh_token"]).status_code == 401
        assert stack.mcp_status(newest["access_token"]) == 401

    def test_a_duplicate_inside_the_window_is_served_and_nothing_is_revoked(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        a = stack.refresh(client_id, tokens["refresh_token"])
        b = stack.refresh(client_id, tokens["refresh_token"])
        assert a.status_code == b.status_code == 200
        assert grant_rows(stack)[0][1] is None
        assert stack.refresh(client_id, a.json()["refresh_token"]).status_code == 200
        assert stack.refresh(client_id, b.json()["refresh_token"]).status_code == 401  # the retired sibling

    def test_the_maximum_age_of_the_sign_in_ends_the_connection(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"MAX_UPSTREAM_AUTH_AGE": "1h"}) as stack:
            stack.enroll(ALICE)
            client_id, tokens = stack.tokens_for(ALICE)
            stack.clock.advance(3601)
            response = stack.refresh(client_id, tokens["refresh_token"])
            assert response.status_code == 401 and response.json()["error"] == "invalid_grant"
            assert grant_rows(stack)[0][1] == "reauth_required"

    def test_the_absolute_lifetime_ends_the_connection(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"REFRESH_ABSOLUTE_TTL": "2h", "MAX_UPSTREAM_AUTH_AGE": "1d"}) as stack:
            stack.enroll(ALICE)
            client_id, tokens = stack.tokens_for(ALICE)
            stack.clock.advance(3000)
            tokens = stack.refresh(client_id, tokens["refresh_token"]).json()
            stack.clock.advance(5000)  # past the two hours
            assert stack.refresh(client_id, tokens["refresh_token"]).status_code == 401

    def test_the_access_token_never_outlives_the_grant(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"REFRESH_ABSOLUTE_TTL": "2h", "MAX_UPSTREAM_AUTH_AGE": "1d"}) as stack:
            stack.enroll(ALICE)
            client_id, tokens = stack.tokens_for(ALICE)
            stack.clock.advance(6600)  # 20 minutes of the grant left
            fresh = stack.refresh(client_id, tokens["refresh_token"]).json()
            assert fresh["expires_in"] <= 1200 + 5

    def test_a_malformed_refresh_token_is_just_unknown(self, stack: Stack, alice: str) -> None:
        client_id = stack.register(CLAUDE_REDIRECT)
        for value in ("", "x", "cmcp_rt_short", "cmcp_ac_" + "A" * 43, "x" * 9000):
            response = stack.refresh(client_id, value)
            assert response.status_code in (400, 401), value[:20]

    def test_a_database_outage_while_refreshing_is_a_503(self, stack: Stack, alice: str, monkeypatch) -> None:
        client_id, tokens = stack.tokens_for(ALICE)

        def failing(*a: Any, **k: Any) -> None:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(stack.authz.store, "rotate_refresh", failing)
        assert stack.refresh(client_id, tokens["refresh_token"]).status_code == 503


# ------------------------------------------------------------------------------------- /revoke


class TestRevoke:
    def revoke(self, stack: Stack, client_id: str | None, token: str | None, **extra: str) -> Any:
        form = {k: v for k, v in {"client_id": client_id, "token": token, **extra}.items() if v is not None}
        return stack.client.post("/revoke", data=form)

    @pytest.mark.parametrize("which", ["refresh_token", "access_token"])
    def test_a_public_client_revokes_the_connection_with_either_token(self, stack: Stack, alice: str, which: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        response = self.revoke(stack, client_id, tokens[which])
        assert response.status_code == 200 and response.headers["cache-control"] == "no-store"
        assert grant_rows(stack)[0][1] == "client_revoked"
        assert stack.mcp_status(tokens["access_token"]) == 401
        assert stack.refresh(client_id, tokens["refresh_token"]).status_code == 401

    def test_it_is_idempotent_and_garbage_is_200(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        for token in (tokens["refresh_token"], tokens["refresh_token"], "garbage", "a.b.c", "cmcp_rt_" + "A" * 43, "x" * 9000):
            assert self.revoke(stack, client_id, token).status_code == 200

    def test_an_unknown_client_is_invalid_client_and_a_missing_token_is_invalid_request(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        unknown = self.revoke(stack, "nobody", tokens["refresh_token"])
        assert unknown.status_code == 401 and unknown.json()["error"] == "invalid_client"
        assert self.revoke(stack, None, tokens["refresh_token"]).status_code == 401
        missing = self.revoke(stack, client_id, None)
        assert missing.status_code == 400 and missing.json()["error"] == "invalid_request"
        assert grant_rows(stack)[0][1] is None

    def test_another_clients_token_is_a_200_that_changes_nothing(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        other = stack.register(CLAUDE_REDIRECT)
        for token in (tokens["refresh_token"], tokens["access_token"]):
            assert self.revoke(stack, other, token).status_code == 200
        assert grant_rows(stack)[0][1] is None
        assert stack.mcp_status(tokens["access_token"]) == 200

    def test_the_stock_secret_requirement_does_not_apply(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        assert self.revoke(stack, client_id, tokens["refresh_token"], token_type_hint="refresh_token").status_code == 200

    def test_a_database_outage_is_a_503(self, stack: Stack, alice: str, monkeypatch) -> None:
        client_id, tokens = stack.tokens_for(ALICE)

        def failing(*a: Any, **k: Any) -> None:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(stack.authz.store, "revoke_client_grant", failing)
        assert self.revoke(stack, client_id, tokens["refresh_token"]).status_code == 503


# ---------------------------------------------------------------------------------------- /mcp


class TestMcpEndpoint:
    def test_a_valid_token_lists_tools_and_the_tool_sees_the_account(self, stack: Stack, alice: str) -> None:
        _, tokens = stack.tokens_for(ALICE)
        assert stack.mcp_status(tokens["access_token"]) == 200
        assert stack.whoami(tokens["access_token"]) == alice

    def test_two_users_do_not_see_each_other(self, stack: Stack, alice: str) -> None:
        bob = stack.enroll(BOB)
        _, a = stack.tokens_for(ALICE)
        _, b = stack.tokens_for(BOB)
        assert stack.whoami(a["access_token"]) == alice and stack.whoami(b["access_token"]) == bob

    def test_an_in_process_revocation_takes_effect_at_once(self, stack: Stack, alice: str) -> None:
        _, tokens = stack.tokens_for(ALICE)
        assert stack.mcp_status(tokens["access_token"]) == 200
        grant_id = grant_rows(stack)[0][0]
        import anyio

        anyio.run(stack.authz.grants.revoke_own, grant_id, alice)
        assert stack.mcp_status(tokens["access_token"]) == 401

    def test_a_change_made_elsewhere_is_noticed_after_the_cache_time(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"GRANT_STATUS_CACHE_S": "1"}) as stack:
            alice = stack.enroll(ALICE)
            _, tokens = stack.tokens_for(ALICE)
            assert stack.mcp_status(tokens["access_token"]) == 200
            grant_id = grant_rows(stack)[0][0]
            # another process: a second store on the same database, which cannot reach our cache
            from canvas_mcp.core.selfhost.authz.store import AuthzStore

            other = AuthzStore(stack.store.database)
            assert other.revoke_own_grant(grant_id, alice)
            assert stack.mcp_status(tokens["access_token"]) == 200  # still cached
            time.sleep(1.2)
            assert stack.mcp_status(tokens["access_token"]) == 401

    def test_with_no_cache_every_request_asks_the_database(self, tmp_path, monkeypatch) -> None:
        with local_stack(tmp_path, monkeypatch, env={"GRANT_STATUS_CACHE_S": "0"}) as stack:
            alice = stack.enroll(ALICE)
            _, tokens = stack.tokens_for(ALICE)
            assert stack.mcp_status(tokens["access_token"]) == 200
            assert stack.store.database and stack.authz.store.revoke_own_grant(grant_rows(stack)[0][0], alice)
            assert stack.mcp_status(tokens["access_token"]) == 401

    def test_disabling_the_account_revokes_its_grants_in_the_same_transaction(self, stack: Stack, alice: str) -> None:
        _, tokens = stack.tokens_for(ALICE)
        stack.store.disable_principal(alice, actor=OPERATOR, reason="operator_disabled")
        stack.authz.account_changed(alice)
        assert grant_rows(stack)[0][1] == "account_disabled"
        assert stack.mcp_status(tokens["access_token"]) == 401

    def test_within_the_cache_window_the_request_context_still_refuses_a_disabled_account(
        self, stack: Stack, alice: str
    ) -> None:
        _, tokens = stack.tokens_for(ALICE)
        assert stack.mcp_status(tokens["access_token"]) == 200  # both caches now hold "fine"
        stack.store.disable_principal(alice, actor=OPERATOR, reason="operator_disabled")  # another process
        stack.runtime.access.invalidate()  # the 5 s account cache has expired; the grant cache has not
        response = stack.rpc(tokens["access_token"], "tools/list")
        assert response.status_code == 403 and "disabled" in response.text

    def test_a_token_whose_account_is_not_the_grants_is_refused(self, stack: Stack, alice: str) -> None:
        bob = stack.enroll(BOB)
        _, tokens = stack.tokens_for(ALICE)
        claims = stack.authz.codec.decode(tokens["access_token"])
        forged = stack.authz.codec.encode(
            account_key=bob, client_id=claims["client_id"], grant_id=claims["grant"],
            scopes=[SCOPE], expires_at=claims["exp"],
        ).token
        assert stack.mcp_status(forged) == 401

    def test_a_token_of_another_client_for_the_same_grant_is_refused(self, stack: Stack, alice: str) -> None:
        _, tokens = stack.tokens_for(ALICE)
        claims = stack.authz.codec.decode(tokens["access_token"])
        forged = stack.authz.codec.encode(
            account_key=alice, client_id="someone-else", grant_id=claims["grant"],
            scopes=[SCOPE], expires_at=claims["exp"],
        ).token
        assert stack.mcp_status(forged) == 401

    def test_a_token_for_a_grant_that_does_not_exist_is_refused(self, stack: Stack, alice: str) -> None:
        forged = stack.authz.codec.encode(
            account_key=alice, client_id="c", grant_id="11111111-1111-4111-8111-111111111111",
            scopes=[SCOPE], expires_at=int(time.time()) + 600,
        ).token
        assert stack.mcp_status(forged) == 401

    def test_an_unreadable_database_fails_closed_but_a_cached_answer_is_served(self, stack: Stack, alice: str, monkeypatch) -> None:
        _, tokens = stack.tokens_for(ALICE)
        assert stack.mcp_status(tokens["access_token"]) == 200  # cached

        def failing(*a: Any, **k: Any) -> None:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(stack.authz.store, "grant_status", failing)
        assert stack.mcp_status(tokens["access_token"]) == 200  # within the TTL
        stack.authz.cache.clear()
        assert stack.mcp_status(tokens["access_token"]) == 401  # cache miss with the database down

    def test_bumping_the_jwt_epoch_invalidates_access_tokens_but_not_the_connection(self, stack: Stack, alice: str) -> None:
        client_id, tokens = stack.tokens_for(ALICE)
        stack.authz.bump_jwt_epoch()
        assert stack.mcp_status(tokens["access_token"]) == 401
        refreshed = stack.refresh(client_id, tokens["refresh_token"])
        assert refreshed.status_code == 200 and stack.mcp_status(refreshed.json()["access_token"]) == 200

    def test_a_token_proxied_by_fastmcp_never_verifies(self, stack: Stack, alice: str) -> None:
        key = derive_jwt_key(low_entropy_material="jwt-signing-key-" + "z" * 40, salt="fastmcp-jwt-signing-key")
        issuer = JWTIssuer(issuer=ISSUER, audience=AUDIENCE, signing_key=key)
        forged = issuer.issue_access_token(
            client_id="c", scopes=[SCOPE], jti="j", expires_in=3600, subject=alice,
            extra_claims={"acct": alice, "grant": "11111111-1111-4111-8111-111111111111", "token_use": "access"},
        )
        assert stack.mcp_status(forged) == 401


# ------------------------------------------------------------------------- the three client kinds


class TestLoopbackClients:
    def test_a_native_app_on_a_random_loopback_port_connects(self, stack: Stack, alice: str) -> None:
        client_id = stack.register("http://127.0.0.1/callback")
        landed = Browser(stack).connect(
            stack.authorize_params(client_id, pkce()[1], redirect_uri=LOOPBACK_REDIRECT), ALICE
        )
        assert landed.url.startswith(LOOPBACK_REDIRECT + "?") and "code" in landed.query

    def test_the_same_registration_does_not_match_another_loopback_host(self, stack: Stack, alice: str) -> None:
        client_id = stack.register("http://127.0.0.1/callback")
        response = stack.client.get(
            "/authorize",
            params=stack.authorize_params(client_id, pkce()[1], redirect_uri="http://localhost:39211/callback"),
        )
        assert response.status_code == 400 and "location" not in response.headers
