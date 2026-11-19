"""``GET /api/v1/readiness``: the pull-based readiness contract (version 1).

The caller presents the same Portal-issued OAuth access token it uses for MCP calls.
The endpoint answers from the Portal's own records: no Canvas call, no cookie, no write.
Driven over the whole stack with a real authorization flow.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
import pytest

from canvas_mcp.core.selfhost.authz.tokens import AccessTokenCodec
from canvas_mcp.core.selfhost.token_store import (
    DISABLE_REASON_OPERATOR,
    OPERATOR,
    REASON_CANVAS_TOKEN_REJECTED,
    REASON_REVOKED_BY_ADMIN,
    CustodyAcknowledgement,
    Keyring,
)

from .stack import ALICE, BASE, BOB, CANVAS_HOST, Stack

PATH = "/api/v1/readiness"
ACTION_URL = BASE + "/account/token"
DAY = 86400
STATES = {"ready", "needs_setup", "degraded", "expiring", "expired", "revoked"}


@pytest.fixture
def stack(react_stack: Stack) -> Stack:
    return react_stack


def access_token(stack: Stack, user: Any = ALICE) -> str:
    _, tokens = stack.tokens_for(user)
    return str(tokens["access_token"])


def readiness(
    stack: Stack, bearer: str | None, **headers: str
) -> httpx.Response:
    sent = {"Accept": "application/json", **headers}
    if bearer is not None:
        sent["Authorization"] = f"Bearer {bearer}"
    return stack.client.get(PATH, headers=sent)


def expect_state(response: httpx.Response, state: str) -> dict[str, Any]:
    assert response.status_code == 200, response.text
    assert response.headers["content-type"].startswith("application/json")
    body = response.json()
    assert body["version"] == 1
    assert body["state"] == state, body
    assert body["state"] in STATES
    return body  # type: ignore[no-any-return]


def enroll_with_expiry(
    stack: Stack, user: Any, expires_at: int | None, source: str = "canvas"
) -> str:
    key = stack.account_of(user)
    stack.store.put(
        principal_key=key,
        api_token=user.canvas_token,
        canvas_user_id="1",
        canvas_user_name=user.name,
        canvas_host=CANVAS_HOST,
        custody=CustodyAcknowledgement(1, int(stack.clock())),
        expiry_source=source,
        access_expires_at=expires_at,
    )
    return key


class TestStates:
    def test_no_canvas_token_is_needs_setup_with_an_absolute_https_action(
        self, stack: Stack
    ) -> None:
        bearer = access_token(stack)  # signs in; no Canvas token is saved
        body = expect_state(readiness(stack, bearer), "needs_setup")
        assert body["action"] == {"label": "Set up Canvas token", "url": ACTION_URL}
        parts = urlsplit(body["action"]["url"])
        assert parts.scheme == "https" and parts.netloc
        assert 0 < len(body["summary"]) <= 200
        assert "expires_at" not in body or body["expires_at"] is None

    def test_saved_token_without_a_known_expiry_is_ready(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        body = expect_state(readiness(stack, bearer), "ready")
        assert body.get("expires_at") is None
        assert 0 < len(body["summary"]) <= 200

    def test_known_expiry_far_away_is_ready_and_reported(self, stack: Stack) -> None:
        bearer = access_token(stack)
        expires = int(stack.clock()) + 90 * DAY
        enroll_with_expiry(stack, ALICE, expires)
        body = expect_state(readiness(stack, bearer), "ready")
        assert body["expires_at"] == datetime.fromtimestamp(expires, tz=UTC).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

    def test_expiry_inside_the_reminder_window_is_expiring(self, stack: Stack) -> None:
        bearer = access_token(stack)
        days = int(
            stack.runtime.snapshots.current.settings["notifications.token_reminder_days"]
        )
        expires = int(stack.clock()) + days * DAY - 60
        enroll_with_expiry(stack, ALICE, expires)
        body = expect_state(readiness(stack, bearer), "expiring")
        assert body["expires_at"].endswith("Z")
        assert body["action"]["url"] == ACTION_URL

    def test_expiry_just_outside_the_reminder_window_is_ready(self, stack: Stack) -> None:
        bearer = access_token(stack)
        days = int(
            stack.runtime.snapshots.current.settings["notifications.token_reminder_days"]
        )
        enroll_with_expiry(stack, ALICE, int(stack.clock()) + days * DAY + 3600)
        expect_state(readiness(stack, bearer), "ready")

    def test_a_manual_expiry_hint_does_not_count(self, stack: Stack) -> None:
        # Only an expiry Canvas itself reported is trusted, as in the account page.
        bearer = access_token(stack)
        enroll_with_expiry(stack, ALICE, int(stack.clock()) + 60, source="manual")
        expect_state(readiness(stack, bearer), "ready")

    def test_expired_token_is_expired(self, stack: Stack) -> None:
        bearer = access_token(stack)
        enroll_with_expiry(stack, ALICE, int(stack.clock()) - 3600)
        body = expect_state(readiness(stack, bearer), "expired")
        assert body["action"]["url"] == ACTION_URL

    def test_expired_wins_over_a_canvas_rejection_that_followed_it(
        self, stack: Stack
    ) -> None:
        bearer = access_token(stack)
        key = enroll_with_expiry(stack, ALICE, int(stack.clock()) - 3600)
        assert stack.store.mark_invalid(key, reason=REASON_CANVAS_TOKEN_REJECTED)
        expect_state(readiness(stack, bearer), "expired")

    def test_canvas_rejected_token_is_revoked(self, stack: Stack) -> None:
        key = stack.enroll(ALICE)
        bearer = access_token(stack)
        assert stack.store.mark_invalid(key, reason=REASON_CANVAS_TOKEN_REJECTED)
        body = expect_state(readiness(stack, bearer), "revoked")
        assert body["action"]["url"] == ACTION_URL
        assert body["action"]["url"].startswith("https://")

    def test_a_token_revoked_by_an_administrator_is_revoked(self, stack: Stack) -> None:
        key = stack.enroll(ALICE)
        bearer = access_token(stack)
        assert stack.store.mark_invalid(
            key, reason=REASON_REVOKED_BY_ADMIN, actor=OPERATOR
        )
        expect_state(readiness(stack, bearer), "revoked")

    def test_a_replaced_token_is_ready_again(self, stack: Stack) -> None:
        key = stack.enroll(ALICE)
        bearer = access_token(stack)
        stack.store.mark_invalid(key, reason=REASON_CANVAS_TOKEN_REJECTED)
        expect_state(readiness(stack, bearer), "revoked")
        stack.enroll(ALICE)  # a fresh token replaces the rejected one
        expect_state(readiness(stack, bearer), "ready")

    def test_an_old_custody_notice_blocks_tools_so_it_is_needs_setup(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from canvas_mcp.core.selfhost import custody

        stack.enroll(ALICE)
        bearer = access_token(stack)
        # A newer notice is published after the token was acknowledged.
        monkeypatch.setattr(custody, "CUSTODY_NOTICE_VERSION", custody.CUSTODY_NOTICE_VERSION + 1)
        body = expect_state(readiness(stack, bearer), "needs_setup")
        assert body["action"]["url"] == ACTION_URL

    def test_a_disabled_account_loses_its_grants_so_the_token_is_401(
        self, stack: Stack
    ) -> None:
        key = stack.enroll(ALICE)
        bearer = access_token(stack)
        assert stack.store.disable_principal(
            key, actor=OPERATOR, reason=DISABLE_REASON_OPERATOR
        )
        assert readiness(stack, bearer).status_code == 401
        assert stack.mcp_status(bearer) == 401


class TestAccountIsolation:
    def test_each_token_sees_only_its_own_account(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        alice = access_token(stack, ALICE)
        bob = access_token(stack, BOB)  # Bob has no Canvas token
        expect_state(readiness(stack, alice), "ready")
        expect_state(readiness(stack, bob), "needs_setup")


class TestAuthentication:
    def test_no_authorization_header_is_401(self, stack: Stack) -> None:
        response = readiness(stack, None)
        assert response.status_code == 401
        assert "state" not in response.text

    @pytest.mark.parametrize(
        "header",
        ["Basic YTpi", "Bearer", "Bearer ", "bearer-only", "Token abc", "Bearer a b"],
    )
    def test_malformed_authorization_is_401(self, stack: Stack, header: str) -> None:
        response = stack.client.get(PATH, headers={"Authorization": header})
        assert response.status_code == 401

    def test_garbage_bearer_is_401(self, stack: Stack) -> None:
        assert readiness(stack, "not-a-jwt").status_code == 401
        assert readiness(stack, "a.b.c").status_code == 401
        assert readiness(stack, "x" * 5000).status_code == 401

    def test_a_tampered_token_is_401(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        head, payload, sig = bearer.split(".")
        flipped = sig[:-2] + ("AA" if not sig.endswith("AA") else "BB")
        assert readiness(stack, f"{head}.{payload}.{flipped}").status_code == 401

    def test_the_refresh_token_is_not_an_access_token(self, stack: Stack) -> None:
        _, tokens = stack.tokens_for(ALICE)
        assert readiness(stack, tokens["refresh_token"]).status_code == 401

    def test_a_revoked_grant_is_401(self, stack: Stack) -> None:
        import asyncio

        stack.enroll(ALICE)
        bearer = access_token(stack)
        expect_state(readiness(stack, bearer), "ready")
        grant = stack.authz.codec.decode(bearer).claims["grant"]
        assert asyncio.run(stack.authz.grants.revoke_by_client(grant))
        assert readiness(stack, bearer).status_code == 401
        assert stack.mcp_status(bearer) == 401  # the MCP endpoint agrees

    def test_an_expired_access_token_is_401(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        stack.clock.advance(30 * DAY)
        assert readiness(stack, bearer).status_code == 401

    def test_a_token_for_another_audience_is_401(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        decoded = stack.authz.codec.decode(bearer)
        claims = decoded.claims
        other = AccessTokenCodec(
            Keyring.parse(stack.settings.canvas_token_keys_raw),
            issuer=stack.authz.issuer,
            audience="https://elsewhere.example.test/mcp",
            scopes=claims["scope"].split(" "),
            clock=stack.clock,
        )
        forged = other.encode(
            account_key=claims["acct"],
            client_id=claims["client_id"],
            grant_id=claims["grant"],
            scopes=claims["scope"].split(" "),
            expires_at=claims["exp"],
            epoch=decoded.epoch,
        ).token
        assert readiness(stack, forged).status_code == 401
        assert stack.mcp_status(forged) == 401

    def test_a_cookie_session_is_not_authentication(self, stack: Stack) -> None:
        from .stack import Browser

        browser = Browser(stack, react=True)
        browser.sign_in(ALICE)
        response = browser.get(PATH)
        assert response.status_code == 401

    def test_a_session_cookie_never_substitutes_for_a_bad_bearer(
        self, stack: Stack
    ) -> None:
        from .stack import Browser

        browser = Browser(stack, react=True)
        browser.sign_in(ALICE)
        response = browser.get(PATH, headers={"Authorization": "Bearer nope"})
        assert response.status_code == 401


class TestRequestShape:
    def test_only_get_is_served(self, stack: Stack) -> None:
        bearer = access_token(stack)
        for method in ("POST", "PUT", "DELETE", "PATCH"):
            response = stack.client.request(
                method, PATH, headers={"Authorization": f"Bearer {bearer}"}
            )
            assert response.status_code == 405, method
            assert "GET" in response.headers["allow"]

    def test_no_cors_headers_and_options_is_refused(self, stack: Stack) -> None:
        bearer = access_token(stack)
        response = readiness(stack, bearer, Origin="https://evil.example")
        assert "access-control-allow-origin" not in response.headers
        options = stack.client.options(PATH, headers={"Origin": "https://evil.example"})
        assert options.status_code in (401, 403, 405)
        assert "access-control-allow-origin" not in options.headers

    def test_the_response_is_not_cacheable(self, stack: Stack) -> None:
        bearer = access_token(stack)
        response = readiness(stack, bearer)
        assert "no-store" in response.headers["cache-control"]
        assert response.headers["x-content-type-options"] == "nosniff"

    def test_unauthenticated_errors_are_json_without_detail(self, stack: Stack) -> None:
        response = readiness(stack, "nope")
        assert response.status_code == 401
        assert response.headers["content-type"].startswith("application/json")
        assert response.headers["www-authenticate"].lower().startswith("bearer")
        assert set(response.json()) == {"error"}

    def test_a_request_is_read_only(self, stack: Stack) -> None:
        key = stack.enroll(ALICE)
        bearer = access_token(stack)
        before = stack.store.info(key)
        audit_before = _row_counts(stack)
        for _ in range(3):
            expect_state(readiness(stack, bearer), "ready")
        assert stack.store.info(key) == before
        assert _row_counts(stack) == audit_before


def _row_counts(stack: Stack) -> dict[str, int]:
    from sqlalchemy import text

    with stack.store.database.read() as conn:
        return {
            name: int(conn.execute(text(f"SELECT COUNT(*) FROM {name}")).scalar_one())
            for name in ("audit_log", "canvas_credentials", "oauth_grants")
        }


class TestNoSecrets:
    def test_the_body_never_contains_a_token_or_a_part_of_one(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        secret = ALICE.canvas_token
        for state_setup in ("ready", "revoked"):
            if state_setup == "revoked":
                stack.store.mark_invalid(
                    stack.account_of(ALICE), reason=REASON_CANVAS_TOKEN_REJECTED
                )
            response = readiness(stack, bearer)
            text = response.text + json.dumps(dict(response.headers))
            assert secret not in text
            for size in (8, 12, 16):
                assert secret[:size] not in text and secret[-size:] not in text
            assert bearer not in text
            assert bearer.split(".")[1] not in text

    def test_only_the_contract_fields_are_returned(self, stack: Stack) -> None:
        body = readiness(stack, access_token(stack)).json()
        assert set(body) <= {
            "version",
            "state",
            "summary",
            "action",
            "expires_at",
            "checked_at",
        }
        assert body["checked_at"].endswith("Z")
        assert set(body["action"]) == {"label", "url"}

    def test_no_canvas_call_is_made(self, stack: Stack, monkeypatch: pytest.MonkeyPatch) -> None:
        import canvas_mcp.core.selfhost.account_core as core

        stack.enroll(ALICE)
        bearer = access_token(stack)

        async def boom(*args: Any, **kwargs: Any) -> Any:
            raise AssertionError("readiness must not call Canvas")

        monkeypatch.setattr(core, "default_canvas_whoami", boom, raising=False)
        monkeypatch.setattr(httpx.AsyncClient, "send", boom)
        expect_state(readiness(stack, bearer), "ready")
