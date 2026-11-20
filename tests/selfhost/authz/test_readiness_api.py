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

from canvas_mcp.core.selfhost import browser_plan
from canvas_mcp.core.selfhost.authz.tokens import AccessTokenCodec
from canvas_mcp.core.selfhost.browser_plan import resource_key
from canvas_mcp.core.selfhost.browser_store import BrowserSyncStore, SnapshotItem
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


BROWSER_PAGE = BASE + "/account/browser-extension"


def sync_binding(
    stack: Stack,
    user: Any = ALICE,
    *,
    captured_ago: int | None = 600,
    canvas_user_id: str = "1",
) -> BrowserSyncStore:
    """Pair the extension for ``user``; with ``captured_ago`` also upload one snapshot that old."""
    store = BrowserSyncStore(stack.store.database, stack.store.keyring, clock=stack.clock)
    code, _ = store.create_pairing_code(stack.account_of(user))
    claimed = store.claim(code)
    assert claimed is not None
    _, binding_id = claimed
    if captured_ago is not None:
        captured = int(stack.clock()) - captured_ago
        courses_query = dict(browser_plan.RESOURCES[7].query)
        items = [
            SnapshotItem(resource_key("/users/self", {}), "/users/self", {}, captured, 200, {"id": 1}),
            SnapshotItem(
                resource_key("/courses", courses_query),
                "/courses",
                courses_query,
                captured,
                200,
                [{"id": 101, "name": "Course 101", "course_code": "C101"}],
            ),
        ]
        accepted, rejected = store.save(
            binding_id, canvas_host=CANVAS_HOST, canvas_user_id=canvas_user_id, items=items
        )
        assert accepted == 2 and not rejected
    return store


def setting(stack: Stack, name: str) -> int:
    return int(stack.runtime.snapshots.current.settings[name])


class TestBrowserSync:
    """/mcp answers from browser sync exactly when there is no usable token; readiness follows."""

    def test_synced_data_without_a_token_is_ready(self, stack: Stack) -> None:
        bearer = access_token(stack)  # signed in, no Canvas token
        sync_binding(stack, captured_ago=600)
        body = expect_state(readiness(stack, bearer), "ready")
        assert "browser sync" in body["summary"].lower()
        assert "action" not in body

    def test_data_older_than_the_freshness_window_is_degraded(self, stack: Stack) -> None:
        bearer = access_token(stack)
        age = (setting(stack, "browser_sync.fresh_hours") + 2) * 3600
        sync_binding(stack, captured_ago=age)
        body = expect_state(readiness(stack, bearer), "degraded")
        assert "browser sync" in body["summary"].lower()
        assert "ago" in body["summary"] and "open Canvas to refresh" in body["summary"]
        assert body["action"]["url"] == BROWSER_PAGE
        assert len(body["summary"]) <= 200

    def test_just_inside_the_freshness_window_is_ready(self, stack: Stack) -> None:
        bearer = access_token(stack)
        age = setting(stack, "browser_sync.fresh_hours") * 3600 - 60
        sync_binding(stack, captured_ago=age)
        expect_state(readiness(stack, bearer), "ready")

    def test_data_older_than_the_maximum_age_is_not_used_so_expired(
        self, stack: Stack
    ) -> None:
        bearer = access_token(stack)
        age = setting(stack, "browser_sync.max_age_days") * 86400 + 3600
        sync_binding(stack, captured_ago=age)
        body = expect_state(readiness(stack, bearer), "expired")
        assert body["action"]["url"] == BROWSER_PAGE

    def test_a_binding_that_never_uploaded_is_needs_setup(self, stack: Stack) -> None:
        bearer = access_token(stack)
        sync_binding(stack, captured_ago=None)
        expect_state(readiness(stack, bearer), "needs_setup")

    def test_a_revoked_binding_is_needs_setup(self, stack: Stack) -> None:
        bearer = access_token(stack)
        store = sync_binding(stack, captured_ago=600)
        expect_state(readiness(stack, bearer), "ready")
        assert store.revoke_account(stack.account_of(ALICE))
        body = expect_state(readiness(stack, bearer), "needs_setup")
        assert body["action"]["url"] == ACTION_URL

    def test_a_usable_token_wins_over_stale_sync(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        age = (setting(stack, "browser_sync.fresh_hours") + 2) * 3600
        sync_binding(stack, captured_ago=age)
        body = expect_state(readiness(stack, bearer), "ready")
        assert "browser sync" not in body["summary"].lower()

    def test_an_expiring_token_still_reports_expiring_beside_fresh_sync(
        self, stack: Stack
    ) -> None:
        bearer = access_token(stack)
        enroll_with_expiry(stack, ALICE, int(stack.clock()) + 3600)
        sync_binding(stack, captured_ago=600)
        expect_state(readiness(stack, bearer), "expiring")

    def test_a_rejected_token_falls_back_to_fresh_sync_as_mcp_does(
        self, stack: Stack
    ) -> None:
        key = stack.enroll(ALICE)
        bearer = access_token(stack)
        stack.store.mark_invalid(key, reason=REASON_CANVAS_TOKEN_REJECTED)
        sync_binding(stack, captured_ago=600)
        expect_state(readiness(stack, bearer), "ready")

    def test_a_rejected_token_and_no_sync_stays_revoked(self, stack: Stack) -> None:
        key = stack.enroll(ALICE)
        bearer = access_token(stack)
        stack.store.mark_invalid(key, reason=REASON_CANVAS_TOKEN_REJECTED)
        expect_state(readiness(stack, bearer), "revoked")

    def test_a_browser_signed_in_as_someone_else_is_refused_like_mcp(
        self, stack: Stack
    ) -> None:
        # The rejected token names Canvas user 1; /mcp refuses a browser of user 2.
        key = stack.enroll(ALICE)
        bearer = access_token(stack)
        stack.store.mark_invalid(key, reason=REASON_CANVAS_TOKEN_REJECTED)
        sync_binding(stack, captured_ago=600, canvas_user_id="2")
        expect_state(readiness(stack, bearer), "revoked")

    def test_sync_of_one_account_never_helps_another(self, stack: Stack) -> None:
        stack.enroll(BOB)
        access_token(stack, ALICE)
        bob = access_token(stack, BOB)
        sync_binding(stack, ALICE, captured_ago=600)
        expect_state(readiness(stack, bob), "ready")  # Bob has his own token
        alice = access_token(stack, ALICE)
        expect_state(readiness(stack, alice), "ready")

    def test_the_token_versus_browser_rule_has_one_home(self) -> None:
        """No module but ``browser_store`` spells the rule: the middleware, the account API
        and the readiness endpoint all go through its functions."""
        import pathlib
        import re

        import canvas_mcp

        root = pathlib.Path(canvas_mcp.__file__).resolve().parent
        owners: dict[str, set[str]] = {}
        for path in root.rglob("*.py"):
            text = path.read_text(encoding="utf-8")
            for name in ("browser_decision(", "max_age_days", "fresh_hours"):
                if name in text:
                    owners.setdefault(name, set()).add(path.name)
        assert owners["browser_decision("] == {"browser_store.py"}
        # The windows are named in the settings table and read in one place.
        assert owners["max_age_days"] == {"browser_store.py", "server_settings.py"}
        assert owners["fresh_hours"] == {"browser_store.py", "server_settings.py"}
        users = {
            path.name
            for path in root.rglob("*.py")
            if re.search(
                r"\b(binding_accepted|decide_binding)\(", path.read_text(encoding="utf-8")
            )
        }
        assert users == {
            "browser_store.py",
            "request_context.py",
            "readiness_api.py",
            "account_api.py",
        }


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


# -- readiness agrees with what /mcp does ------------------------------------------------


def mcp_works(stack: Stack, bearer: str) -> bool:
    """Whether a tool call on /mcp is let through to the tool (no refusal of any kind)."""
    response = stack.rpc(
        bearer, "tools/call", {"name": "list_courses", "arguments": {}}
    )
    if response.status_code != 200:
        return False
    text = response.text
    if response.headers["content-type"].startswith("text/event-stream"):
        text = [
            line[5:].strip() for line in text.splitlines() if line.startswith("data:")
        ][-1]
    payload = json.loads(text)
    return "error" not in payload and not payload["result"].get("isError")


def run_sql(stack: Stack, statement: str, **params: Any) -> None:
    from sqlalchemy import text

    with stack.store.database.write() as conn:
        conn.execute(text(statement), params)


class TestAgreesWithMcp:
    def test_ready_means_mcp_lets_the_call_through(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        expect_state(readiness(stack, bearer), "ready")
        assert mcp_works(stack, bearer)

    def test_needs_setup_means_mcp_refuses(self, stack: Stack) -> None:
        bearer = access_token(stack)
        expect_state(readiness(stack, bearer), "needs_setup")
        assert not mcp_works(stack, bearer)

    def test_a_rejected_token_means_mcp_refuses(self, stack: Stack) -> None:
        key = stack.enroll(ALICE)
        bearer = access_token(stack)
        stack.store.mark_invalid(key, reason=REASON_CANVAS_TOKEN_REJECTED)
        expect_state(readiness(stack, bearer), "revoked")
        assert not mcp_works(stack, bearer)

    def test_a_school_that_is_no_longer_offered(self, stack: Stack) -> None:
        bearer = access_token(stack)
        stack.store.put(
            principal_key=stack.account_of(ALICE),
            api_token=ALICE.canvas_token,
            canvas_user_id="1",
            canvas_user_name=ALICE.name,
            canvas_host="gone.example.test",
            custody=CustodyAcknowledgement(1, int(stack.clock())),
        )
        body = expect_state(readiness(stack, bearer), "needs_setup")
        assert "school" in body["summary"].lower()
        assert not mcp_works(stack, bearer)

    def test_an_outdated_custody_notice(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from canvas_mcp.core.selfhost import custody

        stack.enroll(ALICE)
        bearer = access_token(stack)
        assert mcp_works(stack, bearer)
        monkeypatch.setattr(custody, "CUSTODY_NOTICE_VERSION", custody.CUSTODY_NOTICE_VERSION + 1)
        expect_state(readiness(stack, bearer), "needs_setup")
        assert not mcp_works(stack, bearer)

    def test_a_stored_token_that_cannot_be_decrypted_is_revoked(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        from sqlalchemy import text

        with stack.store.database.write() as conn:
            sealed = bytes(
                conn.execute(text("SELECT ciphertext FROM canvas_credentials")).scalar_one()
            )
            conn.execute(
                text("UPDATE canvas_credentials SET ciphertext = :c"),
                {"c": sealed[:-1] + bytes([sealed[-1] ^ 1])},
            )
        body = expect_state(readiness(stack, bearer), "revoked")
        assert "read" in body["summary"].lower()
        assert body["action"]["url"] == ACTION_URL
        # The readiness call is side-effect free: it did not mark the credential invalid.
        assert stack.store.info(stack.account_of(ALICE)).status == "active"
        assert not mcp_works(stack, bearer)

    def test_a_generation_mismatch_is_revoked(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        run_sql(stack, "UPDATE accounts SET credential_generation = credential_generation + 5")
        expect_state(readiness(stack, bearer), "revoked")
        assert not mcp_works(stack, bearer)

    @pytest.mark.parametrize(
        ("status", "code"), [("pending", "pending_approval"), ("disabled", "access_disabled")]
    )
    def test_an_account_that_is_not_active_is_refused_like_mcp(
        self, stack: Stack, status: str, code: str
    ) -> None:
        # Disabling normally revokes the grants; these rows model the window before that lands.
        stack.enroll(ALICE)
        bearer = access_token(stack)
        run_sql(
            stack,
            "UPDATE accounts SET status = :s, disabled_at = :at, disabled_reason = :why",
            s=status,
            at=int(stack.clock()) if status == "disabled" else None,
            why="operator_disabled" if status == "disabled" else None,
        )
        response = readiness(stack, bearer)
        assert response.status_code == 403
        assert response.json() == {"error": {"code": code}}
        assert stack.rpc(bearer, "tools/list").status_code == 403


class TestTokenChecksMatchMcp:
    def test_an_epoch_bump_invalidates_the_token_on_both(self, stack: Stack) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        expect_state(readiness(stack, bearer), "ready")
        stack.authz.bump_jwt_epoch()
        assert readiness(stack, bearer).status_code == 401
        assert stack.mcp_status(bearer) == 401

    def test_a_grant_of_another_client_invalidates_the_token_on_both(
        self, stack: Stack
    ) -> None:
        stack.enroll(ALICE)
        bearer = access_token(stack)
        run_sql(stack, "UPDATE oauth_grants SET client_id = 'someone-else'")
        assert readiness(stack, bearer).status_code == 401
        assert stack.mcp_status(bearer) == 401

    def test_a_store_outage_is_503_on_both(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from canvas_mcp.core.selfhost.db.errors import StoreUnavailable

        bearer = access_token(stack)

        def down(*args: Any, **kwargs: Any) -> Any:
            raise StoreUnavailable("down")

        monkeypatch.setattr(stack.authz.store, "read_mcp_snapshot", down)
        assert stack.mcp_status(bearer) == 503
        response = readiness(stack, bearer)
        assert response.status_code == 503
        assert response.json() == {"error": {"code": "token_store_unavailable"}}

    def test_options_with_a_valid_bearer_is_405(self, stack: Stack) -> None:
        bearer = access_token(stack)
        response = stack.client.options(
            PATH, headers={"Authorization": f"Bearer {bearer}"}
        )
        assert response.status_code == 405
        assert "access-control-allow-origin" not in response.headers


class TestBrowserBindingErrors:
    def test_an_unreadable_binding_falls_back_to_the_token_path_like_mcp(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        bearer = access_token(stack)  # no token: browser sync would be consulted

        def broken(self: Any, account_id: str) -> Any:
            raise RuntimeError("boom")

        monkeypatch.setattr(BrowserSyncStore, "active_binding", broken)
        expect_state(readiness(stack, bearer), "needs_setup")
        assert not mcp_works(stack, bearer)

    def test_a_store_outage_while_reading_the_binding_is_503(
        self, stack: Stack, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from canvas_mcp.core.selfhost.db.errors import StoreUnavailable

        bearer = access_token(stack)

        def down(self: Any, account_id: str) -> Any:
            raise StoreUnavailable("down")

        monkeypatch.setattr(BrowserSyncStore, "active_binding", down)
        assert readiness(stack, bearer).status_code == 503


class TestReads:
    def test_a_call_reads_the_account_once(self, stack: Stack) -> None:
        """One authenticated read serves the token check and every state: no second lookup."""
        from sqlalchemy import event

        stack.enroll(ALICE)
        bearer = access_token(stack)
        expect_state(readiness(stack, bearer), "ready")  # warm the settings snapshot
        statements: list[str] = []

        def record(conn: Any, cursor: Any, statement: str, *args: Any) -> None:
            statements.append(statement)

        engine = stack.store.database._engine
        event.listen(engine, "before_cursor_execute", record)
        try:
            expect_state(readiness(stack, bearer), "ready")
        finally:
            event.remove(engine, "before_cursor_execute", record)
        selects = [s for s in statements if s.lstrip().upper().startswith("SELECT")]
        # The one authenticated read (grant, account, credential): the same one /mcp makes.
        assert len(selects) == 1 and "canvas_credentials" in selects[0], statements


class TestPlainHttpBase:
    def test_no_action_is_offered_and_the_log_says_so_once(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging
        from types import SimpleNamespace

        from canvas_mcp.core.selfhost.readiness_api import ReadinessApi

        api = ReadinessApi.__new__(ReadinessApi)
        api.app = SimpleNamespace(base="http://portal.example.test", clock=lambda: 1_800_000_000)  # type: ignore[assignment]
        api._warned_plain_http = False
        with caplog.at_level(logging.WARNING, logger="canvas_mcp.selfhost.readiness"):
            first = json.loads(api._state("needs_setup", "No Canvas token is saved yet.", action_label="Set up").body)
            second = json.loads(api._state("revoked", "Canvas rejected it.", action_label="Replace").body)
        assert "action" not in first and "action" not in second
        warnings = [r for r in caplog.records if "not https" in r.getMessage()]
        assert len(warnings) == 1
        for summary in (first["summary"], second["summary"]):
            assert "click" not in summary.lower() and "button" not in summary.lower()
