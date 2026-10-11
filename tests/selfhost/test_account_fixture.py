"""Prove the API fixture uses native ceremonies, custody and live account standing."""

import pytest

from canvas_mcp.core.selfhost.accounts import AccessPolicy, AccessRule
from canvas_mcp.core.selfhost.token_store import OPERATOR

from .account_fixture import (
    CANVAS_TOKEN,
    KEY,
    OID,
    _display_in_utc,  # noqa: F401
    build_harness,
    put_row,
    sign_in,
)


def test_native_sign_in_and_stored_custody_are_visible_to_the_api(tmp_path):
    h = build_harness(tmp_path)
    assert h.client.get("/api/v1/me").status_code == 401
    assert sign_in(h).status_code == 303
    me = h.client.get("/api/v1/me").json()
    assert me["account"]["id"] == KEY
    assert me["account"]["username"] == "ada@example.test"
    assert me["account"]["status"] == "active"
    put_row(h.store, OID, token=CANVAS_TOKEN, name="Ada Canvas")
    me = h.client.get("/api/v1/me").json()
    assert me["canvas"]["custody"]["current"] is True
    assert h.store.get(KEY).api_token == CANVAS_TOKEN
    assert "<form" not in h.client.get("/account").text


def test_disabled_account_is_refused_using_its_existing_cookie(tmp_path):
    h = build_harness(tmp_path)
    sign_in(h)
    assert h.store.disable_principal(KEY, actor=OPERATOR, reason="operator_disabled")
    response = h.client.get("/api/v1/me")
    assert response.status_code == 401
    assert response.json()["error"]["code"] == "not_authenticated"


def test_pending_admission_and_browser_freshness_use_the_native_clock(tmp_path):
    policy = AccessPolicy(
        mode="approval", owner_rules=(AccessRule("entra", "role", "Canvas.Owner"),)
    )
    h = build_harness(tmp_path, policy=policy)
    assert sign_in(h).status_code == 303
    me = h.client.get("/api/v1/me").json()
    assert me["account"]["status"] == "pending" and me["session"]["fresh"]
    h.now += 601
    assert h.client.get("/api/v1/me").json()["session"]["fresh"] is False


@pytest.mark.parametrize("mode", ["open", "rules"])
def test_configured_admission_is_used_by_the_provider_ceremony(tmp_path, mode):
    policy = AccessPolicy(
        mode=mode, rules=(AccessRule("entra", "role", "Other.Role"),), owner_rules=()
    )
    h = build_harness(tmp_path, policy=policy)
    response = sign_in(h)
    assert response.status_code == 303
    if mode == "rules":
        assert response.headers["location"] == "/account/sign-in?error=access_denied"
        assert h.store.account_counts()["total"] == 0
    else:
        assert h.client.get("/api/v1/me").status_code == 200
