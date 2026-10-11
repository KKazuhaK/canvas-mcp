"""Account revocation and old-session replay through the native JSON API."""

from __future__ import annotations

import pathlib
from typing import Any

import pytest

from canvas_mcp.core.selfhost.account_core import SESSION_COOKIE
from canvas_mcp.core.selfhost.token_store import OPERATOR

from .account_fixture import (  # noqa: F401
    KEY,
    KEY_OWNER,
    OID,
    SESSION_SECRET,
    Harness,
    _display_in_utc,
    build_harness,
    sign_in,
)
from .test_account_api import (
    ACKNOWLEDGED,
    CANVAS_TOKEN,
    Api,
    error_of,
    sign_in_owner,
    snapshot_cookies,
    use_cookies,
)


@pytest.fixture
def h(tmp_path: pathlib.Path) -> Harness:
    return build_harness(tmp_path)


def session_payload(h: Harness) -> dict[str, Any]:
    payload = h.core.codec.unseal(SESSION_COOKIE, h.client.cookies.get(SESSION_COOKIE))
    assert payload is not None
    return payload


def use_payload(h: Harness, payload: dict[str, Any]) -> None:
    h.client.cookies.clear()
    h.client.cookies.set(
        SESSION_COOKIE,
        h.core.codec.seal(SESSION_COOKIE, payload),
        domain="canvas.example.test",
        path="/",
    )


@pytest.mark.parametrize("remove", [False, True])
def test_disabled_session_cannot_restore_enrollment_with_its_real_csrf(
    h: Harness, remove: bool
) -> None:
    sign_in(h)
    user = Api(h)
    csrf = user.csrf()
    assert (
        user.put(
            "/me/canvas-token", {"canvas_token": CANVAS_TOKEN, "custody": ACKNOWLEDGED}
        ).status_code
        == 200
    )
    old = snapshot_cookies(h)
    h.client.cookies.clear()
    sign_in_owner(h)
    owner = Api(h)
    assert owner.post(f"/admin/accounts/{KEY}/disable").status_code == 200
    if remove:
        assert owner.delete(f"/admin/enrollments/{KEY}").status_code == 200
    use_cookies(h, old)
    error_of(
        user.put(
            "/me/canvas-token",
            {"canvas_token": CANVAS_TOKEN, "custody": ACKNOWLEDGED},
            csrf=csrf,
        ),
        401,
        "not_authenticated",
    )
    assert h.whoami_calls == [CANVAS_TOKEN]
    assert (h.store.info(KEY) is None) is remove


@pytest.mark.parametrize("actor", ["self", "owner"])
def test_disconnect_preserves_account_and_allows_reenrollment(
    h: Harness, actor: str
) -> None:
    sign_in(h)
    user = Api(h)
    assert (
        user.put(
            "/me/canvas-token", {"canvas_token": CANVAS_TOKEN, "custody": ACKNOWLEDGED}
        ).status_code
        == 200
    )
    saved = snapshot_cookies(h)
    if actor == "owner":
        h.client.cookies.clear()
        sign_in_owner(h)
        assert Api(h).delete(f"/admin/enrollments/{KEY}").status_code == 200
        use_cookies(h, saved)
    else:
        assert user.delete("/me/canvas-token").status_code == 204
    assert h.store.get_principal_status(KEY).active
    assert (
        user.put(
            "/me/canvas-token", {"canvas_token": CANVAS_TOKEN, "custody": ACKNOWLEDGED}
        ).status_code
        == 200
    )


@pytest.mark.parametrize(
    "field,value",
    [
        ("v", 1),
        ("v", 2),
        ("ep", None),
        ("ep", "0"),
        ("ep", True),
        ("ep", -1),
        ("ep", 5),
        ("acct", "acct:aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"),
        ("pid", "google"),
        ("exp", True),
        ("csrf", ""),
        ("acct", "not-an-id"),
    ],
)
def test_session_cookie_refuses_old_or_malformed_claims(
    h: Harness, field: str, value: Any
) -> None:
    sign_in(h)
    payload = session_payload(h)
    if value is None:
        del payload[field]
    else:
        payload[field] = value
    use_payload(h, payload)
    error_of(Api(h).get("/me"), 401, "not_authenticated")


@pytest.mark.parametrize("iat", [None, True, "today", 0, 1_800_001_000])
def test_invalid_issue_time_or_time_beyond_skew_never_counts_as_recent(
    h: Harness, iat: Any
) -> None:
    sign_in_owner(h)
    payload = session_payload(h)
    if iat is None:
        del payload["iat"]
    else:
        payload["iat"] = iat
    use_payload(h, payload)
    assert Api(h).get("/me").status_code == 200
    error_of(Api(h).get("/admin/accounts"), 403, "reauth_required")


def test_signed_owner_flag_cannot_override_database_role(h: Harness) -> None:
    sign_in(h)
    payload = session_payload(h)
    payload["owner"] = True
    use_payload(h, payload)
    assert Api(h).get("/me").json()["account"]["role"] == "user"
    error_of(Api(h).get("/admin/accounts"), 403, "forbidden")


def test_disable_and_enable_changes_epoch_and_new_sign_in_uses_it(h: Harness) -> None:
    sign_in(h)
    before = session_payload(h)
    h.store.disable_principal(KEY, actor=OPERATOR, reason="operator_disabled")
    h.store.enable_principal(KEY, actor=OPERATOR)
    error_of(Api(h).get("/me"), 401, "not_authenticated")
    h.client.cookies.clear()
    sign_in(h)
    after = session_payload(h)
    assert after["ep"] == before["ep"] + 2
    assert after["ep"] == h.store.read_session_snapshot(KEY).session_epoch
    assert Api(h).get("/me").status_code == 200


def test_cookie_expiry_is_checked_by_the_server(h: Harness) -> None:
    sign_in(h)
    h.now += 901
    error_of(Api(h).get("/me"), 401, "not_authenticated")


def test_login_history_stores_digest_and_not_user_agent(h: Harness) -> None:
    from dbbackend import raw_sql

    agent = "Browser unique-marker-9f3a"
    h.client.headers["user-agent"] = agent
    sign_in(h)
    rows = raw_sql(h.store, "SELECT ua_hash FROM auth_events")
    assert rows and all(isinstance(row[0], bytes) and len(row[0]) == 8 for row in rows)
    assert agent not in repr(raw_sql(h.store, "SELECT * FROM auth_events"))
    assert "unique-marker" not in Api(h).get("/me/login-history").text
