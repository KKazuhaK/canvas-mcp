"""The JSON API under /account/api, on whichever backend the run selects.

The API is exercised through the "fallback" composition (``ui="react"`` without a
built bundle): the HTML pages and the API are registered over one application, which
is also how the shared rate-limit budget and the shared operations are proved.
"""

from __future__ import annotations

import copy
import json
import logging
import pathlib
import sqlite3
from collections.abc import Sequence
from typing import Any

import httpx
import pytest

from canvas_mcp.core import audit
from canvas_mcp.core.selfhost import account_api
from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost.account_web import (
    SESSION_COOKIE,
    CanvasCheckError,
    CanvasIdentity,
)
from canvas_mcp.core.selfhost.accounts import AccessPolicy, AccessRule
from canvas_mcp.core.selfhost.db.errors import StoreUnavailable
from canvas_mcp.core.selfhost.schools import (
    DirectoryEntry,
    FeaturedSchool,
    SchoolPolicy,
)
from canvas_mcp.core.selfhost.token_store import ToolPrefs
from canvas_mcp.core.selfhost.tool_prefs import ToolPrefsCache, WriteToolCatalog

from .conftest import acct_key, make_account
from .test_account_schools import (
    DEFAULT_HOST,
    DEFAULT_URL,
    HOST_A,
    HOST_B,
    FakeDirectory,
    FakeResolver,
)
from .test_account_web import (
    BASE,
    CANVAS_TOKEN,
    KEY,
    KEY_2,
    KEY_OWNER,
    OID,
    OID_2,
    OID_OWNER,
    Harness,
    _display_in_utc,  # noqa: F401 - autouse fixture: timestamps render in UTC
    build_harness,
    make_cfg,
    put_row,
    sign_in,
)

P = "/account/api"
OID_PENDING = "dddddddd-0000-4000-8000-0000000000dd"
OID_BLOCKED = "eeeeeeee-0000-4000-8000-0000000000ee"
OWNER_RULE = AccessRule("entra", "role", "Canvas.Owner")
APPROVAL = AccessPolicy(mode="approval", owner_rules=(OWNER_RULE,))
NEW_TOKEN = "8~" + "N" * 62
OTHER_TOKEN = "9~" + "O" * 62

REGISTERED = [
    "list_courses",
    "send_message",
    "reply_to_conversation",
    "mark_module_item_done",
    "create_planner_note",
    "create_assignment",
    "delete_page",
]
CEILING = {
    "send_message",
    "reply_to_conversation",
    "mark_module_item_done",
    "create_planner_note",
    "create_assignment",
}


# -- harness ---------------------------------------------------------------------


class Api:
    """JSON calls as the single-page app makes them, with the CSRF header fetched on demand."""

    def __init__(self, h: Harness) -> None:
        self.h = h
        self._csrf: dict[str, str] = {}

    def csrf(self) -> str:
        cookie = self.h.client.cookies.get(SESSION_COOKIE) or ""
        if cookie not in self._csrf:
            response = self.h.client.get(f"{P}/me")
            assert response.status_code == 200, response.text
            self._csrf[cookie] = response.json()["csrf_token"]
        return self._csrf[cookie]

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        headers = dict(kwargs.pop("headers", {}))
        if kwargs.pop("csrf", False):
            headers["X-CSRF-Token"] = self.csrf()
        return self.h.client.get(P + path, headers=headers, **kwargs)

    def call(
        self,
        method: str,
        path: str,
        body: Any = None,
        *,
        csrf: bool | str = True,
        origin: str | None = BASE,
        headers: dict[str, str] | None = None,
        content: bytes | None = None,
        content_type: str | None = "application/json",
        fetch_site: str | None = None,
    ) -> httpx.Response:
        sent: dict[str, str] = dict(headers or {})
        if csrf is True:
            sent["X-CSRF-Token"] = self.csrf()
        elif isinstance(csrf, str):
            sent["X-CSRF-Token"] = csrf
        if origin is not None:
            sent["Origin"] = origin
        if fetch_site is not None:
            sent["Sec-Fetch-Site"] = fetch_site
        raw = content
        if raw is None and body is not None:
            raw = json.dumps(body).encode("utf-8")
        if raw is not None and content_type is not None:
            sent["Content-Type"] = content_type
        return self.h.client.request(method, P + path, content=raw, headers=sent)

    def put(self, path: str, body: Any, **kwargs: Any) -> httpx.Response:
        return self.call("PUT", path, body, **kwargs)

    def post(self, path: str, body: Any = None, **kwargs: Any) -> httpx.Response:
        return self.call("POST", path, body, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        return self.call("DELETE", path, **kwargs)


def snapshot_cookies(h: Harness) -> httpx.Cookies:
    saved = httpx.Cookies()
    for cookie in h.client.cookies.jar:
        saved.jar.set_cookie(copy.copy(cookie))
    return saved


def use_cookies(h: Harness, saved: httpx.Cookies) -> None:
    h.client.cookies.clear()
    for cookie in saved.jar:
        h.client.cookies.jar.set_cookie(copy.copy(cookie))


def sign_in_owner(h: Harness) -> None:
    assert sign_in(h, oid=OID_OWNER, name="Olive Owner", upn="olive@example.test",
                   roles=("Canvas.Owner",)).status_code == 303


def error_of(response: httpx.Response, status: int, code: str) -> dict[str, Any]:
    assert response.status_code == status, (response.status_code, response.text)
    body = response.json()
    assert set(body) == {"error"}, body
    assert body["error"]["code"] == code, body
    assert code in account_api.API_ERROR_CODES
    params = body["error"].get("params", {})
    assert all(isinstance(v, str | int) for v in params.values())
    return dict(params)


def assert_api_headers(response: httpx.Response) -> None:
    headers = response.headers
    assert headers["content-type"] == "application/json; charset=utf-8"
    assert headers["cache-control"] == "no-store"
    assert headers["pragma"] == "no-cache"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["cross-origin-resource-policy"] == "same-origin"
    assert headers["content-security-policy"] == (
        "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
    )
    assert not [name for name in headers if name.lower().startswith("access-control-")]


def make(tmp_path: pathlib.Path, **kwargs: Any) -> Harness:
    return build_harness(tmp_path, ui="react", **kwargs)


@pytest.fixture
def h(tmp_path: pathlib.Path) -> Harness:
    return make(tmp_path)


@pytest.fixture
def api(h: Harness) -> Api:
    return Api(h)


@pytest.fixture
def user(h: Harness, api: Api) -> Api:
    assert sign_in(h).status_code == 303
    return api


@pytest.fixture
def events(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    lines: list[dict[str, Any]] = []

    class Recorder:
        def info(self, line: str) -> None:
            lines.append(json.loads(line))

    monkeypatch.setattr(audit, "_audit_logger", Recorder())
    monkeypatch.setattr(audit, "_access_events_enabled", True)
    return lines


def demote_directly(h: Harness, key: str) -> None:
    """Lower the stored role the way a later sign-in or request token would."""
    store = h.store
    with store._db.write() as conn:
        store._repos.accounts.set_role(
            conn, acc.account_id_of(key), role="user", source=None, seen_at=None, now=1
        )


def audit_rows(h: Harness) -> list[tuple[str, str | None, str | None]]:
    return [(e.action, e.target, e.reason) for e in h.store.list_audit(500)]


# -- providers and the shape of every answer ----------------------------------------------


class TestProviders:
    def test_it_needs_no_session_and_names_only_microsoft(self, h: Harness, api: Api) -> None:
        response = api.get("/providers")
        assert response.status_code == 200
        assert_api_headers(response)
        assert response.json() == {
            "providers": [
                {
                    "id": "entra",
                    "kind": "oidc",
                    "name": "Microsoft",
                    "icon": "microsoft",
                    "start_url": "/account/login",
                }
            ],
            "mcp_url": f"{BASE}/mcp",
        }

    def test_it_does_not_look_at_the_fetch_site_or_say_anything_about_admission(
        self, h: Harness, api: Api
    ) -> None:
        response = api.get("/providers", headers={"Sec-Fetch-Site": "cross-site"})
        assert response.status_code == 200
        text = response.text.lower()
        assert "tenant" not in text and "approval" not in text and "role" not in text


class TestTransport:
    def test_every_route_without_a_session_is_401(self, h: Harness, api: Api) -> None:
        table = account_api.ApiApp(None).route_table()  # type: ignore[arg-type]
        seen = 0
        for path, endpoints in table:
            url = path.replace("{id}", OID_2)
            for method, endpoint in endpoints.items():
                response = h.client.request(
                    method, url, headers={"Origin": BASE, "X-CSRF-Token": "x"}
                )
                if endpoint.access == "public":
                    assert response.status_code == 200
                else:
                    error_of(response, 401, "not_authenticated")
                assert_api_headers(response)
                seen += 1
        assert seen == 23

    def test_a_known_path_with_the_wrong_method_is_405_with_allow(self, user: Api) -> None:
        response = user.call("PATCH", "/me/canvas-token")
        error_of(response, 405, "method_not_allowed")
        assert response.headers["allow"] == "DELETE, GET, PUT"
        assert_api_headers(response)
        response = user.h.client.post(f"{P}/me")
        error_of(response, 405, "method_not_allowed")
        assert response.headers["allow"] == "GET"

    def test_options_and_head_are_refused_and_nothing_is_cors(self, user: Api) -> None:
        for method in ("OPTIONS", "HEAD"):
            response = user.h.client.request(
                method,
                f"{P}/me",
                headers={
                    "Origin": "https://evil.example",
                    "Access-Control-Request-Method": "PUT",
                },
            )
            assert response.status_code == 405
            assert not [n for n in response.headers if n.lower().startswith("access-control-")]
            if method == "OPTIONS":
                assert_api_headers(response)

    @pytest.mark.parametrize(
        "path",
        [
            "/nothing",
            "/me/identities",
            "/me/grants",
            "/me/grants/abc",
            "/consent/abc",
            "/me/",
            "/me/canvas-token/",
            "/admin",
            "/admin/accounts/x/set-role",
            "/admin/accounts/x/unlink",
            "/admin/accounts/x/revoke-grants",
            "/",
            "",
        ],
    )
    def test_an_unknown_path_is_a_json_404(self, user: Api, path: str) -> None:
        for method in ("GET", "POST", "PUT", "DELETE", "OPTIONS"):
            response = user.h.client.request(method, P + path)
            error_of(response, 404, "not_found")
            assert_api_headers(response)

    def test_the_session_cookie_is_the_one_the_pages_use(self, h: Harness, user: Api) -> None:
        assert h.client.cookies.get(SESSION_COOKIE)
        assert user.get("/me").status_code == 200

    def test_logout_everywhere_is_not_a_thing(self, user: Api) -> None:
        response = user.post("/session/logout?all=1", csrf=True)
        error_of(response, 422, "validation_failed")

    def test_logout_clears_the_cookie_and_signs_out(self, h: Harness, user: Api) -> None:
        response = user.post("/session/logout")
        assert response.status_code == 204 and response.content == b""
        assert_api_headers(response)
        line = next(
            x for x in response.headers.get_list("set-cookie") if x.startswith(SESSION_COOKIE)
        ).lower()
        assert "max-age=0" in line and "secure" in line and "httponly" in line
        assert "samesite=lax" in line and "path=/" in line
        error_of(user.get("/me"), 401, "not_authenticated")

    def test_logout_needs_the_csrf_header(self, user: Api) -> None:
        error_of(user.post("/session/logout", csrf=False), 403, "csrf_invalid")
        assert user.get("/me").status_code == 200


# -- /me ------------------------------------------------------------------------------------------


class TestMe:
    def test_an_active_user(self, h: Harness, user: Api) -> None:
        response = user.get("/me")
        assert response.status_code == 200
        assert_api_headers(response)
        body = response.json()
        assert body["account"] == {
            "id": KEY.removeprefix("acct:"),
            "key": KEY,
            "display_name": "Ada Lovelace",
            "username": "ada@example.test",
            "provider_id": "entra",
            "role": "user",
            "status": "active",
        }
        assert body["csrf_token"] and len(body["csrf_token"]) >= 32
        assert body["session"]["fresh"] is True
        assert body["session"]["fresh_window_s"] == 600
        assert body["session"]["issued_at"] == "2027-01-15T08:00:00Z"
        assert body["session"]["fresh_until"] == "2027-01-15T08:10:00Z"
        assert body["session"]["expires_at"] == "2027-01-15T08:15:00Z"
        assert body["canvas"]["state"] == "none"
        assert body["write_tools"] is None
        assert body["features"] == {
            "school_picker": False,
            "school_search": False,
            "write_tools": False,
            "admin": False,
            "identities": False,
            "connected_apps": False,
            "consent": False,
            "logout_everywhere": False,
            "role_management": False,
        }
        assert body["ui_locale"] is None
        assert body["server"] == {"mcp_url": f"{BASE}/mcp", "display_timezone": "UTC"}

    def test_the_session_goes_stale_after_ten_minutes(self, h: Harness, user: Api) -> None:
        h.now += 601
        body = user.get("/me").json()
        assert body["session"]["fresh"] is False
        assert body["session"]["fresh_until"] is None

    def test_an_owner_sees_the_admin_feature(self, h: Harness, api: Api) -> None:
        sign_in_owner(h)
        body = api.get("/me").json()
        assert body["account"]["role"] == "owner"
        assert body["features"]["admin"] is True

    def test_a_pending_account_sees_almost_nothing(self, tmp_path: pathlib.Path) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())
        body = Api(h).get("/me").json()
        assert body["account"]["status"] == "pending"
        assert body["canvas"] is None and body["write_tools"] is None
        assert not any(body["features"].values())

    def test_the_display_timezone_is_reported(
        self, h: Harness, user: Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from zoneinfo import ZoneInfo

        from canvas_mcp.core.selfhost import account_web

        monkeypatch.setattr(account_web, "output_timezone", lambda: ZoneInfo("America/Los_Angeles"))
        assert user.get("/me").json()["server"]["display_timezone"] == "America/Los_Angeles"

    def test_the_language_cookie_is_reflected(self, h: Harness, user: Api) -> None:
        h.client.cookies.set("canvas_mcp_lang", "zh", path="/account")
        assert user.get("/me").json()["ui_locale"] == "zh"
        h.client.cookies.set("canvas_mcp_lang", "fr", path="/account")
        assert user.get("/me").json()["ui_locale"] is None

    def test_a_disabled_account_is_signed_out(self, h: Harness, user: Api) -> None:
        from canvas_mcp.core.selfhost.token_store import OPERATOR

        assert user.get("/me").status_code == 200
        h.store.disable_principal(KEY, actor=OPERATOR, reason="operator_disabled")
        error_of(user.get("/me"), 401, "not_authenticated")

    def test_a_changed_session_epoch_is_signed_out(self, h: Harness, user: Api) -> None:
        from canvas_mcp.core.selfhost.token_store import OPERATOR

        h.store.disable_principal(KEY, actor=OPERATOR, reason="operator_disabled")
        h.store.enable_principal(KEY, actor=OPERATOR)
        error_of(user.get("/me"), 401, "not_authenticated")

    def test_a_deleted_account_is_signed_out(self, tmp_path: pathlib.Path) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())
        a = Api(h)
        assert a.get("/me").status_code == 200
        assert h.store.purge_stale_pending(retention_seconds=-10) == 1
        error_of(a.get("/me"), 401, "not_authenticated")

    def test_a_store_failure_is_503_and_names_nothing(
        self, h: Harness, user: Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(_key: str) -> Any:
            raise sqlite3.OperationalError("database is locked: /secret/path.db")

        monkeypatch.setattr(h.store, "get_principal_status", boom)
        response = user.get("/me")
        error_of(response, 503, "token_store_unavailable")
        assert "secret" not in response.text and "locked" not in response.text

    def test_the_stored_owner_role_beats_the_cookie(self, h: Harness, api: Api) -> None:
        sign_in_owner(h)
        demote_directly(h, KEY_OWNER)
        body = api.get("/me").json()
        assert body["account"]["role"] == "user"
        assert body["features"]["admin"] is False

    def test_the_cross_site_fetch_metadata_is_refused(self, user: Api) -> None:
        for value in ("cross-site", "same-site"):
            error_of(user.get("/me", headers={"Sec-Fetch-Site": value}), 403, "origin_not_allowed")
        for value in ("same-origin", "none"):
            assert user.get("/me", headers={"Sec-Fetch-Site": value}).status_code == 200


# -- CSRF, Origin, content type and bodies ----------------------------------------------------------

MUTATIONS: list[tuple[str, str, Any]] = [
    ("PUT", "/me/canvas-token", {"canvas_token": CANVAS_TOKEN}),
    ("DELETE", "/me/canvas-token", None),
    ("POST", "/me/canvas-token/recheck", None),
    ("PUT", "/me/write-tools", {"enabled": []}),
    ("DELETE", "/me/write-tools", None),
    ("PUT", "/me/ui-locale", {"locale": "zh"}),
    ("POST", "/session/logout", None),
]


class TestCsrfAndOrigin:
    @pytest.mark.parametrize(("method", "path", "body"), MUTATIONS)
    def test_a_mutation_needs_the_csrf_header(
        self, user: Api, method: str, path: str, body: Any
    ) -> None:
        error_of(user.call(method, path, body, csrf=False), 403, "csrf_invalid")
        error_of(user.call(method, path, body, csrf="not-the-token"), 403, "csrf_invalid")
        error_of(user.call(method, path, body, csrf=""), 403, "csrf_invalid")

    @pytest.mark.parametrize(("method", "path", "body"), MUTATIONS)
    def test_another_sessions_token_is_refused(
        self, h: Harness, user: Api, method: str, path: str, body: Any
    ) -> None:
        mine = snapshot_cookies(h)
        other_token = user.csrf()
        h.client.cookies.clear()
        sign_in(h, oid=OID_2, name="Bob", upn="bob@example.test")
        bob = user.csrf()
        assert bob != other_token
        error_of(user.call(method, path, body, csrf=other_token), 403, "csrf_invalid")
        use_cookies(h, mine)

    @pytest.mark.parametrize(("method", "path", "body"), MUTATIONS)
    def test_the_origin_must_be_the_public_base_url(
        self, user: Api, method: str, path: str, body: Any
    ) -> None:
        error_of(user.call(method, path, body, origin=None), 403, "origin_not_allowed")
        error_of(
            user.call(method, path, body, origin="https://evil.example"), 403, "origin_not_allowed"
        )
        error_of(user.call(method, path, body, origin=BASE + "/"), 403, "origin_not_allowed")

    @pytest.mark.parametrize(("method", "path", "body"), MUTATIONS)
    def test_fetch_metadata_must_say_same_origin(
        self, user: Api, method: str, path: str, body: Any
    ) -> None:
        for value in ("cross-site", "same-site", "none"):
            error_of(
                user.call(method, path, body, fetch_site=value), 403, "origin_not_allowed"
            )

    def test_the_origin_is_checked_before_the_csrf_token(self, user: Api) -> None:
        error_of(
            user.delete("/me/canvas-token", csrf=False, origin="https://evil.example"),
            403,
            "origin_not_allowed",
        )

    @pytest.mark.parametrize(
        "content_type", ["application/x-www-form-urlencoded", "text/plain", "application/jsonx", None]
    )
    def test_a_body_must_be_json(self, user: Api, content_type: str | None) -> None:
        response = user.call(
            "PUT", "/me/ui-locale", content=b"locale=zh", content_type=content_type
        )
        error_of(response, 415, "unsupported_media_type")

    def test_a_non_utf8_charset_is_refused(self, user: Api) -> None:
        response = user.call(
            "PUT",
            "/me/ui-locale",
            content=b'{"locale":"zh"}',
            content_type="application/json; charset=latin-1",
        )
        error_of(response, 415, "unsupported_media_type")
        ok = user.call(
            "PUT",
            "/me/ui-locale",
            content=b'{"locale":"zh"}',
            content_type="Application/JSON; charset=UTF-8",
        )
        assert ok.status_code == 204

    def test_the_school_search_is_a_get_that_still_needs_the_token(
        self, tmp_path: pathlib.Path
    ) -> None:
        r = schools_rig(tmp_path, search=True)
        sign_in(r.h)
        a = Api(r.h)
        error_of(a.get("/me/schools/search?q=abc"), 403, "csrf_invalid")
        error_of(
            a.get("/me/schools/search?q=abc", headers={"X-CSRF-Token": "no"}), 403, "csrf_invalid"
        )
        assert r.directory.calls == 0
        assert a.get("/me/schools/search?q=abc", csrf=True).status_code == 200

    def test_a_pending_account_is_refused_before_the_origin_is_looked_at(
        self, tmp_path: pathlib.Path
    ) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())
        a = Api(h)
        error_of(a.delete("/me/canvas-token", origin=None, csrf=False), 403, "pending_approval")


class TestBodies:
    def test_more_than_8_kib_is_413(self, user: Api) -> None:
        big = json.dumps({"locale": "zh", "pad": "x" * 9000}).encode()
        error_of(user.call("PUT", "/me/ui-locale", content=big), 413, "payload_too_large")

    def test_a_declared_length_over_the_cap_is_refused_before_reading(self, user: Api) -> None:
        response = user.call(
            "PUT",
            "/me/ui-locale",
            content=b'{"locale":"zh"}',
            headers={"Content-Length": "100000"},
        )
        assert response.status_code in (413, 400)
        assert response.json()["error"]["code"] in ("payload_too_large", "malformed_request")

    def test_a_streamed_body_over_the_cap_is_413(self, user: Api) -> None:
        def chunks() -> Any:
            for _ in range(10):
                yield b"x" * 1000

        response = user.h.client.put(
            f"{P}/me/ui-locale",
            content=chunks(),
            headers={
                "Origin": BASE,
                "X-CSRF-Token": user.csrf(),
                "Content-Type": "application/json",
            },
        )
        error_of(response, 413, "payload_too_large")

    @pytest.mark.parametrize(
        "raw",
        [
            b"",
            b"{",
            b"not json",
            b'{"locale": "zh"} trailing',
            b'{"locale": "zh", "locale": "en"}',
            b'{"locale": NaN}',
            b'{"locale": Infinity}',
            b'{"locale": -Infinity}',
            b'{"locale": 1e999}',
            b'["locale"]',
            b'"locale"',
            b"null",
            b"1",
            b'\xff\xfe{"locale":"zh"}',
            b'{"locale":"\xff"}',
            b"[" * 5000,
        ],
    )
    def test_bad_json_is_400(self, user: Api, raw: bytes) -> None:
        error_of(user.call("PUT", "/me/ui-locale", content=raw), 400, "malformed_request")

    def test_an_unknown_field_is_422_and_names_the_field(self, user: Api) -> None:
        params = error_of(
            user.put("/me/ui-locale", {"locale": "zh", "extra": 1}), 422, "validation_failed"
        )
        assert params == {"field": "extra"}

    def test_an_odd_field_name_is_not_echoed(self, user: Api) -> None:
        params = error_of(
            user.put("/me/ui-locale", {"locale": "zh", "<script>": 1}), 422, "validation_failed"
        )
        assert params == {"field": "body"}

    @pytest.mark.parametrize("value", [1, None, ["zh"], {"a": 1}, "fr", "", "ZH"])
    def test_a_wrong_value_is_422(self, user: Api, value: Any) -> None:
        params = error_of(user.put("/me/ui-locale", {"locale": value}), 422, "validation_failed")
        assert params == {"field": "locale"}

    def test_a_missing_field_is_422(self, user: Api) -> None:
        params = error_of(user.put("/me/ui-locale", {}), 422, "validation_failed")
        assert params == {"field": "locale"}

    @pytest.mark.parametrize(
        ("method", "path"),
        [
            ("DELETE", "/me/canvas-token"),
            ("POST", "/me/canvas-token/recheck"),
            ("DELETE", "/me/write-tools"),
            ("POST", "/session/logout"),
        ],
    )
    def test_a_body_less_mutation_refuses_a_body(self, user: Api, method: str, path: str) -> None:
        error_of(user.call(method, path, content=b"{}"), 400, "malformed_request")
        error_of(user.call(method, path, {"x": 1}), 400, "malformed_request")

    def test_a_locale_change_sets_the_language_cookie_like_the_pages(
        self, h: Harness, user: Api
    ) -> None:
        response = user.put("/me/ui-locale", {"locale": "zh"})
        assert response.status_code == 204
        line = next(
            x for x in response.headers.get_list("set-cookie") if x.startswith("canvas_mcp_lang=")
        ).lower()
        assert "canvas_mcp_lang=zh" in line and "path=/account" in line
        assert "secure" in line and "httponly" in line and "samesite=lax" in line
        assert user.get("/me").json()["ui_locale"] == "zh"


# -- the Canvas token --------------------------------------------------------------------------------


class SchoolsRig:
    def __init__(self, h: Harness, directory: FakeDirectory, resolver: FakeResolver) -> None:
        self.h = h
        self.directory = directory
        self.resolver = resolver


def schools_rig(
    tmp_path: pathlib.Path,
    *,
    default: str = DEFAULT_URL,
    featured: Sequence[FeaturedSchool] = (
        FeaturedSchool(HOST_A, "School <b>A</b>"),
        FeaturedSchool(HOST_B, "School B"),
    ),
    search: bool = False,
    entries: Sequence[DirectoryEntry] = (),
    directory_error: bool = False,
    resolver: FakeResolver | None = None,
    **extra: Any,
) -> SchoolsRig:
    directory = FakeDirectory(entries, error=directory_error)
    fake_resolver = resolver or FakeResolver()
    policy = SchoolPolicy.build(default, featured, search)
    h = make(
        tmp_path,
        cfg=make_cfg(schools=policy),
        directory=directory,
        resolve_host=fake_resolver,
        **extra,
    )
    return SchoolsRig(h, directory, fake_resolver)


class TestCanvasTokenRead:
    def test_none_yet(self, user: Api) -> None:
        response = user.get("/me/canvas-token")
        assert response.status_code == 200
        body = response.json()
        assert body["state"] == "none"
        assert body["recheck_allowed"] is False and body["school"] is None
        assert body["expiry_notice"] == "none" and body["settings_url"] is None

    def test_an_enrolled_token(self, h: Harness, user: Api) -> None:
        put_row(
            h.store, OID, token=CANVAS_TOKEN, name="Ada Canvas", canvas_user_id="42",
            canvas_host="canvas.example.test",
        )
        body = user.get("/me/canvas-token").json()
        assert body["state"] == "active"
        assert body["canvas_user_id"] == "42" and body["canvas_user_name"] == "Ada Canvas"
        assert body["school"] == {
            "host": "canvas.example.test", "name": "canvas.example.test", "offered": True,
        }
        assert body["invalid_reason"] is None and body["recheck_allowed"] is False
        assert body["settings_url"] == "https://canvas.example.test/profile/settings"
        assert body["enrolled_at"] == "2027-01-15T08:00:00Z"
        assert body["last_used_at"] is None
        assert CANVAS_TOKEN not in json.dumps(body)

    def test_a_pending_account_is_refused(self, tmp_path: pathlib.Path) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())
        error_of(Api(h).get("/me/canvas-token"), 403, "pending_approval")

    @pytest.mark.parametrize(
        ("reason", "allowed"),
        [("canvas_token_rejected", True), ("decrypt_failed", True), ("revoked_by_admin", False)],
    )
    def test_an_invalid_token_and_whether_it_can_be_rechecked(
        self, h: Harness, user: Api, reason: str, allowed: bool
    ) -> None:
        put_row(h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42")
        h.store.mark_invalid(KEY, reason=reason)
        body = user.get("/me/canvas-token").json()
        assert body["state"] == "invalid"
        assert body["invalid_reason"] == reason
        assert body["invalid_since"] == "2027-01-15T08:00:00Z"
        assert body["recheck_allowed"] is allowed

    def test_the_expiry_reminder(self, h: Harness, user: Api) -> None:
        day = 86400
        # h.now is 2027-01-15 08:00 UTC; the hint is stored as midnight UTC.
        base = int(h.now) - int(h.now) % day
        put_row(
            h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42",
            expires_hint_at=base + 30 * day,
        )
        body = user.get("/me/canvas-token").json()
        assert body["expires_on"] == "2027-02-14" and body["expiry_notice"] == "none"
        for delta, notice in ((6 * day, "soon"), (0, "soon"), (-1 * day, "passed")):
            put_row(
                h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42",
                expires_hint_at=base + delta,
            )
            assert user.get("/me/canvas-token").json()["expiry_notice"] == notice, delta
        put_row(
            h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42",
            expires_hint_at=base + 8 * day,
        )
        assert user.get("/me/canvas-token").json()["expiry_notice"] == "none"

    def test_a_school_the_server_no_longer_offers(self, h: Harness, user: Api) -> None:
        put_row(
            h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42",
            canvas_host="canvas.gone.edu",
        )
        body = user.get("/me/canvas-token").json()
        assert body["school"] == {"host": "canvas.gone.edu", "name": "canvas.gone.edu", "offered": False}
        assert body["settings_url"] is None


class TestCanvasTokenSave:
    def test_a_new_token_is_verified_stored_and_audited(
        self, h: Harness, user: Api, events: list[dict[str, Any]]
    ) -> None:
        response = user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN})
        assert response.status_code == 200
        assert_api_headers(response)
        body = response.json()
        assert body["state"] == "active" and body["canvas_user_name"] == "Ada Canvas"
        assert body["canvas_user_id"] == "42"
        assert h.whoami_calls == [CANVAS_TOKEN]
        assert h.whoami_urls == ["https://canvas.example.test/api/v1"]
        stored = h.store.get(KEY)
        assert stored is not None and stored.api_token == CANVAS_TOKEN
        assert CANVAS_TOKEN not in response.text
        assert ("token_enrolled", KEY, None) in audit_rows(h)

    def test_a_replacement_keeps_the_audit_trail(self, h: Harness, user: Api) -> None:
        user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN})
        user.put("/me/canvas-token", {"canvas_token": NEW_TOKEN})
        assert [r[0] for r in audit_rows(h)].count("token_replaced") == 1

    def test_the_expiry_date_is_stored(self, h: Harness, user: Api) -> None:
        response = user.put(
            "/me/canvas-token", {"canvas_token": CANVAS_TOKEN, "expires_on": "2027-03-01"}
        )
        assert response.json()["expires_on"] == "2027-03-01"

    @pytest.mark.parametrize("value", ["2027-02-30", "yesterday", "2027-1-1", "2020-01-01", "2099-01-01", "x" * 40])
    def test_a_bad_expiry_date_is_422(self, h: Harness, user: Api, value: str) -> None:
        params = error_of(
            user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN, "expires_on": value}),
            422, "validation_failed",
        )
        assert params == {"field": "expires_on"}
        assert h.whoami_calls == []

    @pytest.mark.parametrize("token", ["short", "has space " + "x" * 30, "ü" * 30, "x" * 600, ""])
    def test_a_badly_shaped_token_is_refused_without_asking_canvas(
        self, h: Harness, user: Api, token: str
    ) -> None:
        error_of(user.put("/me/canvas-token", {"canvas_token": token}), 422, "token_invalid_format")
        assert h.whoami_calls == []

    @pytest.mark.parametrize(
        "body",
        [
            {},
            {"canvas_token": 5},
            {"canvas_token": None},
            {"canvas_token": CANVAS_TOKEN, "school": 3},
            {"canvas_token": CANVAS_TOKEN, "school_sig": 3},
            {"canvas_token": CANVAS_TOKEN, "expires_on": 20270101},
            {"canvas_token": CANVAS_TOKEN, "confirm_identity_change": ["x"]},
            {"canvas_token": CANVAS_TOKEN, "principal_key": KEY_2},
            {"canvas_token": CANVAS_TOKEN, "account": KEY_2},
        ],
    )
    def test_the_field_set_is_closed(self, h: Harness, user: Api, body: dict[str, Any]) -> None:
        error_of(user.put("/me/canvas-token", body), 422, "validation_failed")
        assert h.whoami_calls == []
        assert h.store.info(KEY) is None

    def test_canvas_rejecting_the_token(self, h: Harness, user: Api) -> None:
        h.whoami_result = CanvasCheckError("invalid")
        response = user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN})
        error_of(response, 422, "token_rejected")
        assert h.store.info(KEY) is None

    def test_canvas_being_down(self, h: Harness, user: Api) -> None:
        h.whoami_result = CanvasCheckError("unavailable")
        error_of(user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN}), 503, "canvas_unavailable")

    def test_a_pending_account_cannot_save(self, tmp_path: pathlib.Path) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())
        error_of(
            Api(h).put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN}), 403, "pending_approval"
        )
        assert h.whoami_calls == [] and h.store.count() == 0

    def test_an_account_disabled_after_the_session_check_is_refused_by_the_store(
        self, h: Harness, user: Api, events: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from canvas_mcp.core.selfhost.token_store import OPERATOR

        real = h.store.get_principal_status

        def status_then_disable(key: str) -> Any:
            status = real(key)
            h.store.disable_principal(KEY, actor=OPERATOR, reason="operator_disabled")
            return status

        user.csrf()
        monkeypatch.setattr(h.store, "get_principal_status", status_then_disable)
        response = user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN})
        error_of(response, 403, "access_disabled")
        assert h.store.info(KEY) is None
        assert any(e.get("action") == "enroll_refused" for e in events)

    def test_a_store_failure_while_saving_is_503(
        self, h: Harness, user: Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        def boom(**_kw: Any) -> Any:
            raise StoreUnavailable()

        monkeypatch.setattr(h.store, "put", boom)
        response = user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN})
        error_of(response, 503, "token_store_unavailable")
        assert CANVAS_TOKEN not in response.text

    def test_the_token_never_reaches_the_log(
        self, h: Harness, user: Api, caplog: pytest.LogCaptureFixture
    ) -> None:
        caplog.set_level(logging.DEBUG)
        user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN})
        h.whoami_result = CanvasCheckError("invalid")
        user.put("/me/canvas-token", {"canvas_token": OTHER_TOKEN})
        text = caplog.text + "".join(r.getMessage() for r in caplog.records)
        assert CANVAS_TOKEN not in text and OTHER_TOKEN not in text

    def test_ten_attempts_per_ten_minutes_with_retry_after(self, h: Harness, user: Api) -> None:
        for _ in range(10):
            user.put("/me/canvas-token", {"canvas_token": "short"})
        response = user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN})
        params = error_of(response, 429, "rate_limited")
        assert params == {"retry_after_s": 600}
        assert response.headers["retry-after"] == "600"
        assert h.whoami_calls == []
        h.now += 601
        # The session is still valid for 900 s; the budget is back.
        assert user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN}).status_code == 200

    def test_the_budget_is_shared_with_the_html_form(self, h: Harness, user: Api) -> None:
        from .test_account_web import csrf_of, post_form

        csrf = csrf_of(h)
        for _ in range(5):
            post_form(h, "/account/token", {"csrf": csrf, "canvas_token": "short"})
        for _ in range(5):
            user.put("/me/canvas-token", {"canvas_token": "short"})
        error_of(user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN}), 429, "rate_limited")
        assert post_form(
            h, "/account/token", {"csrf": csrf, "canvas_token": CANVAS_TOKEN}
        ).status_code == 429

    def test_each_account_has_its_own_budget(self, h: Harness, user: Api) -> None:
        mine = snapshot_cookies(h)
        for _ in range(10):
            user.put("/me/canvas-token", {"canvas_token": "short"})
        h.client.cookies.clear()
        sign_in(h, oid=OID_2, name="Bob", upn="bob@example.test")
        assert user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN}).status_code == 200
        use_cookies(h, mine)


class TestIdentityChange:
    def enroll(self, h: Harness, a: Api) -> None:
        h.whoami_result = CanvasIdentity("42", "Ada Canvas")
        assert a.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN}).status_code == 200

    def test_a_token_of_another_canvas_user_needs_a_confirmation(
        self, h: Harness, user: Api, events: list[dict[str, Any]]
    ) -> None:
        self.enroll(h, user)
        h.whoami_result = CanvasIdentity("77", "Bob \x07Canvas")
        response = user.put("/me/canvas-token", {"canvas_token": NEW_TOKEN})
        params = error_of(response, 409, "identity_change_required")
        assert params["enrolled_user_name"] == "Ada Canvas"
        assert params["new_user_name"] == "Bob Canvas"
        confirmation = str(params["confirmation"])
        assert len(confirmation) >= 40
        stored = h.store.get(KEY)
        assert stored is not None and stored.api_token == CANVAS_TOKEN  # unchanged
        assert any(e.get("action") == "identity_change_detected" for e in events)

        response = user.put(
            "/me/canvas-token", {"canvas_token": NEW_TOKEN, "confirm_identity_change": confirmation}
        )
        assert response.status_code == 200
        assert response.json()["canvas_user_name"] == "Bob Canvas"
        assert any(e.get("action") == "identity_change_confirmed" for e in events)

    def test_a_confirmation_does_not_carry_to_a_third_user(self, h: Harness, user: Api) -> None:
        self.enroll(h, user)
        h.whoami_result = CanvasIdentity("77", "Bob")
        confirmation = str(
            error_of(
                user.put("/me/canvas-token", {"canvas_token": NEW_TOKEN}), 409, "identity_change_required"
            )["confirmation"]
        )
        h.whoami_result = CanvasIdentity("88", "Cleo")
        error_of(
            user.put(
                "/me/canvas-token",
                {"canvas_token": OTHER_TOKEN, "confirm_identity_change": confirmation},
            ),
            409,
            "identity_change_required",
        )

    def test_a_confirmation_is_bound_to_the_session(self, h: Harness, user: Api) -> None:
        self.enroll(h, user)
        h.whoami_result = CanvasIdentity("77", "Bob")
        confirmation = str(
            error_of(
                user.put("/me/canvas-token", {"canvas_token": NEW_TOKEN}), 409, "identity_change_required"
            )["confirmation"]
        )
        h.client.cookies.clear()
        sign_in(h)  # a new sign-in has a new CSRF secret
        error_of(
            user.put(
                "/me/canvas-token",
                {"canvas_token": NEW_TOKEN, "confirm_identity_change": confirmation},
            ),
            409,
            "identity_change_required",
        )

    def test_the_same_canvas_user_needs_no_confirmation(self, h: Harness, user: Api) -> None:
        self.enroll(h, user)
        assert user.put("/me/canvas-token", {"canvas_token": NEW_TOKEN}).status_code == 200


class TestCanvasTokenDelete:
    def test_it_removes_only_the_callers_token_and_is_idempotent(
        self, h: Harness, user: Api
    ) -> None:
        put_row(h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42")
        put_row(h.store, OID_2, token=OTHER_TOKEN, name="Bob", canvas_user_id="43")
        response = user.delete("/me/canvas-token")
        assert response.status_code == 204 and response.content == b""
        assert_api_headers(response)
        assert h.store.info(KEY) is None
        assert h.store.info(KEY_2) is not None
        assert ("token_deleted", KEY, None) in audit_rows(h)
        assert user.delete("/me/canvas-token").status_code == 204

    def test_a_disabled_user_cannot_use_it_to_get_back_in(self, h: Harness, user: Api) -> None:
        user.delete("/me/canvas-token")
        assert h.store.get_principal_status(KEY).active

    def test_a_self_disconnect_is_audited_for_the_log(
        self, h: Harness, user: Api, events: list[dict[str, Any]]
    ) -> None:
        put_row(h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42")
        user.delete("/me/canvas-token")
        assert [e["action"] for e in events if e.get("action") == "self_disconnected"] == [
            "self_disconnected"
        ]
        events.clear()
        user.delete("/me/canvas-token")
        assert not [e for e in events if e.get("action") == "self_disconnected"]


class TestRecheck:
    def invalid(self, h: Harness, reason: str = "canvas_token_rejected") -> None:
        put_row(h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42",
                canvas_host="canvas.example.test")
        h.store.mark_invalid(KEY, reason=reason)

    def test_a_token_that_canvas_accepts_again_is_restored(
        self, h: Harness, user: Api, events: list[dict[str, Any]]
    ) -> None:
        self.invalid(h)
        response = user.post("/me/canvas-token/recheck")
        assert response.status_code == 200
        body = response.json()
        assert body["result"] == "restored" and body["canvas"]["state"] == "active"
        assert h.whoami_calls == [CANVAS_TOKEN]
        assert any(e.get("action") == "recheck" and e.get("outcome") == "restored" for e in events)

    def test_a_token_that_is_not_invalid_is_unchanged(self, h: Harness, user: Api) -> None:
        put_row(h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42")
        body = user.post("/me/canvas-token/recheck").json()
        assert body["result"] == "unchanged" and body["canvas"]["state"] == "active"
        assert h.whoami_calls == []

    def test_no_token_is_404(self, user: Api) -> None:
        error_of(user.post("/me/canvas-token/recheck"), 404, "not_found")

    def test_an_admin_decision_cannot_be_rechecked(self, h: Harness, user: Api) -> None:
        self.invalid(h, "revoked_by_admin")
        error_of(user.post("/me/canvas-token/recheck"), 409, "recheck_not_allowed")
        assert h.whoami_calls == []

    def test_canvas_still_rejecting(
        self, h: Harness, user: Api, events: list[dict[str, Any]]
    ) -> None:
        self.invalid(h)
        h.whoami_result = CanvasCheckError("invalid")
        error_of(user.post("/me/canvas-token/recheck"), 422, "token_rejected")
        assert h.store.info(KEY).status == "invalid"  # type: ignore[union-attr]
        assert any(e.get("outcome") == "still_rejected" for e in events)

    def test_canvas_unavailable(self, h: Harness, user: Api) -> None:
        self.invalid(h)
        h.whoami_result = CanvasCheckError("unavailable")
        error_of(user.post("/me/canvas-token/recheck"), 503, "canvas_unavailable")

    def test_a_school_the_server_dropped(self, h: Harness, user: Api) -> None:
        put_row(h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42",
                canvas_host="canvas.gone.edu")
        h.store.mark_invalid(KEY, reason="canvas_token_rejected")
        error_of(user.post("/me/canvas-token/recheck"), 422, "school_not_offered")

    def test_an_unreadable_token(self, h: Harness, user: Api, monkeypatch: pytest.MonkeyPatch) -> None:
        from canvas_mcp.core.selfhost.token_store import TokenDecryptionError

        self.invalid(h, "decrypt_failed")

        def boom(_key: str) -> Any:
            raise TokenDecryptionError("cannot decrypt")

        monkeypatch.setattr(h.store, "get", boom)
        error_of(user.post("/me/canvas-token/recheck"), 422, "token_unreadable")

    def test_one_check_per_minute(self, h: Harness, user: Api) -> None:
        self.invalid(h)
        h.whoami_result = CanvasCheckError("invalid")
        error_of(user.post("/me/canvas-token/recheck"), 422, "token_rejected")
        response = user.post("/me/canvas-token/recheck")
        assert error_of(response, 429, "rate_limited") == {"retry_after_s": 60}
        assert response.headers["retry-after"] == "60"
        h.now += 61
        error_of(user.post("/me/canvas-token/recheck"), 422, "token_rejected")

    def test_a_replacement_during_the_check_is_not_overwritten(
        self, h: Harness, user: Api
    ) -> None:
        self.invalid(h)

        class ReplaceWhileAsking(list):  # type: ignore[type-arg]
            """The user pastes a new token while Canvas is being asked about the old one."""

            def append(self, item: Any) -> None:
                super().append(item)
                h.store.put(
                    principal_key=KEY,
                    api_token=NEW_TOKEN,
                    canvas_user_id="42",
                    canvas_user_name="Ada Canvas",
                    canvas_host="canvas.example.test",
                )

        h.whoami_calls = ReplaceWhileAsking()
        body = user.post("/me/canvas-token/recheck").json()
        assert body["result"] == "unchanged"
        stored = h.store.get(KEY)
        assert stored is not None and stored.api_token == NEW_TOKEN
        assert stored.status == "active"

# -- schools --------------------------------------------------------------------------------------


class TestSchools:
    def test_a_pinned_server_has_a_fixed_school(self, user: Api) -> None:
        body = user.get("/me/schools").json()
        assert body["mode"] == "fixed" and body["choices"] == [] and body["selected"] is None
        assert body["sole"] == {"host": "canvas.example.test", "name": "canvas.example.test"}
        assert body["search_enabled"] is False

    def test_a_single_featured_school_without_a_default(self, tmp_path: pathlib.Path) -> None:
        r = schools_rig(tmp_path, default="", featured=(FeaturedSchool(HOST_A, "School A"),))
        sign_in(r.h)
        body = Api(r.h).get("/me/schools").json()
        assert body["mode"] == "sole"
        assert body["sole"] == {"host": HOST_A, "name": "School A"}

    def test_several_schools_make_a_picker_with_the_default_selected(
        self, tmp_path: pathlib.Path
    ) -> None:
        r = schools_rig(tmp_path)
        sign_in(r.h)
        body = Api(r.h).get("/me/schools").json()
        assert body["mode"] == "picker"
        assert [c["host"] for c in body["choices"]] == [DEFAULT_HOST, HOST_A, HOST_B]
        assert {c["source"] for c in body["choices"]} == {"featured"}
        assert body["choices"][1]["name"] == "School <b>A</b>"  # data, not markup
        assert body["selected"] == DEFAULT_HOST
        assert body["sole"] is None

    def test_the_enrolled_school_is_selected_and_a_searched_one_is_listed(
        self, tmp_path: pathlib.Path
    ) -> None:
        r = schools_rig(tmp_path, search=True)
        sign_in(r.h)
        a = Api(r.h)
        put_row(r.h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42", canvas_host=HOST_B)
        assert a.get("/me/schools").json()["selected"] == HOST_B
        put_row(r.h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42",
                canvas_host="canvas.searched.edu")
        body = a.get("/me/schools").json()
        assert body["selected"] == "canvas.searched.edu"
        assert body["choices"][-1] == {
            "host": "canvas.searched.edu", "name": "canvas.searched.edu", "source": "enrolled",
        }

    def test_a_picker_with_search_and_nothing_featured_is_empty(self, tmp_path: pathlib.Path) -> None:
        r = schools_rig(tmp_path, default="", featured=(), search=True)
        sign_in(r.h)
        body = Api(r.h).get("/me/schools").json()
        assert body["mode"] == "picker" and body["choices"] == [] and body["selected"] is None

    def test_a_pending_account_is_refused(self, tmp_path: pathlib.Path) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())
        error_of(Api(h).get("/me/schools"), 403, "pending_approval")


class TestSchoolSearch:
    ENTRIES = (
        DirectoryEntry("Found U", "canvas.found.edu"),
        DirectoryEntry("Local", "canvas.internal"),
        DirectoryEntry("Other", "canvas.other.edu"),
    )

    def rig(self, tmp_path: pathlib.Path, **kw: Any) -> tuple[SchoolsRig, Api]:
        r = schools_rig(tmp_path, search=True, entries=self.ENTRIES, **kw)
        sign_in(r.h)
        return r, Api(r.h)

    def test_results_are_signed_for_this_session_and_blocked_hosts_are_dropped(
        self, tmp_path: pathlib.Path
    ) -> None:
        r, a = self.rig(tmp_path)
        response = a.get("/me/schools/search?q=found", csrf=True)
        assert response.status_code == 200
        assert_api_headers(response)
        results = response.json()["results"]
        assert [x["host"] for x in results] == ["canvas.found.edu", "canvas.other.edu"]
        assert all(set(x) == {"host", "name", "sig"} and len(x["sig"]) == 43 for x in results)
        assert r.directory.searches == ["found"]

    def test_the_search_is_off_unless_enabled(self, tmp_path: pathlib.Path) -> None:
        r = schools_rig(tmp_path, search=False)
        sign_in(r.h)
        error_of(Api(r.h).get("/me/schools/search?q=abc", csrf=True), 404, "not_found")

    @pytest.mark.parametrize("q", ["", "a", "x" * 65, "ab\x00c", "  a  ", "ab\ncd"])
    def test_a_bad_query_is_422_with_the_limits(self, tmp_path: pathlib.Path, q: str) -> None:
        r, a = self.rig(tmp_path)
        params = error_of(
            a.get("/me/schools/search", params={"q": q}, csrf=True), 422, "validation_failed"
        )
        assert params == {"field": "q", "min": 2, "max": 64}
        assert r.directory.calls == 0

    def test_a_missing_query_is_422(self, tmp_path: pathlib.Path) -> None:
        _r, a = self.rig(tmp_path)
        error_of(a.get("/me/schools/search", csrf=True), 422, "validation_failed")

    def test_thirty_searches_per_ten_minutes(self, tmp_path: pathlib.Path) -> None:
        r, a = self.rig(tmp_path)
        for _ in range(30):
            assert a.get("/me/schools/search?q=found", csrf=True).status_code == 200
        response = a.get("/me/schools/search?q=found", csrf=True)
        assert error_of(response, 429, "rate_limited") == {"retry_after_s": 600}
        assert response.headers["retry-after"] == "600"
        assert len(r.directory.searches) == 30

    def test_a_directory_failure_is_503_and_spends_the_budget_like_the_page(
        self, tmp_path: pathlib.Path
    ) -> None:
        _r, a = self.rig(tmp_path, directory_error=True)
        error_of(a.get("/me/schools/search?q=found", csrf=True), 503, "directory_unavailable")

    def test_a_pending_account_cannot_search(self, tmp_path: pathlib.Path) -> None:
        directory = FakeDirectory(self.ENTRIES)
        h = make(
            tmp_path, policy=APPROVAL, directory=directory,
            cfg=make_cfg(schools=SchoolPolicy.build(DEFAULT_URL, (), True)),
        )
        sign_in(h, roles=())
        error_of(Api(h).get("/me/schools/search?q=found", csrf=True), 403, "pending_approval")
        assert directory.calls == 0


class TestEnrollingAtASchool:
    ENTRIES = (DirectoryEntry("Found U", "canvas.found.edu"),)

    def rig(self, tmp_path: pathlib.Path, **kw: Any) -> tuple[SchoolsRig, Api]:
        r = schools_rig(tmp_path, search=True, entries=self.ENTRIES, **kw)
        sign_in(r.h)
        return r, Api(r.h)

    def enroll(self, a: Api, school: str | None, **extra: Any) -> httpx.Response:
        body: dict[str, Any] = {"canvas_token": CANVAS_TOKEN, **extra}
        if school is not None:
            body["school"] = school
        return a.put("/me/canvas-token", body)

    def test_the_default_school_when_none_is_named(self, tmp_path: pathlib.Path) -> None:
        r, a = self.rig(tmp_path)
        assert self.enroll(a, None).status_code == 200
        assert r.h.whoami_urls == [DEFAULT_URL]
        assert self.enroll(a, "").status_code == 200
        assert self.enroll(a, DEFAULT_HOST).status_code == 200

    def test_a_featured_school(self, tmp_path: pathlib.Path) -> None:
        r, a = self.rig(tmp_path)
        response = self.enroll(a, HOST_A)
        assert response.status_code == 200
        assert response.json()["school"]["host"] == HOST_A
        assert r.h.whoami_urls[-1] == f"https://{HOST_A}/api/v1"
        assert r.h.store.info(KEY).canvas_host == HOST_A  # type: ignore[union-attr]

    def test_a_searched_school_needs_the_signature_from_the_search(
        self, tmp_path: pathlib.Path
    ) -> None:
        r, a = self.rig(tmp_path)
        hit = a.get("/me/schools/search?q=found", csrf=True).json()["results"][0]
        assert hit["host"] == "canvas.found.edu"
        response = self.enroll(a, hit["host"], school_sig=hit["sig"])
        assert response.status_code == 200
        assert response.json()["school"]["host"] == "canvas.found.edu"
        assert r.h.whoami_urls[-1] == "https://canvas.found.edu/api/v1"

    def test_a_searched_school_without_or_with_a_wrong_signature_is_refused_before_any_lookup(
        self, tmp_path: pathlib.Path
    ) -> None:
        r, a = self.rig(tmp_path)
        for extra in ({}, {"school_sig": "nope"}, {"school_sig": ""}, {"school_sig": None}):
            error_of(self.enroll(a, "canvas.found.edu", **extra), 422, "school_selection_unverified")
        assert r.directory.calls == 0 and r.resolver.calls == [] and r.h.whoami_calls == []

    def test_a_signature_from_another_session_or_another_host_is_refused(
        self, tmp_path: pathlib.Path
    ) -> None:
        r, a = self.rig(tmp_path)
        hit = a.get("/me/schools/search?q=found", csrf=True).json()["results"][0]
        error_of(
            self.enroll(a, "canvas.other.edu", school_sig=hit["sig"]), 422, "school_selection_unverified"
        )
        r.h.client.cookies.clear()
        sign_in(r.h, oid=OID_2, name="Bob", upn="bob@example.test")
        error_of(
            self.enroll(a, "canvas.found.edu", school_sig=hit["sig"]), 422, "school_selection_unverified"
        )

    def test_the_school_you_are_already_enrolled_at_needs_no_signature(
        self, tmp_path: pathlib.Path
    ) -> None:
        r, a = self.rig(tmp_path)
        put_row(r.h.store, OID, token=CANVAS_TOKEN, name="Ada Canvas", canvas_user_id="42",
                canvas_host="canvas.found.edu")
        response = self.enroll(a, "canvas.found.edu")
        assert response.status_code == 200, response.text

    @pytest.mark.parametrize(
        ("school", "code"),
        [
            ("not a host", "school_invalid"),
            ("localhost", "school_invalid"),
            ("10.0.0.1", "school_invalid"),
            ("https://canvas.found.edu", "school_invalid"),
            ("canvas.internal", "school_invalid"),
        ],
    )
    def test_a_malformed_school_is_school_invalid(
        self, tmp_path: pathlib.Path, school: str, code: str
    ) -> None:
        r, a = self.rig(tmp_path)
        error_of(self.enroll(a, school), 422, code)
        assert r.directory.calls == 0 and r.h.whoami_calls == []

    def test_a_school_nobody_offers(self, tmp_path: pathlib.Path) -> None:
        r = schools_rig(tmp_path, search=False)
        sign_in(r.h)
        error_of(Api(r.h).put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN, "school": "canvas.x.edu"}),
                 422, "school_not_offered")

    def test_an_unlisted_school_cannot_be_named_without_a_search_result(
        self, tmp_path: pathlib.Path
    ) -> None:
        r, a = self.rig(tmp_path)
        error_of(
            self.enroll(a, "canvas.unknown.edu", school_sig="x"), 422, "school_selection_unverified"
        )
        assert r.directory.calls == 0

    def test_featured_schools_that_resolve_badly_are_refused_by_dns(
        self, tmp_path: pathlib.Path
    ) -> None:
        r = schools_rig(
            tmp_path,
            resolver=FakeResolver({HOST_A: OSError("nxdomain"), HOST_B: ["10.0.0.5"]}),
        )
        sign_in(r.h)
        a = Api(r.h)
        error_of(self.enroll(a, HOST_A), 422, "school_unresolvable")
        error_of(self.enroll(a, HOST_B), 422, "school_address_blocked")
        assert r.h.whoami_calls == []

    def test_a_picker_without_a_default_needs_a_school(self, tmp_path: pathlib.Path) -> None:
        r = schools_rig(tmp_path, default="", search=True, entries=self.ENTRIES)
        sign_in(r.h)
        error_of(
            Api(r.h).put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN}), 422, "school_required"
        )

    def test_the_directory_being_down_while_confirming(self, tmp_path: pathlib.Path) -> None:
        r, a = self.rig(tmp_path)
        hit = a.get("/me/schools/search?q=found", csrf=True).json()["results"][0]
        r.directory.error = True
        error_of(self.enroll(a, hit["host"], school_sig=hit["sig"]), 503, "directory_unavailable")

    def test_a_signed_host_the_directory_no_longer_confirms(self, tmp_path: pathlib.Path) -> None:
        r, a = self.rig(tmp_path)
        hit = a.get("/me/schools/search?q=found", csrf=True).json()["results"][0]
        r.directory.entries = []
        error_of(
            self.enroll(a, hit["host"], school_sig=hit["sig"]), 422, "school_not_in_directory"
        )


# -- write tools -----------------------------------------------------------------------------------------


class WtRig:
    def __init__(self, h: Harness, cache: ToolPrefsCache) -> None:
        self.h = h
        self.cache = cache


class _LazySource:
    store: Any = None

    def get_tool_prefs(self, principal_key: str) -> ToolPrefs | None:
        return self.store.get_tool_prefs(principal_key)


def wt_rig(
    tmp_path: pathlib.Path, *, ceiling: set[str] | None = None, catalog: bool = True
) -> WtRig:
    source = _LazySource()
    cache = ToolPrefsCache(source)

    async def listing() -> list[str]:
        return list(REGISTERED)

    kwargs: dict[str, Any] = {}
    if catalog:
        kwargs["write_tools"] = WriteToolCatalog(
            ceiling=CEILING if ceiling is None else ceiling, list_registered=listing
        )
        kwargs["tool_prefs"] = cache
    h = make(tmp_path, **kwargs)
    source.store = h.store
    return WtRig(h, cache)


def stored_tools(r: WtRig, key: str = KEY) -> frozenset[str]:
    prefs = r.h.store.get_tool_prefs(key)
    return prefs.enabled_write_tools if prefs is not None else frozenset()


def tool_state(body: dict[str, Any], name: str) -> dict[str, Any]:
    for group in body["groups"]:
        for tool in group["tools"]:
            if tool["name"] == name:
                return dict(tool)
    raise AssertionError(name)


class TestWriteToolsRead:
    def test_the_groups_and_what_is_offered(self, tmp_path: pathlib.Path) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)
        response = a.get("/me/write-tools")
        assert response.status_code == 200
        body = response.json()
        assert [g["id"] for g in body["groups"]] == [
            "planner", "submissions", "modules", "inbox", "other",
        ]
        assert body["offered_any"] is True and body["editable"] is True
        assert body["kept_not_offered"] == []
        assert tool_state(body, "send_message") == {
            "name": "send_message", "offered": True, "enabled": False, "enabled_at": None,
            "effect": "canvas_write",
        }
        assert tool_state(body, "submit_assignment")["offered"] is False
        assert [t["name"] for t in body["groups"][-1]["tools"]] == ["create_assignment"]

    def test_nothing_offered_means_nothing_to_edit(self, tmp_path: pathlib.Path) -> None:
        r = wt_rig(tmp_path, ceiling=set())
        sign_in(r.h)
        body = Api(r.h).get("/me/write-tools").json()
        assert body["offered_any"] is False and body["editable"] is False
        assert [g["id"] for g in body["groups"]] == ["planner", "submissions", "modules", "inbox"]

    def test_without_a_catalog_it_is_404(self, tmp_path: pathlib.Path) -> None:
        r = wt_rig(tmp_path, catalog=False)
        sign_in(r.h)
        a = Api(r.h)
        error_of(a.get("/me/write-tools"), 404, "not_found")
        error_of(a.put("/me/write-tools", {"enabled": []}), 404, "not_found")
        error_of(a.delete("/me/write-tools"), 404, "not_found")
        assert a.get("/me").json()["features"]["write_tools"] is False

    def test_the_summary_in_me(self, tmp_path: pathlib.Path) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)
        assert a.get("/me").json()["write_tools"] == {"offered": 5, "enabled": 0}
        assert a.get("/me").json()["features"]["write_tools"] is True
        a.put("/me/write-tools", {"enabled": ["send_message", "create_assignment"]})
        assert a.get("/me").json()["write_tools"] == {"offered": 5, "enabled": 2}

    def test_an_unreadable_store_is_503(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)

        def boom(_key: str) -> Any:
            raise sqlite3.OperationalError("locked")

        monkeypatch.setattr(r.h.store, "get_tool_prefs", boom)
        error_of(a.get("/me/write-tools"), 503, "write_tools_unavailable")
        assert a.get("/me").status_code == 200  # the summary is a convenience

    def test_a_pending_account_is_refused(self, tmp_path: pathlib.Path) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())
        a = Api(h)
        # no catalog there, but the pending gate comes first
        error_of(a.get("/me/write-tools"), 403, "pending_approval")
        error_of(a.put("/me/write-tools", {"enabled": []}), 403, "pending_approval")


class TestWriteToolsSave:
    def test_turning_tools_on_while_fresh(
        self, tmp_path: pathlib.Path, events: list[dict[str, Any]]
    ) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)
        assert r.cache.enabled(KEY) == frozenset()
        response = a.put("/me/write-tools", {"enabled": ["send_message", "mark_module_item_done"]})
        assert response.status_code == 200
        body = response.json()
        assert body["result"] == "saved"
        assert tool_state(body, "send_message")["enabled"] is True
        assert tool_state(body, "send_message")["enabled_at"] == "2027-01-15T08:00:00Z"
        assert tool_state(body, "reply_to_conversation")["enabled"] is False
        assert stored_tools(r) == {"send_message", "mark_module_item_done"}
        assert r.cache.enabled(KEY) == {"send_message", "mark_module_item_done"}  # invalidated
        write_events = [e for e in events if e.get("event_type") == "write_tools"]
        assert [e["action"] for e in write_events] == ["changed"]

    def test_the_same_request_again_changes_nothing(self, tmp_path: pathlib.Path) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)
        a.put("/me/write-tools", {"enabled": ["send_message"]})
        before = r.h.store.get_tool_prefs(KEY)
        r.h.now += 5
        assert a.put("/me/write-tools", {"enabled": ["send_message"]}).json()["result"] == "unchanged"
        assert r.h.store.get_tool_prefs(KEY) == before

    def test_a_stale_session_cannot_turn_a_tool_on(
        self, tmp_path: pathlib.Path, events: list[dict[str, Any]]
    ) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)
        r.h.now += 601
        response = a.put("/me/write-tools", {"enabled": ["send_message"]})
        assert error_of(response, 403, "reauth_required") == {"max_age_s": 600}
        assert stored_tools(r) == frozenset()
        refused = [e for e in events if e.get("event_type") == "write_tools"]
        assert [(e["action"], e["outcome"]) for e in refused] == [("refused", "sign_in_too_old")]

    def test_the_freshness_check_comes_before_the_nothing_changed_check(
        self, tmp_path: pathlib.Path
    ) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)
        r.h.now += 601
        error_of(a.put("/me/write-tools", {"enabled": ["create_assignment"]}), 403, "reauth_required")

    def test_turning_tools_off_never_needs_a_fresh_sign_in(self, tmp_path: pathlib.Path) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)
        a.put("/me/write-tools", {"enabled": ["send_message", "create_assignment"]})
        r.h.now += 601
        assert a.put("/me/write-tools", {"enabled": ["send_message"]}).status_code == 200
        assert stored_tools(r) == {"send_message"}
        response = a.delete("/me/write-tools")
        assert response.status_code == 200 and response.json()["result"] == "saved"
        assert stored_tools(r) == frozenset()

    def test_only_offered_tools_can_be_named(self, tmp_path: pathlib.Path) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)
        for name in ("delete_page", "submit_assignment", "execute_typescript", "list_courses", "nonexistent"):
            params = error_of(
                a.put("/me/write-tools", {"enabled": ["send_message", name]}),
                422, "write_tool_not_allowed",
            )
            assert params == {"tool": name}
        assert stored_tools(r) == frozenset()

    @pytest.mark.parametrize(
        "enabled",
        [
            "send_message",
            None,
            {"a": 1},
            [1],
            [None],
            ["send_message", "send_message"],
            ["Send_Message"],
            ["send message"],
            ["x" * 80],
            ["send_message"] * 121,
            [f"tool_{i}" for i in range(121)],
        ],
    )
    def test_a_bad_list_is_422(self, tmp_path: pathlib.Path, enabled: Any) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        params = error_of(
            Api(r.h).put("/me/write-tools", {"enabled": enabled}), 422, "validation_failed"
        )
        assert params == {"field": "enabled"}

    def test_names_kept_from_an_earlier_choice_stay_unless_turn_all_off(
        self, tmp_path: pathlib.Path
    ) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)
        a.put("/me/write-tools", {"enabled": ["send_message", "mark_module_item_done"]})
        # Earlier choices the server no longer offers: one with a row on the page
        # (mark_module_item_done), two without (create_assignment, delete_module).
        r.h.store.set_tool_prefs(
            KEY, {"send_message", "mark_module_item_done", "create_assignment", "delete_module"}
        )
        narrower = wt_rig_with(r, ceiling={"send_message", "reply_to_conversation"})
        body = narrower.get("/me/write-tools").json()
        kept_row = tool_state(body, "mark_module_item_done")
        assert kept_row["offered"] is False and kept_row["enabled"] is True
        assert body["kept_not_offered"] == ["create_assignment", "delete_module"]
        # Kept names may be named again, and saving something else leaves them alone.
        response = narrower.put(
            "/me/write-tools", {"enabled": ["reply_to_conversation", "create_assignment"]}
        )
        assert response.status_code == 200, response.text
        assert stored_tools(r) == {
            "reply_to_conversation", "mark_module_item_done", "create_assignment", "delete_module",
        }
        # "Turn all off" clears the kept names too.
        assert narrower.delete("/me/write-tools").json()["result"] == "saved"
        assert stored_tools(r) == frozenset()

    def test_a_save_failure_is_503(
        self, tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)

        def boom(*_a: Any, **_k: Any) -> Any:
            raise StoreUnavailable()

        monkeypatch.setattr(r.h.store, "set_tool_prefs", boom)
        error_of(a.put("/me/write-tools", {"enabled": ["send_message"]}), 503, "write_tools_unavailable")

    def test_a_disabled_account_cannot_save(self, tmp_path: pathlib.Path) -> None:
        from canvas_mcp.core.selfhost.token_store import OPERATOR

        r = wt_rig(tmp_path)
        sign_in(r.h)
        a = Api(r.h)
        a.csrf()
        r.h.store.disable_principal(KEY, actor=OPERATOR, reason="operator_disabled")
        error_of(a.put("/me/write-tools", {"enabled": ["send_message"]}), 401, "not_authenticated")
        assert stored_tools(r) == frozenset()


def wt_rig_with(r: WtRig, *, ceiling: set[str]) -> Api:
    """The same account with a narrower server ceiling: a second application over the same store."""
    from starlette.applications import Starlette
    from starlette.testclient import TestClient

    from canvas_mcp.core.selfhost.account_web import build_account_routes

    async def listing() -> list[str]:
        return list(REGISTERED)

    h = r.h
    routes = build_account_routes(
        make_cfg(), h.store, h.identity,  # type: ignore[arg-type]
        clock=h.clock,
        write_tools=WriteToolCatalog(ceiling=ceiling, list_registered=listing),
        tool_prefs=r.cache,
        ui="react",
    )
    client = TestClient(Starlette(routes=routes), base_url=BASE, follow_redirects=False)
    client.cookies = h.client.cookies
    other = Harness(client=client, store=h.store, identity=h.identity, now=h.now)
    return Api(other)


# -- login history -----------------------------------------------------------------------------------------


class TestLoginHistory:
    def test_own_sign_ins_only_newest_first_without_addresses(self, h: Harness, api: Api) -> None:
        sign_in(h)
        h.now += 10
        sign_in(h)
        mine = snapshot_cookies(h)
        h.client.cookies.clear()
        sign_in(h, oid=OID_2, name="Bob", upn="bob@example.test")
        use_cookies(h, mine)
        response = api.get("/me/login-history")
        assert response.status_code == 200
        events = response.json()["events"]
        assert len(events) == 2
        assert all(
            set(e) == {"at", "provider_id", "outcome", "reason"} and e["provider_id"] == "entra"
            for e in events
        )
        assert {e["outcome"] for e in events} == {"success"}
        assert "unknown" not in response.text  # the (unknown) client address is not exposed

    def test_at_most_twenty(self, h: Harness, api: Api) -> None:
        for _ in range(25):
            sign_in(h)
            h.now += 1
        assert len(api.get("/me/login-history").json()["events"]) == 20

    def test_a_pending_account_may_read_it(self, tmp_path: pathlib.Path) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())
        events = Api(h).get("/me/login-history").json()["events"]
        assert events and events[0]["outcome"] in ("pending", "success")
        assert events[0]["reason"] in ("account_created", "pending_approval", None)


# -- IDOR: nothing accepts someone else's id ------------------------------------------------------------------


class TestIsolation:
    def test_one_user_never_sees_or_changes_another_users_data(self, h: Harness, api: Api) -> None:
        put_row(h.store, OID_2, token=OTHER_TOKEN, name="Bob Canvas", canvas_user_id="99",
                canvas_host="canvas.example.test")
        sign_in(h)
        assert api.get("/me/canvas-token").json()["state"] == "none"
        assert OTHER_TOKEN not in api.get("/me").text
        assert "Bob" not in api.get("/me").text
        assert api.delete("/me/canvas-token").status_code == 204  # nothing of Bob's is touched
        assert h.store.info(KEY_2) is not None
        error_of(api.post("/me/canvas-token/recheck"), 404, "not_found")
        for body in ({"canvas_token": CANVAS_TOKEN, "principal_key": KEY_2},
                     {"canvas_token": CANVAS_TOKEN, "account_id": KEY_2.removeprefix("acct:")}):
            error_of(api.put("/me/canvas-token", body), 422, "validation_failed")
        assert h.store.get(KEY_2).api_token == OTHER_TOKEN  # type: ignore[union-attr]

    def test_every_admin_route_is_forbidden_to_a_user_even_for_their_own_id(
        self, h: Harness, api: Api
    ) -> None:
        sign_in(h)
        put_row(h.store, OID_2, token=OTHER_TOKEN, name="Bob", canvas_user_id="99")
        bob = KEY_2.removeprefix("acct:")
        me = KEY.removeprefix("acct:")
        count = 0
        for path, endpoints in account_api.ApiApp(None).route_table():  # type: ignore[arg-type]
            if "/admin/" not in path:
                continue
            for method in endpoints:
                for target in (bob, me):
                    url = path.replace("{id}", target)
                    response = api.call(method, url[len(P):])
                    error_of(response, 403, "forbidden")
                    count += 1
        assert count >= 12
        assert h.store.get_principal_status(KEY_2).active
        assert h.store.info(KEY_2) is not None

    def test_a_stale_cookie_of_a_demoted_owner_is_forbidden(self, h: Harness, api: Api) -> None:
        sign_in_owner(h)
        demote_directly(h, KEY_OWNER)
        error_of(api.get("/admin/accounts"), 403, "forbidden")
        error_of(api.get("/admin/audit"), 403, "forbidden")


# -- owner ------------------------------------------------------------------------------------------------------


def seed_people(h: Harness) -> None:
    put_row(h.store, OID, token=CANVAS_TOKEN, name="Ada Canvas", canvas_user_id="42",
            display="Ada Lovelace", upn="ada@example.test", canvas_host="canvas.example.test")
    put_row(h.store, OID_2, token=OTHER_TOKEN, name="Bob Canvas", canvas_user_id="43",
            display="Bob", upn="bob@example.test")


class TestOwnerRead:
    def test_the_account_list(self, h: Harness, api: Api) -> None:
        seed_people(h)
        sign_in_owner(h)
        h.store.mark_invalid(KEY_2, reason="canvas_token_rejected")
        response = api.get("/admin/accounts")
        assert response.status_code == 200
        assert_api_headers(response)
        body = response.json()
        assert body["counts"] == {"total": 3, "active": 3, "pending": 0, "disabled": 0, "owners": 1}
        by_name = {a["display_name"]: a for a in body["accounts"]}
        ada = by_name["Ada Lovelace"]
        assert ada["id"] == KEY.removeprefix("acct:") and ada["key"] == KEY
        assert ada["username"] == "ada@example.test"
        assert ada["role"] == "user" and ada["status"] == "active" and ada["is_self"] is False
        assert ada["identity"]["provider_id"] == "entra" and ada["identity"]["tenant_id"]
        assert ada["enrollment"]["canvas_user_name"] == "Ada Canvas"
        assert ada["enrollment"]["state"] == "active"
        assert ada["enrollment"]["school"] == {
            "host": "canvas.example.test", "name": "canvas.example.test",
            "offered": True, "is_default": True,
        }
        assert ada["actions"] == ["mark_invalid", "disable", "remove_enrollment"]
        bob = by_name["Bob"]
        assert bob["enrollment"]["state"] == "invalid"
        assert bob["enrollment"]["invalid_reason"] == "canvas_token_rejected"
        assert bob["actions"] == ["disable", "remove_enrollment"]
        owner = by_name["Olive Owner"]
        assert owner["role"] == "owner" and owner["is_self"] is True
        assert owner["enrollment"] is None and owner["actions"] == []
        assert CANVAS_TOKEN not in response.text and OTHER_TOKEN not in response.text

    def test_the_status_filter(self, tmp_path: pathlib.Path) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())  # Ada waits
        sign_in_owner(h)
        a = Api(h)
        pending = a.get("/admin/accounts?status=pending").json()
        assert [x["key"] for x in pending["accounts"]] == [KEY]
        assert pending["accounts"][0]["actions"] == ["approve", "deny"]
        assert pending["accounts"][0]["status"] == "pending"
        assert pending["counts"]["pending"] == 1 and pending["counts"]["total"] == 2
        assert [x["key"] for x in a.get("/admin/accounts?status=active").json()["accounts"]] == [KEY_OWNER]
        assert a.get("/admin/accounts?status=disabled").json()["accounts"] == []
        error_of(a.get("/admin/accounts?status=banana"), 422, "validation_failed")
        # Pending people come first in the unfiltered list.
        assert a.get("/admin/accounts").json()["accounts"][0]["key"] == KEY

    def test_a_disabled_account_shows_why(self, h: Harness, api: Api) -> None:
        seed_people(h)
        sign_in_owner(h)
        from canvas_mcp.core.selfhost.token_store import OPERATOR

        h.store.disable_principal(KEY_2, actor=OPERATOR, reason="operator_disabled")
        bob = next(x for x in api.get("/admin/accounts").json()["accounts"] if x["key"] == KEY_2)
        assert bob["status"] == "disabled" and bob["disabled_reason"] == "operator_disabled"
        assert bob["disabled_at"] == "2027-01-15T08:00:00Z"
        assert bob["actions"] == ["enable", "remove_enrollment"]

    def test_the_enrollment_table_and_its_filter(self, h: Harness, api: Api) -> None:
        seed_people(h)
        make_account(h.store, OID_PENDING, status="pending", name="Newcomer")
        make_account(h.store, OID_BLOCKED, status="disabled", name="Blocked")
        sign_in_owner(h)
        h.store.mark_invalid(KEY_2, reason="decrypt_failed")
        body = api.get("/admin/enrollments").json()
        keys = [r["key"] for r in body["rows"]]
        assert keys[0] == acct_key(OID_PENDING)  # waiting people come first
        assert set(keys) == {KEY, KEY_2, acct_key(OID_PENDING), acct_key(OID_BLOCKED)}
        assert body["counts"] == {
            "needing": 1, "total_enrollments": 2, "disabled": 1, "pending": 1,
        }
        needing = api.get("/admin/enrollments?filter=needs_reenroll").json()
        assert [r["key"] for r in needing["rows"]] == [KEY_2]
        assert needing["counts"]["needing"] == 1
        assert api.get("/admin/enrollments?filter=all").json() == body
        error_of(api.get("/admin/enrollments?filter=x"), 422, "validation_failed")

    def test_pending_and_disabled_people_without_a_token_are_listed_only_for_all(
        self, h: Harness, api: Api
    ) -> None:
        make_account(h.store, OID_PENDING, status="pending", name="Newcomer")
        sign_in_owner(h)
        assert [r["key"] for r in api.get("/admin/enrollments").json()["rows"]] == [
            acct_key(OID_PENDING)
        ]
        assert api.get("/admin/enrollments?filter=needs_reenroll").json()["rows"] == []

    def test_an_enrollment_without_an_account_is_listed_as_missing(
        self, h: Harness, api: Api
    ) -> None:
        from sqlalchemy import text

        seed_people(h)
        sign_in_owner(h)
        with h.store._db.write() as conn:
            conn.execute(
                text("DELETE FROM accounts WHERE id = :id"), {"id": KEY_2.removeprefix("acct:")}
            )
        rows = {r["key"]: r for r in api.get("/admin/enrollments").json()["rows"]}
        orphan = rows[KEY_2]
        assert orphan["status"] == "missing" and orphan["enrollment"] is not None
        assert orphan["actions"] == ["remove_enrollment"]  # nothing to disable
        assert orphan["identity"] is None and orphan["display_name"] == ""
        removed = api.delete(f"/admin/enrollments/{KEY_2.removeprefix('acct:')}")
        assert removed.status_code == 200 and removed.json()["changed"] is True
        assert removed.json()["account"]["status"] == "missing"

    def test_the_audit_log(self, h: Harness, api: Api) -> None:
        seed_people(h)
        sign_in_owner(h)
        assert api.post(f"/admin/enrollments/{KEY_2.removeprefix('acct:')}/mark-invalid").status_code == 200
        response = api.get("/admin/audit")
        assert response.status_code == 200
        assert_api_headers(response)
        body = response.json()
        assert body["next_cursor"] is None
        first = body["entries"][0]
        assert first["action"] == "token_marked_invalid"
        assert first["actor"] == {"kind": "account", "key": KEY_OWNER, "name": "Olive Owner"}
        assert first["target"] == {"key": KEY_2, "name": "Bob"}
        assert first["reason"] == "revoked_by_admin"
        assert first["at"] == "2027-01-15T08:00:00Z" and isinstance(first["id"], int)
        assert all(
            isinstance(v, str | int | bool | list)
            for e in body["entries"] for v in e["detail"].values()
        )
        kinds = {e["actor"]["kind"] for e in body["entries"]}
        assert kinds <= {"account", "operator", "system"}

    def test_audit_paging(self, h: Harness, api: Api) -> None:
        sign_in_owner(h)
        with h.store._db.write() as conn:
            for i in range(130):
                h.store._audit(conn, "system", "pending_purged", detail={"count": i}, now=1000 + i)
        page = api.get("/admin/audit").json()
        assert len(page["entries"]) == 100
        assert page["next_cursor"] == str(page["entries"][-1]["id"])
        older = api.get(f"/admin/audit?before={page['next_cursor']}").json()
        ids = [e["id"] for e in page["entries"]] + [e["id"] for e in older["entries"]]
        assert ids == sorted(ids, reverse=True) and len(set(ids)) == len(ids)
        assert older["next_cursor"] is None
        assert older["entries"][0]["actor"] == {"kind": "system", "key": None, "name": None}
        for bad in ("abc", "-1", "1" * 15, "1.5", ""):
            error_of(api.get(f"/admin/audit?before={bad}"), 422, "validation_failed")

    def test_an_owner_needs_a_recent_sign_in_even_to_read(self, h: Harness, api: Api) -> None:
        sign_in_owner(h)
        h.now += 601
        for path in ("/admin/accounts", "/admin/enrollments", "/admin/audit"):
            assert error_of(api.get(path), 403, "reauth_required") == {"max_age_s": 600}
        # Everything else keeps working for the stale session.
        assert api.get("/me").status_code == 200

    def test_a_pending_owner_candidate_gets_pending_not_forbidden(self, tmp_path: pathlib.Path) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())
        error_of(Api(h).get("/admin/accounts"), 403, "pending_approval")


class TestOwnerActions:
    def target(self, key: str) -> str:
        return key.removeprefix("acct:")

    def test_disable_and_enable(self, h: Harness, api: Api, events: list[dict[str, Any]]) -> None:
        seed_people(h)
        sign_in_owner(h)
        response = api.post(f"/admin/accounts/{self.target(KEY)}/disable")
        assert response.status_code == 200
        body = response.json()
        assert body["changed"] is True
        assert body["account"]["status"] == "disabled"
        assert body["account"]["disabled_reason"] == "admin_disabled"
        assert body["account"]["actions"] == ["enable", "remove_enrollment"]
        assert h.store.get_principal_status(KEY).disabled
        assert any(e.get("action") == "disabled" and e.get("actor") == KEY_OWNER for e in events)
        again = api.post(f"/admin/accounts/{self.target(KEY)}/disable").json()
        assert again["changed"] is False
        response = api.post(f"/admin/accounts/{self.target(KEY)}/enable")
        assert response.json()["changed"] is True
        assert response.json()["account"]["status"] == "active"
        assert any(e.get("action") == "enabled" for e in events)

    def test_a_disabled_user_loses_the_session_at_once(self, h: Harness, api: Api) -> None:
        seed_people(h)
        sign_in(h)
        ada = snapshot_cookies(h)
        h.client.cookies.clear()
        sign_in_owner(h)
        api.post(f"/admin/accounts/{self.target(KEY)}/disable")
        use_cookies(h, ada)
        error_of(api.get("/me"), 401, "not_authenticated")

    def test_the_access_cache_is_dropped(self, tmp_path: pathlib.Path) -> None:
        from canvas_mcp.core.selfhost.principal_access import PrincipalAccessCache

        class Lazy:
            store: Any = None

            def get_principal_status(self, key: str) -> Any:
                return self.store.get_principal_status(key)

        class Recording(PrincipalAccessCache):
            def __init__(self, source: Any) -> None:
                super().__init__(source)
                self.dropped: list[str | None] = []

            def invalidate(self, principal_key: str | None = None) -> None:
                self.dropped.append(principal_key)
                super().invalidate(principal_key)

        lazy = Lazy()
        cache = Recording(lazy)
        h = make(tmp_path, access=cache)
        lazy.store = h.store
        seed_people(h)
        sign_in_owner(h)
        api = Api(h)
        api.post(f"/admin/accounts/{self.target(KEY)}/disable")
        api.post(f"/admin/accounts/{self.target(KEY)}/enable")
        api.post(f"/admin/accounts/{self.target(KEY_2)}/deny")
        assert cache.dropped == [KEY, KEY, KEY_2]

    def test_cannot_disable_yourself(self, h: Harness, api: Api, events: list[dict[str, Any]]) -> None:
        seed_people(h)
        sign_in_owner(h)
        error_of(api.post(f"/admin/accounts/{self.target(KEY_OWNER)}/disable"), 409, "cannot_disable_self")
        assert h.store.get_principal_status(KEY_OWNER).active
        assert any(e.get("action") == "refused" and e.get("outcome") == "self" for e in events)

    def test_the_store_refusing_the_last_active_owner_is_409(
        self, h: Harness, api: Api, monkeypatch: pytest.MonkeyPatch, events: list[dict[str, Any]]
    ) -> None:
        from canvas_mcp.core.selfhost.token_store import AccessActionRefused

        seed_people(h)
        sign_in_owner(h)
        api.csrf()

        def refuse(*_a: Any, **_k: Any) -> Any:
            raise AccessActionRefused(AccessActionRefused.LAST_OWNER)

        # The store counts owners inside its transaction; an account actor cannot reach
        # this branch without a race, so the mapping is shown by making the store say it.
        monkeypatch.setattr(h.store, "disable_principal", refuse)
        error_of(api.post(f"/admin/accounts/{self.target(KEY)}/disable"), 409, "last_owner")
        assert any(e.get("action") == "refused" and e.get("outcome") == "last_owner" for e in events)

    def test_two_owners_can_disable_each_other_only_one_at_a_time(
        self, h: Harness, api: Api
    ) -> None:
        sign_in_owner(h)
        second = make_account(h.store, OID, role="owner", name="Second Owner")
        assert h.store.count_active_owners() == 2
        assert api.post(f"/admin/accounts/{self.target(second)}/disable").json()["changed"] is True
        assert h.store.count_active_owners() == 1
        # The one left is the caller, and nobody can disable the caller through the API.
        error_of(
            api.post(f"/admin/accounts/{self.target(KEY_OWNER)}/disable"),
            409,
            "cannot_disable_self",
        )

    def test_approve_and_deny(self, tmp_path: pathlib.Path, events: list[dict[str, Any]]) -> None:
        h = make(tmp_path, policy=APPROVAL)
        sign_in(h, roles=())
        ada = snapshot_cookies(h)
        h.client.cookies.clear()
        sign_in_owner(h)
        a = Api(h)
        response = a.post(f"/admin/accounts/{self.target(KEY)}/approve")
        assert response.json()["changed"] is True
        assert response.json()["account"]["status"] == "active"
        assert response.json()["account"]["approved_at"] == "2027-01-15T08:00:00Z"
        assert h.store.get_principal_status(KEY).active
        assert any(e.get("action") == "approved" for e in events)
        # Denying an account that is no longer pending changes nothing.
        assert a.post(f"/admin/accounts/{self.target(KEY)}/deny").json()["changed"] is False
        # A second newcomer is denied.
        h.client.cookies.clear()
        sign_in(h, oid=OID_2, name="Bob", upn="bob@example.test", roles=())
        h.client.cookies.clear()
        sign_in_owner(h)
        denied = a.post(f"/admin/accounts/{self.target(KEY_2)}/deny").json()
        assert denied["changed"] is True
        assert denied["account"]["status"] == "disabled"
        assert denied["account"]["disabled_reason"] == "approval_denied"
        assert any(e.get("action") == "denied" for e in events)
        use_cookies(h, ada)

    def test_mark_invalid_and_remove(self, h: Harness, api: Api, events: list[dict[str, Any]]) -> None:
        seed_people(h)
        sign_in_owner(h)
        response = api.post(f"/admin/enrollments/{self.target(KEY)}/mark-invalid")
        assert response.status_code == 200
        body = response.json()
        assert body["changed"] is True
        assert body["account"]["enrollment"]["state"] == "invalid"
        assert body["account"]["enrollment"]["invalid_reason"] == "revoked_by_admin"
        assert "mark_invalid" not in body["account"]["actions"]
        assert any(e.get("action") == "admin_marked_invalid" for e in events)
        assert api.post(f"/admin/enrollments/{self.target(KEY)}/mark-invalid").json()["changed"] is False
        response = api.delete(f"/admin/enrollments/{self.target(KEY)}")
        assert response.status_code == 200
        assert response.json()["changed"] is True
        assert response.json()["account"]["enrollment"] is None
        assert h.store.info(KEY) is None
        assert h.store.get_principal_status(KEY).active  # not an access decision
        assert any(e.get("action") == "enrollment_removed" for e in events)
        assert api.delete(f"/admin/enrollments/{self.target(KEY)}").json()["changed"] is False

    def test_unknown_and_malformed_targets(self, h: Harness, api: Api) -> None:
        sign_in_owner(h)
        ghost = "00000000-0000-4000-8000-000000000000"
        for method, path in (
            ("POST", f"/admin/accounts/{ghost}/approve"),
            ("POST", f"/admin/accounts/{ghost}/deny"),
            ("POST", f"/admin/accounts/{ghost}/disable"),
            ("POST", f"/admin/accounts/{ghost}/enable"),
            ("POST", f"/admin/enrollments/{ghost}/mark-invalid"),
            ("DELETE", f"/admin/enrollments/{ghost}"),
        ):
            error_of(api.call(method, path), 404, "not_found")
        for bad in (
            "abc",
            KEY,  # the prefixed key is not an id
            KEY.removeprefix("acct:").upper(),
            "00000000-0000-4000-8000-00000000000g",
            "x" * 300,
        ):
            params = error_of(
                api.post(f"/admin/accounts/{bad}/approve"), 422, "validation_failed"
            )
            assert params == {"field": "id"}
            error_of(api.delete(f"/admin/enrollments/{bad}"), 422, "validation_failed")

    def test_a_stale_owner_gets_reauth_required_on_every_action(self, h: Harness, api: Api) -> None:
        seed_people(h)
        sign_in_owner(h)
        api.csrf()
        h.now += 601
        bob = self.target(KEY_2)
        for method, path in (
            ("POST", f"/admin/accounts/{bob}/disable"),
            ("POST", f"/admin/accounts/{bob}/approve"),
            ("POST", f"/admin/enrollments/{bob}/mark-invalid"),
            ("DELETE", f"/admin/enrollments/{bob}"),
        ):
            assert error_of(api.call(method, path), 403, "reauth_required") == {"max_age_s": 600}
        assert h.store.get_principal_status(KEY_2).active and h.store.info(KEY_2) is not None

    def test_a_non_owner_never_changes_anything(self, h: Harness, api: Api) -> None:
        seed_people(h)
        sign_in(h)
        for method, path in (
            ("POST", f"/admin/accounts/{self.target(KEY_2)}/disable"),
            ("DELETE", f"/admin/enrollments/{self.target(KEY_2)}"),
        ):
            error_of(api.call(method, path), 403, "forbidden")
        assert h.store.get_principal_status(KEY_2).active

    @pytest.mark.parametrize(
        ("method", "tail"),
        [
            ("POST", "/admin/accounts/{t}/disable"),
            ("POST", "/admin/accounts/{t}/enable"),
            ("POST", "/admin/accounts/{t}/approve"),
            ("POST", "/admin/accounts/{t}/deny"),
            ("POST", "/admin/enrollments/{t}/mark-invalid"),
            ("DELETE", "/admin/enrollments/{t}"),
        ],
    )
    def test_an_owner_demoted_between_the_check_and_the_write_is_refused_by_the_store(
        self,
        h: Harness,
        api: Api,
        events: list[dict[str, Any]],
        monkeypatch: pytest.MonkeyPatch,
        method: str,
        tail: str,
    ) -> None:
        seed_people(h)
        sign_in_owner(h)
        api.csrf()
        real = h.store.get_principal_status

        def status_then_demote(key: str) -> Any:
            status = real(key)
            if key == KEY_OWNER:
                demote_directly(h, KEY_OWNER)
            return status

        monkeypatch.setattr(h.store, "get_principal_status", status_then_demote)
        response = api.call(method, tail.format(t=self.target(KEY_2)))
        error_of(response, 403, "forbidden")
        monkeypatch.setattr(h.store, "get_principal_status", real)
        assert h.store.get_principal_status(KEY_2).active
        assert h.store.info(KEY_2) is not None and h.store.info(KEY_2).status == "active"  # type: ignore[union-attr]
        assert any(e.get("action") == "refused" and e.get("outcome") == "not_owner" for e in events)

    def test_a_store_failure_while_changing_access_is_503(
        self, h: Harness, api: Api, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        seed_people(h)
        sign_in_owner(h)
        api.csrf()

        def boom(*_a: Any, **_k: Any) -> Any:
            raise StoreUnavailable()

        monkeypatch.setattr(h.store, "disable_principal", boom)
        error_of(api.post(f"/admin/accounts/{self.target(KEY)}/disable"), 503, "token_store_unavailable")


# -- the shape of every answer ----------------------------------------------------------------------------------


class TestEveryAnswer:
    def test_errors_and_successes_all_carry_the_api_headers_and_closed_codes(
        self, h: Harness, api: Api
    ) -> None:
        seed_people(h)
        sign_in_owner(h)
        responses = [
            api.get("/providers"),
            api.get("/me"),
            api.get("/me/canvas-token"),
            api.get("/me/schools"),
            api.get("/me/login-history"),
            api.get("/admin/accounts"),
            api.get("/admin/enrollments"),
            api.get("/admin/audit"),
            api.get("/nope"),
            api.call("PATCH", "/me"),
            api.put("/me/canvas-token", {"nope": 1}),
            api.call("PUT", "/me/ui-locale", content=b"[", ),
            api.call("PUT", "/me/ui-locale", {"locale": "zh"}, csrf=False),
        ]
        for response in responses:
            assert_api_headers(response)
            body = response.json()
            if "error" in body:
                assert body["error"]["code"] in account_api.API_ERROR_CODES

    def test_an_unexpected_failure_is_a_plain_500_with_only_the_class_logged(
        self, h: Harness, user: Api, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        def boom(_key: str) -> Any:
            raise RuntimeError("secret internal detail /etc/passwd")

        monkeypatch.setattr(h.store, "info", boom)
        caplog.set_level(logging.ERROR)
        response = user.get("/me/canvas-token")
        error_of(response, 500, "internal_error")
        assert "secret" not in response.text
        assert "secret internal detail" not in caplog.text
        assert "RuntimeError" in caplog.text

    def test_upstream_text_never_appears(self, h: Harness, user: Api) -> None:
        marker = "UPSTREAM-MARKER-<script>"
        h.whoami_result = CanvasCheckError("invalid")
        response = user.put("/me/canvas-token", {"canvas_token": CANVAS_TOKEN})
        assert marker not in response.text
        h.token_response = lambda r: httpx.Response(400, json={"error_description": marker})
        h.client.cookies.clear()
        login = sign_in(h)
        assert marker not in login.text

    def test_the_error_codes_equal_the_documented_set(self) -> None:
        assert account_api.API_ERROR_CODES == {
            "not_authenticated", "csrf_invalid", "origin_not_allowed", "reauth_required",
            "forbidden", "pending_approval", "access_disabled", "method_not_allowed",
            "unsupported_media_type", "payload_too_large", "malformed_request",
            "validation_failed", "not_found", "rate_limited", "token_store_unavailable",
            "internal_error", "token_invalid_format", "token_rejected", "token_unreadable",
            "canvas_unavailable", "identity_change_required", "recheck_not_allowed",
            "school_required", "school_invalid", "school_not_offered", "school_not_in_directory",
            "school_unresolvable", "school_address_blocked", "school_selection_unverified",
            "directory_unavailable", "write_tool_not_allowed", "write_tools_unavailable",
            "last_owner", "cannot_disable_self",
        }
        for status in account_api.ERROR_STATUS.values():
            assert 400 <= status < 600


