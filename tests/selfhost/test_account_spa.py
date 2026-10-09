"""Serving the built account UI (and falling back to the pages when it is unusable).

The bundle is read from a small fake ``dist`` made here; the real build is checked by
``npm run check:dist`` in ``web/``.
"""

from __future__ import annotations

import base64
import logging
import pathlib
import re
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlparse

import fastmcp
import httpx
import pytest
from dbbackend import stack_env
from fastmcp import FastMCP
from fastmcp.server.auth.providers.jwt import StaticTokenVerifier
from starlette.testclient import TestClient

from canvas_mcp.core.selfhost import account_spa
from canvas_mcp.core.selfhost.account_spa import CSP, SpaBundle, SpaBundleError
from canvas_mcp.core.selfhost.account_web import (
    ACCOUNT_CALLBACK_PATH,
    LOGIN_COOKIE,
    SESSION_COOKIE,
    SIGN_IN_ERROR_CODES,
    _AccountApp,
    sanitize_return_to,
)
from canvas_mcp.core.selfhost.accounts import (
    DENY_ACCESS_DENIED,
    DENY_ACCESS_DISABLED,
    DENY_BAD_ROLES,
    DENY_BAD_SUBJECT,
    DENY_SIGNUPS_PAUSED,
    DENY_WRONG_CLIENT,
    DENY_WRONG_TENANT,
    Denied,
)
from canvas_mcp.core.selfhost.app import (
    build_selfhost_asgi_app,
    install_selfhost,
    prepare_selfhost,
)
from canvas_mcp.core.selfhost.settings import load_selfhost_settings
from canvas_mcp.core.selfhost.token_store import OPERATOR

from .conftest import CLIENT, TENANT
from .test_account_web import (
    BASE,
    CLIENT_ID,
    KEY,
    OID,
    TID,
    Harness,
    _display_in_utc,  # noqa: F401 - autouse fixture: timestamps render in UTC
    build_harness,
    login_params,
    make_cfg,
    sign_in,
)

INDEX = (
    '<!doctype html><html lang="en"><head><meta charset="UTF-8">'
    '<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">'
    '<link rel="icon" type="image/svg+xml" href="/account/favicon.svg">'
    '<title>Canvas account</title>'
    '<script type="module" crossorigin src="/account/assets/index-abc123.js"></script>'
    '<link rel="modulepreload" crossorigin href="/account/assets/vendor-def456.js">'
    '<link rel="stylesheet" crossorigin href="/account/assets/index-abc123.css">'
    '</head><body><div id="root"></div></body></html>'
)
FILES = {
    "index-abc123.js": b"console.log('app');\n",
    "vendor-def456.js": b"export const v = 1;\n",
    "index-abc123.css": b"body{margin:0}\n",
    "font-1a2b.woff2": b"wOF2....",
}
EXPECTED_CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'"
)


def make_dist(root: pathlib.Path, *, index: str = INDEX, files: dict[str, bytes] | None = None) -> pathlib.Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(index, encoding="utf-8")
    (root / "favicon.svg").write_text("<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8")
    assets = root / "assets"
    assets.mkdir(exist_ok=True)
    for name, body in (FILES if files is None else files).items():
        (assets / name).write_bytes(body)
    return root


@pytest.fixture
def dist(tmp_path: pathlib.Path) -> pathlib.Path:
    return make_dist(tmp_path / "dist")


@pytest.fixture
def bundle(dist: pathlib.Path) -> SpaBundle:
    return SpaBundle.load(dist)


@pytest.fixture
def spa(tmp_path: pathlib.Path, bundle: SpaBundle) -> Harness:
    return build_harness(tmp_path, ui="react", spa=bundle)


def assert_spa_headers(response: httpx.Response) -> None:
    headers = response.headers
    assert headers["content-security-policy"] == EXPECTED_CSP
    assert headers["x-frame-options"] == "DENY"
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["cross-origin-opener-policy"] == "same-origin"
    assert headers["cross-origin-resource-policy"] == "same-origin"


# -- loading the bundle ------------------------------------------------------------


class TestLoading:
    def test_a_good_build(self, bundle: SpaBundle) -> None:
        assert set(bundle.assets) == set(FILES)
        assert set(bundle.extras) == {"favicon.svg"}
        assert bundle.index.content_type == "text/html; charset=utf-8"
        assert bundle.assets["index-abc123.js"].content_type.startswith("text/javascript")
        assert bundle.assets["index-abc123.css"].content_type.startswith("text/css")
        assert bundle.assets["font-1a2b.woff2"].content_type == "font/woff2"
        assert bundle.index.etag.startswith('"') and len(bundle.index.etag) == 34

    @pytest.mark.skipif(
        not (pathlib.Path(__file__).resolve().parents[2] / "web" / "dist" / "index.html").is_file(),
        reason="web/ has not been built (npm run build)",
    )
    def test_the_real_build_loads(self) -> None:
        """What `npm run build` really emits passes the same checks the server applies."""
        root = pathlib.Path(__file__).resolve().parents[2] / "web" / "dist"
        real = SpaBundle.load(root)
        assert real.assets and "favicon.svg" in real.extras
        assert real.index.body.count(b"<script") == 1

    def test_the_policy_constant_is_the_documented_one(self) -> None:
        assert CSP == EXPECTED_CSP

    def test_a_missing_directory(self, tmp_path: pathlib.Path) -> None:
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(tmp_path / "nowhere")
        assert info.value.reason == "directory_missing"
        (tmp_path / "file").write_text("x", encoding="utf-8")
        with pytest.raises(SpaBundleError):
            SpaBundle.load(tmp_path / "file")

    @pytest.mark.parametrize(
        ("mutate", "reason"),
        [
            (lambda d: (d / "index.html").unlink(), "index_unreadable"),
            (lambda d: (d / "assets" / "index-abc123.js").unlink(), "index_reference_missing"),
            (lambda d: (d / "assets" / "vendor-def456.js").unlink(), "index_reference_missing"),
            (lambda d: (d / "favicon.svg").unlink(), "index_reference_not_local"),
            (lambda d: (d / "assets" / "bad name.js").write_bytes(b"x"), "asset_name_not_allowed"),
            (lambda d: (d / "assets" / "app.js.map").write_bytes(b"{}"), "asset_type_not_allowed"),
            (lambda d: (d / "assets" / "notes.txt").write_bytes(b"x"), "asset_type_not_allowed"),
            (lambda d: (d / "assets" / "sub").mkdir(), "asset_not_a_file"),
            (lambda d: (d / "assets" / "noext").write_bytes(b"x"), "asset_type_not_allowed"),
        ],
    )
    def test_an_unusable_build_is_refused(
        self, dist: pathlib.Path, mutate: Any, reason: str
    ) -> None:
        mutate(dist)
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(dist)
        assert info.value.reason == reason

    @pytest.mark.parametrize(
        ("index", "reason"),
        [
            (INDEX.replace('<script type="module" crossorigin src="/account/assets/index-abc123.js"></script>', ""), "index_script_count"),
            (INDEX + '<script type="module" src="/account/assets/vendor-def456.js"></script>', "index_script_count"),
            (INDEX.replace('type="module" crossorigin src', 'crossorigin src'), "index_script_not_a_module"),
            (INDEX.replace("</script>", "alert(1)</script>", 1), "index_script_not_a_module"),
            (INDEX.replace('src="/account/assets/index-abc123.js"', 'src="/elsewhere/app.js"'), "index_script_not_under_assets"),
            (INDEX.replace('src="/account/assets/index-abc123.js"', 'src="https://cdn.example/app.js"'), "index_script_not_under_assets"),
            (INDEX.replace('href="/account/assets/index-abc123.css"', 'href="https://cdn.example/a.css"'), "index_reference_not_local"),
            (INDEX.replace('href="/account/assets/index-abc123.css"', 'href="/other/a.css"'), "index_reference_not_local"),
            (INDEX.replace('href="/account/assets/index-abc123.css"', 'href="//cdn.example/a.css"'), "index_reference_not_local"),
            (INDEX.replace('href="/account/assets/index-abc123.css"', 'href="/account/assets/missing.css"'), "index_reference_missing"),
            (INDEX.replace("<div", "<script>x</script><div"), "index_script_count"),
        ],
    )
    def test_a_bad_index_is_refused(self, tmp_path: pathlib.Path, index: str, reason: str) -> None:
        root = make_dist(tmp_path / "d", index=index)
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(root)
        assert info.value.reason == reason

    def test_an_index_that_is_not_utf8(self, dist: pathlib.Path) -> None:
        (dist / "index.html").write_bytes(b"\xff\xfe" + INDEX.encode("utf-16-le"))
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(dist)
        assert info.value.reason == "index_not_utf8"

    def test_size_limits(self, dist: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(account_spa, "MAX_INDEX_BYTES", 100)
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(dist)
        assert info.value.reason == "index_too_large"
        monkeypatch.setattr(account_spa, "MAX_INDEX_BYTES", 256 * 1024)
        monkeypatch.setattr(account_spa, "MAX_ASSET_BYTES", 10)
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(dist)
        assert info.value.reason == "asset_too_large"
        monkeypatch.setattr(account_spa, "MAX_ASSET_BYTES", 5 * 1024 * 1024)
        monkeypatch.setattr(account_spa, "MAX_TOTAL_ASSET_BYTES", 30)
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(dist)
        assert info.value.reason == "assets_too_large"

    def test_a_symlink_that_leaves_the_directory_is_refused(
        self, tmp_path: pathlib.Path, dist: pathlib.Path
    ) -> None:
        outside = tmp_path / "outside.js"
        outside.write_text("secret", encoding="utf-8")
        link = dist / "assets" / "leak.js"
        try:
            link.symlink_to(outside)
        except (OSError, NotImplementedError):
            pytest.skip("symbolic links are not available here")
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(dist)
        assert info.value.reason == "asset_outside_directory"

    def test_a_missing_assets_directory(self, dist: pathlib.Path) -> None:
        for path in (dist / "assets").iterdir():
            path.unlink()
        (dist / "assets").rmdir()
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(dist)
        assert info.value.reason == "assets_missing"

    def test_the_reason_never_holds_a_path(self, dist: pathlib.Path) -> None:
        (dist / "assets" / "index-abc123.js").unlink()
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(dist)
        assert str(dist) not in str(info.value) and "index-abc123" not in str(info.value)


# -- serving -----------------------------------------------------------------------------


class TestServing:
    @pytest.mark.parametrize(
        "path",
        [
            "/account",
            "/account/",
            "/account/sign-in",
            "/account/token",
            "/account/write-tools",
            "/account/admin",
            "/account/admin/audit",
            "/account/activity",
            "/account/some/deep/client/route",
            "/account/favicon.ico",
        ],
    )
    def test_the_index_for_every_client_route(self, spa: Harness, path: str) -> None:
        response = spa.client.get(path)
        assert response.status_code == 200
        assert response.text == INDEX
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        assert_spa_headers(response)
        assert "etag" not in response.headers

    def test_a_signed_in_user_gets_the_same_page_with_the_same_headers(self, spa: Harness) -> None:
        sign_in(spa)
        response = spa.client.get("/account/")
        assert response.text == INDEX and response.headers["cache-control"] == "no-store"
        assert_spa_headers(response)

    def test_the_page_carries_no_script_but_the_module(self, spa: Harness) -> None:
        text = spa.client.get("/account/").text
        assert len(re.findall(r"<script", text)) == 1

    def test_assets_are_immutable_with_the_right_type(self, spa: Harness) -> None:
        for name, body in FILES.items():
            response = spa.client.get(f"/account/assets/{name}")
            assert response.status_code == 200, name
            assert response.content == body
            assert response.headers["cache-control"] == "public, max-age=31536000, immutable"
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["etag"].startswith('"')
            assert_spa_headers(response)
        assert spa.client.get("/account/assets/index-abc123.js").headers["content-type"].startswith(
            "text/javascript"
        )
        assert spa.client.get("/account/assets/index-abc123.css").headers["content-type"].startswith(
            "text/css"
        )
        assert spa.client.get("/account/assets/font-1a2b.woff2").headers["content-type"] == "font/woff2"

    def test_conditional_requests(self, spa: Harness) -> None:
        first = spa.client.get("/account/assets/index-abc123.js")
        again = spa.client.get(
            "/account/assets/index-abc123.js", headers={"If-None-Match": first.headers["etag"]}
        )
        assert again.status_code == 304 and again.content == b""
        assert again.headers["cache-control"] == "public, max-age=31536000, immutable"
        other = spa.client.get(
            "/account/assets/index-abc123.js", headers={"If-None-Match": '"nope"'}
        )
        assert other.status_code == 200

    def test_the_favicon(self, spa: Harness) -> None:
        response = spa.client.get("/account/favicon.svg")
        assert response.status_code == 200
        assert response.headers["content-type"] == "image/svg+xml"
        assert response.headers["cache-control"] == "public, max-age=86400"
        assert_spa_headers(response)  # an SVG is served under the policy too

    @pytest.mark.parametrize(
        "path",
        [
            "/account/assets/missing.js",
            "/account/assets/",
            "/account/assets",
            "/account/assets/sub/index-abc123.js",
            "/account/assets/../index.html",
            "/account/assets/..%2findex.html",
            "/account/assets/%2e%2e/index.html",
            "/account/assets/..%5cindex.html",
            "/account/assets/index-abc123.js%00",
            "/account/assets/INDEX-ABC123.JS",
        ],
    )
    def test_an_unknown_asset_is_a_plain_404_never_the_index(self, spa: Harness, path: str) -> None:
        response = spa.client.get(path)
        if response.status_code == 200:
            # The client normalised a dot segment away to a real, listed route.
            assert response.text == INDEX and "/assets/" not in str(response.request.url.path)
            return
        assert response.status_code == 404, path
        assert response.headers["content-type"].startswith("text/plain")
        assert response.headers["cache-control"] == "no-store"
        assert INDEX not in response.text
        assert_spa_headers(response)

    def test_long_and_odd_paths_are_404(self, spa: Harness) -> None:
        assert spa.client.get("/account/" + "a" * 520).status_code == 404
        assert spa.client.get("/account/a%00b").status_code == 404
        assert spa.client.get("/account/a%0ab").status_code == 404
        assert spa.client.get("/account/" + "a" * 100).status_code == 200

    def test_head_has_headers_and_no_body(self, spa: Harness) -> None:
        for path in ("/account/", "/account/assets/index-abc123.js"):
            response = spa.client.head(path)
            assert response.status_code == 200 and response.content == b""
            assert response.headers["content-security-policy"] == EXPECTED_CSP
        assert int(spa.client.head("/account/").headers["content-length"]) == len(INDEX)

    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    def test_other_methods_are_405_everywhere(self, spa: Harness, method: str) -> None:
        for path in ("/account", "/account/", "/account/token", "/account/assets/index-abc123.js",
                     "/account/favicon.svg", "/account/admin/remove"):
            response = spa.client.request(method, path, headers={"Origin": BASE})
            assert response.status_code == 405, (method, path)
            assert response.headers["allow"] == "GET, HEAD"
            assert response.headers["cache-control"] == "no-store"
            assert_spa_headers(response)

    @pytest.mark.parametrize("method", ["PROPFIND", "TRACE", "PURGE"])
    def test_an_unlisted_verb_gets_the_spa_headers_not_a_bare_405(
        self, spa: Harness, method: str
    ) -> None:
        for path in ("/account", "/account/", "/account/token", "/account/assets/index-abc123.js",
                     "/account/assets/nope.js", "/account/favicon.svg"):
            response = spa.client.request(method, path)
            assert response.status_code == 405, (method, path)
            assert response.headers["allow"] == "GET, HEAD"
            assert response.headers["cache-control"] == "no-store"
            assert_spa_headers(response)

    def test_the_html_form_posts_do_not_exist_in_this_mode(self, spa: Harness) -> None:
        sign_in(spa)
        for path in ("/account/token", "/account/token/delete", "/account/logout",
                     "/account/write-tools", "/account/admin/disable"):
            response = spa.client.post(path, data={"csrf": "x"}, headers={"Origin": BASE})
            assert response.status_code == 405

    def test_api_paths_never_fall_through_to_the_index(self, spa: Harness) -> None:
        for path in ("/account/api", "/account/api/", "/account/api/nope", "/account/api/me/identities"):
            response = spa.client.get(path)
            assert response.status_code == 404
            assert response.headers["content-type"] == "application/json; charset=utf-8"
            assert response.json() == {"error": {"code": "not_found"}}
        assert spa.client.get("/account/api/providers").status_code == 200
        assert spa.client.get("/account/api/me").status_code == 401

    def test_the_sign_in_routes_stay_server_side(self, spa: Harness) -> None:
        response = spa.client.get("/account/login")
        assert response.status_code == 302
        assert urlparse(response.headers["location"]).netloc == "login.microsoftonline.com"
        assert spa.client.get(ACCOUNT_CALLBACK_PATH).status_code == 303


# -- sign-in returns to the app ----------------------------------------------------------------


def sign_in_returning(h: Harness, return_to: str | None, **claims: Any) -> httpx.Response:
    """The sign-in of the tests' ``sign_in``, started with ``?return_to=``."""
    params: dict[str, str] = {}
    if return_to is not None:
        params["return_to"] = return_to
    started = h.client.get("/account/login", params=params)
    assert started.status_code == 302
    query = {k: v[0] for k, v in parse_qs(urlparse(started.headers["location"]).query).items()}
    h.claims = {
        "tid": TID,
        "oid": OID,
        "name": "Ada Lovelace",
        "preferred_username": "ada@example.test",
        "roles": ["Canvas.User"],
        "nonce": query["nonce"],
        "iat": int(h.now),
        "exp": int(h.now) + 3600,
        "aud": CLIENT_ID,
        **claims,
    }
    return h.client.get(ACCOUNT_CALLBACK_PATH, params={"code": "c", "state": query["state"]})


class TestSignInReturn:
    def test_a_good_sign_in_lands_on_the_app(self, spa: Harness) -> None:
        response = sign_in_returning(spa, None)
        assert response.status_code == 303
        assert response.headers["location"] == "/account/"
        assert response.headers["cache-control"] == "no-store"
        assert SESSION_COOKIE in "".join(response.headers.get_list("set-cookie"))

    @pytest.mark.parametrize(
        "target",
        [
            "/account",
            "/account/",
            "/account/token",
            "/account/write-tools",
            "/account/admin/audit?before=5",
            "/account/admin?filter=needs_reenroll",
            "/account/activity#recent",
            "/account/a%20b",
        ],
    )
    def test_a_valid_return_to_is_followed(self, spa: Harness, target: str) -> None:
        assert sign_in_returning(spa, target).headers["location"] == target

    @pytest.mark.parametrize(
        "target",
        [
            "//evil.example",
            "/\\evil.example",
            "/account//evil.example",
            "/account/%2f%2fevil.example",
            "/account/%2F/evil",
            "/account/..%2f..%2fx",
            "/account/%252e%252e/x",
            "/account/%255c",
            "https://evil.example/account",
            "http://evil.example",
            "javascript:alert(1)",
            "/account/api/me",
            "/account/api",
            "/account/API/me",
            "/account/login",
            "/account/login?return_to=/account",
            "/account/callback",
            "/account/callback/x",
            "/account/../x",
            "/account/./x",
            "/account/x/../y",
            "/accounts",
            "/accountx",
            "/other",
            "account/token",
            "",
            "/account/x\r\nLocation: https://evil.example",
            "/account/\x00",
            "/account/ü",
            "/account/" + "a" * 520,
            "/account/%0d%0a",
        ],
    )
    def test_a_dangerous_return_to_falls_back_to_the_app(self, spa: Harness, target: str) -> None:
        response = sign_in_returning(spa, target)
        assert response.status_code == 303
        assert response.headers["location"] == "/account/"

    def test_the_target_is_sealed_in_the_login_cookie_only(self, spa: Harness) -> None:
        started = spa.client.get("/account/login", params={"return_to": "/account/token"})
        assert "token" not in started.headers["location"]
        assert LOGIN_COOKIE in "".join(started.headers.get_list("set-cookie"))

    def test_the_legacy_mode_ignores_return_to(self, tmp_path: pathlib.Path) -> None:
        h = build_harness(tmp_path)
        response = sign_in_returning(h, "/account/token")
        assert response.status_code == 303
        assert response.headers["location"] == "/account"

    def test_a_second_sign_in_does_not_inherit_the_target(self, spa: Harness) -> None:
        assert sign_in_returning(spa, "/account/token").headers["location"] == "/account/token"
        assert sign_in_returning(spa, None).headers["location"] == "/account/"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("/account/token", True),
            ("/account", True),
            ("/account?x=1", True),
            ("//x", False),
            (None, False),
            ("", False),
            ("/account/api", False),
            ("/account/apix", True),
        ],
    )
    def test_the_function_itself(self, value: str | None, expected: bool) -> None:
        assert (sanitize_return_to(value) is not None) is expected


class TestSignInFailures:
    def landing(self, response: httpx.Response) -> str:
        assert response.status_code == 303, response.text
        location = urlparse(response.headers["location"])
        assert location.path == "/account/sign-in"
        assert response.headers["cache-control"] == "no-store"
        assert "max-age=0" in "".join(response.headers.get_list("set-cookie")).lower()
        assert SESSION_COOKIE not in "".join(
            c for c in response.headers.get_list("set-cookie") if "max-age=0" not in c.lower()
        )
        (code,) = parse_qs(location.query)["error"]
        assert code in SIGN_IN_ERROR_CODES
        assert location.query == f"error={code}"
        return code

    def test_no_login_transaction(self, spa: Harness) -> None:
        response = spa.client.get(ACCOUNT_CALLBACK_PATH, params={"code": "x", "state": "y"})
        assert self.landing(response) == "state_invalid"

    def test_a_wrong_state(self, spa: Harness) -> None:
        login_params(spa)
        response = spa.client.get(ACCOUNT_CALLBACK_PATH, params={"code": "x", "state": "no"})
        assert self.landing(response) == "state_invalid"

    def test_entra_refusing_is_a_provider_error_and_nothing_is_echoed(self, spa: Harness) -> None:
        params = login_params(spa)
        response = spa.client.get(
            ACCOUNT_CALLBACK_PATH,
            params={
                "state": params["state"],
                "error": "access_denied",
                "error_description": "<script>alert(1)</script> AADSTS50105 secret-detail",
            },
        )
        assert self.landing(response) == "provider_error"
        assert "secret" not in response.headers["location"] and "AADSTS" not in response.headers["location"]

    def test_a_missing_code(self, spa: Harness) -> None:
        params = login_params(spa)
        response = spa.client.get(ACCOUNT_CALLBACK_PATH, params={"state": params["state"]})
        assert self.landing(response) == "sign_in_incomplete"

    def test_the_token_endpoint_failing(self, spa: Harness) -> None:
        spa.token_response = lambda r: httpx.Response(400, json={"error_description": "LEAK"})
        response = sign_in_returning(spa, None)
        assert self.landing(response) == "provider_error"
        assert "LEAK" not in response.headers["location"]

    @pytest.mark.parametrize("mode", ["none", "raise"])
    def test_an_unverifiable_id_token(self, spa: Harness, mode: str) -> None:
        spa.verifier_result = mode
        assert self.landing(sign_in_returning(spa, None)) == "sign_in_unverified"

    def test_a_wrong_nonce(self, spa: Harness) -> None:
        assert self.landing(sign_in_returning(spa, None, nonce="other")) == "sign_in_unverified"

    def test_a_wrong_tenant(self, spa: Harness) -> None:
        response = sign_in_returning(spa, None, tid="99999999-9999-9999-9999-999999999999")
        assert self.landing(response) == "wrong_tenant"

    def test_no_role_is_access_denied(self, spa: Harness) -> None:
        assert self.landing(sign_in_returning(spa, None, roles=[])) == "access_denied"

    def test_a_bad_subject(self, spa: Harness) -> None:
        assert self.landing(sign_in_returning(spa, None, oid="not-a-guid")) == "bad_subject"

    def test_malformed_roles(self, spa: Harness) -> None:
        assert self.landing(sign_in_returning(spa, None, roles="Canvas.User")) == "bad_roles"

    def test_a_disabled_account(self, spa: Harness) -> None:
        sign_in_returning(spa, None)
        spa.client.cookies.clear()
        spa.store.disable_principal(KEY, actor=OPERATOR, reason="operator_disabled")
        assert self.landing(sign_in_returning(spa, None)) == "access_disabled"

    @pytest.mark.parametrize(
        ("denied", "expected"),
        [
            (DENY_WRONG_CLIENT, "wrong_client"),
            (DENY_WRONG_TENANT, "wrong_tenant"),
            (DENY_BAD_SUBJECT, "bad_subject"),
            (DENY_BAD_ROLES, "bad_roles"),
            (DENY_ACCESS_DENIED, "access_denied"),
            (DENY_ACCESS_DISABLED, "access_disabled"),
            (DENY_SIGNUPS_PAUSED, "signups_paused"),
            ("unavailable", "token_store_unavailable"),
            ("pending_approval", "access_denied"),
            ("something_new", "access_denied"),
        ],
    )
    def test_every_denial_maps_into_the_closed_set(
        self, spa: Harness, monkeypatch: pytest.MonkeyPatch, denied: str, expected: str
    ) -> None:
        assert spa.identity is not None
        monkeypatch.setattr(
            spa.identity, "sign_in", lambda claims, **kw: Denied(denied, "UPSTREAM MESSAGE <b>")
        )
        response = sign_in_returning(spa, None)
        assert self.landing(response) == expected
        assert "UPSTREAM" not in response.headers["location"]

    def test_an_unreadable_store(self, spa: Harness, monkeypatch: pytest.MonkeyPatch) -> None:
        assert spa.identity is not None

        def boom(claims: Any, **kw: Any) -> Any:
            raise RuntimeError("driver said: /secret/path")

        monkeypatch.setattr(spa.identity, "sign_in", boom)
        response = sign_in_returning(spa, None)
        assert self.landing(response) == "token_store_unavailable"
        assert "secret" not in response.headers["location"]

    def test_the_legacy_pages_still_show_their_messages(self, tmp_path: pathlib.Path) -> None:
        h = build_harness(tmp_path)
        response = h.client.get(ACCOUNT_CALLBACK_PATH, params={"code": "x", "state": "y"})
        assert response.status_code == 400 and "invalid or expired" in response.text


# -- the whole server -------------------------------------------------------------------------


@pytest.fixture
def stack_factory(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> Any:
    monkeypatch.setattr(fastmcp.settings, "home", tmp_path / "fastmcp")
    monkeypatch.setenv("CANVAS_API_URL", "https://canvas.example.edu")
    for name in ("CANVAS_API_TOKEN", "CANVAS_ROLE"):
        monkeypatch.delenv(name, raising=False)
    from canvas_mcp.core.config import reset_config

    reset_config()
    opened: list[Any] = []

    def make(extra: dict[str, str]) -> SimpleNamespace:
        settings = load_selfhost_settings(
            {
                "PUBLIC_BASE_URL": BASE,
                "ENTRA_TENANT_ID": TENANT,
                "ENTRA_CLIENT_ID": CLIENT,
                "ENTRA_CLIENT_SECRET": "entra-client-secret-0123456789",
                "OAUTH_JWT_SIGNING_KEY": "jwt-signing-key-" + "z" * 40,
                "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
                "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(bytes(32)).decode(),
                "FASTMCP_HOME": str(tmp_path / "fastmcp"),
                "SELFHOST_DATA_DIR": str(tmp_path / "data"),
                **stack_env(),
                **extra,
            }
        )
        runtime = prepare_selfhost(settings)
        config: Any = SimpleNamespace(canvas_api_url="https://canvas.example.edu/api/v1")
        mcp = FastMCP("spa", auth=StaticTokenVerifier({}, required_scopes=["Canvas.Access"]))
        effective = install_selfhost(mcp, runtime, config)
        app = build_selfhost_asgi_app(mcp, runtime, config)
        client = TestClient(app, base_url=BASE, follow_redirects=False)
        client.__enter__()
        opened.append(client)
        return SimpleNamespace(client=client, runtime=runtime, effective=effective)

    yield make
    for client in opened:
        client.__exit__(None, None, None)
    reset_config()


class TestWholeServer:
    def test_react_with_a_build_serves_it_beside_the_rest_of_the_server(
        self, stack_factory: Any, dist: pathlib.Path
    ) -> None:
        s = stack_factory({"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(dist)})
        assert s.effective == "react"
        page = s.client.get("/account/")
        assert page.status_code == 200 and page.text == INDEX
        assert_spa_headers(page)
        assert s.client.get("/account/token").text == INDEX
        asset = s.client.get("/account/assets/index-abc123.js")
        assert asset.headers["cache-control"] == "public, max-age=31536000, immutable"
        # Everything outside /account is untouched by the fallback route.
        assert s.client.get("/healthz").text == "ok"
        assert s.client.get("/mcp").status_code in (401, 405, 406)
        assert s.client.get("/.well-known/oauth-authorization-server").status_code in (200, 404)
        assert s.client.get("/nothing-here").status_code == 404
        # The API, the sign-in start and the HTML forms.
        assert s.client.get("/account/api/providers").json()["providers"][0]["id"] == "entra"
        error = s.client.get("/account/api/me")
        assert error.status_code == 401 and error.headers["cache-control"] == "no-store"
        assert error.json() == {"error": {"code": "not_authenticated"}}
        assert s.client.get("/account/login").status_code == 302
        assert s.client.post("/account/token").status_code == 405

    @pytest.mark.parametrize("method", ["PROPFIND", "TRACE"])
    def test_an_unlisted_verb_keeps_the_headers_through_the_real_registration(
        self, stack_factory: Any, dist: pathlib.Path, method: str
    ) -> None:
        s = stack_factory({"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(dist)})
        api = s.client.request(method, "/account/api/me")
        assert api.status_code == 405
        assert api.json() == {"error": {"code": "method_not_allowed"}}
        assert api.headers["cache-control"] == "no-store"
        assert api.headers["x-content-type-options"] == "nosniff"
        assert api.headers["content-security-policy"] == (
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'"
        )
        page = s.client.request(method, "/account/")
        assert page.status_code == 405
        assert_spa_headers(page)

    def test_a_foreign_origin_is_stopped_by_the_outer_guard(
        self, stack_factory: Any, dist: pathlib.Path
    ) -> None:
        s = stack_factory({"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(dist)})
        response = s.client.put(
            "/account/api/me/ui-locale",
            json={"locale": "zh"},
            headers={"Origin": "https://evil.example"},
        )
        assert response.status_code == 403

    def test_the_default_is_the_legacy_pages_and_no_api(self, stack_factory: Any) -> None:
        s = stack_factory({})
        assert s.effective == "legacy"
        page = s.client.get("/account")
        assert page.status_code == 200 and "Sign in with Microsoft" in page.text
        assert page.headers["content-security-policy"].startswith("default-src 'none'; style-src")
        assert s.client.get("/account/api/providers").status_code == 404
        assert s.client.get("/account/api/me").status_code == 404
        assert s.client.post("/account/token").status_code == 303  # signed out: back to /account

    def test_legacy_is_also_what_an_explicit_value_gives(
        self, stack_factory: Any, dist: pathlib.Path
    ) -> None:
        s = stack_factory({"ACCOUNT_UI": "legacy", "ACCOUNT_WEB_DIST": str(dist)})
        assert s.effective == "legacy"
        assert "Sign in with Microsoft" in s.client.get("/account").text
        assert s.client.get("/account/assets/index-abc123.js").status_code == 404

    @pytest.mark.parametrize(
        "damage",
        ["nodir", "noindex", "badindex", "badasset"],
    )
    def test_an_unusable_build_falls_back_to_the_pages_with_one_warning(
        self,
        stack_factory: Any,
        tmp_path: pathlib.Path,
        caplog: pytest.LogCaptureFixture,
        damage: str,
    ) -> None:
        root = make_dist(tmp_path / "broken")
        target = root
        if damage == "nodir":
            target = tmp_path / "does-not-exist"
        elif damage == "noindex":
            (root / "index.html").unlink()
        elif damage == "badindex":
            (root / "index.html").write_text("<html><body>no script</body></html>", encoding="utf-8")
        else:
            (root / "assets" / "evil name.js").write_text("x", encoding="utf-8")
        caplog.set_level(logging.WARNING)
        s = stack_factory({"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(target)})
        assert s.effective == "legacy"
        warnings = [r.getMessage() for r in caplog.records if "ACCOUNT_UI=react" in r.getMessage()]
        assert len(warnings) == 1
        assert "serving the legacy /account pages" in warnings[0]
        assert str(target) not in warnings[0]
        page = s.client.get("/account")
        assert page.status_code == 200 and "Sign in with Microsoft" in page.text
        assert page.headers["content-security-policy"].startswith("default-src 'none'; style-src")
        assert "Content-Security-Policy" not in INDEX
        # The sign-in is the HTML one, and the pages work in full.
        assert s.client.get("/account/callback").status_code == 400
        assert s.client.post("/account/token").status_code == 303
        # The API is still there (for a Vite dev proxy), protected like any other.
        assert s.client.get("/account/api/providers").status_code == 200
        assert s.client.get("/account/api/me").status_code == 401
        # And never a half-served page.
        assert s.client.get("/account/assets/index-abc123.js").status_code == 404
        assert s.client.get("/account/token").status_code == 405

    def test_the_default_dist_is_the_image_path(self) -> None:
        settings = load_selfhost_settings(
            {
                "PUBLIC_BASE_URL": BASE,
                "ENTRA_TENANT_ID": TENANT,
                "ENTRA_CLIENT_ID": CLIENT,
                "ENTRA_CLIENT_SECRET": "entra-client-secret-0123456789",
                "OAUTH_JWT_SIGNING_KEY": "jwt-signing-key-" + "z" * 40,
                "ACCOUNT_SESSION_SECRET": base64.b64encode(bytes(range(32))).decode(),
                "CANVAS_TOKEN_KEYS": "k1:" + base64.b64encode(bytes(32)).decode(),
                "FASTMCP_HOME": "/tmp/fastmcp",
            }
        )
        assert settings.account_ui == "legacy"
        assert settings.account_web_dist == pathlib.PurePosixPath("/app/web-dist") or str(
            settings.account_web_dist
        ).replace("\\", "/") == "/app/web-dist"


def test_the_react_routes_keep_only_the_sign_in_halves_of_the_pages(
    tmp_path: pathlib.Path, bundle: SpaBundle
) -> None:
    from canvas_mcp.core.selfhost.account_web import build_account_routes

    h = build_harness(tmp_path, ui="react", spa=bundle)
    routes = build_account_routes(
        make_cfg(),
        h.store,
        h.identity,  # type: ignore[arg-type]
        ui="react",
        spa=bundle,
    )
    paths = [r.path for r in routes]
    assert "/account/login" in paths and "/account/callback" in paths
    assert "/account/token" not in paths and "/account/admin" not in paths
    # The API (and its JSON 404) come before the single-page fallback.
    assert paths.index("/account/api") < paths.index("/account/{path:path}")
    assert paths.index("/account/api/{rest:path}") < paths.index("/account/{path:path}")
    assert paths.index("/account/assets/{name:path}") < paths.index("/account/{path:path}")
    # The legacy composition has no API and no fallback at all.
    legacy = build_account_routes(make_cfg(), h.store, h.identity)  # type: ignore[arg-type]
    assert not [r.path for r in legacy if r.path.startswith("/account/api")]
    assert "/account/{path:path}" not in [r.path for r in legacy]
    assert len(_AccountApp.route_table(_AccountApp.__new__(_AccountApp))) >= 17
