"""Strict React bundle loading, static serving and native sign-in navigation."""

from __future__ import annotations

import pathlib
import re
from typing import Any
from urllib.parse import urlparse

import httpx
import pytest

from canvas_mcp.core.selfhost import account_spa
from canvas_mcp.core.selfhost.account_core import SESSION_COOKIE, sanitize_return_to
from canvas_mcp.core.selfhost.account_spa import CSP, SpaBundle, SpaBundleError
from canvas_mcp.core.selfhost.accounts import Denied
from canvas_mcp.core.selfhost.login.ceremony import FLOW_COOKIE

from .authz.stack import ALICE, BASE, Browser, Stack, local_stack
from .login.test_entra_only_golden import account_app

ACCOUNT_CALLBACK_PATH = "/auth/callback/entra"
INDEX = (
    '<!doctype html><html lang="en"><head><meta charset="UTF-8">'
    '<meta name="referrer" content="no-referrer"><meta name="robots" content="noindex">'
    '<link rel="icon" type="image/svg+xml" href="/account/favicon.svg">'
    "<title>Canvas account</title>"
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


def make_dist(
    root: pathlib.Path, *, index: str = INDEX, files: dict[str, bytes] | None = None
) -> pathlib.Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "index.html").write_text(index, encoding="utf-8")
    (root / "favicon.svg").write_text(
        "<svg xmlns='http://www.w3.org/2000/svg'/>", encoding="utf-8"
    )
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
def spa(tmp_path: pathlib.Path, dist: pathlib.Path, monkeypatch):
    with local_stack(
        tmp_path / "app", monkeypatch, env={"ACCOUNT_WEB_DIST": str(dist)}
    ) as running:
        yield running


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
        assert bundle.assets["index-abc123.js"].content_type.startswith(
            "text/javascript"
        )
        assert bundle.assets["index-abc123.css"].content_type.startswith("text/css")
        assert bundle.assets["font-1a2b.woff2"].content_type == "font/woff2"
        assert bundle.index.etag.startswith('"') and len(bundle.index.etag) == 34

    @pytest.mark.skipif(
        not (
            pathlib.Path(__file__).resolve().parents[2] / "web" / "dist" / "index.html"
        ).is_file(),
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
            (
                lambda d: (d / "assets" / "index-abc123.js").unlink(),
                "index_reference_missing",
            ),
            (
                lambda d: (d / "assets" / "vendor-def456.js").unlink(),
                "index_reference_missing",
            ),
            (lambda d: (d / "favicon.svg").unlink(), "index_reference_not_local"),
            (
                lambda d: (d / "assets" / "bad name.js").write_bytes(b"x"),
                "asset_name_not_allowed",
            ),
            (
                lambda d: (d / "assets" / "app.js.map").write_bytes(b"{}"),
                "asset_type_not_allowed",
            ),
            (
                lambda d: (d / "assets" / "notes.txt").write_bytes(b"x"),
                "asset_type_not_allowed",
            ),
            (lambda d: (d / "assets" / "sub").mkdir(), "asset_not_a_file"),
            (
                lambda d: (d / "assets" / "noext").write_bytes(b"x"),
                "asset_type_not_allowed",
            ),
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
            (
                INDEX.replace(
                    '<script type="module" crossorigin src="/account/assets/index-abc123.js"></script>',
                    "",
                ),
                "index_script_count",
            ),
            (
                INDEX
                + '<script type="module" src="/account/assets/vendor-def456.js"></script>',
                "index_script_count",
            ),
            (
                INDEX.replace('type="module" crossorigin src', "crossorigin src"),
                "index_script_not_a_module",
            ),
            (
                INDEX.replace("</script>", "alert(1)</script>", 1),
                "index_script_not_a_module",
            ),
            (
                INDEX.replace(
                    'src="/account/assets/index-abc123.js"', 'src="/elsewhere/app.js"'
                ),
                "index_script_not_under_assets",
            ),
            (
                INDEX.replace(
                    'src="/account/assets/index-abc123.js"',
                    'src="https://cdn.example/app.js"',
                ),
                "index_script_not_under_assets",
            ),
            (
                INDEX.replace(
                    'href="/account/assets/index-abc123.css"',
                    'href="https://cdn.example/a.css"',
                ),
                "index_reference_not_local",
            ),
            (
                INDEX.replace(
                    'href="/account/assets/index-abc123.css"', 'href="/other/a.css"'
                ),
                "index_reference_not_local",
            ),
            (
                INDEX.replace(
                    'href="/account/assets/index-abc123.css"',
                    'href="//cdn.example/a.css"',
                ),
                "index_reference_not_local",
            ),
            (
                INDEX.replace(
                    'href="/account/assets/index-abc123.css"',
                    'href="/account/assets/missing.css"',
                ),
                "index_reference_missing",
            ),
            (INDEX.replace("<div", "<script>x</script><div"), "index_script_count"),
        ],
    )
    def test_a_bad_index_is_refused(
        self, tmp_path: pathlib.Path, index: str, reason: str
    ) -> None:
        root = make_dist(tmp_path / "d", index=index)
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(root)
        assert info.value.reason == reason

    def test_an_index_that_is_not_utf8(self, dist: pathlib.Path) -> None:
        (dist / "index.html").write_bytes(b"\xff\xfe" + INDEX.encode("utf-16-le"))
        with pytest.raises(SpaBundleError) as info:
            SpaBundle.load(dist)
        assert info.value.reason == "index_not_utf8"

    def test_size_limits(
        self, dist: pathlib.Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
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
        assert str(dist) not in str(info.value) and "index-abc123" not in str(
            info.value
        )


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
    def test_the_index_for_every_client_route(self, spa: Stack, path: str) -> None:
        response = spa.client.get(path)
        assert response.status_code == 200
        assert response.text == INDEX
        assert response.headers["content-type"] == "text/html; charset=utf-8"
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"
        assert_spa_headers(response)
        assert "etag" not in response.headers

    def test_a_signed_in_user_gets_the_same_page_with_the_same_headers(
        self, spa: Stack
    ) -> None:
        Browser(spa).sign_in(ALICE)
        response = spa.client.get("/account/")
        assert (
            response.text == INDEX and response.headers["cache-control"] == "no-store"
        )
        assert_spa_headers(response)

    def test_the_page_carries_no_script_but_the_module(self, spa: Stack) -> None:
        text = spa.client.get("/account/").text
        assert len(re.findall(r"<script", text)) == 1

    def test_assets_are_immutable_with_the_right_type(self, spa: Stack) -> None:
        for name, body in FILES.items():
            response = spa.client.get(f"/account/assets/{name}")
            assert response.status_code == 200, name
            assert response.content == body
            assert (
                response.headers["cache-control"]
                == "public, max-age=31536000, immutable"
            )
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["etag"].startswith('"')
            assert_spa_headers(response)
        assert (
            spa.client.get("/account/assets/index-abc123.js")
            .headers["content-type"]
            .startswith("text/javascript")
        )
        assert (
            spa.client.get("/account/assets/index-abc123.css")
            .headers["content-type"]
            .startswith("text/css")
        )
        assert (
            spa.client.get("/account/assets/font-1a2b.woff2").headers["content-type"]
            == "font/woff2"
        )

    def test_conditional_requests(self, spa: Stack) -> None:
        first = spa.client.get("/account/assets/index-abc123.js")
        again = spa.client.get(
            "/account/assets/index-abc123.js",
            headers={"If-None-Match": first.headers["etag"]},
        )
        assert again.status_code == 304 and again.content == b""
        assert again.headers["cache-control"] == "public, max-age=31536000, immutable"
        other = spa.client.get(
            "/account/assets/index-abc123.js", headers={"If-None-Match": '"nope"'}
        )
        assert other.status_code == 200

    def test_the_favicon(self, spa: Stack) -> None:
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
    def test_an_unknown_asset_is_a_plain_404_never_the_index(
        self, spa: Stack, path: str
    ) -> None:
        response = spa.client.get(path)
        if response.status_code == 200:
            # The client normalised a dot segment away to a real, listed route.
            assert response.text == INDEX and "/assets/" not in str(
                response.request.url.path
            )
            return
        assert response.status_code == 404, path
        assert response.headers["content-type"].startswith("text/plain")
        assert response.headers["cache-control"] == "no-store"
        assert INDEX not in response.text
        assert_spa_headers(response)

    def test_long_and_odd_paths_are_404(self, spa: Stack) -> None:
        assert spa.client.get("/account/" + "a" * 520).status_code == 404
        assert spa.client.get("/account/a%00b").status_code == 404
        assert spa.client.get("/account/a%0ab").status_code == 404
        assert spa.client.get("/account/" + "a" * 100).status_code == 200

    def test_head_has_headers_and_no_body(self, spa: Stack) -> None:
        for path in ("/account/", "/account/assets/index-abc123.js"):
            response = spa.client.head(path)
            assert response.status_code == 200 and response.content == b""
            assert response.headers["content-security-policy"] == EXPECTED_CSP
        assert int(spa.client.head("/account/").headers["content-length"]) == len(INDEX)

    @pytest.mark.parametrize("method", ["POST", "PUT", "DELETE", "PATCH", "OPTIONS"])
    def test_other_methods_are_405_everywhere(self, spa: Stack, method: str) -> None:
        for path in (
            "/account",
            "/account/",
            "/account/token",
            "/account/assets/index-abc123.js",
            "/account/favicon.svg",
            "/account/admin/remove",
        ):
            response = spa.client.request(method, path, headers={"Origin": BASE})
            assert response.status_code == 405, (method, path)
            assert response.headers["allow"] == "GET, HEAD"
            assert response.headers["cache-control"] == "no-store"
            assert_spa_headers(response)

    @pytest.mark.parametrize("method", ["PROPFIND", "TRACE", "PURGE"])
    def test_an_unlisted_verb_gets_the_spa_headers_not_a_bare_405(
        self, spa: Stack, method: str
    ) -> None:
        for path in (
            "/account",
            "/account/",
            "/account/token",
            "/account/assets/index-abc123.js",
            "/account/assets/nope.js",
            "/account/favicon.svg",
        ):
            response = spa.client.request(method, path)
            assert response.status_code == 405, (method, path)
            assert response.headers["allow"] == "GET, HEAD"
            assert response.headers["cache-control"] == "no-store"
            assert_spa_headers(response)

    def test_the_html_form_posts_do_not_exist_in_this_mode(self, spa: Stack) -> None:
        Browser(spa).sign_in(ALICE)
        for path in (
            "/account/token",
            "/account/token/delete",
            "/account/logout",
            "/account/write-tools",
            "/account/admin/disable",
        ):
            response = spa.client.post(
                path, data={"csrf": "x"}, headers={"Origin": BASE}
            )
            assert response.status_code == 405

    def test_api_paths_never_fall_through_to_the_index(self, spa: Stack) -> None:
        for path in ("/api/v1", "/api/v1/", "/api/v1/nope", "/api/v1/me/identities"):
            response = spa.client.get(path)
            assert response.status_code == 404
            assert response.headers["content-type"] == "application/json; charset=utf-8"
            assert response.json() == {"error": {"code": "not_found"}}
        assert spa.client.get("/api/v1/providers").status_code == 200
        assert spa.client.get("/api/v1/me").status_code == 401

    def test_the_sign_in_routes_stay_server_side(self, spa: Stack) -> None:
        response = spa.client.get("/auth/login/entra")
        assert response.status_code == 302
        assert (
            urlparse(response.headers["location"]).netloc == "login.microsoftonline.com"
        )
        assert spa.client.get(ACCOUNT_CALLBACK_PATH).status_code == 303


# -- sign-in returns to the app ----------------------------------------------------------------


def sign_in_returning(h: Stack, return_to: str | None, **claims: Any) -> httpx.Response:
    browser = Browser(h, client=h.client)
    params = {} if return_to is None else {"return_to": return_to}
    start = browser.get("/auth/login/entra", params=params)
    return browser.entra_login(ALICE, start, **claims)


class TestSignInReturn:
    def test_a_good_sign_in_lands_on_the_app(self, spa: Stack) -> None:
        response = sign_in_returning(spa, None)
        assert response.status_code == 303
        assert response.headers["location"] == "/account/"
        assert response.headers["cache-control"] == "no-store"
        assert SESSION_COOKIE in "".join(response.headers.get_list("set-cookie"))

    @pytest.mark.parametrize(
        "target",
        [
            "/account/",
            "/account/token",
            "/account/write-tools",
            "/account/admin/audit?before=5",
            "/account/admin?filter=needs_reenroll",
            "/account/activity#recent",
            "/account/a%20b",
            "/account/API/me",
        ],
    )
    def test_a_valid_return_to_is_followed(self, spa: Stack, target: str) -> None:
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
            "/api/v1/me",
            "/api/v1",
            "/account",
            "/auth/login",
            "/auth/login?return_to=/account",
            "/auth/callback/entra",
            "/auth/callback/entra/x",
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
    def test_a_dangerous_return_to_falls_back_to_the_app(
        self, spa: Stack, target: str
    ) -> None:
        response = sign_in_returning(spa, target)
        assert response.status_code == 303
        assert response.headers["location"] == "/account/"

    def test_the_target_stays_out_of_the_provider_url_and_cookie(
        self, spa: Stack
    ) -> None:
        started = spa.client.get(
            "/auth/login/entra", params={"return_to": "/account/token"}
        )
        assert "token" not in started.headers["location"]
        assert FLOW_COOKIE in "".join(started.headers.get_list("set-cookie"))
        payload = account_app(spa).codec.unseal(
            FLOW_COOKIE, spa.client.cookies.get(FLOW_COOKIE)
        )
        assert payload is not None and set(payload) == {"v", "s", "b", "p", "pp", "iat"}

    def test_a_second_sign_in_does_not_inherit_the_target(self, spa: Stack) -> None:
        assert (
            sign_in_returning(spa, "/account/token").headers["location"]
            == "/account/token"
        )
        assert sign_in_returning(spa, None).headers["location"] == "/account/"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("/account/token", True),
            ("/account/account/", False),
            ("/account/%61ccount/token", False),
            ("/account", False),
            ("/account?x=1", False),
            ("//x", False),
            (None, False),
            ("", False),
            ("/api/v1", False),
            ("/api/v1x", False),
        ],
    )
    def test_the_function_itself(self, value: str | None, expected: bool) -> None:
        assert (sanitize_return_to(value) is not None) is expected


@pytest.mark.parametrize("target", ["/account", "/account/", "/account/admin"])
def test_foreign_origin_cannot_mutate_account_api(spa: Stack, target):
    response = spa.client.put(
        "/api/v1/me/ui-locale",
        json={"locale": "zh"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert spa.client.get(target).status_code == 200


def assert_closed_failure(spa: Stack, response: httpx.Response, code: str) -> None:
    assert response.status_code == 303
    assert response.headers["location"] == f"/account/sign-in?error={code}"
    assert response.headers["cache-control"] == "no-store"
    assert spa.client.cookies.get(SESSION_COOKIE) is None
    assert spa.client.cookies.get(FLOW_COOKIE) is None
    assert (
        "secret" not in response.text and "secret" not in response.headers["location"]
    )


class TestSignInFailures:
    @pytest.mark.parametrize("failure", ["endpoint", "missing_id_token"])
    def test_provider_failure_is_a_closed_redirect(self, spa: Stack, failure: str):
        if failure == "endpoint":
            spa.idp.provider.token_error = (
                400,
                {"error": "invalid_grant", "error_description": "secret"},
            )
        else:
            spa.idp.provider.drop_id_token = True
        assert_closed_failure(spa, sign_in_returning(spa, None), "provider_error")

    @pytest.mark.parametrize(
        "claims",
        [{"nonce": "wrong"}, {"aud": "wrong"}, {"iss": "https://evil.example"}],
    )
    def test_unverified_id_token_never_issues_a_session(self, spa: Stack, claims):
        spa.idp.provider.id_token_override = claims
        assert_closed_failure(spa, sign_in_returning(spa, None), "sign_in_unverified")

    @pytest.mark.parametrize(
        ("code", "expected"),
        [
            ("wrong_tenant", "wrong_tenant"),
            ("bad_subject", "bad_subject"),
            ("bad_roles", "bad_roles"),
            ("access_denied", "access_denied"),
            ("access_disabled", "access_disabled"),
            ("signups_paused", "signups_paused"),
            ("unavailable", "token_store_unavailable"),
            ("pending_approval", "access_denied"),
            ("secret", "access_denied"),
        ],
    )
    def test_identity_refusal_exposes_only_a_known_code(
        self, spa: Stack, monkeypatch, code, expected
    ):
        app = account_app(spa)
        assert app.login_manager is not None
        app.login_manager.get()
        monkeypatch.setattr(
            app.identity,
            "sign_in_external",
            lambda *args, **kwargs: Denied(code, "secret <b>provider text</b>"),
        )
        assert_closed_failure(spa, sign_in_returning(spa, None), expected)

    def test_bad_state_refuses_before_token_exchange(self, spa: Stack):
        spa.client.get("/auth/login/entra")
        response = spa.client.get(
            ACCOUNT_CALLBACK_PATH, params={"state": "forged", "code": "secret"}
        )
        assert_closed_failure(spa, response, "state_invalid")
        assert spa.idp.token_requests == 0
