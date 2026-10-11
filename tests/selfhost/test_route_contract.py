"""Public paths agree across the API, frontend, proxy, smoke test and guide."""

import re
from pathlib import Path

from canvas_mcp.core.selfhost.account_api import ApiApp
from canvas_mcp.core.selfhost.routes import (
    API_PREFIX,
    AUTH_LOGIN,
    auth_callback,
    auth_login,
)

ROOT = Path(__file__).resolve().parents[2]
DEPLOY = ROOT / "deploy/selfhost"


def read(path):
    return (ROOT / path).read_text(encoding="utf-8")


def test_frontend_api_contract_and_calls_name_actual_server_routes():
    # route_table only binds endpoints; construction needs no live database here.
    actual = ApiApp.__new__(ApiApp).route_keys()
    contract = read("web/src/api/contract.ts")
    declared = {(method, API_PREFIX + path) for method, path in re.findall(r"['\"](GET|POST|PUT|DELETE|PATCH) (/[^'\"]+)['\"]", contract)}
    assert len(declared) >= 20 and declared == actual
    calls = {(method, API_PREFIX + path) for method, path in re.findall(r"call\('([A-Z]+) (/[^']+)'", read("web/src/api/endpoints.ts"))}
    assert calls and calls <= actual
    assert f"API_BASE_URL = '{API_PREFIX}'" in read("web/src/api/client.ts")


def test_proxy_prefixes_do_not_capture_authorize_or_miss_bare_login():
    nginx = (DEPLOY / "nginx.conf.example").read_text(encoding="utf-8")
    assert "location ^~ /auth/ {" in nginx
    assert "location ^~ /auth {" not in nginx
    assert "location = /authorize {" in nginx
    caddy = (DEPLOY / "Caddyfile.example").read_text(encoding="utf-8")
    assert f"path {AUTH_LOGIN} {AUTH_LOGIN}/* /auth/callback/*" in caddy
    for proxy in (nginx, caddy):
        assert "/account/login" not in proxy and "/account/callback" not in proxy


def test_guide_lists_registry_callbacks_for_all_provider_kinds():
    guide = (DEPLOY / "README.md").read_text(encoding="utf-8")
    for provider in ("entra", "google", "github", "oidc:school"):
        assert '`' + auth_callback(provider) + '`' in guide
    assert '`' + API_PREFIX + '`' in guide
    assert auth_login("oidc:school") == "/auth/login/oidc/school"


def test_smoke_and_development_proxy_follow_the_native_paths():
    smoke = (DEPLOY / "smoke-test.sh").read_text(encoding="utf-8")
    assert f"status 200 {API_PREFIX}/providers" in smoke
    assert f"status 303 {AUTH_LOGIN}?txn=bogus" in smoke
    assert "status 302 " + auth_login("entra") in smoke
    vite = read("web/vite.config.ts")
    for prefix in (API_PREFIX, AUTH_LOGIN, "/auth/callback"):
        assert "'" + prefix + "':" in vite
    assert "ACCOUNT_UI=react" not in vite
    assert "/account/login" not in vite
