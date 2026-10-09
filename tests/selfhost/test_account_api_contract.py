"""The server and the web app agree on the API: routes and error codes.

The web app declares its side in ``web/src/api/contract.ts`` (a typed table of
``'METHOD /path'`` keys) and ``web/src/api/errors.ts`` (``CODE_SET``). This test parses
both as text, so it needs no Node. It is skipped until the app has the typed contract.
"""

from __future__ import annotations

import pathlib
import re

import pytest

from canvas_mcp.core.selfhost import account_api
from canvas_mcp.core.selfhost.account_web import SIGN_IN_ERROR_CODES, build_account_app

from .test_account_web import build_harness, make_cfg

WEB_API = pathlib.Path(__file__).resolve().parents[2] / "web" / "src" / "api"
CONTRACT = WEB_API / "contract.ts"
ERRORS = WEB_API / "errors.ts"

pytestmark = pytest.mark.skipif(
    not CONTRACT.is_file(), reason="web/src/api/contract.ts does not exist yet"
)


def _normalise(path: str) -> str:
    return re.sub(r"(\$\{[^}]+\}|:[A-Za-z_]+|\{[A-Za-z_]+\})", "{id}", path)


def test_the_web_apps_routes_are_the_servers_routes(tmp_path: pathlib.Path) -> None:
    h = build_harness(tmp_path)
    app = build_account_app(make_cfg(), h.store, h.identity)  # type: ignore[arg-type]
    server = {
        (method, _normalise(path[len(account_api.API_PREFIX) :]))
        for method, path in account_api.ApiApp(app).route_keys()
    }
    text = CONTRACT.read_text(encoding="utf-8")
    web = {
        (method, _normalise(path))
        for method, path in re.findall(
            r"""['"](GET|POST|PUT|PATCH|DELETE) (/[^'"]*)['"]\s*:""", text
        )
    }
    assert web == server, f"only in the web app: {web - server}; only on the server: {server - web}"


def test_the_web_apps_error_codes_are_the_servers() -> None:
    text = ERRORS.read_text(encoding="utf-8")
    block = text[text.index("CODE_SET") :]
    block = block[block.index("{") : block.index("}")]
    web = set(re.findall(r"^\s*([a-z_]+):\s*true", block, re.MULTILINE))
    assert web == set(account_api.API_ERROR_CODES) | set(SIGN_IN_ERROR_CODES)
