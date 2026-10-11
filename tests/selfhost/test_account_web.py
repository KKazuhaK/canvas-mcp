"""Native account cookie and real default Canvas HTTP checker regression.

HTML rendering is covered by the React suite. Callback protocols and verified
provider claims are covered by tests/selfhost/login and authz.
"""

from __future__ import annotations

import pathlib
from collections.abc import Callable
from typing import Any

import httpx
import pytest

from canvas_mcp.core.selfhost.account_core import CanvasCheckError, _CookieCodec

from .account_fixture import (  # noqa: F401
    KEY,
    SESSION_SECRET,
    Harness,
    _display_in_utc,
    build_harness,
    sign_in,
)
from .test_account_api import ACKNOWLEDGED, CANVAS_TOKEN, Api, error_of


def canvas_harness(
    tmp_path: pathlib.Path,
    handler: Callable[[httpx.Request], httpx.Response],
    seen: list[httpx.Request],
) -> Harness:
    h = build_harness(tmp_path)

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        return handler(request)

    h.core._client_factory = lambda: httpx.AsyncClient(
        transport=httpx.MockTransport(recording)
    )
    h.core._canvas_whoami = h.core._default_whoami
    sign_in(h)
    return h


def enroll(h: Harness) -> httpx.Response:
    return Api(h).put(
        "/me/canvas-token", {"canvas_token": CANVAS_TOKEN, "custody": ACKNOWLEDGED}
    )


def test_default_checker_request_and_stored_identity(tmp_path: pathlib.Path) -> None:
    seen: list[httpx.Request] = []
    h = canvas_harness(
        tmp_path,
        lambda request: httpx.Response(
            200, json={"id": 4242, "name": "Real Name", "secret": "hidden"}
        ),
        seen,
    )
    response = enroll(h)
    assert response.status_code == 200
    (request,) = seen
    assert str(request.url) == "https://canvas.example.edu/api/v1/users/self"
    assert request.headers["authorization"] == f"Bearer {CANVAS_TOKEN}"
    assert request.headers["accept"] == "application/json"
    row = h.store.get(KEY)
    assert row is not None
    assert (row.canvas_user_id, row.canvas_user_name) == ("4242", "Real Name")
    assert "hidden" not in response.text and CANVAS_TOKEN not in response.text


def test_default_checker_short_name_is_bounded(tmp_path: pathlib.Path) -> None:
    h = canvas_harness(
        tmp_path,
        lambda request: httpx.Response(200, json={"id": 1, "short_name": "S" * 300}),
        [],
    )
    assert enroll(h).status_code == 200
    assert h.store.get(KEY).canvas_user_name == "S" * 200


@pytest.mark.parametrize("status", [401, 403])
def test_default_checker_rejection_is_closed(
    tmp_path: pathlib.Path, status: int
) -> None:
    h = canvas_harness(
        tmp_path, lambda request: httpx.Response(status, text="UPSTREAM-MARKER"), []
    )
    response = enroll(h)
    error_of(response, 422, "token_rejected")
    assert "UPSTREAM-MARKER" not in response.text and h.store.count() == 0


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, text="UPSTREAM-MARKER"),
        httpx.Response(302, headers={"Location": "https://evil.example/"}),
        httpx.Response(404),
        httpx.Response(200, content=b"not json"),
        httpx.Response(200, json={"name": "no id"}),
        httpx.Response(200, json=["list"]),
    ],
)
def test_default_checker_invalid_answers_never_enroll(
    tmp_path: pathlib.Path, response: httpx.Response
) -> None:
    seen: list[httpx.Request] = []
    h = canvas_harness(tmp_path, lambda request: response, seen)
    result = enroll(h)
    error_of(result, 503, "canvas_unavailable")
    assert "UPSTREAM-MARKER" not in result.text and h.store.count() == 0
    assert len(seen) == 1  # redirects cannot send the bearer token elsewhere


def test_default_checker_timeout_never_enrolls(tmp_path: pathlib.Path) -> None:
    def timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("secret internal detail")

    h = canvas_harness(tmp_path, timeout, [])
    result = enroll(h)
    error_of(result, 503, "canvas_unavailable")
    assert "secret" not in result.text and h.store.count() == 0


def test_cookie_codec_binds_name_and_refuses_tampering() -> None:
    codec = _CookieCodec(SESSION_SECRET)
    sealed = codec.seal("__Host-a", {"k": "v", "n": 1})
    assert sealed.startswith("v1.") and "=" not in sealed
    assert codec.unseal("__Host-a", sealed) == {"k": "v", "n": 1}
    assert codec.unseal("__Host-b", sealed) is None
    assert codec.unseal("__Host-a", None) is None
    assert codec.unseal("__Host-a", sealed[:-1]) is None


def test_cookie_sealing_is_random_and_bound_to_secret() -> None:
    a, b = _CookieCodec(b"a" * 32), _CookieCodec(b"b" * 32)
    assert a.seal("n", {"a": 1}) != a.seal("n", {"a": 1})
    assert b.unseal("n", a.seal("n", {"x": 1})) is None


@pytest.mark.parametrize("kind", ["invalid", "unavailable"])
def test_canvas_error_keeps_only_closed_kind(kind: Any) -> None:
    assert CanvasCheckError(kind).kind == kind
