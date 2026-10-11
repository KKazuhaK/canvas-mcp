"""The React account app exposes native JSON routes and no HTML form adapter."""

import pathlib

import pytest

from .account_fixture import KEY, _display_in_utc, build_harness, sign_in  # noqa: F401
from .test_account_api import CANVAS_TOKEN, Api


@pytest.mark.parametrize(
    "path",
    [
        "/account/token",
        "/account/token/delete",
        "/account/token/recheck",
        "/account/logout",
        "/account/write-tools",
        "/account/admin/remove",
        "/account/admin/disable",
        "/account/admin/enable",
        "/account/admin/approve",
        "/account/admin/deny",
        "/account/consent",
        "/account/identities/link",
    ],
)
def test_old_html_post_paths_cannot_mutate_native_accounts(
    tmp_path: pathlib.Path, path: str
) -> None:
    h = build_harness(tmp_path)
    sign_in(h)
    csrf = Api(h).csrf()
    response = h.client.post(
        path,
        data={"csrf": csrf, "canvas_token": CANVAS_TOKEN, "principal_key": KEY},
        headers={"Origin": "https://canvas.example.test"},
    )
    assert response.status_code in (404, 405)
    assert h.store.info(KEY) is None and h.store.get_principal_status(KEY).active
    assert h.whoami_calls == []
