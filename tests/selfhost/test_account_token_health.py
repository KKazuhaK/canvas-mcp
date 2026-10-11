"""Restoring or replacing a token invalidates the native health verdict."""

import pathlib

import pytest

from canvas_mcp.core.selfhost.account_core import CanvasCheckError

from .account_fixture import (  # noqa: F401
    CANVAS_TOKEN,
    KEY,
    OID,
    _display_in_utc,
    build_harness,
    put_row,
    sign_in,
)
from .test_account_api import ACKNOWLEDGED, NEW_TOKEN, Api, error_of


class SpyHealth:
    def __init__(self) -> None:
        self.forgotten: list[str] = []

    def forget(self, key: str) -> None:
        self.forgotten.append(key)


@pytest.mark.parametrize("action", ["recheck", "replace", "refused"])
def test_health_verdict_is_forgotten_only_after_success(
    tmp_path: pathlib.Path, action: str
) -> None:
    spy = SpyHealth()
    h = build_harness(tmp_path, health=spy)
    put_row(h.store, OID, token=CANVAS_TOKEN, name="Ada", canvas_user_id="42")
    h.store.mark_invalid(KEY, reason="canvas_token_rejected")
    sign_in(h)
    api = Api(h)
    if action == "replace":
        assert (
            api.put(
                "/me/canvas-token", {"canvas_token": NEW_TOKEN, "custody": ACKNOWLEDGED}
            ).status_code
            == 200
        )
    else:
        if action == "refused":
            h.whoami_result = CanvasCheckError("invalid")
        response = api.post("/me/canvas-token/recheck")
        if action == "refused":
            error_of(response, 422, "token_rejected")
        else:
            assert (
                response.status_code == 200 and response.json()["result"] == "restored"
            )
    assert spy.forgotten == ([] if action == "refused" else [KEY])
