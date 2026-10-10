"""Smoke test of the harness: one complete connection, end to end."""

from __future__ import annotations

from .stack import ALICE, AUDIENCE, local_stack


def test_a_full_connection(tmp_path, monkeypatch) -> None:
    with local_stack(tmp_path, monkeypatch) as stack:
        key = stack.enroll(ALICE)
        client_id, tokens = stack.tokens_for(ALICE)
        assert tokens["token_type"] == "Bearer" and tokens["refresh_token"].startswith("cmcp_rt_")
        assert stack.whoami(tokens["access_token"]) == key
        refreshed = stack.refresh(client_id, tokens["refresh_token"])
        assert refreshed.status_code == 200, refreshed.text
        assert AUDIENCE
