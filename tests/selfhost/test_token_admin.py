"""Tests for the token_admin operator CLI."""

from __future__ import annotations

import base64
import os
import pathlib
import subprocess
import sys

import pytest

from canvas_mcp.core.selfhost import token_admin
from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore, token_db_path

TID = "11111111-2222-3333-4444-555555555555"
OID_A = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_B = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
TOKEN_A = "1234~" + "A" * 60
TOKEN_B = "1234~" + "B" * 60


def _k(byte: int) -> str:
    return base64.b64encode(bytes([byte]) * 32).decode()


KEY1 = _k(1)
KEY2 = _k(2)


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    monkeypatch.setenv("SELFHOST_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k1:{KEY1}")
    return tmp_path


def _seed(data_dir: pathlib.Path, keys: str = f"k1:{KEY1}") -> TokenStore:
    store = TokenStore(token_db_path(data_dir), Keyring.parse(keys), clock=lambda: 1_800_000_000)
    store.initialize()
    store.put(
        tenant_id=TID, object_id=OID_A, api_token=TOKEN_A, canvas_user_id="1",
        canvas_user_name="Ada\tLovelace\nTwo", entra_display_name="Ada", entra_upn="ada@example.test",
    )
    store.put(
        tenant_id=TID, object_id=OID_B, api_token=TOKEN_B, canvas_user_id="2",
        canvas_user_name="Bob", entra_display_name="Bob", entra_upn="bob@example.test",
    )
    store.touch(TID, OID_B)
    return store


def _no_secrets(*texts: str) -> None:
    for text in texts:
        for secret in (TOKEN_A, TOKEN_B, KEY1, KEY2, "A" * 40, "B" * 40):
            assert secret not in text


def test_check_on_empty_store_creates_it(env, capsys) -> None:
    assert token_admin.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "rows: 0" in out and "(none)" in out
    assert token_db_path(env).exists()


def test_check_reports_rows_and_key_ids(env, capsys) -> None:
    _seed(env)
    assert token_admin.main(["check"]) == 0
    captured = capsys.readouterr()
    assert "rows: 2" in captured.out and "key ids in use: k1" in captured.out
    _no_secrets(captured.out, captured.err)


def test_list_is_tab_separated_and_has_no_tokens(env, capsys) -> None:
    _seed(env)
    assert token_admin.main(["list"]) == 0
    captured = capsys.readouterr()
    lines = captured.out.splitlines()
    assert len(lines) == 2
    first = lines[0].split("\t")
    assert first == [
        TID, OID_A, "Ada Lovelace Two", "2027-01-15T08:00:00Z", "-", "-",
    ]
    second = lines[1].split("\t")
    assert second[:3] == [TID, OID_B, "Bob"]
    assert second[4] == "2027-01-15T08:00:00Z"
    assert second[5] == "-"
    _no_secrets(captured.out, captured.err)


def test_revoke_found_and_not_found(env, capsys) -> None:
    store = _seed(env)
    assert token_admin.main(["revoke", TID.upper(), OID_A.upper()]) == 0
    assert store.get(TID, OID_A) is None and store.get(TID, OID_B) is not None
    capsys.readouterr()
    assert token_admin.main(["revoke", TID, OID_A]) == 1
    assert "not found" in capsys.readouterr().out
    assert store.count() == 1


def test_revoke_rejects_non_guid(env, capsys) -> None:
    _seed(env)
    assert token_admin.main(["revoke", "nope", OID_A]) == 2
    assert "GUID" in capsys.readouterr().err


def test_rotate_then_check_with_new_key_only(env, monkeypatch, capsys) -> None:
    _seed(env)
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k2:{KEY2},k1:{KEY1}")
    assert token_admin.main(["rotate"]) == 0
    out = capsys.readouterr().out
    assert "re-encrypted 2 row(s)" in out
    assert token_admin.main(["rotate"]) == 0
    assert "re-encrypted 0 row(s)" in capsys.readouterr().out
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k2:{KEY2}")
    assert token_admin.main(["check"]) == 0
    captured = capsys.readouterr()
    assert "key ids in use: k2" in captured.out
    _no_secrets(out, captured.out, captured.err)


def test_missing_old_key_is_a_config_error(env, monkeypatch, capsys) -> None:
    _seed(env)
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k2:{KEY2}")
    assert token_admin.main(["check"]) == 2
    captured = capsys.readouterr()
    assert "missing key id(s): k1" in captured.err
    _no_secrets(captured.out, captured.err)


def test_wrong_key_under_same_kid_is_a_config_error(env, monkeypatch, capsys) -> None:
    _seed(env)
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k1:{KEY2}")
    assert token_admin.main(["list"]) == 2
    captured = capsys.readouterr()
    assert "does not match" in captured.err
    _no_secrets(captured.out, captured.err)


@pytest.mark.parametrize("value", [None, "", "garbage", f"k1:{_k(1)[:-4]}", "k1:" + base64.b64encode(b"x" * 16).decode()])
def test_bad_or_missing_keys_exit_2_without_echoing_them(env, monkeypatch, capsys, value) -> None:
    if value is None:
        monkeypatch.delenv("CANVAS_TOKEN_KEYS")
    else:
        monkeypatch.setenv("CANVAS_TOKEN_KEYS", value)
    assert token_admin.main(["check"]) == 2
    captured = capsys.readouterr()
    assert captured.err.startswith("error: ")
    if value:
        assert value not in captured.err and value not in captured.out


def test_unwritable_data_dir_is_a_config_error(
    env, tmp_path, monkeypatch, capsys
) -> None:
    blocker = tmp_path / "file-not-dir"
    blocker.write_text("x", encoding="utf-8")
    monkeypatch.setenv("SELFHOST_DATA_DIR", str(blocker))
    assert token_admin.main(["check"]) == 2
    assert capsys.readouterr().err.startswith("error: cannot open the token store")


def test_corrupt_row_in_rotate_is_exit_2(env, monkeypatch, capsys) -> None:
    import sqlite3

    store = _seed(env)
    with sqlite3.connect(str(store._path)) as conn:
        conn.execute("UPDATE canvas_tokens SET ciphertext = X'00' WHERE object_id = ?", (OID_B,))
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k2:{KEY2},k1:{KEY1}")
    # initialize() only probe-decrypts one row per key; make the probe row good.
    assert token_admin.main(["rotate"]) == 2
    err = capsys.readouterr().err
    assert "could not be decrypted" in err or "does not match" in err


def test_unknown_command_is_rejected_by_argparse(env) -> None:
    with pytest.raises(SystemExit) as exc:
        token_admin.main(["frobnicate"])
    assert exc.value.code == 2


def test_runs_as_a_module(env) -> None:
    _seed(env)
    child_env = dict(os.environ)
    child_env["PYTHONUTF8"] = "1"
    result = subprocess.run(
        [sys.executable, "-m", "canvas_mcp.core.selfhost.token_admin", "check"],
        capture_output=True, text=True, env=child_env, timeout=60, encoding="utf-8",
    )
    assert result.returncode == 0, result.stderr
    assert "rows: 2" in result.stdout
    _no_secrets(result.stdout, result.stderr)


def test_list_shows_the_canvas_host_and_dash_for_legacy_rows(env, capsys) -> None:
    store = _seed(env)
    store.put(
        tenant_id=TID, object_id=OID_B, api_token=TOKEN_B, canvas_user_id="2",
        canvas_user_name="Bob", entra_display_name="Bob", entra_upn="bob@example.test",
        canvas_host="canvas.school-b.edu",
    )
    assert token_admin.main(["list"]) == 0
    captured = capsys.readouterr()
    rows = [line.split("\t") for line in captured.out.splitlines()]
    assert all(len(r) == 6 for r in rows)
    assert rows[0][5] == "-"
    assert rows[1][5] == "canvas.school-b.edu"
    _no_secrets(captured.out, captured.err)


def test_check_reports_schools_in_use(env, capsys) -> None:
    store = _seed(env)
    store.put(
        tenant_id=TID, object_id=OID_B, api_token=TOKEN_B, canvas_user_id="2",
        canvas_user_name="Bob", entra_display_name="Bob", entra_upn="bob@example.test",
        canvas_host="canvas.school-b.edu",
    )
    assert token_admin.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "schools in use: 1 (+1 legacy row(s))" in out


def test_rotate_with_mixed_rows_keeps_working(env, monkeypatch, capsys) -> None:
    store = _seed(env)
    store.put(
        tenant_id=TID, object_id=OID_B, api_token=TOKEN_B, canvas_user_id="2",
        canvas_user_name="Bob", entra_display_name="Bob", entra_upn="bob@example.test",
        canvas_host="canvas.school-b.edu",
    )
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k2:{KEY2},k1:{KEY1}")
    assert token_admin.main(["rotate"]) == 0
    assert "re-encrypted 2 row(s)" in capsys.readouterr().out
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k2:{KEY2}")
    assert token_admin.main(["check"]) == 0
    assert token_admin.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "canvas.school-b.edu" in out
