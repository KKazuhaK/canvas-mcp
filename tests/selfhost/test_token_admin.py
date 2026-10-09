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


def test_a_version_1_database_is_migrated_by_the_cli_and_stays_manageable(env, monkeypatch, capsys) -> None:
    import sqlite3

    path = token_db_path(env)
    path.parent.mkdir(parents=True)
    ring = Keyring.parse(f"k1:{KEY1}")
    aad = b"canvas-mcp/canvas-token/v1\x1f" + f"{TID}\x1f{OID_A}\x1fk1".encode()
    kid, nonce, ct = ring.encrypt(TOKEN_A.encode(), aad)
    conn = sqlite3.connect(str(path), isolation_level=None)
    try:
        conn.execute("CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL) WITHOUT ROWID")
        conn.execute(
            "CREATE TABLE canvas_tokens ("
            " tenant_id TEXT NOT NULL, object_id TEXT NOT NULL, key_id TEXT NOT NULL,"
            " nonce BLOB NOT NULL, ciphertext BLOB NOT NULL, canvas_user_id TEXT NOT NULL,"
            " canvas_user_name TEXT NOT NULL, entra_display_name TEXT NOT NULL DEFAULT '',"
            " entra_upn TEXT NOT NULL DEFAULT '', created_at INTEGER NOT NULL,"
            " updated_at INTEGER NOT NULL, last_used_at INTEGER,"
            " PRIMARY KEY (tenant_id, object_id)) WITHOUT ROWID"
        )
        conn.execute("INSERT INTO meta VALUES ('schema_version', '1')")
        conn.execute(
            "INSERT INTO canvas_tokens VALUES (?,?,?,?,?,?,?,?,?,?,?,NULL)",
            (TID, OID_A, kid, nonce, ct, "1", "Ada", "Ada", "ada@example.test", 1, 1),
        )
    finally:
        conn.close()

    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k2:{KEY2},k1:{KEY1}")
    assert token_admin.main(["rotate"]) == 0
    assert "re-encrypted 1 row(s)" in capsys.readouterr().out
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k2:{KEY2}")
    assert token_admin.main(["list"]) == 0
    row = capsys.readouterr().out.splitlines()[0].split("\t")
    assert row[:2] == [TID, OID_A] and row[5] == "-"
    assert token_admin.main(["revoke", TID, OID_A]) == 0
    assert "revoked 1 enrollment" in capsys.readouterr().out
    assert token_admin.main(["revoke", TID, OID_A]) == 1


# -- disable / enable: the authorization decision --------------------------------

KEY_A = f"entra:{TID}:{OID_A}"
KEY_B = f"entra:{TID}:{OID_B}"


def test_disable_blocks_and_survives_deleting_the_enrollment(env, capsys) -> None:
    from canvas_mcp.core.selfhost.token_store import PrincipalDisabledError

    store = _seed(env)
    assert token_admin.main(["disable", TID.upper(), OID_A.upper()]) == 0
    assert "disabled 1 user" in capsys.readouterr().out
    assert store.get_principal_status(KEY_A).disabled
    assert store.get_principal_status(KEY_A).disabled_by == "operator"
    assert token_admin.main(["remove", TID, OID_A]) == 0  # remove the token as well
    capsys.readouterr()
    assert store.get_principal_status(KEY_A).disabled  # still disabled
    with pytest.raises(PrincipalDisabledError):
        store.put(
            tenant_id=TID, object_id=OID_A, api_token=TOKEN_A, canvas_user_id="1",
            canvas_user_name="n", entra_display_name="n", entra_upn="n@example.test",
        )


def test_disable_twice_and_enable(env, capsys) -> None:
    store = _seed(env)
    assert token_admin.main(["disable", TID, OID_A]) == 0
    assert token_admin.main(["disable", TID, OID_A]) == 0
    assert "already disabled" in capsys.readouterr().out
    assert token_admin.main(["enable", TID, OID_A]) == 0
    assert "enabled 1 user" in capsys.readouterr().out
    assert not store.get_principal_status(KEY_A).disabled
    assert token_admin.main(["enable", TID, OID_A]) == 1  # nothing to enable
    assert "not disabled" in capsys.readouterr().out


def test_disable_and_enable_reject_non_guids(env, capsys) -> None:
    _seed(env)
    assert token_admin.main(["disable", "nope", OID_A]) == 2
    assert token_admin.main(["enable", TID, "nope"]) == 2
    assert "GUID" in capsys.readouterr().err


def test_the_last_owner_needs_the_break_glass_flag(env, capsys) -> None:
    store = _seed(env)
    store.record_sign_in(KEY_A, is_owner=True)
    assert token_admin.main(["disable", TID, OID_A]) == 3
    assert "last active owner" in capsys.readouterr().err
    assert not store.get_principal_status(KEY_A).disabled
    store.record_sign_in(KEY_B, is_owner=True)
    assert token_admin.main(["disable", TID, OID_A]) == 0  # a second owner exists
    capsys.readouterr()
    assert token_admin.main(["disable", TID, OID_B]) == 3  # B is the last one now
    capsys.readouterr()
    assert token_admin.main(["disable", TID, OID_B, "--allow-last-owner"]) == 0
    assert store.count_active_owners() == 0


def test_access_lists_disabled_users_and_owners_without_secrets(env, capsys) -> None:
    store = _seed(env)
    store.record_sign_in(KEY_B, is_owner=True)
    token_admin.main(["disable", TID, OID_A])
    capsys.readouterr()
    assert token_admin.main(["access"]) == 0
    captured = capsys.readouterr()
    rows = [line.split("\t") for line in captured.out.splitlines()]
    assert [r[0] for r in rows] == [KEY_A, KEY_B]
    assert rows[0][1:3] == ["disabled", "-"] and rows[0][4:6] == ["operator", "operator_disabled"]
    assert rows[1][1:3] == ["active", "owner"]
    _no_secrets(captured.out, captured.err)


def test_history_records_the_cli_transitions(env, capsys) -> None:
    _seed(env)
    token_admin.main(["disable", TID, OID_A])
    token_admin.main(["enable", TID, OID_A])
    capsys.readouterr()
    assert token_admin.main(["history", TID, OID_A]) == 0
    lines = [line.split("\t") for line in capsys.readouterr().out.splitlines()]
    assert [(r[2], r[3]) for r in lines] == [("enabled", "operator"), ("disabled", "operator")]
    assert token_admin.main(["history"]) == 0
    assert len(capsys.readouterr().out.splitlines()) == 2
    assert token_admin.main(["history", TID]) == 2


def test_check_reports_the_access_state(env, capsys) -> None:
    store = _seed(env)
    store.record_sign_in(KEY_B, is_owner=True)
    token_admin.main(["disable", TID, OID_A])
    capsys.readouterr()
    assert token_admin.main(["check"]) == 0
    out = capsys.readouterr().out
    assert "disabled users: 1" in out and "active owners seen: 1" in out


def test_remove_and_revoke_only_delete_the_token_and_say_so(env, capsys) -> None:
    store = _seed(env)
    assert token_admin.main(["remove", TID, OID_A]) == 0
    captured = capsys.readouterr()
    assert "removed 1 enrollment" in captured.out
    assert "can enroll again" in captured.err and "disable" in captured.err
    assert not store.get_principal_status(KEY_A).disabled
    assert token_admin.main(["revoke", TID, OID_B]) == 0
    assert "revoked 1 enrollment" in capsys.readouterr().out
