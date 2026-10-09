"""token_admin and the account model: acct ids, legacy keys, `accounts`, `approve`, `promote-owner`."""

from __future__ import annotations

import base64
import pathlib

import pytest
from dbbackend import make_store, stack_env

from canvas_mcp.core.selfhost import accounts as acc
from canvas_mcp.core.selfhost import token_admin
from canvas_mcp.core.selfhost.token_store import Keyring, TokenStore, token_db_path

from .conftest import TENANT as CONFTEST_TENANT
from .conftest import acct_key, make_account

TID = "11111111-2222-3333-4444-555555555555"
OID_A = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_B = "bbbbbbbb-cccc-dddd-eeee-ffffffffffff"
OID_C = "cccccccc-dddd-eeee-ffff-000000000000"
KEY_A = acct_key(OID_A)
KEY_B = acct_key(OID_B)
KEY_C = acct_key(OID_C)
TOKEN_A = "1234~" + "A" * 60
RING = "k1:" + base64.b64encode(b"\x01" * 32).decode()


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch) -> pathlib.Path:
    monkeypatch.setenv("SELFHOST_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", RING)
    for name, value in stack_env().items():
        monkeypatch.setenv(name, value)
    return tmp_path


@pytest.fixture
def store(env: pathlib.Path) -> TokenStore:
    s = make_store(token_db_path(env), Keyring.parse(RING), clock=lambda: 1_800_000_000, public=True)
    s.initialize()
    return s


def _lines(capsys: pytest.CaptureFixture[str]) -> list[list[str]]:
    return [line.split("\t") for line in capsys.readouterr().out.splitlines()]


class TestAccountsCommand:
    def test_it_lists_every_account_without_secrets(self, store, capsys) -> None:
        make_account(store, OID_A, name="Ada\tL", username="ada@example.test")
        make_account(store, OID_B, status="pending")
        store.put(principal_key=KEY_A, api_token=TOKEN_A, canvas_user_id="1", canvas_user_name="Ada")
        assert token_admin.main(["accounts"]) == 0
        out = capsys.readouterr().out
        assert TOKEN_A not in out and "A" * 40 not in out
        rows = {line.split("\t")[0]: line.split("\t") for line in out.splitlines()}
        assert set(rows) == {KEY_A, KEY_B}
        a = rows[KEY_A]
        assert len(a) == 10 and a[1:3] == ["active", "user"] and a[4] == "Ada L"
        assert a[5] == "ada@example.test" and a[6] == "entra"
        assert rows[KEY_B][1] == "pending"

    def test_it_prints_nothing_for_no_accounts(self, store, capsys) -> None:
        assert token_admin.main(["accounts"]) == 0
        assert capsys.readouterr().out == ""


class TestNamingAnAccount:
    @pytest.mark.parametrize("form", ["acct", "bare", "legacy", "pair"])
    def test_every_form_reaches_the_same_account(self, store, capsys, form: str) -> None:
        make_account(store, OID_A)
        make_account(store, OID_B, role="owner")
        args = {
            "acct": [KEY_A],
            "bare": [KEY_A.removeprefix("acct:")],
            "legacy": [f"entra:{TID}:{OID_A}"],
            "pair": [TID, OID_A],
        }[form]
        assert token_admin.main(["disable", *args]) == 0
        assert "disabled 1 user" in capsys.readouterr().out
        assert store.get_principal_status(KEY_A).disabled
        assert not store.get_principal_status(KEY_B).disabled
        assert token_admin.main(["enable", *args]) == 0
        assert store.get_principal_status(KEY_A).active

    @pytest.mark.parametrize(
        "args",
        [["nope"], ["acct:not-a-uuid"], ["entra:x:y"], ["acct:" + OID_A.upper() + "x"], []],
    )
    def test_anything_else_is_a_usage_error(self, store, capsys, args: list[str]) -> None:
        if not args:
            with pytest.raises(SystemExit):
                token_admin.main(["disable"])
            return
        assert token_admin.main(["disable", *args]) == 2
        assert "acct:<uuid>" in capsys.readouterr().err

    def test_an_unknown_account_is_not_found(self, store, capsys) -> None:
        for command in ("enable", "approve", "promote-owner", "remove"):
            assert token_admin.main([command, KEY_C]) == 1, command
        assert token_admin.main(["history", KEY_C]) == 1
        assert store.list_accounts() == []

    def test_disabling_an_unseen_entra_user_blocks_them_before_their_first_sign_in(
        self, store, capsys
    ) -> None:
        assert token_admin.main(["disable", TID, OID_C]) == 0
        assert "a new account was created" in capsys.readouterr().out
        (account,) = store.list_accounts()
        assert account.status.disabled and account.status.disabled_by == "operator"
        assert store.lookup_identity("entra", acc.entra_issuer(TID), OID_C) == account.principal_key

    def test_an_unseen_acct_id_cannot_be_disabled(self, store, capsys) -> None:
        assert token_admin.main(["disable", KEY_C]) == 1
        assert "no such account" in capsys.readouterr().err
        assert store.list_accounts() == []


class TestApprove:
    def test_it_approves_a_pending_account(self, store, capsys) -> None:
        make_account(store, OID_A, status="pending")
        assert token_admin.main(["approve", KEY_A]) == 0
        assert "approved 1 account" in capsys.readouterr().out
        st = store.get_principal_status(KEY_A)
        assert st.active and st.approved_by == "operator" and st.admitted_via == "approval"

    def test_twice_or_for_an_active_account_is_nothing_to_approve(self, store, capsys) -> None:
        make_account(store, OID_A)
        assert token_admin.main(["approve", KEY_A]) == 1
        assert "not pending" in capsys.readouterr().out

    def test_it_accepts_the_entra_pair(self, store, capsys) -> None:
        make_account(store, OID_A, status="pending")
        assert token_admin.main(["approve", TID, OID_A]) == 0
        assert store.get_principal_status(KEY_A).active

    def test_the_approval_is_in_the_history_and_the_audit_log(self, store, capsys) -> None:
        make_account(store, OID_A, status="pending")
        token_admin.main(["approve", KEY_A])
        capsys.readouterr()
        assert token_admin.main(["history", KEY_A]) == 0
        events = _lines(capsys)
        assert events and events[0][1:5] == [KEY_A, "approved", "operator", "-"]
        assert [e.action for e in store.list_audit() if e.target == KEY_A][0] == "account_approved"


class TestPromoteOwner:
    def test_it_makes_an_active_account_an_owner(self, store, capsys) -> None:
        make_account(store, OID_A)
        assert token_admin.main(["promote-owner", KEY_A]) == 0
        assert "promoted 1 account to owner" in capsys.readouterr().out
        st = store.get_principal_status(KEY_A)
        assert st.is_owner and st.role_source == "operator"
        assert store.count_active_owners() == 1

    def test_not_for_a_pending_disabled_or_owner_account(self, store, capsys) -> None:
        make_account(store, OID_A, status="pending")
        make_account(store, OID_B, status="disabled")
        make_account(store, OID_C, role="owner")
        for key in (KEY_A, KEY_B, KEY_C):
            assert token_admin.main(["promote-owner", key]) == 1
        assert store.count_active_owners() == 1


class TestListingsAndGuards:
    def test_list_carries_the_account_key_and_the_legacy_columns(self, store, capsys) -> None:
        make_account(store, OID_A, name="Ada")
        store.put(principal_key=KEY_A, api_token=TOKEN_A, canvas_user_id="1", canvas_user_name="Ada")
        assert token_admin.main(["list"]) == 0
        (row,) = _lines(capsys)
        assert len(row) == 7 and row[6] == KEY_A and row[2] == "Ada"
        assert row[:2] == [CONFTEST_TENANT, OID_A]  # the Entra identity, as the old columns showed it

    def test_the_last_owner_cannot_be_disabled_without_the_flag(self, store, capsys) -> None:
        make_account(store, OID_A, role="owner")
        assert token_admin.main(["disable", KEY_A]) == 3
        assert "last active owner" in capsys.readouterr().err
        assert token_admin.main(["disable", "--allow-last-owner", KEY_A]) == 0
        assert store.get_principal_status(KEY_A).disabled

    def test_check_and_access_describe_the_account_model(self, store, capsys) -> None:
        make_account(store, OID_A, role="owner")
        make_account(store, OID_B, status="pending")
        make_account(store, OID_C, status="disabled")
        assert token_admin.main(["check"]) == 0
        out = capsys.readouterr().out
        assert "accounts: 3 (active 1, pending 1, disabled 1)" in out
        assert "tokens of principals without an account: 0" in out
        assert token_admin.main(["access"]) == 0
        rows = {r[0]: r for r in _lines(capsys)}
        assert set(rows) == {KEY_A, KEY_B, KEY_C}
        assert rows[KEY_A][2] == "owner" and rows[KEY_B][1] == "pending" and rows[KEY_C][1] == "disabled"

    def test_remove_by_acct_id_deletes_only_the_token(self, store, capsys) -> None:
        make_account(store, OID_A)
        store.put(principal_key=KEY_A, api_token=TOKEN_A, canvas_user_id="1", canvas_user_name="Ada")
        assert token_admin.main(["remove", KEY_A]) == 0
        assert store.get(KEY_A) is None and store.get_principal_status(KEY_A).active
        assert token_admin.main(["remove", KEY_A]) == 1
