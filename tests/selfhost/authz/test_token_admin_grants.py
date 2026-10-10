"""token_admin list-grants, revoke-grant and rotate-jwt-key."""

from __future__ import annotations

import base64
import pathlib
import uuid

import pytest
from dbbackend import make_store, raw_sql, stack_env

from canvas_mcp.core.selfhost import token_admin
from canvas_mcp.core.selfhost.authz import tokens as tk
from canvas_mcp.core.selfhost.authz.store import AuthzStore
from canvas_mcp.core.selfhost.token_store import Keyring, token_db_path

from ..conftest import OID_A, OID_B, make_account
from .helpers import CHALLENGE, CLIENT, REDIRECT, RESOURCE, SCOPE

KEY = base64.b64encode(bytes([1]) * 32).decode()


@pytest.fixture
def env(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv("SELFHOST_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("CANVAS_TOKEN_KEYS", f"k1:{KEY}")
    for name, value in stack_env().items():
        monkeypatch.setenv(name, value)
    store = make_store(token_db_path(tmp_path), Keyring.parse(f"k1:{KEY}"), clock=lambda: 1_800_000_000, public=True)
    store.initialize()
    account = make_account(store, OID_A)
    authz = AuthzStore(store.database, clock=lambda: 1_800_000_000)
    return store, authz, account


def make_grant(authz: AuthzStore, account: str, *, kind: str = "dcr", client_id: str = CLIENT, name: str = "Test\tapp") -> str:
    raw = tk.new_auth_code()
    assert authz.create_code(
        code_hash=tk.hash_secret(raw), client_id=client_id, client_kind=kind, client_name=name,
        client_host="claude.ai" if kind == "cimd" else None, account_id=account.removeprefix("acct:"),
        redirect_uri=REDIRECT, redirect_uri_explicit=True, redirect_host="claude.ai", code_challenge=CHALLENGE,
        scopes=(SCOPE,), resource=RESOURCE, upstream_auth_at=1_800_000_000,
    )
    result = authz.exchange_code(
        code_hash=tk.hash_secret(raw), client_id=client_id, grant_id=str(uuid.uuid4()),
        refresh_hash=tk.hash_secret(tk.new_refresh_token()),
    )
    assert result.grant is not None
    return result.grant.id


def test_list_grants_prints_one_safe_line_per_live_connection(env, capsys) -> None:
    store, authz, account = env
    first = make_grant(authz, account, kind="cimd", client_id="https://claude.ai/oauth/mcp-oauth-client-metadata")
    second = make_grant(authz, account)
    authz.operator_revoke_grant(second)
    assert token_admin.main(["list-grants"]) == 0
    live = capsys.readouterr().out.strip().splitlines()
    assert len(live) == 1
    fields = live[0].split("\t")
    assert fields[0] == first and fields[1] == account and fields[2] == "cimd"
    assert fields[3] == "https://claude.ai/oauth/mcp-oauth-client-metadata" and fields[5] == "claude.ai"
    assert fields[-1] == "active" and len(fields) == 10
    assert token_admin.main(["list-grants", "--all"]) == 0
    everything = capsys.readouterr().out.strip().splitlines()
    assert len(everything) == 2
    assert any(line.endswith("revoked:operator_revoked") for line in everything)
    assert all("\t\t" not in line and "Test\tapp" not in line for line in everything)


def test_list_grants_never_prints_a_secret(env, capsys) -> None:
    _, authz, account = env
    make_grant(authz, account)
    token_admin.main(["list-grants", "--all"])
    out = capsys.readouterr().out
    assert "cmcp_" not in out and KEY not in out
    assert not any(len(part) == 64 and all(c in "0123456789abcdef" for c in part) for part in out.split())


def test_revoke_grant_ends_one_connection_and_reports_what_it_could_not_find(env, capsys) -> None:
    store, authz, account = env
    grant_id = make_grant(authz, account)
    assert token_admin.main(["revoke-grant", grant_id]) == 0
    assert "revoked 1 connection" in capsys.readouterr().out
    assert raw_sql(store, "SELECT revoked_reason, revoked_by FROM oauth_grants")[0] == ("operator_revoked", "operator")
    assert token_admin.main(["revoke-grant", grant_id]) == token_admin.EXIT_NOT_FOUND
    assert token_admin.main(["revoke-grant", "00000000-0000-4000-8000-000000000000"]) == token_admin.EXIT_NOT_FOUND
    assert token_admin.main(["revoke-grant", "not a uuid"]) == token_admin.EXIT_NOT_FOUND
    assert any(e.action == "grant_revoked" for e in store.list_audit())


def test_rotate_jwt_key_raises_the_epoch(env, capsys) -> None:
    store, authz, _ = env
    assert authz.jwt_epoch() == 0
    assert token_admin.main(["rotate-jwt-key"]) == 0
    out = capsys.readouterr().out
    assert "epoch 1" in out
    assert "access tokens stop verifying within 30 s; refresh tokens and grants are kept" in out
    assert authz.jwt_epoch() == 1
    assert any(e.action == "jwt_key_rotated" for e in store.list_audit())


def test_the_commands_work_on_a_database_that_never_had_a_grant(env, capsys) -> None:
    assert token_admin.main(["list-grants"]) == 0
    assert capsys.readouterr().out == ""


def test_list_grants_for_one_account(env, capsys) -> None:
    store, authz, alice = env
    bob = make_account(store, OID_B)
    mine = make_grant(authz, alice)
    theirs = make_grant(authz, bob)
    assert token_admin.main(["list-grants", alice]) == 0
    lines = capsys.readouterr().out.strip().splitlines()
    assert [line.split("	")[0] for line in lines] == [mine]
    # the bare uuid works too, and an ended one needs --all
    authz.operator_revoke_grant(mine)
    assert token_admin.main(["list-grants", alice.removeprefix("acct:")]) == 0
    assert capsys.readouterr().out == ""
    assert token_admin.main(["list-grants", alice, "--all"]) == 0
    out = capsys.readouterr().out
    assert out.strip().splitlines()[0].split("	")[0] == mine and theirs not in out


def test_list_grants_for_one_account_is_not_cut_off_by_newer_grants_of_others(env, capsys, monkeypatch) -> None:
    store, authz, alice = env
    old = make_grant(authz, alice)
    bob = make_account(store, OID_B)
    later = AuthzStore(store.database, clock=lambda: 1_800_000_500)
    for _ in range(4):
        make_grant(later, bob)
    monkeypatch.setattr(token_admin, "_MAX_LISTED_GRANTS", 2)
    assert token_admin.main(["list-grants"]) == 0
    assert old not in capsys.readouterr().out  # the page of newest grants does not reach it ...
    assert token_admin.main(["list-grants", alice]) == 0  # ... but asking for the account does
    assert [line.split("	")[0] for line in capsys.readouterr().out.strip().splitlines()] == [old]
    assert token_admin.main(["list-grants", alice, "--all"]) == 0
    assert [line.split("	")[0] for line in capsys.readouterr().out.strip().splitlines()] == [old]


def test_list_grants_for_an_unknown_or_malformed_account(env, capsys) -> None:
    assert token_admin.main(["list-grants", "acct:00000000-0000-4000-8000-000000000000"]) == token_admin.EXIT_NOT_FOUND
    assert "no such account" in capsys.readouterr().err
    assert token_admin.main(["list-grants", "nonsense"]) == token_admin.EXIT_CONFIG


def test_revoke_grant_for_a_whole_account_audits_each_one(env, capsys) -> None:
    store, authz, alice = env
    bob = make_account(store, OID_B)
    first, second = make_grant(authz, alice), make_grant(authz, alice)
    other = make_grant(authz, bob)
    assert token_admin.main(["revoke-grant", "--account", alice]) == 0
    assert "revoked 2 connection(s)" in capsys.readouterr().out
    rows = dict(raw_sql(store, "SELECT id, revoked_reason FROM oauth_grants"))
    assert rows[first] == rows[second] == "operator_revoked" and rows[other] is None
    assert len([e for e in store.list_audit() if e.action == "grant_revoked"]) == 2
    assert token_admin.main(["revoke-grant", "--account", alice]) == token_admin.EXIT_NOT_FOUND
    assert token_admin.main(["revoke-grant", "--account", "acct:00000000-0000-4000-8000-000000000000"]) == token_admin.EXIT_NOT_FOUND


def test_revoke_grant_wants_exactly_one_target(env, capsys) -> None:
    _, authz, alice = env
    grant_id = make_grant(authz, alice)
    assert token_admin.main(["revoke-grant"]) == token_admin.EXIT_CONFIG
    assert token_admin.main(["revoke-grant", grant_id, "--account", alice]) == token_admin.EXIT_CONFIG
    assert "not both" in capsys.readouterr().err
    assert token_admin.main(["list-grants"]) == 0
    assert grant_id in capsys.readouterr().out  # nothing was revoked


def test_check_prints_the_number_of_live_connections(env, capsys) -> None:
    _, authz, alice = env
    assert token_admin.main(["check"]) == 0
    assert "live connected apps: 0" in capsys.readouterr().out
    make_grant(authz, alice)
    revoked = make_grant(authz, alice)
    authz.operator_revoke_grant(revoked)
    assert token_admin.main(["check"]) == 0
    assert "live connected apps: 1" in capsys.readouterr().out
