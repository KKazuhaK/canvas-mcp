"""Native keyset reads, wire bounds and mutation-stable continuation."""

import base64
import json
from dataclasses import FrozenInstanceError

import pytest
from sqlalchemy import delete, event, insert

from canvas_mcp.core.selfhost.authz.store import AuthzStore
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.types import new_id
from canvas_mcp.core.selfhost.pagination import decode_cursor, make_page, page_limit

from .authz.stack import ALICE, OWNER, Browser, local_stack
from .test_v1_store import account, put, stores  # noqa: F401

NOW = 1_800_000_000


def encoded(value):
    return base64.urlsafe_b64encode(json.dumps(value).encode()).decode().rstrip("=")


@pytest.mark.parametrize("value", [0, -1, 201, True, "50", 1.0])
def test_page_limit_is_bounded_and_exactly_integer(value):
    with pytest.raises(ValueError):
        page_limit(value)


@pytest.mark.parametrize(
    "value",
    [
        [True, "scope", 1],
        [1.0, "scope", 1],
        [2, "scope", 1],
        [1, "wrong", 1],
        [1, "scope", True],
        [1, "scope", 0],
        [1, "scope", 2**63],
        [1, "scope", 1.5],
        {"key": 1},
        [1, "scope", 1, "extra"],
    ],
)
def test_noncanonical_and_wrong_scope_cursors_are_refused(value):
    with pytest.raises(ValueError):
        decode_cursor(encoded(value), "scope", integer=True)


def test_cursor_is_opaque_canonical_and_page_is_frozen():
    page = make_page([3, 2, 1], limit=2, scope="history", key=lambda row: row)
    assert page.items == (3, 2) and page.next_cursor != "2"
    assert decode_cursor(page.next_cursor, "history", integer=True) == 2
    with pytest.raises(ValueError):
        decode_cursor(page.next_cursor + "=", "history", integer=True)
    with pytest.raises(ValueError):
        decode_cursor("2", "history", integer=True)
    with pytest.raises(FrozenInstanceError):
        page.next_cursor = None
    assert (
        make_page([2, 1], limit=2, scope="history", key=lambda row: row).next_cursor
        is None
    )


def test_account_pages_filter_in_sql_and_remain_stable_after_insert_and_delete(stores):  # noqa: F811
    one, _, _ = stores
    ids = [account(one, str(index)) for index in range(5)]
    first = one.accounts_page(limit=2)
    assert [row.principal_key for row in first.items] == sorted(ids, reverse=True)[:2]
    added = account(one, "new")
    with one.database.write() as conn:
        conn.execute(
            delete(s.accounts).where(s.accounts.c.id == first.items[-1].principal_key)
        )
    second = one.accounts_page(limit=2, cursor=first.next_cursor)
    third = one.accounts_page(limit=2, cursor=second.next_cursor)
    older = [row.principal_key for row in (*second.items, *third.items)]
    assert older == sorted(ids, reverse=True)[2:] and added not in older
    assert third.next_cursor is None
    with pytest.raises(ValueError):
        one.accounts_page(limit=2, cursor=first.next_cursor, status="pending")


def test_page_queries_load_only_referenced_identities_and_credentials(stores):  # noqa: F811
    one, _, _ = stores
    for index in range(5):
        key = account(one, str(index))
        put(one, key)
    statements = []

    def observe(conn, cursor, statement, parameters, context, executemany):
        if statement.lstrip().startswith("SELECT"):
            statements.append(statement)

    event.listen(one.database.engine, "before_cursor_execute", observe)
    try:
        page = one.accounts_page(limit=2)
    finally:
        event.remove(one.database.engine, "before_cursor_execute", observe)
    assert len(page.items) == 2 and all(
        row.enrollment and len(row.identities) == 1 for row in page.items
    )
    assert len(statements) == 3 and "LIMIT" in statements[0]
    assert "account_id IN" in statements[1] and "account_id IN" in statements[2]


def test_credentials_history_audit_and_grants_use_their_own_unique_keys(stores):  # noqa: F811
    one, _, _ = stores
    keys = [account(one, str(index)) for index in range(4)]
    credentials = [put(one, key) for key in keys]
    first = one.enrollments_page(limit=2)
    second = one.enrollments_page(limit=2, cursor=first.next_cursor)
    assert [row.credential_id for row in (*first.items, *second.items)] == sorted(
        (row.credential_id for row in credentials), reverse=True
    )
    assert second.next_cursor is None
    with one.database.write() as conn:
        conn.execute(
            insert(s.auth_events),
            [
                {
                    "at": NOW,
                    "account_id": keys[0],
                    "provider_id": "entra",
                    "surface": "account",
                    "outcome": "success",
                    "reason": "ok",
                }
                for _ in range(4)
            ],
        )
        conn.execute(
            insert(s.oauth_grants),
            [
                {
                    "id": new_id(),
                    "account_id": key,
                    "client_id": "client",
                    "client_kind": "dcr",
                    "redirect_host": "client.example",
                    "scopes": "Canvas.Access",
                    "resource": "https://mcp.example/mcp",
                    "created_at": NOW,
                    "upstream_auth_at": NOW,
                    "expires_at": NOW + 1000,
                }
                for key in keys
                for _ in range(2)
            ],
        )
    events = one.auth_events_page(keys[0], limit=2)
    remaining = one.auth_events_page(keys[0], limit=2, cursor=events.next_cursor)
    assert (
        len(events.items) == len(remaining.items) == 2 and remaining.next_cursor is None
    )
    assert min(row.id for row in events.items) > max(row.id for row in remaining.items)
    with pytest.raises(ValueError):
        one.auth_events_page(keys[1], cursor=events.next_cursor)
    audit = one.audit_page(account_id=keys[0], limit=2)
    assert audit.next_cursor is not None
    with pytest.raises(ValueError):
        one.audit_page(cursor=audit.next_cursor)
    authz = AuthzStore(one.database, clock=lambda: NOW)
    grants = authz.grants_page(account_key=keys[0], limit=1)
    last = authz.grants_page(account_key=keys[0], limit=1, cursor=grants.next_cursor)
    assert all(row.account_key == keys[0] for row in (*grants.items, *last.items))
    assert last.next_cursor is None and authz.count_live_grants() == 8
    assert len(list(authz.iter_grants())) == 8


@pytest.fixture
def stack(tmp_path, monkeypatch):
    with local_stack(tmp_path, monkeypatch) as running:
        yield running


@pytest.mark.parametrize(
    "path",
    [
        "/admin/accounts",
        "/admin/enrollments",
        "/admin/audit",
        "/me/login-history",
        "/me/grants",
    ],
)
def test_api_default_page_is_50_and_rejects_old_duplicate_or_unbounded_query(
    stack, path
):
    browser = Browser(stack)
    browser.sign_in(OWNER)
    result = browser.api("GET", path)
    assert result.status_code == 200 and "next_cursor" in result.json()
    for query in [
        "limit=0",
        "limit=201",
        "limit=true",
        "limit=1.5",
        "cursor=1",
        "before=10",
        "limit=1&limit=2",
    ]:
        response = browser.api("GET", path + "?" + query)
        assert response.status_code == 422, response.text
        assert response.json()["error"]["code"] == "validation_failed"


def test_owner_api_pages_counts_names_and_credentials_without_pending_pseudo_enrollments(
    stack,
):
    owner = Browser(stack)
    owner.sign_in(OWNER)
    ids = [new_id() for _ in range(53)]
    with stack.store.database.write() as conn:
        conn.execute(
            insert(s.accounts),
            [
                {
                    "id": key,
                    "status": "pending",
                    "admitted_via": "approval",
                    "created_at": NOW,
                    "updated_at": NOW,
                    "display_name": "Pending",
                }
                for key in ids
            ],
        )
    first = owner.api("GET", "/admin/accounts?status=pending").json()
    assert len(first["accounts"]) == 50 and first["counts"]["pending"] == 53
    second = owner.api(
        "GET", "/admin/accounts?status=pending&cursor=" + first["next_cursor"]
    ).json()
    assert len(second["accounts"]) == 3 and second["next_cursor"] is None
    assert len({row["id"] for row in first["accounts"] + second["accounts"]}) == 53
    enrollments = owner.api("GET", "/admin/enrollments").json()
    assert enrollments["counts"]["pending"] == 53 and enrollments["rows"] == []
    foreign = owner.api("GET", "/admin/enrollments?cursor=" + first["next_cursor"])
    assert foreign.status_code == 422
    guest = Browser(stack)
    guest.sign_in(ALICE)
    assert (
        guest.api("GET", "/admin/accounts?cursor=" + first["next_cursor"]).status_code
        == 403
    )


def test_operator_lists_past_200_and_counts_without_loading_all_records(stores, capsys):  # noqa: F811
    from canvas_mcp.core.selfhost.token_admin import _build_parser, _run

    one, _, _ = stores
    first = account(one, "operator-list")
    put(one, first)
    ids = [new_id() for _ in range(202)]
    with one.database.write() as conn:
        conn.execute(
            insert(s.accounts),
            [
                {
                    "id": key,
                    "status": "pending",
                    "admitted_via": "approval",
                    "created_at": NOW,
                    "updated_at": NOW,
                    "display_name": "Pending",
                }
                for key in ids
            ],
        )
    parser = _build_parser()
    assert _run(parser.parse_args(["accounts"]), one) == 0
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 203 and len({line.split("\t")[0] for line in lines}) == 203
    statements = []

    def record(_conn, _cursor, statement, _parameters, _context, _many):
        statements.append(statement.lower())

    event.listen(one.database.engine, "before_cursor_execute", record)
    try:
        assert _run(parser.parse_args(["check"]), one) == 0
    finally:
        event.remove(one.database.engine, "before_cursor_execute", record)
    output = capsys.readouterr().out
    assert "rows: 1" in output and "accounts: 203 (active 1, pending 202" in output
    assert not any("select accounts.id," in query for query in statements)
    assert not any("select canvas_credentials.id," in query for query in statements)
    # History prints its continuation separately from the tab-separated rows.
    assert _run(parser.parse_args(["history", "--limit", "1"]), one) == 0
    result = capsys.readouterr()
    assert len(result.out.splitlines()) == 1
    cursor = result.err.removeprefix("next_cursor: ").strip()
    assert cursor and cursor != "1"
    assert (
        _run(parser.parse_args(["history", "--limit", "1", "--cursor", cursor]), one)
        == 0
    )
    assert len(capsys.readouterr().out.splitlines()) == 1
    assert _run(parser.parse_args(["history", "--limit", "201"]), one) == 2


@pytest.mark.parametrize(
    "form", ["acct", "entra", "google", "github", "oidc", "uppercase"]
)
def test_operator_requires_canonical_account_ids_and_does_not_preblock_identities(
    stores,  # noqa: F811
    capsys,
    form,
):  # noqa: F811
    from canvas_mcp.core.selfhost.token_admin import _build_parser, _run

    one, _, _ = stores
    key = account(one, "operator-target")
    invalid = {
        "acct": "acct:" + key,
        "entra": "entra:" + key + ":" + key,
        "google": "google:123",
        "github": "github:123",
        "oidc": "oidc:campus:123",
        "uppercase": "AAAAAAAA-0000-4000-8000-000000000001",
    }[form]
    parser = _build_parser()
    assert _run(parser.parse_args(["disable", invalid]), one) == 2
    assert "canonical bare UUID" in capsys.readouterr().err
    assert one.account_counts()["total"] == 1
    assert one.get_principal_status(key).active
    missing = new_id()
    assert _run(parser.parse_args(["disable", missing]), one) == 1
    assert one.account_counts()["total"] == 1
    assert _run(parser.parse_args(["disable", key]), one) == 0
    assert one.get_principal_status(key).disabled
    with pytest.raises(SystemExit):
        parser.parse_args(["revoke", key])


def test_operator_can_read_retained_audit_after_account_deletion(stores, capsys):  # noqa: F811
    from canvas_mcp.core.selfhost.token_admin import _build_parser, _run

    one, _, _ = stores
    key = account(one, "deleted-history")
    assert one.delete_account(key)
    assert _run(_build_parser().parse_args(["history", key]), one) == 0
    assert "account_deleted" in capsys.readouterr().out
