"""Actual v1 stores: ownership, lifecycle, custody, named rows and protocol state."""

import base64
from concurrent.futures import ThreadPoolExecutor
from dataclasses import FrozenInstanceError
from threading import Barrier
from time import perf_counter
from uuid import UUID

import pytest
from dbbackend import IS_POSTGRES, make_store
from sqlalchemy import select, update

from canvas_mcp.core.selfhost.authz import tokens
from canvas_mcp.core.selfhost.authz.models import ExchangeOutcome, RotateOutcome
from canvas_mcp.core.selfhost.authz.store import AuthzStore
from canvas_mcp.core.selfhost.authz.transactions import SqlLoginStateStore
from canvas_mcp.core.selfhost.custody import CustodyAcknowledgement
from canvas_mcp.core.selfhost.db import schema as s
from canvas_mcp.core.selfhost.db.repos import Repositories
from canvas_mcp.core.selfhost.db.types import new_id
from canvas_mcp.core.selfhost.token_store import (
    OPERATOR,
    Keyring,
    TokenDecryptionError,
    credential_aad,
)


@pytest.fixture
def stores(tmp_path):
    ring = Keyring.parse("k1:" + base64.b64encode(bytes(32)).decode())
    one = make_store(tmp_path / "store.sqlite3", ring, clock=lambda: 1_800_000_000)
    two = make_store(tmp_path / "store.sqlite3", ring, clock=lambda: 1_800_000_000)
    one.initialize()
    try:
        yield one, two, ring
    finally:
        one.close()
        two.close()


def account(store, subject="one", **overrides):
    return store.create_operator_account(
        provider_id="oidc:school",
        issuer="https://idp.example.edu",
        subject=subject,
        status="active",
        **overrides,
    )


def put(store, key, host="canvas.example.edu", **overrides):
    kwargs = {
        "principal_key": key,
        "api_token": "secret-pat",
        "canvas_user_id": "17",
        "canvas_user_name": "Student",
        "canvas_host": host,
        "custody": CustodyAcknowledgement(1, 1_800_000_000),
    }
    kwargs.update(overrides)
    return store.put(**kwargs)


def test_entity_ids_are_bare_v7_and_repository_results_cannot_be_mutated_or_indexed(
    stores,
):
    one, _, _ = stores
    key = account(one)
    info = put(one, key)
    assert UUID(key).version == UUID(info.credential_id).version == 7
    assert UUID(one.list_identities(key)[0].id).version == 7
    with one.database.read() as conn:
        row = Repositories(one.database.kind).accounts.get(conn, key)
    assert row.id == key and row.status == "active"
    with pytest.raises(FrozenInstanceError):
        row.status = "disabled"
    with pytest.raises(TypeError):
        _ = row[1]
    with pytest.raises(ValueError):
        one.get_principal_status("acct:" + key)


@pytest.mark.parametrize(
    "ack",
    [
        None,
        CustodyAcknowledgement(0, 1_800_000_000),
        CustodyAcknowledgement(2, 1_800_000_000),
        CustodyAcknowledgement(True, 1_800_000_000),
        CustodyAcknowledgement(1, 1_800_000_001),
    ],
)
def test_invalid_custody_never_creates_school_or_credential_or_audit(stores, ack):
    one, _, _ = stores
    key = account(one)
    before = list(one.iter_audit())
    with pytest.raises(ValueError, match="custody"):
        put(one, key, custody=ack)
    assert one.info(key) is None and list(one.iter_audit()) == before
    with one.database.read() as conn:
        assert conn.execute(select(s.canvas_schools)).first() is None


def test_replacement_preserves_same_host_identity_and_switching_host_leaves_one_credential(
    stores,
):
    one, two, _ = stores
    key = account(one)
    first = put(one, key, expires_hint_at=1_900_000_000)
    second = put(two, key, api_token="replacement")
    assert second.credential_id == first.credential_id
    assert (
        second.created_at == first.created_at
        and second.expires_hint_at == first.expires_hint_at
    )
    assert second.credential_generation == 2
    assert one.get(key).api_token == "replacement"
    third = put(one, key, "another.example.edu")
    assert third.credential_id != first.credential_id and third.expires_hint_at is None
    assert one.count() == 1 and two.get(key).canvas_host == "another.example.edu"
    history = one.audit_page(account_id=key).items
    assert sum(row.action == "custody_notice_acknowledged" for row in history) == 3
    with one.database.read() as conn:
        acknowledgement = (
            conn.execute(
                select(s.audit_log).where(
                    s.audit_log.c.action == "custody_notice_acknowledged"
                )
            )
            .mappings()
            .first()
        )
        assert acknowledgement["target_kind"] == "credential"
        assert acknowledgement["subject_account_id"] == key


def test_generation_survives_deletion_and_health_guards_refuse_replaced_versions(
    stores,
):
    one, two, _ = stores
    key = account(one)
    first = put(one, key)
    put(two, key, api_token="replacement")
    assert not one.mark_invalid(
        key,
        reason="canvas_token_rejected",
        expected_generation=first.credential_generation,
    )
    assert two.get(key).status == "active"
    current = one.info(key)
    assert one.mark_invalid(
        key,
        reason="canvas_token_rejected",
        expected_generation=current.credential_generation,
    )
    assert two.get(key).credential_generation == 3
    assert one.restore_active(key, expected_generation=3)
    assert two.get(key).credential_generation == 4
    one.disable_principal(key, actor=OPERATOR, reason="operator_disabled")
    one.enable_principal(key, actor=OPERATOR)
    assert one.info(key).credential_generation == 6
    assert one.delete(key)
    assert two.credential_generation(key) == 7 and two.get(key) is None
    assert put(two, key).credential_generation == 8


def test_seal_rejects_ciphertext_copied_to_another_account(stores):
    one, _, _ = stores
    a, b = account(one, "a"), account(one, "b")
    put(one, a)
    put(one, b, api_token="other-secret")
    with one.database.write() as conn:
        row = Repositories(one.database.kind).credentials.primary(conn, a)
        conn.execute(
            update(s.canvas_credentials)
            .where(s.canvas_credentials.c.account_id == b)
            .values(nonce=row.nonce, ciphertext=row.ciphertext)
        )
    with pytest.raises(TokenDecryptionError):
        one.get(b)


def test_seal_binds_credential_kind_and_rotation_preserves_custody_and_generation(
    stores, tmp_path
):
    one, _, old_ring = stores
    key = account(one)
    first = put(one, key)
    with one.database.read() as conn:
        row = Repositories(one.database.kind).credentials.primary(conn, key)
    with pytest.raises(TokenDecryptionError):
        old_ring.decrypt(
            row.key_id,
            row.nonce,
            row.ciphertext,
            credential_aad(key, row.canvas_host, "oauth", row.key_id),
        )
    rotated_ring = Keyring.parse(
        "k2:"
        + base64.b64encode(b"2" * 32).decode()
        + ",k1:"
        + base64.b64encode(bytes(32)).decode()
    )
    rotated = make_store(
        tmp_path / "store.sqlite3", rotated_ring, clock=lambda: 1_800_000_000
    )
    try:
        rotated.initialize()
        assert rotated.rotate() == 1
        second = rotated.info(key)
        assert second.key_id == "k2" and second.credential_id == first.credential_id
        assert second.credential_generation == first.credential_generation
        assert (second.custody_notice_version, second.custody_ack_at) == (
            1,
            1_800_000_000,
        )
        assert rotated.get(key).api_token == "secret-pat"
    finally:
        rotated.close()


def test_write_tools_are_child_rows_with_account_version_and_cross_instance_visibility(
    stores,
):
    one, two, _ = stores
    key = account(one)
    assert one.get_tool_prefs(key) is None
    first = one.set_tool_prefs(key, ["submit_assignment", "create_planner_note"])
    assert first.version == 1 and two.get_tool_prefs(key).enabled_at == first.enabled_at
    cleared = two.set_tool_prefs(key, [])
    assert (
        cleared.version == 2
        and one.get_tool_prefs(key).enabled_write_tools == frozenset()
    )
    with one.database.read() as conn:
        assert conn.execute(select(s.account_write_tools)).first() is None
        assert (
            Repositories(one.database.kind).accounts.get(conn, key).write_tools_version
            == 2
        )


def test_provider_reconcile_preserves_names_and_bumps_revision_only_on_changes(stores):
    one, two, _ = stores
    account(one)
    one.record_login_providers(["entra", "oidc:school"])
    with one.database.write() as conn:
        conn.execute(
            update(s.login_providers)
            .where(s.login_providers.c.id == "entra")
            .values(display_name="School login")
        )
    with one.database.read() as conn:
        first = conn.execute(select(s.server_state.c.settings_revision)).scalar_one()
    two.record_login_providers(["entra", "oidc:school"])
    with one.database.read() as conn:
        assert (
            conn.execute(select(s.server_state.c.settings_revision)).scalar_one()
            == first
        )
    two.record_login_providers(["oidc:school"])
    assert one.recorded_login_providers() == frozenset({"oidc:school"})
    with one.database.read() as conn:
        row = (
            conn.execute(
                select(s.login_providers).where(s.login_providers.c.id == "entra")
            )
            .mappings()
            .one()
        )
        assert row["display_name"] == "School login" and not row["configured"]


def test_state_pop_has_one_winner_and_requires_the_browser_binding(stores):
    one, two, _ = stores
    first = SqlLoginStateStore(one.database, clock=lambda: 100)
    second = SqlLoginStateStore(two.database, clock=lambda: 100)
    binding = tokens.hash_secret("cookie")
    state = first.put_sync("login", b"payload", 60, binding_hash=binding)
    assert second.pop_sync("login", state) is None
    assert (
        second.pop_sync("login", state, binding_hash=tokens.hash_secret("wrong"))
        is None
    )
    barrier = Barrier(2)

    def pop(store):
        barrier.wait(timeout=3)
        return store.pop_sync("login", state, binding_hash=binding)

    with ThreadPoolExecutor(max_workers=2) as workers:
        pending = [workers.submit(pop, store) for store in (first, second)]
        assert sorted(
            (job.result(timeout=6) for job in pending), key=lambda item: item is None
        ) == [b"payload", None]


def test_authorization_code_refresh_and_revocation_use_named_v1_rows(stores):
    one, two, _ = stores
    key = account(one)
    authz = AuthzStore(one.database, clock=lambda: 1_800_000_000)
    other = AuthzStore(two.database, clock=lambda: 1_800_000_000)
    authz.put_client("client", '{"client_name":"App"}', "App", 1_800_100_000)
    assert other.get_client_record("client").info == {"client_name": "App"}
    code = tokens.hash_secret("code")
    assert authz.create_code(
        code_hash=code,
        client_id="client",
        client_kind="dcr",
        client_name="App",
        client_host=None,
        account_id=key,
        redirect_uri="https://client.example/callback",
        redirect_uri_explicit=True,
        redirect_host="client.example",
        code_challenge="challenge",
        scopes=("Canvas.Access",),
        resource="https://mcp.example/mcp",
        upstream_auth_at=1_800_000_000,
        session_epoch=0,
    )
    grant_id = new_id()
    first_hash, next_hash = tokens.hash_secret("first"), tokens.hash_secret("next")
    exchanged = other.exchange_code(
        code_hash=code, client_id="client", grant_id=grant_id, refresh_hash=first_hash
    )
    assert (
        exchanged.outcome == ExchangeOutcome.WON and exchanged.grant.account_key == key
    )
    view = authz.load_refresh(first_hash)
    assert view.expires_at == exchanged.grant.expires_at
    rotated = authz.rotate_refresh(token_hash=first_hash, new_hash=next_hash)
    assert rotated.outcome == RotateOutcome.ROTATED
    assert other.grant_status(grant_id).usable(1_800_000_000)
    assert other.revoke_own_grant(grant_id, key)
    assert not authz.grant_status(grant_id).usable(1_800_000_000)
    assert (
        authz.rotate_refresh(
            token_hash=next_hash, new_hash=tokens.hash_secret("third")
        ).outcome
        == RotateOutcome.DEAD
    )


@pytest.mark.skipif(not IS_POSTGRES, reason="real PostgreSQL row locks")
def test_touch_skips_a_held_credential_row_instead_of_waiting(stores):
    one, two, _ = stores
    key = account(one)
    info = put(one, key)
    with one.database.row_write() as conn:
        conn.execute(
            select(s.canvas_credentials.c.id)
            .where(s.canvas_credentials.c.id == info.credential_id)
            .with_for_update(key_share=True)
        ).one()
        began = perf_counter()
        two.touch(key)
        assert perf_counter() - began < 1
    assert one.info(key).last_used_at is None
    two.touch(key)
    assert one.info(key).last_used_at == 1_800_000_000
