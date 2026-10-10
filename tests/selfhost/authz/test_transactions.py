"""Pending authorizations and the database-backed login-state store."""

from __future__ import annotations

import asyncio
import json

import pytest
from dbbackend import raw_sql

from canvas_mcp.core.selfhost.authz import transactions as tx
from canvas_mcp.core.selfhost.login_state import (
    InMemoryLoginStateStore,
    LoginStateStore,
)

from .helpers import CHALLENGE, CLIENT, REDIRECT, RESOURCE, SCOPE, Env, make_env


@pytest.fixture
def env(tmp_path, keyring, clock) -> Env:
    return make_env(tmp_path, keyring, clock)


@pytest.fixture
def store(env: Env, clock) -> tx.SqlLoginStateStore:
    return tx.SqlLoginStateStore(env.tokens.database, clock=clock)


def pending(**overrides) -> tx.PendingAuthorization:
    fields = {
        "client_id": CLIENT, "client_kind": "dcr", "redirect_uri": REDIRECT,
        "redirect_uri_explicit": True, "code_challenge": CHALLENGE, "scopes": (SCOPE,),
        "state": "st-1", "resource": RESOURCE, "created_at": 1_800_000_000,
    }
    fields.update(overrides)
    return tx.PendingAuthorization(**fields)


class TestBindingHelpers:
    def test_a_binding_is_43_url_safe_characters(self) -> None:
        value = tx.new_binding()
        assert tx.binding_ok(value) and tx.txn_id_ok(value)
        assert len({tx.new_binding() for _ in range(100)}) == 100

    @pytest.mark.parametrize("bad", ["", "short", "A" * 42, "A" * 44, "A" * 42 + "=", "A" * 42 + " ", None, 5])
    def test_other_shapes_are_refused(self, bad) -> None:
        assert not tx.binding_ok(bad)

    def test_the_hash_is_stable_hex_and_differs_per_value(self) -> None:
        a, b = tx.new_binding(), tx.new_binding()
        assert tx.binding_hash(a) == tx.binding_hash(a) != tx.binding_hash(b)
        assert len(tx.binding_hash(a)) == 64 and a not in tx.binding_hash(a)

    def test_the_cookie_name_uses_the_host_prefix(self) -> None:
        assert tx.BINDING_COOKIE == "__Host-cmcp_bind" and tx.TXN_TTL_S == 600 and tx.TXN_KIND == "mcp_txn"


class TestPendingAuthorization:
    def test_it_round_trips(self) -> None:
        original = pending(scopes=("a", "b"), state=None, redirect_uri_explicit=False)
        assert tx.PendingAuthorization.from_json(original.to_json()) == original

    def test_the_payload_stays_under_the_store_limit(self) -> None:
        raw = pending(state="s" * tx.MAX_STATE_CHARS, redirect_uri="https://e.test/" + "p" * 2000).to_json()
        assert len(raw) <= tx.MAX_PAYLOAD_BYTES

    @pytest.mark.parametrize(
        "overrides",
        [
            {"client_id": ""},
            {"client_id": "c" * 513},
            {"redirect_uri": "u" * 2049},
            {"state": "s" * 1025},
            {"scopes": ()},
            {"scopes": ("s",) * 9},
            {"scopes": ("s" * 65,)},
            {"resource": ""},
            {"resource": "r" * 513},
        ],
    )
    def test_out_of_bounds_values_are_refused(self, overrides) -> None:
        with pytest.raises(ValueError):
            pending(**overrides).to_json()

    @pytest.mark.parametrize(
        "mutate",
        [
            lambda d: d.update(v=2),
            lambda d: d.pop("client_id"),
            lambda d: d.update(scopes="a b"),
            lambda d: d.update(scopes=[1]),
            lambda d: d.update(state=5),
            lambda d: d.update(explicit="yes"),
            lambda d: d.update(created_at=True),
            lambda d: d.update(created_at="1"),
            lambda d: d.update(client_id=5),
            lambda d: d.update(redirect_uri="x" * 3000),
        ],
    )
    def test_a_stored_payload_that_was_tampered_with_is_refused(self, mutate) -> None:
        data = json.loads(pending().to_json())
        mutate(data)
        with pytest.raises(ValueError):
            tx.PendingAuthorization.from_json(json.dumps(data))

    @pytest.mark.parametrize("raw", [b"", b"nope", b"[]", b"null", b"\xff\xfe", "{"])
    def test_garbage_is_refused(self, raw) -> None:
        with pytest.raises(ValueError):
            tx.PendingAuthorization.from_json(raw)


class TestSqlLoginStateStore:
    def test_it_satisfies_the_protocol(self, store: tx.SqlLoginStateStore) -> None:
        checked: LoginStateStore = store
        assert checked is store

    async def test_a_payload_is_returned_exactly_once(self, store) -> None:
        state_id = await store.put("mcp_txn", b'{"x":1}', 60)
        assert tx.txn_id_ok(state_id)
        assert await store.pop("mcp_txn", state_id) == b'{"x":1}'
        assert await store.pop("mcp_txn", state_id) is None

    async def test_only_hashes_are_stored(self, store, env: Env) -> None:
        binding = tx.binding_hash(tx.new_binding())
        state_id = await store.put("mcp_txn", b'{"secret":"payload"}', 60, binding_hash=binding)
        rows = raw_sql(env.tokens, "SELECT kind, id_hash, binding_hash FROM login_states")
        assert rows == [("mcp_txn", __import__("hashlib").sha256(state_id.encode()).hexdigest(), binding)]
        assert state_id not in str(rows)

    async def test_missing_wrong_kind_and_malformed_ids_look_the_same(self, store) -> None:
        state_id = await store.put("mcp_txn", b"x", 60)
        assert await store.pop("other", state_id) is None
        assert await store.pop("mcp_txn", "never-issued") is None
        assert await store.pop("mcp_txn", "A" * 43) is None
        assert await store.peek("mcp_txn", "x" * 5000) is None
        assert await store.pop("mcp_txn", state_id) == b"x"

    async def test_expiry(self, store, clock) -> None:
        state_id = await store.put("mcp_txn", b"x", 30)
        clock.advance(29)
        assert await store.peek("mcp_txn", state_id) == b"x"
        clock.advance(2)
        assert await store.peek("mcp_txn", state_id) is None
        assert await store.pop("mcp_txn", state_id) is None

    async def test_binding_rules_match_the_in_memory_store(self, store) -> None:
        memory = InMemoryLoginStateStore()
        for impl in (store, memory):
            sid = await impl.put("mcp_txn", b"payload", 60, binding_hash="h1")
            assert await impl.pop("mcp_txn", sid) is None
            assert await impl.pop("mcp_txn", sid, binding_hash="h2") is None
            assert await impl.peek("mcp_txn", sid, binding_hash="h2") is None
            assert await impl.peek("mcp_txn", sid, binding_hash="h1") == b"payload"
            assert await impl.pop("mcp_txn", sid, binding_hash="h1") == b"payload"
            assert await impl.pop("mcp_txn", sid, binding_hash="h1") is None
            plain = await impl.put("oidc", b"y", 60)
            assert await impl.pop("oidc", plain, binding_hash="h1") is None
            assert await impl.pop("oidc", plain) == b"y"

    async def test_a_refused_pop_leaves_the_state_for_its_holder(self, store) -> None:
        sid = await store.put("mcp_txn", b"payload", 60, binding_hash="h1")
        for _ in range(3):
            assert await store.pop("mcp_txn", sid, binding_hash="wrong") is None
        assert await store.pop("mcp_txn", sid, binding_hash="h1") == b"payload"

    @pytest.mark.parametrize(
        ("kind", "payload", "ttl"),
        [("", b"x", 10), ("k", b"x", 0), ("k", b"x", -1), ("k", b"x", 10_000), ("k", b"x" * 5000, 10), ("k", b"\xff", 10)],
    )
    async def test_invalid_input_is_refused(self, store, kind, payload, ttl) -> None:
        with pytest.raises(ValueError):
            await store.put(kind, payload, ttl)

    async def test_concurrent_pops_hand_the_payload_to_one_caller(self, store) -> None:
        sid = await store.put("mcp_txn", b"secret", 60, binding_hash="h1")
        results = await asyncio.gather(*(store.pop("mcp_txn", sid, binding_hash="h1") for _ in range(12)))
        assert results.count(b"secret") == 1 and results.count(None) == 11
