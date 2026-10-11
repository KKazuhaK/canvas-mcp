"""The per-user write-tool preferences in the token database."""

from __future__ import annotations

import pathlib

import pytest
from dbbackend import make_store
from sqlalchemy import inspect

from canvas_mcp.core.selfhost.token_store import TokenStore

from .conftest import acct_key, make_account
from .test_token_store import OID_A, OID_B, Clock, _put, _ring

PK_A = acct_key(OID_A)
PK_B = acct_key(OID_B)


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: pathlib.Path, clock: Clock) -> TokenStore:
    s = make_store(tmp_path / "data" / "tokens.sqlite3", _ring(("k1", 1)), clock=clock)
    s.initialize()
    make_account(s, OID_A)
    make_account(s, OID_B)
    return s


def _tables(store: TokenStore) -> set[str]:
    return set(inspect(store.database.engine).get_table_names())


class TestDefaultsAndRoundTrip:
    def test_nothing_is_stored_for_a_new_user(self, store: TokenStore) -> None:
        assert store.get_tool_prefs(PK_A) is None

    def test_explicit_names_round_trip(self, store: TokenStore, clock: Clock) -> None:
        saved = store.set_tool_prefs(PK_A, ["send_message", "submit_assignment"])
        got = store.get_tool_prefs(PK_A)
        assert got == saved
        assert got is not None
        assert got.principal_key == PK_A
        assert got.enabled_write_tools == {"send_message", "submit_assignment"}
        assert got.enabled_at == {"send_message": int(clock.now), "submit_assignment": int(clock.now)}
        assert got.updated_at == int(clock.now)
        assert got.updated_via == "api"

    def test_users_are_independent(self, store: TokenStore) -> None:
        store.set_tool_prefs(PK_A, ["send_message"])
        assert store.get_tool_prefs(PK_B) is None
        store.set_tool_prefs(PK_B, ["submit_assignment"])
        a = store.get_tool_prefs(PK_A)
        assert a is not None and a.enabled_write_tools == {"send_message"}

    def test_a_name_that_stays_on_keeps_its_enabled_time(self, store: TokenStore, clock: Clock) -> None:
        first = int(clock.now)
        store.set_tool_prefs(PK_A, ["send_message"])
        clock.now += 500
        store.set_tool_prefs(PK_A, ["send_message", "submit_assignment"])
        got = store.get_tool_prefs(PK_A)
        assert got is not None
        assert got.enabled_at == {"send_message": first, "submit_assignment": first + 500}
        assert got.updated_at == first + 500

    def test_turning_a_tool_off_and_on_again_restarts_its_time(
        self, store: TokenStore, clock: Clock
    ) -> None:
        store.set_tool_prefs(PK_A, ["send_message"])
        store.set_tool_prefs(PK_A, [])
        clock.now += 90
        store.set_tool_prefs(PK_A, ["send_message"])
        got = store.get_tool_prefs(PK_A)
        assert got is not None and got.enabled_at == {"send_message": int(clock.now)}

    def test_an_empty_set_is_stored_as_nothing_enabled(self, store: TokenStore) -> None:
        store.set_tool_prefs(PK_A, ["send_message"])
        store.set_tool_prefs(PK_A, [])
        got = store.get_tool_prefs(PK_A)
        assert got is not None and got.enabled_write_tools == frozenset()

    def test_names_that_are_not_known_to_the_server_are_kept_verbatim(self, store: TokenStore) -> None:
        # Unknown or no-longer-allowed names are ignored when the effective set is
        # worked out, but the record keeps them.
        store.set_tool_prefs(PK_A, ["a_tool_removed_later"])
        got = store.get_tool_prefs(PK_A)
        assert got is not None and got.enabled_write_tools == {"a_tool_removed_later"}

    def test_there_is_no_all_option(self, store: TokenStore) -> None:
        for bad in ("*", "ALL", "all tools", "send message", "send-message", ""):
            with pytest.raises(ValueError):
                store.set_tool_prefs(PK_A, [bad])
        # "all" is a well-formed name, and only ever means a tool called "all".
        store.set_tool_prefs(PK_A, ["all"])
        got = store.get_tool_prefs(PK_A)
        assert got is not None and got.enabled_write_tools == {"all"}


class TestValidation:
    @pytest.mark.parametrize("bad", ["", "Send", "1abc", "a b", "a-b", "x" * 65, "é", "a;b", "a\n"])
    def test_malformed_names_are_refused_and_nothing_changes(self, store: TokenStore, bad: str) -> None:
        store.set_tool_prefs(PK_A, ["send_message"])
        with pytest.raises(ValueError):
            store.set_tool_prefs(PK_A, ["submit_assignment", bad])
        got = store.get_tool_prefs(PK_A)
        assert got is not None and got.enabled_write_tools == {"send_message"}

    def test_non_strings_are_refused(self, store: TokenStore) -> None:
        with pytest.raises(ValueError):
            store.set_tool_prefs(PK_A, [None])  # type: ignore[list-item]

    def test_too_many_names_are_refused(self, store: TokenStore) -> None:
        with pytest.raises(ValueError):
            store.set_tool_prefs(PK_A, [f"tool_{i}" for i in range(300)])

    @pytest.mark.parametrize("key", ["", "Entra:x", "entra:not-a-guid", "a" * 300, "a b\x00"])
    def test_a_bad_principal_key_is_refused(self, store: TokenStore, key: str) -> None:
        with pytest.raises(ValueError):
            store.set_tool_prefs(key, ["send_message"])
        with pytest.raises(ValueError):
            store.get_tool_prefs(key)

    def test_via_is_a_short_ascii_label(self, store: TokenStore) -> None:
        for bad in ("", "x" * 33, "é"):
            with pytest.raises(ValueError):
                store.set_tool_prefs(PK_A, [], via=bad)
        store.set_tool_prefs(PK_A, ["send_message"], via="operator")
        got = store.get_tool_prefs(PK_A)
        assert got is not None and got.updated_via == "operator"


class TestIndependenceFromTheToken:
    def test_replacing_a_token_keeps_the_switches(self, store: TokenStore) -> None:
        _put(store, canvas_host="canvas.example.edu")
        store.set_tool_prefs(PK_A, ["send_message"])
        _put(store, canvas_host="canvas.example.edu", api_token="a-new-canvas-token-0123456789")
        got = store.get_tool_prefs(PK_A)
        assert got is not None and got.enabled_write_tools == {"send_message"}

    def test_deleting_the_token_keeps_the_switches(self, store: TokenStore) -> None:
        _put(store, canvas_host="canvas.example.edu")
        store.set_tool_prefs(PK_A, ["send_message"])
        assert store.delete(PK_A) is True
        got = store.get_tool_prefs(PK_A)
        assert got is not None and got.enabled_write_tools == {"send_message"}

    def test_switches_can_exist_before_a_token_does(self, store: TokenStore) -> None:
        store.set_tool_prefs(PK_A, ["send_message"])
        assert store.info(PK_A) is None
        assert store.count() == 0


class TestNativeRows:
    def test_each_enabled_tool_is_one_native_row(self, store: TokenStore, clock: Clock) -> None:
        from sqlalchemy import select

        from canvas_mcp.core.selfhost.db import schema
        store.set_tool_prefs(PK_A, ["send_message", "submit_assignment"])
        with store.database.read() as conn:
            rows = conn.execute(select(schema.account_write_tools).order_by(schema.account_write_tools.c.tool_name)).mappings().all()
        assert [(r["account_id"], r["tool_name"], r["enabled_at"], r["enabled_via"]) for r in rows] == [
            (PK_A, "send_message", int(clock.now), "api"),
            (PK_A, "submit_assignment", int(clock.now), "api"),
        ]

    @pytest.mark.parametrize("values", [{"tool_name": ""}, {"enabled_at": "not-an-epoch"}])
    def test_database_rejects_malformed_native_values(self, store: TokenStore, values) -> None:
        from sqlalchemy import update
        from sqlalchemy.exc import DBAPIError

        from canvas_mcp.core.selfhost.db import schema
        store.set_tool_prefs(PK_A, ["send_message"])
        with pytest.raises(DBAPIError):
            with store.database.engine.begin() as conn:
                conn.execute(update(schema.account_write_tools).values(**values))
        assert store.get_tool_prefs(PK_A).enabled_write_tools == {"send_message"}


class TestInitialization:
    def test_a_fresh_database_uses_native_rows(self, store: TokenStore) -> None:
        assert "account_write_tools" in _tables(store)
        assert "user_tool_prefs" not in _tables(store)


    def test_opening_twice_keeps_the_saved_switches(
        self, store: TokenStore, tmp_path: pathlib.Path, clock: Clock
    ) -> None:
        store.set_tool_prefs(PK_A, ["send_message"])
        again = make_store(tmp_path / "data" / "tokens.sqlite3", _ring(("k1", 1)), clock=clock)
        again.initialize()
        again.initialize()
        got = again.get_tool_prefs(PK_A)
        assert got is not None and got.enabled_write_tools == {"send_message"}
