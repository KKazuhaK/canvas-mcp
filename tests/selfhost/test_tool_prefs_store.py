"""The per-user write-tool preferences in the token database."""

from __future__ import annotations

import pathlib

import pytest
from dbbackend import make_store, raw_connection
from sqlalchemy import inspect

from canvas_mcp.core.selfhost.token_store import SCHEMA_VERSION, TokenStore

from .test_token_store import OID_A, OID_B, TID, Clock, _put, _ring

PK_A = f"entra:{TID}:{OID_A}"
PK_B = f"entra:{TID}:{OID_B}"


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: pathlib.Path, clock: Clock) -> TokenStore:
    s = make_store(tmp_path / "data" / "tokens.sqlite3", _ring(("k1", 1)), clock=clock)
    s.initialize()
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
        assert got.updated_via == "account_web"

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
        store.set_tool_prefs(PK_A, [], via="operator")
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


class TestFailClosed:
    def _corrupt(self, store: TokenStore, tmp_path: pathlib.Path, names: str, at: str) -> None:
        store.set_tool_prefs(PK_A, ["send_message"])
        with raw_connection(store) as conn:
            conn.execute(
                "UPDATE user_tool_prefs SET enabled_write_tools = ?, enabled_at = ?",
                (names, at),
            )

    @pytest.mark.parametrize("names", ["not json", '{"a": 1}', '"send_message"', '["Bad Name"]', "[1]"])
    def test_an_unreadable_record_enables_nothing(
        self, store: TokenStore, tmp_path: pathlib.Path, names: str
    ) -> None:
        self._corrupt(store, tmp_path, names, "{}")
        got = store.get_tool_prefs(PK_A)
        assert got is not None and got.enabled_write_tools == frozenset()

    def test_a_damaged_time_map_never_adds_names(self, store: TokenStore, tmp_path: pathlib.Path) -> None:
        self._corrupt(store, tmp_path, '["send_message"]', '{"send_message": "x", "ghost": 5}')
        got = store.get_tool_prefs(PK_A)
        assert got is not None
        assert got.enabled_write_tools == {"send_message"}
        assert got.enabled_at == {}


class TestMigration:
    def test_a_fresh_database_has_the_table_and_the_same_schema_version(
        self, store: TokenStore, tmp_path: pathlib.Path
    ) -> None:
        assert "user_tool_prefs" in _tables(store)
        # The table was added without a version change; version 3 added the access
        # tables, and this table must still be there.
        assert SCHEMA_VERSION == 4

    @pytest.mark.sqlite_only

    def test_opening_a_database_without_the_table_adds_it_and_keeps_the_rows(
        self, tmp_path: pathlib.Path, clock: Clock
    ) -> None:
        path = tmp_path / "data" / "tokens.sqlite3"
        first = make_store(path, _ring(("k1", 1)), clock=clock)
        first.initialize()
        _put(first, canvas_host="canvas.example.edu")
        with raw_connection(first) as conn:
            conn.execute("DROP TABLE user_tool_prefs")
        assert "user_tool_prefs" not in _tables(first)

        reopened = make_store(path, _ring(("k1", 1)), clock=clock)
        reopened.initialize()
        assert "user_tool_prefs" in _tables(reopened)
        assert reopened.count() == 1
        assert reopened.get_tool_prefs(PK_A) is None

    def test_opening_twice_keeps_the_saved_switches(
        self, store: TokenStore, tmp_path: pathlib.Path, clock: Clock
    ) -> None:
        store.set_tool_prefs(PK_A, ["send_message"])
        again = make_store(tmp_path / "data" / "tokens.sqlite3", _ring(("k1", 1)), clock=clock)
        again.initialize()
        again.initialize()
        got = again.get_tool_prefs(PK_A)
        assert got is not None and got.enabled_write_tools == {"send_message"}
