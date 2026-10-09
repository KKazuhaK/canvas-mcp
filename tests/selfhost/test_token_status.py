"""State transitions of a stored Canvas token: active, invalid, restored."""

from __future__ import annotations

import pathlib

import pytest

from canvas_mcp.core.selfhost.token_store import (
    INVALID_REASONS,
    KEEP_EXPIRY_HINT,
    REASON_CANVAS_TOKEN_REJECTED,
    REASON_DECRYPT_FAILED,
    REASON_REVOKED_BY_ADMIN,
    STATUS_ACTIVE,
    STATUS_INVALID,
    StoreUnavailable,
    TokenStore,
)

from .test_token_store import OID_A, OID_B, TID, TOKEN_A, TOKEN_B, Clock, _put, _ring

PK_A = f"entra:{TID}:{OID_A}"


@pytest.fixture
def clock() -> Clock:
    return Clock()


@pytest.fixture
def store(tmp_path: pathlib.Path, clock: Clock) -> TokenStore:
    s = TokenStore(tmp_path / "data" / "tokens.sqlite3", _ring(("k1", 1)), clock=clock)
    s.initialize()
    return s


class TestMarkInvalid:
    def test_marks_an_active_row_and_keeps_the_token(self, store: TokenStore, clock: Clock) -> None:
        _put(store, canvas_host="canvas.example.edu")
        clock.now += 10
        assert store.mark_invalid(PK_A, reason=REASON_CANVAS_TOKEN_REJECTED) is True
        info = store.info(PK_A)
        assert info is not None
        assert info.status == STATUS_INVALID
        assert info.invalid_reason == REASON_CANVAS_TOKEN_REJECTED
        assert info.invalid_since == int(clock.now)
        # The ciphertext stays, so a successful re-check can restore the same token.
        got = store.get(PK_A)
        assert got is not None and got.api_token == TOKEN_A and got.status == STATUS_INVALID

    def test_the_first_reason_wins(self, store: TokenStore, clock: Clock) -> None:
        _put(store, canvas_host="canvas.example.edu")
        assert store.mark_invalid(PK_A, reason=REASON_CANVAS_TOKEN_REJECTED) is True
        clock.now += 60
        assert store.mark_invalid(PK_A, reason=REASON_REVOKED_BY_ADMIN) is False
        info = store.info(PK_A)
        assert info is not None and info.invalid_reason == REASON_CANVAS_TOKEN_REJECTED

    def test_an_unknown_reason_is_refused(self, store: TokenStore) -> None:
        _put(store, canvas_host="canvas.example.edu")
        with pytest.raises(ValueError):
            store.mark_invalid(PK_A, reason="because")
        assert INVALID_REASONS == {
            "canvas_token_rejected",
            "decrypt_failed",
            "revoked_by_admin",
        }

    def test_a_missing_row_is_not_an_error(self, store: TokenStore) -> None:
        assert store.mark_invalid(PK_A, reason=REASON_DECRYPT_FAILED) is False

    def test_the_adapter_form_names_the_entra_principal(self, store: TokenStore) -> None:
        _put(store, canvas_host="canvas.example.edu")
        assert store.mark_invalid(TID, OID_A, reason=REASON_REVOKED_BY_ADMIN) is True
        info = store.info(TID, OID_A)
        assert info is not None and info.status == STATUS_INVALID

    def test_a_replaced_token_is_not_invalidated_by_the_old_one(
        self, store: TokenStore, clock: Clock
    ) -> None:
        first = _put(store, canvas_host="canvas.example.edu")
        clock.now += 30
        _put(store, token=TOKEN_B, canvas_host="canvas.example.edu")
        # Canvas rejected the first token, but the user has already saved a new one.
        assert (
            store.mark_invalid(
                PK_A, reason=REASON_CANVAS_TOKEN_REJECTED, expected_updated_at=first.updated_at
            )
            is False
        )
        info = store.info(PK_A)
        assert info is not None and info.status == STATUS_ACTIVE

    def test_only_the_named_row_changes(self, store: TokenStore) -> None:
        _put(store, canvas_host="canvas.example.edu")
        _put(store, oid=OID_B, canvas_host="canvas.example.edu")
        store.mark_invalid(PK_A, reason=REASON_REVOKED_BY_ADMIN)
        other = store.info(TID, OID_B)
        assert other is not None and other.status == STATUS_ACTIVE


class TestRestoreAndResave:
    def test_restore_active_clears_the_mark(self, store: TokenStore, clock: Clock) -> None:
        _put(store, canvas_host="canvas.example.edu")
        store.mark_invalid(PK_A, reason=REASON_CANVAS_TOKEN_REJECTED)
        clock.now += 90
        assert store.restore_active(PK_A) is True
        info = store.info(PK_A)
        assert info is not None
        assert (info.status, info.invalid_reason, info.invalid_since) == (STATUS_ACTIVE, None, None)
        assert info.last_verified_at == int(clock.now)
        assert store.restore_active(PK_A) is False  # nothing left to restore

    def test_restore_respects_a_replaced_token(self, store: TokenStore, clock: Clock) -> None:
        first = _put(store, canvas_host="canvas.example.edu")
        store.mark_invalid(PK_A, reason=REASON_CANVAS_TOKEN_REJECTED)
        clock.now += 30
        _put(store, token=TOKEN_B, canvas_host="canvas.example.edu")
        assert store.restore_active(PK_A, expected_updated_at=first.updated_at) is False

    def test_saving_a_new_token_restores_an_invalid_row(self, store: TokenStore, clock: Clock) -> None:
        _put(store, canvas_host="canvas.example.edu")
        store.mark_invalid(PK_A, reason=REASON_REVOKED_BY_ADMIN)
        clock.now += 5
        _put(store, token=TOKEN_B, canvas_host="canvas.example.edu")
        info = store.info(PK_A)
        assert info is not None
        assert (info.status, info.invalid_reason, info.invalid_since) == (STATUS_ACTIVE, None, None)
        got = store.get(PK_A)
        assert got is not None and got.api_token == TOKEN_B


class TestVerifiedAndHint:
    def test_mark_verified_is_rate_limited(self, store: TokenStore, clock: Clock) -> None:
        _put(store, canvas_host="canvas.example.edu")
        first = int(clock.now)
        clock.now += 100
        store.mark_verified(PK_A, min_interval_seconds=600)
        info = store.info(PK_A)
        assert info is not None and info.last_verified_at == first  # too soon, no write
        clock.now += 600
        store.mark_verified(PK_A, min_interval_seconds=600)
        info = store.info(PK_A)
        assert info is not None and info.last_verified_at == int(clock.now)

    def test_mark_verified_never_touches_an_invalid_row(self, store: TokenStore, clock: Clock) -> None:
        _put(store, canvas_host="canvas.example.edu")
        store.mark_invalid(PK_A, reason=REASON_CANVAS_TOKEN_REJECTED)
        before = store.info(PK_A)
        clock.now += 5000
        store.mark_verified(PK_A, min_interval_seconds=1)
        assert store.info(PK_A) == before

    def test_mark_verified_never_raises(
        self, store: TokenStore, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        store.mark_verified("Not A Lower-Case Key")  # refused key

        def broken(**_: object) -> None:
            raise StoreUnavailable("the token database is unavailable", "OperationalError")

        monkeypatch.setattr(store._db, "best_effort_write", broken)
        store.mark_verified(PK_A)

    def test_the_expiry_hint_is_stored_replaced_cleared_or_kept(self, store: TokenStore) -> None:
        info = _put(store, canvas_host="canvas.example.edu", expires_hint_at=1_900_000_000)
        assert info.expires_hint_at == 1_900_000_000
        again = _put(store, canvas_host="canvas.example.edu")  # left out: kept
        assert again.expires_hint_at == 1_900_000_000
        newer = _put(store, canvas_host="canvas.example.edu", expires_hint_at=1_950_000_000)
        assert newer.expires_hint_at == 1_950_000_000
        cleared = _put(store, canvas_host="canvas.example.edu", expires_hint_at=None)
        assert cleared.expires_hint_at is None
        assert KEEP_EXPIRY_HINT is not None

    @pytest.mark.parametrize("bad", [0, -5, 10**12, True])
    def test_a_bad_hint_is_refused(self, store: TokenStore, bad: object) -> None:
        with pytest.raises(ValueError):
            _put(store, canvas_host="canvas.example.edu", expires_hint_at=bad)

    def test_status_columns_come_back_on_list_and_info(self, store: TokenStore) -> None:
        _put(store, canvas_host="canvas.example.edu")
        _put(store, oid=OID_B, canvas_host="canvas.example.edu")
        store.mark_invalid(PK_A, reason=REASON_REVOKED_BY_ADMIN)
        listed = {row.object_id: row for row in store.list_enrollments()}
        assert listed[OID_A].status == STATUS_INVALID
        assert listed[OID_B].status == STATUS_ACTIVE
