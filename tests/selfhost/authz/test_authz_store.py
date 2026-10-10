"""The transactions of the authorization server on one connection: every state machine step."""

from __future__ import annotations

import dataclasses

import pytest
from dbbackend import raw_sql

from canvas_mcp.core.selfhost.authz import tokens as tk
from canvas_mcp.core.selfhost.authz.models import (
    ExchangeOutcome as X,
)
from canvas_mcp.core.selfhost.authz.models import (
    RotateOutcome as R,
)
from canvas_mcp.core.selfhost.settings import AuthzSettings
from canvas_mcp.core.selfhost.token_store import OPERATOR, AccessActionRefused

from ..conftest import OID_B, make_account
from .helpers import CLIENT, Env, make_env


@pytest.fixture
def env(tmp_path, keyring, clock) -> Env:
    return make_env(tmp_path, keyring, clock)


def rows(env: Env, sql: str, **params):
    return raw_sql(env.tokens, sql, params)


def refresh_row(env: Env, raw: str):
    return rows(
        env,
        "SELECT used_at, replaced_by, parent_hash, expires_at, grace_replays "
        "FROM oauth_refresh_tokens WHERE token_hash = :h",
        h=tk.hash_secret(raw),
    )[0]


class TestCodes:
    def test_a_code_for_an_active_account_is_stored_hashed(self, env: Env) -> None:
        raw = env.new_code()
        stored = rows(env, "SELECT code_hash, expires_at, created_at FROM oauth_codes")
        assert len(stored) == 1 and stored[0][0] == tk.hash_secret(raw) and raw not in stored[0][0]
        assert stored[0][1] - stored[0][2] == 300
        record = env.authz.load_code(tk.hash_secret(raw))
        assert record is not None and record.consumed_at is None and record.scopes == ("Canvas.Access",)

    @pytest.mark.parametrize("status", ["pending", "disabled"])
    def test_no_code_for_an_account_that_is_not_active(self, env: Env, status: str) -> None:
        other = make_account(env.tokens, OID_B, status=status)
        raw = tk.new_auth_code()
        ok = env.authz.create_code(
            code_hash=tk.hash_secret(raw), client_id=CLIENT, client_kind="dcr", client_name="",
            client_host=None, account_id=other.removeprefix("acct:"), redirect_uri="https://e.test/cb",
            redirect_uri_explicit=True, redirect_host="e.test", code_challenge="c" * 43,
            scopes=("Canvas.Access",), resource="r", upstream_auth_at=1,
            session_epoch=env.epoch(other.removeprefix("acct:")),
        )
        assert not ok and rows(env, "SELECT COUNT(*) FROM oauth_codes")[0][0] == 0

    def test_the_consent_is_noted_on_the_oauth_surface_only(self, env: Env) -> None:
        env.new_code()
        events = rows(env, "SELECT surface, reason, outcome FROM auth_events")
        assert events == [("oauth", "consent_granted", "success")]


class TestFirstExchange:
    def test_the_winner_gets_a_grant_and_a_refresh_token(self, env: Env) -> None:
        raw = env.new_code()
        result, refresh, grant_id = env.exchange(raw)
        assert result.outcome is X.WON and result.refresh_issued
        grant = result.grant
        assert grant is not None and grant.id == grant_id and grant.account_id == env.account_id
        assert grant.client_id == CLIENT and grant.scopes == ("Canvas.Access",)
        assert grant.expires_at - grant.created_at == 30 * 86400
        assert grant.upstream_auth_at == int(env.clock())
        code = env.authz.load_code(tk.hash_secret(raw))
        assert code is not None and code.consumed_at == int(env.clock()) and code.grant_id == grant_id
        assert refresh_row(env, refresh)[:3] == (None, None, None)
        assert refresh_row(env, refresh)[3] == grant.expires_at
        # only the hash of the refresh token is stored
        assert refresh not in "".join(str(c) for r in rows(env, "SELECT * FROM oauth_refresh_tokens") for c in r)

    def test_a_client_that_cannot_refresh_gets_no_refresh_token(self, env: Env) -> None:
        result, refresh, _ = env.exchange(env.new_code(), refresh=False)
        assert result.outcome is X.WON and not result.refresh_issued and refresh is None
        assert rows(env, "SELECT COUNT(*) FROM oauth_refresh_tokens")[0][0] == 0

    def test_the_registration_lives_as_long_as_its_grant(self, env: Env) -> None:
        env.authz.put_client(CLIENT, "{}", "App", int(env.clock()) + 100)
        result, _, _ = env.exchange(env.new_code(client_kind="dcr"))
        assert rows(env, "SELECT expires_at FROM oauth_clients")[0][0] == result.grant.expires_at

    def test_a_wrong_client_or_unknown_code_is_dead(self, env: Env) -> None:
        raw = env.new_code()
        result, _, _ = env.exchange(raw, client_id="44444444-4444-4444-8444-444444444444")
        assert result.outcome is X.DEAD
        result, _, _ = env.exchange("cmcp_ac_" + "A" * 43)
        assert result.outcome is X.DEAD
        # the code was not burned by the wrong client
        assert env.exchange(raw)[0].outcome is X.WON

    def test_an_expired_code_is_dead(self, env: Env, clock) -> None:
        raw = env.new_code()
        clock.advance(301)
        assert env.exchange(raw)[0].outcome is X.DEAD
        assert rows(env, "SELECT COUNT(*) FROM oauth_grants")[0][0] == 0

    @pytest.mark.parametrize("status", ["disabled"])
    def test_an_account_that_is_not_active_gets_no_grant_but_burns_the_code(self, env: Env, status: str) -> None:
        raw = env.new_code()
        env.tokens.disable_principal(env.account_key, actor=OPERATOR, reason="operator_disabled")
        result, _, _ = env.exchange(raw)
        assert result.outcome is X.INACTIVE
        assert rows(env, "SELECT COUNT(*) FROM oauth_grants")[0][0] == 0
        assert env.exchange(raw)[0].outcome is X.DEAD  # consumed, and no grant behind it

    def test_a_sign_in_older_than_the_limit_forces_a_new_one(self, env: Env, clock) -> None:
        raw = env.new_code(upstream_auth_at=int(clock()) - 15 * 86400)
        result, _, _ = env.exchange(raw)
        assert result.outcome is X.REAUTH
        assert rows(env, "SELECT COUNT(*) FROM oauth_grants")[0][0] == 0
        assert ("oauth", "reauth_required", "denied") in rows(
            env, "SELECT surface, reason, outcome FROM auth_events"
        )

    def test_a_sign_in_exactly_at_the_limit_is_still_good(self, env: Env, clock) -> None:
        raw = env.new_code(upstream_auth_at=int(clock()) - 14 * 86400)
        assert env.exchange(raw)[0].outcome is X.WON


class TestCodeReplays:
    def test_duplicates_inside_the_window_get_siblings_up_to_the_cap(self, env: Env, clock) -> None:
        raw = env.new_code()
        first, refresh1, _ = env.exchange(raw)
        clock.advance(5)
        second, refresh2, _ = env.exchange(raw)
        third, refresh3, _ = env.exchange(raw)
        fourth, _, _ = env.exchange(raw)
        assert (first.outcome, second.outcome, third.outcome, fourth.outcome) == (
            X.WON, X.GRACE, X.GRACE, X.CAPPED,
        )
        assert second.grant.id == first.grant.id == third.grant.id
        for token in (refresh1, refresh2, refresh3):
            assert refresh_row(env, token)[2] is None  # siblings: no parent
        assert rows(env, "SELECT revoked_at FROM oauth_grants")[0][0] is None  # nothing revoked

    def test_a_replay_after_the_window_revokes_the_grant(self, env: Env, clock) -> None:
        raw = env.new_code()
        first, refresh, _ = env.exchange(raw)
        clock.advance(31)
        result, _, _ = env.exchange(raw)
        assert result.outcome is X.REPLAY_REVOKED
        assert rows(env, "SELECT revoked_reason, revoked_by FROM oauth_grants") == [("code_replay", "system")]
        assert ("oauth", "code_replay", "denied") in rows(env, "SELECT surface, reason, outcome FROM auth_events")
        assert env.rotate(refresh)[0].outcome is R.DEAD  # the whole family is gone

    def test_a_replay_inside_the_window_after_the_family_rotated_revokes(self, env: Env, clock) -> None:
        raw = env.new_code()
        first, refresh, _ = env.exchange(raw)
        assert env.rotate(refresh)[0].outcome is R.ROTATED
        clock.advance(2)
        assert env.exchange(raw)[0].outcome is X.REPLAY_REVOKED

    def test_strict_mode_revokes_on_any_replay(self, tmp_path, keyring, clock) -> None:
        env = make_env(tmp_path, keyring, clock, settings=AuthzSettings(refresh_reuse_grace_s=0))
        raw = env.new_code()
        assert env.exchange(raw)[0].outcome is X.WON
        assert env.exchange(raw)[0].outcome is X.REPLAY_REVOKED

    def test_a_replay_after_the_grant_was_revoked_is_dead(self, env: Env) -> None:
        raw = env.new_code()
        first, _, _ = env.exchange(raw)
        assert env.authz.revoke_own_grant(first.grant.id, env.account_key)
        assert env.exchange(raw)[0].outcome is X.DEAD


class TestRotation:
    def test_rotation_issues_a_successor_and_keeps_the_absolute_cap(self, env: Env, clock) -> None:
        grant, refresh = env.grant_with_token()
        clock.advance(3000)
        result, successor = env.rotate(refresh)
        assert result.outcome is R.ROTATED and result.refresh_issued
        old = refresh_row(env, refresh)
        assert old[0] == int(clock()) and old[1] == tk.hash_secret(successor)
        new = refresh_row(env, successor)
        assert new[2] == tk.hash_secret(refresh)
        assert new[3] == grant.expires_at  # the cap is inherited, never extended
        clock.advance(100)
        again, third = env.rotate(successor)
        assert again.outcome is R.ROTATED and refresh_row(env, third)[3] == grant.expires_at
        assert env.authz.get_grant(grant.id).last_used_at == int(clock())

    def test_unknown_and_expired_tokens_are_dead(self, env: Env, clock) -> None:
        assert env.rotate("cmcp_rt_" + "B" * 43)[0].outcome is R.DEAD
        grant, refresh = env.grant_with_token()
        clock.advance(30 * 86400 + 1)
        assert env.rotate(refresh)[0].outcome is R.DEAD

    def test_a_duplicate_inside_the_window_gets_a_sibling_and_the_family_survives(self, env: Env, clock) -> None:
        grant, refresh = env.grant_with_token()
        won, a = env.rotate(refresh)
        clock.advance(3)
        dup, b = env.rotate(refresh)
        dup2, c = env.rotate(refresh)
        capped, _ = env.rotate(refresh)
        assert (won.outcome, dup.outcome, dup2.outcome, capped.outcome) == (
            R.ROTATED, R.GRACE, R.GRACE, R.CAPPED,
        )
        assert rows(env, "SELECT revoked_at FROM oauth_grants")[0][0] is None
        for sibling in (a, b, c):
            assert refresh_row(env, sibling)[2] == tk.hash_secret(refresh)

    def test_using_one_sibling_retires_the_others_and_a_retired_one_is_a_reuse(self, env: Env, clock) -> None:
        grant, refresh = env.grant_with_token()
        _, a = env.rotate(refresh)
        clock.advance(2)
        _, b = env.rotate(refresh)  # the duplicate's sibling
        used, successor = env.rotate(a)
        assert used.outcome is R.ROTATED
        assert refresh_row(env, b)[:2] == (int(clock()), None)  # retired: used, no successor
        # whoever holds the retired sibling presents it: theft detection is back
        result, _ = env.rotate(b)
        assert result.outcome is R.REUSE_REVOKED
        assert env.rotate(successor)[0].outcome is R.DEAD

    def test_reuse_outside_the_window_revokes_the_family(self, env: Env, clock) -> None:
        grant, refresh = env.grant_with_token()
        _, successor = env.rotate(refresh)
        clock.advance(31)
        assert env.rotate(refresh)[0].outcome is R.REUSE_REVOKED
        assert rows(env, "SELECT revoked_reason FROM oauth_grants")[0][0] == "refresh_reuse"
        assert env.rotate(successor)[0].outcome is R.DEAD

    def test_a_token_two_steps_behind_revokes_even_inside_the_window(self, env: Env, clock) -> None:
        grant, refresh = env.grant_with_token()
        _, second = env.rotate(refresh)
        _, third = env.rotate(second)
        clock.advance(1)
        assert env.rotate(refresh)[0].outcome is R.REUSE_REVOKED
        assert env.rotate(third)[0].outcome is R.DEAD

    def test_strict_mode_revokes_on_any_reuse(self, tmp_path, keyring, clock) -> None:
        env = make_env(tmp_path, keyring, clock, settings=AuthzSettings(refresh_reuse_grace_s=0))
        grant, refresh = env.grant_with_token()
        env.rotate(refresh)
        assert env.rotate(refresh)[0].outcome is R.REUSE_REVOKED

    def test_an_account_that_was_disabled_cannot_refresh(self, env: Env) -> None:
        grant, refresh = env.grant_with_token()
        env.tokens.disable_principal(env.account_key, actor=OPERATOR, reason="operator_disabled")
        assert env.rotate(refresh)[0].outcome is R.DEAD  # its grants were revoked with it
        assert rows(env, "SELECT revoked_reason FROM oauth_grants")[0][0] == "account_disabled"

    def test_an_inactive_account_with_a_live_grant_is_refused(self, env: Env) -> None:
        # e.g. the row was changed behind the store's back
        grant, refresh = env.grant_with_token()
        rows(env, "UPDATE accounts SET status = 'disabled', disabled_reason = 'operator_disabled'")
        assert env.rotate(refresh)[0].outcome is R.INACTIVE

    def test_the_maximum_age_of_the_sign_in_forces_a_new_one_and_revokes(self, env: Env, clock) -> None:
        grant, refresh = env.grant_with_token()
        clock.advance(14 * 86400 + 1)
        result, _ = env.rotate(refresh)
        assert result.outcome is R.REAUTH
        assert rows(env, "SELECT revoked_reason FROM oauth_grants")[0][0] == "reauth_required"
        assert ("oauth", "reauth_required", "denied") in rows(env, "SELECT surface, reason, outcome FROM auth_events")
        assert env.rotate(refresh)[0].outcome is R.DEAD

    def test_load_refresh_returns_used_tokens_and_the_grant_facts(self, env: Env) -> None:
        grant, refresh = env.grant_with_token()
        env.rotate(refresh)
        view = env.authz.load_refresh(tk.hash_secret(refresh))
        assert view is not None and view.used_at is not None
        assert view.client_id == CLIENT and view.account_id == env.account_id and view.grant_revoked_at is None
        assert env.authz.load_refresh(tk.hash_secret("nope")) is None
        env.authz.revoke_own_grant(grant.id, env.account_key)
        assert env.authz.load_refresh(tk.hash_secret(refresh)).grant_revoked_at is not None


class TestRevocation:
    def test_a_user_ends_only_their_own_connection(self, env: Env) -> None:
        grant, _ = env.grant_with_token()
        stranger = make_account(env.tokens, OID_B)
        assert not env.authz.revoke_own_grant(grant.id, stranger)
        assert env.authz.revoke_own_grant(grant.id, env.account_key)
        assert not env.authz.revoke_own_grant(grant.id, env.account_key)  # already over
        row = rows(env, "SELECT revoked_reason, revoked_by FROM oauth_grants")[0]
        assert row == ("user_revoked", env.account_key)
        assert [e.action for e in env.tokens.list_audit() if e.action == "grant_revoked"] == ["grant_revoked"]

    def test_an_owner_ends_any_connection_and_is_rechecked_in_the_transaction(self, env: Env) -> None:
        owner = make_account(env.tokens, OID_B, role="owner")
        grant, _ = env.grant_with_token()
        with pytest.raises(AccessActionRefused):
            env.authz.owner_revoke_grant(grant.id, env.account_key)  # not an owner
        assert env.authz.owner_revoke_grant(grant.id, owner)
        assert rows(env, "SELECT revoked_reason, revoked_by FROM oauth_grants")[0] == ("owner_revoked", owner)
        # an owner who was disabled meanwhile cannot act
        env.tokens.disable_principal(owner, actor=OPERATOR, reason="operator_disabled", allow_last_owner=True)
        other, _ = env.grant_with_token()
        with pytest.raises(AccessActionRefused):
            env.authz.owner_revoke_grant(other.id, owner)
        assert env.authz.get_grant(other.id).revoked_at is None

    def test_the_operator_ends_any_connection(self, env: Env) -> None:
        grant, _ = env.grant_with_token()
        assert env.authz.operator_revoke_grant(grant.id)
        assert not env.authz.operator_revoke_grant(grant.id)
        assert not env.authz.operator_revoke_grant("00000000-0000-4000-8000-000000000000")
        assert rows(env, "SELECT revoked_reason, revoked_by FROM oauth_grants")[0] == ("operator_revoked", "operator")

    def test_a_client_revocation_is_noted_and_idempotent(self, env: Env) -> None:
        grant, _ = env.grant_with_token()
        assert env.authz.revoke_client_grant(grant.id)
        assert not env.authz.revoke_client_grant(grant.id)
        assert ("oauth", "client_revoked", "success") in rows(env, "SELECT surface, reason, outcome FROM auth_events")

    def test_admission_lost_ends_every_connection_of_the_account(self, env: Env) -> None:
        g1, _ = env.grant_with_token()
        g2, _ = env.grant_with_token()
        assert env.authz.revoke_all_for_account(env.account_key, reason="admission_lost") == 2
        assert env.authz.revoke_all_for_account(env.account_key, reason="admission_lost") == 0
        assert {r[0] for r in rows(env, "SELECT revoked_reason FROM oauth_grants")} == {"admission_lost"}
        assert any(e.action == "grants_revoked_for_account" for e in env.tokens.list_audit())
        assert env.authz.list_grants(env.account_key) == []
        assert g1.id != g2.id

    def test_admission_lost_also_ends_the_sessions_and_the_unredeemed_codes(self, env: Env) -> None:
        env.grant_with_token()
        redeemed = env.new_code()
        env.exchange(redeemed)
        pending = env.new_code()
        epoch = rows(env, "SELECT session_epoch FROM accounts WHERE id = :a", a=env.account_id)[0][0]
        env.authz.revoke_all_for_account(env.account_key, reason="admission_lost")
        assert rows(env, "SELECT session_epoch FROM accounts WHERE id = :a", a=env.account_id)[0][0] == epoch + 1
        assert env.authz.load_code(tk.hash_secret(pending)) is None
        assert env.authz.load_code(tk.hash_secret(redeemed)) is not None  # kept: replay detection
        assert rows(env, "SELECT status FROM accounts WHERE id = :a", a=env.account_id)[0][0] == "active"
        assert env.exchange(pending)[0].outcome is X.DEAD

    def test_status_and_listing(self, env: Env, clock) -> None:
        grant, _ = env.grant_with_token()
        status = env.authz.grant_status(grant.id)
        assert status.found and status.usable(int(clock())) and status.account_status == "active"
        assert status.client_id == CLIENT and status.account_id == env.account_id
        assert not env.authz.grant_status("00000000-0000-4000-8000-000000000000").found
        assert [g.id for g in env.authz.list_grants(env.account_key)] == [grant.id]
        env.authz.revoke_own_grant(grant.id, env.account_key)
        assert not env.authz.grant_status(grant.id).usable(int(clock()))
        assert env.authz.list_grants(env.account_key) == []
        assert [g.id for g in env.authz.list_all_grants(include_inactive=True)] == [grant.id]
        assert env.authz.list_all_grants() == []

    def test_touching_a_grant_is_rate_limited_to_five_minutes(self, env: Env, clock) -> None:
        grant, _ = env.grant_with_token()
        base = env.authz.get_grant(grant.id).last_used_at
        clock.advance(60)
        env.authz.touch_grant(grant.id)
        assert env.authz.get_grant(grant.id).last_used_at == base
        clock.advance(300)
        env.authz.touch_grant(grant.id)
        assert env.authz.get_grant(grant.id).last_used_at == int(clock())


class TestEpochAndClientsAndCulling:
    def test_the_jwt_epoch_starts_at_zero_and_is_raised_with_an_audit_entry(self, env: Env) -> None:
        assert env.authz.jwt_epoch() == 0
        assert env.authz.bump_jwt_epoch() == 1 and env.authz.bump_jwt_epoch() == 2
        assert env.authz.jwt_epoch() == 2
        assert [e.action for e in env.tokens.list_audit() if e.action == "jwt_key_rotated"] == ["jwt_key_rotated"] * 2

    def test_a_registered_client_round_trips(self, env: Env, clock) -> None:
        env.authz.put_client(CLIENT, '{"client_id": "x"}', "My app", int(clock()) + 10)
        record = env.authz.get_client_record(CLIENT)
        assert record is not None and record.client_name == "My app" and record.info_json == '{"client_id": "x"}'
        assert env.authz.get_client_record("nope") is None

    def test_the_document_snapshot_is_monotonic(self, env: Env) -> None:
        url = "https://client.example/cimd.json"
        assert env.authz.upsert_cimd(url, '{"v": 2}', fetched_at=200, fresh_until=300)
        assert not env.authz.upsert_cimd(url, '{"v": 1}', fetched_at=100, fresh_until=400)
        assert not env.authz.upsert_cimd(url, '{"v": 3}', fetched_at=200, fresh_until=400)
        assert env.authz.upsert_cimd(url, '{"v": 4}', fetched_at=201, fresh_until=202)
        snap = env.authz.cimd_snapshot(url)
        assert snap is not None and snap.doc_json == '{"v": 4}' and snap.fetched_at == 201
        env.authz.record_cimd_error(url, "timeout")
        assert env.authz.cimd_snapshot(url).last_error == "timeout"
        env.authz.upsert_cimd(url, '{"v": 5}', fetched_at=300, fresh_until=400)
        assert env.authz.cimd_snapshot(url).last_error is None
        env.authz.record_cimd_error("https://unknown.example/x", "timeout")  # no row: no failure

    def test_culling_removes_each_expired_class_and_keeps_live_state(self, env: Env, clock) -> None:
        live_grant, live_refresh = env.grant_with_token()
        _, rotated_refresh = env.grant_with_token()
        env.rotate(rotated_refresh)  # a used token of a live grant must stay
        old_code = env.new_code()
        env.authz.put_client("old-client", "{}", "", int(clock()) - 1)
        env.authz.put_client("live-client", "{}", "", int(clock()) + 40 * 86400)
        env.authz.upsert_cimd("https://old.example/c", "{}", fetched_at=int(clock()) - 9 * 86400, fresh_until=int(clock()) - 9 * 86400)
        env.authz.upsert_cimd("https://new.example/c", "{}", fetched_at=int(clock()), fresh_until=int(clock()) + 60)
        first = env.authz.cull()
        # only the expired registration and the 9-day-old document are old enough
        assert first["oauth_clients"] == 1 and first["cimd_clients"] == 1
        assert all(count == 0 for name, count in first.items() if name not in ("oauth_clients", "cimd_clients"))
        clock.advance(2 * 3600)
        removed = env.authz.cull()
        assert removed["oauth_codes"] == 3 and removed["oauth_grants"] == 0
        assert env.authz.load_code(tk.hash_secret(old_code)) is None
        assert env.authz.get_client_record("live-client") is not None
        assert env.authz.cimd_snapshot("https://new.example/c") is not None
        assert env.authz.load_refresh(tk.hash_secret(rotated_refresh)) is not None
        assert env.authz.get_grant(live_grant.id) is not None
        clock.advance(31 * 86400)
        removed = env.authz.cull()
        # past their 30-day cap: the tokens go at once, the grant rows 30 days later
        assert removed["oauth_refresh_tokens"] == 3 and removed["oauth_grants"] == 0
        assert env.authz.load_refresh(tk.hash_secret(live_refresh)) is None
        clock.advance(31 * 86400)
        assert env.authz.cull()["oauth_grants"] == 2
        assert rows(env, "SELECT COUNT(*) FROM oauth_grants")[0][0] == 0

    def test_revoked_grants_and_their_tokens_are_culled_after_their_waiting_periods(self, env: Env, clock) -> None:
        grant, refresh = env.grant_with_token()
        env.authz.revoke_own_grant(grant.id, env.account_key)
        clock.advance(8 * 86400)
        removed = env.authz.cull()
        assert removed["oauth_refresh_tokens"] == 1 and removed["oauth_grants"] == 0
        clock.advance(23 * 86400)
        assert env.authz.cull()["oauth_grants"] == 1


def test_results_are_immutable() -> None:
    from canvas_mcp.core.selfhost.authz.models import ExchangeResult

    with pytest.raises(dataclasses.FrozenInstanceError):
        ExchangeResult(X.DEAD).outcome = X.WON  # type: ignore[misc]
