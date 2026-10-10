"""The grant status cache and the grant service."""

from __future__ import annotations

import threading

import pytest

from canvas_mcp.core.selfhost.authz import tokens as tk
from canvas_mcp.core.selfhost.authz.grants import GrantService, GrantStatusCache
from canvas_mcp.core.selfhost.authz.models import GrantStatus
from canvas_mcp.core.selfhost.db.errors import StoreUnavailable
from canvas_mcp.core.selfhost.settings import AuthzSettings
from canvas_mcp.core.selfhost.token_store import OPERATOR

from .helpers import CLIENT, Env, make_env
from .test_tokens import AUDIENCE, ISSUER, Epoch

ACCT = "aaaaaaaa-0000-4000-8000-00000000000a"


def status(account_id: str = ACCT, **kw) -> GrantStatus:
    base = {
        "found": True, "account_id": account_id, "client_id": "c", "revoked": False,
        "expires_at": 10**10, "account_status": "active",
    }
    base.update(kw)
    return GrantStatus(**base)  # type: ignore[arg-type]


class Mono:
    def __init__(self) -> None:
        self.now = 100.0

    def __call__(self) -> float:
        return self.now


class TestStatusCache:
    def test_an_answer_is_reused_for_the_ttl_and_then_forgotten(self) -> None:
        clock = Mono()
        cache = GrantStatusCache(30, clock=clock)
        cache.put("g", status(), cache.epoch)
        assert cache.get("g") == status()
        clock.now += 29.9
        assert cache.get("g") is not None
        clock.now += 0.2
        assert cache.get("g") is None

    def test_a_ttl_of_zero_caches_nothing(self) -> None:
        cache = GrantStatusCache(0)
        cache.put("g", status(), cache.epoch)
        assert cache.get("g") is None

    def test_invalidating_a_grant_drops_it_and_a_read_in_flight_cannot_bring_it_back(self) -> None:
        cache = GrantStatusCache(30, clock=Mono())
        epoch = cache.epoch  # a reader starts ...
        cache.invalidate("g")  # ... a revocation happens ...
        cache.put("g", status(), epoch)  # ... and the reader finishes with the old answer
        assert cache.get("g") is None
        cache.put("g", status(), cache.epoch)
        assert cache.get("g") is not None
        cache.invalidate("g")
        assert cache.get("g") is None

    def test_invalidating_an_account_drops_all_its_grants_only(self) -> None:
        cache = GrantStatusCache(30, clock=Mono())
        other = "bbbbbbbb-0000-4000-8000-00000000000b"
        cache.put("g1", status(), cache.epoch)
        cache.put("g2", status(), cache.epoch)
        cache.put("g3", status(other), cache.epoch)
        cache.invalidate_account(ACCT)
        assert cache.get("g1") is None and cache.get("g2") is None and cache.get("g3") is not None
        epoch = cache.epoch
        cache.invalidate_account(other)
        cache.put("g3", status(other), epoch)
        assert cache.get("g3") is None

    def test_clear_and_the_size_bound(self) -> None:
        cache = GrantStatusCache(30, clock=Mono(), max_entries=3)
        for i in range(5):
            cache.put(f"g{i}", status(), cache.epoch)
        assert cache.get("g0") is None and cache.get("g1") is None and cache.get("g4") is not None
        cache.clear()
        assert cache.get("g4") is None

    def test_a_revoked_or_missing_answer_is_cached_too(self) -> None:
        cache = GrantStatusCache(30, clock=Mono())
        cache.put("gone", GrantStatus(found=False), cache.epoch)
        cache.put("revoked", status(revoked=True), cache.epoch)
        assert cache.get("gone") is not None and cache.get("revoked") is not None

    def test_it_is_thread_safe_under_a_hammering(self) -> None:
        cache = GrantStatusCache(30, clock=Mono(), max_entries=50)
        errors: list[BaseException] = []

        def work(n: int) -> None:
            try:
                for i in range(500):
                    key = f"g{(n * 7 + i) % 80}"
                    cache.put(key, status(), cache.epoch)
                    cache.get(key)
                    if i % 50 == 0:
                        cache.invalidate(key)
                    if i % 97 == 0:
                        cache.invalidate_account(ACCT)
            except BaseException as exc:  # noqa: BLE001
                errors.append(exc)

        threads = [threading.Thread(target=work, args=(n,)) for n in range(8)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert errors == []


class TestStatusRules:
    def test_usable_needs_a_live_grant_and_an_active_account(self) -> None:
        assert status().usable(100)
        assert not status(revoked=True).usable(100)
        assert not status(expires_at=100).usable(100)
        assert not status(account_status="disabled").usable(100)
        assert not status(account_status="pending").usable(100)
        assert not status(account_status=None).usable(100)
        assert not GrantStatus(found=False).usable(100)


@pytest.fixture
def env(tmp_path, keyring, clock) -> Env:
    return make_env(tmp_path, keyring, clock)


def service(env: Env, *, ttl: float = 30.0, settings: AuthzSettings | None = None):
    settings = settings or AuthzSettings()
    codec = tk.AccessTokenCodec(
        env.tokens._keyring, Epoch(), issuer=ISSUER, audience=AUDIENCE, scopes=["Canvas.Access"], clock=env.clock
    )
    cache = GrantStatusCache(ttl, clock=env.clock)
    return GrantService(env.authz, codec, cache, settings, clock=env.clock), cache, codec


def claims_of(env: Env, grant_record, **over) -> dict:
    base = {"grant": grant_record.id, "acct": grant_record.account_key, "client_id": grant_record.client_id}
    base.update(over)
    return base


class TestCheckAccess:
    async def test_a_live_grant_passes_and_the_answer_is_cached(self, env: Env, monkeypatch) -> None:
        grant, _ = env.grant_with_token()
        svc, cache, _ = service(env)
        calls = []
        original = env.authz.grant_status
        monkeypatch.setattr(env.authz, "grant_status", lambda gid: calls.append(gid) or original(gid))
        assert await svc.check_access(claims_of(env, grant))
        assert await svc.check_access(claims_of(env, grant))
        assert calls == [grant.id]

    async def test_a_mismatch_of_account_or_client_fails(self, env: Env) -> None:
        grant, _ = env.grant_with_token()
        svc, _, _ = service(env)
        assert not await svc.check_access(claims_of(env, grant, acct="acct:bbbbbbbb-0000-4000-8000-00000000000b"))
        assert not await svc.check_access(claims_of(env, grant, client_id="other"))
        assert not await svc.check_access(claims_of(env, grant, **{"grant": "00000000-0000-4000-8000-000000000000"}))

    async def test_revocation_through_the_service_is_seen_at_once(self, env: Env) -> None:
        grant, _ = env.grant_with_token()
        svc, _, _ = service(env)
        assert await svc.check_access(claims_of(env, grant))
        assert await svc.revoke_own(grant.id, env.account_key)
        assert not await svc.check_access(claims_of(env, grant))

    async def test_a_change_made_elsewhere_is_seen_after_the_ttl_not_before(self, env: Env) -> None:
        grant, _ = env.grant_with_token()
        svc, cache, _ = service(env, ttl=30)
        assert await svc.check_access(claims_of(env, grant))
        env.authz.revoke_own_grant(grant.id, env.account_key)  # not through the service
        assert await svc.check_access(claims_of(env, grant))  # cached
        env.clock.advance(31)
        assert not await svc.check_access(claims_of(env, grant))

    async def test_disabling_the_account_is_seen_through_the_account_hook(self, env: Env) -> None:
        grant, _ = env.grant_with_token()
        svc, _, _ = service(env)
        assert await svc.check_access(claims_of(env, grant))
        env.tokens.disable_principal(env.account_key, actor=OPERATOR, reason="operator_disabled")
        svc.invalidate_account(env.account_key)
        assert not await svc.check_access(claims_of(env, grant))

    async def test_a_database_error_propagates_and_is_not_cached(self, env: Env, monkeypatch) -> None:
        grant, _ = env.grant_with_token()
        svc, cache, _ = service(env)

        def failing(_gid: str) -> None:
            raise StoreUnavailable(kind="OperationalError")

        monkeypatch.setattr(env.authz, "grant_status", failing)
        with pytest.raises(StoreUnavailable):
            await svc.check_access(claims_of(env, grant))
        assert cache.get(grant.id) is None

    async def test_last_used_is_noted_when_the_status_is_read(self, env: Env) -> None:
        grant, _ = env.grant_with_token()
        svc, _, _ = service(env, ttl=0)
        env.clock.advance(400)
        assert await svc.check_access(claims_of(env, grant))
        assert env.authz.get_grant(grant.id).last_used_at == int(env.clock())

    async def test_revoking_everything_for_an_account(self, env: Env) -> None:
        g1, _ = env.grant_with_token()
        g2, _ = env.grant_with_token()
        svc, _, _ = service(env)
        assert await svc.check_access(claims_of(env, g1)) and await svc.check_access(claims_of(env, g2))
        assert await svc.revoke_all_for_account(env.account_key) == 2
        assert not await svc.check_access(claims_of(env, g1)) and not await svc.check_access(claims_of(env, g2))
        assert await svc.list_grants(env.account_key) == []
        with pytest.raises(AssertionError):
            await svc.revoke_all_for_account(env.account_key, "user_revoked")


class TestMinting:
    async def test_the_pair_matches_the_grant(self, env: Env) -> None:
        svc, _, codec = service(env)
        raw = env.new_code()

        class Code:
            code_hash = tk.hash_secret(raw)

        class Client:
            client_id = CLIENT
            grant_types = ["authorization_code", "refresh_token"]

        token = await svc.issue_from_code(Client, Code)
        claims = codec.decode(token.access_token)
        assert claims["client_id"] == CLIENT and claims["scope"] == "Canvas.Access"
        assert token.refresh_token is not None and tk.REFRESH_RE.fullmatch(token.refresh_token)
        assert token.expires_in == claims["exp"] - claims["iat"] or abs(token.expires_in - 3600) <= 2

    async def test_the_access_token_is_clamped_to_the_grant_and_the_sign_in(self, env: Env) -> None:
        settings = AuthzSettings(access_token_ttl=86400, refresh_absolute_ttl=3 * 86400, max_upstream_auth_age=7200)
        svc, _, codec = service(env, settings=settings)
        env.authz.settings = settings
        raw = env.new_code()

        class Code:
            code_hash = tk.hash_secret(raw)

        class Client:
            client_id = CLIENT
            grant_types = ["authorization_code"]

        token = await svc.issue_from_code(Client, Code)
        assert token.refresh_token is None
        assert 7100 <= token.expires_in <= 7200  # the sign-in's maximum age, not the 24 h lifetime
        assert codec.decode(token.access_token)["exp"] - codec.decode(token.access_token)["iat"] <= 7200
