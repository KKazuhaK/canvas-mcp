"""Grant operations and signing with the exchange transaction's epoch."""

from types import SimpleNamespace

import pytest

from canvas_mcp.core.selfhost.authz import tokens as tk
from canvas_mcp.core.selfhost.authz.grants import GrantService
from canvas_mcp.core.selfhost.authz.models import GrantStatus
from canvas_mcp.core.selfhost.settings import AuthzSettings

from .helpers import CLIENT, Env, make_env
from .test_tokens import AUDIENCE, ISSUER

ACCT = "aaaaaaaa-0000-4000-8000-00000000000a"


def status(account_id: str = ACCT, **kw) -> GrantStatus:
    base = {
        "found": True,
        "account_id": account_id,
        "client_id": "c",
        "revoked": False,
        "expires_at": 10**10,
        "account_status": "active",
    }
    base.update(kw)
    return GrantStatus(**base)


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


def service(env: Env, *, settings: AuthzSettings | None = None):
    settings = settings or AuthzSettings()
    codec = tk.AccessTokenCodec(
        env.tokens._keyring,
        issuer=ISSUER,
        audience=AUDIENCE,
        scopes=["Canvas.Access"],
        clock=env.clock,
    )
    return GrantService(env.authz, codec, settings, clock=env.clock), codec


class TestMinting:
    async def test_the_pair_matches_the_grant(self, env: Env) -> None:
        svc, codec = service(env)
        raw = env.new_code()

        class Code:
            code_hash = tk.hash_secret(raw)

        class Client:
            client_id = CLIENT
            grant_types = ["authorization_code", "refresh_token"]

        token = await svc.issue_from_code(Client, Code)
        claims = codec.decode(token.access_token).claims
        assert claims["client_id"] == CLIENT and claims["scope"] == "Canvas.Access"
        assert token.refresh_token is not None and tk.REFRESH_RE.fullmatch(
            token.refresh_token
        )
        assert (
            token.expires_in == claims["exp"] - claims["iat"]
            or abs(token.expires_in - 3600) <= 2
        )

    async def test_the_access_token_is_clamped_to_the_grant_and_the_sign_in(
        self, env: Env
    ) -> None:
        settings = AuthzSettings(
            access_token_ttl=86400,
            refresh_absolute_ttl=3 * 86400,
            max_upstream_auth_age=7200,
        )
        svc, codec = service(env, settings=settings)
        env.authz.settings = settings
        raw = env.new_code()

        class Code:
            code_hash = tk.hash_secret(raw)

        class Client:
            client_id = CLIENT
            grant_types = ["authorization_code"]

        token = await svc.issue_from_code(Client, Code)
        assert token.refresh_token is None
        assert (
            7100 <= token.expires_in <= 7200
        )  # the sign-in's maximum age, not the 24 h lifetime
        assert (
            codec.decode(token.access_token).claims["exp"]
            - codec.decode(token.access_token).claims["iat"]
            <= 7200
        )


class TestTransactionalEpoch:
    @pytest.mark.parametrize(
        "ceremony", ["first_code", "code_grace", "refresh", "refresh_grace"]
    )
    async def test_success_carries_epoch_read_in_its_transaction(
        self, env, ceremony, monkeypatch
    ):
        svc, codec = service(env)
        client = SimpleNamespace(
            client_id=CLIENT, grant_types=["authorization_code", "refresh_token"]
        )
        raw = env.new_code()
        if ceremony != "first_code":
            result, refresh, _ = env.exchange(raw)
            if ceremony == "refresh_grace":
                env.rotate(refresh)
        env.authz.bump_jwt_epoch()
        monkeypatch.setattr(
            env.authz,
            "jwt_epoch",
            lambda: pytest.fail("epoch read outside exchange transaction"),
        )
        if ceremony.startswith("refresh"):
            token = await svc.rotate(
                client,
                SimpleNamespace(token_hash=tk.hash_secret(refresh)),
                ["Canvas.Access"],
            )
        else:
            token = await svc.issue_from_code(
                client, SimpleNamespace(code_hash=tk.hash_secret(raw))
            )
        assert codec.decode(token.access_token).epoch == 1

    async def test_rotation_after_exchange_does_not_change_the_epoch_being_signed(
        self, env, monkeypatch
    ):
        svc, codec = service(env)
        exchange = env.authz.exchange_code

        def commit_then_rotate(**kw):
            result = exchange(**kw)
            assert result.jwt_epoch == 0
            env.authz.bump_jwt_epoch()
            return result

        monkeypatch.setattr(env.authz, "exchange_code", commit_then_rotate)
        token = await svc.issue_from_code(
            SimpleNamespace(client_id=CLIENT, grant_types=["authorization_code"]),
            SimpleNamespace(code_hash=tk.hash_secret(env.new_code())),
        )
        assert (
            codec.decode(token.access_token).epoch == 0 and env.authz.jwt_epoch() == 1
        )

    async def test_revoke_all_and_single_grant_operations(self, env):
        svc, _ = service(env)
        first, _ = env.grant_with_token()
        second, _ = env.grant_with_token()
        assert len(env.authz.grants_page(account_key=env.account_key).items) == 2
        assert await svc.revoke_own(first.id, env.account_key)
        assert await svc.revoke_all_for_account(env.account_key) == 1
        assert env.authz.grants_page(account_key=env.account_key).items == ()
        assert (
            env.authz.grant_status(first.id).revoked
            and env.authz.grant_status(second.id).revoked
        )
