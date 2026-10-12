"""First installation and governed provider editing through the actual account API."""

from contextlib import contextmanager
from urllib.parse import parse_qs, urlsplit

import pytest
from sqlalchemy import select
from starlette.applications import Starlette
from starlette.testclient import TestClient

from canvas_mcp.core.selfhost.account_api import build_api_routes
from canvas_mcp.core.selfhost.account_core import AccountConfig, build_account_app
from canvas_mcp.core.selfhost.app import prepare_selfhost
from canvas_mcp.core.selfhost.db import schema
from canvas_mcp.core.selfhost.login.registry import build_login_runtime
from canvas_mcp.core.selfhost.login.routes import build_login_routes
from canvas_mcp.core.selfhost.settings import load_selfhost_settings

from ..authz.stack import (
    ALICE,
    BASE,
    ENTRA_CLIENT_ID,
    ENTRA_TENANT,
    OWNER,
    Browser,
    default_env,
    local_stack,
)
from .test_entra_only_golden import account_app

SECRET = "entra-client-secret-0123456789"
CONFIG = {"tenant_id": ENTRA_TENANT, "client_id": ENTRA_CLIENT_ID}


@contextmanager
def installation(tmp_path):
    values = default_env(tmp_path)
    runtime = prepare_selfhost(load_selfhost_settings(values))
    logins = build_login_runtime(runtime.settings, flow_store=runtime.authz.txns)
    core = build_account_app(
        AccountConfig(BASE, runtime.settings.account_session_secret),
        runtime.store,
        runtime.identity,
        authz=runtime.authz,
        logins=logins,
        snapshots=runtime.snapshots,
        provider_store=runtime.provider_store,
        installation=runtime.installation,
        infrastructure=runtime.settings,
    )
    code = runtime.installation.issue()
    try:
        with TestClient(
            Starlette(routes=build_login_routes(core) + build_api_routes(core)),
            base_url=BASE,
            follow_redirects=False,
        ) as client:
            yield client, runtime, code
    finally:
        runtime.store.close()


def setup_body(revision, code):
    return {
        "revision": revision,
        "code": code,
        "config": CONFIG,
        "client_secret": SECRET,
    }


def test_only_operator_code_can_initialize_and_secret_is_never_returned(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        status = client.get("/api/v1/setup")
        assert status.status_code == 200 and status.json()["initialized"] is False
        assert code not in status.text and SECRET not in status.text
        revision = status.json()["revision"]
        body = setup_body(revision, code)
        assert client.get("/auth/login").headers["location"] == "/account/setup"
        assert client.post("/api/v1/setup", json=body).status_code == 403
        wrong = client.post(
            "/api/v1/setup",
            headers={"Origin": BASE},
            json=setup_body(revision, "X" * 43),
        )
        assert (
            wrong.status_code == 403
            and wrong.json()["error"]["code"] == "installation_code_invalid"
        )
        response = client.post("/api/v1/setup", headers={"Origin": BASE}, json=body)
        assert (
            response.status_code == 200
            and SECRET not in response.text
            and code not in response.text
        )
        assert client.get("/api/v1/setup").json()["initialized"] is True
        assert client.get("/auth/login").headers["location"] == "/auth/login/entra"
        assert client.get("/api/v1/providers").json()["providers"][0]["id"] == "entra"
        again = client.post("/api/v1/setup", headers={"Origin": BASE}, json=body)
        assert again.status_code == 409
        with runtime.store.database.read() as conn:
            row = conn.execute(select(schema.login_providers)).mappings().one()
            assert (
                row["config_source"] == "db"
                and row["secret_ciphertext"] != SECRET.encode()
            )
            assert "secret" not in row["config"]


def test_setup_conflict_does_not_consume_operator_authority(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        revision = client.get("/api/v1/setup").json()["revision"]
        response = client.post(
            "/api/v1/setup",
            headers={"Origin": BASE},
            json=setup_body(revision + 1, code),
        )
        assert (
            response.status_code == 409
            and response.json()["error"]["code"] == "settings_conflict"
        )
        assert runtime.installation.verify(code)
        assert runtime.provider_store.load_snapshot().providers == ()


def test_failed_setup_is_globally_rate_limited(tmp_path):
    with installation(tmp_path) as (client, _runtime, _code):
        for _ in range(5):
            response = client.post(
                "/api/v1/setup", headers={"Origin": BASE}, json=setup_body(0, "X" * 43)
            )
            assert response.status_code == 403
        response = client.post(
            "/api/v1/setup", headers={"Origin": BASE}, json=setup_body(0, "X" * 43)
        )
        assert response.status_code == 429


def test_owner_edit_uses_csrf_cas_preserves_secret_and_refreshes_runtime(
    tmp_path, monkeypatch
):
    with local_stack(tmp_path, monkeypatch) as stack:
        browser = Browser(stack)
        browser.sign_in(OWNER)
        me = browser.api("GET", "/me").json()
        csrf = me["csrf_token"]
        settings = browser.api("GET", "/admin/login-providers").json()
        revision = settings["revision"]
        assert (
            SECRET not in str(settings) and settings["providers"][0]["secret_present"]
        )
        change = {"revision": revision, "config": CONFIG, "enabled": True, "rank": 0}
        assert (
            browser.api("PUT", "/admin/login-providers/entra", body=change).status_code
            == 403
        )
        saved = browser.api(
            "PUT", "/admin/login-providers/entra", body=change, csrf=csrf
        )
        assert saved.status_code == 200 and saved.json()["revision"] == revision + 1
        assert (
            stack.runtime.provider_store.load_snapshot().providers[0].client_secret
            == SECRET
        )
        assert (
            browser.api(
                "PUT", "/admin/login-providers/entra", body=change, csrf=csrf
            ).status_code
            == 409
        )
        google = {
            "revision": revision + 1,
            "config": {"client_id": "123456.apps.googleusercontent.com"},
            "enabled": True,
            "rank": 1,
            "client_secret": "google-client-secret-0123456789",
        }
        response = browser.api(
            "PUT", "/admin/login-providers/google", body=google, csrf=csrf
        )
        assert response.status_code == 200
        assert {
            entry["id"]
            for entry in stack.client.get("/api/v1/providers").json()["providers"]
        } == {"entra", "google"}
        assert account_app(stack).logins.accepted_pids == {"entra", "google"}
        change.update(revision=revision + 2, enabled=False)
        refused = browser.api(
            "PUT", "/admin/login-providers/entra", body=change, csrf=csrf
        )
        assert (
            refused.status_code == 409
            and refused.json()["error"]["code"] == "last_owner"
        )


@pytest.mark.parametrize("code", [None, 1, "", "invalid"])
def test_invalid_authority_shapes_are_closed_errors(tmp_path, code):
    with installation(tmp_path) as (client, _runtime, _issued):
        revision = client.get("/api/v1/setup").json()["revision"]
        response = client.post(
            "/api/v1/setup", headers={"Origin": BASE}, json=setup_body(revision, code)
        )
        assert (
            response.status_code == 403
            and response.json()["error"]["code"] == "installation_code_invalid"
        )


def begin_callback(stack, browser):
    start = browser.get("/auth/login/entra")
    assert start.status_code == 302
    nonce = parse_qs(urlsplit(start.headers["location"]).query)["nonce"][0]
    stack.idp.set_user(ALICE, nonce)
    return stack.idp.authorize(start.headers["location"])


def touch_provider(stack):
    providers = stack.runtime.provider_store
    return providers.save(
        "entra",
        config=CONFIG,
        client_secret=None,
        enabled=True,
        rank=0,
        revision=providers.load_snapshot().revision,
        actor=None,
        now=int(stack.clock()),
    )


def test_edit_invalidates_outstanding_login_before_token_exchange(
    tmp_path, monkeypatch
):
    with local_stack(tmp_path, monkeypatch) as stack:
        browser = Browser(stack)
        callback = begin_callback(stack, browser)
        touch_provider(stack)
        response = browser.get(callback)
        assert "error=state_invalid" in response.headers["location"]
        assert stack.idp.token_requests == 0
        assert (
            stack.store.lookup_identity(
                "entra",
                f"https://login.microsoftonline.com/{ENTRA_TENANT}/v2.0",
                ALICE.oid,
            )
            is None
        )


def test_edit_during_exchange_cannot_write_an_account_with_stale_policy(
    tmp_path, monkeypatch
):
    with local_stack(tmp_path, monkeypatch) as stack:
        browser = Browser(stack)
        callback = begin_callback(stack, browser)
        core = account_app(stack)
        provider = core.logins.providers["entra"]
        finish = provider.finish

        async def interrupted(**kwargs):
            claims = await finish(**kwargs)
            old = core.login_bundle.revision
            fresh = touch_provider(stack)
            core.login_manager.get()  # A second request publishes the new generation.
            assert fresh != old and core.login_bundle.revision == old
            return claims

        monkeypatch.setattr(provider, "finish", interrupted)
        response = browser.get(callback)
        assert "error=state_invalid" in response.headers["location"]
        assert stack.idp.token_requests == 1
        with stack.store.database.read() as conn:
            assert conn.execute(select(schema.accounts.c.id)).all() == []
            assert conn.execute(select(schema.external_identities.c.id)).all() == []
