"""Only fresh administrators rename account login names; identity ownership is retained."""

from sqlalchemy import select

from canvas_mcp.core.selfhost.login.local_accounts import LocalAccounts

from ..authz.stack import BASE
from ..authz.test_authz_schema import _grant_fields
from .test_database_login_api import installation
from .test_local_accounts import PASSWORD, initialize


def login(client, name):
    assert (
        client.post(
            "/api/v1/login/local",
            headers={"Origin": BASE},
            json={"username": name, "password": PASSWORD},
        ).status_code
        == 200
    )
    me = client.get("/api/v1/me").json()
    return me, {"Origin": BASE, "X-CSRF-Token": me["csrf_token"]}


def test_upn_is_admin_only_with_origin_csrf_cas_unique_names_and_revocation(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        me, _ = login(client, "admin")
        owner = me["account"]["id"]
        local = LocalAccounts(runtime.provider_store)
        user, _ = local.create(
            name="student", password=PASSWORD, actor=owner, revision=1, now=10
        )
        identities = runtime.store.list_identities(user)
        epoch = runtime.store.get_principal_status(user).session_epoch
        with runtime.store.database.write() as conn:
            runtime.store._repos.grants.insert(conn, **_grant_fields(user))
        route = "/api/v1/admin/accounts/" + user + "/upn"
        me, headers = login(client, "student")
        body = {"revision": 2, "upn": "renamed.student"}
        assert client.put(route, headers=headers, json=body).status_code == 403
        assert (
            client.put(
                "/api/v1/me/upn", headers=headers, json={"upn": "self.rename"}
            ).status_code
            == 404
        )
        me, headers = login(client, "admin")
        assert client.put(route, headers={"Origin": BASE}, json=body).status_code == 403
        assert (
            client.put(
                route, headers={**headers, "Origin": "https://other.test"}, json=body
            ).status_code
            == 403
        )
        assert (
            client.put(route, headers=headers, json={**body, "revision": 1}).status_code
            == 409
        )
        assert (
            client.put(
                route, headers=headers, json={**body, "upn": "ADMIN"}
            ).status_code
            == 409
        )
        assert (
            client.put(
                route, headers=headers, json={**body, "upn": "invalid name"}
            ).status_code
            == 422
        )
        response = client.put(route, headers=headers, json=body)
        assert response.status_code == 200 and response.json() == {
            "revision": 3,
            "account_id": user,
        }
        assert client.get("/api/v1/admin/settings").status_code == 200
        assert [
            (row.id, row.issuer, row.subject, row.provider_id)
            for row in runtime.store.list_identities(user)
        ] == [(row.id, row.issuer, row.subject, row.provider_id) for row in identities]
        assert runtime.store.get_principal_status(user).session_epoch == epoch + 1
        with runtime.store.database.read() as conn:
            from canvas_mcp.core.selfhost.db import schema as s

            assert (
                conn.execute(
                    select(s.oauth_grants.c.revoked_at).where(
                        s.oauth_grants.c.account_id == user
                    )
                ).scalar_one()
                is not None
            )
        assert local.authenticate("renamed.student", PASSWORD, now=11).id == user
        audit = [
            row
            for row in runtime.store.iter_audit(account_id=user)
            if row.action == "account_upn_changed"
        ]
        assert len(audit) == 1 and audit[0].actor == owner


def test_own_admin_rename_ends_old_session_and_old_login_name(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        me, headers = login(client, "admin")
        account = me["account"]["id"]
        response = client.put(
            "/api/v1/admin/accounts/" + account + "/upn",
            headers=headers,
            json={"revision": 1, "upn": "new.admin"},
        )
        assert response.status_code == 200
        assert client.get("/api/v1/me").status_code == 401
        assert (
            client.post(
                "/api/v1/login/local",
                headers={"Origin": BASE},
                json={"username": "admin", "password": PASSWORD},
            ).status_code
            == 401
        )
        login(client, "new.admin")
        assert client.get("/api/v1/admin/settings").status_code == 200
