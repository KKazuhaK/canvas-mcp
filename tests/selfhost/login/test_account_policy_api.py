"""Owner, CSRF, revision and last-owner guards on the public policy routes."""

from ..authz.stack import BASE
from .test_database_login_api import installation
from .test_local_accounts import PASSWORD, initialize


def login(client):
    response = client.post(
        "/api/v1/login/local",
        headers={"Origin": BASE},
        json={"username": "admin", "password": PASSWORD},
    )
    assert response.status_code == 200
    me = client.get("/api/v1/me").json()
    return me, {"Origin": BASE, "X-CSRF-Token": me["csrf_token"]}


def test_policy_write_requires_origin_csrf_and_revision_and_ends_sessions(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        me, headers = login(client)
        policy = {
            "allow_multiple": True,
            "lock_first_sso": True,
            "block_conflicting_registration": True,
        }
        before = client.get("/api/v1/admin/settings/login-policy").json()
        body = {"revision": before["revision"], "policy": policy}
        for bad_headers in (
            {"Origin": BASE},
            {**headers, "Origin": "https://attacker.test"},
        ):
            assert (
                client.put(
                    "/api/v1/admin/settings/login-policy",
                    headers=bad_headers,
                    json=body,
                ).status_code
                == 403
            )
        assert (
            client.put(
                "/api/v1/admin/settings/login-policy",
                headers=headers,
                json={**body, "revision": before["revision"] + 1},
            ).status_code
            == 409
        )
        saved = client.put(
            "/api/v1/admin/settings/login-policy", headers=headers, json=body
        )
        assert saved.status_code == 200 and saved.json()["policy"] == policy
        assert client.get("/api/v1/me").status_code == 401
        assert (
            runtime.store.get_principal_status(me["account"]["id"]).session_epoch == 1
        )


def test_last_local_administrator_cannot_disallow_its_only_method(tmp_path):
    with installation(tmp_path) as (client, _runtime, code):
        assert initialize(client, code).status_code == 200
        me, headers = login(client)
        route = "/api/v1/admin/accounts/" + me["account"]["id"] + "/login-policy"
        before = client.get(route).json()
        refused = client.put(
            route,
            headers=headers,
            json={
                "revision": before["revision"],
                "policy": {"allow_multiple": None, "allowed_providers": []},
            },
        )
        assert (
            refused.status_code == 409
            and refused.json()["error"]["code"] == "last_local_owner"
        )
        assert client.get(route).json() == before
        assert client.get("/api/v1/me").status_code == 200
        assert (
            client.get("/api/v1/admin/accounts/not-a-uuid/login-policy").status_code
            == 422
        )
