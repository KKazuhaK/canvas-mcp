"""``GET /api/v1/readiness`` accepts exactly the tokens ``/mcp`` accepts, federated ones included.

MCPHub is a trusted issuer: its tokens work on ``/mcp``, so a 401 here would show every
user as "revoked" for ever. Both endpoints are asked the same question on the same state.
"""

from __future__ import annotations

from sqlalchemy import text

from canvas_mcp.core.selfhost.custody import CustodyAcknowledgement

from ..authz.stack import AUDIENCE, CANVAS_HOST
from .issuer import FakeIssuer
from .test_accounts import refusal_of

PATH = "/api/v1/readiness"


def readiness(hub, token):
    headers = {"Accept": "application/json"}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return hub.stack.client.get(PATH, headers=headers)


def enroll(hub, account: str) -> None:
    hub.stack.store.put(
        principal_key=account,
        api_token="canvas-pat-federated-0123456789abcdef",
        canvas_user_id="9",
        canvas_user_name="Hub User",
        canvas_host=CANVAS_HOST,
        custody=CustodyAcknowledgement(1, int(hub.stack.clock())),
    )


def test_a_federated_token_of_a_new_person_is_needs_setup(open_hub):
    open_hub.trust()
    token = open_hub.issuer.mint()
    assert open_hub.status(token) == 200
    response = readiness(open_hub, token)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["state"] == "needs_setup"
    assert body["action"]["url"] == "https://canvas.example.test/account/token"


def test_a_federated_token_works_before_the_account_exists(open_hub):
    # Readiness is the first call the hub makes: it creates the account like /mcp does.
    open_hub.trust()
    response = readiness(open_hub, open_hub.issuer.mint())
    assert response.status_code == 200, response.text
    assert response.json()["state"] == "needs_setup"
    assert len(open_hub.accounts()) == 1


def test_a_federated_token_with_a_saved_canvas_token_is_ready(open_hub):
    open_hub.trust()
    token = open_hub.issuer.mint()
    assert open_hub.status(token) == 200
    (account,) = open_hub.accounts()
    enroll(open_hub, account)
    assert readiness(open_hub, token).json()["state"] == "ready"
    assert open_hub.status(token) == 200


def test_a_federated_token_sees_only_its_own_account(open_hub):
    open_hub.trust()
    first = open_hub.issuer.mint(sub="user-1")
    second = open_hub.issuer.mint(sub="user-2")
    assert open_hub.status(first) == 200 and open_hub.status(second) == 200
    accounts = open_hub.accounts()
    assert len(accounts) == 2
    with open_hub.stack.store.database.read() as conn:
        rows = conn.execute(
            text("SELECT account_id FROM oauth_grants WHERE client_id LIKE 'federated:%'")
        ).all()
    assert len(rows) == 2
    # Whoever owns the first grant is the only one that gets a token state.
    enroll(open_hub, str(rows[0][0]))
    states = {readiness(open_hub, t).json()["state"] for t in (first, second)}
    assert states == {"ready", "needs_setup"}


def test_a_token_of_an_untrusted_issuer_is_401_like_mcp(open_hub):
    open_hub.trust()
    other = FakeIssuer(
        open_hub.stack.clock, issuer="https://other.example.test", audience=AUDIENCE
    )
    token = other.mint()
    assert open_hub.status(token) == 401
    assert readiness(open_hub, token).status_code == 401


def test_an_expired_federated_token_is_401_like_mcp(open_hub):
    open_hub.trust()
    now = int(open_hub.stack.clock())
    token = open_hub.issuer.mint(iat=now - 1200, exp=now - 600)
    assert open_hub.status(token) == 401
    assert readiness(open_hub, token).status_code == 401


def test_a_federated_token_for_another_audience_is_401_like_mcp(open_hub):
    open_hub.trust()
    token = open_hub.issuer.mint(aud="https://elsewhere.example.test/mcp")
    assert open_hub.status(token) == 401
    assert readiness(open_hub, token).status_code == 401


def test_a_verified_person_the_server_does_not_admit_is_403_like_mcp(hub):
    # The default policy admits Entra roles only: a stranger's valid token is refused.
    hub.trust()
    token = hub.issuer.mint()
    assert hub.status(token) == 403
    response = readiness(hub, token)
    assert response.status_code == 403
    assert "state" not in response.text
    # The very message /mcp refuses with.
    assert response.json()["error"] == {
        "code": "forbidden",
        "message": refusal_of(hub.call(token)),
    }
    assert hub.accounts() == []


def test_a_federated_token_stops_working_when_the_grant_is_revoked(open_hub):
    import asyncio

    open_hub.trust()
    token = open_hub.issuer.mint()
    assert readiness(open_hub, token).status_code == 200
    (_, client_id), = open_hub.grants()
    with open_hub.stack.store.database.read() as conn:
        grant = str(
            conn.execute(
                text("SELECT id FROM oauth_grants WHERE client_id = :c"), {"c": client_id}
            ).scalar_one()
        )
    assert asyncio.run(open_hub.stack.authz.grants.revoke_by_client(grant))
    refused = open_hub.status(token)
    assert refused in (401, 403)
    assert readiness(open_hub, token).status_code == refused
