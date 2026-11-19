"""The account page shows a federated connection read-only; clean-up keeps what the operator ended."""

from __future__ import annotations

from sqlalchemy import text

from canvas_mcp.core.selfhost.maintenance import MaintenanceRunner

from ..authz.stack import ALICE, Browser
from .issuer import ISSUER


def signed_in(hub, user=ALICE) -> Browser:
    browser = Browser(hub.stack, react=True)
    browser.sign_in(user)
    return browser


def linked_alice(hub) -> str:
    alice = hub.stack.enroll(ALICE)
    hub.federation.store.link(alice, ISSUER, "hub-alice")
    return alice


def test_the_grant_is_listed_as_via_the_issuer(open_hub):
    open_hub.trust(name="MCPHub")
    linked_alice(open_hub)
    assert open_hub.status(open_hub.issuer.mint(sub="hub-alice")) == 200
    grants = signed_in(open_hub).api("GET", "/me/grants").json()["grants"]
    assert len(grants) == 1
    assert grants[0]["federated"] == {"issuer_name": "MCPHub"}
    assert grants[0]["client"]["verified"] is False


def test_the_person_cannot_end_it_from_the_account_page(open_hub):
    open_hub.trust(name="MCPHub")
    linked_alice(open_hub)
    token = open_hub.issuer.mint(sub="hub-alice")
    assert open_hub.status(token) == 200
    browser = signed_in(open_hub)
    grant = browser.api("GET", "/me/grants").json()["grants"][0]["id"]
    response = browser.api("DELETE", f"/me/grants/{grant}", csrf=browser.csrf_token())
    assert response.status_code == 404
    assert open_hub.status(token) == 200


def test_cleanup_keeps_a_federated_grant_the_operator_ended(open_hub):
    open_hub.trust()
    assert open_hub.status(open_hub.issuer.mint()) == 200
    database = open_hub.stack.store.database
    with database.write() as conn:
        conn.execute(
            text(
                "UPDATE oauth_grants SET revoked_at = 1, revoked_reason = 'operator_revoked' "
                "WHERE client_id LIKE 'federated:%'"
            )
        )
    runner = MaintenanceRunner(database, cimd_stale_max=86400, now=open_hub.stack.clock)
    for job in runner.jobs(int(open_hub.stack.clock())):
        if job.name in ("revoked_grants", "expired_grants"):
            with database.write() as conn:
                from sqlalchemy import delete

                conn.execute(delete(job.table).where(job.due))
    with database.read() as conn:
        assert (
            conn.execute(
                text(
                    "SELECT count(*) FROM oauth_grants WHERE client_id LIKE 'federated:%'"
                )
            ).scalar_one()
            == 1
        )
