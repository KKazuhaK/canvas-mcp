"""Regression tests for the review of the sign-in providers (one section per finding)."""

from __future__ import annotations

import pathlib

import pytest
from dbbackend import raw_sql

from .fake_idp import GitHubUser
from .stack_providers import provider_stack
from .test_entra_only_golden import account_app

# -- the iss requirement survives a restart between the start and the callback ------------------


def test_a_missing_iss_is_refused_after_a_restart_when_the_provider_advertises_rfc9207(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with provider_stack(tmp_path, monkeypatch) as ps:
        ps.school.iss_param = True
        app = account_app(ps.stack)
        assert app.logins is not None
        school = app.logins.providers["oidc:school"]
        person = ps.person()
        start = person.start("school")
        assert school.requires_iss() is True
        # A restart: the flow record is in the database, the discovery snapshot is not.
        school.discovery._snapshot = None
        done = person.get(person.callback_url("school", start, iss=None))
        assert done.status_code == 400
        assert not person.signed_in()
        assert ps.school.counts["token"] == 0


def test_a_provider_that_cannot_be_reached_at_the_callback_fails_closed(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with provider_stack(tmp_path, monkeypatch) as ps:
        ps.school.iss_param = True
        app = account_app(ps.stack)
        assert app.logins is not None
        school = app.logins.providers["oidc:school"]
        person = ps.person()
        start = person.start("school")
        callback = person.callback_url("school", start, iss=None)
        school.discovery._snapshot = None
        ps.school.discovery_overrides = {"issuer": "https://elsewhere.example"}
        done = person.get(callback)
        assert done.status_code == 502
        assert not person.signed_in()
        assert ps.school.counts["token"] == 0


def test_a_correct_iss_after_a_restart_still_signs_in(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with provider_stack(tmp_path, monkeypatch) as ps:
        ps.school.iss_param = True
        app = account_app(ps.stack)
        assert app.logins is not None
        person = ps.person()
        start = person.start("school")
        app.logins.providers["oidc:school"].discovery._snapshot = None
        assert person.get(person.callback_url("school", start)).status_code == 303
        assert person.signed_in()


# -- an unknown membership does not end the connected apps ---------------------------------------


def _connected(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):  # noqa: ANN202
    policy = {"ACCESS_POLICY": "rules", "ACCESS_RULES": "github:org:acme"}
    return provider_stack(tmp_path, monkeypatch, policy=policy, providers="github")


def _revocations(ps) -> list[tuple[str | None, str | None]]:  # noqa: ANN001
    return [tuple(r) for r in raw_sql(ps.store, "SELECT revoked_reason, revoked_by FROM oauth_grants")]


def test_a_restricted_membership_lookup_refuses_the_sign_in_but_keeps_the_grants(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _connected(tmp_path, monkeypatch) as ps:
        ps.github.user = GitHubUser(orgs={"acme": "active"})
        landed, client_id, verifier = (person := ps.person()).connect("github")
        access = person.tokens(landed, client_id, verifier)["access_token"]
        assert ps.stack.mcp_status(access) == 200
        ps.github.user = GitHubUser(orgs={"acme": 403})  # OAuth App access restrictions
        assert ps.person().sign_in("github").status_code == 403
        assert _revocations(ps) == [(None, None)]
        assert ps.stack.mcp_status(access) == 200


def test_a_rate_limited_membership_lookup_is_a_provider_error_and_keeps_the_grants(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _connected(tmp_path, monkeypatch) as ps:
        ps.github.user = GitHubUser(orgs={"acme": "active"})
        landed, client_id, verifier = (person := ps.person()).connect("github")
        access = person.tokens(landed, client_id, verifier)["access_token"]
        ps.github.membership_override = (403, {"x-ratelimit-remaining": "0"})
        assert ps.person().sign_in("github").status_code == 502
        assert _revocations(ps) == [(None, None)]
        assert ps.stack.mcp_status(access) == 200


def test_a_real_loss_of_membership_still_ends_the_connected_apps(
    tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    with _connected(tmp_path, monkeypatch) as ps:
        ps.github.user = GitHubUser(orgs={"acme": "active"})
        landed, client_id, verifier = (person := ps.person()).connect("github")
        access = person.tokens(landed, client_id, verifier)["access_token"]
        ps.github.user = GitHubUser(orgs={})  # 404: no longer a member
        assert ps.person().sign_in("github").status_code == 403
        assert _revocations(ps) == [("admission_lost", "system")]
        assert ps.stack.mcp_status(access) == 401
