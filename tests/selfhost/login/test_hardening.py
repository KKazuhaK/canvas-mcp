"""Regression tests for the review of the sign-in providers (one section per finding)."""

from __future__ import annotations

import pathlib

import pytest

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
