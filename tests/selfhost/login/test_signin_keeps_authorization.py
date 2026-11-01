"""A sign-in that began with a waiting app ends at that app's consent step, whichever method is used."""

from __future__ import annotations

import pathlib
from urllib.parse import parse_qs, urlsplit

import pytest

from ..spa_fixture import make_dist
from .stack_providers import ProviderStack, provider_stack
from .test_start_limit import FrozenClock

EVIL = [
    "//evil.example/x",
    "https://evil.example/",
    "/\\evil.example",
    "/account/../x",
    "/auth/login/google",
]


@pytest.fixture
def ps(tmp_path: pathlib.Path, monkeypatch: pytest.MonkeyPatch):
    env = {"ACCOUNT_WEB_DIST": str(make_dist(tmp_path / "dist"))}
    with provider_stack(
        tmp_path / "app", monkeypatch, env=env, clock=FrozenClock()
    ) as stack:
        yield stack


def _txn(login: str) -> str:
    return parse_qs(urlsplit(login).query)["txn"][0]


@pytest.mark.parametrize("provider", ["google", "github", "school"])
def test_a_provider_sign_in_with_a_waiting_app_ends_at_its_consent_step(
    ps: ProviderStack, provider: str
) -> None:
    person = ps.person()
    _client, _verifier, login = person.begin_connect()
    txn = _txn(login)
    assert person.get(login).headers["location"] == f"/account/sign-in?txn={txn}"
    start = person.start(provider, txn=txn)
    done = person.get(person.callback_url(provider, start))
    assert done.status_code == 303
    assert done.headers["location"] == f"/account/consent?txn={txn}"


@pytest.mark.parametrize("bad", EVIL)
def test_a_crafted_return_address_never_wins_over_or_beside_a_waiting_app(
    ps: ProviderStack, bad: str
) -> None:
    person = ps.person()
    _client, _verifier, login = person.begin_connect()
    txn = _txn(login)
    start = person.start("school", txn=txn, return_to=bad)
    done = person.get(person.callback_url("school", start))
    assert done.headers["location"] == f"/account/consent?txn={txn}"


@pytest.mark.parametrize("bad", EVIL)
def test_a_crafted_return_address_without_a_waiting_app_lands_on_the_account_home(
    ps: ProviderStack, bad: str
) -> None:
    person = ps.person()
    start = person.start("school", return_to=bad)
    done = person.get(person.callback_url("school", start))
    assert done.headers["location"] == "/account/"


@pytest.mark.parametrize(
    "bad",
    [
        "//evil.example/x",
        "https://evil.example/",
        "x" * 43,
        "short",
        "a" * 43 + "&return_to=//evil.example",
    ],
)
def test_a_bad_request_id_does_not_start_a_sign_in_or_redirect_anywhere(
    ps: ProviderStack, bad: str
) -> None:
    person = ps.person()
    start = person.start("school", txn=bad)
    assert start.status_code == 303
    assert start.headers["location"] == "/account/sign-in?error=authorization_invalid"


def test_a_request_id_from_another_browser_is_refused(ps: ProviderStack) -> None:
    owner, stranger = ps.person(), ps.person()
    _client, _verifier, login = owner.begin_connect()
    start = stranger.start("school", txn=_txn(login))
    assert start.status_code == 303
    assert start.headers["location"] == "/account/sign-in?error=authorization_invalid"


def test_a_request_that_expired_during_the_provider_round_trip_lands_on_the_account_home(
    ps: ProviderStack,
) -> None:
    person = ps.person()
    _client, _verifier, login = person.begin_connect()
    txn = _txn(login)
    ps.clock.advance(590)
    start = person.start("school", txn=txn)
    callback = person.callback_url("school", start)
    ps.clock.advance(20)
    done = person.get(callback)
    assert done.status_code == 303
    assert done.headers["location"] == "/account/?notice=authorization_expired"
    me = person.client.get("/api/v1/me")
    assert me.status_code == 200


def test_a_signed_in_person_with_a_waiting_app_goes_straight_to_consent(
    ps: ProviderStack,
) -> None:
    person = ps.person()
    assert person.sign_in("school").status_code == 303
    _client, _verifier, login = person.begin_connect()
    txn = _txn(login)
    assert person.get(login).headers["location"] == f"/account/consent?txn={txn}"
    assert (
        person.start("school", txn=txn).headers["location"]
        == f"/account/consent?txn={txn}"
    )
