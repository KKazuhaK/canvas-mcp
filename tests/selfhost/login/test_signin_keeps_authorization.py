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


NOTICE_HOME = "/account/?notice=authorization_unavailable"
BINDING = "__Host-cmcp_bind"


def _forget_binding(person) -> None:
    """What a browser does when the binding cookie's 600 s are over."""
    person.client.cookies.delete(BINDING)


@pytest.mark.parametrize(
    "bad",
    [
        "//evil.example/x",
        "https://evil.example/",
        "x" * 43,
        "short",
        "a" * 43 + "&return_to=//evil.example",
        "A" * 500,
    ],
)
def test_an_unusable_request_id_never_blocks_the_sign_in_or_redirects_anywhere(
    ps: ProviderStack, bad: str
) -> None:
    person = ps.person()
    start = person.start("school", txn=bad, return_to="/account/schools")
    assert start.status_code == 302
    done = person.get(person.callback_url("school", start))
    # The notice wins over the return address, and nothing is followed.
    assert done.status_code == 303 and done.headers["location"] == NOTICE_HOME
    assert person.client.get("/api/v1/me").status_code == 200


def test_a_request_id_from_another_browser_is_dropped_with_a_notice(
    ps: ProviderStack,
) -> None:
    owner, stranger = ps.person(), ps.person()
    _client, _verifier, login = owner.begin_connect()
    start = stranger.start("school", txn=_txn(login))
    done = stranger.get(stranger.callback_url("school", start))
    assert done.headers["location"] == NOTICE_HOME


def test_a_request_that_expired_before_the_sign_in_ended_lands_on_the_notice_without_its_cookie(
    ps: ProviderStack,
) -> None:
    person = ps.person()
    _client, _verifier, login = person.begin_connect()
    txn = _txn(login)
    ps.clock.advance(590)
    start = person.start("school", txn=txn)
    callback = person.callback_url("school", start)
    ps.clock.advance(20)
    _forget_binding(person)
    done = person.get(callback)
    assert done.status_code == 303 and done.headers["location"] == NOTICE_HOME
    assert person.client.get("/api/v1/me").status_code == 200


def test_a_sign_in_that_starts_long_after_the_request_expired_ends_on_the_notice(
    ps: ProviderStack,
) -> None:
    """The production case: the person signs in 57 minutes after the app asked."""
    person = ps.person()
    _client, _verifier, login = person.begin_connect()
    txn = _txn(login)
    ps.clock.advance(57 * 60)
    _forget_binding(person)
    chooser = person.get(login)
    assert chooser.headers["location"] == "/account/sign-in?notice=authorization_unavailable"
    # The sign-in page of the single-page app still carries the stale id on its links.
    start = person.start("school", txn=txn)
    assert start.status_code == 302
    done = person.get(person.callback_url("school", start))
    assert done.headers["location"] == NOTICE_HOME


def test_a_signed_in_person_with_an_unusable_request_goes_to_the_notice(
    ps: ProviderStack,
) -> None:
    person = ps.person()
    assert person.sign_in("school").status_code == 303
    _client, _verifier, login = person.begin_connect()
    _forget_binding(person)
    ps.clock.advance(601)
    assert person.get(login).headers["location"] == NOTICE_HOME


def test_consent_still_needs_a_live_request_of_this_browser(ps: ProviderStack) -> None:
    person = ps.person()
    _client, _verifier, login = person.begin_connect()
    txn = _txn(login)
    assert person.sign_in("school").status_code == 303
    _forget_binding(person)
    shown = person.client.get("/api/v1/consent", params={"txn": txn})
    assert shown.status_code != 200


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


def test_a_live_request_whose_binding_cookie_was_lost_ends_on_the_notice_not_consent(
    ps: ProviderStack,
) -> None:
    person = ps.person()
    _client, _verifier, login = person.begin_connect()
    txn = _txn(login)
    start = person.start("school", txn=txn)
    callback = person.callback_url("school", start)
    _forget_binding(person)  # no clock advance: the request itself is still live
    done = person.get(callback)
    assert done.headers["location"] == NOTICE_HOME


def test_the_chooser_keeps_a_request_for_another_account_when_it_drops_the_request(
    ps: ProviderStack,
) -> None:
    person = ps.person()
    assert person.sign_in("school").status_code == 303
    _client, _verifier, login = person.begin_connect()
    _forget_binding(person)
    chooser = person.get(login + "&reauth=1&return_to=/account/schools")
    assert chooser.headers["location"] == (
        "/account/sign-in?notice=authorization_unavailable&reauth=1"
    )
