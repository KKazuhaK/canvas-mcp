"""The authorization continuation under ``ACCOUNT_UI=react``.

The single-page UI has no consent screen yet, so the server-rendered one stays registered
next to the two server halves of the sign-in; a failed continuation reports a closed code on
the sign-in page instead of an HTML message.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from ..test_account_spa import make_dist
from .stack import ALICE, ISSUER, Browser, local_stack, pkce
from .test_authz_flows import query, start_request


@pytest.fixture
def react(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    dist = make_dist(tmp_path / "dist")
    env = {"ACCOUNT_UI": "react", "ACCOUNT_WEB_DIST": str(dist)}
    with local_stack(tmp_path / "app", monkeypatch, env=env) as stack:
        yield stack


def test_the_single_page_app_is_what_serves_the_account_pages(react) -> None:
    page = react.client.get("/account/")
    assert page.status_code == 200 and 'id="root"' in page.text
    assert react.client.get("/account/consent").status_code != 404  # ours, registered before the fallback


def test_a_request_that_is_not_this_browsers_goes_to_the_sign_in_page_with_a_closed_code(react) -> None:
    _, _, url = start_request(react)
    response = Browser(react).get(url)
    assert response.status_code == 303
    assert response.headers["location"] == "/account/sign-in?error=authorization_invalid"
    assert parse_qs(urlsplit(response.headers["location"]).query) == {"error": ["authorization_invalid"]}


def test_the_whole_flow_works_with_the_server_rendered_consent_page(react) -> None:
    browser, txn, url = start_request(react)
    login = browser.get(url)
    assert login.status_code == 302 and "login.microsoftonline.com" in login.headers["location"]
    callback = browser.entra_login(ALICE, login)
    assert callback.status_code == 303 and callback.headers["location"] == f"/account/consent?txn={txn}"
    page = browser.get(callback.headers["location"])
    assert page.status_code == 200 and "Connect this app" in page.text and 'id="root"' not in page.text
    assert "form-action" not in page.headers["content-security-policy"]
    done = browser.decide(page, "approve")
    assert done.status_code == 303 and query(done)["iss"] == [ISSUER]


def test_a_complete_connection_through_the_react_mode(react) -> None:
    react.enroll(ALICE)
    _, tokens = react.tokens_for(ALICE)
    assert react.whoami(tokens["access_token"]) == react.account_of(ALICE)
    assert pkce()[0]
