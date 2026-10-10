"""The authorization continuation under ``ACCOUNT_UI=react``.

The single-page UI owns the consent screen and the connected apps (it talks to the JSON API,
see ``test_account_api_authz.py``); the server keeps the two halves of the sign-in. A failed
continuation reports a closed code on the sign-in page instead of an HTML message.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

from .stack import ALICE, ISSUER, Browser, Stack
from .test_authz_flows import start_request


def test_the_single_page_app_is_what_serves_the_account_pages(react_stack: Stack) -> None:
    page = react_stack.client.get("/account/")
    assert page.status_code == 200 and 'id="root"' in page.text
    # the consent screen is a page of the app now: the server renders no form of its own
    consent = react_stack.client.get("/account/consent?txn=" + "A" * 43)
    assert consent.status_code == 200 and 'id="root"' in consent.text
    assert 'name="decision"' not in consent.text and "form-action 'self'" in consent.headers["content-security-policy"]
    assert react_stack.client.post("/account/consent", data={}, headers={"Origin": "https://canvas.example.test"}).status_code in (404, 405)
    assert react_stack.client.post("/account/grants/revoke", data={}, headers={"Origin": "https://canvas.example.test"}).status_code in (404, 405)


def test_a_request_that_is_not_this_browsers_goes_to_the_sign_in_page_with_a_closed_code(react_stack: Stack) -> None:
    _, _, url = start_request(react_stack)
    response = Browser(react_stack, react=True).get(url)
    assert response.status_code == 303
    assert response.headers["location"] == "/account/sign-in?error=authorization_invalid"
    assert parse_qs(urlsplit(response.headers["location"]).query) == {"error": ["authorization_invalid"]}


def test_the_sign_in_continues_to_the_apps_consent_screen_and_the_api_decides(react_stack: Stack) -> None:
    browser, txn, url = start_request(react_stack, Browser(react_stack, react=True))
    login = browser.get(url)
    assert login.status_code == 302 and "login.microsoftonline.com" in login.headers["location"]
    callback = browser.entra_login(ALICE, login)
    assert callback.status_code == 303 and callback.headers["location"] == f"/account/consent?txn={txn}"
    page = browser.get(callback.headers["location"])
    assert page.status_code == 200 and 'id="root"' in page.text and 'name="decision"' not in page.text
    landed = browser.decide_api(callback.headers["location"], "approve")
    assert landed.query["iss"] == ISSUER and "code" in landed.query


def test_a_session_that_already_exists_goes_straight_to_the_consent_screen(react_stack: Stack) -> None:
    browser = Browser(react_stack, react=True)
    browser.sign_in(ALICE)
    _, txn, url = start_request(react_stack, browser)
    response = browser.get(url)
    assert response.status_code == 303 and response.headers["location"] == f"/account/consent?txn={txn}"


def test_a_complete_connection_through_the_react_mode(react_stack: Stack) -> None:
    react_stack.enroll(ALICE)
    _, tokens = react_stack.tokens_for(ALICE)
    assert react_stack.whoami(tokens["access_token"]) == react_stack.account_of(ALICE)
