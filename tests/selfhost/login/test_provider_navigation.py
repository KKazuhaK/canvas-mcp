"""Native React chooser navigation; presentation is covered by the frontend suite.

The retired server-rendered chooser, language toggle and identity forms have no
v1 surface. Their remaining protocol and authorization checks use React/API routes.
"""

from __future__ import annotations

from urllib.parse import parse_qs, urlsplit

import pytest

from .stack_providers import provider_stack


@pytest.fixture
def ps(tmp_path, monkeypatch):
    with provider_stack(tmp_path, monkeypatch) as running:
        yield running


@pytest.mark.parametrize("reauth", [None, "1", "yes"])
def test_chooser_preserves_only_its_browser_bound_transaction(ps, reauth):
    person = ps.person()
    _, _, login = person.begin_connect()
    txn = parse_qs(urlsplit(login).query)["txn"][0]
    params = {"txn": txn}
    if reauth is not None:
        params["reauth"] = reauth
    response = person.get("/auth/login", params=params)
    assert response.status_code == 303
    assert response.headers["cache-control"] == "no-store"
    destination = urlsplit(response.headers["location"])
    assert destination.path == "/account/sign-in"
    expected = {"txn": [txn]}
    if reauth == "1":
        expected["reauth"] = ["1"]
    assert parse_qs(destination.query) == expected
    assert person.get(response.headers["location"]).status_code == 200
    stranger = ps.person()
    rejected = stranger.get(login)
    assert rejected.status_code == 303
    assert (
        rejected.headers["location"] == "/account/sign-in?error=authorization_invalid"
    )


@pytest.mark.parametrize(
    "target", ["/account/token", "//evil.example", "/account/../x", "<script>"]
)
def test_chooser_passes_only_a_valid_local_return_target(ps, target):
    response = ps.person().get(
        "/auth/login", params={"return_to": target, "noise": "secret"}
    )
    assert response.status_code == 303
    expected = "/account/sign-in"
    if target == "/account/token":
        assert urlsplit(response.headers["location"]).path == expected
        assert parse_qs(urlsplit(response.headers["location"]).query) == {
            "return_to": [target]
        }
    else:
        assert response.headers["location"] == expected
    assert "secret" not in response.headers["location"]


def test_provider_manifest_matches_native_start_routes(ps):
    providers = ps.stack.client.get("/api/v1/providers").json()["providers"]
    assert [provider["id"] for provider in providers] == [
        "entra",
        "google",
        "github",
        "oidc:school",
    ]
    assert [provider["start_url"] for provider in providers] == [
        "/auth/login/entra",
        "/auth/login/google",
        "/auth/login/github",
        "/auth/login/oidc/school",
    ]
    assert [provider["name"] for provider in providers][:3] == [
        "Microsoft",
        "Google",
        "GitHub",
    ]
    assert all(not provider["icon"].startswith("http") for provider in providers)


@pytest.mark.parametrize("language", ["en", "zh"])
def test_refusal_uses_a_provider_neutral_closed_code(tmp_path, monkeypatch, language):
    with provider_stack(
        tmp_path,
        monkeypatch,
        policy={"ACCESS_POLICY": "rules", "ACCESS_RULES": "entra:role:Canvas.User"},
    ) as running:
        person = running.person()
        person.client.cookies.set(
            "canvas_mcp_lang", language, domain="canvas.example.test"
        )
        response = person.sign_in("github")
        assert response.status_code == 303
        assert response.headers["location"] == "/account/sign-in?error=access_denied"
        assert not person.signed_in()
