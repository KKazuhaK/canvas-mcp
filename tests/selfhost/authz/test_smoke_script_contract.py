"""The image smoke test's local-mode checks, replayed in process.

``deploy/selfhost/smoke-test.sh`` needs Docker, which CI has and a developer machine may not.
Its sections (m), (m2) and (n) check the externally visible contract of
``SELFHOST_AUTH_MODE=local`` with curl; this file replays the same requests against the same app
(``Host: 127.0.0.1:<port>`` as curl sends it) so an expectation in the script that the code does
not meet fails here, not only in the image build. ``tests/test_selfhost_docs.py`` ties the script's
text to these checks.
"""

from __future__ import annotations

import json
import pathlib
import re

import pytest

from .stack import BASE as PUBLIC_URL
from .stack import SCOPE, local_stack

SMOKE = pathlib.Path(__file__).resolve().parents[3] / "deploy" / "selfhost" / "smoke-test.sh"
BASE = "http://127.0.0.1:18819"
PUBLIC = PUBLIC_URL
UNKNOWN = "00000000-0000-4000-8000-000000000000"
CLAUDE = "https://claude.ai/api/mcp/auth_callback"
REGISTRATION = {
    "client_name": "smoke",
    "grant_types": ["authorization_code", "refresh_token"],
    "response_types": ["code"],
    "token_endpoint_auth_method": "none",
}


def test_the_script_has_the_sections_this_file_replays() -> None:
    text = SMOKE.read_text(encoding="utf-8")
    for marker in ("(m) SELFHOST_AUTH_MODE=local", "(m2) local mode with the React UI", "(n) an unknown SELFHOST_AUTH_MODE fails closed"):
        assert marker in text, marker
    assert text.index("(l) ACCOUNT_UI=react with no usable build") < text.index("(m) SELFHOST_AUTH_MODE=local")
    assert text.index("(m2)") < text.index("(n) an unknown")


@pytest.fixture
def local(tmp_path, monkeypatch):  # type: ignore[no-untyped-def]
    with local_stack(tmp_path, monkeypatch, tools=False) as stack:
        yield stack


class TestSectionM:
    def test_the_metadata(self, local) -> None:
        doc = local.client.get(f"{BASE}/.well-known/oauth-authorization-server").json()
        assert doc["issuer"] == PUBLIC + "/"
        assert doc["token_endpoint_auth_methods_supported"] == ["none"]
        assert doc["revocation_endpoint_auth_methods_supported"] == ["none"]
        assert doc["revocation_endpoint"] == PUBLIC + "/revoke"
        assert doc["code_challenge_methods_supported"] == ["S256"]
        assert doc["authorization_response_iss_parameter_supported"] is True
        assert doc["client_id_metadata_document_supported"] is True
        assert "offline_access" not in doc.get("scopes_supported", [])
        prm = local.client.get(f"{BASE}/.well-known/oauth-protected-resource/mcp").json()
        assert prm["resource"] == PUBLIC + "/mcp" and prm["authorization_servers"] == [PUBLIC + "/"]

    def test_mcp_without_a_bearer(self, local) -> None:
        response = local.client.post(
            f"{BASE}/mcp",
            content=json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}}),
            headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
        )
        assert response.status_code == 401
        assert f'resource_metadata="{PUBLIC}/.well-known/oauth-protected-resource/mcp"' in response.headers["www-authenticate"]

    def test_registration(self, local) -> None:
        evil = local.client.post(f"{BASE}/register", json={**REGISTRATION, "redirect_uris": ["https://evil.example/cb"]})
        assert evil.status_code == 400 and "invalid_redirect_uri" in evil.text
        good = local.client.post(f"{BASE}/register", json={**REGISTRATION, "redirect_uris": [CLAUDE]})
        assert good.status_code == 201
        doc = good.json()
        assert doc.get("client_secret") in (None, "") and doc["token_endpoint_auth_method"] == "none"

    def test_revoke(self, local) -> None:
        client_id = local.client.post(f"{BASE}/register", json={**REGISTRATION, "redirect_uris": [CLAUDE]}).json()["client_id"]
        post = local.client.post
        no_client = post(f"{BASE}/revoke", data={"token": "garbage"})
        assert no_client.status_code == 401
        unknown = post(f"{BASE}/revoke", data={"client_id": UNKNOWN, "token": "garbage"})
        assert unknown.status_code == 401 and "invalid_client" in unknown.text
        assert post(f"{BASE}/revoke", data={"client_id": client_id}).status_code == 400
        assert post(f"{BASE}/revoke", data={"client_id": client_id, "token": "garbage"}).status_code == 200

    def test_token_for_an_unknown_client(self, local) -> None:
        response = local.client.post(
            f"{BASE}/token",
            data={
                "grant_type": "authorization_code", "code": "cmcp_ac_nope", "client_id": UNKNOWN,
                "redirect_uri": CLAUDE, "code_verifier": "a" * 44,
            },
        )
        assert response.status_code == 401 and "invalid_client" in response.text

    def test_authorize_for_an_unknown_client(self, local) -> None:
        response = local.client.get(
            f"{BASE}/authorize",
            params={
                "response_type": "code", "client_id": UNKNOWN, "redirect_uri": CLAUDE,
                "code_challenge": "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", "code_challenge_method": "S256",
                "state": "smoke",
            },
        )
        assert response.status_code == 400 and "location" not in response.headers

    def test_a_sign_in_request_that_does_not_exist(self, local) -> None:
        response = local.client.get(f"{BASE}/account/login?txn=bogus")
        assert response.status_code == 400 and "location" not in response.headers
        assert "opened in another browser" in response.text

    @pytest.mark.parametrize("path", ["/consent", "/auth/callback", "/.well-known/openid-configuration"])
    def test_the_proxys_routes_are_not_served(self, local, path: str) -> None:
        assert local.client.get(f"{BASE}{path}").status_code == 404


class TestSectionM2:
    @pytest.fixture
    def stack(self, tmp_path, monkeypatch, react_env):  # type: ignore[no-untyped-def]
        with local_stack(tmp_path / "m2", monkeypatch, env={**react_env, "CIMD_ENABLED": "false"}, tools=False) as stack:
            yield stack

    def test_the_metadata_does_not_advertise_client_metadata_documents(self, stack) -> None:
        doc = stack.client.get(f"{BASE}/.well-known/oauth-authorization-server").json()
        assert "client_id_metadata_document_supported" not in doc
        assert doc["token_endpoint_auth_methods_supported"] == ["none"]

    def test_a_bad_sign_in_request_ends_on_the_sign_in_page(self, stack) -> None:
        response = stack.client.get(f"{BASE}/account/login?txn=bogus")
        assert response.status_code == 303
        assert "/account/sign-in?error=authorization_invalid" in response.headers["location"]

    def test_the_consent_screen_is_the_app_and_its_api_wants_a_session(self, stack) -> None:
        txn = "A" * 43
        page = stack.client.get(f"{BASE}/account/consent?txn={txn}")
        assert page.status_code == 200 and 'id="root"' in page.text and 'name="decision"' not in page.text
        for path in (f"/account/api/consent?txn={txn}", "/account/api/me/grants"):
            response = stack.client.get(f"{BASE}{path}")
            assert response.status_code == 401 and "not_authenticated" in response.text


class TestSectionN:
    @pytest.mark.parametrize(
        "extra",
        [{"SELFHOST_AUTH_MODE": "bogus"}, {"SELFHOST_AUTH_MODE": "local", "ACCESS_TOKEN_TTL": "1"}],
    )
    def test_a_bad_value_stops_the_server(self, tmp_path, monkeypatch, extra) -> None:
        from canvas_mcp.core.selfhost.settings import SelfhostConfigError

        with pytest.raises(SelfhostConfigError) as raised:
            with local_stack(tmp_path, monkeypatch, env=extra):
                pass
        assert "SELFHOST_AUTH_MODE" in str(raised.value) or "ACCESS_TOKEN_TTL" in str(raised.value)

    def test_the_script_exercises_exactly_these_two_values(self) -> None:
        text = SMOKE.read_text(encoding="utf-8")
        assert re.search(r"-e SELFHOST_AUTH_MODE=bogus", text) and "ACCESS_TOKEN_TTL=1" in text
        assert SCOPE
