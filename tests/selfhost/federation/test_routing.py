"""Which decoder a token goes to, and where these tokens are not accepted at all."""

from __future__ import annotations

from canvas_mcp.core.selfhost.federation.config import build_issuer

from ..authz.stack import ALICE, AUDIENCE, BASE
from .issuer import FakeIssuer


def test_without_trusted_issuers_nothing_changes(open_hub):
    # Our own tokens work as ever ...
    _, tokens = open_hub.stack.tokens_for(ALICE)
    assert open_hub.status(tokens["access_token"]) == 200
    # ... a foreign token is a plain 401, and the issuer was never contacted.
    assert open_hub.status(open_hub.issuer.mint()) == 401
    assert open_hub.issuer.log == []
    assert open_hub.grants() == []
    with open_hub.stack.store.database.read() as conn:
        from sqlalchemy import text

        assert (
            conn.execute(text("SELECT count(*) FROM trusted_issuers")).scalar_one() == 0
        )


def test_our_own_token_goes_to_our_own_decoder(open_hub):
    open_hub.trust()
    _, tokens = open_hub.stack.tokens_for(ALICE)
    assert open_hub.status(tokens["access_token"]) == 200
    assert open_hub.issuer.log == []  # the trusted issuer was not consulted
    assert open_hub.grants() == []  # and no federated account or grant was made


def test_a_foreign_token_naming_this_server_as_issuer_is_not_given_to_the_issuers(
    open_hub,
):
    open_hub.trust()
    forged = open_hub.issuer.mint(iss=open_hub.stack.authz.issuer, aud=AUDIENCE)
    assert open_hub.status(forged) == 401
    assert open_hub.issuer.log == []


def test_a_token_of_an_untrusted_issuer_is_ignored(open_hub):
    open_hub.trust()
    other = FakeIssuer(
        open_hub.stack.clock, issuer="https://other.example.test", audience=AUDIENCE
    )
    assert open_hub.status(other.mint()) == 401
    assert other.log == []


def test_the_issuer_list_is_reread_so_the_cli_works_on_a_running_server(open_hub):
    clock = open_hub.stack.clock
    assert open_hub.status(open_hub.issuer.mint()) == 401
    from canvas_mcp.core.selfhost.federation.config import build_issuer

    # Added by another process (the operator command): the running server notices soon.
    open_hub.federation.store.add_issuer(build_issuer(open_hub.issuer.issuer))
    assert open_hub.status(open_hub.issuer.mint()) == 401
    clock.advance(11)
    assert open_hub.status(open_hub.issuer.mint()) == 200


class TestOnlyOnMcp:
    def test_the_token_is_not_a_web_session_nor_an_api_credential(self, open_hub):
        open_hub.trust()
        token = open_hub.issuer.mint()
        assert open_hub.status(token) == 200  # it does work on /mcp
        client = open_hub.stack.client
        headers = {"Authorization": f"Bearer {token}"}
        for path in ("/api/v1/me", "/api/v1/me/grants", "/api/v1/admin/accounts"):
            response = client.get(path, headers=headers)
            assert response.status_code == 401, path
            assert "set-cookie" not in response.headers
        # The account page's own API still sees nobody: no session was made.
        assert client.get("/api/v1/me").status_code == 401
        # A state-changing call, with the Origin of a browser, is refused the same way.
        response = client.put(
            "/api/v1/me/canvas-token",
            json={},
            headers={**headers, "Origin": "https://canvas.example.test"},
        )
        assert response.status_code in (401, 403)
        assert client.get("/api/v1/me").status_code == 401

    def test_it_is_not_accepted_on_the_browser_extension_endpoints(self, open_hub):
        open_hub.trust()
        token = open_hub.issuer.mint()
        response = open_hub.stack.client.get(
            "/api/v1/extension/plan", headers={"Authorization": f"Bearer {token}"}
        )
        assert response.status_code in (401, 403)


class TestProtectedResourceMetadata:
    PATH = "/.well-known/oauth-protected-resource/mcp"

    def _doc(self, hub):
        return hub.stack.client.get(self.PATH)

    def test_no_issuer_is_the_stock_document(self, hub):
        from ..authz.stack import ISSUER

        response = self._doc(hub)
        assert response.json()["authorization_servers"] == [ISSUER]
        assert response.headers["cache-control"] == "public, max-age=3600"

    def test_issuers_are_listed_after_this_one_as_configured(self, hub):
        from ..authz.stack import ISSUER

        stock = self._doc(hub)
        hub.federation.store.add_issuer(build_issuer("https://b.example/"))
        hub.federation.store.add_issuer(build_issuer("https://a.example"))
        hub.federation.reload()
        response = self._doc(hub)
        body = response.json()
        assert body["authorization_servers"] == [
            ISSUER,
            "https://a.example",
            "https://b.example/",
        ]
        assert {k: v for k, v in body.items() if k != "authorization_servers"} == {
            k: v for k, v in stock.json().items() if k != "authorization_servers"
        }
        assert response.headers["cache-control"] == stock.headers["cache-control"]
        assert int(response.headers["content-length"]) == len(response.content)
        cors = hub.stack.client.get(self.PATH, headers={"Origin": BASE})
        assert cors.headers["access-control-allow-origin"] == "*"

    def test_one_issuer(self, hub):
        from ..authz.stack import ISSUER

        hub.trust()
        servers = self._doc(hub).json()["authorization_servers"]
        assert servers == [ISSUER, hub.issuer.issuer]

    def test_removing_an_issuer_drops_it_after_the_ttl(self, hub):
        hub.trust()
        assert len(self._doc(hub).json()["authorization_servers"]) == 2
        hub.federation.store.remove_issuer(hub.issuer.issuer)
        assert len(self._doc(hub).json()["authorization_servers"]) == 2
        hub.stack.clock.advance(11)
        assert len(self._doc(hub).json()["authorization_servers"]) == 1
