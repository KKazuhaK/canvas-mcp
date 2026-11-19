"""An in-process OAuth issuer: RFC 8414 metadata, a JWKS, and signed access tokens.

Nothing touches the network: :attr:`FakeIssuer.transport` is handed to the server's outbound
client, and every request to the issuer lands in :meth:`FakeIssuer._handle`.
"""

from __future__ import annotations

import base64
import json
from collections.abc import Callable
from typing import Any

import httpx
from joserfc import jwt
from joserfc.jwk import ECKey, OctKey

ISSUER = "https://hub.example.test"
JWKS_URI = ISSUER + "/jwks.json"
METADATA_PATH = "/.well-known/oauth-authorization-server"


def b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


class FakeIssuer:
    """Signs with ES256 by default; keys can be added and removed to model rotation."""

    def __init__(
        self,
        clock: Callable[[], float],
        *,
        issuer: str = ISSUER,
        audience: str = "https://canvas.example.test/mcp",
    ) -> None:
        self.clock = clock
        self.issuer = issuer
        self.audience = audience
        self.keys: dict[str, ECKey] = {}
        self.add_key("k1")
        self.metadata_issuer = issuer
        self.log: list[str] = []
        self.transport = httpx.MockTransport(self._handle)

    # -- keys -----------------------------------------------------------------------------

    def add_key(self, kid: str) -> ECKey:
        key = ECKey.generate_key("P-256", parameters={"kid": kid, "use": "sig"})
        self.keys[kid] = key
        return key

    def retire(self, kid: str) -> None:
        del self.keys[kid]

    def jwks(self) -> dict[str, Any]:
        return {"keys": [key.as_dict(private=False) for key in self.keys.values()]}

    # -- the issuer's endpoints -------------------------------------------------------------

    def _handle(self, request: httpx.Request) -> httpx.Response:
        self.log.append(request.url.path)
        if request.url.path.startswith(METADATA_PATH):
            return httpx.Response(
                200,
                json={
                    "issuer": self.metadata_issuer,
                    "jwks_uri": f"{self.issuer}/jwks.json",
                },
            )
        if request.url.path == "/jwks.json":
            return httpx.Response(200, json=self.jwks())
        return httpx.Response(404)

    def fetches(self, path: str = "/jwks.json") -> int:
        return self.log.count(path)

    # -- tokens -----------------------------------------------------------------------------

    def claims(self, **overrides: Any) -> dict[str, Any]:
        now = int(self.clock())
        claims: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.audience,
            "sub": "user-1",
            "iat": now,
            "exp": now + 600,
            "scope": "canvas",
        }
        claims.update(overrides)
        return {k: v for k, v in claims.items() if v is not None}

    def mint(
        self,
        *,
        kid: str = "k1",
        alg: str = "ES256",
        typ: str | None = "at+jwt",
        key: Any = None,
        header: dict[str, Any] | None = None,
        **claims: Any,
    ) -> str:
        head: dict[str, Any] = {"alg": alg, "kid": kid}
        if typ is not None:
            head["typ"] = typ
        head.update(header or {})
        return jwt.encode(
            head,
            self.claims(**claims),
            key or self.keys[kid],
            algorithms=[alg],
        )

    def hs256_with_public_key(self, **claims: Any) -> str:
        """The key-confusion attack: HS256 whose secret is the issuer's public key."""
        secret = json.dumps(self.keys["k1"].as_dict(private=False)).encode()
        return jwt.encode(
            {"alg": "HS256", "typ": "at+jwt", "kid": "k1"},
            self.claims(**claims),
            OctKey.import_key(secret),
            algorithms=["HS256"],
        )

    def unsigned(self, **claims: Any) -> str:
        head = b64(json.dumps({"alg": "none", "typ": "at+jwt", "kid": "k1"}).encode())
        body = b64(json.dumps(self.claims(**claims)).encode())
        return f"{head}.{body}."
