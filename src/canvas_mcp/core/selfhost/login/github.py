"""GitHub sign-in (an OAuth App; plain OAuth 2.0, not OpenID Connect).

GitHub's access token is opaque, so the identity comes from the REST API, and the token lives
only inside :meth:`GitHubLoginProvider.finish`: it is used for at most a handful of calls
(``/user``, ``/user/emails`` and the organisation or team membership lookups the admission
rules need) and then dropped. It is never stored, logged, sealed into a cookie or put in an
exception, and it is not used again after the callback.

Facts this relies on (GitHub's documentation):

* the identity key is the numeric ``id`` of ``GET /user`` (logins can be renamed);
* the authorization request supports PKCE with ``S256`` only; ``prompt=select_account`` shows
  the account picker; scopes are space separated; the user can edit them, so the scopes in the
  token response (not the requested ones) say what the token can do;
* the token endpoint answers with a JSON body that carries ``error`` (status 200) when it fails;
* ``user:email`` unlocks ``GET /user/emails`` (``primary`` and ``verified`` flags);
* ``GET /user/memberships/orgs/{org}`` gives ``state`` ``active`` or ``pending`` (404 when the
  person is not affiliated; 403 when an organisation's OAuth App access restrictions block the
  app); the team lookup needs ``read:org`` and counts members of child teams.

``read:org`` is requested only when an ``ACCESS_RULES`` ``github:org`` or ``github:team`` rule
exists. A lookup that cannot be answered sets ``membership_unavailable`` (the person is then
refused unless another rule admits them: fail closed).
"""

from __future__ import annotations

import logging
import string
import urllib.parse
from collections.abc import Mapping
from typing import Any

from ..accounts import GITHUB_ISSUER, PROVIDER_GITHUB, ExternalClaims
from .config import GitHubConfig
from .http import CAP_GITHUB, CAP_TOKEN, HttpResult, SafeHttp, UpstreamError
from .oidc import clean_text
from .protocol import ProviderDisplay, SignInRejected

logger = logging.getLogger("canvas_mcp.selfhost.login")

GITHUB_START_PATH = "/account/login/github"
GITHUB_CALLBACK_PATH = "/account/callback/github"
AUTHORIZE_URL = "https://github.com/login/oauth/authorize"
TOKEN_URL = "https://github.com/login/oauth/access_token"
API = "https://api.github.com"
API_VERSION = "2026-03-10"

_ORG_SCOPES = frozenset({"read:org", "write:org", "admin:org"})
_EMAIL_SCOPES = frozenset({"user:email", "user"})
_LOGIN_OK = frozenset(string.ascii_letters + string.digits + "-")
_MAX_LOGIN = 39


def _is_login(value: Any) -> bool:
    return isinstance(value, str) and 0 < len(value) <= _MAX_LOGIN and set(value) <= _LOGIN_OK


class GitHubLoginProvider:
    """GitHub as a sign-in provider."""

    id = PROVIDER_GITHUB
    kind = "oauth2"
    display = ProviderDisplay("GitHub", "github")
    start_path = GITHUB_START_PATH
    callback_path = GITHUB_CALLBACK_PATH
    #: GitHub's authorization response has no ``iss`` (RFC 9207 is not offered).
    response_issuer = None

    def __init__(
        self,
        config: GitHubConfig,
        *,
        public_base_url: str,
        http: SafeHttp,
        orgs: tuple[str, ...] = (),
        teams: tuple[str, ...] = (),
    ) -> None:
        self._client_id = config.client_id
        self._client_secret = config.client_secret
        self._http = http
        self._orgs = orgs
        self._teams = teams
        self.redirect_uri = public_base_url.rstrip("/") + GITHUB_CALLBACK_PATH

    def __repr__(self) -> str:
        return "GitHubLoginProvider()"

    @property
    def wants_membership(self) -> bool:
        return bool(self._orgs or self._teams)

    async def prepare(self) -> None:
        """GitHub's endpoints are fixed: there is nothing to discover."""

    def requires_iss(self) -> bool:
        return False

    def authorize_url(
        self, *, state: str, nonce: str, code_challenge: str, reauth: bool
    ) -> str:
        scope = "user:email" + (" read:org" if self.wants_membership else "")
        params = {
            "client_id": self._client_id,
            "redirect_uri": self.redirect_uri,
            "scope": scope,
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        if reauth:
            params["prompt"] = "select_account"
        return AUTHORIZE_URL + "?" + urllib.parse.urlencode(params)

    # -- the callback ---------------------------------------------------------------------------

    async def finish(self, *, code: str, code_verifier: str, nonce: str) -> ExternalClaims:
        token, granted = await self._exchange(code, code_verifier)
        try:
            return await self._identity(token, granted)
        except UpstreamError as exc:
            logger.warning(
                "provider sign-in failed provider=github step=api code=%s status=%s",
                exc.code, exc.status,
            )
            raise SignInRejected("provider_error") from None

    async def _exchange(self, code: str, verifier: str) -> tuple[str, frozenset[str]]:
        form = {
            "client_id": self._client_id,
            "client_secret": self._client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": verifier,
        }
        try:
            result = await self._http.post_form(TOKEN_URL, form, max_bytes=CAP_TOKEN)
        except UpstreamError as exc:
            logger.warning(
                "provider sign-in failed provider=github step=token code=%s status=%s",
                exc.code, exc.status,
            )
            raise SignInRejected("provider_error") from None
        body: Mapping[str, Any] = result.body
        token = body.get("access_token")
        if "error" in body or not isinstance(token, str) or not token:
            error = body.get("error")
            logger.warning(
                "provider sign-in failed provider=github step=token reason=%s",
                error if isinstance(error, str) and error.replace("_", "").isalpha() and len(error) <= 64 else "unusable_response",
            )
            raise SignInRejected("provider_error")
        scope = body.get("scope")
        granted = frozenset(
            part.strip().lower() for part in str(scope or "").replace(" ", ",").split(",") if part.strip()
        )
        return token, granted

    def _api_headers(self, token: str) -> dict[str, str]:
        return {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
            "Authorization": f"Bearer {token}",
        }

    async def _get(
        self, token: str, path: str, *, ok: tuple[int, ...] = (200,), expect: Any = "object"
    ) -> HttpResult:
        return await self._http.request(
            "GET", API + path, max_bytes=CAP_GITHUB, headers=self._api_headers(token),
            ok_statuses=ok, expect=expect,
        )

    async def _identity(self, token: str, granted: frozenset[str]) -> ExternalClaims:
        user = (await self._get(token, "/user")).body
        raw_id = user.get("id")
        if isinstance(raw_id, bool) or not isinstance(raw_id, int) or raw_id <= 0:
            logger.warning("provider sign-in refused provider=github step=user reason=id")
            raise SignInRejected("sign_in_unverified")
        login = user.get("login")
        login_text = login if _is_login(login) else ""
        email, verified = await self._email(token, granted, user)
        orgs, teams, unavailable = await self._memberships(token, granted, login_text)
        return ExternalClaims(
            provider_id=PROVIDER_GITHUB,
            issuer=GITHUB_ISSUER,
            subject=str(raw_id),
            email=email,
            email_verified=verified,
            display_name=clean_text(user.get("name"), 200) or login_text,
            username=login_text,
            orgs=orgs,
            teams=teams,
            membership_unavailable=unavailable,
        )

    async def _email(
        self, token: str, granted: frozenset[str], user: Mapping[str, Any]
    ) -> tuple[str | None, bool]:
        """The primary verified address, else the public profile address (unverified), else None."""
        if granted & _EMAIL_SCOPES:
            result = await self._get(token, "/user/emails", ok=(200, 403, 404), expect="array")
            if result.status == 200 and isinstance(result.body, list):
                for entry in result.body:
                    if (
                        isinstance(entry, dict)
                        and entry.get("primary") is True
                        and entry.get("verified") is True
                        and isinstance(entry.get("email"), str)
                        and 0 < len(entry["email"]) <= 254
                    ):
                        return entry["email"], True
        public = user.get("email")
        if isinstance(public, str) and 0 < len(public) <= 254:
            return public, False
        return None, False

    async def _memberships(
        self, token: str, granted: frozenset[str], login: str
    ) -> tuple[frozenset[str], frozenset[str], bool]:
        if not self.wants_membership:
            return frozenset(), frozenset(), False
        if not granted & _ORG_SCOPES:
            # The person edited the scopes on GitHub's consent page: nothing can be looked up.
            return frozenset(), frozenset(), True
        orgs: set[str] = set()
        teams: set[str] = set()
        unavailable = False
        for org in self._orgs:
            status = await self._member_state(
                token, f"/user/memberships/orgs/{urllib.parse.quote(org, safe='')}"
            )
            if status == "active":
                orgs.add(org)
            elif status == "unavailable":
                unavailable = True
        for slug in self._teams:
            org, _, team = slug.partition("/")
            if not _is_login(login):
                unavailable = True
                continue
            path = (
                f"/orgs/{urllib.parse.quote(org, safe='')}/teams/{urllib.parse.quote(team, safe='')}"
                f"/memberships/{urllib.parse.quote(login, safe='')}"
            )
            status = await self._member_state(token, path)
            if status == "active":
                teams.add(slug)
            elif status == "unavailable":
                unavailable = True
        return frozenset(orgs), frozenset(teams), unavailable

    async def _member_state(self, token: str, path: str) -> str:
        """``active``, ``pending``, ``none`` (not affiliated) or ``unavailable`` (403)."""
        result = await self._get(token, path, ok=(200, 403, 404))
        if result.status == 404:
            return "none"
        if result.status == 403:
            return "unavailable"
        state = result.body.get("state") if isinstance(result.body, dict) else None
        return "active" if state == "active" else "pending" if state == "pending" else "none"
