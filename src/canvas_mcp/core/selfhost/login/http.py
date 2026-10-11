"""The outbound HTTP client of the sign-in providers.

Discovery, JWKS, token, userinfo and GitHub API calls all go through :class:`SafeHttp`:

* https only; URLs with user information are refused; ``localhost`` and loopback,
  link-local, unspecified and multicast IP literals are refused (``config.blocked_host``);
* no redirect is ever followed, and any 3xx answer is an error;
* a connect timeout and a deadline for the whole request;
* the body is streamed and cut off at a per-call size cap;
* a JSON body needs a JSON media type and is parsed strictly (a single object or array,
  no duplicate keys, no ``NaN``).

Errors are :class:`UpstreamError` with a code from a closed set. They never carry a URL, a
header or a body, so a log line built from one cannot leak a secret.
"""

from __future__ import annotations

import base64
import json
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from typing import Any, Literal
from urllib.parse import urlsplit

import anyio
import httpx

from .config import blocked_host

USER_AGENT = "canvas-mcp-selfhost"
CONNECT_TIMEOUT_S = 5.0
TOTAL_TIMEOUT_S = 10.0

#: Body caps in bytes.
CAP_DISCOVERY = 64 * 1024
CAP_JWKS = 64 * 1024
CAP_TOKEN = 64 * 1024
CAP_USERINFO = 32 * 1024
CAP_GITHUB = 256 * 1024

ERROR_CODES = frozenset(
    {"blocked_url", "timeout", "network", "http_status", "too_large", "not_json", "redirect"}
)
_OAUTH_ERROR_RE = re.compile(r"^[a-z_]{1,64}$")


class UpstreamError(Exception):
    """A call to an identity provider failed. ``code`` is one of :data:`ERROR_CODES`."""

    def __init__(
        self, code: str, *, status: int | None = None, oauth_error: str | None = None
    ) -> None:
        super().__init__(code)
        self.code = code if code in ERROR_CODES else "network"
        #: The HTTP status for ``http_status``.
        self.status = status
        #: The ``error`` member of an OAuth error body, only if it is a plain lower-case code.
        self.oauth_error = oauth_error

    def __str__(self) -> str:
        return self.code if self.status is None else f"{self.code} {self.status}"


@dataclass(frozen=True)
class HttpResult:
    status: int
    body: Any
    headers: Mapping[str, str] = field(default_factory=dict)


def check_url(url: str) -> str:
    """The URL if it may be called, else :class:`UpstreamError` ``blocked_url``."""
    try:
        parts = urlsplit(url)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError for a malformed port
    except ValueError:
        raise UpstreamError("blocked_url") from None
    if (
        parts.scheme.lower() != "https"
        or not host
        or "@" in parts.netloc
        or parts.fragment
        or blocked_host(host)
        or any(ch.isspace() for ch in url)
    ):
        raise UpstreamError("blocked_url")
    return url


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate key")
        out[key] = value
    return out


def _refuse_constant(_name: str) -> Any:
    raise ValueError("not JSON")


def parse_json(raw: bytes, expect: Literal["object", "array"] = "object") -> Any:
    """Strict JSON: UTF-8, no duplicate keys, no NaN or Infinity, the expected root type."""
    try:
        value = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_no_duplicates,
            parse_constant=_refuse_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        raise UpstreamError("not_json") from None
    if expect == "object" and not isinstance(value, dict):
        raise UpstreamError("not_json")
    if expect == "array" and not isinstance(value, list):
        raise UpstreamError("not_json")
    return value


def _is_json_media(content_type: str) -> bool:
    media = content_type.split(";", 1)[0].strip().lower()
    return media == "application/json" or media.endswith("+json")


class SafeHttp:
    """Outbound requests with the limits above. ``transport`` replaces the network (tests)."""

    def __init__(
        self,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        connect_timeout: float = CONNECT_TIMEOUT_S,
        total_timeout: float = TOTAL_TIMEOUT_S,
    ) -> None:
        self._transport = transport
        self._connect_timeout = connect_timeout
        self._total_timeout = total_timeout

    async def request(
        self,
        method: Literal["GET", "POST"],
        url: str,
        *,
        max_bytes: int,
        headers: Mapping[str, str] | None = None,
        data: Mapping[str, str] | None = None,
        basic_auth: tuple[str, str] | None = None,
        ok_statuses: tuple[int, ...] = (200,),
        expect: Literal["object", "array"] = "object",
    ) -> HttpResult:
        """One request. A status in ``ok_statuses`` is returned (its body parsed as JSON when it is
        a 200, and best-effort otherwise); any other status raises ``http_status``."""
        check_url(url)
        sent = {"User-Agent": USER_AGENT, "Accept": "application/json", **(headers or {})}
        if basic_auth is not None:
            # The caller form-encodes both parts first (RFC 6749 section 2.3.1).
            pair = f"{basic_auth[0]}:{basic_auth[1]}".encode()
            sent["Authorization"] = "Basic " + base64.b64encode(pair).decode("ascii")
        try:
            with anyio.fail_after(self._total_timeout):
                async with httpx.AsyncClient(
                    transport=self._transport,
                    follow_redirects=False,
                    timeout=httpx.Timeout(self._total_timeout, connect=self._connect_timeout),
                ) as client:
                    request = client.build_request(
                        method,
                        url,
                        headers=sent,
                        data=dict(data) if data is not None else None,
                    )
                    response = await client.send(request, stream=True)
                    try:
                        status = response.status_code
                        if 300 <= status < 400:
                            raise UpstreamError("redirect", status=status)
                        raw = await self._read(response, max_bytes)
                        content_type = response.headers.get("content-type", "")
                        result_headers = {k.lower(): v for k, v in response.headers.items()}
                    finally:
                        await response.aclose()
        except UpstreamError:
            raise
        except (TimeoutError, httpx.TimeoutException):
            raise UpstreamError("timeout") from None
        except (httpx.HTTPError, OSError, ValueError):
            raise UpstreamError("network") from None
        if status not in ok_statuses:
            raise UpstreamError(
                "http_status", status=status, oauth_error=_oauth_error_of(raw, content_type)
            )
        if status == 200:
            if not _is_json_media(content_type):
                raise UpstreamError("not_json")
            return HttpResult(status, parse_json(raw, expect), result_headers)
        body: Any = None
        if raw and _is_json_media(content_type):
            try:
                body = parse_json(raw, "object")
            except UpstreamError:
                body = None
        return HttpResult(status, body, result_headers)

    @staticmethod
    async def _read(response: httpx.Response, max_bytes: int) -> bytes:
        declared = response.headers.get("content-length")
        if declared is not None and declared.isdigit() and int(declared) > max_bytes:
            raise UpstreamError("too_large")
        chunks: list[bytes] = []
        total = 0
        async for chunk in response.aiter_bytes():
            total += len(chunk)
            if total > max_bytes:
                raise UpstreamError("too_large")
            chunks.append(chunk)
        return b"".join(chunks)

    async def get_json(
        self,
        url: str,
        *,
        max_bytes: int,
        headers: Mapping[str, str] | None = None,
        expect: Literal["object", "array"] = "object",
    ) -> HttpResult:
        return await self.request("GET", url, max_bytes=max_bytes, headers=headers, expect=expect)

    async def post_form(
        self,
        url: str,
        data: Mapping[str, str],
        *,
        max_bytes: int,
        headers: Mapping[str, str] | None = None,
        basic_auth: tuple[str, str] | None = None,
    ) -> HttpResult:
        return await self.request(
            "POST", url, max_bytes=max_bytes, headers=headers, data=data, basic_auth=basic_auth
        )


def _oauth_error_of(raw: bytes, content_type: str) -> str | None:
    """The ``error`` code of an OAuth error body, only if it is a short lower-case code."""
    if not raw or not _is_json_media(content_type):
        return None
    try:
        body = parse_json(raw, "object")
    except UpstreamError:
        return None
    value = body.get("error")
    return value if isinstance(value, str) and _OAUTH_ERROR_RE.fullmatch(value) else None
