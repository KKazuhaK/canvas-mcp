"""Best-effort read-only discovery of the submitted PAT's permanent expiration.

Canvas documents the token show endpoint and its expires_at field:
https://developerdocs.instructure.com/services/canvas/resources/access_tokens
Canvas AccessToken.token= derives token_hint from the first five unsharded characters.
Its token serializer can expose that hint as visible_token="<hint>..." instead,
with the submitted shard prefix retained by some Canvas deployments:
https://github.com/instructure/canvas-lms/blob/master/lib/api/v1/token.rb
A successful response must match the hint or its exact mask and the verified user.
"""

from __future__ import annotations

import datetime as dt
import re
from collections.abc import Callable
from dataclasses import dataclass
from urllib.parse import quote

import httpx


@dataclass(frozen=True)
class TokenExpiry:
    known: bool = False
    expires_at: int | None = None


async def fetch_expiry(
    token: str,
    api_url: str,
    user_id: str,
    *,
    client_factory: Callable[[], httpx.AsyncClient],
) -> TokenExpiry:
    raw = token.rsplit("~", 1)[-1]
    if len(raw) < 20 or not re.fullmatch(r"[A-Za-z0-9_-]+", raw):
        return TokenExpiry()
    hint = raw[:5]
    visible_masks = {hint + "...", token[: len(token) - len(raw)] + hint + "..."}
    url = api_url.rstrip("/") + "/users/self/tokens/" + quote(hint, safe="")
    try:
        async with client_factory() as client:
            async with client.stream(
                "GET",
                url,
                headers={
                    "Authorization": "Bearer " + token,
                    "Accept": "application/json",
                },
                timeout=5.0,
                follow_redirects=False,
            ) as response:
                if response.status_code != 200:
                    return TokenExpiry()
                payload = bytearray()
                async for chunk in response.aiter_bytes():
                    payload.extend(chunk)
                    if len(payload) > 16384:
                        return TokenExpiry()
                import json

                data = json.loads(payload)
        if (
            not isinstance(data, dict)
            or str(data.get("user_id")) != user_id
            or "expires_at" not in data
        ):
            return TokenExpiry()
        identifiers = []
        if "token_hint" in data:
            identifiers.append(data["token_hint"] == hint)
        if data.get("visible_token") is not None:
            visible = data["visible_token"]
            identifiers.append(isinstance(visible, str) and visible in visible_masks)
        if not identifiers or not all(identifiers):
            return TokenExpiry()
        value = data["expires_at"]
        if value is None:
            return TokenExpiry(known=True)
        if not isinstance(value, str) or len(value) > 64:
            return TokenExpiry()
        date = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
        if date.tzinfo is None:
            return TokenExpiry()
        epoch = int(date.timestamp())
        if not 0 < epoch <= 4_102_444_800:
            return TokenExpiry()
        return TokenExpiry(True, epoch)
    except (httpx.HTTPError, ValueError, OverflowError, OSError):
        # Never print a response, URL, exception, token or token hint.
        return TokenExpiry()
