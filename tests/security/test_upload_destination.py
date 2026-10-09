"""upload_file_to_storage must not post to an address a hostile school picked.

In HTTP mode the upload URL comes from whichever Canvas the caller enrolled at.
That Canvas may be any school in a public directory, so the URL is checked
before anything is sent: https only, a plain public DNS name, public addresses.
The caller's own Canvas origin is always acceptable.
"""

from __future__ import annotations

import httpx
import pytest
import respx

from canvas_mcp.core import client as client_module
from canvas_mcp.core.credentials import (
    RequestCredentials,
    clear_request_credentials,
    set_http_request_active,
    set_request_credentials,
)
from canvas_mcp.core.selfhost import schools

SCHOOL = "https://evil-school.example.org"
PUBLIC_UPLOAD = "https://storage.example.org/upload?sig=s"


@pytest.fixture(autouse=True)
def _config(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("CANVAS_API_TOKEN", "synthetic-token")
    monkeypatch.setenv("CANVAS_API_URL", f"{SCHOOL}/api/v1")
    from canvas_mcp.core.config import reset_config

    reset_config()


@pytest.fixture
def resolved(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Replace DNS: every name resolves to a public address; records the lookups."""
    seen: list[str] = []

    async def fake_resolve(host: str) -> list[str]:
        seen.append(host)
        return ["93.184.216.34"]

    monkeypatch.setattr(schools, "system_resolve", fake_resolve)
    return seen


async def _upload(tmp_path, url: str) -> dict:
    source = tmp_path / "essay.txt"
    source.write_text("my essay", encoding="utf-8")
    set_http_request_active(True)
    set_request_credentials(RequestCredentials(api_token="tok", api_url=f"{SCHOOL}/api/v1"))
    try:
        return await client_module.upload_file_to_storage(
            url, {"k": "v"}, str(source), "essay.txt", "text/plain"
        )
    finally:
        clear_request_credentials()
        set_http_request_active(False)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "url",
    [
        "http://storage.example.org/upload",
        "http://169.254.169.254/latest/whatever",
        "https://169.254.169.254/latest/whatever",
        "https://127.0.0.1:8443/upload",
        "https://[::1]/upload",
        "https://localhost/upload",
        "https://metadata.internal/upload",
        "https://printer.local/upload",
        "https://user:pw@storage.example.org/upload",
        "ftp://storage.example.org/upload",
        "not a url",
    ],
)
async def test_unsafe_upload_urls_are_refused_and_never_dispatched(
    tmp_path, resolved: list[str], url: str
) -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.route().mock(return_value=httpx.Response(500, text="INTERNAL SECRET BODY"))
        result = await _upload(tmp_path, url)
    assert "Upload refused" in result["error"]
    assert "details" not in result
    assert not route.called


@pytest.mark.asyncio
async def test_a_public_name_that_resolves_to_a_private_address_is_refused(
    tmp_path, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def to_loopback(host: str) -> list[str]:
        return ["127.0.0.1"]

    monkeypatch.setattr(schools, "system_resolve", to_loopback)
    with respx.mock(assert_all_called=False) as router:
        route = router.route().mock(return_value=httpx.Response(200, json={"id": 1}))
        result = await _upload(tmp_path, PUBLIC_UPLOAD)
    assert "Upload refused" in result["error"]
    assert not route.called


@pytest.mark.asyncio
async def test_a_public_https_storage_host_is_still_allowed(tmp_path, resolved: list[str]) -> None:
    with respx.mock(assert_all_called=False) as router:
        route = router.post(PUBLIC_UPLOAD).mock(return_value=httpx.Response(200, json={"id": 9}))
        result = await _upload(tmp_path, PUBLIC_UPLOAD)
    assert result == {"id": 9}
    assert route.called
    assert resolved == ["storage.example.org"]


@pytest.mark.asyncio
async def test_the_callers_own_canvas_origin_is_allowed_without_a_lookup(
    tmp_path, resolved: list[str]
) -> None:
    own = f"{SCHOOL}/files/upload?sig=s"
    with respx.mock(assert_all_called=False) as router:
        route = router.post(own).mock(return_value=httpx.Response(200, json={"id": 3}))
        result = await _upload(tmp_path, own)
    assert result == {"id": 3}
    assert route.called and resolved == []


@pytest.mark.asyncio
async def test_stdio_mode_is_unchanged(tmp_path, resolved: list[str]) -> None:
    source = tmp_path / "essay.txt"
    source.write_text("my essay", encoding="utf-8")
    with respx.mock(assert_all_called=False) as router:
        route = router.post("http://127.0.0.1:9000/upload").mock(
            return_value=httpx.Response(200, json={"id": 5})
        )
        result = await client_module.upload_file_to_storage(
            "http://127.0.0.1:9000/upload", {}, str(source), "essay.txt", "text/plain"
        )
    assert result == {"id": 5}
    assert route.called and resolved == []
