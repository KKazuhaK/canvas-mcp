"""Module-file discovery and token-safe downloads (core/course_files.py).

Downloads run through real httpx clients over a MockTransport, so redirect
handling and the headers that actually leave the process are observed, not
assumed. The security requirement is independent of the implementation: the
Canvas bearer token may reach only the configured Canvas origin.
"""

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from canvas_mcp.core import client as cm
from canvas_mcp.core import course_files as cf
from canvas_mcp.core.credentials import RequestCredentials
from canvas_mcp.core.write_outcome import RequestFailure, WriteOutcome

CANVAS = "https://canvas.example.edu"
TOKEN = "synthetic-canvas-token"
DOWNLOAD_URL = f"{CANVAS}/files/12345/download?download_frd=1&verifier=v3r1f13r"
STORAGE_URL = "https://files.storage.example.net/blob/abc?signature=s1gn3d"


class Recorder:
    """MockTransport handler that records every request leaving the process."""

    def __init__(self, routes):
        self.routes = routes
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        handler = self.routes.get(str(request.url))
        if handler is None:
            return httpx.Response(599, text="unexpected URL in test")
        return handler(request)

    def auth_by_host(self) -> list[tuple[str, str | None]]:
        return [(r.url.host, r.headers.get("Authorization")) for r in self.requests]


@pytest.fixture
def transport_env(monkeypatch):
    """Point both download clients at a recording MockTransport (stdio mode)."""
    config = SimpleNamespace(canvas_api_url=f"{CANVAS}/api/v1", api_timeout=5)
    monkeypatch.setattr(cf, "get_config", lambda: config)
    monkeypatch.setattr(cf, "get_request_credentials", lambda: None)

    def install(routes):
        recorder = Recorder(routes)
        mock = httpx.MockTransport(recorder)

        @asynccontextmanager
        async def authed():
            # Same shape as the real stdio client: token in default headers.
            async with httpx.AsyncClient(
                transport=mock, headers={"Authorization": f"Bearer {TOKEN}"}
            ) as client:
                yield client

        @asynccontextmanager
        async def anonymous():
            async with httpx.AsyncClient(transport=mock) as client:
                yield client

        monkeypatch.setattr(cf, "canvas_authenticated_client", authed)
        monkeypatch.setattr(cf, "_unauthenticated_client", anonymous)
        return recorder

    return install


def redirect(to: str, status: int = 302):
    return lambda request: httpx.Response(status, headers={"Location": to})


def body(content: bytes, **headers):
    return lambda request: httpx.Response(200, content=content, headers=headers)


class TestDownloadTokenBoundary:
    @pytest.mark.asyncio
    async def test_token_goes_to_canvas_but_not_to_storage(self, transport_env):
        recorder = transport_env({
            DOWNLOAD_URL: redirect(STORAGE_URL),
            STORAGE_URL: body(b"%PDF-1.4 slides"),
        })

        data = await cf.download_file_bytes(DOWNLOAD_URL, 1024)

        assert data == b"%PDF-1.4 slides"
        assert recorder.auth_by_host() == [
            ("canvas.example.edu", f"Bearer {TOKEN}"),
            ("files.storage.example.net", None),
        ]

    @pytest.mark.asyncio
    async def test_non_canvas_first_hop_never_sees_the_token(self, transport_env):
        recorder = transport_env({STORAGE_URL: body(b"bytes")})

        assert await cf.download_file_bytes(STORAGE_URL, 1024) == b"bytes"
        assert recorder.auth_by_host() == [("files.storage.example.net", None)]

    @pytest.mark.asyncio
    async def test_lookalike_host_is_not_canvas(self, transport_env):
        lookalike = "https://canvas.example.edu.attacker.example/files/1/download"
        recorder = transport_env({lookalike: body(b"x")})

        await cf.download_file_bytes(lookalike, 1024)
        assert recorder.auth_by_host() == [("canvas.example.edu.attacker.example", None)]

    @pytest.mark.asyncio
    async def test_other_port_on_canvas_host_is_a_different_origin(self, transport_env):
        other_port = "https://canvas.example.edu:8443/files/1/download"
        recorder = transport_env({other_port: body(b"x")})

        await cf.download_file_bytes(other_port, 1024)
        assert recorder.auth_by_host() == [("canvas.example.edu", None)]

    @pytest.mark.asyncio
    async def test_relative_redirect_stays_on_canvas_with_token(self, transport_env):
        target = f"{CANVAS}/files/12345/download?inline=1"
        recorder = transport_env({
            DOWNLOAD_URL: redirect("/files/12345/download?inline=1"),
            target: body(b"ok"),
        })

        assert await cf.download_file_bytes(DOWNLOAD_URL, 1024) == b"ok"
        assert [auth for _, auth in recorder.auth_by_host()] == [f"Bearer {TOKEN}"] * 2

    @pytest.mark.asyncio
    async def test_plain_http_storage_hop_is_refused_before_any_request(self, transport_env):
        insecure = "http://files.storage.example.net/blob"
        recorder = transport_env({DOWNLOAD_URL: redirect(insecure)})

        result = await cf.download_file_bytes(DOWNLOAD_URL, 1024)

        assert "non-HTTPS" in result["error"]
        assert [str(r.url) for r in recorder.requests] == [DOWNLOAD_URL]

    @pytest.mark.asyncio
    async def test_storage_cannot_bounce_back_to_an_authenticated_canvas_get(
        self, transport_env
    ):
        """Once a hop leaves Canvas, a hop back to Canvas carries no token.

        Otherwise a hostile storage host picks which authenticated Canvas GET
        the server makes (here the student's profile) and the response is
        handed over as the file.
        """
        profile = f"{CANVAS}/api/v1/users/self/profile"
        recorder = transport_env({
            DOWNLOAD_URL: redirect(STORAGE_URL),
            STORAGE_URL: redirect(profile),
            profile: lambda request: (
                httpx.Response(200, content=b'{"name": "Student"}')
                if request.headers.get("Authorization")
                else httpx.Response(401, text="unauthenticated")
            ),
        })

        result = await cf.download_file_bytes(DOWNLOAD_URL, 1024)

        assert recorder.auth_by_host() == [
            ("canvas.example.edu", f"Bearer {TOKEN}"),
            ("files.storage.example.net", None),
            ("canvas.example.edu", None),
        ]
        assert result == {"error": "HTTP 401 while downloading the file"}

    @pytest.mark.asyncio
    @pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://canvas.example.edu/x"])
    async def test_non_http_schemes_are_refused(self, transport_env, url):
        recorder = transport_env({})
        result = await cf.download_file_bytes(url, 1024)
        assert "Refusing" in result["error"]
        assert recorder.requests == []

    @pytest.mark.asyncio
    async def test_redirect_loop_is_bounded(self, transport_env):
        loop_url = f"{CANVAS}/files/1/download"
        recorder = transport_env({loop_url: redirect(loop_url)})

        result = await cf.download_file_bytes(loop_url, 1024)

        assert "Too many redirects" in result["error"]
        assert len(recorder.requests) == cf.MAX_DOWNLOAD_REDIRECTS + 1

    @pytest.mark.asyncio
    async def test_redirect_without_location_is_an_error(self, transport_env):
        transport_env({DOWNLOAD_URL: lambda r: httpx.Response(302)})
        result = await cf.download_file_bytes(DOWNLOAD_URL, 1024)
        assert "without a Location" in result["error"]

    @pytest.mark.asyncio
    async def test_http_mode_uses_the_callers_canvas_origin(self, transport_env, monkeypatch):
        """Hosted mode: the caller's own Canvas URL defines the trusted origin."""
        other_canvas = "https://other-school.instructure.com/files/9/download"
        recorder = transport_env({other_canvas: body(b"x")})
        monkeypatch.setattr(
            cf,
            "get_request_credentials",
            lambda: RequestCredentials(
                api_token=TOKEN, api_url="https://other-school.instructure.com/api/v1"
            ),
        )

        await cf.download_file_bytes(other_canvas, 1024)
        assert recorder.auth_by_host() == [("other-school.instructure.com", f"Bearer {TOKEN}")]


class TestDownloadLimitsAndErrors:
    @pytest.mark.asyncio
    async def test_declared_length_over_cap_is_refused(self, transport_env):
        transport_env({STORAGE_URL: body(b"x" * 10, **{"Content-Length": "999999"})})
        result = await cf.download_file_bytes(STORAGE_URL, 100)
        assert "size limit" in result["error"]

    @pytest.mark.asyncio
    async def test_streamed_body_over_cap_is_refused(self, transport_env):
        transport_env({STORAGE_URL: lambda r: httpx.Response(
            200, stream=httpx.ByteStream(b"x" * 500)
        )})
        result = await cf.download_file_bytes(STORAGE_URL, 100)
        assert "size limit" in result["error"]

    @pytest.mark.asyncio
    async def test_body_exactly_at_cap_is_accepted(self, transport_env):
        transport_env({STORAGE_URL: body(b"x" * 100)})
        assert await cf.download_file_bytes(STORAGE_URL, 100) == b"x" * 100

    @pytest.mark.asyncio
    async def test_error_status_does_not_echo_signed_urls(self, transport_env):
        transport_env({
            DOWNLOAD_URL: redirect(STORAGE_URL),
            STORAGE_URL: lambda r: httpx.Response(403, text="AccessDenied"),
        })
        result = await cf.download_file_bytes(DOWNLOAD_URL, 1024)
        assert result == {"error": "HTTP 403 while downloading the file"}
        assert "s1gn3d" not in result["error"] and "v3r1f13r" not in result["error"]

    @pytest.mark.asyncio
    async def test_transport_error_is_reported_without_url(self, transport_env):
        def boom(request):
            raise httpx.ConnectError("connection refused to " + str(request.url))

        transport_env({STORAGE_URL: boom})
        result = await cf.download_file_bytes(STORAGE_URL, 1024)
        assert result == {"error": "Download failed: ConnectError"}

    @pytest.mark.asyncio
    async def test_invalid_url(self, transport_env):
        transport_env({})
        result = await cf.download_file_bytes("https://[::1", 1024)
        assert "invalid download URL" in result["error"]


class TestStreamFileDownload:
    """The streaming form download_course_file writes to disk with."""

    @pytest.mark.asyncio
    async def test_body_reaches_the_sink_and_the_count_is_returned(self, transport_env):
        recorder = transport_env({
            DOWNLOAD_URL: redirect(STORAGE_URL),
            STORAGE_URL: lambda r: httpx.Response(
                200, stream=httpx.ByteStream(b"abc" * 10)
            ),
        })
        received: list[bytes] = []

        total = await cf.stream_file_download(DOWNLOAD_URL, 1024, received.append)

        assert total == 30 and b"".join(received) == b"abc" * 10
        assert recorder.auth_by_host() == [
            ("canvas.example.edu", f"Bearer {TOKEN}"),
            ("files.storage.example.net", None),
        ]

    @pytest.mark.asyncio
    async def test_sink_never_receives_more_than_the_cap(self, transport_env):
        transport_env({STORAGE_URL: lambda r: httpx.Response(
            200, stream=httpx.ByteStream(b"x" * 500)
        )})
        received: list[bytes] = []

        result = await cf.stream_file_download(STORAGE_URL, 100, received.append)

        assert "size limit" in result["error"]
        assert sum(len(chunk) for chunk in received) <= 100

    @pytest.mark.asyncio
    async def test_declared_oversize_writes_nothing(self, transport_env):
        transport_env({STORAGE_URL: body(b"x" * 10, **{"Content-Length": "999999"})})
        received: list[bytes] = []

        result = await cf.stream_file_download(STORAGE_URL, 100, received.append)

        assert "size limit" in result["error"]
        assert received == []

    @pytest.mark.asyncio
    async def test_a_failing_sink_propagates(self, transport_env):
        transport_env({STORAGE_URL: body(b"bytes")})

        def full_disk(_chunk: bytes) -> None:
            raise OSError(28, "No space left on device")

        with pytest.raises(OSError):
            await cf.stream_file_download(STORAGE_URL, 1024, full_disk)


class TestIsCanvasOrigin:
    @pytest.fixture(autouse=True)
    def canvas_config(self, monkeypatch):
        config = SimpleNamespace(canvas_api_url=f"{CANVAS}/api/v1", api_timeout=5)
        monkeypatch.setattr(cf, "get_config", lambda: config)
        monkeypatch.setattr(cf, "get_request_credentials", lambda: None)

    @pytest.mark.parametrize(("url", "expected"), [
        (f"{CANVAS}/api/v1/files/1/create_success?uuid=x", True),
        ("https://canvas.example.edu:443/api/v1/files/1", True),
        ("http://canvas.example.edu/api/v1/files/1", False),
        ("https://canvas.example.edu:8443/api/v1/files/1", False),
        ("https://canvas.example.edu.attacker.example/api/v1/files/1", False),
        ("https://attacker.example/canvas.example.edu", False),
        ("/api/v1/files/1", False),
        ("https://[::1", False),
    ])
    def test_origin_match(self, url, expected):
        assert cf.is_canvas_origin(url) is expected

    def test_hosted_caller_origin_comes_from_their_credentials(self, monkeypatch):
        monkeypatch.setattr(
            cf,
            "get_request_credentials",
            lambda: RequestCredentials(
                api_token=TOKEN, api_url="https://other-school.instructure.com/api/v1"
            ),
        )
        assert cf.is_canvas_origin("https://other-school.instructure.com/api/v1/files/1")
        assert not cf.is_canvas_origin(f"{CANVAS}/api/v1/files/1")


class TestNoServerDefaultDuringHttpRequests:
    """In the self-hosted multi-school mode each caller has their own Canvas; an HTTP
    request without request credentials has no Canvas origin and must not fall back
    to the server's CANVAS_API_URL."""

    def test_no_origin_without_credentials_in_an_http_request(self, transport_env, monkeypatch):
        transport_env({})
        monkeypatch.setattr(cf, "is_http_request_active", lambda: True)
        assert cf._canvas_origin() is None
        assert cf.is_canvas_origin(f"{CANVAS}/api/v1/files/1") is False

    def test_stdio_keeps_the_configured_origin(self, transport_env, monkeypatch):
        transport_env({})
        monkeypatch.setattr(cf, "is_http_request_active", lambda: False)
        assert cf.is_canvas_origin(f"{CANVAS}/api/v1/files/1") is True

    @pytest.mark.asyncio
    async def test_download_never_sends_a_token_to_the_server_default(self, transport_env, monkeypatch):
        recorder = transport_env({DOWNLOAD_URL: body(b"x")})
        monkeypatch.setattr(cf, "is_http_request_active", lambda: True)
        await cf.download_file_bytes(DOWNLOAD_URL, 1024)
        assert recorder.auth_by_host() == [("canvas.example.edu", None)]

    def test_another_schools_origin_is_judged_by_its_own_credentials(self, transport_env, monkeypatch):
        transport_env({})
        monkeypatch.setattr(cf, "is_http_request_active", lambda: True)
        monkeypatch.setattr(
            cf,
            "get_request_credentials",
            lambda: RequestCredentials(api_token=TOKEN, api_url="https://canvas.school-b.edu/api/v1"),
        )
        assert cf.is_canvas_origin("https://canvas.school-b.edu/files/1/download")
        assert not cf.is_canvas_origin(f"{CANVAS}/files/1/download")


class TestErrorStatus:
    @pytest.mark.asyncio
    @pytest.mark.parametrize(("status", "denied"), [(401, True), (403, True), (404, False), (500, False)])
    async def test_status_parsed_from_real_make_canvas_request(self, monkeypatch, status, denied):
        """The classifier reads the error string make_canvas_request really produces."""
        for name in ("http_client", "_http_client_loop_ref", "_request_semaphore", "_semaphore_loop_ref"):
            monkeypatch.setattr(cm, name, None)
        config = SimpleNamespace(
            canvas_api_url=f"{CANVAS}/api/v1", canvas_api_token="t", max_concurrent_requests=2,
            api_timeout=1, log_api_requests=False, enable_data_anonymization=False,
            anonymization_debug=False,
        )
        monkeypatch.setattr("canvas_mcp.core.config.get_config", lambda: config)
        monkeypatch.setattr(cm, "get_request_credentials", lambda: None)
        monkeypatch.setattr(cm, "is_http_request_active", lambda: False)

        transport = httpx.MockTransport(lambda r: httpx.Response(
            status, json={"status": "unauthorized", "errors": [{"message": "user not authorized"}]}
        ))
        async with httpx.AsyncClient(transport=transport) as client:
            with patch.object(cm, "_get_http_client", return_value=client), \
                 patch("canvas_mcp.core.audit.log_data_access"):
                response = await cm.make_canvas_request("get", "/courses/1/files")

        assert cf.canvas_error_status(response) == status
        assert cf.is_access_denied(response) is denied

    @pytest.mark.parametrize("value", [
        {"error": "Insufficient permissions"}, [], None, {"error": None}, {"id": 1},
    ])
    def test_non_http_errors_have_no_status(self, value):
        assert cf.canvas_error_status(value) is None
        assert cf.is_access_denied(value) is False


def _denied(status: int = 403) -> RequestFailure:
    return RequestFailure(
        f"HTTP error: {status}, Details: {{'status': 'unauthorized'}}", WriteOutcome.REJECTED
    )


class TestListFilesViaModules:
    @pytest.mark.asyncio
    async def test_inline_items_and_omitted_items(self):
        calls = []

        async def fetch(endpoint, params=None, **kwargs):
            calls.append((endpoint, params))
            if endpoint == "/courses/60366/modules":
                return [
                    {"id": 1, "name": "Week 1", "items": [
                        {"type": "File", "content_id": 501, "title": "Lecture 1.pdf"},
                        {"type": "Page", "content_id": 9, "title": "Read me"},
                        {"type": "File", "content_id": 502, "title": "Lab 1.docx"},
                    ]},
                    # Canvas omitted items for this module: must be fetched.
                    {"id": 2, "name": "Week 2", "items_count": 2},
                ]
            if endpoint == "/courses/60366/modules/2/items":
                return [
                    {"type": "File", "content_id": 501, "title": "Lecture 1.pdf"},
                    {"type": "File", "content_id": 503, "title": "Lecture 2.pptx"},
                ]
            raise AssertionError(endpoint)

        with patch.object(cf, "fetch_all_paginated_results", side_effect=fetch):
            files = await cf.list_files_via_modules("60366")

        assert calls == [
            ("/courses/60366/modules", {"per_page": 100, "include[]": ["items"]}),
            ("/courses/60366/modules/2/items", {"per_page": 100}),
        ]
        assert files == [
            {"id": "501", "title": "Lecture 1.pdf", "modules": ["Week 1", "Week 2"]},
            {"id": "502", "title": "Lab 1.docx", "modules": ["Week 1"]},
            {"id": "503", "title": "Lecture 2.pptx", "modules": ["Week 2"]},
        ]

    @pytest.mark.asyncio
    async def test_non_numeric_ids_are_never_put_in_paths(self):
        calls = []

        async def fetch(endpoint, params=None, **kwargs):
            calls.append(endpoint)
            if endpoint == "/courses/60366/modules":
                return [
                    {"id": "2/../../users/self", "name": "Bad"},
                    {"id": 3, "name": "Ok", "items": [
                        {"type": "File", "content_id": "7?x=1", "title": "bad id"},
                    ]},
                ]
            raise AssertionError(endpoint)

        with patch.object(cf, "fetch_all_paginated_results", side_effect=fetch):
            files = await cf.list_files_via_modules("60366")

        assert calls == ["/courses/60366/modules"]
        assert files == []

    @pytest.mark.asyncio
    async def test_module_error_is_returned(self):
        with patch.object(cf, "fetch_all_paginated_results", AsyncMock(return_value=_denied(401))):
            result = await cf.list_files_via_modules("60366")
        assert result["error"].startswith("HTTP error: 401")

    @pytest.mark.asyncio
    async def test_item_listing_error_is_returned(self):
        async def fetch(endpoint, params=None, **kwargs):
            if endpoint.endswith("/modules"):
                return [{"id": 4, "name": "Big"}]
            return {"error": "HTTP error: 500, Text: boom"}

        with patch.object(cf, "fetch_all_paginated_results", side_effect=fetch):
            result = await cf.list_files_via_modules("60366")
        assert result == {"error": "HTTP error: 500, Text: boom"}


class TestFetchModuleLinkedFile:
    MODULES = [{"id": 1, "name": "Week 1", "items": [
        {"type": "File", "content_id": 12345, "title": "Slides"},
    ]}]

    @pytest.mark.asyncio
    async def test_linked_file_is_read_through_files_route(self):
        info = {"id": 12345, "display_name": "slides.pdf", "url": DOWNLOAD_URL}
        with patch.object(cf, "fetch_all_paginated_results", AsyncMock(return_value=self.MODULES)), \
             patch.object(cf, "make_canvas_request", AsyncMock(return_value=info)) as request:
            result, note = await cf.fetch_module_linked_file("60366", "12345", _denied())

        request.assert_awaited_once_with("get", "/files/12345")
        assert result == info
        assert "module" in note

    @pytest.mark.asyncio
    async def test_unlinked_file_is_not_fetched(self):
        """The fallback must not widen access to files the course does not link."""
        with patch.object(cf, "fetch_all_paginated_results", AsyncMock(return_value=self.MODULES)), \
             patch.object(cf, "make_canvas_request", AsyncMock()) as request:
            result, note = await cf.fetch_module_linked_file("60366", "99999", _denied())

        request.assert_not_awaited()
        assert note is None
        assert "HTTP error: 403" in result["error"]
        assert "not linked from any module" in result["error"]

    @pytest.mark.asyncio
    async def test_modules_failure_reports_both_errors(self):
        with patch.object(cf, "fetch_all_paginated_results", AsyncMock(return_value=_denied(401))), \
             patch.object(cf, "make_canvas_request", AsyncMock()) as request:
            result, note = await cf.fetch_module_linked_file("60366", "12345", _denied(403))

        request.assert_not_awaited()
        assert note is None
        assert "HTTP error: 403" in result["error"] and "HTTP error: 401" in result["error"]

    @pytest.mark.asyncio
    async def test_files_route_error_is_returned(self):
        with patch.object(cf, "fetch_all_paginated_results", AsyncMock(return_value=self.MODULES)), \
             patch.object(cf, "make_canvas_request", AsyncMock(return_value=_denied(404))):
            result, note = await cf.fetch_module_linked_file("60366", "12345", _denied())
        assert note is None
        assert result["error"].startswith("HTTP error: 404")
