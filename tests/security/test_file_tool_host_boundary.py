"""Host boundary invariants for the Canvas file tools.

Two boundaries, both independent of the implementation:

1. The server's filesystem. ``download_course_file`` writes to it and
   ``upload_course_file`` reads from it. Both are correct on a local stdio
   server (that filesystem is the caller's own machine) and both are
   cross-boundary primitives on a shared HTTP server, where the caller is
   remote:

   - download lets the caller pick the destination directory while Canvas
     supplies the filename and bytes, i.e. an arbitrary write as the service
     account.
   - upload lets the caller name any file the service account can read and
     copy it into their own Canvas course, i.e. an arbitrary read.

   These tests pin the transport refusal for both, plus the local-mode
   hardening that keeps a Canvas-controlled filename from clobbering an
   existing file.

2. The Canvas token. It may reach only the configured Canvas origin. A file
   download redirects from Canvas to a storage host, and an upload
   confirmation redirect comes from the storage host, so neither redirect may
   carry the token anywhere else, a non-Canvas hop must be HTTPS, and the hop
   count is capped. These run the real Canvas clients (the stdio client with
   its bearer header, and the credential-free storage client) over a
   recording transport, so the headers that would leave the process are
   observed, not assumed.
"""

import os
import sys
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from canvas_mcp.core import client as client_module
from canvas_mcp.core.course_files import MAX_DOWNLOAD_REDIRECTS

CANVAS = "https://canvas.example.edu"
TOKEN = "synthetic-canvas-token"
DOWNLOAD_URL = f"{CANVAS}/files/12345/download?download_frd=1&verifier=v3r1f13r"
STORAGE_URL = "https://files.storage.example.net/blob/abc?signature=s1gn3d"


def get_tool_function(tool_name: str):
    """Get a tool function by name from the registered file tools."""
    from fastmcp import FastMCP

    from canvas_mcp.tools.files import (
        register_educator_file_tools,
        register_shared_file_tools,
    )

    mcp = FastMCP("test")
    captured: dict = {}
    original_tool = mcp.tool

    def capturing_tool(*args, **kwargs):
        decorator = original_tool(*args, **kwargs)

        def wrapper(fn):
            captured[fn.__name__] = fn
            return decorator(fn)

        return wrapper

    mcp.tool = capturing_tool
    register_shared_file_tools(mcp)
    register_educator_file_tools(mcp)
    return captured.get(tool_name)


class Recorder:
    """Transport handler that records every request leaving the process."""

    def __init__(self) -> None:
        self.routes: dict[tuple[str, str], object] = {}
        self.requests: list[httpx.Request] = []

    def route(self, url: str, handler, method: str = "GET") -> None:
        self.routes[(method, url)] = handler

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        handler = self.routes.get((request.method, str(request.url)))
        if handler is None:
            return httpx.Response(599, text="unexpected URL in test")
        return handler(request)

    def auth_by_host(self) -> list[tuple[str, str | None]]:
        return [(r.url.host, r.headers.get("Authorization")) for r in self.requests]

    def token_seen_by(self) -> set[str]:
        """Hosts that received the token in any header at all."""
        return {
            r.url.host
            for r in self.requests
            if any(TOKEN in value for value in r.headers.values())
        }


@pytest.fixture
def wire(monkeypatch):
    """Real Canvas clients (stdio mode) over a recording transport.

    Every ``httpx.AsyncClient`` the server builds gets the recorder as its
    transport and keeps its own headers, so the shared Canvas client sends
    the configured bearer token exactly as in production and the storage
    client sends none.
    """
    monkeypatch.setenv("CANVAS_API_TOKEN", TOKEN)
    monkeypatch.setenv("CANVAS_API_URL", f"{CANVAS}/api/v1")
    from canvas_mcp.core.config import reset_config

    reset_config()
    recorder = Recorder()
    transport = httpx.MockTransport(recorder)
    real_client = httpx.AsyncClient

    class RecordingClient(real_client):  # type: ignore[misc, valid-type]
        def __init__(self, *args, **kwargs):
            kwargs["transport"] = transport
            super().__init__(*args, **kwargs)

    monkeypatch.setattr(httpx, "AsyncClient", RecordingClient)
    monkeypatch.setattr(client_module, "http_client", None)
    monkeypatch.setattr(client_module, "_http_client_loop_ref", None)
    return recorder


def configure_download_limit(monkeypatch, value: str) -> None:
    """Set DOWNLOAD_FILE_MAX_SIZE_MB and rebuild the config that reads it."""
    from canvas_mcp.core.config import reset_config

    monkeypatch.setenv("DOWNLOAD_FILE_MAX_SIZE_MB", value)
    reset_config()


def redirect(to: str, status: int = 302):
    return lambda request: httpx.Response(status, headers={"Location": to})


def body(content: bytes, **headers):
    return lambda request: httpx.Response(200, content=content, headers=headers)


def file_info(url: str = DOWNLOAD_URL, **overrides) -> dict:
    info = {
        "id": 12345,
        "display_name": "syllabus.pdf",
        "url": url,
        "size": 1024,
        "content-type": "application/pdf",
    }
    info.update(overrides)
    return info


FILE_INFO = file_info()


@pytest.fixture
def stdio_tool():
    """download_course_file on a local server, course route, metadata patched."""
    with patch(
        "canvas_mcp.tools.files.is_http_request_active", return_value=False
    ), patch(
        "canvas_mcp.tools.files.get_course_id", new=AsyncMock(return_value="60366")
    ), patch(
        "canvas_mcp.tools.files.get_course_code", new=AsyncMock(return_value="badm_350")
    ), patch(
        "canvas_mcp.tools.files.make_canvas_request", new=AsyncMock(return_value=FILE_INFO)
    ) as request:
        yield request


class TestDownloadRefusedOverHttp:
    """A remote caller must never direct a write onto the server's filesystem."""

    @pytest.mark.asyncio
    async def test_download_refused_over_http(self, tmp_path):
        with patch(
            "canvas_mcp.tools.files.is_http_request_active", return_value=True
        ), patch(
            "canvas_mcp.tools.files.make_canvas_request", new_callable=AsyncMock
        ) as request, patch(
            "canvas_mcp.tools.files.get_course_id", new=AsyncMock(return_value="60366")
        ), patch(
            "canvas_mcp.tools.files.stream_file_download", new_callable=AsyncMock
        ) as stream:
            download = get_tool_function("download_course_file")
            result = await download("badm_350", 12345, save_directory=str(tmp_path))

        assert "only available on a local (stdio) server" in result
        # It names both read tools, each for what it does, and never base64.
        assert "read_course_file to see the file as it is" in result
        assert "read_course_file_text for its plain text" in result
        assert "base64" not in result.lower()
        # The guard runs before any Canvas call, so no request is issued at all.
        assert request.call_count == 0
        assert stream.await_count == 0
        # Nothing was written into the caller-chosen directory.
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.asyncio
    async def test_download_allowed_over_stdio(self, tmp_path, wire, stdio_tool):
        """The stdio path still works: the guard is transport-scoped, not a removal."""
        wire.route(DOWNLOAD_URL, body(b"file content here"))

        download = get_tool_function("download_course_file")
        result = await download("badm_350", 12345, save_directory=str(tmp_path))

        assert "syllabus.pdf" in result and "Downloaded:" in result
        assert (tmp_path / "syllabus.pdf").read_bytes() == b"file content here"


class TestDownloadDoesNotClobber:
    """Canvas controls the filename, so the write must never truncate a real file."""

    @pytest.mark.asyncio
    async def test_existing_file_is_not_overwritten(self, tmp_path, wire, stdio_tool):
        wire.route(DOWNLOAD_URL, body(b"attacker bytes"))
        victim = tmp_path / "syllabus.pdf"
        victim.write_bytes(b"important pre-existing content")

        download = get_tool_function("download_course_file")
        result = await download("badm_350", 12345, save_directory=str(tmp_path))

        assert "already exists" in result
        assert "Refusing to overwrite" in result
        assert victim.read_bytes() == b"important pre-existing content"
        # Refused before downloading anything.
        assert wire.requests == []

    @pytest.mark.asyncio
    async def test_symlink_destination_is_not_followed(self, tmp_path, wire, stdio_tool):
        """A pre-planted symlink must not redirect the write to its target."""
        wire.route(DOWNLOAD_URL, body(b"attacker bytes"))
        outside = tmp_path / "outside.txt"
        outside.write_bytes(b"do not touch")
        save_dir = tmp_path / "downloads"
        save_dir.mkdir()
        try:
            (save_dir / "syllabus.pdf").symlink_to(outside)
        except OSError as exc:
            if sys.platform != "win32":
                raise
            # Windows lets only administrators or Developer Mode create
            # symlinks (WinError 1314 otherwise), and there is no unprivileged
            # file-link equivalent: a junction targets directories only, and a
            # hard link is the plain existing-file case covered above. Where
            # the privilege exists (e.g. GitHub's Windows runners) this runs.
            pytest.skip(f"cannot create a file symlink without privilege: {exc}")

        download = get_tool_function("download_course_file")
        result = await download("badm_350", 12345, save_directory=str(save_dir))

        assert result.lower().startswith("error")
        assert outside.read_bytes() == b"do not touch"

    @pytest.mark.asyncio
    async def test_partial_file_removed_on_failure(self, tmp_path, wire, stdio_tool):
        """A failed download must not leave a truncated file behind."""
        wire.route(DOWNLOAD_URL, redirect(STORAGE_URL))
        wire.route(STORAGE_URL, lambda request: httpx.Response(403, text="AccessDenied"))

        download = get_tool_function("download_course_file")
        result = await download("badm_350", 12345, save_directory=str(tmp_path))

        assert "Error downloading file" in result
        assert "HTTP 403" in result
        # The signed storage URL and the Canvas verifier are never echoed.
        assert "s1gn3d" not in result and "v3r1f13r" not in result
        assert not (tmp_path / "syllabus.pdf").exists()
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.asyncio
    async def test_partial_file_removed_when_cancelled(self, tmp_path, stdio_tool):
        """A call cancelled mid-download leaves no partial file either."""
        import asyncio

        async def cancelled_midway(url, max_bytes, write):
            write(b"partial")
            raise asyncio.CancelledError

        with patch(
            "canvas_mcp.tools.files.stream_file_download", new=cancelled_midway
        ), pytest.raises(asyncio.CancelledError):
            await get_tool_function("download_course_file")(
                "badm_350", 12345, save_directory=str(tmp_path)
            )

        assert list(tmp_path.iterdir()) == []


class TestUploadRefusedOverHttp:
    """A remote caller must never make the server read its own filesystem."""

    @pytest.mark.asyncio
    async def test_upload_refused_over_http(self, tmp_path):
        secret = tmp_path / "secret.txt"
        secret.write_text("service-account readable content")

        with patch(
            "canvas_mcp.tools.files.is_http_request_active", return_value=True
        ), patch(
            "canvas_mcp.tools.files.make_canvas_request", new_callable=AsyncMock
        ) as request, patch(
            "canvas_mcp.tools.files.upload_file_to_storage", new_callable=AsyncMock
        ) as storage, patch(
            "canvas_mcp.tools.files.validate_file_for_upload"
        ) as validate, patch(
            "canvas_mcp.tools.files.get_course_id", new=AsyncMock(return_value="60366")
        ):
            upload = get_tool_function("upload_course_file")
            result = await upload("badm_350", str(secret))

        assert "only available on a local (stdio) server" in result
        # The refusal precedes every side effect: no Canvas call, no upload, and
        # not even a local stat of the requested path.
        assert request.call_count == 0
        assert storage.call_count == 0
        assert validate.call_count == 0

    @pytest.mark.asyncio
    async def test_upload_refusal_precedes_path_probing(self, tmp_path):
        """The error must not reveal whether the requested path exists."""
        with patch(
            "canvas_mcp.tools.files.is_http_request_active", return_value=True
        ), patch(
            "canvas_mcp.tools.files.get_course_id", new=AsyncMock(return_value="60366")
        ):
            upload = get_tool_function("upload_course_file")
            missing = await upload("badm_350", str(tmp_path / "does-not-exist"))
            present = await upload("badm_350", str(tmp_path))

        assert missing == present


class TestDownloadPermissions:
    """Downloads land owner-only; the bytes come from a third party."""

    @pytest.mark.skipif(
        sys.platform == "win32",
        reason=(
            "POSIX permission bits: on Windows os.open's mode only sets the "
            "read-only attribute and st_mode always reports 0o666/0o444; access "
            "is governed by the ACL inherited from the destination directory."
        ),
    )
    @pytest.mark.asyncio
    async def test_downloaded_file_is_owner_only(self, tmp_path, wire, stdio_tool):
        wire.route(DOWNLOAD_URL, body(b"file content here"))

        download = get_tool_function("download_course_file")
        await download("badm_350", 12345, save_directory=str(tmp_path))

        mode = os.stat(tmp_path / "syllabus.pdf").st_mode & 0o777
        assert mode == 0o600


class TestDownloadIsPortable:
    """The hardening must not break a supported platform.

    O_NOFOLLOW is POSIX-only. Naming os.O_NOFOLLOW directly raises AttributeError
    on Windows before os.open runs, and the handlers below it catch only
    FileExistsError and OSError, so every local download would fail there.
    """

    def test_open_flags_survive_a_missing_o_nofollow(self, monkeypatch):
        import canvas_mcp.tools.files as files_module

        monkeypatch.delattr(files_module.os, "O_NOFOLLOW", raising=False)
        flags = (
            files_module.os.O_WRONLY
            | files_module.os.O_CREAT
            | files_module.os.O_EXCL
            | getattr(files_module.os, "O_NOFOLLOW", 0)
        )
        # Exclusive creation, the bulk of the protection, is still requested.
        assert flags & files_module.os.O_EXCL

    @pytest.mark.asyncio
    async def test_download_works_without_o_nofollow(
        self, tmp_path, monkeypatch, wire, stdio_tool
    ):
        """Simulates Windows: the platform flag is absent, download still works."""
        import canvas_mcp.tools.files as files_module

        monkeypatch.delattr(files_module.os, "O_NOFOLLOW", raising=False)
        wire.route(DOWNLOAD_URL, body(b"file content here"))

        download = get_tool_function("download_course_file")
        result = await download("badm_350", 12345, save_directory=str(tmp_path))

        assert "syllabus.pdf" in result and "Downloaded:" in result
        assert (tmp_path / "syllabus.pdf").read_bytes() == b"file content here"

    @pytest.mark.asyncio
    async def test_overwrite_refusal_still_holds_without_o_nofollow(
        self, tmp_path, monkeypatch, wire, stdio_tool
    ):
        import canvas_mcp.tools.files as files_module

        monkeypatch.delattr(files_module.os, "O_NOFOLLOW", raising=False)
        wire.route(DOWNLOAD_URL, body(b"attacker bytes"))
        (tmp_path / "syllabus.pdf").write_bytes(b"pre-existing")

        download = get_tool_function("download_course_file")
        result = await download("badm_350", 12345, save_directory=str(tmp_path))

        assert "already exists" in result
        assert (tmp_path / "syllabus.pdf").read_bytes() == b"pre-existing"


# Files tab hidden: the course route is refused, the module links the file.
HIDDEN_TAB_MODULES = [
    {"id": 11, "name": "Week 1", "items": [
        {"id": 1, "type": "File", "content_id": 12345, "title": "Syllabus"},
    ]},
]


@pytest.fixture(params=["course", "module"])
def download_route(request):
    """download_course_file reaching its metadata through either route.

    ``course``: GET /courses/:id/files/:id answers. ``module``: that route is
    refused (hidden Files tab) and the file is read through the module that
    links it (GET /files/:id). Yields a function that sets the download URL
    Canvas reports for the file, and a check that the route was taken.
    """
    course_get = AsyncMock()
    files_get = AsyncMock()
    module_fetch = AsyncMock(return_value=HIDDEN_TAB_MODULES)

    def set_info(info: dict) -> None:
        if request.param == "course":
            course_get.return_value = info
        else:
            course_get.return_value = {"error": "HTTP error: 403, Details: {}"}
            files_get.return_value = info

    def check_route(result: str, noted: bool = True) -> None:
        course_get.assert_awaited_once_with("get", "/courses/60366/files/12345")
        if request.param == "module":
            files_get.assert_awaited_once_with("get", "/files/12345")
            if noted:
                assert "Note: Canvas refused the course Files route" in result
        else:
            files_get.assert_not_awaited()
            module_fetch.assert_not_awaited()

    with patch(
        "canvas_mcp.tools.files.is_http_request_active", return_value=False
    ), patch(
        "canvas_mcp.tools.files.get_course_id", new=AsyncMock(return_value="60366")
    ), patch(
        "canvas_mcp.tools.files.get_course_code", new=AsyncMock(return_value="badm_350")
    ), patch(
        "canvas_mcp.tools.files.make_canvas_request", new=course_get
    ), patch(
        "canvas_mcp.core.course_files.make_canvas_request", new=files_get
    ), patch(
        "canvas_mcp.core.course_files.fetch_all_paginated_results", new=module_fetch
    ):
        set_info(FILE_INFO)
        yield set_info, check_route


class TestDownloadTokenBoundary:
    """download_course_file: the Canvas token reaches the Canvas origin only."""

    @pytest.mark.asyncio
    async def test_storage_redirect_never_carries_authorization(
        self, tmp_path, wire, download_route, monkeypatch
    ):
        _, check_route = download_route
        wire.route(DOWNLOAD_URL, redirect(STORAGE_URL))
        wire.route(STORAGE_URL, body(b"%PDF-1.4 slides"))
        # The recorder sees a request whoever follows the redirect, so record
        # how each hop was asked for: the library must never follow on its own.
        follow_flags: list[object] = []
        real_stream = httpx.AsyncClient.stream

        def recording_stream(self, method, url, **kwargs):
            follow_flags.append(kwargs.get("follow_redirects", "unset"))
            return real_stream(self, method, url, **kwargs)

        monkeypatch.setattr(httpx.AsyncClient, "stream", recording_stream)

        result = await get_tool_function("download_course_file")(
            "badm_350", 12345, save_directory=str(tmp_path)
        )

        check_route(result)
        assert "Downloaded:" in result
        assert (tmp_path / "syllabus.pdf").read_bytes() == b"%PDF-1.4 slides"
        assert wire.auth_by_host() == [
            ("canvas.example.edu", f"Bearer {TOKEN}"),
            ("files.storage.example.net", None),
        ]
        assert wire.token_seen_by() == {"canvas.example.edu"}
        # Exactly one request to Canvas and one to storage, each fetched by
        # hand with library redirect following turned off.
        assert len(wire.requests) == 2
        assert follow_flags == [False, False]

    @pytest.mark.asyncio
    async def test_chained_redirects_off_canvas_never_carry_authorization(
        self, tmp_path, wire, download_route
    ):
        """Storage bouncing to a lookalike of the Canvas host gets no token."""
        _, check_route = download_route
        lookalike = "https://canvas.example.edu.attacker.example/collect"
        wire.route(DOWNLOAD_URL, redirect(STORAGE_URL))
        wire.route(STORAGE_URL, redirect(lookalike, status=307))
        wire.route(lookalike, body(b"bytes"))

        result = await get_tool_function("download_course_file")(
            "badm_350", 12345, save_directory=str(tmp_path)
        )

        check_route(result)
        assert [host for host, _ in wire.auth_by_host()] == [
            "canvas.example.edu",
            "files.storage.example.net",
            "canvas.example.edu.attacker.example",
        ]
        assert wire.token_seen_by() == {"canvas.example.edu"}

    @pytest.mark.asyncio
    async def test_storage_cannot_bounce_back_to_an_authenticated_canvas_get(
        self, tmp_path, wire, download_route
    ):
        """After leaving Canvas, a hop back to a Canvas API path gets no token.

        Otherwise the storage host would choose which authenticated Canvas GET
        the server makes for the student, and the response would be saved as
        the file.
        """
        _, check_route = download_route
        profile = f"{CANVAS}/api/v1/users/self/profile"
        wire.route(DOWNLOAD_URL, redirect(STORAGE_URL))
        wire.route(STORAGE_URL, redirect(profile))
        wire.route(profile, lambda request: (
            httpx.Response(200, content=b'{"name": "Student"}')
            if request.headers.get("Authorization")
            else httpx.Response(401, text="unauthenticated")
        ))

        result = await get_tool_function("download_course_file")(
            "badm_350", 12345, save_directory=str(tmp_path)
        )

        check_route(result, noted=False)
        assert wire.auth_by_host() == [
            ("canvas.example.edu", f"Bearer {TOKEN}"),
            ("files.storage.example.net", None),
            ("canvas.example.edu", None),
        ]
        third = wire.requests[2]
        assert not any(TOKEN in value for value in third.headers.values())
        assert result.startswith("Error downloading file") and "HTTP 401" in result
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.asyncio
    async def test_non_canvas_download_url_never_sees_the_token(
        self, tmp_path, wire, download_route
    ):
        """A file whose Canvas-reported URL is already off-Canvas gets no token."""
        set_info, check_route = download_route
        set_info(file_info(url=STORAGE_URL))
        wire.route(STORAGE_URL, body(b"bytes"))

        result = await get_tool_function("download_course_file")(
            "badm_350", 12345, save_directory=str(tmp_path)
        )

        check_route(result)
        assert wire.auth_by_host() == [("files.storage.example.net", None)]
        assert (tmp_path / "syllabus.pdf").read_bytes() == b"bytes"

    @pytest.mark.asyncio
    async def test_plain_http_non_canvas_hop_is_refused_unsent(
        self, tmp_path, wire, download_route
    ):
        _, check_route = download_route
        insecure = "http://files.storage.example.net/blob/abc"
        wire.route(DOWNLOAD_URL, redirect(insecure))
        wire.route(insecure, body(b"bytes"))

        result = await get_tool_function("download_course_file")(
            "badm_350", 12345, save_directory=str(tmp_path)
        )

        check_route(result, noted=False)
        assert result.startswith("Error downloading file")
        assert "non-HTTPS" in result
        # The http:// hop was never requested, with or without the token.
        assert [str(r.url) for r in wire.requests] == [DOWNLOAD_URL]
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.asyncio
    async def test_redirect_hops_are_capped(self, tmp_path, wire, download_route):
        _, check_route = download_route
        wire.route(DOWNLOAD_URL, redirect(STORAGE_URL))
        wire.route(STORAGE_URL, redirect(STORAGE_URL))

        result = await get_tool_function("download_course_file")(
            "badm_350", 12345, save_directory=str(tmp_path)
        )

        check_route(result, noted=False)
        assert "Too many redirects" in result
        assert len(wire.requests) == MAX_DOWNLOAD_REDIRECTS + 1
        assert wire.token_seen_by() == {"canvas.example.edu"}
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.asyncio
    async def test_size_cap_holds_while_streaming(
        self, tmp_path, wire, download_route, monkeypatch
    ):
        """Storage sends more than Canvas reported, with no Content-Length.

        The reported size passes the up-front check, so only the streaming
        cap stops it; the partial file is removed.
        """
        set_info, check_route = download_route
        set_info(file_info(size=50))
        # 0.0001 MB is 104 bytes: the 500-byte body overruns it mid-stream.
        configure_download_limit(monkeypatch, "0.0001")
        wire.route(DOWNLOAD_URL, redirect(STORAGE_URL))
        wire.route(STORAGE_URL, lambda request: httpx.Response(
            200, stream=httpx.ByteStream(b"x" * 500)
        ))

        result = await get_tool_function("download_course_file")(
            "badm_350", 12345, save_directory=str(tmp_path)
        )

        check_route(result, noted=False)
        assert result.startswith("Error downloading file")
        assert "download limit" in result and "DOWNLOAD_FILE_MAX_SIZE_MB" in result
        assert len(wire.requests) == 2
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.asyncio
    async def test_reported_size_over_cap_is_refused_before_anything(
        self, tmp_path, wire, download_route, monkeypatch
    ):
        from canvas_mcp.core.config import reset_config

        set_info, check_route = download_route
        # The default cap is 1 GB.
        monkeypatch.delenv("DOWNLOAD_FILE_MAX_SIZE_MB", raising=False)
        reset_config()
        set_info(file_info(size=1024 * 1024 * 1024 + 1))

        result = await get_tool_function("download_course_file")(
            "badm_350", 12345, save_directory=str(tmp_path)
        )

        # Refused before the route note is written, so only the route is checked.
        check_route(result, noted=False)
        assert result.startswith("Error:")
        assert "1 GB download limit" in result and "Nothing was downloaded" in result
        # The refusal names the setting a local user raises to allow more.
        assert "DOWNLOAD_FILE_MAX_SIZE_MB=1024" in result
        assert wire.requests == []
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.asyncio
    async def test_configured_limit_lowers_the_cap(
        self, tmp_path, wire, download_route, monkeypatch
    ):
        set_info, check_route = download_route
        set_info(file_info(size=2 * 1024 * 1024))
        configure_download_limit(monkeypatch, "1")

        result = await get_tool_function("download_course_file")(
            "badm_350", 12345, save_directory=str(tmp_path)
        )

        check_route(result, noted=False)
        assert result.startswith("Error:")
        assert "1 MB download limit" in result and "DOWNLOAD_FILE_MAX_SIZE_MB=1 " in result
        assert wire.requests == []
        assert list(tmp_path.iterdir()) == []

    @pytest.mark.asyncio
    async def test_configured_limit_raises_the_cap(
        self, tmp_path, wire, download_route, monkeypatch
    ):
        """A local user can allow a file over the 1 GB default."""
        import canvas_mcp.tools.files as files_module

        set_info, check_route = download_route
        set_info(file_info(size=1536 * 1024 * 1024))
        configure_download_limit(monkeypatch, "2048")
        wire.route(DOWNLOAD_URL, redirect(STORAGE_URL))
        wire.route(STORAGE_URL, body(b"%PDF-1.4 lecture capture"))
        caps: list[int] = []
        real_stream = files_module.stream_file_download

        async def recording_stream(url, max_bytes, write):
            caps.append(max_bytes)
            return await real_stream(url, max_bytes, write)

        monkeypatch.setattr(files_module, "stream_file_download", recording_stream)

        result = await get_tool_function("download_course_file")(
            "badm_350", 12345, save_directory=str(tmp_path)
        )

        check_route(result)
        assert "Downloaded:" in result
        assert caps == [2048 * 1024 * 1024]
        assert (tmp_path / "syllabus.pdf").read_bytes() == b"%PDF-1.4 lecture capture"


UPLOAD_URL = "https://inst-fs.storage.example.net/upload?token=s1gn3d"
CONFIRM_URL = f"{CANVAS}/api/v1/files/777/create_success?uuid=u1"


class TestUploadConfirmationTokenBoundary:
    """upload_file_to_storage follows a Location chosen by the storage host.

    It is reachable from student tools: submit_assignment uploads files with
    it. The token may go to that Location only on the Canvas origin.
    """

    def test_student_submissions_use_this_upload_path(self):
        from canvas_mcp.tools import student_write

        assert student_write.upload_file_to_storage is client_module.upload_file_to_storage

    @staticmethod
    async def _upload(tmp_path):
        source = tmp_path / "essay.txt"
        source.write_text("my essay")
        return await client_module.upload_file_to_storage(
            UPLOAD_URL, {"key": "k"}, str(source), "essay.txt", "text/plain"
        )

    @pytest.mark.asyncio
    async def test_canvas_confirmation_gets_the_token_storage_does_not(self, tmp_path, wire):
        wire.route(UPLOAD_URL, redirect(CONFIRM_URL, status=303), method="POST")
        wire.route(CONFIRM_URL, lambda request: httpx.Response(200, json={"id": 777}))

        result = await self._upload(tmp_path)

        assert result == {"id": 777}
        assert wire.auth_by_host() == [
            ("inst-fs.storage.example.net", None),
            ("canvas.example.edu", f"Bearer {TOKEN}"),
        ]

    @pytest.mark.asyncio
    @pytest.mark.parametrize("location", [
        "https://attacker.example/confirm",
        "https://canvas.example.edu.attacker.example/api/v1/files/777",
        "https://canvas.example.edu:8443/api/v1/files/777",
        "http://canvas.example.edu/api/v1/files/777",
        # Relative: resolves against the storage host, not Canvas.
        "/api/v1/files/777/create_success",
    ])
    async def test_off_canvas_confirmation_is_refused_unsent(
        self, tmp_path, wire, location
    ):
        wire.route(UPLOAD_URL, redirect(location, status=303), method="POST")

        result = await self._upload(tmp_path)

        assert "not followed" in result["error"]
        # Only the storage POST left the process, and it carried no token.
        assert [(r.method, r.url.host) for r in wire.requests] == [
            ("POST", "inst-fs.storage.example.net")
        ]
        assert wire.token_seen_by() == set()

    @pytest.mark.asyncio
    async def test_confirmation_does_not_follow_a_further_redirect(self, tmp_path, wire):
        wire.route(UPLOAD_URL, redirect(CONFIRM_URL, status=303), method="POST")
        wire.route(CONFIRM_URL, redirect("https://attacker.example/again"))

        result = await self._upload(tmp_path)

        assert "error" in result
        assert wire.token_seen_by() == {"canvas.example.edu"}
        assert "attacker.example" not in {r.url.host for r in wire.requests}
