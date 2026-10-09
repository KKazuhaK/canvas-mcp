"""Serves the built single-page account UI under ``/account/``.

The bundle (``web/dist`` in development, ``/app/web-dist`` in the image) is read once
at startup into memory and checked: one ``index.html`` that loads exactly one module
script from ``/account/assets/``, flat asset files with plain names, every local
reference present. Nothing is read from disk while serving, so a request can never
reach a file that was not validated at startup, whatever path it names.

Every response carries a strict Content Security Policy (scripts and connections
from this origin only), ``index.html`` is never cached, and the hashed files under
``/account/assets/`` are cached for a year. Any other GET below ``/account/`` that is
not ``/account/api`` answers with ``index.html`` (the client-side router decides what
to show); an unknown asset is a plain 404, never ``index.html``.

If the bundle is unusable the caller falls back to the server-rendered pages (see
:func:`~.app.install_selfhost`); this module never serves a half-working page.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from starlette.requests import Request
from starlette.responses import Response
from starlette.routing import Route

ASSETS_PREFIX = "/account/assets/"
BASE_PATH = "/account"

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'self'"
)
SECURITY_HEADERS = {
    "Content-Security-Policy": CSP,
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
IMMUTABLE = "public, max-age=31536000, immutable"
ROOT_CACHE = "public, max-age=86400"

MAX_INDEX_BYTES = 256 * 1024
MAX_ASSET_BYTES = 5 * 1024 * 1024
MAX_TOTAL_ASSET_BYTES = 20 * 1024 * 1024
MAX_PATH_CHARS = 512
#: The only files outside ``assets/`` that are served, besides ``index.html``.
ROOT_EXTRAS = ("favicon.svg",)

CONTENT_TYPES: Mapping[str, str] = {
    ".js": "text/javascript; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".svg": "image/svg+xml",
    ".woff2": "font/woff2",
    ".png": "image/png",
    ".ico": "image/x-icon",
    ".json": "application/json",
    ".webmanifest": "application/manifest+json",
}

_ASSET_NAME_RE = re.compile(r"^[A-Za-z0-9._-]+$")
_SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.IGNORECASE | re.DOTALL)
_TAG_RE = re.compile(r"<(?:script|link|img|source|iframe)\b[^>]*>", re.IGNORECASE)
_URL_ATTR_RE = re.compile(r'\b(?:src|href)\s*=\s*"([^"]*)"', re.IGNORECASE)
_TYPE_MODULE_RE = re.compile(r'\btype\s*=\s*"module"', re.IGNORECASE)
_SRC_RE = re.compile(r'\bsrc\s*=\s*"([^"]+)"', re.IGNORECASE)


class SpaBundleError(Exception):
    """The built UI cannot be served. ``reason`` is a short fixed label (no paths)."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


@dataclass(frozen=True)
class SpaFile:
    """One served file, held in memory."""

    body: bytes
    content_type: str
    etag: str


def _file(body: bytes, content_type: str) -> SpaFile:
    return SpaFile(body, content_type, '"' + hashlib.sha256(body).hexdigest()[:32] + '"')


@dataclass(frozen=True)
class SpaBundle:
    """A validated build of the account UI."""

    index: SpaFile
    assets: Mapping[str, SpaFile]
    extras: Mapping[str, SpaFile]

    @classmethod
    def load(cls, root: Path) -> SpaBundle:
        """Read and validate the build at ``root``; raise :class:`SpaBundleError` if unusable."""
        try:
            real_root = root.resolve(strict=True)
        except (OSError, RuntimeError):
            raise SpaBundleError("directory_missing") from None
        if not real_root.is_dir():
            raise SpaBundleError("directory_missing")

        index_bytes = _read_regular(real_root / "index.html", real_root, MAX_INDEX_BYTES, "index")
        assets = _load_assets(real_root)
        extras: dict[str, SpaFile] = {}
        for name in ROOT_EXTRAS:
            candidate = real_root / name
            if candidate.exists() or candidate.is_symlink():
                body = _read_regular(candidate, real_root, MAX_ASSET_BYTES, "extra")
                extras[name] = _file(body, _content_type(name, "extra"))
        _check_index(index_bytes, assets, extras)
        return cls(_file(index_bytes, "text/html; charset=utf-8"), assets, extras)


def _content_type(name: str, what: str) -> str:
    dot = name.rfind(".")
    content_type = CONTENT_TYPES.get(name[dot:].lower()) if dot >= 0 else None
    if content_type is None:
        raise SpaBundleError(f"{what}_type_not_allowed")
    return content_type


def _read_regular(path: Path, root: Path, limit: int, what: str) -> bytes:
    """The bytes of a regular file that really lives inside ``root`` and is small enough."""
    try:
        resolved = path.resolve(strict=True)
        if not resolved.is_relative_to(root):
            raise SpaBundleError(f"{what}_outside_directory")
        if not resolved.is_file():
            raise SpaBundleError(f"{what}_not_a_file")
        if resolved.stat().st_size > limit:
            raise SpaBundleError(f"{what}_too_large")
        body = resolved.read_bytes()
    except SpaBundleError:
        raise
    except (OSError, RuntimeError):
        raise SpaBundleError(f"{what}_unreadable") from None
    if len(body) > limit:
        raise SpaBundleError(f"{what}_too_large")
    return body


def _load_assets(root: Path) -> dict[str, SpaFile]:
    directory = root / "assets"
    try:
        if directory.is_symlink() or not directory.is_dir():
            raise SpaBundleError("assets_missing")
        entries = sorted(directory.iterdir(), key=lambda p: p.name)
    except OSError:
        raise SpaBundleError("assets_unreadable") from None
    assets: dict[str, SpaFile] = {}
    total = 0
    for entry in entries:
        name = entry.name
        if not _ASSET_NAME_RE.fullmatch(name) or name in (".", ".."):
            raise SpaBundleError("asset_name_not_allowed")
        body = _read_regular(entry, root, MAX_ASSET_BYTES, "asset")
        total += len(body)
        if total > MAX_TOTAL_ASSET_BYTES:
            raise SpaBundleError("assets_too_large")
        assets[name] = _file(body, _content_type(name, "asset"))
    if not assets:
        raise SpaBundleError("assets_missing")
    return assets


def _check_index(
    raw: bytes, assets: Mapping[str, SpaFile], extras: Mapping[str, SpaFile]
) -> None:
    try:
        html = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise SpaBundleError("index_not_utf8") from None
    scripts = _SCRIPT_RE.findall(html)
    if len(scripts) != 1 or len(re.findall(r"<script\b", html, re.IGNORECASE)) != 1:
        raise SpaBundleError("index_script_count")
    attrs, body = scripts[0]
    if body.strip() or not _TYPE_MODULE_RE.search(attrs):
        raise SpaBundleError("index_script_not_a_module")
    source = _SRC_RE.search(attrs)
    if source is None or not source.group(1).startswith(ASSETS_PREFIX):
        raise SpaBundleError("index_script_not_under_assets")
    for tag in _TAG_RE.findall(html):
        for url in _URL_ATTR_RE.findall(tag):
            if url.startswith(ASSETS_PREFIX):
                if url[len(ASSETS_PREFIX) :] not in assets:
                    raise SpaBundleError("index_reference_missing")
            elif url.startswith(BASE_PATH + "/") and url[len(BASE_PATH) + 1 :] in extras:
                continue
            else:
                raise SpaBundleError("index_reference_not_local")


class _SpaApp:
    def __init__(self, bundle: SpaBundle) -> None:
        self.bundle = bundle

    @staticmethod
    def _headers(extra: Mapping[str, str]) -> dict[str, str]:
        return {**SECURITY_HEADERS, **extra}

    def _refuse_method(self) -> Response:
        return Response(
            "Method not allowed.",
            status_code=405,
            headers=self._headers(
                {
                    "Allow": "GET, HEAD",
                    "Cache-Control": "no-store",
                    "Content-Type": "text/plain; charset=utf-8",
                }
            ),
        )

    def not_found(self) -> Response:
        return Response(
            "Not found.",
            status_code=404,
            headers=self._headers(
                {"Cache-Control": "no-store", "Content-Type": "text/plain; charset=utf-8"}
            ),
        )

    def _serve(self, request: Request, file: SpaFile, cache: str, *, etag: bool) -> Response:
        headers = {"Cache-Control": cache, "Content-Type": file.content_type}
        if etag:
            headers["ETag"] = file.etag
            if request.headers.get("if-none-match") == file.etag:
                return Response(b"", status_code=304, headers=self._headers(headers))
        else:
            headers["Pragma"] = "no-cache"
        if request.method == "HEAD":
            headers["Content-Length"] = str(len(file.body))
            return Response(b"", headers=self._headers(headers))
        return Response(file.body, headers=self._headers(headers))

    async def index(self, request: Request) -> Response:
        if request.method not in ("GET", "HEAD"):
            return self._refuse_method()
        path = request.url.path
        if len(path) > MAX_PATH_CHARS or any(ord(ch) < 0x20 or ord(ch) == 0x7F for ch in path):
            return self.not_found()
        return self._serve(request, self.bundle.index, "no-store", etag=False)

    async def asset(self, request: Request) -> Response:
        if request.method not in ("GET", "HEAD"):
            return self._refuse_method()
        name = request.path_params.get("name", "")
        file = self.bundle.assets.get(name) if isinstance(name, str) else None
        if file is None:
            return self.not_found()
        return self._serve(request, file, IMMUTABLE, etag=True)

    async def extra(self, request: Request) -> Response:
        if request.method not in ("GET", "HEAD"):
            return self._refuse_method()
        file = self.bundle.extras.get(request.url.path.rsplit("/", 1)[-1])
        if file is None:
            return self.not_found()
        return self._serve(request, file, ROOT_CACHE, etag=True)


_ALL = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"]


def build_spa_routes(bundle: SpaBundle) -> list[Route]:
    """The routes that serve ``bundle``. Register them after the ``/account/api`` routes."""
    app = _SpaApp(bundle)
    routes = [
        Route("/account/assets", app.asset, methods=_ALL),
        Route("/account/assets/{name:path}", app.asset, methods=_ALL),
    ]
    routes.extend(Route(f"/account/{name}", app.extra, methods=_ALL) for name in bundle.extras)
    routes.append(Route("/account", app.index, methods=_ALL))
    routes.append(Route("/account/{path:path}", app.index, methods=_ALL))
    return routes
