"""Bounded PNG uploads and content-addressed files in the persistent data volume."""

import base64
import binascii
import hashlib
import io
import os
import re
import struct
import tempfile
import zlib
from contextlib import suppress
from pathlib import Path

from PIL import Image, UnidentifiedImageError
from starlette.routing import Route

from .provider_config import ProviderConfigurationError

PREFIX = "data:image/png;base64,"
MAX_ICON_BYTES = 65536
ICON_PATH = "/account/provider-icons/"
_REFERENCE = re.compile(r"/account/provider-icons/[a-f0-9]{64}\.png\Z")


def validate_icon_reference(value: object) -> str | None:
    if value is None:
        return None
    if not isinstance(value, str) or not _REFERENCE.fullmatch(value):
        raise ProviderConfigurationError()
    return value


def validate_icon(value: object) -> str | None:
    if value is None:
        return None
    try:
        if (
            not isinstance(value, str)
            or not value.startswith(PREFIX)
            or len(value) > 87406
        ):
            raise ValueError
        raw = base64.b64decode(value[len(PREFIX) :], validate=True)
        if len(raw) > MAX_ICON_BYTES or raw[:8] != b"\x89PNG\r\n\x1a\n":
            raise ValueError
        offset, first, image_data = 8, True, False
        while offset + 12 <= len(raw):
            size = struct.unpack(">I", raw[offset : offset + 4])[0]
            end = offset + size + 12
            if end > len(raw):
                raise ValueError
            kind = raw[offset + 4 : offset + 8]
            payload = raw[offset + 8 : end - 4]
            crc = struct.unpack(">I", raw[end - 4 : end])[0]
            if zlib.crc32(kind + payload) != crc:
                raise ValueError
            if first:
                if kind != b"IHDR" or size != 13:
                    raise ValueError
                width, height = struct.unpack(">II", payload[:8])
                if not 1 <= width <= 512 or not 1 <= height <= 512:
                    raise ValueError
                first = False
            elif kind == b"IHDR":
                raise ValueError
            image_data = image_data or kind == b"IDAT"
            if kind == b"IEND":
                if size or end != len(raw) or not image_data:
                    raise ValueError
                # Decode pixels, discard metadata and normalize the persisted format.
                with Image.open(io.BytesIO(raw), formats=["PNG"]) as source:
                    if getattr(source, "n_frames", 1) != 1:
                        raise ValueError
                    source.load()
                    pixels = source.convert("RGBA")
                pixels.info.clear()
                for side in (256, 192, 128, 96, 64):
                    pixels.thumbnail((side, side), Image.Resampling.LANCZOS)
                    output = io.BytesIO()
                    pixels.save(output, format="PNG", optimize=True)
                    if output.tell() <= MAX_ICON_BYTES:
                        return PREFIX + base64.b64encode(output.getvalue()).decode(
                            "ascii"
                        )
                raise ValueError
            offset = end
        raise ValueError
    except (
        ValueError,
        binascii.Error,
        struct.error,
        OSError,
        SyntaxError,
        UnidentifiedImageError,
    ):
        raise ProviderConfigurationError() from None


class ProviderIconFiles:
    def __init__(self, directory: Path):
        self.directory = directory

    def save(self, normalized: str) -> str:
        raw = base64.b64decode(normalized[len(PREFIX) :], validate=True)
        name = hashlib.sha256(raw).hexdigest() + ".png"
        temporary: str | None = None
        try:
            self.directory.mkdir(mode=0o700, parents=True, exist_ok=True)
            with tempfile.NamedTemporaryFile(
                dir=self.directory, delete=False
            ) as stream:
                temporary = stream.name
                stream.write(raw)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.directory / name)
        except OSError:
            raise ProviderConfigurationError(
                "provider_configuration_unavailable"
            ) from None
        finally:
            if temporary is not None:
                with suppress(OSError):
                    Path(temporary).unlink(missing_ok=True)
        return ICON_PATH + name

    def read(self, reference: str) -> bytes | None:
        validate_icon_reference(reference)
        path = self.directory / reference.removeprefix(ICON_PATH)
        try:
            if path.is_symlink():
                return None
            with path.open("rb") as stream:
                raw = stream.read(MAX_ICON_BYTES + 1)
        except OSError:
            return None
        if (
            len(raw) > MAX_ICON_BYTES
            or not raw.startswith(b"\x89PNG\r\n\x1a\n")
            or hashlib.sha256(raw).hexdigest() + ".png" != path.name
        ):
            return None
        return raw


def build_icon_routes(files: ProviderIconFiles | None) -> list[Route]:
    """Serve only hashed PNG files; never expose the containing data directory."""
    from anyio import to_thread
    from starlette.requests import Request
    from starlette.responses import Response

    async def icon(request: Request) -> Response:
        reference = ICON_PATH + request.path_params["filename"]
        try:
            validate_icon_reference(reference)
        except ProviderConfigurationError:
            return Response(status_code=404)
        raw = await to_thread.run_sync(files.read, reference) if files else None
        if raw is None:
            return Response(status_code=404)
        headers = {
            "Cache-Control": "public, max-age=31536000, immutable",
            "X-Content-Type-Options": "nosniff",
            "ETag": '"' + request.path_params["filename"][:-4] + '"',
        }
        return Response(raw, media_type="image/png", headers=headers)

    return [Route(ICON_PATH + "{filename}", icon, methods=["GET"])]
