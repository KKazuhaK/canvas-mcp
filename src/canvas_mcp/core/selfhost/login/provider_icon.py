"""Small embedded PNG icons; no remote fetches, SVG or executable image formats."""

import base64
import binascii
import struct
import zlib

from .provider_config import ProviderConfigurationError

PREFIX = "data:image/png;base64,"
MAX_ICON_BYTES = 65536


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
                return value
            offset = end
        raise ValueError
    except (ValueError, binascii.Error, struct.error):
        raise ProviderConfigurationError() from None
