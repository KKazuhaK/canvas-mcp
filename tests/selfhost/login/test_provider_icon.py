"""Database-owned bounded PNG icons survive unrelated registration edits."""

import base64
import struct
import zlib

import pytest

from canvas_mcp.core.selfhost.login.provider_config import ProviderConfigurationError
from canvas_mcp.core.selfhost.login.provider_icon import PREFIX, validate_icon

from ..authz.stack import BASE
from .test_admin_upn import login
from .test_database_login_api import installation
from .test_local_accounts import initialize


def png(width=1, height=1):
    def chunk(kind, data):
        return (
            struct.pack(">I", len(data))
            + kind
            + data
            + struct.pack(">I", zlib.crc32(kind + data))
        )

    raw = (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", struct.pack(">IIBBBBB", width, height, 8, 6, 0, 0, 0))
        + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00\xff"))
        + chunk(b"IEND", b"")
    )
    return PREFIX + base64.b64encode(raw).decode("ascii")


@pytest.mark.parametrize(
    "value",
    [
        "https://icons.test/icon.png",
        "data:image/svg+xml;base64,PHN2Zz4=",
        PREFIX + "bad!",
        png(513),
        png(0),
        PREFIX + base64.b64encode(b"not-png").decode("ascii"),
        PREFIX + "A" * 100000,
    ],
    ids=["remote", "svg", "base64", "dimensions", "zero", "signature", "size"],
)
def test_rejects_remote_executable_malformed_or_oversized_icons(value):
    with pytest.raises(ProviderConfigurationError):
        validate_icon(value)


def test_icon_upload_is_governed_public_and_retained_or_reset(tmp_path):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        _, headers = login(client, "admin")
        icon = png()
        body = {
            "revision": 1,
            "config": {},
            "enabled": True,
            "rank": 0,
            "icon_data": icon,
        }
        route = "/api/v1/admin/login-providers/local"
        assert client.put(route, headers={"Origin": BASE}, json=body).status_code == 403
        uploaded = client.put(route, headers=headers, json=body)
        assert uploaded.status_code == 200, uploaded.text
        assert uploaded.json()["providers"][0]["icon_data"] == icon
        assert (
            client.get("/api/v1/providers").json()["providers"][0]["icon_data"] == icon
        )
        body.pop("icon_data")
        body["revision"] = 2
        assert client.put(route, headers=headers, json=body).status_code == 200
        assert runtime.provider_store.list_public()[0]["icon_data"] == icon
        assert (
            client.put(
                route,
                headers=headers,
                json={**body, "revision": 3, "icon_data": "https://bad.test/icon.svg"},
            ).status_code
            == 422
        )
        reset = client.put(
            route, headers=headers, json={**body, "revision": 3, "icon_data": None}
        )
        assert reset.status_code == 200
        assert "icon_data" not in client.get("/api/v1/providers").json()["providers"][0]
        assert all(icon not in str(row.detail) for row in runtime.store.iter_audit())
