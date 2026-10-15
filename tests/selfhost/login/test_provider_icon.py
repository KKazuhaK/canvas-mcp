"""Database-owned bounded PNG icons survive unrelated registration edits."""

import base64
import hashlib
import io
import struct
import zlib

import pytest
from PIL import Image, PngImagePlugin
from sqlalchemy import select

from canvas_mcp.core.selfhost.db import schema
from canvas_mcp.core.selfhost.login.provider_config import ProviderConfigurationError
from canvas_mcp.core.selfhost.login.provider_icon import (
    PREFIX,
    ProviderIconFiles,
    validate_icon,
    validate_icon_reference,
)

from ..authz.stack import BASE, local_stack
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
        reference = uploaded.json()["providers"][0]["icon_data"]
        assert validate_icon_reference(reference) == reference
        assert not reference.startswith("data:")
        assert (
            client.get("/api/v1/providers").json()["providers"][0]["icon_data"]
            == reference
        )
        raw = runtime.provider_store.icons.read(reference)
        assert raw is not None
        assert hashlib.sha256(raw).hexdigest() in reference
        assert (
            runtime.settings.data_dir / "provider-icons" / reference.rsplit("/", 1)[1]
        ).read_bytes() == raw
        with runtime.store.database.read() as conn:
            assert (
                conn.execute(
                    select(schema.login_providers.c.icon_data).where(
                        schema.login_providers.c.id == "local"
                    )
                ).scalar_one()
                == reference
            )
        # The login page must be able to read its logo before signing in.
        client.cookies.clear()
        served = client.get(reference)
        assert served.status_code == 200 and served.content == raw
        assert served.headers["content-type"] == "image/png"
        assert served.headers["x-content-type-options"] == "nosniff"
        _, headers = login(client, "admin")
        body.pop("icon_data")
        body["revision"] = 2
        assert client.put(route, headers=headers, json=body).status_code == 200
        assert runtime.provider_store.list_public()[0]["icon_data"] == reference
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


def test_resize_preserves_aspect_and_alpha_without_metadata(tmp_path):
    source = Image.new("RGBA", (512, 256), (23, 67, 98, 80))
    metadata = PngImagePlugin.PngInfo()
    metadata.add_text("private", "not retained")
    output = io.BytesIO()
    source.save(output, format="PNG", pnginfo=metadata)
    normalized = validate_icon(PREFIX + base64.b64encode(output.getvalue()).decode())
    files = ProviderIconFiles(tmp_path / "icons")
    reference = files.save(normalized)
    # A newly constructed store can serve the same bytes (restart contract).
    raw = ProviderIconFiles(tmp_path / "icons").read(reference)
    assert len(raw) <= 65536
    with Image.open(io.BytesIO(raw)) as image:
        assert image.size == (256, 128)
        assert image.getpixel((0, 0))[3] == 80
        assert "private" not in image.info
    assert files.save(normalized) == reference
    assert len(list((tmp_path / "icons").iterdir())) == 1


@pytest.mark.parametrize(
    "value",
    [
        "/data/runtime-secrets.json",
        "/account/provider-icons/../secrets",
        "/account/provider-icons/" + "0" * 64 + ".svg",
        PREFIX + "abcd",
    ],
)
def test_references_cannot_escape_asset_directory(value):
    with pytest.raises(ProviderConfigurationError):
        validate_icon_reference(value)


def test_corrupt_missing_and_oversized_files_are_not_served(tmp_path):
    files = ProviderIconFiles(tmp_path)
    reference = files.save(validate_icon(png()))
    path = tmp_path / reference.rsplit("/", 1)[1]
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"private data")
    assert files.read(reference) is None
    path.write_bytes(b"\x89PNG\r\n\x1a\n" + b"A" * 65536)
    assert files.read(reference) is None
    path.unlink()
    assert files.read(reference) is None


def test_icon_route_is_public_in_full_selfhost_stack(tmp_path, monkeypatch):
    with local_stack(tmp_path, monkeypatch, tools=False) as stack:
        files = stack.runtime.provider_store.icons
        reference = files.save(validate_icon(png()))
        response = stack.client.get(reference)
        assert response.status_code == 200
        assert response.content == files.read(reference)
        assert response.headers["cache-control"].endswith("immutable")
        assert (
            stack.client.get("/account/provider-icons/not-a-hash.png").status_code
            == 404
        )
        assert (
            stack.client.get("/account/provider-icons/" + "0" * 64 + ".png").status_code
            == 404
        )


def test_animation_and_truncated_pixel_stream_are_rejected():
    output = io.BytesIO()
    Image.new("RGBA", (2, 2), "red").save(
        output,
        format="PNG",
        save_all=True,
        append_images=[Image.new("RGBA", (2, 2), "blue")],
    )
    with pytest.raises(ProviderConfigurationError):
        validate_icon(PREFIX + base64.b64encode(output.getvalue()).decode())
    # Valid chunk CRCs and a bounded header do not prove that the pixel stream is complete.
    with pytest.raises(ProviderConfigurationError):
        validate_icon(png(32, 32))


def test_stale_and_csrf_requests_never_create_files_and_disk_failure_rolls_back(
    tmp_path, monkeypatch
):
    with installation(tmp_path) as (client, runtime, code):
        assert initialize(client, code).status_code == 200
        _, headers = login(client, "admin")
        body = {
            "revision": 0,
            "config": {},
            "enabled": True,
            "rank": 0,
            "icon_data": png(),
        }
        route = "/api/v1/admin/login-providers/local"
        assert client.put(route, headers=headers, json=body).status_code == 409
        body["revision"] = 1
        assert client.put(route, headers={"Origin": BASE}, json=body).status_code == 403
        assert not runtime.provider_store.icons.directory.exists()

        def fail_replace(*_args):
            raise OSError("private path must not leak")

        monkeypatch.setattr(
            "canvas_mcp.core.selfhost.login.provider_icon.os.replace", fail_replace
        )
        response = client.put(route, headers=headers, json=body)
        assert response.status_code == 503
        assert "private path" not in response.text
        assert runtime.provider_store.public_snapshot()[0] == 1
        assert runtime.provider_store.list_public()[0]["icon_data"] is None
        assert list(runtime.provider_store.icons.directory.iterdir()) == []
