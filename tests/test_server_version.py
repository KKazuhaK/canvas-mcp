"""Clients must receive the application's version, not its framework version."""

from typing import Literal

import pytest
from fastmcp import Client

from canvas_mcp import __version__
from canvas_mcp.server import create_server


@pytest.mark.asyncio
@pytest.mark.parametrize("mode", ["auto", "legacy"])
async def test_negotiation_reports_canvas_application_version(
    mode: Literal["auto", "legacy"],
) -> None:
    async with Client(create_server(), mode=mode) as client:
        assert client.server_info is not None
        assert client.server_info.version == __version__
