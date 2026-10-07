"""Shared helpers for the self-hosted mode tests."""

from collections.abc import Iterator

import pytest

from canvas_mcp.core.credentials import (
    RequestPrincipal,
    clear_http_request_context,
    set_request_principal,
)

TENANT = "11111111-2222-3333-4444-555555555555"
CLIENT = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OID_A = "aaaaaaaa-0000-4000-8000-00000000000a"
OID_B = "bbbbbbbb-0000-4000-8000-00000000000b"


def make_principal(oid: str, *, tenant: str = TENANT) -> RequestPrincipal:
    return RequestPrincipal(
        key=f"entra:{tenant}:{oid}".lower(),
        tenant_id=tenant,
        object_id=oid.lower(),
        display_name="",
        upn="",
        roles=frozenset({"Canvas.User"}),
        is_owner=False,
    )


@pytest.fixture(autouse=True)
def clean_request_context() -> Iterator[None]:
    """No test may leave request identity behind for the next one."""
    clear_http_request_context()
    yield
    clear_http_request_context()


@pytest.fixture
def as_principal() -> Iterator[object]:
    """Call ``as_principal(oid)`` to act as that principal for the rest of the test."""

    def activate(oid: str) -> RequestPrincipal:
        principal = make_principal(oid)
        set_request_principal(principal)
        return principal

    yield activate
