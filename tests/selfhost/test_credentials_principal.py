"""Tests for the request principal, the principal key and the missing-token message."""

from canvas_mcp.core.credentials import (
    RequestCredentials,
    clear_http_request_context,
    current_principal_key,
    get_request_credentials,
    get_request_principal,
    is_http_request_active,
    missing_credentials_message,
    set_http_request_active,
    set_missing_credentials_message,
    set_request_credentials,
    set_request_principal,
)

from .conftest import OID_A, OID_B, make_principal

LEGACY_TEXT = "Canvas token required for HTTP request"


def _use_token(token: str) -> None:
    set_request_credentials(RequestCredentials(api_token=token, api_url="https://canvas.example.test/api/v1"))


class TestTokenSecrecy:
    def test_the_token_is_not_in_repr_or_str(self):
        creds = RequestCredentials(api_token="secret-xyz", api_url="https://x")
        assert "secret-xyz" not in repr(creds)
        assert "secret-xyz" not in str(creds)
        assert "api_url='https://x'" in repr(creds)
        assert creds.api_token == "secret-xyz"  # still usable

    def test_the_token_is_not_in_a_formatted_exception_or_log_argument(self):
        creds = RequestCredentials(api_token="secret-xyz", api_url="https://x")
        assert "secret-xyz" not in f"{creds!r} {creds}"
        assert "secret-xyz" not in str(ValueError(creds))


class TestPrincipalKey:
    def test_stdio_is_local(self):
        assert current_principal_key() == "local"

    def test_entra_principal_key(self):
        principal = make_principal(OID_A)
        set_request_principal(principal)
        assert current_principal_key() == principal.key
        assert current_principal_key().startswith("entra:")

    def test_principal_wins_over_a_token(self):
        principal = make_principal(OID_A)
        set_request_principal(principal)
        _use_token("some-canvas-token-1234567890")
        key = current_principal_key()
        assert key.startswith(principal.key)
        assert not key.startswith("token:")

    def test_the_key_names_the_school_and_never_the_token(self):
        principal = make_principal(OID_A)
        set_request_principal(principal)
        _use_token("some-canvas-token-1234567890")
        assert current_principal_key() == principal.key + "|https://canvas.example.test/api/v1"
        assert "some-canvas-token" not in current_principal_key()

    def test_the_same_principal_at_two_schools_has_two_keys(self):
        set_request_principal(make_principal(OID_A))
        set_request_credentials(RequestCredentials(api_token="t" * 30, api_url="https://canvas.a.edu/api/v1"))
        key_a = current_principal_key()
        set_request_credentials(RequestCredentials(api_token="t" * 30, api_url="https://canvas.b.edu/api/v1"))
        assert current_principal_key() != key_a

    def test_the_url_is_normalised(self):
        set_request_principal(make_principal(OID_A))
        set_request_credentials(RequestCredentials(api_token="t" * 30, api_url="https://Canvas.A.edu/api/v1/"))
        upper = current_principal_key()
        set_request_credentials(RequestCredentials(api_token="t" * 30, api_url="https://canvas.a.edu/api/v1"))
        assert current_principal_key() == upper

    def test_without_credentials_the_key_is_the_bare_principal_key(self):
        principal = make_principal(OID_A)
        set_request_principal(principal)
        assert current_principal_key() == principal.key

    def test_legacy_token_key_is_stable_distinct_and_opaque(self):
        token_a = "legacy-canvas-token-A-1234567890"
        token_b = "legacy-canvas-token-B-1234567890"
        _use_token(token_a)
        key_a = current_principal_key()
        assert key_a == current_principal_key()
        assert key_a.startswith("token:")
        assert len(key_a) == len("token:") + 32
        assert token_a not in key_a
        _use_token(token_b)
        key_b = current_principal_key()
        assert key_b != key_a
        assert token_b not in key_b

    def test_two_principals_have_different_keys(self):
        set_request_principal(make_principal(OID_A))
        key_a = current_principal_key()
        set_request_principal(make_principal(OID_B))
        assert current_principal_key() != key_a


class TestMissingCredentialsMessage:
    def test_default_is_the_legacy_text(self):
        assert missing_credentials_message() == LEGACY_TEXT

    def test_can_be_set_and_reset_with_its_token(self):
        token = set_missing_credentials_message("Enroll at https://x.test/account")
        assert missing_credentials_message() == "Enroll at https://x.test/account"
        from canvas_mcp.core import credentials

        credentials._missing_credentials_message.reset(token)
        assert missing_credentials_message() == LEGACY_TEXT

    def test_none_restores_the_default(self):
        set_missing_credentials_message("custom")
        set_missing_credentials_message(None)
        assert missing_credentials_message() == LEGACY_TEXT


class TestClear:
    def test_clear_resets_every_variable(self):
        set_http_request_active(True)
        _use_token("some-canvas-token-1234567890")
        set_request_principal(make_principal(OID_A))
        set_missing_credentials_message("custom")

        clear_http_request_context()

        assert is_http_request_active() is False
        assert get_request_credentials() is None
        assert get_request_principal() is None
        assert missing_credentials_message() == LEGACY_TEXT
        assert current_principal_key() == "local"


class TestClientUsesTheMessage:
    async def test_client_fails_closed_with_the_selfhost_text(self):
        from canvas_mcp.core.client import make_canvas_request

        set_http_request_active(True)
        set_missing_credentials_message("Enroll at https://x.test/account")
        assert await make_canvas_request("get", "/users/self") == {
            "error": "Enroll at https://x.test/account"
        }

    async def test_client_keeps_the_legacy_text_by_default(self):
        from canvas_mcp.core.client import make_canvas_request

        set_http_request_active(True)
        assert await make_canvas_request("get", "/users/self") == {"error": LEGACY_TEXT}

    async def test_authenticated_client_raises_the_message(self):
        import pytest

        from canvas_mcp.core.client import canvas_authenticated_client

        set_http_request_active(True)
        set_missing_credentials_message("Enroll at https://x.test/account")
        with pytest.raises(PermissionError, match="Enroll at https://x.test/account"):
            async with canvas_authenticated_client():
                pass
