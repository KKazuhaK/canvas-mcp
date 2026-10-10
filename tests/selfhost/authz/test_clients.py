"""Registered clients: metadata validation, the public-client rewrite, redirect matching."""

from __future__ import annotations

import pytest
from mcp.shared.auth import InvalidRedirectUriError, OAuthClientInformationFull
from pydantic import AnyUrl

from canvas_mcp.core.selfhost import oauth
from canvas_mcp.core.selfhost.authz.clients import (
    DCR_TTL_SECONDS,
    PublicClient,
    clean_label,
    make_public,
    validate_dcr_metadata,
)
from canvas_mcp.core.selfhost.settings import DEFAULT_REDIRECT_URIS

ALLOW = DEFAULT_REDIRECT_URIS
SCOPES = ["Canvas.Access"]


def info(redirect_uris: list[str] | None = None, **kw) -> OAuthClientInformationFull:
    base = {
        "client_id": "c1", "redirect_uris": redirect_uris or ["https://claude.ai/api/mcp/auth_callback"],
        "scope": "Canvas.Access",
    }
    base.update(kw)
    return OAuthClientInformationFull.model_validate(base)


def error_of(client: OAuthClientInformationFull) -> str | None:
    problem = validate_dcr_metadata(client, ALLOW, SCOPES)
    return None if problem is None else problem.error


def test_a_registration_lives_as_long_as_the_proxy_kept_one() -> None:
    assert DCR_TTL_SECONDS == oauth.DCR_CLIENT_TTL_SECONDS == 30 * 86400


class TestValidation:
    def test_the_usual_registrations_pass(self) -> None:
        assert error_of(info()) is None
        assert error_of(info(["http://localhost:53682/callback", "http://127.0.0.1:1/callback"])) is None
        assert error_of(info(grant_types=["authorization_code"])) is None
        assert error_of(info(application_type="web")) is None
        assert error_of(info(response_types=["code"], client_name="Claude")) is None

    @pytest.mark.parametrize(
        "uris",
        [
            ["javascript:alert(1)"],
            ["data:text/html,x"],
            ["file:///etc/passwd"],
            ["vbscript:x"],
            ["myapp://callback"],
            ["http://evil.example/callback"],
            ["https://evil.example/callback"],
            ["https://claude.ai/api/mcp/auth_callback#f"],
            ["https://claude.ai/*"],
            ["https://claude.ai/api/mcp/auth_callback?x=1"],
            ["https://user@claude.ai/api/mcp/auth_callback"],
            ["https://localhost/callback"],
            ["http://localhost/other"],
            ["http://localhost@evil.example/callback"],
            ["https://claude.ai/api/mcp/auth_callback", "https://evil.example/cb"],
        ],
    )
    def test_bad_redirect_uris(self, uris: list[str]) -> None:
        assert error_of(info(uris)) == "invalid_redirect_uri"

    def test_the_number_and_length_of_redirect_uris(self) -> None:
        many = [f"http://localhost:{5000 + i}/callback" for i in range(10)]
        assert error_of(info(many)) is None
        assert error_of(info(many + ["http://localhost:6000/callback"])) == "invalid_redirect_uri"
        assert error_of(info(["https://claude.ai/api/mcp/" + "a" * 2100])) == "invalid_redirect_uri"

    def test_application_type_rules(self) -> None:
        assert error_of(info(["http://localhost/callback"], application_type="web")) == "invalid_redirect_uri"
        assert error_of(info(["http://localhost/callback"], application_type="native")) is None
        assert error_of(info(application_type="desktop")) == "invalid_client_metadata"

    @pytest.mark.parametrize(
        "kw",
        [
            {"grant_types": ["implicit"]},
            {"grant_types": ["refresh_token"]},
            {"grant_types": ["authorization_code", "password"]},
            {"grant_types": ["authorization_code", "urn:ietf:params:oauth:grant-type:jwt-bearer"]},
            {"response_types": ["token"]},
            {"response_types": ["code", "token"]},
            {"scope": "Canvas.Access admin"},
            {"client_name": "n" * 201},
        ],
    )
    def test_bad_metadata(self, kw) -> None:
        assert error_of(info(**kw)) == "invalid_client_metadata"

    def test_messages_never_echo_the_input(self) -> None:
        problem = validate_dcr_metadata(info(["https://evil-marker.example/cb"]), ALLOW, SCOPES)
        assert problem is not None and "evil-marker" not in (problem.error_description or "")


class TestMakePublic:
    def test_it_removes_every_secret_and_unused_field_in_place(self) -> None:
        record = info(
            client_secret="s3cret", client_secret_expires_at=0, token_endpoint_auth_method="client_secret_post",
            jwks_uri="https://evil.example/jwks", contacts=["a@b.c"], software_id="x", logo_uri="https://e.example/l.png",
            client_uri="https://e.example", scope=None,
        )
        make_public(record, "Canvas.Access")
        assert record.token_endpoint_auth_method == "none" and record.client_secret is None
        assert record.client_secret_expires_at is None and record.scope == "Canvas.Access"
        for name in ("jwks_uri", "contacts", "software_id", "logo_uri", "client_uri", "jwks"):
            assert getattr(record, name) is None
        dumped = record.model_dump_json(exclude_none=True)
        assert "s3cret" not in dumped and "evil.example" not in dumped


def public(uris: list[str], allow=ALLOW, kind: str = "dcr") -> PublicClient:
    return PublicClient.build(
        {"client_id": "c1", "redirect_uris": uris, "scope": "Canvas.Access", "token_endpoint_auth_method": "none"},
        kind=kind, allowlist=tuple(allow),
    )


class TestPublicClient:
    def test_the_registered_and_the_allowed_uri_must_both_match(self) -> None:
        client = public(["https://claude.ai/api/mcp/auth_callback"])
        assert str(client.validate_redirect_uri(AnyUrl("https://claude.ai/api/mcp/auth_callback"))) == (
            "https://claude.ai/api/mcp/auth_callback"
        )
        with pytest.raises(InvalidRedirectUriError):
            client.validate_redirect_uri(AnyUrl("https://claude.com/api/mcp/auth_callback"))  # allowed, not registered
        narrowed = public(["https://claude.ai/api/mcp/auth_callback"], allow=["https://claude.com/api/mcp/auth_callback"])
        with pytest.raises(InvalidRedirectUriError):
            narrowed.validate_redirect_uri(AnyUrl("https://claude.ai/api/mcp/auth_callback"))  # registered, not allowed

    def test_loopback_ports_are_free_only_for_a_port_less_registration(self) -> None:
        portless = public(["http://localhost/callback"])
        assert portless.validate_redirect_uri(AnyUrl("http://localhost:7777/callback"))
        fixed = public(["http://localhost:5000/callback"])
        assert fixed.validate_redirect_uri(AnyUrl("http://localhost:5000/callback"))
        with pytest.raises(InvalidRedirectUriError):
            fixed.validate_redirect_uri(AnyUrl("http://localhost:5001/callback"))
        with pytest.raises(InvalidRedirectUriError):
            portless.validate_redirect_uri(AnyUrl("http://127.0.0.1:7777/callback"))

    def test_a_missing_redirect_uri_means_the_single_https_one_only(self) -> None:
        single = public(["https://claude.ai/api/mcp/auth_callback"])
        assert str(single.validate_redirect_uri(None)) == "https://claude.ai/api/mcp/auth_callback"
        for uris in (["http://localhost/callback"], ["https://claude.ai/api/mcp/auth_callback", "https://claude.com/api/mcp/auth_callback"]):
            with pytest.raises(InvalidRedirectUriError):
                public(uris).validate_redirect_uri(None)
        with pytest.raises(InvalidRedirectUriError):
            public(["https://claude.ai/api/mcp/auth_callback"], allow=["https://other.example/cb"]).validate_redirect_uri(None)

    def test_scope_validation_is_the_clients_scope(self) -> None:
        from mcp.shared.auth import InvalidScopeError

        client = public(["https://claude.ai/api/mcp/auth_callback"])
        assert client.validate_scope("Canvas.Access") == ["Canvas.Access"] and client.validate_scope(None) is None
        with pytest.raises(InvalidScopeError):
            client.validate_scope("admin")

    def test_display_names(self) -> None:
        dcr = PublicClient.build(
            {"client_id": "c1", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"], "client_name": "  My‮ app\n"},
            kind="dcr", allowlist=ALLOW,
        )
        assert dcr.display_name == "My app" and dcr.client_host is None
        cimd = PublicClient.build(
            {"client_id": "https://claude.ai/x", "redirect_uris": ["https://claude.ai/api/mcp/auth_callback"], "client_name": "Evil"},
            kind="cimd", allowlist=ALLOW, client_host="claude.ai",
        )
        assert cimd.display_name == "claude.ai" and cimd.kind == "cimd"


class TestCleanLabel:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            (None, ""),
            ("", ""),
            ("  hello   world ", "hello world"),
            ("a\nb\tc", "a b c"),
            ("evil‮gnp.exe", "evil gnp.exe"),
            ("zero​width", "zero width"),
            ("x" * 300, "x" * 100),
            ("<b>bold</b>", "<b>bold</b>"),
        ],
    )
    def test_table(self, raw, expected) -> None:
        assert clean_label(raw) == expected

    def test_the_limit_is_adjustable(self) -> None:
        assert clean_label("abcdef", 3) == "abc"
