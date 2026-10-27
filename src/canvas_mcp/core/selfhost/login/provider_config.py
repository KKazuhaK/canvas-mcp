"""Validated database provider values; secrets never participate in reprs."""

from __future__ import annotations

import re
import uuid
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any

from ..accounts import OIDC_SLUG_RE
from .config import env_prefix, parse_login_providers


class ProviderConfigurationError(ValueError):
    """A closed configuration error, without caller or database values."""

    def __init__(self, code: str = "invalid_provider_configuration") -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True)
class ProviderConfiguration:
    id: str
    protocol: str
    config: Mapping[str, Any]
    client_secret: str | None = field(repr=False)

    @property
    def issuer(self) -> str:
        if self.id == "hub":
            return str(self.config["origin"])
        if self.id == "local":
            return "urn:canvas-mcp:local"
        if self.id == "entra":
            return f"https://login.microsoftonline.com/{self.config['tenant_id']}/v2.0"
        if self.id == "google":
            return "https://accounts.google.com"
        if self.id == "github":
            return "https://github.com"
        return str(self.config["issuer"])


def validate_provider(
    identifier: str, config: object, client_secret: object
) -> ProviderConfiguration:
    """Validate closed public fields separately from a write-only secret."""
    if identifier == "hub":
        from urllib.parse import urlsplit

        from .config import HubConfig, _issuer_problem

        if (
            not isinstance(config, Mapping)
            or set(config) != {"origin"}
            or not isinstance(config["origin"], str)
            or _issuer_problem(config["origin"])
            or urlsplit(config["origin"]).path not in ("", "/")
            or client_secret is not None
        ):
            raise ProviderConfigurationError()
        hub = HubConfig(config["origin"].rstrip("/"))
        return ProviderConfiguration(
            "hub", "hub", MappingProxyType({"origin": hub.origin}), None
        )
    if identifier == "local":
        if config != {} or client_secret is not None:
            raise ProviderConfigurationError()
        return ProviderConfiguration("local", "local", MappingProxyType({}), None)
    if not isinstance(identifier, str) or (
        identifier not in {"entra", "google", "github"}
        and not (
            identifier.startswith("oidc:")
            and OIDC_SLUG_RE.fullmatch(identifier.removeprefix("oidc:"))
        )
    ):
        raise ProviderConfigurationError()
    if not isinstance(config, Mapping):
        raise ProviderConfigurationError()
    if client_secret is not None and (
        not isinstance(client_secret, str)
        or not 16 <= len(client_secret.strip()) <= 4096
        or any(ord(char) < 32 or ord(char) == 127 for char in client_secret)
    ):
        raise ProviderConfigurationError()
    secret = client_secret.strip() if isinstance(client_secret, str) else None
    common = {"client_id"}
    allowed = (
        common | {"tenant_id", "required_role", "owner_role"}
        if identifier == "entra"
        else (
            common | {"issuer", "scopes", "token_auth_method", "userinfo"}
            if identifier.startswith("oidc:")
            else common
        )
    )
    if set(config) - allowed:
        raise ProviderConfigurationError()
    values = dict(config)
    if any(
        not isinstance(value, str)
        for key, value in values.items()
        if key not in {"scopes", "userinfo"}
    ):
        raise ProviderConfigurationError()
    values = {
        key: value.strip() if isinstance(value, str) else value
        for key, value in values.items()
    }
    if identifier == "entra":
        try:
            for name in ("tenant_id", "client_id"):
                raw = values[name]
                if not re.fullmatch(r"[0-9a-fA-F-]{36}", raw):
                    raise ValueError
                values[name] = str(uuid.UUID(raw))
        except (KeyError, ValueError, TypeError):
            raise ProviderConfigurationError() from None
        for name, default in (
            ("required_role", "Canvas.User"),
            ("owner_role", "Canvas.Owner"),
        ):
            values.setdefault(name, default)
            if not re.fullmatch(r"[A-Za-z0-9._-]{1,120}", values[name]):
                raise ProviderConfigurationError()
        if values["required_role"] == values["owner_role"]:
            raise ProviderConfigurationError()
    else:
        prefix = (
            env_prefix(identifier[5:])
            if identifier.startswith("oidc:")
            else identifier.upper() + "_"
        )
        # Reuse the standard-library protocol validators with a private input
        # mapping, never os.environ. Missing secrets are handled by the repository.
        validation = {
            "SELFHOST_LOGIN_PROVIDERS": identifier,
            prefix + "CLIENT_SECRET": secret or "validation-placeholder-secret",
        }
        for key, value in values.items():
            if key == "scopes":
                if not isinstance(value, (list, tuple)) or not all(
                    isinstance(v, str) for v in value
                ):
                    raise ProviderConfigurationError()
                value = " ".join(value)
            elif key == "userinfo":
                if type(value) is not bool:
                    raise ProviderConfigurationError()
                value = "true" if value else "false"
            validation[prefix + key.upper()] = value
        problems: list[str] = []
        parsed = parse_login_providers(validation, problems)
        if problems:
            raise ProviderConfigurationError()
        if identifier.startswith("oidc:"):
            oidc = parsed.oidc[0]
            values = {
                "issuer": oidc.issuer,
                "client_id": oidc.client_id,
                "scopes": oidc.scopes,
                "userinfo": oidc.userinfo,
            }
            if oidc.token_auth_method is not None:
                values["token_auth_method"] = oidc.token_auth_method
    return ProviderConfiguration(
        identifier,
        "oidc" if identifier.startswith("oidc:") else identifier,
        MappingProxyType(values),
        secret,
    )
