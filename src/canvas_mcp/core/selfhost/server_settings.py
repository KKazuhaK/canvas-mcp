"""Typed, database-owned server settings and public display-name validation.

Missing database rows use the code defaults. The canonical site address is
adopted once from the first-install environment by isolated upgrade tooling;
subsequent site edits require the dedicated credential-revoking save path.
"""

from __future__ import annotations

import json
import unicodedata
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType

MAX_SETTING_BYTES = 8192


@dataclass(frozen=True)
class SettingSpec:
    value_type: type[bool] | type[int] | type[str]
    default: bool | int | str
    minimum: int | None = None
    maximum: int | None = None
    sensitive: bool = False
    editable_in_panel: bool = False

    def validate(self, value: object) -> bool | int | str:
        # bool is an int subclass, but a retention value cannot be a checkbox.
        if type(value) is not self.value_type:
            raise ValueError("setting has the wrong type")
        if isinstance(value, str):
            from .site_url import validate_site_url

            return validate_site_url(value)
        if not isinstance(value, (bool, int)):
            raise ValueError("setting has the wrong type")
        if self.minimum is not None and value < self.minimum:
            raise ValueError("setting is below its minimum")
        if self.maximum is not None and value > self.maximum:
            raise ValueError("setting exceeds its maximum")
        if len(json.dumps(value, allow_nan=False).encode("utf-8")) > MAX_SETTING_BYTES:
            raise ValueError("setting is too large")
        return value


SETTINGS: Mapping[str, SettingSpec] = MappingProxyType(
    {
        "site.public_base_url": SettingSpec(str, "", editable_in_panel=True),
        "schools.directory_search": SettingSpec(bool, True, editable_in_panel=True),
        "retention.auth_events_days": SettingSpec(int, 90, minimum=7, maximum=3650),
        "retention.audit_days": SettingSpec(int, 0, minimum=0, maximum=3650),
    }
)


def validate_setting(
    key: str, value: object, *, panel: bool = False
) -> bool | int | str:
    spec = SETTINGS.get(key)
    if spec is None:
        raise ValueError("unknown setting")
    if panel and not spec.editable_in_panel:
        raise ValueError("setting is operator-only")
    return spec.validate(value)


def provider_display_name(value: object) -> str | None:
    """Return a normalized public name, or None for a reset.

    Reject hidden and control characters before collapsing whitespace, so a
    newline or bidi override cannot disappear into an apparently safe name.
    """
    if value is None or value == "":
        return None
    if not isinstance(value, str):
        raise ValueError("display name must be a string")
    value = unicodedata.normalize("NFC", value)
    refused = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}
    if any(unicodedata.category(char) in refused for char in value):
        raise ValueError("display name contains a forbidden character")
    value = " ".join(value.split())
    if not 1 <= len(value) <= 40 or len(value.encode("utf-8")) > 160:
        raise ValueError("display name has an invalid length")
    if any(char in value for char in "<>{}") or not any(
        char.isalnum() for char in value
    ):
        raise ValueError("display name contains invalid text")
    return value


def validate_provider_names(
    defaults: Mapping[str, str],
    current: Mapping[str, str | None],
    changes: Mapping[str, object],
) -> dict[str, str | None]:
    """Validate a partial save and uniqueness of all configured effective names."""
    if any(identifier not in defaults for identifier in changes):
        raise ValueError("provider is not configured")
    result = {identifier: current.get(identifier) for identifier in defaults}
    result.update({key: provider_display_name(value) for key, value in changes.items()})
    names = [(result[key] or default).casefold() for key, default in defaults.items()]
    if len(set(names)) != len(names):
        raise ValueError("effective display names must be unique")
    return result
