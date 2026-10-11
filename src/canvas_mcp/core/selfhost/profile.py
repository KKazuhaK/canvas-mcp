"""Optional pilot constraints; ordinary selfhost deployments keep their defaults."""

from collections.abc import Mapping

from .schools import SchoolPolicy

PROFILE_ENV = "SELFHOST_PROFILE"
PILOT_DISABLED_TOOLS = frozenset(
    {"read_course_file", "read_course_file_text", "download_course_file"}
)


class PilotProfileViolation(ValueError):
    """A configuration would widen the pilot's scope."""


def read_profile(source: Mapping[str, str]) -> str:
    value = source.get(PROFILE_ENV, "").strip().lower()
    if value not in {"", "pilot"}:
        raise ValueError(f"{PROFILE_ENV} must be unset or pilot")
    return value


def validate_pilot_schools(policy: SchoolPolicy) -> None:
    if len(policy.featured) != 1 or policy.search_enabled:
        raise PilotProfileViolation(
            "SELFHOST_PROFILE=pilot requires exactly one featured school and "
            "schools.directory_search=false; configure them with token_admin"
        )
