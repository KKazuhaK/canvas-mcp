"""Isolated schema upgrades, frozen revisions and database transfer tooling."""


def dependencies_available() -> bool:
    """Keep the optional upgrade dependency probe removable with this package."""
    try:
        import alembic  # noqa: F401
        import sqlalchemy  # noqa: F401
    except ImportError:
        return False
    return True
