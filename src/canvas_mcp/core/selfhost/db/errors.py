"""Errors of the data layer. Standard library only; messages carry no secrets."""

from __future__ import annotations


class TokenStoreError(Exception):
    """Base class for token store failures. Messages carry no secrets."""


class StoreUnavailable(TokenStoreError):
    """The database could not be reached, locked in time, or refused a statement.

    The message is fixed: it never contains SQL, bound values, file paths or the
    connection URL, all of which a driver error can quote. ``kind`` names the
    exception class of the underlying driver error, for the operator's log.
    """

    def __init__(self, message: str = "the token database is unavailable", kind: str = "") -> None:
        super().__init__(f"{message} ({kind})" if kind else message)
        self.kind = kind
