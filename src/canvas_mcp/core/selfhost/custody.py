"""Versioned acknowledgement required before a Canvas credential is enrolled."""

from dataclasses import dataclass

CUSTODY_NOTICE_VERSION = 1


def custody_ack_required_message(account_url: str) -> str:
    return (
        "Please read and acknowledge the updated Canvas token custody notice at "
        + account_url.rstrip("/")
        + "/token before using Canvas tools. "
        "Your saved token remains stored."
    )


@dataclass(frozen=True)
class CustodyAcknowledgement:
    notice_version: int
    acked_at: int

    def validate(self, *, now: int) -> None:
        if (
            type(self.notice_version) is not int
            or self.notice_version != CUSTODY_NOTICE_VERSION
        ):
            raise ValueError("custody notice version is not current")
        if type(self.acked_at) is not int or not 0 < self.acked_at <= now:
            raise ValueError("custody acknowledgement time is invalid")
