"""One trusted issuer as the operator configures it, and the checks done when it is saved."""

from __future__ import annotations

import re
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..login.http import is_loopback_host

#: What a new issuer accepts unless the operator names others. Asymmetric algorithms only.
DEFAULT_ALGORITHMS = ("ES256", "RS256", "PS256", "EdDSA")
#: Every algorithm that may be configured. ``none`` and the HMAC family are never one of them:
#: a token signed with the issuer's public key used as a shared secret is the classic confusion.
ALLOWED_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)
DEFAULT_SUBJECT_CLAIM = "sub"
#: Prefix of the ``client_id`` of a federated grant (one per account and issuer).
GRANT_PREFIX = "federated:"
MAX_ISSUER = 512
MAX_NAME = 40

_PRINTABLE = re.compile(r"^[\x21-\x7e]+$")
_CLAIM_NAME = re.compile(r"^[\x21-\x7e]{1,64}$")
_SCOPE_NAME = re.compile(r"^[\x21-\x7e]{1,128}$")


class IssuerConfigError(ValueError):
    """The configuration is refused. The message is safe to show to the operator."""


@dataclass(frozen=True)
class TrustedIssuer:
    """One trusted issuer. ``audience`` and ``jwks_url`` of ``None`` mean "the default"."""

    issuer: str
    audience: str | None = None
    jwks_url: str | None = None
    algorithms: tuple[str, ...] = DEFAULT_ALGORITHMS
    require_typ_at_jwt: bool = True
    subject_claim: str = DEFAULT_SUBJECT_CLAIM
    read_scope: str | None = None
    write_scope: str | None = None
    name: str | None = None

    @property
    def label(self) -> str:
        """What the account page calls this issuer: its name, else its host."""
        if self.name:
            return self.name
        return (urlsplit(self.issuer).hostname or self.issuer)[:MAX_NAME]

    @property
    def is_loopback(self) -> bool:
        """Only an issuer that is itself on localhost may be reached on localhost."""
        return is_loopback_host(urlsplit(self.issuer).hostname or "")

    @property
    def grant_client_id(self) -> str:
        return GRANT_PREFIX + self.issuer


def _url(value: str, what: str) -> str:
    """An https URL, or an http one for localhost only; no user information, no fragment."""
    try:
        parts = urlsplit(value)
        host = parts.hostname
        parts.port  # noqa: B018 - raises ValueError for a malformed port
    except ValueError:
        raise IssuerConfigError(f"{what} is not a valid URL") from None
    if (
        not _PRINTABLE.fullmatch(value)
        or not host
        or "@" in parts.netloc
        or parts.fragment
    ):
        raise IssuerConfigError(f"{what} is not a valid URL")
    if parts.scheme == "https":
        return value
    if parts.scheme == "http" and is_loopback_host(host):
        return value
    raise IssuerConfigError(
        f"{what} must be https (http is allowed for localhost only)"
    )


def parse_algorithms(raw: str | None) -> tuple[str, ...]:
    if raw is None or not raw.strip():
        return DEFAULT_ALGORITHMS
    seen: list[str] = []
    for item in re.split(r"[,\s]+", raw.strip()):
        if not item:
            continue
        lowered = item.lower()
        if lowered == "none" or lowered.startswith("hs"):
            raise IssuerConfigError(
                "algorithms must be asymmetric: none and HS256/HS384/HS512 are refused"
            )
        if item not in ALLOWED_ALGORITHMS:
            raise IssuerConfigError(
                "unknown algorithm; use " + ", ".join(sorted(ALLOWED_ALGORITHMS))
            )
        if item not in seen:
            seen.append(item)
    if not seen:
        raise IssuerConfigError("algorithms is empty")
    return tuple(seen)


def build_issuer(
    issuer: str,
    *,
    audience: str | None = None,
    jwks_url: str | None = None,
    algorithms: str | None = None,
    require_typ_at_jwt: bool = True,
    subject_claim: str | None = None,
    read_scope: str | None = None,
    write_scope: str | None = None,
    name: str | None = None,
) -> TrustedIssuer:
    """Check every field and return the issuer, or raise :class:`IssuerConfigError`."""
    if not issuer or len(issuer) > MAX_ISSUER:
        raise IssuerConfigError("issuer is empty or too long")
    _url(issuer, "issuer")
    if urlsplit(issuer).query:
        raise IssuerConfigError("issuer must not have a query")
    if audience is not None:
        if (
            not audience
            or len(audience) > MAX_ISSUER
            or not _PRINTABLE.fullmatch(audience)
        ):
            raise IssuerConfigError("audience must be printable text without spaces")
    if jwks_url is not None:
        _url(jwks_url, "jwks_url")
        local_issuer = is_loopback_host(urlsplit(issuer).hostname or "")
        if is_loopback_host(urlsplit(jwks_url).hostname or "") and not local_issuer:
            raise IssuerConfigError(
                "jwks_url may be on localhost only for a localhost issuer"
            )
    claim = subject_claim or DEFAULT_SUBJECT_CLAIM
    if not _CLAIM_NAME.fullmatch(claim):
        raise IssuerConfigError("subject_claim is not a plain claim name")
    for label, scope in (("read", read_scope), ("write", write_scope)):
        if scope is not None and not _SCOPE_NAME.fullmatch(scope):
            raise IssuerConfigError(f"the {label} scope is not a plain scope name")
    if name is not None:
        name = name.strip()
        if not name or len(name) > MAX_NAME or not name.isprintable():
            raise IssuerConfigError(
                f"name must be 1 to {MAX_NAME} printable characters"
            )
    return TrustedIssuer(
        issuer=issuer,
        audience=audience,
        jwks_url=jwks_url,
        algorithms=parse_algorithms(algorithms),
        require_typ_at_jwt=require_typ_at_jwt,
        subject_claim=claim,
        read_scope=read_scope,
        write_scope=write_scope,
        name=name,
    )


def metadata_url(issuer: str) -> str:
    """The RFC 8414 metadata address: the well-known path goes between the host and the path."""
    parts = urlsplit(issuer)
    path = parts.path.rstrip("/")
    return (
        f"{parts.scheme}://{parts.netloc}/.well-known/oauth-authorization-server{path}"
    )
