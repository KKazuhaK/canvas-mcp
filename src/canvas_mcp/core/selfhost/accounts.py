"""Who may use the server, as pure functions: external identities, rules, decisions.

This module is the table-driven core of admission. It imports the standard
library only (a test pins that), so the upstream modes and the settings parser can
use it without the data layer. The store (``token_store.py``) runs these functions
inside its write transaction and applies the result; nothing here reads or writes
a database.

The model:

* An **external identity** is what a login provider says about a person, reduced to
  :class:`ExternalClaims`. Its key is ``(provider_id, issuer, subject)``. For Entra
  the issuer is ``https://login.microsoftonline.com/<tid>/v2.0`` and the subject is
  the ``oid`` claim: never ``sub`` (Entra makes that per application) and never the
  e-mail address or the user principal name (neither is verified).
* An **account** is the local person: ``acct:<uuid>``. Every stored row of the
  server is keyed by it, so another provider can later attach to the same account
  without touching a table.
* **Admission** is decided by one policy: ``ACCESS_POLICY`` (``open``, ``rules`` or
  ``approval``), ``ACCESS_RULES`` (who the rules admit), ``ACCESS_FALLBACK`` (what
  happens to someone no rule admits) and ``OWNER_RULES`` (who is an owner). With the
  defaults the rules are the Entra application roles of the first release, so
  nothing changes for an existing deployment.

Rule grammar (checked at startup; anything else refuses to start)::

    entra:role:<app role value>     the role is in the token's ``roles`` claim
    entra:group:<group object id>   the group is in the ``groups`` claim (an
                                    overage never matches; Graph is never called)
    entra:tenant:<tenant id>        the token's ``tid`` (must be the configured tenant)

Further providers (``SELFHOST_LOGIN_PROVIDERS``, ``SELFHOST_AUTH_MODE=local`` only) add::

    google:domain:<hd>              the id token's ``hd`` claim, with a verified e-mail
    google:email:<address>          a verified e-mail address (exact, lower case)
    github:user:<numeric id>        the immutable GitHub user id
    github:org:<org>                an active member of the organisation
    github:team:<org>/<team slug>   an active member of the team (child teams count)
    oidc:<slug>:claim:<name>=<value>  the claim is that string, or a list holding it
    oidc:<slug>:email:<address>     a verified e-mail address (exact, lower case)
    oidc:<slug>:any                 everybody who signs in through that provider

A rule of a provider that ``SELFHOST_LOGIN_PROVIDERS`` does not list refuses to start.
``OWNER_RULES`` stay Entra-only: Google, GitHub and generic OIDC can never make an owner
through what the identity provider says (the bootstrap owner and the operator CLI can).
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass
from typing import Any, Literal

PROVIDER_ENTRA = "entra"
PROVIDER_GOOGLE = "google"
PROVIDER_GITHUB = "github"
#: Generic OpenID Connect providers are ``oidc:<slug>``.
PROVIDER_OIDC_PREFIX = "oidc:"
ENTRA_ISSUER_PREFIX = "https://login.microsoftonline.com/"
GOOGLE_ISSUER = "https://accounts.google.com"
GITHUB_ISSUER = "https://github.com"

ACCOUNT_KEY_PREFIX = "acct:"

# -- closed vocabularies -------------------------------------------------------

STATUS_PENDING = "pending"
STATUS_ACTIVE = "active"
STATUS_DISABLED = "disabled"
ACCOUNT_STATUSES = (STATUS_PENDING, STATUS_ACTIVE, STATUS_DISABLED)

ROLE_USER = "user"
ROLE_OWNER = "owner"
ROLES = (ROLE_USER, ROLE_OWNER)

# Where a role came from. Only ``rules`` is re-evaluated by a sign-in.
ROLE_SOURCE_RULES = "rules"
ROLE_SOURCE_BOOTSTRAP = "bootstrap"
ROLE_SOURCE_OPERATOR = "operator"
ROLE_SOURCES = (ROLE_SOURCE_RULES, ROLE_SOURCE_BOOTSTRAP, ROLE_SOURCE_OPERATOR)

# How an account came to be admitted. ``approval``, ``operator`` and ``bootstrap``
# are personal decisions that a later change of the rules does not undo.
ADMITTED_RULES = "rules"
ADMITTED_OPEN = "open"
ADMITTED_APPROVAL = "approval"
ADMITTED_OPERATOR = "operator"
ADMITTED_BOOTSTRAP = "bootstrap"
ADMITTED_VIA = (
    ADMITTED_RULES,
    ADMITTED_OPEN,
    ADMITTED_APPROVAL,
    ADMITTED_OPERATOR,
    ADMITTED_BOOTSTRAP,
)
_PERSONAL_ADMISSION = frozenset({ADMITTED_APPROVAL, ADMITTED_OPERATOR, ADMITTED_BOOTSTRAP})

POLICY_OPEN = "open"
POLICY_RULES = "rules"
POLICY_APPROVAL = "approval"
POLICIES = (POLICY_OPEN, POLICY_RULES, POLICY_APPROVAL)
FALLBACK_DENY = "deny"
FALLBACK_APPROVAL = "approval"
FALLBACKS = (FALLBACK_DENY, FALLBACK_APPROVAL)

#: Pending accounts the server keeps before it answers ``signups_paused``.
DEFAULT_PENDING_LIMIT = 200
#: Pending accounts older than this are removed.
PENDING_RETENTION_SECONDS = 30 * 86400
#: Sign-in history is kept this long.
AUTH_EVENT_RETENTION_SECONDS = 90 * 86400

# Why a request or sign-in was refused (``Denied.code``): a closed set.
DENY_WRONG_TENANT = "wrong_tenant"
DENY_WRONG_CLIENT = "wrong_client"
DENY_BAD_SUBJECT = "bad_subject"
DENY_BAD_ROLES = "bad_roles"
DENY_ACCESS_DENIED = "access_denied"
DENY_ACCESS_DISABLED = "access_disabled"
DENY_PENDING_APPROVAL = "pending_approval"
DENY_SIGNUPS_PAUSED = "signups_paused"
DENY_UNAVAILABLE = "unavailable"

#: Reason codes of ``auth_events`` (a refusal's code, or what a success did).
REASON_OK = "ok"
REASON_ACCOUNT_CREATED = "account_created"
REASON_ACTIVATED = "activated"
REASON_GROUPS_OVERAGE = "groups_overage"
REASON_STATE_INVALID = "state_invalid"
REASON_TOKEN_INVALID = "token_invalid"
REASON_PROVIDER_ERROR = "provider_error"
REASON_STORE_UNAVAILABLE = "store_unavailable"
#: An identity was linked to an existing account from /account.
REASON_IDENTITY_LINKED = "identity_linked"
#: No rule matched and a GitHub organisation or team lookup was not possible (fail closed).
REASON_MEMBERSHIP_UNAVAILABLE = "membership_unavailable"
# Reasons of the ``oauth`` surface (the local authorization server).
REASON_CONSENT_GRANTED = "consent_granted"
REASON_CONSENT_DENIED = "consent_denied"
REASON_GRANT_CREATED = "grant_created"
REASON_CODE_REPLAY = "code_replay"
REASON_REFRESH_REUSE = "refresh_reuse"
REASON_REAUTH_REQUIRED = "reauth_required"
REASON_CLIENT_REVOKED = "client_revoked"
AUTH_REASONS = frozenset(
    {
        REASON_CONSENT_GRANTED,
        REASON_CONSENT_DENIED,
        REASON_GRANT_CREATED,
        REASON_CODE_REPLAY,
        REASON_REFRESH_REUSE,
        REASON_REAUTH_REQUIRED,
        REASON_CLIENT_REVOKED,
        REASON_OK,
        REASON_ACCOUNT_CREATED,
        REASON_ACTIVATED,
        REASON_GROUPS_OVERAGE,
        REASON_STATE_INVALID,
        REASON_TOKEN_INVALID,
        REASON_PROVIDER_ERROR,
        REASON_STORE_UNAVAILABLE,
        REASON_IDENTITY_LINKED,
        REASON_MEMBERSHIP_UNAVAILABLE,
        DENY_WRONG_TENANT,
        DENY_WRONG_CLIENT,
        DENY_BAD_SUBJECT,
        DENY_BAD_ROLES,
        DENY_ACCESS_DENIED,
        DENY_ACCESS_DISABLED,
        DENY_PENDING_APPROVAL,
        DENY_SIGNUPS_PAUSED,
    }
)

OUTCOME_SUCCESS = "success"
OUTCOME_PENDING = "pending"
OUTCOME_DENIED = "denied"
OUTCOME_ERROR = "error"
AUTH_OUTCOMES = (OUTCOME_SUCCESS, OUTCOME_PENDING, OUTCOME_DENIED, OUTCOME_ERROR)

SURFACE_ACCOUNT = "account"
SURFACE_MCP = "mcp"
#: The server's own authorization server (SELFHOST_AUTH_MODE=local): consent, grants,
#: replayed codes and refresh tokens. Kept out of the sign-in history a user sees.
SURFACE_OAUTH = "oauth"
#: The surfaces the sign-in history shows.
SIGN_IN_SURFACES = (SURFACE_ACCOUNT, SURFACE_MCP)

# History entries written by a decision (``principal_status_events.action``).
EVENT_ACCOUNT_CREATED = "account_created"
EVENT_ACTIVATED = "activated"
EVENT_OWNER_GAINED = "owner_gained"
EVENT_OWNER_LOST = "owner_lost"
EVENT_OWNER_LOSS_REFUSED = "owner_loss_refused_last_owner"

DENIAL_MESSAGES: dict[str, str] = {
    DENY_WRONG_TENANT: (
        "Your Microsoft account belongs to a different directory than this server accepts."
    ),
    DENY_WRONG_CLIENT: (
        "This sign-in was issued to a different application than this server accepts."
    ),
    DENY_BAD_SUBJECT: "Your sign-in does not carry a valid account identifier.",
    DENY_BAD_ROLES: "Your sign-in carries malformed role information. Sign in again.",
    DENY_ACCESS_DENIED: (
        "Your Microsoft account is not allowed to use this server. "
        "Ask the server owner to add you to the access group."
    ),
    DENY_ACCESS_DISABLED: (
        "Your access to this server was disabled by an administrator. "
        "Contact the server owner to have it restored."
    ),
    DENY_PENDING_APPROVAL: (
        "Your account is waiting for approval by the server owner. "
        "You will be able to use this server once it is approved."
    ),
    DENY_SIGNUPS_PAUSED: (
        "New sign-ups are paused on this server. Contact the server owner."
    ),
    DENY_UNAVAILABLE: "Your access could not be verified right now. Try again in a moment.",
}

#: The refusal for an account of any provider but Entra (whose message names Microsoft).
NEUTRAL_ACCESS_DENIED = (
    "This account is not allowed to use this server. Ask the server owner for access."
)

_GUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)
_ROLE_VALUE_RE = re.compile(r"^[A-Za-z0-9._-]{1,120}$")
_MAX_RULES = 100
_MAX_NAME = 200
_MAX_USERNAME = 254


@dataclass(frozen=True)
class Denied:
    """A refusal with a stable ``code`` (see ``DENY_*``) and a safe English ``message``."""

    code: str
    message: str


def denied(code: str) -> Denied:
    return Denied(code=code, message=DENIAL_MESSAGES[code])


# -- identities ----------------------------------------------------------------


def entra_issuer(tenant_id: str) -> str:
    """The issuer string stored for an Entra identity: ``https://login.microsoftonline.com/<tid>/v2.0``."""
    return f"{ENTRA_ISSUER_PREFIX}{tenant_id.lower()}/v2.0"


@dataclass(frozen=True)
class ExternalClaims:
    """What a login provider says about a person (already verified by the caller).

    ``subject`` is the provider's immutable identifier; ``email`` and the display
    fields are informational and never part of the identity key.
    """

    provider_id: str
    issuer: str
    subject: str
    email: str | None = None
    email_verified: bool = False
    display_name: str = ""
    username: str = ""
    roles: frozenset[str] = frozenset()
    groups: frozenset[str] = frozenset()
    groups_overage: bool = False
    tenant_id: str = ""
    #: Google: the ``hd`` claim of the id token (lower case); never the request hint.
    hd: str = ""
    #: GitHub: lower-case logins of the organisations (among those a rule names) the
    #: person is an active member of.
    orgs: frozenset[str] = frozenset()
    #: GitHub: ``org/team`` slugs (lower case) the person is an active member of.
    teams: frozenset[str] = frozenset()
    #: Generic OIDC: only the claims ``ACCESS_RULES`` reference, as (name, values) pairs.
    claims: tuple[tuple[str, tuple[str, ...]], ...] = ()
    #: GitHub: a membership lookup was refused or impossible (fail closed for org/team rules).
    membership_unavailable: bool = False

    @property
    def identity(self) -> tuple[str, str, str]:
        return (self.provider_id, self.issuer, self.subject)


@dataclass(frozen=True)
class EntraClaimsPolicy:
    """What the operator configured about the Entra application: the tenant and the client."""

    tenant_id: str
    client_id: str


def _same_guid(value: Any, expected: str) -> bool:
    return isinstance(value, str) and value.lower() == expected.lower()


def entra_external_claims(
    claims: Mapping[str, Any],
    policy: EntraClaimsPolicy,
    *,
    token_kind: Literal["access", "id"],
    parse_groups: bool = True,
) -> ExternalClaims | Denied:
    """Reduce VERIFIED Entra claims to an external identity, or say why not.

    The tenant (and for an access token the issuing client) must be the configured
    ones, the ``oid`` must be a GUID and ``roles`` (when present) a list of strings.
    ``groups`` is read only when ``parse_groups`` is true (the policy has a group
    rule): the first release ignored the claim, and a tenant may emit non-GUID values
    in it (on-premises names or SIDs), which must not lock anyone out. A malformed
    claim, or one entry that is not a GUID, simply matches no group rule, which keeps
    group admission closed. A groups overage (the token carries a reference instead of
    the list) yields no groups; nothing is ever fetched from Microsoft Graph.
    """
    if not _same_guid(claims.get("tid"), policy.tenant_id):
        return denied(DENY_WRONG_TENANT)
    if token_kind == "access" and not _same_guid(claims.get("azp"), policy.client_id):
        return denied(DENY_WRONG_CLIENT)
    oid = claims.get("oid")
    if not isinstance(oid, str) or not _GUID_RE.match(oid):
        return denied(DENY_BAD_SUBJECT)

    roles: frozenset[str] = frozenset()
    if "roles" in claims:
        raw_roles = claims["roles"]
        if not isinstance(raw_roles, list) or not all(isinstance(r, str) for r in raw_roles):
            return denied(DENY_BAD_ROLES)
        roles = frozenset(raw_roles)

    groups: frozenset[str] = frozenset()
    overage = _has_groups_overage(claims)
    if parse_groups and not overage:
        raw_groups = claims.get("groups")
        if isinstance(raw_groups, list):
            groups = frozenset(
                g.lower() for g in raw_groups if isinstance(g, str) and _GUID_RE.match(g)
            )

    tid = policy.tenant_id.lower()
    return ExternalClaims(
        provider_id=PROVIDER_ENTRA,
        issuer=entra_issuer(tid),
        subject=oid.lower(),
        display_name=str(claims.get("name") or "")[:_MAX_NAME],
        username=str(claims.get("preferred_username") or claims.get("upn") or "")[
            :_MAX_USERNAME
        ],
        roles=roles,
        groups=groups,
        groups_overage=overage,
        tenant_id=tid,
    )


def _has_groups_overage(claims: Mapping[str, Any]) -> bool:
    names = claims.get("_claim_names")
    if isinstance(names, Mapping) and "groups" in names:
        return True
    return bool(claims.get("hasgroups"))


# -- rules and policy ------------------------------------------------------------


@dataclass(frozen=True)
class AccessRule:
    """One entry of ``ACCESS_RULES`` / ``OWNER_RULES``: ``<provider>:<kind>:<value>``."""

    provider: str
    kind: str
    value: str

    def __str__(self) -> str:
        if not self.value:
            return f"{self.provider}:{self.kind}"
        return f"{self.provider}:{self.kind}:{self.value}"


@dataclass(frozen=True)
class BootstrapOwner:
    """The identity named by ``SELFHOST_BOOTSTRAP_OWNER``."""

    provider_id: str
    issuer: str
    subject: str


@dataclass(frozen=True)
class AccessPolicy:
    """The admission policy of the server (parsed once at startup)."""

    mode: str = POLICY_RULES
    rules: tuple[AccessRule, ...] = ()
    fallback: str = FALLBACK_DENY
    owner_rules: tuple[AccessRule, ...] = ()
    bootstrap_owner: BootstrapOwner | None = None
    ack_public: bool = False
    pending_limit: int = DEFAULT_PENDING_LIMIT
    #: ``SELFHOST_BOOTSTRAP_OWNER=token_admin``: the first owner is made with the operator
    #: CLI (``promote-owner``), so no identity is named in advance.
    bootstrap_via_token_admin: bool = False

    def has_group_rule(self) -> bool:
        return any(rule.kind == "group" for rule in self.rules)

    def github_orgs(self) -> tuple[str, ...]:
        """The organisations named by ``github:org`` rules (lower case, in rule order)."""
        return tuple(r.value for r in self.rules if r.provider == PROVIDER_GITHUB and r.kind == "org")

    def github_teams(self) -> tuple[str, ...]:
        """The ``org/team`` slugs named by ``github:team`` rules (lower case, in rule order)."""
        return tuple(r.value for r in self.rules if r.provider == PROVIDER_GITHUB and r.kind == "team")

    def google_domains(self) -> tuple[str, ...]:
        return tuple(r.value for r in self.rules if r.provider == PROVIDER_GOOGLE and r.kind == "domain")

    def oidc_claim_names(self, provider_id: str) -> frozenset[str]:
        """The claim names ``oidc:<slug>:claim:`` rules of one provider look at."""
        return frozenset(
            r.value.partition("=")[0]
            for r in self.rules
            if r.provider == provider_id and r.kind == "claim"
        )


def default_policy(required_role: str, owner_role: str) -> AccessPolicy:
    """The policy equal to the first release: the two Entra application roles."""
    return AccessPolicy(
        mode=POLICY_RULES,
        rules=(AccessRule(PROVIDER_ENTRA, "role", required_role),),
        fallback=FALLBACK_DENY,
        owner_rules=(AccessRule(PROVIDER_ENTRA, "role", owner_role),),
    )


_KNOWN_PROVIDERS = frozenset({PROVIDER_ENTRA, PROVIDER_GOOGLE, PROVIDER_GITHUB, "oidc"})
_ENTRA_KINDS = frozenset({"role", "group", "tenant"})
_GOOGLE_KINDS = frozenset({"domain", "email"})
_GITHUB_KINDS = frozenset({"user", "org", "team"})
_OIDC_KINDS = frozenset({"claim", "email", "any"})

#: ``oidc:<slug>`` slugs (see ``login.config``): lower-case letters, digits and hyphens.
OIDC_SLUG_RE = re.compile(r"^[a-z](?:[a-z0-9-]{0,30}[a-z0-9])?$")
_DNS_NAME_RE = re.compile(
    r"^(?=.{1,253}$)[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$"
)
_EMAIL_RULE_RE = re.compile(r"^[^@\s,:=]{1,64}@[a-z0-9.-]{1,189}$")
_GITHUB_ID_RE = re.compile(r"^[1-9][0-9]{0,19}$")
_GITHUB_ORG_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}$")
_GITHUB_TEAM_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,99}$")
_CLAIM_NAME_RE = re.compile(r"^[A-Za-z0-9_.:/-]{1,128}$")
#: At most this many ``github:org`` and ``github:team`` rules (one API call each per sign-in).
MAX_GITHUB_MEMBERSHIP_RULES = 10
_MAX_RULE_VALUE = 256
_MAX_EMAIL = 254

_OWNER_ONLY_ENTRA = (
    "owners come only from Entra app roles or groups, SELFHOST_BOOTSTRAP_OWNER or token_admin"
)


def _enabled_providers(providers: Collection[str] | None) -> frozenset[str]:
    """The provider ids a rule may name; ``None`` means the first release's Entra only."""
    return frozenset({PROVIDER_ENTRA}) if providers is None else frozenset(providers)


def _not_enabled(provider_id: str) -> str:
    return (
        f"names the provider '{provider_id}', which is not enabled in this release's "
        "configuration (add it to SELFHOST_LOGIN_PROVIDERS)"
    )


def parse_rule(
    text: str,
    *,
    tenant_id: str = "",
    owner: bool = False,
    providers: Collection[str] | None = None,
) -> AccessRule | str:
    """Parse one rule, or return a problem description (never echoing the value).

    ``providers`` are the provider ids ``SELFHOST_LOGIN_PROVIDERS`` lists (default: only
    Entra, the first release). A rule that names another provider is refused.
    """
    enabled = _enabled_providers(providers)
    entry = text.strip()
    provider, sep, rest = entry.partition(":")
    if not sep or not provider:
        return "is not '<provider>:<kind>:<value>'"
    if provider not in _KNOWN_PROVIDERS:
        return "has an unknown provider prefix"
    provider_id = provider
    if provider == "oidc":
        slug, sep, rest = rest.partition(":")
        if not sep or not OIDC_SLUG_RE.match(slug):
            return "needs oidc:<slug>:<kind>:<value> with a valid provider slug"
        provider_id = f"oidc:{slug}"
    if provider_id not in enabled:
        return _not_enabled(provider_id)
    if owner and provider_id != PROVIDER_ENTRA:
        return f"names {provider_id}: {_OWNER_ONLY_ENTRA}"
    kind, sep, value = rest.partition(":")
    if provider_id == PROVIDER_ENTRA:
        return _parse_entra_rule(kind, sep, value, tenant_id=tenant_id, owner=owner)
    if provider_id == PROVIDER_GOOGLE:
        return _parse_google_rule(kind, sep, value)
    if provider_id == PROVIDER_GITHUB:
        return _parse_github_rule(kind, sep, value)
    return _parse_oidc_rule(provider_id, kind, sep, value)


def _parse_entra_rule(
    kind: str, sep: str, value: str, *, tenant_id: str, owner: bool
) -> AccessRule | str:
    if not sep or kind not in _ENTRA_KINDS:
        return "has an unknown rule kind (use entra:role, entra:group or entra:tenant)"
    if kind == "role":
        if not _ROLE_VALUE_RE.match(value):
            return "has a role value outside [A-Za-z0-9._-] (1 to 120 characters)"
        return AccessRule(PROVIDER_ENTRA, "role", value)
    if not _GUID_RE.match(value):
        return f"needs a GUID after 'entra:{kind}:'"
    if kind == "tenant":
        if owner:
            return "may not use entra:tenant (a tenant is not an owner)"
        if tenant_id and value.lower() != tenant_id.lower():
            return "names a tenant other than ENTRA_TENANT_ID"
    return AccessRule(PROVIDER_ENTRA, kind, value.lower())


def _email_value(value: str) -> str | None:
    lowered = value.lower()
    if len(lowered) > _MAX_EMAIL or not _EMAIL_RULE_RE.match(lowered):
        return None
    return lowered


def _parse_google_rule(kind: str, sep: str, value: str) -> AccessRule | str:
    if not sep or kind not in _GOOGLE_KINDS:
        return "has an unknown rule kind (use google:domain or google:email)"
    if kind == "domain":
        lowered = value.lower()
        if not _DNS_NAME_RE.match(lowered):
            return "needs a domain name after 'google:domain:'"
        return AccessRule(PROVIDER_GOOGLE, "domain", lowered)
    address = _email_value(value)
    if address is None:
        return "needs an e-mail address after 'google:email:'"
    return AccessRule(PROVIDER_GOOGLE, "email", address)


def _parse_github_rule(kind: str, sep: str, value: str) -> AccessRule | str:
    if not sep or kind not in _GITHUB_KINDS:
        return "has an unknown rule kind (use github:user, github:org or github:team)"
    if kind == "user":
        if not _GITHUB_ID_RE.match(value):
            return "needs the numeric GitHub user id after 'github:user:' (not the login)"
        return AccessRule(PROVIDER_GITHUB, "user", value)
    if kind == "org":
        if not _GITHUB_ORG_RE.match(value):
            return "needs an organisation login after 'github:org:'"
        return AccessRule(PROVIDER_GITHUB, "org", value.lower())
    org, slash, team = value.partition("/")
    if not slash or not _GITHUB_ORG_RE.match(org) or not _GITHUB_TEAM_RE.match(team.lower()):
        return "needs <organisation>/<team slug> after 'github:team:'"
    return AccessRule(PROVIDER_GITHUB, "team", f"{org.lower()}/{team.lower()}")


def _printable_ascii(text: str) -> bool:
    return text.isascii() and all(0x20 <= ord(ch) <= 0x7E for ch in text)


def _parse_oidc_rule(provider_id: str, kind: str, sep: str, value: str) -> AccessRule | str:
    if kind == "any" and (not sep or not value):
        return AccessRule(provider_id, "any", "")
    if not sep or kind not in _OIDC_KINDS or kind == "any":
        return "has an unknown rule kind (use claim, email or any after the provider slug)"
    if kind == "email":
        address = _email_value(value)
        if address is None:
            return "needs an e-mail address after the 'email:' kind"
        return AccessRule(provider_id, "email", address)
    name, eq, expected = value.partition("=")
    if not eq or not _CLAIM_NAME_RE.match(name):
        return "needs claim:<name>=<value> with a plain claim name"
    if name.lower() in ("email", "email_verified"):
        return "may not match the 'email' claim as a claim (use the email: kind)"
    if (
        not expected
        or len(expected) > _MAX_RULE_VALUE
        or not _printable_ascii(expected)
        or expected != expected.strip()
    ):
        return "has a claim value that is empty, too long, not printable ASCII or padded with spaces"
    return AccessRule(provider_id, "claim", f"{name}={expected}")


def _parse_rules(
    name: str,
    raw: str,
    problems: list[str],
    *,
    tenant_id: str,
    owner: bool,
    providers: Collection[str] | None = None,
) -> tuple[AccessRule, ...]:
    rules: list[AccessRule] = []
    entries = [part for part in (p.strip() for p in raw.split(",")) if part]
    if len(entries) > _MAX_RULES:
        problems.append(f"{name} lists more than {_MAX_RULES} rules")
        return ()
    for index, entry in enumerate(entries, start=1):
        parsed = parse_rule(entry, tenant_id=tenant_id, owner=owner, providers=providers)
        if isinstance(parsed, str):
            problems.append(f"{name} entry {index} {parsed}")
            continue
        if parsed not in rules:
            rules.append(parsed)
    return tuple(rules)


_TRUE = frozenset({"true", "1", "yes"})
_FALSE = frozenset({"", "false", "0", "no"})


def _flag(name: str, raw: str, problems: list[str]) -> bool:
    word = raw.strip().lower()
    if word in _TRUE:
        return True
    if word not in _FALSE:
        problems.append(f"{name} must be true or false")
    return False


ACCESS_POLICY_ENV = "ACCESS_POLICY"
ACCESS_RULES_ENV = "ACCESS_RULES"
ACCESS_FALLBACK_ENV = "ACCESS_FALLBACK"
OWNER_RULES_ENV = "OWNER_RULES"
OPEN_ACK_ENV = "ACCESS_OPEN_ACKNOWLEDGE_PUBLIC"
BOOTSTRAP_OWNER_ENV = "SELFHOST_BOOTSTRAP_OWNER"
TRUSTED_PROXY_ENV = "TRUSTED_PROXY_CIDRS"
LINK_BY_EMAIL_ENV = "ACCOUNT_LINK_BY_VERIFIED_EMAIL"

#: ``SELFHOST_BOOTSTRAP_OWNER=token_admin``: no identity is named; the operator makes the first
#: owner with ``token_admin promote-owner`` after that person has signed in once.
BOOTSTRAP_TOKEN_ADMIN = "token_admin"

_BOOTSTRAP_RE = re.compile(
    r"^entra:([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})"
    r":([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12})$"
)
_BOOTSTRAP_GOOGLE_RE = re.compile(r"^google:([A-Za-z0-9_-]{1,255})$")
_BOOTSTRAP_GITHUB_RE = re.compile(r"^github:([1-9][0-9]{0,19})$")
_BOOTSTRAP_OIDC_RE = re.compile(r"^oidc:([a-z][a-z0-9-]{0,30}[a-z0-9]|[a-z]):([\x21-\x7e]{1,255})$")


def _parse_bootstrap(
    raw: str,
    *,
    tenant_id: str,
    enabled: frozenset[str],
    issuers: Mapping[str, str],
    problems: list[str],
) -> tuple[BootstrapOwner | None, bool]:
    """``(identity, via_token_admin)`` for ``SELFHOST_BOOTSTRAP_OWNER``; problems never echo the value."""
    if raw == BOOTSTRAP_TOKEN_ADMIN:
        return None, True
    only_entra = enabled <= {PROVIDER_ENTRA}
    shape = (
        f"{BOOTSTRAP_OWNER_ENV} must look like entra:<tenant id>:<object id> or {BOOTSTRAP_TOKEN_ADMIN}"
        if only_entra
        else f"{BOOTSTRAP_OWNER_ENV} must look like entra:<tenant id>:<object id>, "
        "google:<subject>, github:<numeric user id>, oidc:<slug>:<subject> or "
        f"{BOOTSTRAP_TOKEN_ADMIN}"
    )
    provider_id: str
    issuer: str
    subject: str
    if (match := _BOOTSTRAP_RE.match(raw)) is not None:
        provider_id = PROVIDER_ENTRA
        if provider_id in enabled and tenant_id and match.group(1).lower() != tenant_id.lower():
            problems.append(f"{BOOTSTRAP_OWNER_ENV} must name a user of ENTRA_TENANT_ID")
            return None, False
        issuer, subject = entra_issuer(match.group(1)), match.group(2).lower()
    elif (match := _BOOTSTRAP_GOOGLE_RE.match(raw)) is not None:
        provider_id, issuer, subject = PROVIDER_GOOGLE, GOOGLE_ISSUER, match.group(1)
    elif (match := _BOOTSTRAP_GITHUB_RE.match(raw)) is not None:
        provider_id, issuer, subject = PROVIDER_GITHUB, GITHUB_ISSUER, match.group(1)
    elif (match := _BOOTSTRAP_OIDC_RE.match(raw)) is not None and "," not in raw:
        provider_id = f"{PROVIDER_OIDC_PREFIX}{match.group(1)}"
        issuer, subject = issuers.get(provider_id, ""), match.group(2)
    else:
        problems.append(shape)
        return None, False
    if provider_id not in enabled:
        shown = provider_id if provider_id in _KNOWN_PROVIDERS or provider_id.startswith("oidc:") else "a provider"
        problems.append(
            f"{BOOTSTRAP_OWNER_ENV} names {shown}, which is not in SELFHOST_LOGIN_PROVIDERS"
        )
        return None, False
    return BootstrapOwner(provider_id, issuer, subject), False


def parse_access_settings(
    env: Mapping[str, str],
    *,
    tenant_id: str,
    required_role: str,
    owner_role: str,
    problems: list[str],
    providers: Collection[str] | None = None,
    issuers: Mapping[str, str] | None = None,
) -> AccessPolicy:
    """Parse the admission variables; every problem is appended to ``problems``.

    Unset variables give the first release's behaviour: ``rules`` with the required
    app role, fallback ``deny`` and the owner app role as the owner rule.

    ``providers`` are the provider ids ``SELFHOST_LOGIN_PROVIDERS`` lists (``None``: only
    Entra, as in the first release) and ``issuers`` maps ``oidc:<slug>`` to the configured
    issuer (the bootstrap owner needs it). Without Entra there is no default rule and no
    default owner rule: ``ACCESS_RULES`` is required with ``ACCESS_POLICY=rules``.
    """

    def get(name: str) -> str:
        return (env.get(name) or "").strip()

    enabled = _enabled_providers(providers)
    entra = PROVIDER_ENTRA in enabled
    public_provider = bool(enabled - {PROVIDER_ENTRA})

    mode_raw = get(ACCESS_POLICY_ENV).lower() or POLICY_RULES
    if mode_raw not in POLICIES:
        problems.append(f"{ACCESS_POLICY_ENV} must be 'open', 'rules' or 'approval'")
        mode_raw = POLICY_RULES

    rules_raw = env.get(ACCESS_RULES_ENV)
    rules_set = rules_raw is not None and rules_raw.strip() != ""
    fallback_raw = get(ACCESS_FALLBACK_ENV).lower()

    rules: tuple[AccessRule, ...] = ()
    fallback = FALLBACK_DENY
    if mode_raw == POLICY_RULES:
        if rules_set:
            rules = _parse_rules(
                ACCESS_RULES_ENV, rules_raw or "", problems,
                tenant_id=tenant_id, owner=False, providers=enabled,
            )
            if not rules and not any(p.startswith(ACCESS_RULES_ENV) for p in problems):
                problems.append(f"{ACCESS_RULES_ENV} is set but lists no rule")
            membership = sum(1 for r in rules if r.provider == PROVIDER_GITHUB and r.kind in ("org", "team"))
            if membership > MAX_GITHUB_MEMBERSHIP_RULES:
                problems.append(
                    f"{ACCESS_RULES_ENV} lists more than {MAX_GITHUB_MEMBERSHIP_RULES} "
                    "github:org and github:team rules"
                )
        elif entra:
            rules = (AccessRule(PROVIDER_ENTRA, "role", required_role),)
        else:
            problems.append(
                f"{ACCESS_RULES_ENV} is required with {ACCESS_POLICY_ENV}=rules when "
                "SELFHOST_LOGIN_PROVIDERS does not list entra"
            )
        if fallback_raw:
            if fallback_raw in FALLBACKS:
                fallback = fallback_raw
            else:
                problems.append(f"{ACCESS_FALLBACK_ENV} must be 'deny' or 'approval'")
    else:
        if rules_set:
            problems.append(
                f"{ACCESS_RULES_ENV} must not be set with {ACCESS_POLICY_ENV}={mode_raw} "
                "(it only applies to 'rules')"
            )
        if fallback_raw:
            problems.append(
                f"{ACCESS_FALLBACK_ENV} must not be set with {ACCESS_POLICY_ENV}={mode_raw} "
                "(it only applies to 'rules')"
            )

    owner_rules: tuple[AccessRule, ...]
    owner_raw = get(OWNER_RULES_ENV)
    if not owner_raw:
        owner_rules = (AccessRule(PROVIDER_ENTRA, "role", owner_role),) if entra else ()
    elif owner_raw.lower() == "none":
        owner_rules = ()
    else:
        owner_rules = _parse_rules(
            OWNER_RULES_ENV, owner_raw, problems,
            tenant_id=tenant_id, owner=True, providers=enabled,
        )
        if not owner_rules and not any(p.startswith(OWNER_RULES_ENV) for p in problems):
            problems.append(f"{OWNER_RULES_ENV} is set but lists no rule (use 'none' for none)")

    ack = _flag(OPEN_ACK_ENV, get(OPEN_ACK_ENV), problems)
    if mode_raw == POLICY_OPEN and public_provider and not ack:
        problems.append(
            f"{ACCESS_POLICY_ENV}=open with google, github or oidc sign-in admits anyone who has "
            f"such an account: set {OPEN_ACK_ENV}=true to confirm"
        )

    bootstrap: BootstrapOwner | None = None
    via_token_admin = False
    bootstrap_raw = get(BOOTSTRAP_OWNER_ENV)
    if bootstrap_raw:
        bootstrap, via_token_admin = _parse_bootstrap(
            bootstrap_raw,
            tenant_id=tenant_id,
            enabled=enabled,
            issuers=issuers or {},
            problems=problems,
        )

    if get(TRUSTED_PROXY_ENV):
        problems.append(
            f"{TRUSTED_PROXY_ENV} is reserved and not implemented yet; leave it unset "
            "(sign-in history records the client address as 'unknown')"
        )
    if get(LINK_BY_EMAIL_ENV):
        problems.append(
            f"{LINK_BY_EMAIL_ENV} is reserved and not implemented; leave it unset "
            "(accounts are linked only from /account)"
        )

    return AccessPolicy(
        mode=mode_raw,
        rules=rules,
        fallback=fallback,
        owner_rules=owner_rules,
        bootstrap_owner=bootstrap,
        ack_public=ack,
        bootstrap_via_token_admin=via_token_admin,
    )


# -- admission -----------------------------------------------------------------


@dataclass(frozen=True)
class Verdict:
    """What the rules say about one identity (before any stored state is consulted).

    ``owner_evidence`` says whether this sign-in could have shown an owner role at all:
    only Entra can (its app roles and groups are owner rules). A sign-in through another
    provider says nothing about an owner role, so it neither grants nor takes one away.
    """

    admitted_by_rule: bool
    owner_by_rule: bool
    reason: str = REASON_OK
    owner_evidence: bool = True


def _claim_values(ext: ExternalClaims, name: str) -> tuple[str, ...]:
    for claim, values in ext.claims:
        if claim == name:
            return values
    return ()


def rule_matches(rule: AccessRule, ext: ExternalClaims) -> bool:
    if rule.provider != ext.provider_id:
        return False
    kind = rule.kind
    if ext.provider_id == PROVIDER_ENTRA:
        if kind == "role":
            return rule.value in ext.roles
        if kind == "group":
            return (not ext.groups_overage) and rule.value in ext.groups
        if kind == "tenant":
            return bool(ext.tenant_id) and ext.tenant_id.lower() == rule.value
        return False
    if ext.provider_id == PROVIDER_GOOGLE:
        # ``hd`` is read from the id token only, and an address counts only when Google
        # says it is verified. The request's ``hd`` hint is never an input.
        if kind == "domain":
            return ext.email_verified and bool(ext.hd) and ext.hd.lower() == rule.value
        if kind == "email":
            return _verified_email_is(ext, rule.value)
        return False
    if ext.provider_id == PROVIDER_GITHUB:
        if kind == "user":
            return ext.subject == rule.value
        if kind == "org":
            return rule.value in ext.orgs
        if kind == "team":
            return rule.value in ext.teams
        return False
    # A generic OIDC provider (``oidc:<slug>``).
    if kind == "any":
        return True
    if kind == "email":
        return _verified_email_is(ext, rule.value)
    if kind == "claim":
        name, _, expected = rule.value.partition("=")
        return expected in _claim_values(ext, name)
    return False


def _verified_email_is(ext: ExternalClaims, expected: str) -> bool:
    return ext.email_verified and ext.email is not None and ext.email.lower() == expected


def evaluate_admission(ext: ExternalClaims, policy: AccessPolicy) -> Verdict:
    """Match the identity against ``ACCESS_RULES`` and ``OWNER_RULES`` (pure)."""
    owner = any(rule_matches(rule, ext) for rule in policy.owner_rules)
    admitted = any(rule_matches(rule, ext) for rule in policy.rules)
    reason = REASON_OK
    if not admitted and not owner:
        if ext.groups_overage and policy.has_group_rule():
            reason = REASON_GROUPS_OVERAGE
        elif (
            ext.provider_id == PROVIDER_GITHUB
            and ext.membership_unavailable
            and (policy.github_orgs() or policy.github_teams())
        ):
            reason = REASON_MEMBERSHIP_UNAVAILABLE
    return Verdict(
        admitted_by_rule=admitted,
        owner_by_rule=owner,
        reason=reason,
        owner_evidence=ext.provider_id == PROVIDER_ENTRA,
    )


def is_bootstrap_identity(ext: ExternalClaims, policy: AccessPolicy) -> bool:
    boot = policy.bootstrap_owner
    return boot is not None and ext.identity == (boot.provider_id, boot.issuer, boot.subject)


@dataclass(frozen=True)
class AccountFacts:
    """The stored fields a decision needs about an existing account."""

    status: str
    role: str = ROLE_USER
    role_source: str | None = None
    admitted_via: str = ADMITTED_RULES

    @property
    def is_active_owner(self) -> bool:
        return self.status == STATUS_ACTIVE and self.role == ROLE_OWNER


@dataclass(frozen=True)
class DecisionFacts:
    """Counts read in the same transaction as the decision."""

    #: Active owners, including the account being decided when it is one.
    active_owner_count: int = 0
    pending_count: int = 0
    is_bootstrap_identity: bool = False


Purpose = Literal["sign_in", "request"]
Outcome = Literal["allow", "pending", "deny"]


@dataclass(frozen=True)
class Decision:
    """What to do about one identity. The store applies it in one transaction.

    ``outcome``: ``allow`` (use the server), ``pending`` (signed in, waiting for
    approval: the account page only) or ``deny``. A decision can both deny and
    create (a pending account on the MCP path). ``reason`` is the closed code for
    the sign-in history.
    """

    outcome: Outcome
    reason: str
    denied: Denied | None = None
    create: bool = False
    create_status: str | None = None
    admitted_via: str | None = None
    activate: bool = False
    role: str | None = None
    role_source: str | None = None
    role_event: str | None = None
    session_owner: bool = False

    @property
    def writes(self) -> bool:
        return self.create or self.activate or self.role is not None or self.role_event is not None


def _deny(code: str, *, reason: str | None = None) -> Decision:
    return Decision(outcome="deny", reason=reason or code, denied=denied(code))


def _pending_or_denied(
    policy: AccessPolicy, facts: DecisionFacts, purpose: Purpose
) -> Decision:
    if facts.pending_count >= policy.pending_limit:
        return _deny(DENY_SIGNUPS_PAUSED)
    if purpose == "sign_in":
        return Decision(
            outcome="pending",
            reason=DENY_PENDING_APPROVAL,
            create=True,
            create_status=STATUS_PENDING,
            admitted_via=ADMITTED_RULES,
        )
    return Decision(
        outcome="deny",
        reason=DENY_PENDING_APPROVAL,
        denied=denied(DENY_PENDING_APPROVAL),
        create=True,
        create_status=STATUS_PENDING,
        admitted_via=ADMITTED_RULES,
    )


def decide(
    existing: AccountFacts | None,
    verdict: Verdict,
    policy: AccessPolicy,
    facts: DecisionFacts,
    purpose: Purpose,
) -> Decision:
    """The admission table: one identity, the stored state and the policy -> a decision.

    ======================  ========================================  ==========================
    existing account        policy / conditions                       outcome
    ======================  ========================================  ==========================
    none                    owner rule or bootstrap identity          create active (owner at a
                                                                      sign-in, user on MCP)
    none                    open                                      create active (``open``)
    none                    rules, a rule matches                     create active (``rules``)
    none                    rules, no match, fallback deny            deny, nothing written
    none                    rules no match + fallback approval, or    create pending (or
                            approval                                  ``signups_paused`` at cap)
    disabled                any                                       deny ``access_disabled``
    pending                 open, a rule matches, owner rule          activate
    pending                 otherwise                                 pending (MCP: deny)
    active                  open / approval / a rule matches / owner  allow
                            rule / personally admitted
    active                  rules, no match, admitted by rules/open   deny ``access_denied``
    ======================  ========================================  ==========================

    Roles are recomputed at a sign-in only: an owner rule raises ``user`` to
    ``owner``; losing the rule lowers a rules-sourced owner unless that is the last
    active owner; a bootstrap or operator owner is never changed by rules. The MCP
    path (``purpose='request'``) never raises a role.
    """
    owner_match = verdict.owner_by_rule
    bootstrap = facts.is_bootstrap_identity and facts.active_owner_count == 0
    sign_in = purpose == "sign_in"

    if existing is None:
        return _decide_new(verdict, policy, facts, purpose, owner_match, bootstrap)

    if existing.status == STATUS_DISABLED:
        return _deny(DENY_ACCESS_DISABLED)

    if existing.status == STATUS_PENDING:
        admit = (
            owner_match
            or bootstrap
            or policy.mode == POLICY_OPEN
            or (policy.mode == POLICY_RULES and verdict.admitted_by_rule)
        )
        if not admit:
            if sign_in:
                return Decision(outcome="pending", reason=DENY_PENDING_APPROVAL)
            return _deny(DENY_PENDING_APPROVAL)
        via = (
            ADMITTED_RULES
            if (owner_match or verdict.admitted_by_rule)
            else (ADMITTED_BOOTSTRAP if bootstrap else ADMITTED_OPEN)
        )
        role, source, event = _raise_role(sign_in, owner_match, bootstrap, ROLE_USER)
        return Decision(
            outcome="allow",
            reason=REASON_ACTIVATED,
            activate=True,
            admitted_via=via,
            role=role,
            role_source=source,
            role_event=event,
            session_owner=role == ROLE_OWNER,
        )

    # An active account.
    if not link_admissible(existing, verdict, policy):
        return _deny(
            DENY_ACCESS_DENIED,
            reason=verdict.reason
            if verdict.reason in (REASON_GROUPS_OVERAGE, REASON_MEMBERSHIP_UNAVAILABLE)
            else DENY_ACCESS_DENIED,
        )
    new_role: str | None = None
    new_source: str | None = None
    new_event: str | None = None
    if sign_in:
        new_role, new_source, new_event = _recompute_role(
            existing, owner_match, bootstrap, facts, verdict.owner_evidence
        )
    effective_role = new_role if new_role is not None else existing.role
    effective_source = new_source if new_role is not None else existing.role_source
    return Decision(
        outcome="allow",
        reason=REASON_OK,
        role=new_role,
        role_source=new_source,
        role_event=new_event,
        session_owner=(
            sign_in
            and effective_role == ROLE_OWNER
            and (effective_source != ROLE_SOURCE_RULES or owner_match)
        ),
    )


def _raise_role(
    sign_in: bool, owner_match: bool, bootstrap: bool, current: str
) -> tuple[str | None, str | None, str | None]:
    """Role for an account that is being created or activated (sign-in only)."""
    if not sign_in:
        return None, None, None
    if owner_match:
        return ROLE_OWNER, ROLE_SOURCE_RULES, EVENT_OWNER_GAINED
    if bootstrap:
        return ROLE_OWNER, ROLE_SOURCE_BOOTSTRAP, EVENT_OWNER_GAINED
    return None, None, None


def link_admissible(existing: AccountFacts, verdict: Verdict, policy: AccessPolicy) -> bool:
    """Whether an identity may use an account that already exists (pure).

    This is exactly the admission of an active account in :func:`decide`, so linking cannot
    attach an identity that the same rules would refuse at sign-in.
    """
    return (
        policy.mode in (POLICY_OPEN, POLICY_APPROVAL)
        or verdict.owner_by_rule
        or (policy.mode == POLICY_RULES and verdict.admitted_by_rule)
        or existing.admitted_via in _PERSONAL_ADMISSION
    )


def _recompute_role(
    existing: AccountFacts,
    owner_match: bool,
    bootstrap: bool,
    facts: DecisionFacts,
    owner_evidence: bool = True,
) -> tuple[str | None, str | None, str | None]:
    """``(new role, source, event)`` for an active account at a sign-in; role None = unchanged.

    A role that rules granted is taken back only on ``owner_evidence``: a sign-in through a
    provider whose data cannot show an owner role must not demote an Entra-granted owner.
    """
    if existing.role == ROLE_USER:
        if owner_match:
            return ROLE_OWNER, ROLE_SOURCE_RULES, EVENT_OWNER_GAINED
        if bootstrap:
            return ROLE_OWNER, ROLE_SOURCE_BOOTSTRAP, EVENT_OWNER_GAINED
        return None, None, None
    # An owner. Only a role that rules granted is taken back by rules.
    if existing.role_source == ROLE_SOURCE_RULES and not owner_match and owner_evidence:
        others = facts.active_owner_count - (1 if existing.is_active_owner else 0)
        if others <= 0:
            return None, None, EVENT_OWNER_LOSS_REFUSED
        return ROLE_USER, None, EVENT_OWNER_LOST
    return None, None, None


def _decide_new(
    verdict: Verdict,
    policy: AccessPolicy,
    facts: DecisionFacts,
    purpose: Purpose,
    owner_match: bool,
    bootstrap: bool,
) -> Decision:
    sign_in = purpose == "sign_in"
    if owner_match or bootstrap:
        role, source, event = _raise_role(sign_in, owner_match, bootstrap, ROLE_USER)
        return Decision(
            outcome="allow",
            reason=REASON_ACCOUNT_CREATED,
            create=True,
            create_status=STATUS_ACTIVE,
            admitted_via=ADMITTED_RULES if owner_match else ADMITTED_BOOTSTRAP,
            role=role,
            role_source=source,
            role_event=event,
            session_owner=role == ROLE_OWNER,
        )
    if policy.mode == POLICY_OPEN:
        return Decision(
            outcome="allow",
            reason=REASON_ACCOUNT_CREATED,
            create=True,
            create_status=STATUS_ACTIVE,
            admitted_via=ADMITTED_OPEN,
        )
    if policy.mode == POLICY_RULES:
        if verdict.admitted_by_rule:
            return Decision(
                outcome="allow",
                reason=REASON_ACCOUNT_CREATED,
                create=True,
                create_status=STATUS_ACTIVE,
                admitted_via=ADMITTED_RULES,
            )
        if policy.fallback == FALLBACK_DENY:
            return _deny(
                DENY_ACCESS_DENIED,
                reason=verdict.reason
                if verdict.reason in (REASON_GROUPS_OVERAGE, REASON_MEMBERSHIP_UNAVAILABLE)
                else DENY_ACCESS_DENIED,
            )
    return _pending_or_denied(policy, facts, purpose)


def valid_account_key(value: object) -> bool:
    """True for ``acct:`` followed by a lower-case canonical UUID."""
    return (
        isinstance(value, str)
        and value.startswith(ACCOUNT_KEY_PREFIX)
        and re.fullmatch(
            r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
            value[len(ACCOUNT_KEY_PREFIX) :],
        )
        is not None
    )


def account_id_of(key: str) -> str:
    """The bare UUID of an ``acct:<uuid>`` key. Raises ValueError for any other string."""
    if not valid_account_key(key):
        raise ValueError("not an account key")
    return key[len(ACCOUNT_KEY_PREFIX) :]


def account_key_of(account_id: str) -> str:
    return ACCOUNT_KEY_PREFIX + account_id


