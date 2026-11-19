# Database-managed configuration

The v1 account panel has **Admin > Settings** for login registrations, public sign-in names,
featured schools and school directory search. An active owner must have signed
in within the last ten minutes. Saves require the session CSRF header, a
same-origin JSON request and the configuration revision shown when editing.
If another process saves first, reload the settings before saving again.

This is a configuration checkpoint on the v1 development branch. The complete
runtime and Docker acceptance gates are tracked in [V1-PROGRESS.md](V1-PROGRESS.md).

## Defaults and ownership

- A new database has no featured school. Directory search is enabled.
- The optional `SELFHOST_PROFILE=pilot` requires exactly one featured school
  and directory search disabled before startup. Enable the profile after initial
  configuration; panel and CLI changes cannot widen it while active.
- There is no implicit default school. A picker starts without a choice unless
  the account already has an offered school. One featured school with search
  disabled is selected automatically.
- Public names default to Microsoft, Google, GitHub, or the OIDC provider slug.
  Resetting a name uses that default; it does not remove the provider.
- Provider credentials, enablement, button order and provider app-role names are
  database-owned. Client secrets are encrypted and write-only: a blank field
  keeps the saved value. Configuration takes effect on the next request.
- Entra has one more option, **Always show the Microsoft account picker**
  (`always_select_account`, on by default, which sends `prompt=select_account`).
  Turn it off in Admin > Settings > Entra to send no `prompt` on a normal sign-in:
  Microsoft then signs in without a click when exactly one account is signed in
  at Microsoft, and shows its own picker otherwise. Turning it off also makes
  re-authentication (step-up) and sign-in-method linking send `prompt=login`,
  which forces Microsoft to ask again; with it on they send `select_account`. Google and generic OIDC have
  no such option. The value is part of the Entra registration, so
  `token_admin login-providers --configure` accepts `"always_select_account": false`
  in its `config` object too.
- Fresh installations use `/account/setup` with the private expiring operator
  code. Disabling providers does not reopen setup. Old environment adoption is
  explicit and isolated in the migration package; saved DB values always win.
- Owner mutations read current provider enablement inside the governed write,
  so a stale request or shell environment cannot bypass last-owner protection.
- `CANVAS_API_URL`, `CANVAS_FEATURED_SCHOOLS`, `CANVAS_SCHOOL_SEARCH` and
  `OIDC_<SLUG>_DISPLAY_NAME` are refused in self-host mode. They do not seed the
  database. Upstream authentication modes retain their own configuration.

School checks require a plain DNS hostname and public address answers unless
the operator explicitly granted a private-address exception. The public
Instructure directory is advisory for an administrator's featured-school check.
It still supplies the signed search results users choose during enrollment.
Directory searches send the search terms to `canvas.instructure.com`.

When directory search is disabled, removing a featured school may stop existing
bindings. The panel shows the affected counts and requires confirmation.
Encrypted credentials remain stored; offering that school again restores access
on the next request. Private-address exceptions are read-only in the panel and
can only be changed at the operator CLI.

## Headless commands

Run these in the server's environment, with its database and keyring settings:

```sh
python -m canvas_mcp.core.selfhost.token_admin providers list
python -m canvas_mcp.core.selfhost.token_admin providers rename entra "Campus sign-in"
python -m canvas_mcp.core.selfhost.token_admin providers reset-name entra
python -m canvas_mcp.core.selfhost.token_admin login-providers
python -m canvas_mcp.core.selfhost.token_admin login-providers --check

python -m canvas_mcp.core.selfhost.token_admin schools list
python -m canvas_mcp.core.selfhost.token_admin schools add SCHOOL_HOST --name "Your school"
python -m canvas_mcp.core.selfhost.token_admin schools move SCHOOL_HOST 1
python -m canvas_mcp.core.selfhost.token_admin schools rename SCHOOL_HOST "New school name"
python -m canvas_mcp.core.selfhost.token_admin schools remove SCHOOL_HOST
# After reviewing the affected bindings:
python -m canvas_mcp.core.selfhost.token_admin schools remove SCHOOL_HOST --confirm-affected

python -m canvas_mcp.core.selfhost.token_admin settings get
python -m canvas_mcp.core.selfhost.token_admin settings set schools.directory_search false
python -m canvas_mcp.core.selfhost.token_admin settings set retention.auth_events_days 180
python -m canvas_mcp.core.selfhost.token_admin settings reset retention.auth_events_days
```

The first-install code can be renewed with `token_admin setup-code` only while
unconfigured. Operator recovery uses `token_admin login-providers --configure
PROVIDER`, reading a closed JSON object from stdin with `revision`, `config`,
`enabled`, `rank` and optional `client_secret`; no secret belongs in an argument.
Read the revision without loading provider configuration using
`token_admin login-providers --revision`. Explicit legacy adoption uses
`token_admin login-providers --import-env`, which never replaces DB-owned values.

Settings values are JSON booleans or integers with exact types. Authentication
event retention accepts 7–3650 days; audit retention accepts 0–3650 days, where
zero means keep forever. See [MAINTENANCE.md](MAINTENANCE.md) for scheduled
retention jobs and bounded cleanup; a policy save does not synchronously prune
existing history.

## Browser sync

Schools that do not let students create access tokens can use the browser
extension instead (design and contract: [BROWSER-SYNC-DESIGN.md](BROWSER-SYNC-DESIGN.md)).
Nothing needs enabling: the account page offers it, and a request uses synced
browser data only when the account has no usable token for the school the data
came from. Three operator-only settings (JSON integers) tune it:

| Setting | Default | Range | Meaning |
| --- | --- | --- | --- |
| `browser_sync.fresh_hours` | 24 | 1–720 | Older synced data is still used, but the tool result says it may be out of date |
| `browser_sync.max_age_days` | 14 | 1–90 | Synced data older than this is not used at all |
| `browser_sync.purge_days` | 30 | 1–365 | Maintenance deletes snapshots (and revoked bindings) older than this |

```sh
python -m canvas_mcp.core.selfhost.token_admin settings set browser_sync.max_age_days 7
```

Per-binding limits are fixed (not settings): 200 courses, 3000 snapshot rows and 64 MiB of sealed data. Keep `purge_days` at least `max_age_days`. Snapshots are sealed with the same
keys as stored tokens, so key rotation covers them and a database backup is
useless without the matching keys. The extension's endpoints are CORS-enabled
for extension origins only; the reverse proxy must pass the `Origin` and
`Authorization` headers and must not add cookies. The Portal rate-limits by the
address it sees, so put the real limiter in the proxy as for the other public
endpoints.

An internal school can be explicitly added with `schools add SCHOOL_HOST
--allow-private`. Use `schools allow-private SCHOOL_HOST on|off` to change its
exception later. Remove a featured internal host before withdrawing its
exception. A rejected command never echoes its supplied value.

Configuration commands use governance transactions and the same audit actions
as the panel, with an `operator` actor. They do not require IdP credentials:
provider names use the provider set last recorded by a server. On a fresh
database, start the server once to record that set before renaming providers.

## Trusted issuers

A trusted issuer is an external OAuth server, such as a hub that signs people in,
whose access tokens this server accepts on `/mcp` on the person's behalf. The
person does not sign in to Canvas MCP or approve anything again. The feature is
off until you add an issuer: with none configured, `/mcp` accepts exactly the
tokens this server issued itself, as before.

Trusted issuers are listed after this server in `authorization_servers` of the
protected-resource metadata (`/.well-known/oauth-protected-resource/mcp`), exactly as
configured, because a hub looks for itself there before it issues a token for this
resource. With none configured the document lists only this server, as before.

**Choosing the checks.** A token whose issuer is this server goes to this
server's own decoder, as always. Any other token goes to the trusted issuers,
and only if at least one is configured. Everything below is checked in this
order, and the first failure refuses the token with a plain 401:
the size (8 KiB at most); the header (the algorithm must be on the issuer's
list, the type must be `at+jwt` unless you relax it, and a header that points
at keys, `jku`, `jwk` or `x5u`, is refused); the signature; the issuer; the
audience; the times; the subject.

**Algorithms and keys.** Only asymmetric algorithms can be configured
(default `ES256`, `RS256`, `PS256` and `EdDSA`). `none` and `HS256`/`HS384`/`HS512`
are refused when you add the issuer and again on every token, because a token
signed with the issuer's public key used as a shared secret is the classic
forgery. The signing keys come from the issuer's key set, found through its
RFC 8414 metadata at `/.well-known/oauth-authorization-server`, whose `issuer`
must equal the configured one character for character, or from `--jwks-url`.
Keys are cached for an hour. A token naming a key the cache does not know makes
the server fetch the key set again, at most once a minute per issuer, so
invented key ids cannot make it hammer the issuer. Addresses must be https. The key set found through the metadata must be on the
issuer's own address (use `--jwks-url` for anything else). Plain http and `localhost`
are allowed only when the issuer itself is on `localhost`, for development.

**Claims.** `iss` must equal the issuer string exactly (a trailing slash
counts). `aud` must contain the audience, by default this server's own
`/mcp` URL (`--audience` changes it). `exp` is required and the token must not
be expired. `nbf` and `iat`, when present, may be at most 60 seconds in the future.

**Who the person is.** The person is the pair (issuer, subject). The subject
is the claim named by `--subject-claim` (default `sub`); it must be present and a
non-empty string. There is no fallback to another claim: if the configured claim
is missing, the token is refused. A hub that gives each person a stable id of
its own should name that claim, because `sub` may be per-client or per-session there.
The claim must be immutable and not editable by the person: MCPHub's stable id claim
is, `preferred_username` and `email` are not. Identities of an issuer live in a
namespace of their own, keyed by issuer, claim and subject, so they can only reach an
account through a first token or `link-federated`, never by matching a sign-in identity.

**Accounts.** A subject you have not seen before gets an account under the same
admission policy as a first sign-in (`ACCESS_POLICY` is `open`, `rules` or
`approval`, with `ACCESS_RULES` and `ACCESS_FALLBACK`). `open` creates an active account. `approval` creates a pending
one, and so does `rules` with `ACCESS_FALLBACK=approval` when no rule matches.
`rules` admits the issuer's people only if a rule says so: add `federated:any` to
`ACCESS_RULES` (for example `ACCESS_RULES=entra:role:Canvas.User,federated:any`);
without it the people of a trusted issuer are refused unless you link them. The admission policy is checked again on every request: a person
made by a first token who the policy no longer admits is refused, while a person you
linked stays admitted. A pending
or disabled account is refused on `/mcp` with a message that says so, and nothing
about the person is matched by e-mail address or name: an existing account is only
ever attached by an operator, with `link-federated`. An account made this way has no
sign-in method of its own, so a person who needs to open the account page (to bind
a Canvas token, for instance) should be linked to the account they sign in with.

**The connection.** The first token of an account through an issuer creates one
connection (a "federated grant") so that last-use tracking, the write-tool
switches and the Canvas token binding work as for any app. The person sees it under
Connected apps as "via NAME — manage there" and cannot end it from there; the
issuer is where it is managed. Disabling the account stops it at once (the account's standing is checked on every
request, so the connection itself is left alone), and enabling it again restores it.
The connection lasts as long as an upstream sign-in may (`max_upstream_auth_age`) and
is renewed by use. Ending it with `revoke-grant` (or an owner doing so) is final: to
restore it, unlink the person and link them again.

**Scopes only narrow.** `--read-scope` names a scope the token must carry (`scope`
or `scp`); without it the token is refused. `--write-scope` names the scope write
tools need; a token without it can only use read tools, whatever the person switched
on at the account page. Neither can add anything: write tools still need the
person's own switch and the operator's `ALLOWED_WRITE_TOOLS`.

**Only on `/mcp`.** These tokens are never a web session and are refused on `/api`,
the account pages and the browser-extension endpoints, which all keep their own
credentials.

**No Canvas token yet.** A person who has not bound a Canvas token gets, from every
tool, the usual "no Canvas access token is enrolled" message with the address of the
account page where it is bound.

Commands, run in the server's environment like the others:

```sh
python -m canvas_mcp.core.selfhost.token_admin trusted-issuers add ISSUER \
  [--name NAME] [--audience AUD] [--jwks-url URL] [--algorithms ES256,RS256] \
  [--allow-typ-jwt] [--subject-claim CLAIM] [--read-scope S] [--write-scope S]
python -m canvas_mcp.core.selfhost.token_admin trusted-issuers list
python -m canvas_mcp.core.selfhost.token_admin trusted-issuers links [--account UUID]
python -m canvas_mcp.core.selfhost.token_admin trusted-issuers remove ISSUER
python -m canvas_mcp.core.selfhost.token_admin link-federated --account UUID --issuer ISSUER --subject SUBJECT
python -m canvas_mcp.core.selfhost.token_admin unlink-federated --issuer ISSUER --subject SUBJECT
```

A running server notices a change within about ten seconds. `remove` deletes the
issuer's connections but keeps the links, so adding the issuer back restores people
on their own accounts. `unlink-federated` deletes that person's connection; a sign-in
method is never removed by it (use `unlink-identity` for those).

### Recipe: MCPHub

In MCPHub, let it sign the person in for this server. The names below follow MCPHub's
own configuration; check them against its documentation.

1. Set this server's public address (`PUBLIC_BASE_URL`), so that the `/mcp` address is
   fixed, for example `https://canvas.example.edu/mcp`.
2. In MCPHub add an `oauthServer.externalResources` entry whose `resource` is exactly
   that `/mcp` address, with `allowedClients` including MCPHub's personal OAuth
   client, and the scopes you want to grant.
3. Add the server in MCPHub as `streamable-http`, with `oauth.identityMode: personal`
   and `url` equal to that same resource.
4. Trust MCPHub here. MCPHub is adding a stable per-person id claim (`mcphub_uid`);
   use it as the subject, because `sub` is not a stable person id there:

   ```sh
   python -m canvas_mcp.core.selfhost.token_admin trusted-issuers add https://mcphub.example.edu \
     --name MCPHub --subject-claim mcphub_uid
   ```

   If MCPHub's tokens carry scopes you want to honour, add `--read-scope` and
   `--write-scope`. Until MCPHub issues `mcphub_uid`, do not add the issuer: tokens
   without the configured claim are refused.
5. Pick how people get accounts (see Accounts above), or link existing ones with
   `link-federated`.

### Recipe: Microsoft Entra or Keycloak

These issue ID-style `typ: JWT` access tokens, so relax the type check, and name the
key set, because they publish OpenID Connect rather than RFC 8414 metadata:

```sh
# Entra (v2.0 tokens): issuer https://login.microsoftonline.com/<tenant id>/v2.0
python -m canvas_mcp.core.selfhost.token_admin trusted-issuers add \
  https://login.microsoftonline.com/TENANT_ID/v2.0 --name Entra --allow-typ-jwt \
  --audience API_APP_ID_OR_URI --jwks-url https://login.microsoftonline.com/TENANT_ID/discovery/v2.0/keys \
  --subject-claim oid

# Keycloak: issuer https://keycloak.example.edu/realms/REALM
python -m canvas_mcp.core.selfhost.token_admin trusted-issuers add \
  https://keycloak.example.edu/realms/REALM --name Keycloak --allow-typ-jwt \
  --audience canvas-mcp --jwks-url https://keycloak.example.edu/realms/REALM/protocol/openid-connect/certs
```

Register this server's `/mcp` as the resource (Entra: the API's application ID URI;
Keycloak: an audience mapper) so that `aud` carries the audience you set. Only access
tokens work: an ID token has the wrong audience and is refused.

## Runtime and migration boundaries

Each authenticated MCP or browser request reads the committed configuration
revision together with its authorization snapshot. A warm configuration adds
no SQL read. A changed revision rebuilds an immutable bundle from three reads;
mixed revisions retry, and invalid configuration fails closed without serving
an older bundle. Public provider and known login routes read the current
revision explicitly. Unknown login routes create no state and perform no read.

Runtime configuration writes live in `selfhost/config_store.py` and
`selfhost/config_cli.py`. Every schema upgrade, backup, database transfer and
Alembic revision lives separately in `selfhost/db/migrations/`; normal
configuration changes do not depend on upgrade compatibility code.
