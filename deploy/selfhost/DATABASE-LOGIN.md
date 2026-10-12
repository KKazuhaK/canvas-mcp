# Database-owned login configuration

## Required behavior

The owner's October 11 correction supersedes V1-DESIGN sections 2.5, 4.3.3
and 4.16 for login configuration. Provider credentials and enablement belong
in the database, managed through the web interface. `PUBLIC_BASE_URL` seeds
the database once; subsequent site-address edits belong in Admin > Settings.
Database connection and other infrastructure overrides remain in `.env`. Compose and `.env` are
the only deployment files; no host environment exports or setup script are
required. The already published beta.4 does not implement this correction.

Use the existing `login_providers.config`, `config_source='db'` and sealed
`secret_*` columns. Client secrets use the existing AES-GCM keyring and the
registered provider-specific AAD, so verification, rotation and transfer
continue covering them. GET responses, reprs, audit details and errors must
never include a client secret or ciphertext. The UI reports only whether a
secret is present; leaving its field unchanged preserves the saved value.

## Initial installation

An unconfigured installation starts healthy and serves `/account/setup`.
A private random installation code from the container logs authorizes creation
of a local administrator. Account UPN and password are required; Entra, Google,
GitHub or generic OIDC can optionally be configured on the same screen. The
owner can add, enable and disable providers later in Settings. Knowing the
public URL alone cannot initialize the service. Origin, content type, body size,
rate limits and a database revision CAS protect initialization; account,
credential, provider registration and audit changes commit together. A durable
installation marker prevents setup reopening on restart or provider disablement.

Local passwords are salted scrypt hashes (N=131072, r=8, p=1), never plaintext
or recoverable encryption. Local identities use opaque account UUID subjects,
with one unique case-insensitive UPN stored on `accounts`. Password credentials
contain the account FK, salted hash and timestamps, without another login name.
The original nineteen-table baseline and additive local-credential revision
stay frozen. `0003_account_login_policy` raises compatibility floor to 2 and
preserves existing names, account ids and ciphertext. The current schema has
23 business tables, including generic identity ownership, account login policy
and provider allowlists. Existing local names continue to work after upgrade.

There is no public local registration. A freshly signed-in owner can create
active regular accounts. Local login uses the same sealed cookie, account
standing, session epoch, consent and MCP authorization paths as external login.
Password changes require the current password and CSRF/Origin checks, and
atomically end existing sessions, unconsumed codes and connected app grants.
Provider disablement and the last usable owner rule also apply to local login.
Email changes never move a known external identity. Each provider instance can
independently enable automatic matching-email association, default off. Enabling
it trusts that provider's supplied matching claims, without a second mailbox
challenge; account allowlists and SSO locks take priority. Entra can match its
email or UPN. External accounts can add a local password after fresh sign-in;
the same UPN and account id are used. Admin unlock retains the original identity,
does not attach another one, and records an audit entry. See
[ACCOUNT-LOGIN-DESIGN.md](ACCOUNT-LOGIN-DESIGN.md) for the closed policy format.

Without explicit admission policy overrides, installations with local login and
no Entra use approval for new external users. Entra retains app-role admission
when enabled. Explicit operator policies continue to apply unchanged.

## Administration and runtime

The canonical origin is stored as `settings.site.public_base_url` (setting key
`site.public_base_url`). Startup reads it before constructing the OAuth issuer,
audience, callback URLs and Host/Origin guards. A missing initial value still
requires `.env`; a stored invalid value refuses startup rather than falling
back to the environment. Existing v1 origins are adopted once by the isolated
`db/migrations/site_environment.py` adapter. No new table or frozen schema change
is needed.

Site-address changes require a fresh owner session, explicit confirmation,
Origin/CSRF checks and global revision CAS. Saving another address atomically
ends browser sessions, unused codes, login/link ceremonies and MCP grants,
advances account and JWT epochs, and records the old/new address. The running
process refuses configuration-dependent requests until restart; it never mixes
old host guards with a new issuer. The same normalized address does not revoke
connections. After restarting, the operator must update proxy and external-login
callback registrations and clients must reconnect. The database value wins over
a stale or absent `PUBLIC_BASE_URL`; it cannot be reset back to an environment
fallback.

An active owner with a fresh session edits Entra, Google, GitHub and generic
OIDC in Admin > Settings. Writes use the existing governance transaction,
global revision CAS, CSRF and Origin protection. Enabling, disabling, secret
replacement and non-secret configuration edits commit with their audit row.
Disabling the last usable owner's sign-in method is refused atomically.
A provider id already associated with identities cannot silently be rebound
to a different issuer or client audience.

Provider runtime instances refresh by the committed database revision. A
failed refresh fails closed; it never falls back to stale credentials or
environment credentials. Enablement affects buttons, login, linking, cookie
acceptance and owner guards together. A configuration save invalidates
outstanding login/link ceremonies; callbacks cannot exchange a code using
another configuration. Existing browser/MCP sessions retain their normal
epochs unless their provider becomes unavailable, and unrelated credential
writes must not grant or remove access.

Existing beta installations may explicitly import their environment provider
configuration once. That compatibility path lives entirely in
`core/selfhost/db/migrations/`, uses the ordinary governed repository methods,
does not overwrite database-owned configuration, and never runs on every
restart. No upgrade, schema DDL or compatibility handling belongs in the
current-runtime provider repository. New installations do not require this
import path or any provider credential in `.env`.

## Evidence required before the next beta

- Actual two-file Compose boot with only a public origin; setup health and
  authenticated initialization, followed by container recreation.
- SQLite and PostgreSQL encrypted round trips, key rotation, wrong-key and
  tamper refusal, metadata/error/audit redaction, and secret preservation.
- Owner/session/CSRF/Origin refusal, stale CAS, last-owner protection and
  concurrent save/disable/sign-in races using real governed transactions.
- Actual provider code exchange with controlled HTTP transport, hot edits,
  disabled endpoints and invalidated in-flight ceremonies.
- React setup and administration forms, English/Chinese locale coverage,
  validation, retained-secret indication and conflict/error handling.
- Compatibility import remains isolated and cannot replace DB-owned values.
- Full CI and native amd64/arm64 Docker checks at the released source; stable
  `:latest` remains unchanged. Real staging/IdP/B2B/client/refresh acceptance
  stays pending until observed after deployment.
