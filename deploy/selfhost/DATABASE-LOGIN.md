# Database-owned login configuration

## Required behavior

The owner's October 11 correction supersedes V1-DESIGN sections 2.5, 4.3.3
and 4.16 for login configuration. Provider credentials and enablement belong
in the database, managed through the web interface. `PUBLIC_BASE_URL` and
optional infrastructure overrides remain in `.env`. Compose and `.env` are
the only deployment files; no host environment exports or setup script are
required. The already published beta.4 does not implement this correction.

Use the existing `login_providers.config`, `config_source='db'` and sealed
`secret_*` columns. Client secrets use the existing AES-GCM keyring and the
registered provider-specific AAD, so verification, rotation and transfer
continue covering them. GET responses, reprs, audit details and errors must
never include a client secret or ciphertext. The UI reports only whether a
secret is present; leaving its field unchanged preserves the saved value.

## Initial installation

An unconfigured installation starts healthy and serves a protected setup
screen at `/account/setup`. It offers the default Entra registration fields
and the exact callback URL. A private random setup code, available to the
server operator, authorizes the first save. Origin, content type, body size
and rate-limit checks apply. Knowing the public URL alone cannot initialize
the service. A durable installation marker prevents restart or disabling
providers from reopening setup.

The setup save stores Entra configuration and a sealed secret atomically.
Normal Entra app-role admission follows: `Canvas.Owner` for the owner and
`Canvas.User` for guests. Setup possession does not grant an arbitrary
visitor owner status. Owner recovery remains an explicit operator action.

## Administration and runtime

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
