# Canvas MCP v1 self-host deployment

This is an independent fork of [vishalsachdev/canvas-mcp](https://github.com/vishalsachdev/canvas-mcp),
not endorsed by upstream. The project keeps the name `canvas-mcp`; only small
core improvements are offered upstream. The fork's hosting stack stays here.

This fork provides a multi-user Canvas MCP service with a built-in OAuth
authorization server, explicit per-user Canvas credentials and a mandatory React
account panel. All account, grant and protocol state lives in one SQL database.
Run one process and one replica. This is the v1 development deployment guide;
[V1-PROGRESS.md](V1-PROGRESS.md) records unfinished validation and release gates.

Use a fresh v1 database. Pre-v1 files are refused. Upgrade, backup and transfer
instructions are kept separately in [the migration package](../../src/canvas_mcp/core/selfhost/db/migrations/README.md).

## Prepare an external sign-in provider

This step is optional. First installation creates a local administrator;
additional local accounts can be created in Admin > Accounts without an external provider.

For the owner's deployment sequence, follow [OPERATOR.md](OPERATOR.md).

Use a public HTTPS origin such as `https://mcp.example.com`. Replace this
example everywhere, including provider callback registrations and the proxy.

For Microsoft Entra, create a single-tenant Web app registration and register
`https://mcp.example.com/auth/callback/entra`. Record the tenant ID, client ID
and client secret **Value**. Define enabled user/group app roles `Canvas.User`
and `Canvas.Owner`, then assign trusted users and the operator in Enterprise
applications. Assigned roles are included in the app's ID token; see
[Microsoft's app-role guide](https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps).
The built-in authorization server issues the MCP client's access/refresh tokens;
Entra supplies the browser sign-in identity. `MCP_SCOPE` defaults to `Canvas.Access`.

Invite external users into your workforce tenant and have them redeem the
invitation, then assign the appropriate app role. Use
[Microsoft's B2B invitation guide](https://learn.microsoft.com/en-us/entra/external-id/b2b-quickstart-add-guest-users-portal).
The real guest sign-in and client refresh flow still need staging validation.

Google, GitHub and generic OIDC can be configured independently of Entra in
Admin > Settings. Register these callbacks in their respective apps:

| Provider | Web callback |
| --- | --- |
| Entra | `/auth/callback/entra` |
| Google | `/auth/callback/google` |
| GitHub | `/auth/callback/github` |
| OIDC slug `school` | `/auth/callback/oidc/school` |

Provider credentials, role names, enablement and button order belong in the
database. See [env.reference.example](env.reference.example) for optional global
admission and owner policy overrides. Configure admission rules for optional
providers before offering them to users. Removing Entra requires another usable
owner path. Never link accounts by matching
email addresses; users link identities while signed in.

## Prepare Docker

The host needs Docker Engine with Compose v2, enough disk for the image/database,
and outbound HTTPS to the configured IdPs, Canvas and optional school directory.
The self-host image is built from `Dockerfile.selfhost`; the root Dockerfile is
the upstream Azure deployment. The image builds React and installs locked Python
dependencies, including document extraction and PostgreSQL. It runs as UID/GID
10001, keeps the root filesystem read-only and writes persistent data to `/data`.

Deployment needs exactly two files: `docker-compose.yml` and `.env`. Download
`env.example` as `.env`, fill `PUBLIC_BASE_URL`, and run:

```sh
docker compose up -d
```

The image defaults to `ghcr.io/kkazuhak/canvas-mcp:beta`. Set `CANVAS_MCP_IMAGE`
only to choose another reviewed version or digest. The container generates its
internal encryption keyring and browser-session secret once, saving a private
`/data/runtime-secrets.json` on the persistent data volume. Recreating the
container keeps the same keys. No host environment exports, OpenSSL commands,
setup script or other downloaded files are required. The defaults are student,
read-only and anonymized. Schools are managed after sign-in.

Open `PUBLIC_BASE_URL/account/setup`. Use the installation code from
`docker compose logs canvas-mcp` and create your local administrator there.
You can optionally configure Entra, Google, GitHub or OIDC during setup, or add
them later in Admin > Settings. Local passwords are stored as salted scrypt
hashes in SQL. Owners create regular local accounts in Settings; public local
registration is closed. Password changes on the account home page invalidate
existing sessions and connected app grants.
The code expires after 30 minutes; obtain another with
`docker compose exec canvas-mcp python -m canvas_mcp.core.selfhost.token_admin setup-code`.
Login credentials and enablement are encrypted/database-managed through
Admin > Settings. Existing database-owned values always win over environment
credentials. Old deployments can explicitly adopt their previous provider
environment once with `token_admin login-providers --import-env`.

Use `docker compose ps` to observe readiness; `up -d` returns before the health
check completes. Editing `.env` requires `docker compose up -d` to recreate the
container. Keep `.env` private and preserve the persistent volume. If an existing
database has lost its original keys, startup refuses to generate replacements.
Existing explicitly configured keys remain supported; keep those keys in `.env`.

[env.reference.example](env.reference.example) is the optional full settings
reference. Legacy environment export, upgrade, backup and transfer tooling
remain together in the removable `core/selfhost/db/migrations/` package.

For a source build, select `CANVAS_MCP_IMAGE=canvas-mcp:selfhost-v1-local` in
`.env` and use the repository's build override:

```sh
docker compose -f docker-compose.yml -f docker-compose.build.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build
```

### Optional PostgreSQL

SQLite is the default, at `/data/canvas-mcp/tokens.sqlite3` on the fixed
`canvas-mcp-data` volume. For a new PostgreSQL installation, generate
`POSTGRES_PASSWORD` with `openssl rand -hex 32` and set the matching
`DATABASE_URL=postgresql+psycopg://canvas:PASSWORD@postgres:5432/canvas_mcp`.
Do not paste the placeholder literally. The override publishes no database port,
uses an internal network and waits for the PostgreSQL health check.

```sh
docker compose -f docker-compose.yml -f docker-compose.build.yml \
  -f docker-compose.postgres.yml config --quiet
docker compose -f docker-compose.yml -f docker-compose.build.yml \
  -f docker-compose.postgres.yml up -d --build
```

For a published image, omit `-f docker-compose.build.yml`. A managed PostgreSQL
service uses `DATABASE_URL` without the local database override; configure TLS
verification for that service. Do not switch an enrolled SQLite deployment by
just changing `DATABASE_URL`; use [the isolated transfer tooling](../../src/canvas_mcp/core/selfhost/db/migrations/README.md).

## Configure the reverse proxy

Compose publishes only `127.0.0.1:8819`. Terminate HTTPS at nginx or Caddy, using
[nginx.conf.example](nginx.conf.example) or [Caddyfile.example](Caddyfile.example).
Replace `mcp.example.com` and certificate paths. Preserve the Host header,
stream MCP responses without buffering and allow a suitable stream timeout.
Use per-IP rate limits at the proxy; the server's limits are process-wide.

Forward these public route families to the service:

| Route | Purpose |
| --- | --- |
| `/mcp` | Authenticated MCP streamable HTTP |
| `/healthz` | Liveness |
| `/.well-known/oauth-authorization-server` | Local OAuth metadata |
| `/.well-known/oauth-protected-resource/mcp` | MCP resource metadata |
| `/authorize`, `/token`, `/register`, `/revoke` | Local OAuth protocol |
| `/auth/login/<provider>` | External browser sign-in |
| `/auth/callback/<provider>` | External browser callback |
| `/account` and `/account/*` | React panel and static assets |
| `/api/v1` and `/api/v1/*` | Account JSON API |

For OIDC, `<provider>` is `oidc/<slug>`. nginx uses the trailing-slash `/auth/` prefix to cover sign-in and callbacks;
never use a broad `/auth` prefix that also matches `/authorize`. Public provider data is `GET /api/v1/providers`; session
status is `GET /api/v1/me`. Old account login/API aliases are absent.

Keep authorization codes, `state`, transaction IDs, headers and cookies out of
proxy logs. nginx logs the path rather than the full request line; review error
logs too. If Cloudflare is used, keep OAuth/MCP/API responses uncached and avoid
interactive challenges on client protocol routes. Use TLS between proxy layers.
Any exemption for shared client egress addresses in the example must be reviewed
for your deployment; an address list is not an authentication boundary.

For MCPHub connections with each user's own Canvas identity, see the
[MCPHub configuration guide](../mcphub/README.md).

## Enroll and connect a client

1. Open `https://mcp.example.com/account`, sign in as an admitted owner and
   check the Admin panel. Pending accounts need approval before enrollment.
2. Use Admin > Settings to rename sign-in buttons, add featured schools or turn
   directory search off. A new database has no featured school and directory
   search enabled. Search terms are sent to Instructure's public directory.
3. Each user chooses their own school, reads and acknowledges the custody notice
   and submits their own Canvas API token in `/account/token`. Never paste a token
   into an assistant chat. Removing a school from the offered set can stop its
   bindings; encrypted tokens remain stored and can be used if offered again.
4. Configure the MCP client with `https://mcp.example.com/mcp`, finish browser
   sign-in and approve its consent request. The connected app appears in the
   user's Apps page and can be revoked there.

MCP authorization reads the current account/grant/credential state on each
request. Disabled accounts and revoked grants stop immediately; no grant-status
TTL delays that decision. Credential replacement invalidates dependent state.
Outdated custody acknowledgements require re-acknowledgement in the panel before
Canvas tools can use the saved credential.

**Write tools: each user opts in.** The operator's `ALLOWED_WRITE_TOOLS` and
`STUDENT_WRITE_TOOLS` form a ceiling. Every user must explicitly enable individual
write tools, and course policy can still refuse them. Submission, messaging and
other confirmation tools require the human's approval after preview. Prompt
injection in Canvas content can influence a client: keep sensitive writes subject
to the client's approval controls. Code execution is disabled in self-host mode.

**Course state.** `SELFHOST_COURSE_STATE=request_local` is the default. The
`per_principal` opt-in caches course data under account/school/credential generation
and invalidates it when the credential changes. It retains more per-user data.
`SELFHOST_DISABLED_TOOLS` removes named tools entirely and cannot enable a write.

**Optional pilot profile.** `SELFHOST_PROFILE=pilot` removes `read_course_file`,
`read_course_file_text` and `download_course_file`, and refuses every download
hop that leaves the configured Canvas origin before sending that request.
Canvas files usually redirect to storage, so the pilot cannot read those files.
The ordinary deployment keeps its existing HTTPS download behavior and strips
Canvas credentials from off-Canvas requests.

Before enabling the profile, configure exactly one featured school and turn
`schools.directory_search` off with `token_admin schools/settings` (see
[CONFIGURATION.md](CONFIGURATION.md)). Startup refuses a different school
configuration, any `ALLOWED_WRITE_TOOLS`, enabled code execution, or
`SELFHOST_COURSE_STATE=per_principal`. While active, the panel and operator
commands refuse enabling directory search or changing the featured list to
zero or multiple schools. Run operator commands with the same profile environment;
a running pilot also refuses a changed snapshot that violates these constraints.
The owner's multi-school deployment leaves this optional profile unset.

## Custody and privacy boundary

The enrolled Canvas PAT is encrypted with AES-256-GCM and bound to its account,
school, credential kind and key ID. Encryption protects a database or backup
leaked without its keyring. It does not protect against a compromised running
server or an operator who holds both keys and data: either can decrypt every
stored token. Browser owner pages and API responses do not display saved PATs.
Each user must acknowledge this custody boundary before enrollment or when the
notice changes. Disconnecting removes the saved credential; account disablement
blocks access while keeping it, and account deletion removes dependent records.
Retention policy can preserve audit history after deletion.

| Sensitive material | Custodian and purpose |
| --- | --- |
| `CANVAS_TOKEN_KEYS` | Private persistent key file and protected backups; optional explicit environment override; credential/sealed-secret encryption and derived local JWT keys |
| `ACCOUNT_SESSION_SECRET` | Private persistent key file; optional explicit environment override; browser session and sign-in protection |
| External provider client secrets | Encrypted SQL database fields; authenticating the app to the configured IdP; never returned by the configuration API |
| Canvas credentials and reserved Canvas OAuth-app seals | SQL database; decrypted only by the service/operator with the keyring |
| Browser cookies, OAuth codes, refresh tokens and protocol state | Short-lived bearer/protocol material; never log or publish it |

Account/identity names, school bindings, statuses and audit metadata are stored
in plaintext SQL. Enabling tool-result anonymization does not anonymize this
operational database, external IdP requests, proxy logs or all Canvas content.
Keep host, database, backups and `.env` access restricted. Access-event logging
is opt-in through `LOG_ACCESS_EVENTS`; administrative/security SQL audit remains
separate. Never attach credentials or authorization query values to a report.

## Operate and inspect

See [CONFIGURATION.md](CONFIGURATION.md) for governed settings commands,
[MAINTENANCE.md](MAINTENANCE.md) for retention/cleanup behavior and
[PAGINATION.md](PAGINATION.md) for list cursors and CLI history continuation.
Account targets are canonical bare UUIDs.

```sh
docker compose exec canvas-mcp python -m canvas_mcp.core.selfhost.token_admin check
docker compose exec canvas-mcp python -m canvas_mcp.core.selfhost.token_admin accounts
docker compose exec canvas-mcp python -m canvas_mcp.core.selfhost.token_admin providers list
docker compose exec canvas-mcp python -m canvas_mcp.core.selfhost.token_admin schools list
docker compose exec canvas-mcp python -m canvas_mcp.core.selfhost.token_admin settings get
```

Use the CLI's `--help` for account disable/enable/delete and grant revoke commands.
Owner actions re-check permissions transactionally and protect the last usable
owner. The operator CLI is privileged; keep its host access restricted. Deleting
an account removes its dependent credentials and grants while retaining the
configured audit history.

For encryption-key rotation, keep old keys in `CANVAS_TOKEN_KEYS`, prepend a new
active key, recreate the server and run `token_admin rotate`. The rotation covers
credential, provider-secret and reserved OAuth-app seals without changing custody
or credential generations. Verify the key inventory and active clients before
removing old keys. Back up the SQL database and its matching keyring together.
Use the dedicated migration/backup guide for database copying and schema changes;
do not copy a live SQLite file without its WAL or the SQLite backup API.

## Validate before publishing a v1 release

### Tested clients

Only `Passed` rows are compatibility claims. Unit and simulated SDK checks do
not establish a real client result; mobile support requires its own passing row.
Fill in versions, date, tester and a secret-free evidence reference during staging.

| Client/surface | Client version | Server version/image digest | Date | Tester | Result | Evidence | Notes |
| --- | --- | --- | --- | --- | --- | --- | --- |
| claude.ai web | Web; build not exposed | 1.14.0-beta.8, revision 85ffeca7 (operator output) | 2026-10-12 | Owner/live web check | Partial | [Live checkpoint](V1-PROGRESS.md#historical-beta8-staging-image) | Real CIMD/OAuth, 48 read-only tools, missing-token refusal and successful get_my_profile after enrollment. Consecutive-day refresh and broader acceptance pending. |
| Claude Desktop (shared remote connector) | Desktop build not separately observed | Shared web acceptance; no separate server observation | 2026-10-13 | Owner acceptance decision | Partial | [Acceptance scope](V1-PROGRESS.md#shared-remote-connector-acceptance) | Owner accepts the existing claude.ai remote-service evidence for the shared connector and waives a duplicate Desktop call. Desktop UI and build compatibility were not separately tested. |
| Claude Code | 2.1.285, Windows, HTTP | Beta.10, then version-endpoint-confirmed beta.11 | 2026-10-13 | Owner/local client check | Partial | [Live checkpoint](V1-PROGRESS.md#claude-code-read-only-acceptance) | Real OAuth and one successful get_my_profile call per check with Sonnet; the beta.11 call reused the existing grant without interactive reauthorization. No other tools or writes. Earlier beta.8 next-request grant revocation passed. Consecutive-day refresh and broader acceptance remain pending; the temporary project connection is retained for that check. |
| Claude mobile | - | - | - | - | Not tested | - | Support is not claimed |

The owner accepts web and Desktop as one remote-service acceptance scope for
the existing account-managed Canvas MCP connector; a duplicate Desktop call
is no longer a HANDOFF gate. Current
[client guidance](DEVELOPMENT.md#612-live-live-verification-checklist)
explains the shared account and cloud request path. This scope decision does
not add a separately observed Desktop UI or build result, a local stdio result,
or mobile acceptance. Claude Code retains its separate real HTTP-client evidence.

### Staging acceptance

Build the reviewed source and run `bash deploy/selfhost/smoke-test.sh IMAGE` on a
Docker host. The smoke test uses throwaway credentials and volumes, exercises the
image's public contract and refusal paths, and deletes its temporary resources.
It does not authenticate a real IdP user or simulate a real client's long-lived
refresh. Windows source checks alone do not prove the Linux image starts.

The staging beta is published for acceptance, not as a compatibility claim.
Before a stable release, production use or a compatibility claim, perform the
handoff's staging gates: owner/member and Entra B2B
guest sign-in; two users with separate Canvas credentials; two schools; all
configured providers and identity-link conflicts; Claude client consent and
refresh; account/grant/token revocation; key rotation with old access/refresh
tokens; restart and proxy failure; both persistence backends; and consecutive-day
refresh observations. Record exact image/source versions and timestamps without
secrets. The maintainer's pilot/client compatibility confirmation is a separate
outstanding gate. Local unit tests do not substitute for these checks.

## Reuse an existing MCPHub login

The optional [Hub session integration](hub-session.md) adds MCPHub as a login method while preserving existing Canvas accounts and OAuth. It requires only a narrow reverse proxy route alongside the Hub deployment.
