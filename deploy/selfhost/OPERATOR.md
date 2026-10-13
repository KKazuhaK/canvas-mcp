# Owner deployment walkthrough

Use this checklist for the independent fork's v1 deployment. The complete
configuration reference is [README.md](README.md); source acceptance and pending
live gates are recorded in [V1-PROGRESS.md](V1-PROGRESS.md). The owner supplies the
host and reverse proxy. This walkthrough does not record a deployment as tested.
The reviewed multi-architecture staging image and its immutable digest are in
[V1-PROGRESS.md](V1-PROGRESS.md#deployable-staging-image).

1. Choose the reviewed commit or image digest and a staging origin, for example
   `https://mcp.example.com`. Keep that origin consistent across `.env`, the
   reverse proxy and the Entra redirect URI. Follow
   [host prerequisites](README.md#prepare-docker): Docker Engine, Compose v2,
   persistent storage and outbound HTTPS. Start with a fresh v1 database;
   pre-v1 databases are refused. An existing `latest` or `edge` image may be old.
2. External sign-in is optional; local accounts need no external app registration.
   If using Entra, follow [Entra setup](README.md#prepare-an-external-sign-in-provider) in the
   owner's tenant. Register a single-tenant Web application with only
   `https://mcp.example.com/auth/callback/entra` as the callback. Set assignment
   required, define `Canvas.User` and `Canvas.Owner`, and grant the required
   consent. Do not configure an exposed MCP API: the service issues MCP tokens.
   Assign the owner `Canvas.Owner`, or use the documented bootstrap-owner option.
   Invite friends as B2B guests and assign `Canvas.User`; include a guest whose
   home account is in another tenant in the later acceptance checks. Optional
   Google, GitHub or OIDC providers remain off unless explicitly configured.
3. Download only `docker-compose.yml` and `env.example` from the reviewed revision.
   Save the latter as `.env`, fill `PUBLIC_BASE_URL`, and run
   `docker compose up -d`. No setup script or manual key generation is required.
   The beta image is the Compose default; override `CANVAS_MCP_IMAGE` only to pin
   another reviewed version/digest. The image generates and persists its own
   internal keys in `/data/runtime-secrets.json`, private to UID 10001. Preserve
   the data volume and `.env` when recreating the container. Explicit keys from
   an existing deployment remain supported and must be retained. Optional source
   builds and PostgreSQL are covered by the repository's advanced reference.
4. Start the container using the chosen Compose files. Confirm the local
   `/healthz` response, inspect the startup log, and run:

   ```sh
   docker compose exec canvas-mcp python -m canvas_mcp.core.selfhost.token_admin check
   ```

   The command runs inside the existing app container, including its selected
   database configuration. A healthy process alone does not prove real sign-in
   or client compatibility.
5. Configure DNS, TLS and [nginx or Caddy](README.md#configure-the-reverse-proxy).
   Replace the neutral host and certificate paths in the shipped examples.
   nginx's `location ^~ /auth/` must keep its trailing slash. Preserve Host,
   streaming responses, request limits and callback log redaction. Check the
   external health response and provider callback through that proxy.
   Both `/.well-known/oauth-authorization-server` and
   `/.well-known/oauth-protected-resource/mcp` must return application JSON.
   In aaPanel/BaoTa, open Website > the site's Settings > Configuration and
   add the `location ^~ /.well-known/oauth-` block from
   [nginx.conf.example](nginx.conf.example) inside the HTTPS `server` block,
   alongside its other locations, if a panel-generated `.well-known` rule
   returns a static 404. Save, validate and reload nginx in the panel. The
   prefix preserves the original request path and leaves ACME validation alone.
6. Open first-install `/account/setup` using the private code from the container
   logs and create a local administrator. External login configuration is optional
   during setup and can be added later in Settings. Configuration belongs in the
   database, not `.env`. After initialization, sign in and follow
   [enrollment and client setup](README.md#enroll-and-connect-a-client). A fresh
   database has no preset schools. Manage sign-in names, featured-school order
   and directory search in Admin > Settings, or use the governed
   [`providers`, `schools` and `settings` CLI commands](CONFIGURATION.md).
   Read the [custody notice](README.md#custody-and-privacy-boundary) and record
   its acknowledgement before storing a PAT. Each friend stores their own PAT
   and chooses their school; no server-wide Canvas token is configured.
7. Complete [live acceptance](README.md#validate-before-publishing-a-v1-release)
   using the staging beta before a stable release, production use or compatibility claims.
   Record client versions, exact server commit/image
   digest, date and results in the tested-client table. Exercise Entra B2B guest
   sign-in, two users/two schools, disable at the next MCP request, real consent
   and refresh across consecutive days, CIMD reachability, proxy limits and log
   redaction. Test optional providers only if enabled. Keep untested rows marked
   `Not tested`; mobile support is claimed only after its own passing check.

For normal operations, use [Operate and inspect](README.md#operate-and-inspect)
and [MAINTENANCE.md](MAINTENANCE.md). Offboard in this order: disable the account
in the panel first, verify the next MCP request is refused, then remove the
guest/assignment in Entra. Entra role changes are observed at verified sign-in
and the configured maximum upstream-authentication age; they do not replace
local account disable.

Keep all upgrade, compatibility, backup and database-transfer instructions in
[the dedicated migration package](../../src/canvas_mcp/core/selfhost/db/migrations/README.md).
Pin each new image before pulling it, preserve the database and matching keyring,
and use the reviewed automatic or explicit schema-upgrade path. Verify a restore
before relying on a backup. Restore the matching keys along with the SQL data.

For encryption rotation, retain old key IDs, prepend a new active key, recreate
the container with its updated environment and run `token_admin rotate`; inspect
the key inventory and live clients before removing old keys. For a JWT-only
epoch change, use `token_admin rotate-jwt-key` and verify reconnect/refresh
behavior. These are separate operations. Keep operator host access restricted;
never include secrets, bearer tokens, authorization codes or cookies in an
acceptance report.


## Browser sessions and Canvas token reminders

In **Admin → Settings**, browser sign-in duration is database-owned and defaults
on first installation to 7 days. The legacy environment override is adopted only
once. Changes need no restart: shortening also limits existing sessions; a longer
duration takes effect at the next sign-in. Sensitive administrator actions still
require a sign-in within the last 10 minutes.

The same page configures SMTP with verified STARTTLS or TLS and a reminder window
of 1–90 days (default 7). The password is encrypted in the database and included
in normal key verification, rotation and database transfer. Save the settings,
then use **Test saved SMTP connection** to check connection, certificates and
authentication; this test does not send an email. Users opt in and save a reminder
recipient on their account home page. No additional deployment environment values
are required.

When verifying a Canvas token, the service attempts the documented read-only token
metadata endpoint. A response must match the submitted token hint and the verified
Canvas user. A supported response supplies the real UTC expiry or reports no
permanent expiry. Unavailable or forbidden metadata falls back to the date entered
by the user, and the account page shows its source. Existing active tokens can
use **Re-check token** to read supported expiry without re-entering the token or
revoking connected apps. Tokens are never regenerated
in Canvas by this feature; the home page guides the user to create and save a new
token. Token values are never included in reminder messages.

Email delivery is checked at startup and hourly, independently of web traffic.
Each bounded pass considers at most 100 eligible credentials. Shared SQL claims
prevent concurrent workers from sending the same stage together. A successful
pre-expiry notice and a successful expiry notice are each recorded once per token
generation and expiry. Failed attempts wait at least an hour and stop after three
attempts; SMTP acknowledgement loss can still cause a retry of an already delivered
message. Disabled accounts, opt-out, deleted/replaced credentials and unknown
expiry are excluded. Check container logs for the redacted delivery-failure message.

**Before upgrading from beta.8 or earlier, take a database backup.** The SMTP
revision raises compatibility floor to 3 because older key tooling cannot verify
or rotate this newly sealed secret. Existing account IDs, identities and token
ciphertexts are preserved. SQLite's normal contract migration automatically saves
its pre-upgrade backup; PostgreSQL needs the operator's existing backup procedure.
Running an older image after this upgrade requires restoring its matching backup.
The runnable deployment remains just Compose plus the complete `.env` template.
