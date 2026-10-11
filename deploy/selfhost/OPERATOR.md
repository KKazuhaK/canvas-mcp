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
2. Follow [Entra setup](README.md#prepare-an-external-sign-in-provider) in the
   owner's tenant. Register a single-tenant Web application with only
   `https://mcp.example.com/auth/callback/entra` as the callback. Set assignment
   required, define `Canvas.User` and `Canvas.Owner`, and grant the required
   consent. Do not configure an exposed MCP API: the service issues MCP tokens.
   Assign the owner `Canvas.Owner`, or use the documented bootstrap-owner option.
   Invite friends as B2B guests and assign `Canvas.User`; include a guest whose
   home account is in another tenant in the later acceptance checks. Optional
   Google, GitHub or OIDC providers remain off unless explicitly configured.
3. Use [the Docker instructions](README.md#prepare-docker) from the reviewed
   revision. Run `bash setup-env.sh` inside `deploy/selfhost`; it prompts for the
   origin, Entra IDs, image name and client secret and writes a private `.env`.
   It does not prompt for a school. For a source build, select the local image
   name and use `docker-compose.build.yml`; for a published image, pin its v1
   version or digest. Keep an offline copy of `.env` and the encryption keyring.
   Use [the PostgreSQL override](README.md#optional-postgresql) only when selected;
   it publishes no database port. Never point an enrolled SQLite installation
   at an empty PostgreSQL database without the explicit transfer procedure.
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
6. Sign in as the admitted owner and follow
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
