# canvas-mcp self-hosted mode: v1 consolidation design

Status: design, ready to implement. The owner decisions D1-D14 of 2026-10-11 (1.1) are authoritative. Audience: the developer who implements it. It is committed as `deploy/selfhost/V1-DESIGN.md`, next to the developer handoff `deploy/selfhost/DEVELOPMENT.md` . Read handoff sections 2 to 4 first: runtimes, commands, invariants.

Conventions:
- `selfhost/` means `src/canvas_mcp/core/selfhost/`. Other paths are relative to the repository root.
- "P7" means the branch `feature/p7-login-providers`, HEAD `53b86dd` (clean, unpushed). Its last fix round (bootstrap and re-sourced owners get `admitted_via` set, `token_admin` uses the intersection of the recorded and environment provider lists, the `owner_re_sourced` event) passed the full test matrix but has not been independently reviewed. Merge P7 only after one more independent review (6.0).
- Line numbers are approximate and refer to `uci-student` at `71602e6` (the P7 worktree shifts many of them, for example `deploy/selfhost/env.example` has `OAUTH_JWT_SIGNING_KEY` at line 155 there and 202 on P7). Function and constant names are the stable anchors.
- "A" and "B" are the two candidate designs this document reconciles: A is extensibility-first, B is performance-first.
- Measurements quoted here come from the surveys and candidates. They are single runs on one Windows machine against PostgreSQL 16.2 and SQLite 3.50.4 with synthetic stress data. Read them as plan evidence, not as benchmarks. At the real scale (tens of accounts) every statement is sub-millisecond.

This document supersedes the following parts of the handoff (the handoff has been updated to match; where the two differ on a technical fact, this document wins, and on an owner decision the handoff decisions log, section 5, wins):
- 5, the P6 decision "do not remove `entra_proxy`".
- 6.1a, the `server_settings` JSON table.
- 6.2 and 6.3, the precedence and data-model parts. Their UI site inventories, validation rules and tests still apply; section 5.9 lists them.
- 9, the former "Removing `entra_proxy`" row (deleted from the handoff).

---

## 1. Summary of decisions

### 1.1 Decisions

**Owner decisions of 2026-10-11.** Each is applied everywhere in this document; the bullets after the table give the design reasons.

| Id | Decision | Applied in |
|---|---|---|
| D1 | Nothing is deployed, so the consolidation is done once, in one step: no aliases, no transition release, no data migration from pre-v1 builds. | 6.0 |
| D2 | `entra_proxy` is removed; the own authorization server is the only MCP auth path. Entra (the owner's own tenant) is the default sign-in provider; friends join as Entra B2B guests assigned `Canvas.User`. Google, GitHub and OIDC stay available but off until listed. | 2, 2.5 |
| D3 | Routes `/auth/login`, `/auth/login/{provider}`, `/auth/callback/{provider}` (Entra: `/auth/callback/entra`), per RFC 9700 section 4.4.2.2. The JSON API moves to `/api/v1`; `/account` is the React UI. | 3 |
| D4 | All Alembic revisions are squashed into one clean v1 baseline designed for extensibility and performance. | 4 |
| D5 | The React UI is the only account UI. The legacy server-rendered pages are removed (step 2 is mandatory). Every new feature is built once. | 2.3, 3.7, 5.7, step 2 |
| D6 | Featured schools come only from the admin panel (and its `token_admin` twin). The list starts empty: no preset school of any kind. `CANVAS_FEATURED_SCHOOLS` is removed and refused. | 2.3, 4.3.4, 5, step 6 |
| D7 | The school directory search switch is admin-editable and ON by default. `CANVAS_SCHOOL_SEARCH` is removed and refused. | 2.3, 4.3.2, 5, step 6 |
| D8 | One custom name per sign-in method, shared by English and Chinese, editable by the owner in the admin panel (not hardcoded, not env-only). | 4.3.3, 5 |
| D9 | Renames now: `MCP_AUTH_MODE=entra-oauth` becomes `MCP_AUTH_MODE=selfhost`, `ENTRA_API_SCOPE` becomes `MCP_SCOPE` (default `Canvas.Access` kept). The old names refuse startup with a message naming the replacement. | 2.2, 2.3, 2.5, step 1, step 8 |
| D10 | Before a Canvas token is enrolled, the user sees a custody notice and must tick a required checkbox. The acknowledgement is recorded server-side with time and notice version; a changed notice version requires a new acknowledgement. | 3.2, 4.3.8, 4.5.1, step 6b |
| D11 | Repo docs and the nginx/Caddy examples use neutral examples (`mcp.example.com`, `canvas.example.edu`) instead of the owner's real domain and UCI's Canvas host. | step 8 |
| D12 | The name stays `canvas-mcp`. The docs state that this is an independent fork of `vishalsachdev/canvas-mcp`, not endorsed by upstream. Only small core improvements go upstream. | step 8 |
| D13 | Canvas OAuth (institutional Developer Key) is rejected for now and only reserved. | 4.14 |
| D14 | Python plus React/TypeScript stay; MUI 9 stays the UI library. | 1.1 |

**Authorization**
- **The own authorization server is the only MCP authorization path.**
  - `SELFHOST_AUTH_MODE`, `entra_proxy`, FastMCP `OAuthProxy`/`AzureProvider`, `FASTMCP_HOME` and `OAUTH_JWT_SIGNING_KEY` are deleted.
  - Reason: one path to review. It also removes the only node-local persistent state, the Fernet file store.
- **Entra stays the default sign-in provider, as a plain OpenID Connect web client.**
  - The app registration loses "Expose an API", `Canvas.Access`, `offline_access` and the proxy redirect URI.
  - Reason: the server never needs an Entra access token again.
- **Google, GitHub and generic OIDC stay available and off by default.** An unset `SELFHOST_LOGIN_PROVIDERS` means `entra` alone (P7 `login/config.py`, unchanged); another provider is enabled only by listing it.
- **Old settings refuse startup, with a message naming the replacement.**
  - Reason: an old `.env` must not silently mean something else.
- **Entra moves onto P7's server-side flow engine** (`login/flows.py`).
  - Reason: one ceremony, one cookie (`__Host-cmcp_flow`), and the same mix-up defence for every provider.

**Routes**
- **Sign-in ceremonies live under `/auth/*`.** The shapes are `/auth/login`, `/auth/login/{provider}` and `/auth/callback/{provider}`, with `oidc/{slug}` for generic OIDC.
  - Reason: a standard namespace, and nothing in FastMCP or the MCP SDK uses it.
- **Entra uses `/auth/callback/entra`, not a bare `/auth/callback`.**
  - Reason: one rule for all providers. It is RFC 9700 section 4.4.2.2 conformant, and it is the only Microsoft-documented mix-up defence for Entra.
- **The JSON API moves from `/account/api` to `/api/v1`.** `/account` is only the React UI.
  - Reason: it is cheapest now, gives clean per-prefix proxy and CSP rules, and adds a version segment for free.

**UI library**
- **The React UI uses MUI (Material UI) 9.4 with Emotion, not Ant Design.**
  - Evidence: `web/package.json` pins `@mui/material` and `@mui/icons-material` 9.4.0, `@emotion/react` 11.14.0 and `@emotion/styled` 11.14.1.
  - Keep MUI. Switching would be a rewrite with no gain.
- **The React app is the only account UI (D5).** `ACCOUNT_UI` and the server-rendered pages (about 4,100 lines of `account_web.py` plus about 20 form routes) are removed; `ACCOUNT_UI` refuses startup.
  - Reason: every route move, R1, R2 and D10 would otherwise be built twice. The image already builds the bundle.

**Names (D9)**
- **`MCP_AUTH_MODE=selfhost` and `MCP_SCOPE` replace `MCP_AUTH_MODE=entra-oauth` and `ENTRA_API_SCOPE`** in step 1. `MCP_SCOPE` keeps the default `Canvas.Access`. The old spellings refuse startup and name the replacement (2.3).
  - Reason: Entra is only a sign-in method now. It is cheap before anything is deployed.

**Canvas token custody (D10)**
- **A token is enrolled only together with an acknowledgement of the current custody notice**, stored on the credential row (`custody_notice_version`, `custody_ack_at`, both NOT NULL, 4.3.8), audited, and checked on every MCP request (4.5.1). A notice version bump makes every older acknowledgement insufficient until the user acknowledges again (step 6b).
  - Reason: the operator can technically decrypt stored tokens; users must know that, and the server must be able to show who accepted which text and when.

**Database: identity and types**
- **One clean Alembic baseline, `0001_v1_baseline`.** It replaces `0001_baseline_v4`, `0002_accounts` and `0003_oauth_authz` (P7 adds none).
  - Reason: nothing is deployed, and the legacy migration code goes with them: 1,391 lines in `baseline_v4.py`, `accounts_v5.py` and the three revision files, plus the legacy-adoption, backup and data-migration parts of `db/migrate.py` and `db/transfer.py` (538 and 428 lines in total).
- **One account reference: a UUIDv7 minted by the application.**
  - Stored as native `uuid` on PostgreSQL and as canonical 36-character `TEXT` on SQLite.
  - `acct:<uuid>` exists only inside the AES-GCM AAD and the JWT `sub`/`acct` claims.
  - Reason: the bare/`acct:` duality goes away. Ids are ordered (index locality, keyset paging by id) and need no coordinator.
- **Times stay `bigint` Unix seconds.** Flags are booleans. Secret hashes and nonces are binary. JSON is used only for whole documents.
  - Reason: one representation on both backends, injected test clocks keep working, and binary hash keys are about 40% smaller.
- **CHECK constraints guard only closed state machines.** Open vocabularies are validated by code registries.
  - Reason: on SQLite, changing a CHECK rebuilds the table.

**Database: integrity and storage**
- **Foreign keys on every ownership edge, `ON DELETE CASCADE`. None on history tables.** SQLite runs `foreign_keys=ON`.
  - Reason: integrity is enforced, and purge, account deletion and grant cleanup become single statements.
- **19 tables.**
  - 16 live: `server_state`, `settings`, `login_providers`, `canvas_schools`, `accounts`, `external_identities`, `account_write_tools`, `canvas_credentials`, `oauth_clients`, `cimd_clients`, `oauth_grants`, `oauth_codes`, `oauth_refresh_tokens`, `login_states`, `auth_events`, `audit_log`.
  - 3 reserved and empty: `canvas_oauth_apps`, `web_sessions`, `account_quotas`.
  - Dropped from today: `meta`, `canvas_tokens`, `user_tool_prefs`, `credential_generations`, `principal_status_events`.
- **Credential generation, session epoch and write-tools version live on the `accounts` row.**
  - Reason: the per-request standing check becomes one primary-key probe.
  - It also lets health writes use a row-local guard instead of a global lock.
- **A school registry (`canvas_schools`) with a nullable `featured_rank`.**
  - No school is featured by default and nothing is seeded (D6). Credentials reference the school.
  - Reason: per-school data (name, featured order, the reserved Developer Key, `allow_private`) has one home.
- **One credential table for every Canvas credential kind** (`pat` now, `oauth` reserved), unique per `(account, school)`.
  - Reason: one hot read, one AAD layout, one rotation path. Multi-school needs no migration later.

**Request path and locking**
- **The MCP hot path is one statement per request and no write in steady state.**
  - One read returns the grant, the account standing, the credential, the JWT epoch and the settings revision.
  - The 5 s and 30 s status caches are deleted.
  - Reason: revocation, disable and key rotation take effect at the next request on every instance. Today it takes up to 30 s and only works in-process. This also replaces today's 2 statements per request (`get` plus `touch`).
- **Locking keeps the governance tier and adds two lock-free tiers (4.6).** Writes that decide from a set predicate or from owner standing (sign-in, owner and operator actions, credential, prefs and settings writes) take the global PostgreSQL governance lock. Machine-initiated per-request writes (tiers 0 and 1) and maintenance never take it, except the pending-accounts purge.
  - Reason: the set-predicate invariants (last usable owner, bootstrap, pending cap) stay as reviewed, and the hot path and maintenance stop queuing behind it.
- **One row-lock order for every transaction: code, then account, then grant, then refresh token** (4.6). Any statement that writes `oauth_codes` runs before the account row is locked. Per-request touches never wait for a lock.
  - Reason: the lock-free tier makes lock order the only deadlock defence. With the account locked before the codes, PostgreSQL 16.2 reproducibly deadlocks a first code exchange against a revoke-all and against an account deletion (4.6).

**Settings**
- **Admin-editable settings live in the database. The old environment variables are removed and refuse startup.**
  - Removed: `CANVAS_FEATURED_SCHOOLS`, `CANVAS_SCHOOL_SEARCH`, `OIDC_<SLUG>_DISPLAY_NAME`, and `CANVAS_API_URL` in self-host mode.
  - Featured schools: an empty list on a fresh install (D6). Directory search: ON by default, switched in Admin > Settings (D7). Sign-in method names: one name per method for both languages, edited in Admin > Settings (D8).
  - Reason: "env seeds an empty DB" is hidden first-boot state that re-adds what the owner deleted.

**Engines and operations**
- **SQLite engine.** A small connection pool replaces `NullPool`, STRICT tables, `foreign_keys=ON`, `trusted_schema=OFF`, `auto_vacuum=INCREMENTAL` at creation, `synchronous=FULL` kept, version 3.37 or newer required.
  - Reason: 1.1 ms of connection setup per call goes away, and types are enforced.
- **PostgreSQL engine.** A pool of 10 with no overflow, behind a process-wide `CapacityLimiter(10)`. `UNLOGGED login_states`. `fillfactor=90` on hot-update tables.
  - Reason: bursts queue in process instead of turning into 503s, and ceremony churn writes no WAL.
- **Maintenance is chunked.** Explicit id lists, about 2 s or 10 s per job per run, a per-job try-lock, never under the governance lock (the pending-accounts purge is the one exception, 4.6).
  - Reason: today's unbatched deletes can exceed the 15 s statement timeout forever and block sign-ins.
- **Migration policy is expand/contract, guarded by `server_state.compat_floor`.** It replaces `meta.schema_version` and the per-revision `COMPAT_SCHEMA_VERSION`.
  - Reason: an application rollback across an expand step works without a database restore.

### 1.2 Where the candidates disagreed, and what this design picks

| Topic | A | B | Pick | Why |
|---|---|---|---|---|
| Server facts | `meta` key/value, `config_revision` | `server_state` singleton row | **B**, plus A's `database_id` | Typed counters read on every request in one primary-key probe. A new counter is an `ADD COLUMN ... DEFAULT 0`. |
| Request path | Account plus credential read; caches kept, config polled every 10 s | One statement incl. grant and `server_state`; caches deleted | **B** | Same statement count as today, and revocation becomes immediate on all instances. It removes the main multi-instance blocker. |
| Schools | `canvas_schools` registry, credentials FK to it | `featured_schools` list, no FK | **A** | One entity per host. The reserved Developer Key and per-school options need it. "Who is enrolled at X" is an index probe. |
| `allow_private` | owner may set it | operator (`token_admin`) only | **B** | Skipping the SSRF guard must not be reachable from a web session. |
| Credential key | surrogate `id`, `UNIQUE(account, host)` | natural PK `(account, host, kind)`, `is_primary` | **A's key plus B's `is_primary`** | A stable id for the API and rotation chunks. One credential per person per school, with an explicit primary for later multi-school. |
| Identity ids | uuid v7 | bigint identity | **A** | Not enumerable through `/me/identities/{id}`, and no sequence to fix after a transfer. |
| Accounts list index | `(created_at, id)` | none, keyset on v7 `id` | **B** | v7 ids are creation-ordered, so one index fewer. |
| Write-tool cache | 30 s TTL kept | `accounts.write_tools_version` keys the cache | **B** | Never stale, no TTL, works across instances. |
| Refresh-token indexes | one composite `(grant_id, parent_hash)` | `(grant_id)` plus partial `(parent_hash)` | **A** | One index serves FK cascade, `any_used`, `retire_siblings` and `has_rotated_child`. The latter gains a `grant_id = ?` term, which is equivalent because a child always shares its parent's grant. |
| `auth_events` retention | primary-key walk, no `at` index | `at` index | **A** | Smaller and cheaper inserts. Ids and `at` are both monotonic up to clock skew, which only delays a few rows. |
| Batch delete form | `DELETE ... IN (SELECT ... LIMIT)` | two steps: select ids, then delete by explicit list | **B** | B measured the subquery form planned as a hash semi-join over a sequential scan (29 to 52 ms). The explicit list uses the key (1.3 to 3.8 ms). (Not reproduced in the fact-check run on PostgreSQL 16.2 with 1.2M rows: there the subquery form planned as a hash aggregate plus primary-key nested loop, 2 ms. The plan depends on statistics, so the explicit-list form stays as the plan-independent choice.) |
| Audit shape | `actor_kind`, `actor_id`, `subject_account_id`, `target_kind`/`target_id` | `actor` text, `target` | **A** | Typed actors. One per-account history covers status, credentials and grants. |
| `auth_events.ip` | nullable, kept | dropped | **B** | Always `unknown` today. An `ADD COLUMN` later costs nothing. |
| Vocabulary CHECKs | state machines only | also small closed sets (`admitted_via`, ...) | **A** | P7 already grew `admitted_via` semantics. One rule for all tables. |
| Exchange account lock | `FOR SHARE` | `FOR NO KEY UPDATE` | **B** | Smallest change from today's reviewed `FOR UPDATE`. It still conflicts with disable's `UPDATE`, and it no longer blocks FK child inserts. |
| Credential, prefs and settings writes | governance lock (A keeps credential writes; settings move off) | account-row and settings-row tiers | **Neither fully: all human-initiated writes stay under the governance lock** | Rare writes, and no measurable gain at this scale. The reviewed transactions stay as they are. The schema keeps B's row protocol possible without a migration. |
| Health writes (`mark_verified`, automatic `mark_invalid`) | row-local generation guard, no lock | same | **Both** | The generation is now on the same row, so READ COMMITTED re-evaluation is sound (`db/engine.py` docstring reason (c) is gone). |
| PostgreSQL pool | 5+5 | 10+0 plus `CapacityLimiter(10)` | **B** | 40 anyio threads against 10 connections turned bursts into 503s. |
| Settings concurrency | per-row `version` | per-row `version` | **One global CAS on `server_state.settings_revision`** | One owner and rare edits. No version columns, and one rule for the UI. |
| Refresh pre-purge 7 days after revocation | optional | kept | **Dropped** | Tokens leave with their grant at 30 days by cascade. Same rejection outcome, and one job fewer. |

---

## 2. Authorization: local only

### 2.1 What stays

- `selfhost/authz/*` (`LocalAuthorizationServer`) is the MCP authorization server. It serves `/authorize`, `/token`, `/register`, `/revoke` and both metadata documents. `assert_route_table`/`EXPECTED_ROUTES` keep pinning the route table.
- Access tokens stay HS256 JWTs whose key is HKDF-derived from `CANVAS_TOKEN_KEYS` per ring key and epoch (`authz/tokens.py`, `kid = <ring key id>.<epoch>`). Nothing replaces `OAUTH_JWT_SIGNING_KEY`.
- These settings stay:
  - `OAUTH_ALLOWED_REDIRECT_URIS`, `ACCESS_TOKEN_TTL`, `REFRESH_ABSOLUTE_TTL`, `REFRESH_REUSE_GRACE_S`;
  - `CIMD_ENABLED`, `CIMD_FETCH_TIMEOUT_S`, `CIMD_STALE_MAX`, `MAX_UPSTREAM_AUTH_AGE`;
  - all admission settings, and `ACCOUNT_SESSION_*`.
- The CIMD fetcher keeps using FastMCP's SSRF-pinned fetcher, so `FASTMCP_SSRF_TRUST_PROXY` stays refused (`app._ssrf_trust_proxy_enabled`).
- `authz/fastmcp_compat.py` stays the only importer of FastMCP and MCP internals. `tests/selfhost/authz/test_authz_compat_contract.py` now guards the only path, so treat its failures as release blockers.

### 2.2 Removal inventory

**Source (`selfhost/` unless a path says otherwise)**

| File | Remove | Keep or collapse |
|---|---|---|
| `oauth.py` | Remove the whole module: `OAuthStorage`, `_STORES`, `oauth_storage_of`, `cull_expired_oauth_state`, `build_entra_auth_provider` (it registers `redirect_path="/auth/callback"`), `_JWT_KEY_SALT`, `_STORAGE_KEY_SALT`, `_STORAGE_SUBDIRECTORY`, and the duplicate `DCR_CLIENT_TTL_SECONDS` (adjust `tests/selfhost/authz/test_clients.py` ~38). | `build_auth_provider` moves to `authz/runtime.py` and returns `LocalAuthorizationServer`. |
| `settings.py` | `AUTHZ_MODE_ENV`, `AUTHZ_MODE_ENTRA_PROXY`, `AUTHZ_MODE_LOCAL`, `AUTHZ_MODES`, `_parse_authz_mode`; fields `authz_mode`, `oauth_jwt_signing_key`, `fastmcp_home`; `MIN_SIGNING_KEY_CHARS`; the `OAUTH_JWT_SIGNING_KEY` and `FASTMCP_HOME` checks; `GRANT_STATUS_CACHE_S`; the parsing of `CANVAS_FEATURED_SCHOOLS` (`_parse_featured_schools`, `MAX_FEATURED_NAME_CHARS`) and `CANVAS_SCHOOL_SEARCH` (section 5). `CANVAS_API_URL` is not parsed in `settings.py`: it comes from `core/config.py` (`Config.canvas_api_url`, shared with the upstream modes), is consumed by `app.selfhost_school_policy`/`_school_problems` and `schools.SchoolPolicy.build(default, ...)`, and is required by the HTTP-mode checks in `src/canvas_mcp/server.py` (~425, ~866), which must stop requiring it in self-host mode. | The `:443` refusal becomes unconditional. `AuthzSettings` is always parsed; drop the "parsed in both modes" wording. Add `REMOVED_SETTINGS` (2.3). The module stays standard library only. |
| `app.py` | The `cull_expired_oauth_state` import and call. The `FASTMCP_HOME` writability and consistency checks in `validate_selfhost_startup`. In `prepare_selfhost`, the `if authz_mode == "local"` guard. In `install_selfhost`, `identity_mode=`. In `build_selfhost_asgi_app`: the `local`/`identity_mode`/`owners=None if local` logic, `provider = mcp.auth`, and `authz_local=`. P7's `assert runtime.authz is not None`. | `SelfhostRuntime.authz` becomes required. Keep `_ssrf_trust_proxy_enabled`. |
| `request_context.py` | `_GUID_RE`, `OwnerLedger`, `owners=`, `identity_mode`/`local_identity`, the `oid` logging branch for denied requests, `_note_owner_role_gone` and its call, and P7's `login_providers=` parameter. | `LocalClaimsResolver`, `RequestIdentity`. The request-context read (4.5) replaces `PrincipalAccessCache` use. |
| `tool_gate.py` | `_check_identity` (Entra `tid`/`oid`), the `entra_issuer` import, `identity_mode`, and the `_verify_identity` branching. | `_check_local_identity`. |
| `identity.py` | `IdentityService.resolve_request`, `_status`, `_resolve_with_write`; `IdentityCache` and `IDENTITY_CACHE_SECONDS`; `request_principal`; P7's `discard` calls after unlink; the test-only "first release oracle" (`ClaimsPolicy`, `ClaimsDenied`, `DenyReason`, `principal_key()`, `evaluate_entra_claims`, `authorize_id_token_claims`) and its tests. | Sign-in resolution (`resolve_identity` with `purpose="sign_in"` semantics). |
| `accounts.py` | In `entra_external_claims(token_kind=...)`, the `"access"` branch and the `azp` check. `DENY_WRONG_CLIENT`, including its `SIGN_IN_ERROR_CODES` entry in `account_web.py`, its denial text and its web locale strings. `Purpose` loses `"request"`, and every `"request"` branch of `decide()` goes. `SURFACE_MCP`, and `"mcp"` in `SIGN_IN_SURFACES` (also `db/repos.py`). | ID-token claim handling (`oid`, `tid`, `roles`, `groups`, `name`, `preferred_username`). |
| `token_store.py` | `resolve_identity(purpose="request")`; `demote_owner` (including P7's `listed_providers`); the `access_token_roles` vocabulary. | Everything else is ported in step 5. |
| `core/credentials.py` | `RequestPrincipal.tenant_id`, `object_id`, `upn` and `roles`. They are fork-only Entra fields, and their only consumer was `_check_identity`. | The rest. Keep the diff against upstream minimal. |
| `src/canvas_mcp/server.py` | In `_authz_summary`, the "entra_proxy ... ignored" line. The "FastMCP home" line. The `build_auth_provider` import and use (moved). The `authz_mode=` log field. The comments about Entra callbacks and "OAuth proxy logs" (~1071, ~1088). The proxy wording in the `--list-grants`/`--revoke` refusal text. | `--config` prints "MCP authorization: built-in authorization server". |
| `edge_guard.py` | The `authz_local` flag (always local) and the file-volume wording (`REGISTRATIONS_PER_DAY` comment, docstring). | `/token`, `/revoke`, `HEAD /authorize` refusal and the 16 KiB form cap become unconditional. Add a per-provider bucket for `/auth/login/*` and `/auth/callback/*`, Entra included. |
| `core/redact.py`, `core/logging.py` | The stale comments about the proxy and Fernet. | Keep `_ENTRA_REFRESH_RE` and the `gAAAA` pattern; redaction is harmless defence in depth. |
| `account_api.py`, `account_web.py` | The `local_authz` route flag. `features.connected_apps` and `features.consent` (always true). Every `self.authz is None` branch. | |
| `token_admin.py` | The proxy-mode refusals (~52, ~211). | `list-grants`, `revoke-grant`, `rotate-jwt-key` always available. |
| Comment-only | `authz/__init__.py`, `authz/runtime.py`, `authz/tokens.py` (the `OAUTH_JWT_SIGNING_KEY` note), `db/repos.py` ~836, `db/schema.py` ~202, `login_state.py` ~5, `accounts.py` ~160. | |
| `web/` | `features.connected_apps`/`consent` in `RequireFeature`, `api/types.ts`, `dev/mockServer.ts`, test fixtures and `ConnectedAppsView.test.tsx`. | |

**Renames (D9).** Inventory from `git grep` at P7 `53b86dd`; re-run it at the merge commit.

| Old | New | Sites |
|---|---|---|
| `MCP_AUTH_MODE=entra-oauth` (`settings.AUTH_MODE_ENTRA`) | `MCP_AUTH_MODE=selfhost` (`settings.AUTH_MODE_SELFHOST`) | Source: `selfhost/settings.py` (the constant and `auth_mode()`, whose return type becomes `Literal["legacy", "selfhost"]`), `src/canvas_mcp/server.py` (import, `--config` line ~645, the transport, `--test` and `--list-grants`/`--revoke` messages ~686-695, the start log ~753, the dispatch ~849), the docstrings of `core/cache.py` and `core/credentials.py` (keep the upstream diff to those lines). Deploy: `deploy/selfhost/{README.md,env.example,setup-env.sh,smoke-test.sh}`. Tests: `tests/selfhost/authz/test_settings_authz.py`, `test_course_state_modes.py`, `test_settings.py`, `test_setup_env_script.py`, `test_startup.py`, `tests/test_fastmcp_compat.py`, `tests/test_selfhost_docs.py`. |
| `ENTRA_API_SCOPE` (`settings.DEFAULT_API_SCOPE`) | `MCP_SCOPE` (`settings.DEFAULT_MCP_SCOPE`, value `Canvas.Access`) | `selfhost/settings.py` ~642-647: same format check (`[A-Za-z0-9._-]`, 1 to 64 characters); the message "must be the custom scope exposed by the app" goes, because no Entra API is exposed any more (2.5). `deploy/selfhost/README.md`, `env.example`; `tests/selfhost/test_settings.py`, `tests/selfhost/login/test_provider_settings.py`. |
| History | unchanged | `CHANGELOG.md` keeps its old entries and gains the v1 entry; `internal/*` and `proposals/selfhost-pilot/*` are history (see Docs and deploy below). |

`MCP_AUTH_MODE=legacy` and an unset `MCP_AUTH_MODE` keep selecting the upstream modes.

**Dependencies**
- `pyproject.toml` ~44-48: remove `py-key-value-aio[filetree]` and its comment. Its only importer was `oauth.py`.
- Regenerate `uv.lock` with `uv lock`. It stays as a transitive FastMCP dependency.
- `cryptography`, `joserfc`, and the `fastmcp`/`mcp` floors stay.
- `.github/workflows/canvas-mcp-testing.yml` ~195-198: drop the `py-key-value-aio` comment in `test-locked`.

**Tests**

| Action | Files |
|---|---|
| Delete | `tests/selfhost/test_oauth_storage.py` (move its dependency-range tests, the fastmcp/mcp/joserfc floors and "installed versions inside range", into `tests/selfhost/authz/test_authz_compat_contract.py` first); `tests/selfhost/test_oauth_wiring.py`; `tests/test_fastmcp_compat.py` ~162-298 (OAuthProxy contract, `_entra_provider`; keep 1-160); the `proxy_stack` fixture (`tests/selfhost/authz/conftest.py` ~89-95) and its users: `test_authz_flows.py` ~257, `test_metadata_routes.py` ~85-98, ~169-212, `test_account_api_authz.py` ~140, `test_account_pages_apps.py` ~84, 151, 245, `test_authz_e2e.py` ~366-402. |
| Rewrite on the local stack (`tests/selfhost/authz/stack.py`) | `tests/test_multiuser_e2e.py`: delete `TestOAuthProxyHardening` and the `build_entra_auth_provider` world builders; port `TestMcpAsTwoUsers`, `TestRefusedUsers`, `TestRefreshAndRevocation` and the enrollment, credential-lifecycle and legacy/stdio tests. Keep the filename so the CI PostgreSQL job line stays valid. In `tests/selfhost/test_edge_guard.py`, keep `TestTokenBucket`, `TestRegistrationLimits`, `TestSchemeIsPinnedToHttps` and `TestMaintenance`, and replace `TestThroughTheRealApp` and `TestStorageLifetimeAndCleanup` with local-server equivalents. |
| Rewrite (identity path gone) | `test_identity_service.py`, `test_identity.py`, `test_accounts_rules.py` (access-token kind, `azp`, wrong client), `test_request_context.py`, `test_tool_gate.py`, `test_course_state_modes.py`, `test_account_access_lifecycle.py`; `demote_owner` tests in `test_principal_status_store.py`, `test_account_races.py`, `test_principal_access.py`; `tests/selfhost/conftest.py` (`IdentityService(store, EntraClaimsPolicy(...))`). |
| Edit (drop `SELFHOST_AUTH_MODE`, `OAUTH_JWT_SIGNING_KEY`, `FASTMCP_HOME` from env fixtures) | `tests/selfhost/authz/stack.py` ~428-464; `test_settings.py`; `test_startup.py` (incl. ~139-148, the `FASTMCP_HOME` tests); `test_database_settings.py`; `test_silent_switch.py`; `test_selfhost_integration.py`; `test_disabled_tools.py`; `test_token_invalid_stack.py`; `test_write_tool_optin_stack.py`; `test_account_spa.py`; `test_dependency_isolation.py`; `test_setup_env_script.py`; `tests/test_selfhost_dockerfile.py`; `authz/test_settings_authz.py` (mode-parsing tests); `authz/test_smoke_script_contract.py`. |
| Rewrite (docs pins) | `tests/test_selfhost_docs.py`: the OAuth proxy replay section, the whole `AUTHZ_HEADING` family, `/auth/callback` in the README route test, the env lists naming `OAUTH_JWT_SIGNING_KEY`/`FASTMCP_HOME`, and the redirect-URI assertion. Prefer the route contract test of 3.8 over string pins. |
| P7 tests | `tests/selfhost/login/conftest.py` (the `entra_proxy` fixture); `test_entra_only_golden.py` (drop the `entra_proxy` parametrisation, `LOCAL_EXTRA`); `test_provider_settings.py` ~168-177 and `test_provider_startup.py` ~152 (the "refused under entra_proxy" cases); `test_config_summary.py`; `test_smoke_providers.py` (section markers). |

**Docs and deploy**
- `deploy/selfhost/README.md`:
  - The architecture diagram (`/consent /auth/callback OAuth proxy`, `fastmcp/` state).
  - Step 1 is rewritten to 2.5.
  - The proxy-log and disk-abuse text, and the optional `canvas-mcp-oauth` volume.
  - The section "MCP authorization: entra_proxy (default) or local" collapses into one "MCP authorization" section. Keep the staging checklist as an operator pre-flight.
  - The custody rows for upstream Entra tokens and `OAUTH_JWT_SIGNING_KEY`.
  - "How the OAuth proxy treats replayed codes".
  - "What stays outside the database: FastMCP's OAuth proxy state".
  - The rotation and troubleshooting rows. Rows marked "With `SELFHOST_AUTH_MODE=local`" become unconditional.
- `Dockerfile.selfhost`: remove `mkdir /data/fastmcp`, its chown/chmod (~67-74) and `ENV FASTMCP_HOME` (~90). Keep `FASTMCP_CHECK_FOR_UPDATES=off` and `FASTMCP_SHOW_SERVER_BANNER=false`.
- `deploy/selfhost/docker-compose.yml`: remove the optional `canvas-mcp-oauth` volume (~39-47, ~78-79).
- `deploy/selfhost/env.example`: remove the `SELFHOST_AUTH_MODE` block (~96-114), `OAUTH_JWT_SIGNING_KEY` (~155), `FASTMCP_HOME` (~301) and the school variables (section 5).
- `deploy/selfhost/setup-env.sh`: stop generating `OAUTH_JWT_SIGNING_KEY` and `FASTMCP_HOME`, and drop the school prompts (section 5).
- `nginx.conf.example` and `Caddyfile.example`: see 3.8.
- `CHANGELOG.md`: one "v1 consolidation (breaking)" entry under `[Unreleased]`.
- `proposals/selfhost-pilot/*` and `internal/issue-triage/*` are history for the removals and renames of this section: leave their content, or add a one-line "historical" header (handoff 6.8 adds a status banner to the Stage A files). D11 still applies to hostnames in `proposals/` (handoff 6.5).
- Neutral example hosts (D11) and the fork statement (D12): step 8.

**Smoke test and CI**
- `deploy/selfhost/smoke-test.sh`:
  - Header and `ENTRA_ENV`: drop `OAUTH_JWT_SIGNING_KEY`.
  - Sections (b)-(l) boot the own server.
  - (k) is rewritten for `/auth/*` (3.8).
  - (m)/(m2) become the default path.
  - (n) drops `SELFHOST_AUTH_MODE=bogus`, adds the removed-setting refusals, and keeps `ACCESS_TOKEN_TTL=1`.
  - `tests/selfhost/authz/test_smoke_script_contract.py` follows the markers.
- `.github/workflows/selfhost-image.yml` is unchanged: the smoke test still runs before any push, pinned by `tests/security/test_selfhost_workflow.py`.
- `canvas-mcp-testing.yml` line ~300 (PostgreSQL job file list) stays valid because `tests/test_multiuser_e2e.py` keeps its name. Update `.github/workflows/README.md` ~92 if it describes the proxy.

### 2.3 Startup behaviour when an old setting is present

`settings.py` gains a standard-library table:

```python
REMOVED_SETTINGS: dict[str, str]  # name -> replacement hint
```

`load_selfhost_settings()` adds one problem per name present in the environment. It collects them all, then raises `SelfhostConfigError`, the existing pattern. The process exits non-zero before binding a port. `--config` prints the same problems. A message names the setting and the replacement, never the value. An empty value counts as present: the variable must be deleted.

| Setting | Behaviour | Message (gist) |
|---|---|---|
| `SELFHOST_AUTH_MODE` (any value, including `local`) | refuse | "removed in v1: the built-in authorization server is the only mode; delete this variable" |
| `OAUTH_JWT_SIGNING_KEY` | refuse | "removed in v1: access tokens are signed with keys derived from CANVAS_TOKEN_KEYS; delete this secret" |
| `GRANT_STATUS_CACHE_S` | refuse | "removed in v1: grant status is read on every request" |
| `CANVAS_FEATURED_SCHOOLS` (D6) | refuse | "removed in v1: featured schools are managed only in Admin > Settings or with `token_admin schools`; a fresh install features none" |
| `CANVAS_SCHOOL_SEARCH` (D7) | refuse | "removed in v1: directory search is on by default; switch it in Admin > Settings or with `token_admin settings set schools.directory_search`" |
| `CANVAS_API_URL` (self-host mode only; upstream modes unchanged) | refuse | "removed in self-host mode: add the school with `token_admin schools add <host>` and turn directory search off for a single-school deployment" |
| `OIDC_<SLUG>_DISPLAY_NAME` (any slug) | refuse | "removed in v1: rename sign-in methods in Admin > Settings or with `token_admin providers rename`" |
| `ACCOUNT_UI` (D5, any value, including `react`) | refuse | "removed in v1: the React UI is the only account UI; delete this variable" |
| `ENTRA_API_SCOPE` (D9, also when `MCP_SCOPE` is set) | refuse | "renamed in v1: use MCP_SCOPE (same format, default Canvas.Access)" |
| `MCP_AUTH_MODE=entra-oauth` (D9) | refuse, in `settings.auth_mode()` | "renamed in v1: use MCP_AUTH_MODE=selfhost". This is a value check, not a `REMOVED_SETTINGS` entry: `auth_mode()` runs before the self-host settings are loaded, and it serves `--config` and the server start alike. |
| `FASTMCP_HOME` | **not refused**; canvas-mcp ignores it | It is FastMCP's own variable and harmless. It is removed from the image and the docs. |

`ACCOUNT_WEB_DIST` stays: it locates the bundle, and a missing or invalid bundle refuses startup (step 2).

The existing refusals (`CANVAS_API_TOKEN`, `MCP_ACCESS_KEYS`, `FASTMCP_SSRF_TRUST_PROXY`, `SELFHOST_STATE_BACKEND=redis`, and so on) stay.

### 2.4 Behaviour changes to accept

1. **An account is created only by a sign-in ceremony** (`/auth/login...`), with one operator exception: `token_admin disable` for someone who has not signed in yet creates a disabled account (`create_operator_account`). Today the proxy could create one on the first Entra access token reaching `/mcp`. The consent flow already required a sign-in.
2. **Role changes made in Entra reach the server only at the next sign-in, or after `MAX_UPSTREAM_AUTH_AGE`** (14 days). Access tokens carry no roles. The offboarding rule is "disable in the panel first, then remove in Entra" (handoff 6.12).
3. **There is no fallback mode.** The README staging checklist stays as a pre-flight, and live verification (handoff 6.12) becomes a release gate for the first v1 tag.
4. **The Entra ceremony moves to the server-side flow record**, a `login_states` row with `kind='login_flow'` plus `__Host-cmcp_flow`. The `__Host-cmcp_login` cookie disappears.
5. **Revocation, disable and `rotate-jwt-key` act at the next request on every process.** Today they take up to 30 s, and only in the same process.

### 2.5 Simplified Entra app registration

The server signs users in with the authorization code flow:
- PKCE S256, `nonce`, `state`, `prompt=select_account`;
- `scope=openid profile`, `response_type=code`, `response_mode=query`.

It redeems the code with the client secret at `https://login.microsoftonline.com/<tenant guid>/oauth2/v2.0/token`. It verifies the ID token against the tenant JWKS: issuer `https://login.microsoftonline.com/<tid>/v2.0`, audience equal to the client id, `nonce`, `iat`/`exp` and `tid`. The subject is `oid`. It never uses an Entra access or refresh token and never calls Graph.

| Item | v1 | Reason and source |
|---|---|---|
| Platform and redirect URI | **Web**, exactly one URI: `https://<PUBLIC_BASE_URL host>/auth/callback/entra`. Delete the old `/auth/callback` and `/account/callback` entries. | Entra requires redirect URIs to start with `https` (localhost excepted), treats them as case-sensitive, ignores the port only for localhost, allows at most 256 characters, and does not support the special characters `! $ ' ( ) , ;` or internationalised domain names. Wildcard URIs are possible on work-or-school-only registrations via the manifest; never add one: https://learn.microsoft.com/en-us/entra/identity-platform/reply-url |
| Implicit grant and hybrid flows (ID tokens, access tokens) | both **off** | The code flow receives the ID token from the token endpoint: https://learn.microsoft.com/en-us/entra/identity-platform/v2-protocols-oidc , https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow |
| Supported account types | **Single tenant** (`AzureADMyOrg`) | B2B guests are user objects (`userType` Guest, not members) in your directory. A guest signing in to this app gets a token for your tenant: `tid` is "the tenant that the user is signing in to", and `oid` is per tenant. The authorize request must name your tenant GUID for guests. The code refuses `common`, `organizations` and `consumers` (`settings._RESERVED_TENANTS`). https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference , https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow |
| Credentials | client secret, with an expiry reminder. A certificate (`client_assertion`) is out of scope. | Confidential web client: https://learn.microsoft.com/en-us/entra/identity-platform/v2-oauth2-auth-code-flow |
| App roles | `Canvas.User` and `Canvas.Owner`, member types Users/Groups | Assigned roles appear in the ID token `roles` claim: https://learn.microsoft.com/en-us/entra/identity-platform/howto-add-app-roles-in-apps |
| Enterprise application, "Assignment required?" | **Yes** | Unassigned users and guests get no token. The one documented exception is the Global Administrator role, which can sign in whatever the setting says; such a user carries no `roles` claim unless assigned, so the server's `ENTRA_REQUIRED_ROLE` check still refuses them. https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/application-properties |
| Users and groups | Friends (B2B guests) get `Canvas.User`; the owner gets `Canvas.Owner`. Group assignment needs Entra ID P1/P2 and does not cascade to nested groups. | https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/assign-user-or-group-access-portal , https://learn.microsoft.com/en-us/entra/external-id/what-is-b2b |
| Admin consent | Grant tenant-wide consent once for the default `User.Read` / `openid profile` | Avoids "approval required" prompts for assigned guests: https://learn.microsoft.com/en-us/entra/identity/enterprise-apps/user-admin-consent-overview |
| Expose an API, Application ID URI, `Canvas.Access` scope | **delete** | Only the proxy requested Entra access tokens. The MCP scope is the server's own string. |
| `requestedAccessTokenVersion` | leave the default | It concerns access tokens for this app as an API. The v2.0 endpoint already yields v2.0 ID tokens. https://learn.microsoft.com/en-us/entra/identity-platform/reference-microsoft-graph-app-manifest |
| API permissions | none beyond the default; remove the self-referencing `Canvas.Access`, `offline_access` and any Graph list | `openid` and `profile` are OpenID Connect scopes requested in the authorize request. The `profile` scope is required to receive `oid`, `name` and `preferred_username`: https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference , https://learn.microsoft.com/en-us/entra/identity-platform/scopes-oidc |
| `groups` claim | only if `ACCESS_RULES` uses `entra:group:<id>`; then prefer "groups assigned to the application" | More than 200 groups (JWT) replaces the claim with an overage reference and the rule simply does not match: https://learn.microsoft.com/en-us/entra/identity-platform/optional-claims , https://learn.microsoft.com/en-us/entra/identity-platform/id-token-claims-reference |
| Optional claims (`email`, `upn`), front-channel logout URL | no | `preferred_username` is display-only; sign-out is local |

Inviting a friend:
1. Invite the friend as an external user.
2. Assign `Canvas.User` on the enterprise application.
3. The friend opens `https://<host>/auth/login` and signs in with their home account.

Their `tid` is the owner's tenant, so the existing tenant check holds. `#EXT#` in `preferred_username` is display-only.

**Environment for Entra:**
- unchanged: `ENTRA_TENANT_ID` (the owner's own tenant GUID), `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_REQUIRED_ROLE`, `ENTRA_OWNER_ROLE`;
- renamed (D9): `ENTRA_API_SCOPE` becomes `MCP_SCOPE`. It is the server's own MCP scope string, not an Entra setting; the old name refuses startup (2.3).

The README "Step 1" becomes six short sub-steps: register, redirect URI, secret, roles, assignment and guests, consent.

### 2.6 What changes for P7

v1 starts after P7 is merged (handoff 6.1 [B0]). On top of P7:

- **Config and wiring**
  - `login/config.py`: remove the refusal of non-Entra providers when `authz_mode != "local"` (~269-274) and the docstring line. `parse_login_providers(...)` loses `authz_mode`, and `settings.py` stops passing it.
  - `app.py`: `build_login_runtime(flow_store=runtime.authz.txns)` is unconditional. Remove `owners=None if local else runtime.store`.
  - `request_context.py`, `token_store.demote_owner(listed_providers=...)`: deleted with the proxy identity path. Also delete the `identity.py` comment ~57 and the cache `discard` after unlink.
- **Routes**
  - Rename every start and callback constant to the v1 routes through the new `selfhost/routes.py`: `ENTRA_START_PATH`, `ENTRA_ALIAS_START_PATH`, `ENTRA_CALLBACK_PATH`, `GOOGLE_*_PATH`, `GITHUB_*_PATH`, the `oidc.py` `start_path`/`callback_path`, `account_web.ENTRA_LOGIN_PATH`, `ACCOUNT_CALLBACK_PATH` and `_LOGIN_PATH`. Registration moves from static per-provider routes (`ExternalSignIn.route_table`) to the parameterised routes of 3.3.
- **Entra on the flow engine**
  - Entra gets a provider profile in `login/entra.py` on `login/flows.py`: issuer, `tid` check, `roles`/`groups` via `entra_external_claims`, and `oid` as subject.
  - The sealed `__Host-cmcp_login` ceremony in `account_web.py` is deleted.
  - Linking Entra uses the same callback; the stored `FlowRecord.pp='link'` distinguishes the purpose.
- **Data**
  - `meta['login_providers']` is replaced by the `login_providers` table (4.3.3).
  - `TokenStore.record_login_providers` becomes the startup reconcile.
  - `recorded_login_providers` and `token_admin._listed_providers` read `login_providers.configured`. Keep the rule P7 `53b86dd` implements for finding F2 (an owner counts as usable only under providers in both the recorded list and the environment list, and the record stands when they share none), or whatever B0 review changes it to; only the storage changes.
  - The usable-owner SQL (`usable_owner_ids`) joins `login_providers` on `configured` (4.5.2). The Python twin `accounts.owner_is_usable` and its equality test stay.
  - `link_identity` keeps P7's order: under the governance lock, the pre-checks (`identity_in_use`, `provider_already_linked`, `access_denied`) are authoritative and write the refusal audit row; `count_for_provider` becomes a probe of `uq_external_identities_account_provider`. The unique constraints stay a second barrier that fails closed: an `IntegrityError` propagates as `StoreUnavailable`. Do not map it to `LINK_PROVIDER_TAKEN`: on PostgreSQL the error aborts the transaction, so the refusal audit could not be written in it. `unlink_identity` is unchanged apart from named rows.
  - `IdentityRepo` returns named rows with uuid ids. The "append `id` to the row tuple" problem disappears.
- **Display names**: `ProviderDisplay` names become defaults only. Effective names come from `login_providers.display_name` (section 5). The P7 README section "Sign-in providers" and its redirect-URI recipes move to `/auth/callback/...`.

---

## 3. Route map v1

### 3.1 Namespaces

| Prefix | Purpose | Responses |
|---|---|---|
| `/auth/*` | Browser ceremonies that leave for an identity provider and come back | 302/303 redirects only; GET only |
| `/account/*` | The React single-page app | HTML and static assets |
| `/api/v1/*` | The app's JSON API: session cookie, CSRF header, `Origin` check, never CORS | JSON, `no-store` |
| `/.well-known/*`, `/authorize`, `/token`, `/register`, `/revoke`, `/mcp` | Fixed by the MCP SDK, FastMCP and RFC 8414/9728 | per spec |
| `/healthz` | Liveness | text |

### 3.2 Complete route table

Nothing else is served. `/` stays a 404.

**Protocol (fixed)**

| Methods | Path | Purpose | Handler |
|---|---|---|---|
| GET HEAD OPTIONS | `/.well-known/oauth-authorization-server` | RFC 8414 metadata, with `authorization_response_iss_parameter_supported: true` | `authz/server.py` `_metadata_route` |
| GET HEAD OPTIONS | `/.well-known/oauth-protected-resource/mcp` | RFC 9728 metadata | FastMCP / MCP SDK, built via `authz/server.py` |
| GET POST (HEAD metered then 405 in `edge_guard.py`) | `/authorize` | Authorization request. A valid one becomes a 302 to `{base}/auth/login?txn=<id>` and sets `__Host-cmcp_bind`. | `authz/server.py` `_authorize_route` |
| POST OPTIONS | `/token` | Code exchange and refresh, with the RFC 8707 resource check | `authz/server.py` `_token_route` |
| POST OPTIONS | `/register` | Dynamic client registration | MCP SDK behind `_StoreGuard` |
| POST OPTIONS | `/revoke` | RFC 7009 revocation | `authz/server.py` `_revoke_route` |
| POST DELETE | `/mcp` | Streamable HTTP (stateless) | FastMCP, behind `request_context.py` `SelfhostRequestContextMiddleware` |
| GET HEAD | `/healthz` | "ok", no database access | `app.py` `install_selfhost` |

**Sign-in ceremonies.** The handlers live in the new `selfhost/login/routes.py`. The provider is resolved per request through `login/registry.py`, and paths come from `selfhost/routes.py`.

| Methods | Path | Purpose |
|---|---|---|
| GET | `/auth/login` | Dispatcher. Validates `txn`, `return_to` and `reauth`. With one configured provider: 303 to its start, query kept. With several: 303 to `/account/sign-in?...`. With a bad `txn`: 303 to `/account/sign-in?error=authorization_invalid`. |
| GET | `/auth/login/{provider}` | Start, for `provider` in `entra`, `google`, `github`. Writes a `login_flow` record and sets `__Host-cmcp_flow`. |
| GET | `/auth/login/oidc/{slug}` | Start for a generic OIDC provider |
| GET | `/auth/callback/{provider}` | The redirect URI registered at `entra`, `google` or `github` |
| GET | `/auth/callback/oidc/{slug}` | The redirect URI of a generic provider |
| (reserved, not registered) | `/auth/connect/canvas/{host}`, `/auth/callback/canvas/{host}` | Canvas OAuth (Developer Key). Per-host callbacks, because Canvas sends neither `iss` nor an ID token. |

**Single-page app** (`selfhost/account_spa.py`)

| Methods | Path | Purpose |
|---|---|---|
| GET HEAD | `/account/assets/{name:path}` | Immutable bundle assets |
| GET HEAD | `/account/favicon.svg` | Icon |
| GET HEAD | `/account`, `/account/`, `/account/{path:path}` | `index.html`, `no-store`, registered last |

Client routes (basename `/account`):
- `sign-in`, index, `consent`, `token`, `write-tools`, `connected-apps`, `sign-in-methods`, `activity`;
- `admin`, `admin/enrollments`, `admin/audit`, and the new `admin/settings`.

**JSON API** (`selfhost/account_api.py`, prefix `/api/v1`). Access levels are those of `route_table()`. Owner routes run the full owner-action pipeline (handoff 3.3).

| Methods | Path | Access |
|---|---|---|
| GET | `/providers` | public; effective display names |
| GET | `/me` | session |
| GET PUT DELETE | `/me/canvas-token` | active; PUT requires the custody acknowledgement (D10, step 6b) |
| POST | `/me/canvas-token/acknowledge` | active (new, D10): re-acknowledge a changed notice without re-entering the token |
| POST | `/me/canvas-token/recheck` | active |
| GET | `/me/schools` | active |
| GET | `/me/schools/search` | active, CSRF |
| GET PUT DELETE | `/me/write-tools` | active (enabling needs a fresh sign-in) |
| GET | `/me/login-history` | session (today `access="session"`) |
| PUT | `/me/ui-locale` | session (cookie only) |
| POST | `/session/logout` | session |
| GET POST | `/consent` | session (today `access="session"`) |
| GET | `/me/grants` | active |
| DELETE | `/me/grants/{id}` | active |
| GET | `/me/identities` | active; `not_found` unless 2 or more providers are configured (P7 rule) |
| POST | `/me/identities/link` | active; starts the flow (purpose `link`); access rules unchanged from P7 |
| DELETE | `/me/identities/{id}` | active |
| GET | `/admin/accounts?cursor=&limit=` | owner; keyset paged (4.11) |
| POST | `/admin/accounts/{id}/approve`, `/deny`, `/disable`, `/enable` | owner |
| GET | `/admin/accounts/{id}/grants` | owner |
| DELETE | `/admin/grants/{id}` | owner |
| GET | `/admin/enrollments?cursor=&limit=` | owner; `{id}` below is now the **credential id** |
| DELETE | `/admin/enrollments/{id}` | owner |
| POST | `/admin/enrollments/{id}/mark-invalid` | owner |
| GET | `/admin/audit?cursor=&limit=&account=` | owner |
| DELETE | `/admin/identities/{id}` | owner |
| GET | `/admin/settings` | owner (new, section 5) |
| PUT | `/admin/settings/sign-in-methods` | owner (new) |
| PUT | `/admin/settings/schools` | owner (new) |
| POST | `/admin/settings/schools/check` | owner, rate-limited (new) |
| PUT | `/admin/settings/directory-search` | owner (new) |

Unknown `/api/v1/*` paths return a JSON 404 and never reach the SPA.

### 3.3 Rules for `/auth/*`

- **Methods.** GET only. `HEAD` is refused with 405 in `edge_guard.py`, because a HEAD must not create a flow record (the same treatment as `HEAD /authorize`). Any other method gets 405 with `Allow: GET`. Only `response_mode=query` is used; `form_post` is out of scope because `SameSite=Lax` cookies are not sent on a cross-site POST.
- **Parameterised routes.** The four route patterns are registered once. The handler asks the registry for a configured provider. An unknown or unconfigured key returns 404 before any state is written. This also lets a future database-stored provider configuration work without re-registering routes.
- **Route key vs provider id.**
  - Route keys are `entra`, `google`, `github` and `oidc/<slug>`.
  - Stored `provider_id` values are `entra`, `google`, `github` and `oidc:<slug>`; a colon in a redirect URI is avoided.
  - `canvas` is a reserved route key.
  - The `oidc/` sub-namespace means a generic provider can never shadow a built-in one.
- **Cookies.**
  - `__Host-cmcp_flow` (ceremony), `__Host-cmcp_session`, `__Host-cmcp_bind` (authorization transaction). All are `Path=/`, so moving paths changes nothing for them.
  - The language cookie `canvas_mcp_lang` changes to `Path=/`, because the API leaves `/account`.
- **Mix-up defence.** Per RFC 9700 section 4.4.2, the issuer of each request is stored and bound to the browser. `FlowRecord.p` is stored server-side, and `FlowCookie.provider_id` is in the sealed cookie. The callback refuses when the record's provider differs from the provider named by the path.
- **Callback order** (P7 `flows.py`, now including Entra):
  1. Delete the flow cookie on every response.
  2. A provider `error` ends the ceremony.
  3. Compare `state` with the cookie in constant time.
  4. Pop the record once. The pop is bound to the cookie secret, so replay, another browser, expiry and unknown state all look the same.
  5. Compare the record's provider with the path's provider.
  6. Compare `iss` when the provider sends it or promises it (RFC 9207 section 2.4).
  7. Compare `record.ru` with the current redirect URI.
  8. Exchange the code and validate the ID token (`iss`, `aud`, `nonce`, `exp`).
- **Outcomes.**
  - Success: 303 to `/account/consent?txn=...`, a sanitised `return_to`, or `/account/`.
  - Failure: 303 to `/account/sign-in?error=<code>`, or `/account/sign-in-methods?error=<code>` for a link.
  - The codes are the existing closed set: `state_invalid`, `provider_error`, `sign_in_incomplete`, `sign_in_unverified`, the deny codes, `rate_limited`, `token_store_unavailable`.
- **`return_to`** must start with `/account/`. It is refused when it starts with `/api/` or `/auth/` (replacing the three old forbidden prefixes).
- **Headers.** `Cache-Control: no-store` and `Referrer-Policy: no-referrer` on every `/auth/*` response.
- **Rate limits.** The per-provider process bucket (P7 `START_BURST`) now covers Entra too. Per-IP limits stay at the reverse proxy.

### 3.4 Per-provider callbacks and the RFC 9700 basis

RFC 9700 section 2.1 makes a mix-up defence REQUIRED for a client that can talk to more than one authorization server; section 4.4.2 waives it only for a single server. With Google, GitHub or OIDC enabled, this server is such a client.

Section 4.4.2.1 prefers issuer identification: the RFC 9207 `iss` response parameter, or the ID-token `iss`. Section 4.4.2.2 is the alternative, which states that "clients MUST use a distinct redirection URI for each issuer they interact with". Section 4.4.2.2 adds that this defence should be used only when the other options are unavailable.

Why per-provider callbacks are still right here:
- **GitHub** (plain OAuth 2.0) and a future **Canvas OAuth** send neither `iss` nor an ID token. For them the distinct redirect URI, plus the cookie-bound record, is the only issuer binding available.
- **Entra.** Microsoft documents no `iss` authorization-response parameter. The ID-token `iss` is checked, but only after the code has been sent to the token endpoint.
- We use both defences where both exist. RFC 9700 section 2.1 also tells authorization servers to use exact string matching of redirect URIs (localhost ports excepted); Entra, Google and GitHub do, except for the wildcard options noted here and in 2.5. GitHub OAuth apps created with a single callback before 2026-08-03 have wildcard matching on by default; **turn it off**.

**Entra: bare `/auth/callback` or `/auth/callback/entra`? Decision: `/auth/callback/entra`.**

| | Bare `/auth/callback` | `/auth/callback/entra` (chosen) |
|---|---|---|
| Matches the owner's wording | literally | `/auth/callback/` is the callback namespace |
| One shape for every provider | no; Entra is a special case in the router, nginx, docs, tests, `token_admin` and the registry | yes |
| RFC 9700 section 4.4.2.2 | holds only while no other provider shares the URI | holds by construction |
| A second Entra tenant later | needs a rule for which tenant owns the bare path | `entra-<slug>` fits |
| Azure portal cost | one URI | one URI (nothing is deployed, so nothing is saved by reuse) |
| Stale registration risk | the old proxy registration of `/auth/callback` would silently keep matching | an old registration cannot match |

The bare `/auth/callback` is **not served** (404). Do not add an alias: it would reintroduce a shared URI.

### 3.5 `/account/api` becomes `/api/v1`

Decision: move.
- The SPA catch-all no longer shares a prefix with machine routes. The `/account` rule becomes "everything except `assets/` and `favicon.svg` is `index.html`".
- Proxy, WAF, CSP, cache and rate-limit rules become per-prefix.
- `return_to` rules shrink.
- The version segment lets a later release serve an old shape to a browser tab that still runs the old bundle.

Cost: one constant (`API_PREFIX` in `routes.py`), `web/src/api/client.ts` `API_BASE_URL`, `web/vite.config.ts`, the parity and contract tests, and the docs. Nothing is deployed, so there are no aliases.

### 3.6 Collision check

- The MCP SDK `mcp/server/auth/routes.py` serves `/authorize`, `/token`, `/register`, `/revoke` and `/.well-known/oauth-authorization-server`, and its `create_protected_resource_routes` serves `/.well-known/oauth-protected-resource{resource path}` (RFC 9728, `/mcp` here). FastMCP serves `/mcp`.
- The only `/auth/...` paths in the installed `fastmcp`/`mcp` (fastmcp 4.0.10, mcp 2.2.0) are the `redirect_path="/auth/callback"` defaults of the OAuth proxy (`fastmcp/server/auth/oauth_proxy/proxy.py`) and of the provider classes built on it (`providers/azure.py`, `github.py`, `google.py` and others), none of which is instantiated after `entra_proxy` is deleted. `providers/supabase.py` mentions `/auth/v1`, which is an upstream Supabase URL, not a route. FastMCP's server serves nothing under `/api`; the `/api/launch` and `/api/logs*` routes belong to the dev-only `apps_dev` CLI (`fastmcp/cli/apps_dev.py`).
- Starlette matches whole segments, so `/auth/{...}` cannot match `/authorize`. In nginx, however, `location ^~ /auth` without the trailing slash **does** match `/authorize`: always write `^~ /auth/`.
- `EXPECTED_ROUTES` stays exact for the authorization-server routes. A new route-table test pins the full v1 table above.

### 3.7 Old to new

| Today | v1 |
|---|---|
| `/account/login` | `/auth/login` |
| `/account/login/entra` (P7) | `/auth/login/entra` |
| `/account/login/{google,github}`, `/account/login/oidc/{slug}` | `/auth/login/...` |
| `/account/callback` (Entra) | `/auth/callback/entra` |
| `/account/callback/{google,github}`, `/account/callback/oidc/{slug}` | `/auth/callback/...` |
| `/auth/callback`, `/consent` (`entra_proxy`) | deleted (404) |
| `/account/api/*` | `/api/v1/*` |
| `/account/identities/link` and other legacy form POSTs | deleted with the legacy UI (D5, step 2) |
| SPA pages under `/account/*` | unchanged; `admin/settings` added |

### 3.8 What else changes

- **`selfhost/routes.py`** (new, standard library only) is the single source of path builders:
  - `AUTH_LOGIN`, `auth_login(provider)`, `auth_callback(provider)`, `API_PREFIX`, `ACCOUNT_PREFIX`, `SIGN_IN_PAGE`, `consent_page(txn)`, `redirect_uri(base, provider)`.
  - It feeds the router, the registry, `authz/server.py` (both copies of the login prefix, ~290 and ~465, including the `__Host-cmcp_bind` gating), `token_admin` (displayed callback URLs, ~920), `--config` and the tests.
- **Route contract test** (`tests/selfhost/test_route_contract.py`, new). It parses `deploy/selfhost/nginx.conf.example`, `Caddyfile.example`, `smoke-test.sh`, the README route list, `web/src/api/client.ts`, `web/src/api/endpoints.ts`, `web/vite.config.ts` and `web/src/utils/returnTo.ts`. It fails when any of them names a path that `routes.py` does not define. It replaces most string pins in `tests/test_selfhost_docs.py`.
- **nginx** (`nginx.conf.example`):
  - Replace the `^~ /account/login` and `^~ /account/callback` blocks with `location ^~ /auth/ { limit_req zone=canvas_signin burst=10 nodelay; ... }`.
  - Optionally add `location ^~ /api/ { ... }` with its own zone.
  - Keep the exact `= /authorize`, `= /token`, `= /register`, `= /revoke` blocks and the `canvas_safe` log format.
  - Drop the "entra_proxy `/token`" note and the `/auth/callback?code=` comments.
- **Caddy**:
  - The matcher becomes `path /auth/*`.
  - Keep the log filter that blanks `code`, `state`, `txn`, `session_state`, `id_token` and `access_token`.
  - Update the comments.
- **SPA** (`web/`):
  - `src/api/client.ts` `API_BASE_URL='/api/v1'`.
  - `src/api/endpoints.ts` `LOGIN_PATH='/auth/login'`.
  - `src/utils/appRedirect.ts` `consentLoginPath()` builds `/auth/login?txn=`.
  - `src/utils/returnTo.ts` `FORBIDDEN_PREFIXES=['/api/','/auth/']`.
  - `vite.config.ts`: the dev proxy entries become `/api` and `/auth`, and the mock-login regex changes.
  - `src/dev/mockServer.ts`: `start_url`, the prefix and the new admin settings endpoints.
  - `src/utils/providerRedirect.ts` (P7).
  - Contract and test files: `contract.ts` (the `{id}` of enrollments becomes the credential id), `endpoints.test.ts`, `SignInView.test.tsx`, `ConsentView.test.tsx`, `WriteToolsView.test.tsx`, `AdminPages.test.tsx`, `returnTo.test.ts`.
  - `web/README.md`.
- **Smoke test** (`deploy/selfhost/smoke-test.sh`):
  - (k) `GET /auth/login/entra`: 302 to `https://login.microsoftonline.com/<tid>/oauth2/v2.0/authorize`, with `redirect_uri=<base>/auth/callback/entra`, and sets `__Host-cmcp_flow`.
  - `GET /auth/login` with one provider: 303 to `/auth/login/entra`.
  - `GET /auth/login?txn=bogus`: 303 to `/account/sign-in?error=authorization_invalid`.
  - `HEAD /auth/login/entra`: 405.
  - `GET /api/v1/providers`: 200 JSON.
  - 404 for the bare `/auth/callback`, for `/consent` and for `/.well-known/openid-configuration`.
  - The removed-setting refusals from 2.3 (at least `SELFHOST_AUTH_MODE` and `CANVAS_FEATURED_SCHOOLS`).

---

## 4. Database v1

### 4.1 Principles

1. **Identifiers.**
   - Entities (accounts, identities, credentials, grants, Canvas OAuth apps) use **UUIDv7 from the application**, via `new_id()`.
     - It is needed before the INSERT: for the AAD and for multi-table writes.
     - PostgreSQL 16/17 and SQLite cannot mint v7.
     - `new_id()` uses `uuid.uuid7()` on Python 3.14+, with an RFC 9562 counter-method fallback for 3.11-3.13 (`requires-python >=3.11`).
   - Externally minted keys stay text:
     - DCR client ids are minted by the MCP SDK; no format is assumed.
     - CIMD clients are keyed by URL.
     - Provider ids and hosts are text.
   - Secret-derived keys are a 32-byte SHA-256 value in binary: codes, refresh tokens, login states, web sessions. `hash_secret()` returns `bytes`.
   - History rows use `bigint` identity.
2. **Time** is `bigint` Unix seconds UTC. Every comparison uses the injected clock in Python, never SQL `now()`. Several instances need NTP; the tightest window is the 30 s refresh grace.
3. **Flags** are `boolean` on PostgreSQL and `INTEGER` with `CHECK (x IN (0,1))` on SQLite (STRICT forbids `BOOLEAN`).
4. **JSON** (`jsonb` on PostgreSQL, `TEXT` on SQLite) is used only for documents written and read whole and never filtered, joined or indexed: `oauth_clients.info`, `cimd_clients.doc`, `audit_log.detail`, `settings.value`, and the reserved `login_providers.config`. If SQL needs it, it is a column or a child table.
5. **Vocabularies.**
   - `CHECK (col IN (...))` only on closed state machines: `accounts.status`, `accounts.role`, `canvas_credentials.kind` and `status`, `oauth_grants.client_kind`, `oauth_codes.client_kind`, `auth_events.outcome`, `audit_log.actor_kind`, `login_providers.config_source`.
   - Every other vocabulary gets at most a length CHECK, plus a registry in `selfhost/db/vocab.py`. Each repo validates on write, and a test asserts the registry matches the code constants: `role_source`, `admitted_via`, `disabled_reason`, `invalid_reason`, `revoked_reason`, `auth_events.surface` and `reason`, `audit_log.action` and `target_kind`, `login_providers.protocol`, `canvas_schools.origin`, `account_write_tools.enabled_via`, `login_states.kind`.
   - There are no native enums and no lookup tables.
6. **Foreign keys.**
   - Declared on every ownership edge. Every FK child column has an index whose leading column is the FK column.
   - None on history (`auth_events`, `audit_log`), tombstone pointers (`oauth_codes.grant_id`), polymorphic references (`oauth_grants.client_id`) or actor columns (`*_by`).
   - SQLite sets `PRAGMA foreign_keys=ON` per connection, asserted.
7. **Collation.** Externally minted key text is `COLLATE "C"` on PostgreSQL; on SQLite it is BINARY. Byte order is identical, and native `uuid` sorts byte-wise in the same order as lower-case hex text, so keyset cursors agree on both backends.
8. **One SQLAlchemy Core definition renders both dialects.** All dialect differences live in `selfhost/db/types.py`.
   - Naming convention:
     ```
     pk_%(table_name)s
     uq_%(table_name)s_%(column_0_N_name)s
     ix_%(table_name)s_%(column_0_N_name)s
     ck_%(table_name)s_%(constraint_name)s      -- every CheckConstraint needs an explicit name=
     fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s
     ```
   - Every SQLite table is STRICT. WITHOUT ROWID is used only for narrow rows with non-integer keys.
9. **No server-computed defaults** (`now()`, `gen_random_uuid()`). Constant `server_default`s only.
10. **Rows are read by name** (`row._mapping`), into frozen dataclasses. Positional tuples (`account[16]`, `row[:-1]`, `AuthEvent(*tuple(r))`) are forbidden, and a lint test enforces it.
11. **`Table.info` is the single registry of table policy**:
    - `lifecycle`: `state`, `durable`, `history`, `ephemeral` or `reserved`;
    - `sealed`: the encrypted columns and their AAD builder;
    - `cull`: the maintenance job.

    It replaces `TABLE_NAMES`, `COPIED_TABLES`, `EPHEMERAL_TABLES`, `_DATA_TABLES`, `_PROBE_TABLES` and `_IDENTITY_TABLES`.

### 4.2 Logical types (`selfhost/db/types.py`)

| Type | Python | PostgreSQL | SQLite (STRICT) | Implementation note |
|---|---|---|---|---|
| `Uuid` | `str`, canonical lower-case with hyphens | `uuid` | `TEXT` | `TypeDecorator(impl=Text)`; `load_dialect_impl` returns `postgresql.UUID(as_uuid=False)` on PostgreSQL. The bind canonicalises with `str(uuid.UUID(v))`. Not `sa.Uuid`, which stores 32 hex characters without hyphens on SQLite. `accounts.id` adds `CHECK (length(id) = 36)` on SQLite via `.ddl_if(dialect="sqlite")`. |
| `Key` | `str` | `text COLLATE "C"` | `TEXT` | `Text().with_variant(postgresql.TEXT(collation="C"), "postgresql")` |
| `Epoch` | `int` | `bigint` | `INTEGER` | `BigInteger().with_variant(sqlite.INTEGER(), "sqlite")`. Also used for counters. |
| `Flag` | `bool` | `boolean` | `INTEGER` plus the 0/1 CHECK | `TypeDecorator(impl=Boolean(create_constraint=False))` whose `load_dialect_impl` returns `Integer()` on SQLite (without it the column renders as `BOOLEAN`, which a STRICT table rejects: "unknown datatype"; checked on SQLite 3.50.4, and the same holds for `BIGINT`, `UUID` and `JSON`); the 0/1 `CheckConstraint` is added per column with `.ddl_if(dialect="sqlite")`; the bind does `bool(v)`. Needed because psycopg sends a Python `int` as an integer type, which a `boolean` column rejects (this matters in the SQLite-to-PostgreSQL copy). Default `server_default=sa.false()`. |
| `Bytes` | `bytes` | `bytea` | `BLOB` | `LargeBinary().with_variant(sqlite.BLOB(), "sqlite")` |
| `JsonDoc` | `dict`/`list` | `jsonb` | `TEXT` | On SQLite, `json.dumps(sort_keys=True, separators=(",",":"))` in and `json.loads` out. `\u0000` is refused before storing (jsonb rejects it). Size caps are enforced in Python. |
| identity id | `int` | `bigint GENERATED BY DEFAULT AS IDENTITY` | `INTEGER PRIMARY KEY AUTOINCREMENT` | The `Epoch` type plus `sa.Identity(always=False)` plus the table kwarg `sqlite_autoincrement=True`. The column type must render `INTEGER` on SQLite: a plain `BigInteger` renders `BIGINT NOT NULL PRIMARY KEY AUTOINCREMENT`, which SQLite rejects ("AUTOINCREMENT is only allowed on an INTEGER PRIMARY KEY"; checked with SQLAlchemy 2.1.4 and SQLite 3.50.4). BY DEFAULT, so transfer can insert ids and then `setval`. AUTOINCREMENT prevents id reuse in the audit log. SQLite reflection does not return `sqlite_autoincrement` (it does return `sqlite_strict`, `sqlite_with_rowid`, partial-index predicates and named CHECKs), so a batch rebuild must pass it explicitly (4.12). |

### 4.3 Tables

PostgreSQL DDL is the reference. The SQLite form follows 4.2 mechanically: `bigint`/`integer`/`smallint` become `INTEGER`, `uuid`/`text` become `TEXT`, `bytea` becomes `BLOB`, `jsonb` becomes `TEXT`, `boolean` becomes `INTEGER` plus a CHECK; `COLLATE "C"`, `WITH (...)` and `UNLOGGED` are dropped; every table is `STRICT`; and `WITHOUT ROWID` is added where marked.

The order below is FK order, which is also `metadata.sorted_tables`.

The DDL blocks were executed unchanged on PostgreSQL 16.2 (19 tables, 12 foreign keys, 41 indexes including primary keys) and, converted mechanically by the 4.2 rules, on SQLite 3.50.4 as STRICT tables with `foreign_keys=ON`; both run clean. Two notes on reading them: (1) the inline column `CHECK`s are shown unnamed, but in the SQLAlchemy definition every `CheckConstraint` carries `name=` so that the `ck_` convention of 4.1 applies (PostgreSQL's auto-names such as `canvas_schools_host_check` would otherwise appear in the golden DDL); (2) `WITHOUT ROWID` is also used for `server_state`, whose key is an integer but whose single row is narrow. The two `custody_*` columns of `canvas_credentials` (D10, 4.3.8) were added after that run; they are plain NOT NULL columns with one named CHECK and change no table, key or index count.

#### 4.3.1 `server_state`: typed server facts, read on every request

```sql
CREATE TABLE server_state (
  id                smallint PRIMARY KEY CHECK (id = 1),   -- singleton
  database_id       uuid   NOT NULL,          -- minted by the baseline; transfer refuses copying onto itself
  compat_floor      bigint NOT NULL,          -- lowest app SCHEMA_EPOCH allowed to run (4.12)
  jwt_epoch         bigint NOT NULL DEFAULT 0,-- was meta['mcp_jwt_epoch']
  settings_revision bigint NOT NULL DEFAULT 0,-- bumped in the same transaction as any settings, school or provider-name write
  created_at        bigint NOT NULL,
  updated_at        bigint NOT NULL
);  -- SQLite: WITHOUT ROWID, STRICT. lifecycle=state
```

- The baseline inserts the row.
- Bumps are `UPDATE server_state SET jwt_epoch = jwt_epoch + 1, updated_at = :now WHERE id = 1 RETURNING jwt_epoch`.
- The settings CAS is `UPDATE server_state SET settings_revision = settings_revision + 1, updated_at = :now WHERE id = 1 AND settings_revision = :expected RETURNING settings_revision`. Zero rows means `settings_conflict`.
- A new counter is `ADD COLUMN ... NOT NULL DEFAULT 0`, which is metadata-only on PostgreSQL and in-place on SQLite.

#### 4.3.2 `settings`: typed admin settings

```sql
CREATE TABLE settings (
  key        text COLLATE "C" PRIMARY KEY CHECK (length(key) BETWEEN 1 AND 64),
  value      jsonb  NOT NULL,     -- <= 8 KiB serialised (Python)
  updated_at bigint NOT NULL,
  updated_by uuid                 -- acting account; NULL = operator CLI
);  -- SQLite: WITHOUT ROWID. lifecycle=durable
```

- A row exists only after an edit; a missing row means the code default. Nothing is seeded. So a fresh database has directory search ON (`schools.directory_search` default `true`, D7) until the owner switches it off in the panel.
- Keys and types live in `SETTINGS` (5.1).
- An unknown key (written by a newer expand release) is ignored with a warning.

#### 4.3.3 `login_providers`: sign-in methods

This table holds the owner-edited display names and the reserved database-stored configuration.

```sql
CREATE TABLE login_providers (
  id                text COLLATE "C" PRIMARY KEY,        -- entra | google | github | oidc:<slug> (shape validated in code)
  protocol          text COLLATE "C" NOT NULL,           -- entra | google | github | oidc (registry)
  display_name      text CHECK (display_name IS NULL OR length(display_name) BETWEEN 1 AND 40),  -- NULL = built-in default; one name for English and Chinese (D8)
  sort_rank         integer NOT NULL DEFAULT 0,          -- reserved: owner-controlled button order (v1 uses env order)
  configured        boolean NOT NULL DEFAULT false,      -- listed by SELFHOST_LOGIN_PROVIDERS at the last start
  configured_at     bigint,
  config_source     text COLLATE "C" NOT NULL DEFAULT 'env' CHECK (config_source IN ('env','db')),  -- 'db' reserved
  config            jsonb,                               -- reserved: non-secret config (issuer, client id, scopes)
  secret_key_id     text COLLATE "C",                    -- reserved: sealed client secret
  secret_nonce      bytea CHECK (secret_nonce IS NULL OR length(secret_nonce) = 12),
  secret_ciphertext bytea,
  created_at bigint NOT NULL, updated_at bigint NOT NULL, updated_by uuid,
  CONSTRAINT ck_login_providers_secret_all_or_none CHECK (
    (secret_ciphertext IS NULL) = (secret_nonce IS NULL) AND (secret_nonce IS NULL) = (secret_key_id IS NULL))
);  -- lifecycle=durable, sealed={secret_*}
```

- **Startup reconcile** (governance tier, before the server accepts traffic):
  - Upsert every provider listed in the environment with `configured=true, configured_at=now`.
  - Set `configured=false` on `config_source='env'` rows no longer listed. Rows are never deleted, because identities reference them.
  - Never touch `display_name`.
  - Bump `settings_revision` when anything changed.
- **`ensure_provider_row(id, protocol)`** is an idempotent `INSERT ... ON CONFLICT DO NOTHING`. It is called by every path that inserts an identity, including the operator path (`create_operator_account`, used by `token_admin disable` for someone who has not signed in yet), so the FK never fails because the server has not started yet.
- No secondary index: there are at most a handful of rows.

#### 4.3.4 `canvas_schools`: school registry; featured is a rank

```sql
CREATE TABLE canvas_schools (
  host          text COLLATE "C" PRIMARY KEY CHECK (host = lower(host) AND length(host) BETWEEN 1 AND 253),
  display_name  text NOT NULL DEFAULT '' CHECK (length(display_name) <= 120),
  featured_rank integer CHECK (featured_rank IS NULL OR featured_rank >= 1),  -- NULL = not featured; none by default (D6)
  origin        text COLLATE "C" NOT NULL,          -- owner | directory | operator (registry; informational)
  allow_private boolean NOT NULL DEFAULT false,     -- operator-only (token_admin): skip the public-address guard
  created_at bigint NOT NULL, created_by uuid,
  updated_at bigint NOT NULL, updated_by uuid
);  -- SQLite: WITHOUT ROWID. lifecycle=durable
```

- The baseline inserts no row, and no code path, setting or environment variable creates a featured row: `featured_rank` is set only by the owner's panel save or by `token_admin schools add|move` (D6).
- Hosts are punycode ASCII after `parse_hostname`, so `lower()` is correct on both backends.
- `featured_rank` is not UNIQUE: SQLite has no deferrable unique constraints. Order by `(featured_rank, host)`, and rewrite all ranks in one transaction on reorder.
- At most 50 featured schools (`MAX_FEATURED`, code).
- Credential put upserts the school with `INSERT ... ON CONFLICT (host) DO UPDATE SET updated_at = excluded.updated_at` (`origin='directory'` for a directory pick; the update never changes `origin`, name or rank). **Not `DO NOTHING`:** `DO NOTHING` takes no lock on an existing row, so the orphan-school cull (4.8) can delete the row between the upsert and the credential insert, and the insert then fails its foreign key. Checked on PostgreSQL 16.2: with `DO NOTHING` the cull deleted the row and the put failed with `ForeignKeyViolation`; with `DO UPDATE` the put locked the row, the cull's re-checked predicate skipped it, and both succeeded. A cull that already holds the row makes `DO UPDATE` wait, then insert a fresh row.
- No secondary index: the snapshot loads `WHERE featured_rank IS NOT NULL OR allow_private`, from tens of rows.

#### 4.3.5 `accounts`

```sql
CREATE TABLE accounts (
  id                    uuid PRIMARY KEY,
  status                text COLLATE "C" NOT NULL CHECK (status IN ('pending','active','disabled')),
  role                  text COLLATE "C" NOT NULL DEFAULT 'user' CHECK (role IN ('user','owner')),
  role_source           text COLLATE "C",          -- rules | bootstrap | operator (registry)
  role_seen_at          bigint,                    -- last sign-in that confirmed the owner role (token_admin shows it)
  admitted_via          text COLLATE "C" NOT NULL, -- rules | open | approval | operator | bootstrap (registry)
  display_name          text NOT NULL DEFAULT '' CHECK (length(display_name) <= 200),
  created_at            bigint NOT NULL,
  updated_at            bigint NOT NULL,
  approved_at           bigint, approved_by uuid,  -- NULL actor with a time = operator/system; audit_log says which
  disabled_at           bigint, disabled_by uuid, disabled_reason text COLLATE "C",
  last_login_at         bigint,
  session_epoch         bigint NOT NULL DEFAULT 0, -- bound into every /account session and every code (P6)
  credential_generation bigint NOT NULL DEFAULT 0, -- replaces credential_generations; survives credential deletion
  write_tools_version   bigint NOT NULL DEFAULT 0, -- bumped with account_write_tools; keys the prefs cache
  CONSTRAINT ck_accounts_disabled_consistent CHECK ((status = 'disabled') = (disabled_at IS NOT NULL))
) WITH (fillfactor = 90);
CREATE INDEX ix_accounts_status_role ON accounts (status, role);
-- lifecycle=durable
```

- `ix_accounts_status_role` serves:
  - `count_active_owners` and the last-owner guard (index-only, 3 buffers);
  - `count_pending` and the pending-queue cap;
  - the usable-owner query;
  - the pending purge (status prefix plus a `created_at` filter).
- No `(created_at, id)` index: v7 ids are creation-ordered, so the admin list pages on `id`.
- Dropped: `contact_email` and `ui_locale`. They were never written; the locale lives in a cookie.
- Every status transition sets or clears `disabled_*` (today `enable` clears them and `deny` goes through `disable`); the CHECK enforces it. Port the insert at `db/repos.py` ~508 accordingly.
- **Generation invariant.** For every credential row, `canvas_credentials.generation = accounts.credential_generation`. Every bump is one helper, `bump_credential_generation(conn, account_id, *, writing: str | None = None) -> int`:
  ```sql
  UPDATE accounts SET credential_generation = credential_generation + 1, updated_at = :now
   WHERE id = :id RETURNING credential_generation;
  UPDATE canvas_credentials SET generation = :g
   WHERE account_id = :id AND (:writing IS NULL OR id <> :writing);
  ```
  `writing` is the id of the credential row the same transaction writes next; that write sets `generation = :g` itself and keeps its own `generation = :old` guard (automatic `mark_invalid`, 4.6). The first statement takes (or already holds) the account row lock, so it must run after any `oauth_codes` statement of the same transaction (lock order, 4.6). Callers: enroll, replace, delete, invalidate, restore, disable, enable, deny.
- `session_epoch` bumps use `UPDATE ... RETURNING session_epoch`, one statement instead of today's update then select.

#### 4.3.6 `external_identities`

```sql
CREATE TABLE external_identities (
  id             uuid PRIMARY KEY,                     -- v7; exposed by /me/identities/{id}
  account_id     uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  provider_id    text COLLATE "C" NOT NULL REFERENCES login_providers (id) ON DELETE RESTRICT,
  issuer         text COLLATE "C" NOT NULL CHECK (length(issuer) BETWEEN 1 AND 512),
  subject        text COLLATE "C" NOT NULL CHECK (length(subject) BETWEEN 1 AND 255),  -- Entra: oid
  username       text CHECK (username IS NULL OR length(username) <= 254),
  email          text CHECK (email IS NULL OR length(email) <= 320),
  email_verified boolean NOT NULL DEFAULT false,
  linked_at      bigint NOT NULL,
  last_login_at  bigint,
  CONSTRAINT uq_external_identities_subject UNIQUE (provider_id, issuer, subject),         -- sign-in lookup
  CONSTRAINT uq_external_identities_account_provider UNIQUE (account_id, provider_id)      -- P7 "one per provider"; also the FK index
);  -- lifecycle=durable
```

- The issuer stays in the key, so a changed tenant or issuer can never match an old subject. Entra's issuer is `https://login.microsoftonline.com/<tid>/v2.0`.
- Reserved for a future "link by verified e-mail" (refused today): an expand-step index `(lower(email)) WHERE email_verified`.

#### 4.3.7 `account_write_tools` (replaces the JSON columns of `user_tool_prefs`)

```sql
CREATE TABLE account_write_tools (
  account_id  uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  tool_name   text COLLATE "C" NOT NULL CHECK (length(tool_name) BETWEEN 1 AND 128),
  enabled_at  bigint NOT NULL,
  enabled_via text COLLATE "C" NOT NULL,   -- account_web | api | operator (registry)
  PRIMARY KEY (account_id, tool_name)
);  -- SQLite: WITHOUT ROWID. lifecycle=durable
```

- Read: a primary-key prefix range, only on a cache miss of `(account_id, write_tools_version)`.
- Write (governance tier):
  1. Lock the account row.
  2. Delete the account's rows and insert the new set.
  3. Bump `write_tools_version`.
  4. Write the audit row.
- Per-tool options later become columns.

#### 4.3.8 `canvas_oauth_apps` (reserved) and `canvas_credentials`

```sql
-- RESERVED: one institutional Developer Key per school. Created empty; nothing writes it in v1.
CREATE TABLE canvas_oauth_apps (
  id                uuid PRIMARY KEY,
  canvas_host       text COLLATE "C" NOT NULL REFERENCES canvas_schools (host) ON DELETE RESTRICT,
  client_id         text NOT NULL,
  scopes            text NOT NULL DEFAULT '',
  enabled           boolean NOT NULL DEFAULT false,
  secret_key_id     text COLLATE "C" NOT NULL,
  secret_nonce      bytea NOT NULL CHECK (length(secret_nonce) = 12),
  secret_ciphertext bytea NOT NULL CHECK (length(secret_ciphertext) >= 17),
  created_at bigint NOT NULL, updated_at bigint NOT NULL, updated_by uuid,
  CONSTRAINT uq_canvas_oauth_apps_canvas_host UNIQUE (canvas_host)
);  -- lifecycle=reserved, sealed={secret_*}

CREATE TABLE canvas_credentials (
  id                uuid PRIMARY KEY,
  account_id        uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  canvas_host       text COLLATE "C" NOT NULL REFERENCES canvas_schools (host) ON DELETE RESTRICT,
  kind              text COLLATE "C" NOT NULL CHECK (kind IN ('pat','oauth')),   -- 'oauth' reserved
  oauth_app_id      uuid REFERENCES canvas_oauth_apps (id) ON DELETE RESTRICT,
  is_primary        boolean NOT NULL,          -- the credential MCP requests use
  generation        bigint NOT NULL,           -- = accounts.credential_generation (invariant, 4.3.5)
  key_id            text COLLATE "C" NOT NULL, -- CANVAS_TOKEN_KEYS ring id
  nonce             bytea NOT NULL CHECK (length(nonce) = 12),
  ciphertext        bytea NOT NULL CHECK (length(ciphertext) >= 17),  -- pat: the token; oauth: sealed {access, refresh}
  canvas_user_id    text NOT NULL,
  canvas_user_name  text NOT NULL,
  status            text COLLATE "C" NOT NULL DEFAULT 'active' CHECK (status IN ('active','invalid')),
  invalid_reason    text COLLATE "C",
  invalid_since     bigint,
  created_at        bigint NOT NULL,
  updated_at        bigint NOT NULL,
  last_used_at      bigint,
  last_verified_at  bigint,
  expires_hint_at   bigint,                    -- pat: expiry the user noted
  access_expires_at bigint,                    -- reserved (oauth; Canvas access tokens live 1 h)
  scopes            text,                      -- reserved (oauth)
  custody_notice_version integer NOT NULL,     -- D10: custody notice version the user acknowledged for this token
  custody_ack_at    bigint NOT NULL,           -- D10: when (server clock)
  CONSTRAINT uq_canvas_credentials_account_host UNIQUE (account_id, canvas_host),
  CONSTRAINT ck_canvas_credentials_custody_notice_version CHECK (custody_notice_version >= 1),
  CONSTRAINT ck_canvas_credentials_oauth_app CHECK ((kind = 'oauth') = (oauth_app_id IS NOT NULL)),
  CONSTRAINT ck_canvas_credentials_invalid_since CHECK ((status = 'invalid') = (invalid_since IS NOT NULL))
) WITH (fillfactor = 90);
CREATE UNIQUE INDEX uq_canvas_credentials_primary ON canvas_credentials (account_id) WHERE is_primary;
CREATE INDEX ix_canvas_credentials_canvas_host ON canvas_credentials (canvas_host);
CREATE INDEX ix_canvas_credentials_oauth_app_id ON canvas_credentials (oauth_app_id) WHERE oauth_app_id IS NOT NULL;
-- lifecycle=durable, sealed={nonce, ciphertext}
```

- One credential per person per school; `kind` says how it was obtained. Switching kind replaces the row and bumps the generation.
- **v1 rule (code):** at most one credential per account. A put deletes the account's other rows and sets `is_primary=true` in the same transaction. Multiple schools later need only a selection rule.
- Partial index predicates are dialect-specific: `postgresql_where=t.c.is_primary` and `sqlite_where=t.c.is_primary == 1`. The hot read does not depend on the partial index, because the `uq_canvas_credentials_account_host` prefix serves it. The partial unique index exists to enforce one primary credential.
- `ix_canvas_credentials_canvas_host` serves "N people use this school" (the unfeature confirmation) and the `RESTRICT` check when a school row is culled.
- No `key_id` index. The start-up `DISTINCT key_id` and rotation read at most thousands of rows (0.1 ms per candidate A).
- No `last_used_at` index, so touches stay heap-only (HOT) updates on PostgreSQL.
- **Custody acknowledgement (D10).**
  - It lives on the credential row, not on `accounts`: the acknowledgement is a precondition of storing this token, so NOT NULL makes a credential without one unrepresentable on both backends, and a re-enrollment after a delete cannot inherit an old acknowledgement. The history of acknowledgements is the audit log (5.4, step 6b), which outlives the row.
  - `custody_notice_version` is compared with the code constant `CUSTODY_NOTICE_VERSION` (`selfhost/custody.py`, standard library). The CHECK only guards the range; a value above the current constant cannot be written, because the server writes only the current constant.
  - Every put (enroll, replace, kind switch) writes both columns from the request's acknowledgement; the acknowledge endpoint updates them on the existing row (step 6b). Key rotation, health writes, restore, transfer and touches never change them.
  - Not part of the AAD: the columns are not secret, and binding them would force a re-seal on every re-acknowledgement.
  - No index. The hot read takes the column from the row it already fetches; "credentials below the current version" (admin view, `token_admin db check`) scans at most thousands of rows.

#### 4.3.9 Authorization server

```sql
CREATE TABLE oauth_clients (                  -- DCR registrations; /register is unauthenticated
  id          text COLLATE "C" PRIMARY KEY,    -- minted by the MCP SDK
  info        jsonb  NOT NULL,
  client_name text   NOT NULL DEFAULT '',
  created_at  bigint NOT NULL,
  expires_at  bigint NOT NULL                  -- 30 d DCR TTL; extended to the grant expiry on first exchange
);
CREATE INDEX ix_oauth_clients_expires_at ON oauth_clients (expires_at);
-- lifecycle=durable

CREATE TABLE cimd_clients (                   -- client-metadata-document snapshots
  url           text COLLATE "C" PRIMARY KEY,
  doc           jsonb  NOT NULL,
  fetched_at    bigint NOT NULL,
  fresh_until   bigint NOT NULL,
  last_error_at bigint,
  last_error    text,
  CONSTRAINT ck_cimd_clients_fresh CHECK (fresh_until >= fetched_at)
);
CREATE INDEX ix_cimd_clients_fetched_at ON cimd_clients (fetched_at);
-- lifecycle=durable

CREATE TABLE oauth_grants (
  id               uuid PRIMARY KEY,           -- v7; the JWT "grant" claim
  account_id       uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  client_id        text COLLATE "C" NOT NULL,  -- DCR id or CIMD URL: polymorphic, no FK
  client_kind      text COLLATE "C" NOT NULL CHECK (client_kind IN ('dcr','cimd')),
  client_name      text NOT NULL DEFAULT '',
  client_host      text,
  redirect_host    text NOT NULL DEFAULT '',
  scopes           text NOT NULL,              -- space-separated (OAuth wire form)
  resource         text NOT NULL,
  created_at       bigint NOT NULL,
  last_used_at     bigint,
  upstream_auth_at bigint NOT NULL,
  expires_at       bigint NOT NULL,            -- absolute family cap (REFRESH_ABSOLUTE_TTL)
  revoked_at       bigint,
  revoked_reason   text COLLATE "C" CHECK (revoked_reason IS NULL OR length(revoked_reason) <= 64),
  revoked_by       uuid,
  CONSTRAINT ck_oauth_grants_revoked CHECK ((revoked_at IS NULL) = (revoked_reason IS NULL))
) WITH (fillfactor = 90);
CREATE INDEX ix_oauth_grants_account_id_id ON oauth_grants (account_id, id);   -- FK, /me/grants, revoke-all, hot read
CREATE INDEX ix_oauth_grants_expires_at    ON oauth_grants (expires_at);       -- cull
CREATE INDEX ix_oauth_grants_revoked_at    ON oauth_grants (revoked_at) WHERE revoked_at IS NOT NULL;  -- cull
-- lifecycle=durable

CREATE TABLE oauth_codes (
  code_hash             bytea PRIMARY KEY CHECK (length(code_hash) = 32),
  client_id             text COLLATE "C" NOT NULL,
  account_id            uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  redirect_uri          text NOT NULL,
  redirect_uri_explicit boolean NOT NULL,
  code_challenge        text NOT NULL,
  scopes                text NOT NULL,
  resource              text NOT NULL,
  client_kind           text COLLATE "C" NOT NULL CHECK (client_kind IN ('dcr','cimd')),
  client_name           text NOT NULL DEFAULT '',
  client_host           text,
  redirect_host         text NOT NULL DEFAULT '',
  upstream_auth_at      bigint NOT NULL,
  session_epoch         bigint NOT NULL,       -- P6 binding, unchanged
  created_at            bigint NOT NULL,
  expires_at            bigint NOT NULL,
  consumed_at           bigint,
  grant_id              uuid,                  -- tombstone pointer, no FK
  grace_replays         integer NOT NULL DEFAULT 0 CHECK (grace_replays >= 0)
);
CREATE INDEX ix_oauth_codes_account_id ON oauth_codes (account_id);   -- FK + delete_unconsumed_for_account (seq scan today)
CREATE INDEX ix_oauth_codes_expires_at ON oauth_codes (expires_at);   -- cull
-- lifecycle=ephemeral; stays LOGGED (losing tombstones would turn a replay into "not found" instead of "revoke")

CREATE TABLE oauth_refresh_tokens (
  token_hash    bytea PRIMARY KEY CHECK (length(token_hash) = 32),
  grant_id      uuid NOT NULL REFERENCES oauth_grants (id) ON DELETE CASCADE,
  parent_hash   bytea CHECK (parent_hash IS NULL OR length(parent_hash) = 32),
  created_at    bigint NOT NULL,
  used_at       bigint,
  replaced_by   bytea CHECK (replaced_by IS NULL OR length(replaced_by) = 32),
  grace_replays integer NOT NULL DEFAULT 0 CHECK (grace_replays >= 0)
);
CREATE INDEX ix_oauth_refresh_tokens_grant_id_parent_hash ON oauth_refresh_tokens (grant_id, parent_hash);
-- SQLite: WITHOUT ROWID. lifecycle=durable

CREATE TABLE login_states (                   -- mcp_txn (600 s) and login_flow (600 s, every provider incl. Entra); today's account_link kind (Entra link) is retired
  kind         text COLLATE "C" NOT NULL CHECK (length(kind) <= 32),
  id_hash      bytea NOT NULL CHECK (length(id_hash) = 32),
  binding_hash bytea CHECK (binding_hash IS NULL OR length(binding_hash) = 32),
  payload      bytea NOT NULL CHECK (length(payload) <= 4096),
  created_at   bigint NOT NULL,
  expires_at   bigint NOT NULL,
  PRIMARY KEY (kind, id_hash)
);
CREATE INDEX ix_login_states_expires_at ON login_states (expires_at);
-- PostgreSQL only, in the baseline: ALTER TABLE login_states SET UNLOGGED;  lifecycle=ephemeral
```

Notes:
- **Refresh tokens.**
  - `oauth_refresh_tokens.expires_at` is dropped. It always equals the grant's `expires_at`, every refresh already joins the grant, and `lock_live` already requires `expires_at > now`.
  - The rotation chain (`parent_hash`, `replaced_by`, `grace_replays`, used rows kept until the family dies) is unchanged. That is what detects reuse two or more generations back, a reviewed property.
  - `has_rotated_child(grant_id, token_hash)` gains `grant_id = :g`. It is equivalent, because a child is always inserted with its parent's grant, and it makes the probe exact on the composite index.
- **Dropped indexes:** `oauth_grants_client` (nothing filters on `client_id`), `oauth_refresh_expires`, `oauth_refresh_grant`, `oauth_refresh_parent`.
- **`login_states`.**
  - It is `UNLOGGED` on PostgreSQL: 2.57 MB against 0.40 MB of WAL per 5,000 put/pop cycles (routes survey; a re-run in the fact-check with 300-byte payloads gave 4.1 MB against 0.4 MB, so the ratio holds and the absolute figure depends on payload size). A crash or failover empties it, which fails in-flight sign-ins closed.
  - `pop` becomes one statement: `DELETE ... WHERE kind=? AND id_hash=? AND expires_at>? AND binding_hash IS NOT DISTINCT FROM ? RETURNING payload`. On SQLite use `binding_hash IS ?`; the repo renders the operator per dialect.

#### 4.3.10 History

```sql
CREATE TABLE auth_events (                    -- sign-in history; 90-day retention
  id          bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  at          bigint NOT NULL,
  account_id  uuid,                           -- no FK: history outlives the account
  provider_id text COLLATE "C" NOT NULL,
  surface     text COLLATE "C" NOT NULL CHECK (length(surface) <= 16),   -- account | oauth (today: account, mcp, oauth) | link (new; no code writes it today) (registry; 'mcp' is gone)
  outcome     text COLLATE "C" NOT NULL CHECK (outcome IN ('success','pending','denied','error')),
  reason      text COLLATE "C" NOT NULL CHECK (length(reason) <= 64),
  ua_hash     bytea CHECK (ua_hash IS NULL OR length(ua_hash) = 8)       -- truncated HMAC, raw bytes
);
CREATE INDEX ix_auth_events_account_id_id ON auth_events (account_id, id) WHERE account_id IS NOT NULL;
-- No index on "at": retention walks the primary key (4.8). lifecycle=history

CREATE TABLE audit_log (                      -- absorbs principal_status_events
  id                 bigint GENERATED BY DEFAULT AS IDENTITY PRIMARY KEY,
  at                 bigint NOT NULL,
  actor_kind         text COLLATE "C" NOT NULL CHECK (actor_kind IN ('account','operator','system')),
  actor_id           uuid,                    -- set iff actor_kind = 'account'
  subject_account_id uuid,                    -- whose account the event concerns
  action             text COLLATE "C" NOT NULL CHECK (length(action) <= 64),   -- registry AUDIT_ACTIONS
  target_kind        text COLLATE "C",        -- account | credential | grant | identity | school | provider | setting | server
  target_id          text COLLATE "C",
  reason             text,
  detail             jsonb NOT NULL DEFAULT '{}',   -- e.g. {"session_epoch": 4, "from": "active", "to": "disabled"}
  CONSTRAINT ck_audit_log_actor CHECK ((actor_kind = 'account') = (actor_id IS NOT NULL)),
  CONSTRAINT ck_audit_log_target CHECK ((target_kind IS NULL) = (target_id IS NULL))
);
CREATE INDEX ix_audit_log_subject ON audit_log (subject_account_id, id) WHERE subject_account_id IS NOT NULL;
CREATE INDEX ix_audit_log_target  ON audit_log (target_kind, target_id, id) WHERE target_id IS NOT NULL;
-- lifecycle=history
```

- **Merge of `principal_status_events`.**
  - Every status transition writes one audit row instead of two.
  - The status-event actions (`account_created`, `activated`, `owner_gained`, `owner_lost`, `owner_loss_refused_last_owner`, `owner_re_sourced`, ...) join `AUDIT_ACTIONS` where they have no counterpart already.
  - The epoch moves to `detail.session_epoch`.
  - `token_admin history` and the admin history read `ix_audit_log_subject`.
  - `access_token_roles` disappears with `demote_owner`.
- **No actor index.** Add one as an expand step only if the audit UI ever filters by actor.

#### 4.3.11 Reserved, created empty

```sql
CREATE TABLE web_sessions (                   -- RESERVED: server-side /account sessions (today: sealed cookie)
  id_hash       bytea PRIMARY KEY CHECK (length(id_hash) = 32),
  account_id    uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  session_epoch bigint NOT NULL,              -- valid only while equal to accounts.session_epoch (rule kept)
  provider_id   text COLLATE "C" NOT NULL,
  issued_at     bigint NOT NULL,
  last_seen_at  bigint NOT NULL,
  expires_at    bigint NOT NULL,
  revoked_at    bigint,
  ua_hash       bytea CHECK (ua_hash IS NULL OR length(ua_hash) = 8)
);
CREATE INDEX ix_web_sessions_account_id ON web_sessions (account_id);
CREATE INDEX ix_web_sessions_expires_at ON web_sessions (expires_at);
-- SQLite: WITHOUT ROWID. lifecycle=reserved

CREATE TABLE account_quotas (                 -- RESERVED: per-user overrides; defaults live in settings
  account_id     uuid NOT NULL REFERENCES accounts (id) ON DELETE CASCADE,
  quota_key      text COLLATE "C" NOT NULL CHECK (length(quota_key) <= 64),
  limit_value    bigint NOT NULL CHECK (limit_value >= 0),
  window_seconds integer,
  updated_at     bigint NOT NULL,
  updated_by     uuid,
  PRIMARY KEY (account_id, quota_key)
);  -- SQLite: WITHOUT ROWID. lifecycle=reserved
```

Usage counters never go into SQL. They stay behind the `RateLimiters` protocol: memory now, Redis later.

#### 4.3.12 Version table

The version table stays `canvas_mcp_alembic_version` (Alembic's own; the name is kept).

**Total:** 19 tables, 17 non-unique secondary indexes, 5 unique constraints or unique indexes besides primary keys, 12 foreign keys, no native enums.

### 4.4 Index catalogue

| Index | Serves |
|---|---|
| `ix_accounts_status_role` | owner counts, last-usable-owner guard, pending cap, pending purge, usable owners |
| `uq_external_identities_subject` | sign-in lookup |
| `uq_external_identities_account_provider` | FK cascade, `for_account`, usable-owner `EXISTS`, "one per provider" |
| `pk_account_write_tools` | prefs read (prefix range) |
| `uq_canvas_credentials_account_host` | **hot read** (prefix), FK cascade, put |
| `uq_canvas_credentials_primary` | integrity: one primary per account |
| `ix_canvas_credentials_canvas_host` | unfeature impact count, `RESTRICT` check on school cull |
| `ix_canvas_credentials_oauth_app_id` | `RESTRICT` check on app delete (reserved) |
| `uq_canvas_oauth_apps_canvas_host` | one Developer Key per school (reserved) |
| `ix_oauth_clients_expires_at`, `ix_cimd_clients_fetched_at` | culls; both tables are written by unauthenticated endpoints |
| `ix_oauth_grants_account_id_id` | **hot read**, `/me/grants` (order by `id DESC`), revoke-all, FK cascade |
| `ix_oauth_grants_expires_at`, `ix_oauth_grants_revoked_at` | the two cull statements (never an `OR`) |
| `ix_oauth_codes_account_id` | revoke-all deletes unconsumed codes (0.096 ms per candidate A, sequential scan today), FK |
| `ix_oauth_codes_expires_at`, `ix_login_states_expires_at` | culls |
| `ix_oauth_refresh_tokens_grant_id_parent_hash` | FK cascade, `any_used`, `retire_siblings` (prefix then about 20 rows filtered, 0.195 ms), `has_rotated_child` (exact, 0.042 ms) |
| `ix_auth_events_account_id_id` | sign-in history page (backward scan) |
| `ix_audit_log_subject`, `ix_audit_log_target` | per-account and per-object history pages, no sort |
| `ix_web_sessions_*` | reserved |

### 4.5 Hot paths

#### 4.5.1 Per MCP request: one statement, no write in steady state

```sql
SELECT a.status, a.role, a.session_epoch, a.credential_generation, a.write_tools_version,
       g.revoked_at, g.expires_at, g.last_used_at AS grant_used_at,
       c.id AS credential_id, c.canvas_host, c.kind, c.generation, c.key_id, c.nonce, c.ciphertext,
       c.status AS credential_status, c.last_used_at AS credential_used_at, c.last_verified_at,
       c.canvas_user_id, c.custody_notice_version,
       s.jwt_epoch, s.settings_revision
FROM oauth_grants g
JOIN accounts a ON a.id = g.account_id
LEFT JOIN canvas_credentials c ON c.account_id = a.id AND c.is_primary
CROSS JOIN server_state s
WHERE g.id = :grant_id AND g.account_id = :account_id AND s.id = 1
```

**Plans.**
- PostgreSQL: a nested loop over `pk_oauth_grants` or `ix_oauth_grants_account_id_id`, then `pk_accounts`, then `uq_canvas_credentials_primary` or the `uq_canvas_credentials_account_host` prefix, then `server_state` (a one-row sequential scan on the checked PostgreSQL 16.2 plan, which is as cheap as `pk_server_state`).
- SQLite:
  ```
  SEARCH g USING (COVERING) INDEX ...
  SEARCH a USING INDEX (id=?)
  SEARCH c USING INDEX ...
  SEARCH s USING PRIMARY KEY
  ```
- Candidate B measured the grant, account and credential part at 0.05 ms and 9 buffers; `server_state` adds one page.

**Where it runs.** The read happens once, in the authorization server's `load_access_token`, in a worker thread. The row is published in a ContextVar for `SelfhostRequestContextMiddleware` and the tool gate, which never read the database again in that request. Failure semantics are exactly today's:
- token or grant problems return `None`, which FastMCP turns into a 401 with `WWW-Authenticate`;
- account standing gives a 403 with the existing messages;
- `StoreUnavailable` gives a 503.

**Steps in Python, in order:**
1. **JWT.** Verify the signature with the key derived for the token's own `kid` (`<ring key id>.<epoch>`), whatever the epoch: the key is HKDF-derived from `CANVAS_TOKEN_KEYS` (`AccessTokenCodec._key`), so no database read is needed to verify. Keep the bounded per-process key cache (at most 64 entries) and the existing checks (ring key id known, epoch all digits), and add a cap of 10 digits on the epoch so a forged `kid` cannot make the server derive keys for huge integers. The signature check comes first because the statement below uses the `grant` and `acct` claims.
2. **Run the statement.** No row (unknown grant, or the account does not match `acct`) is a 401.
3. **Epoch.** `s.jwt_epoch != token epoch` is a 401. The database value is the only authority, so `rotate-jwt-key` is effective on every instance at the next request, with no cache and no synchronous epoch read. A token epoch above `s.jwt_epoch` cannot be produced by this server and is refused the same way.
4. **Grant.** Revoked, or `expires_at <= now`, is a 401.
5. **Account.** A status other than `active` is a 403 with the existing pending or disabled messages.
6. **Settings snapshot.** If `s.settings_revision` differs from the cached snapshot's revision, rebuild it from three tiny reads. A rebuild failure is a 503: it fails closed, and nothing is ever "allow all". This step comes before the credential check, which needs the current snapshot.
7. **Credential.**
   - None: the existing "not enrolled" refusal at the tool gate.
   - `invalid`: the existing invalid-token message.
   - Host not offered: the new `school_not_offered_message()` (5.8). A host is offered when it is featured in the snapshot, or when directory search is on (the host passed the directory and address checks when the credential was saved, and the address guard runs again on every Canvas call), or when its row has `allow_private` (operator decision).
   - `c.custody_notice_version < CUSTODY_NOTICE_VERSION` (D10): the new `custody_ack_required_message()`, which points at `/account/token`. The token is not decrypted and no Canvas request is made; the row is kept, and an acknowledgement restores service at the next request.
   - `c.generation != a.credential_generation`: a store inconsistency, so 503 and a log entry. This cannot happen under the invariant.
8. **Decrypt** with AAD v1 (4.7). A failure is a 503 plus a log line, as for an undecryptable row today.
9. **Write-tool prefs** come from an LRU keyed `(account_id, write_tools_version)`, with 4,096 entries. A miss is one prefix read.
10. **Touches, only when stale.**
    - Grant: `last_used_at IS NULL OR last_used_at < now - 300`.
    - Credential: the same rule.
    - Each is a tier-0 statement (4.6) that **never waits for a row lock**. On PostgreSQL: `UPDATE oauth_grants SET last_used_at = :now WHERE id = (SELECT id FROM oauth_grants WHERE id = :id AND (last_used_at IS NULL OR last_used_at < :stale) FOR NO KEY UPDATE SKIP LOCKED)`, and the same shape for `canvas_credentials`. Checked on PostgreSQL 16.2: the plan is two primary-key probes, and while another transaction held the row the statement returned 0 rows in 0.9 ms, where the plain conditional `UPDATE` waited for `lock_timeout` (5 s in production). A row held by a rotation, a revocation or a credential write is simply touched by a later request.
    - Touches are deduplicated in-process so concurrent requests do not all touch, run after the tool gate has decided, and a failure is ignored.

**Issuing tokens.** `/token` (first exchange, code replay sibling and refresh) reads `jwt_epoch` from `server_state` inside its own transaction and signs with that epoch. A `rotate-jwt-key` that commits after the read makes the new access token fail at its first use, and the client refreshes; that is the intended effect of a rotation.

**Deleted:**
- `PrincipalAccessCache` (`principal_access.py` becomes a pure function over the row);
- `GrantStatusCache` (`authz/grants.py`, `GRANT_STATUS_CACHE_S`);
- `EpochSource` and `EPOCH_CACHE_SECONDS` (`authz/tokens.py`), and `AuthzRuntime.epoch`; `AccessTokenCodec` takes the epoch as an argument when encoding and returns the token epoch when decoding;
- `ToolPrefsCache`'s TTL;
- `TokenStore.get` and `touch` as separate calls.

The module-level credential-generation registry in `core/credentials.py` stays, fed by `a.credential_generation`.

**Result:** 1 statement per request in steady state, and at most two cheap writes per 5 minutes per active grant. Today it is 2 statements on 2 connections, `touch` takes the SQLite write lock on every request (measured stalling 5.5 s behind another writer), and cache refreshes add more reads.

#### 4.5.2 Other paths

The PostgreSQL figures are from candidate stress seeds. SQLite plans are index searches unless noted.

| Path | Shape | Evidence |
|---|---|---|
| `/api/v1` session check (every API request) | `SELECT a.status, a.role, a.session_epoch, s.settings_revision FROM accounts a CROSS JOIN server_state s WHERE a.id = ? AND s.id = 1` | two primary-key probes |
| `/auth/*` handlers | `SELECT settings_revision FROM server_state WHERE id = 1`, then the provider snapshot | one probe |
| Sign-in identity lookup | `uq_external_identities_subject` join `accounts` | 0.044 ms |
| `/token` refresh | refresh primary key join grant primary key (expiry from the grant) | 0.046 ms, 7 buffers |
| Code consume | `UPDATE oauth_codes ... WHERE code_hash AND client_id AND consumed_at IS NULL AND expires_at > ?` | primary key |
| Login-state pop | `DELETE ... RETURNING payload` | 0.013 ms, 5 buffers |
| `mark_verified` | `UPDATE canvas_credentials SET last_verified_at=:now WHERE id=:id AND generation=:g AND status='active' AND (last_verified_at IS NULL OR last_verified_at < :now - 600)` | primary key; no advisory lock and no explicit row lock (it waits only for a concurrent writer of the same row, then re-checks) |
| Usable owners (P7) | `SELECT a.id FROM accounts a WHERE a.status='active' AND a.role='owner' AND EXISTS (SELECT 1 FROM external_identities i JOIN login_providers p ON p.id = i.provider_id WHERE i.account_id = a.id AND p.configured)`, plus P7's remaining conditions, unchanged | 0.022-0.065 ms |
| Revoke-all codes | `DELETE FROM oauth_codes WHERE account_id=? AND consumed_at IS NULL` | `ix_oauth_codes_account_id` |
| Admin accounts page | `WHERE id < :cursor ORDER BY id DESC LIMIT 50`, left join the primary credential | 0.09 ms |
| Unfeature impact | `SELECT count(*) FROM canvas_credentials WHERE canvas_host=?` | index-only, 0.018 ms |
| Account deletion | `DELETE FROM accounts WHERE id=?` (8 cascades) | 1.0-1.08 ms |

`resolve_identity` drops from 8-14 statements to about 6-10: there is no generation join and no separate status-event row, and `RETURNING` merges the bumps.

### 4.6 Transactions and locking

**Tiers.** On SQLite every writer path still takes the per-process lock and then `BEGIN IMMEDIATE`, so the tiers differ only on PostgreSQL, which runs `READ COMMITTED`.

| Tier | Mechanism | Rule |
|---|---|---|
| **0 best effort** | PostgreSQL: autocommit, one statement; an `UPDATE` of an existing row uses the `SKIP LOCKED` form of 4.5.1, so it never waits for a row lock; an `INSERT` into a table without foreign keys never waits. SQLite: one statement in a deferred transaction, skipped if this process's writer lock is held, with `busy_timeout=250` for that call, restored to 5000 in a `finally` block before the connection returns to the pool. | Loss is harmless. Never on any other path. |
| **1 row-conditional** (`Database.row_write()`) | `READ COMMITTED`, no global lock. Correctness comes from conditional `UPDATE`/`DELETE` statements checked by rowcount or `RETURNING`, plus the lock order below. Explicit account locks are `FOR NO KEY UPDATE` (`with_for_update(key_share=True)`, which SQLAlchemy 2.1 renders as `FOR NO KEY UPDATE`; SQLite omits the clause). | Machine-initiated protocol, health and maintenance writes, and single-row revocations by the subject (`/revoke`, `DELETE /me/grants/{id}`), which decide nothing from a set predicate. |
| **G governance** (`Database.write()`) | PostgreSQL: a per-process `threading.Lock` (the governance gate, the twin of SQLite's process lock) is taken **before** a pool connection is checked out; then the first statement is `pg_advisory_xact_lock(GOVERNANCE_LOCK_KEY)` (today's `WRITER_LOCK_KEY`, renamed); then the actor and target account rows `FOR NO KEY UPDATE`. The gate costs nothing (the advisory lock serialises these transactions anyway) and keeps a burst of sign-ins from parking every pooled connection on the advisory lock while hot-path reads wait for a connection. | Every write that decides from a set predicate or from owner standing: sign-in, every owner or operator action, every credential, prefs and settings write, and the startup reconcile. |
| maintenance | One short tier-1 transaction per batch, preceded by `pg_try_advisory_xact_lock(<job key>)`. If the lock is not acquired, skip. | Never under the governance lock, except the pending purge. |
| migrations | Session advisory lock `MIGRATION_LOCK_KEY` on a direct connection (unchanged) | |

`best_effort_write(lock=True)` is deleted.

**Row-lock order (PostgreSQL).** Every transaction that locks or writes more than one of these rows does so in this order: **`oauth_codes` -> `accounts` -> `oauth_grants` -> `oauth_refresh_tokens`**, and `accounts` -> `canvas_schools` -> `canvas_credentials` for credential writes. Consequences the implementer must keep:
- A statement that deletes or updates `oauth_codes` runs before the account row is locked (by `FOR NO KEY UPDATE`, by an `UPDATE accounts`, or by `bump_credential_generation`). This is today's order in `AuthzStore.revoke_all_for_account` ("codes first, then the account lock").
- Deleting an account deletes its codes first (`DELETE FROM oauth_codes WHERE account_id = ?`), then deletes the account row, whose cascade reaches the other children. A bare `DELETE FROM accounts` locks the account and then cascades into `oauth_codes`, which is the reverse order.
- Checked on PostgreSQL 16.2 with a first exchange holding its code row and waiting for the account: an account lock followed by a code delete (revoke-all) and a bare account delete each ended in `DeadlockDetected`; the codes-first forms of both completed, with the exchange succeeding.
- One reviewed exception: the code-replay branch of `exchange_code` locks the grant (`lock_live`) and then updates the code row (`bump_grace`). It cannot deadlock, because the code is already consumed: no transaction holds a consumed code row while waiting for a grant (a first exchange inserts a new grant, and the revoke-all delete matches only `consumed_at IS NULL`, which it evaluates without waiting on a consumed row).
- Among account rows, only G transactions lock more than one, and they are serialised by the advisory lock, so their order among themselves does not matter. The other owners' rows read by `usable_owner_ids` are locked `FOR NO KEY UPDATE` (today `FOR UPDATE`, the reviewed form); the lock is redundant under the advisory lock and costs at most a short wait for those owners' first code exchanges.

**Every write path:**

| Write path | Tier | Statements and the race prevented |
|---|---|---|
| Credential touch, grant touch, `record_auth_event`, `record_cimd_error`, `record_consent_denied` | 0 | Single conditional statements. Removes the SQLite write lock from the per-request path. |
| `login_states.put` / `pop` | 1 | `INSERT`; `DELETE ... RETURNING`. Exactly one caller gets the payload. |
| `/register` (`put_client`), client extend on first exchange | 1 | `INSERT`; conditional `UPDATE` |
| `upsert_cimd` | 1 | `ON CONFLICT (url) DO UPDATE ... WHERE excluded.fetched_at > cimd_clients.fetched_at RETURNING url`. An older fetch never overwrites a newer one. |
| `create_code` | 1 | Plain standing read, insert code, insert auth event. The binding is re-checked at exchange. |
| `exchange_code`, first exchange | 1 | (1) `UPDATE oauth_codes SET consumed_at ... WHERE code_hash, client_id, consumed_at IS NULL, expires_at > now`: rowcount 1, so there is no double redeem. (2) Account `FOR NO KEY UPDATE`, then check `active` and `session_epoch == code.session_epoch` (**P6**). (3) Insert the grant and the first refresh token. (4) Extend the client. (5) Auth event. **Disable vs first exchange:** disable's `UPDATE accounts` conflicts with `FOR NO KEY UPDATE`. Either disable commits first and the exchange sees `disabled`, or the exchange commits first and disable's grant revocation sees the new grant. The lock does not block FK child inserts (`KEY SHARE`) by other transactions, which today's `FOR UPDATE` would. |
| `exchange_code` replay, `rotate_refresh`, reuse revocation | 1 | `lock_live` (`UPDATE oauth_grants SET last_used_at ... WHERE id AND revoked_at IS NULL AND expires_at > now`) serialises the family on the grant row. Then `mark_used ... WHERE used_at IS NULL` (single winner), `retire_siblings`, and insert the successor. The replay branch runs `has_rotated_child(grant_id, parent)`, `bump_grace ... WHERE grace_replays < cap`, or revoke. Unchanged, and atomic on both backends. |
| `/revoke`, `DELETE /me/grants/{id}` | 1 | Conditional `UPDATE ... WHERE revoked_at IS NULL` |
| Revoke-all on `admission_lost` (`AuthzStore.revoke_all_for_account`, system-initiated after a refused sign-in, in its own transaction after the sign-in transaction) | 1 | In this order: (1) `DELETE` the account's unconsumed codes (cleanup only; the epoch is what kills them); (2) account `FOR NO KEY UPDATE`; (3) `session_epoch` bump with `RETURNING`; (4) `UPDATE` the grants; (5) audit. Today's order, kept. There is no self-service revoke-all route in v1. |
| `mark_verified` (health) | 1 (SQLite: tier-0 mechanics, because it is one statement and SQLite has one writer at a time) | Single row-local conditional `UPDATE` (4.5.2). The generation is on the same row, so PostgreSQL's re-check after a concurrent update re-evaluates it against the new version. A token replaced or invalidated meanwhile cannot be marked verified. This removes `engine.py` docstring reason (c). It may wait for the row lock of a concurrent credential write; that wait is what makes the guard sound, so it must not use `SKIP LOCKED`. |
| Automatic `mark_invalid` (Canvas confirmed the token dead, on the MCP path) | 1 | `bump_credential_generation(conn, account_id, writing=credential_id)` (row lock through the `UPDATE`, `RETURNING` the new generation `:g`), then `UPDATE canvas_credentials SET status='invalid', generation=:g, ... WHERE id=:id AND generation=:old AND status='active'`. Zero rows means roll back. A concurrent put (G) also locks the account row first, so the two serialise on it. |
| Sign-in (`resolve_identity`): admission, bootstrap owner, pending cap, role recompute, identity touch, audit, auth event | G | Set predicates that READ COMMITTED row locks cannot protect: "no owner yet, so bootstrap", pending cap, owner count. The unique constraints back up identity races. |
| `link_identity`, `unlink_identity` | G | The last usable identity of an owner, and the last usable owner. The pre-checks under the advisory lock decide and audit refusals; a unique violation is a second barrier that fails closed (2.6). |
| Approve, deny, disable, enable, promote, set role, `create_operator_account`, sign-out-everywhere (`session_epoch` bump) | G | Last usable owner. Each bumps `session_epoch` and/or the generation with `RETURNING`. Disable also revokes grants under the same account lock. |
| Credential put, replace, delete, admin mark-invalid, restore, recheck verdict | G | Status gate on the locked account row, owner re-check for admin actions, school upsert, generation bump, audit. A put also writes the custody columns (D10). *Possible later without a migration: account-row tier, B's design.* |
| Custody re-acknowledgement (D10) | G | Account lock, status gate, `UPDATE canvas_credentials SET custody_notice_version=:v, custody_ack_at=:now, updated_at=:now WHERE account_id=:id AND is_primary` (zero rows: `not_enrolled`), audit. No generation bump: the hot read takes the column from the row. |
| Write-tool prefs | G | Account lock, replace rows, bump `write_tools_version`, audit |
| Settings, featured schools, sign-in method names | G | `_require_owner_actor` inside the transaction, the `settings_revision` CAS (a lost update is impossible, and a stale form gets `settings_conflict`), the writes, then audit |
| Owner or operator grant revoke | G | Owner re-check plus a conditional `UPDATE` |
| `bump_jwt_epoch` (`rotate-jwt-key`) | G | `UPDATE server_state ... RETURNING jwt_epoch`, audit |
| Key rotation (`token_admin rotate`) | G per chunk of 500 credential ids | `UPDATE ... WHERE id=? AND key_id=:old AND generation=:g`. A concurrent put wins and the chunk skips that row. |
| Startup provider reconcile | G | Owner usability depends on it |
| Pending purge, account deletion (operator) | G | Last-usable-owner guard; per account, `DELETE` its codes, then `DELETE` the account (cascade), then audit (lock order above) |

**Races that must stay prevented, with the PostgreSQL concurrency test that pins each one** (`tests/selfhost/test_v1_races.py`, both orders where it applies):
1. **Last usable owner.** Two concurrent disables, demotions or unlinks of two different owners never leave zero owners.
2. **Bootstrap owner and pending cap.** Two first sign-ins do not both become owner, and do not both slip under the cap.
3. **Identity uniqueness.** The same subject twice, or the same provider twice on one account, is impossible.
4. **Disable vs first code exchange (P6).** Either the exchange is refused or the new grant is revoked.
5. **Credential put vs disable.** They serialise on the account row, and the put re-checks `active`.
6. **`mark_verified` and automatic `mark_invalid` vs a concurrent replace or delete.** A stale health verdict never touches the new token.
7. **Refresh rotation.** Exactly one winner. A replay inside the grace window returns a sibling; a reuse revokes the family.
8. **Concurrent settings saves.** Exactly one succeeds; the other gets `settings_conflict` and writes no audit row.
9. **Owner demoted while acting.** The admin action re-checks the actor inside the governance transaction and is refused with no write and no audit (pattern of `test_store_owner_recheck.py`).
10. **Login-state pop.** Two concurrent pops of the same record: exactly one payload.
11. **Lock order: revoke-all and account deletion vs a first code exchange.** With the exchange paused after consuming its code (`pause_hook("after_code_consume")`), an `admission_lost` revoke-all and an operator account deletion of the same account both finish without `DeadlockDetected`, in both orders.
12. **Orphan-school cull vs credential put.** With the put paused between the school upsert and the credential insert, a cull run neither deletes the school nor makes the put fail; with the cull paused between its two steps, the put waits and then succeeds.
13. **Touches never wait.** A grant touch and a credential touch return within 50 ms while another transaction holds the row, and change nothing.
14. **Governance gate.** With one G transaction paused holding the advisory lock and eight more G calls queued in the same process, a hot-path read still gets a pool connection within 100 ms.

### 4.7 Encryption and the sealed-column registry

- **Primitive.** AES-256-GCM under `CANVAS_TOKEN_KEYS`, a 12-byte random nonce (now a CHECK) and the ring `key_id` per row. Unchanged.
- **One AAD layout per sealed column.** Fields are joined with `0x1f`. The hostless v3 layout, the v2 prefix and every `entra:` key helper are deleted.

| Table | Sealed columns | AAD |
|---|---|---|
| `canvas_credentials` | `nonce`, `ciphertext` | `canvas-mcp/canvas-credential/v1`, `acct:<account_id>`, `canvas_host`, `kind`, `key_id` |
| `canvas_oauth_apps` (reserved) | `secret_nonce`, `secret_ciphertext` | `canvas-mcp/canvas-oauth-app/v1`, `canvas_host`, `client_id`, `key_id` |
| `login_providers` (reserved) | `secret_nonce`, `secret_ciphertext` | `canvas-mcp/provider-secret/v1`, `id`, `key_id` |

- The credential AAD keeps the required binding of principal, host and key id. It adds `kind`, so a PAT ciphertext cannot be moved into an OAuth row. `canvas_host` is mandatory.
- **`selfhost/db/sealed.py`** builds `SEALED` from `Table.info["sealed"]`. Everything that touches ciphertext iterates it:
  - the startup keyring probe (one row per `key_id` per table);
  - `token_admin rotate` (chunks of 500 by primary key);
  - `rows_not_under_key`;
  - the transfer decrypt check.
- **Registry test.** Every `bytea` column whose name ends in `ciphertext` must be registered, so a new sealed column cannot be missed by rotation.

### 4.8 Retention and maintenance

The maintenance runner moves from `edge_guard.py` into a new `selfhost/maintenance.py`. Scheduling is unchanged: at most hourly per process, triggered by traffic.

**Rules for every job:**
- It is chunked, and each chunk is its own transaction.
- On PostgreSQL each chunk first takes `pg_try_advisory_xact_lock(<job key>)` and skips if busy, so several instances never duplicate work. This is transaction-scoped and safe behind a pooler.
- Each job has a budget per run: 2 s on SQLite, with a 50 ms yield between chunks; 10 s on PostgreSQL. A job that hits its budget continues next hour.
- A `StoreUnavailable` ends the job for this run and is logged without values.

**Statement pattern.** Two steps, never `IN (SELECT ... LIMIT)`:

```sql
-- step 1 (PostgreSQL adds FOR UPDATE SKIP LOCKED)
SELECT <pk> FROM <table> WHERE <due> ORDER BY <due column> LIMIT :n;
-- step 2 (expanding bind parameter), in the same transaction
DELETE FROM <table> WHERE <pk> IN (:ids) AND <due>;
```

Step 2 always repeats the due predicate. On PostgreSQL step 1's `SKIP LOCKED` row locks already pin the selected rows, but the repeated predicate is what keeps the orphan-school cull correct (a credential insert takes only `KEY SHARE` on the school, see 4.3.4) and keeps SQLite and PostgreSQL on one statement text. A job whose delete still raises an `IntegrityError` (a foreign key that appeared between the steps) rolls back that chunk, logs the job name only, and ends for this run.

**Batch sizes:**
- Plain rows: 2,000 on PostgreSQL, 500 on SQLite.
- Cascading grant deletes: 200 grants per chunk on both. Candidate A measured 98.7 ms for 500 grants and 5,000 tokens on SQLite, and 9 ms for 500 grants and 10,000 tokens on PostgreSQL.

| Job | Due | Access path | Default |
|---|---|---|---|
| Login states | `expires_at < now` | `ix_login_states_expires_at` | at expiry |
| Code tombstones | `expires_at < now - 3600` | `ix_oauth_codes_expires_at` | 1 h (replay detection) |
| Revoked grants (refresh tokens follow by cascade) | `revoked_at < now - 30 d` | `ix_oauth_grants_revoked_at` | 30 d |
| Expired grants (cascade) | `expires_at < now - 30 d` | `ix_oauth_grants_expires_at` | 30 d |
| DCR clients | `expires_at < now` | `ix_oauth_clients_expires_at` | 30 d TTL, extended on first exchange |
| CIMD snapshots | `fetched_at < now - (CIMD_STALE_MAX + 1 d)` | `ix_cimd_clients_fetched_at` | about 8 d |
| Sign-in events | `at < now - retention.auth_events_days` | **primary-key walk with a cursor**: each run starts at `cursor = 0`; per chunk `SELECT id, at FROM auth_events WHERE id > :cursor ORDER BY id LIMIT :n`, delete the due ids, set `cursor` to the chunk's last id; stop when the chunk is shorter than `:n`, when the chunk's **last** row is not due, or at the budget. A not-due row with a lower id (clock skew between instances) is skipped, not a stop condition, and is deleted by a later run. (Stopping at "fewer due rows than the chunk size" would let one skewed row cap every run at one chunk.) | 90 d. Candidate A measured 0.20 ms when nothing is due and 1.3 ms per 1,000 due rows; the walk measured 0.22 ms in the fact-check run (1.2M rows). Today's `DELETE ... WHERE at < cutoff` is not a sequential scan: schema.py has an `auth_events_at` index and the planner uses it (0.08 ms when nothing is due, 30 ms for one unbatched delete of 98k rows). What changes is that the delete is chunked, and that the index on `at` is not maintained on every sign-in insert any more. |
| Audit log | same walk, only when `retention.audit_days > 0` | primary key | 0 = keep forever |
| Pending accounts | `status = 'pending' AND created_at < now - 30 d`; **G tier**, at most 100 per run, codes first then the account (4.6 lock order), cascade, one audit row each | `ix_accounts_status_role` | 30 d |
| Orphan schools | `featured_rank IS NULL AND NOT allow_private AND updated_at < now - 1 d AND NOT EXISTS (credential) AND NOT EXISTS (oauth app)`, repeated in step 2 | primary key plus FK indexes | 1 d. Safe against a concurrent credential put only together with the put's `ON CONFLICT DO UPDATE SET updated_at` (4.3.4, race 12). |
| SQLite housekeeping | after a run that deleted more than 1,000 rows: `PRAGMA incremental_vacuum(2000)`; once a day: `PRAGMA optimize` | | |

**Changed from today:**
- The separate refresh-token deletion 7 days after revocation is dropped; tokens leave with the grant at 30 days.
- `prune_auth_events` no longer holds the global lock (today 427 ms on 300k rows).

**Never culled:** accounts, identities, credentials and write tools. They go only through explicit deletion (credential delete, identity unlink, pending purge, account deletion), with cascades.

### 4.9 SQLite configuration (`selfhost/db/engine.py`)

- **Version.** Refuse SQLite older than **3.37**: STRICT needs 3.37, `RETURNING` 3.35, row values 3.15. The dev environment has 3.50.4.
  - Add a test to `tests/test_selfhost_dockerfile.py`, or to the smoke test, that prints `sqlite3.sqlite_version` inside the image. It is not verified for `python:3.14-slim` (Debian; expected 3.46).
- **Pool.** `QueuePool(pool_size=4, max_overflow=4, pool_pre_ping=False)` with `connect_args={"check_same_thread": False, "timeout": 5}` replaces `NullPool`.
  - Measured: 0.06 ms against 0.89-1.16 ms per call.
  - The writer path is unchanged: the per-process lock, then `BEGIN IMMEDIATE`. The driver stays in `isolation_level=None` (explicit transactions).
  - Tests that need to delete the file on Windows call `Database.dispose()`. The git history shows no documented reason for `NullPool`.
- **Every connect** (`_sqlite_on_connect`):
  ```
  PRAGMA busy_timeout=5000
  PRAGMA foreign_keys=ON          -- asserted: SELECT returns 1
  PRAGMA synchronous=FULL         -- kept: revocations and consumed codes must survive power loss (about 0.34 ms per commit)
  PRAGMA trusted_schema=OFF
  PRAGMA journal_size_limit=67108864
  PRAGMA secure_delete=FAST       -- zero deleted hashes and ciphertext when it costs no extra I/O
  ```
  `journal_mode=WAL` is persistent; keep `_enter_wal_mode`.
- **At file creation only**, on an empty file before the migration creates any table, and **before** `PRAGMA journal_mode=WAL` is issued on that file. The order matters: checked on SQLite 3.50.4, `auto_vacuum=INCREMENTAL` set after `journal_mode=WAL` leaves `PRAGMA auto_vacuum` at 0, while set before it gives 2. Today's `_sqlite_on_connect` enters WAL first, so a creation step must run on its own bootstrap connection before the pool's first connect (and `test_v1_engine.py` asserts `auto_vacuum == 2` on a new file). `application_id` is not order-sensitive:
  ```
  PRAGMA auto_vacuum=INCREMENTAL
  PRAGMA application_id=0x434D4350   -- "CMCP"
  ```
  File mode stays 0600.
- **Migration connection.** A dedicated connection outside the pool (`NullPool` engine or a raw `sqlite3` connection), closed after the migration, so a connection with foreign keys off can never be handed to request code. It runs `PRAGMA foreign_keys=OFF` before `BEGIN IMMEDIATE` (the pragma is a no-op inside a transaction), and `PRAGMA foreign_key_check` before `COMMIT`; the migration fails if the check reports anything. Reason: a batch table rebuild's `DROP TABLE` cascades with FKs on, which the db-practice survey reproduced as silent child-row loss.
- **Single host.** WAL needs one host, so several instances imply PostgreSQL. Document it, and keep `SELFHOST_STATE_BACKEND=memory`.

### 4.10 PostgreSQL configuration

- **Pool.** `pool_size=10, max_overflow=0, pool_timeout=10, pool_recycle=1800, pool_pre_ping=True`.
  - Every store call goes through `anyio.to_thread.run_sync(..., limiter=STORE_LIMITER)`, where `STORE_LIMITER = CapacityLimiter(10)`. Bursts queue in process instead of failing at the pool and surfacing as 503s; today 40 threads compete for 10 connections.
  - A store call must never nest another store call (deadlock).
  - G transactions pass the per-process governance gate (4.6) before checking out a connection, so at most one pooled connection per process waits on the advisory lock.
  - Maintenance runs one job at a time per process, one chunk transaction at a time, so it holds at most one connection.
  - Budget `instances x 10` connections, plus one per `token_admin` invocation and the migration connection, below `max_connections`.
- **Timeouts** (unchanged): `statement_timeout=15s`, `lock_timeout=5s`, `idle_in_transaction_session_timeout=30s`, set via the startup `options` parameter.
  - Behind PgBouncer, which rejects `options` by default: document `ALTER ROLE ... SET` for the three timeouts and `prepare_threshold=None`, unless PgBouncer supports protocol-level prepared statements with `max_prepared_statements` above 0 (added in 1.21; `DISCARD ALL`/`DEALLOCATE ALL` support in 1.22; default 200 since 1.24; unverified here which version a given pooler needs for psycopg).
  - Migrate over a direct connection; the migration lock is session-level.
- **Isolation.** `READ COMMITTED` everywhere. Never `REPEATABLE READ` or `SERIALIZABLE` for writes: their snapshot would predate the lock wait.
- **Storage parameters**, set by the baseline:
  - `fillfactor=90` on `accounts`, `canvas_credentials` and `oauth_grants` (via `postgresql_with`);
  - `autovacuum_vacuum_scale_factor=0.05` on `login_states`, `oauth_codes` and `oauth_refresh_tokens`;
  - `login_states` `UNLOGGED`.
- **CI** uses PostgreSQL 18.6; local runs use 16.2. Nothing in the design needs a version above 16.

### 4.11 Pagination

Every list is keyset-paged on a unique key, using SQLAlchemy `tuple_()` where needed. There is no `OFFSET`.

| List | Key | Index |
|---|---|---|
| Admin accounts | `id DESC` (v7 = creation order) | `pk_accounts` |
| Admin enrollments | credential `id DESC` | `pk_canvas_credentials` |
| Grants of an account | `id DESC` | `ix_oauth_grants_account_id_id` |
| All live grants (admin) | `id DESC` with `revoked_at IS NULL` | `pk_oauth_grants`, filtered; fine at this scale |
| Sign-in history | `id DESC` | `ix_auth_events_account_id_id` |
| Audit, global | `id DESC` | `pk_audit_log` |
| Audit, per account | `id DESC` | `ix_audit_log_subject` |

The API takes `cursor` (an opaque base64url of the last key) and `limit` (default 50, maximum 200), and returns `next_cursor`. This retires the unpaginated `list_accounts`, `list_enrollments` and `grants.list_all(limit=500)`.

### 4.12 Alembic: squashed baseline and migration policy

**Baseline `0001_v1_baseline`:**
- `selfhost/db/migrations/versions/0001_v1_baseline.py`: hand-written, frozen `op.create_table`/`op.create_index` with dialect variants:
  - `postgresql_where`/`sqlite_where`, `postgresql_with`, `sqlite_strict=True`, `sqlite_with_rowid=False`, `sqlite_autoincrement`;
  - the PostgreSQL-only `op.execute` for `SET UNLOGGED` and the autovacuum parameters.
- It must **not** import `db/schema.py`, the same rule as today's revisions.
- It inserts the `server_state` row: `database_id = uuid4()`, `compat_floor = 1`, `jwt_epoch = 0`, `settings_revision = 0`.
- The version table stays `canvas_mcp_alembic_version`.

**Deleted:**
- `db/baseline_v4.py`, `db/accounts_v5.py`, the three revision files;
- in `db/migrate.py`: `STATE_LEGACY` and adoption, `BACKUP_BEFORE` and `_auto_backup` for data migrations, `_backup_revision`, `MigrationOptions`, `AccountMigrationReport`, `--mark-undecryptable-invalid`, `_DATA_TABLES`, `COMPAT_SCHEMA_VERSION`, `meta.schema_version`;
- tests and fixtures: `tests/selfhost/legacy_schemas.py`, `schema4.py`, `fixtures/schema4_*` and its generator, `test_account_migration.py`, `test_account_aad_tamper.py` (replace with AAD v1 tests), and most of `test_store_migrations.py`.

**Compatibility rule:**
- The code carries `SCHEMA_EPOCH` (starts at 1) in `db/migrate.py`.
- A contract revision sets `server_state.compat_floor` to the epoch of the oldest release whose code tolerates the contracted shape.
- Startup states in `ensure_ready`:

| State | Detection | Behaviour |
|---|---|---|
| uninitialized | no tables | apply creation pragmas (SQLite), run the baseline |
| current | head revision known and current | run |
| behind | known older revision | upgrade if `DATABASE_AUTO_MIGRATE=true`, else refuse |
| newer | unknown revision and `compat_floor <= SCHEMA_EPOCH` | run without migrating; log "database is newer than this release" |
| too new | unknown revision and `compat_floor > SCHEMA_EPOCH` | refuse |
| pre-v1 | `meta` table present, or revision in {`0001_baseline_v4`, `0002_accounts`, `0003_oauth_authz`} | refuse: "database from a pre-v1 build; nothing is deployed, so delete it" |
| unreadable | anything else | refuse |

**Expand/contract for every later revision:**
1. **Expand releases only add.**
   - What they may add: tables, nullable or constant-default columns, indexes, `CHECK ... NOT VALID` then `VALIDATE`, FKs `NOT VALID` then `VALIDATE`.
   - Backfills run in batches.
   - Expand revisions never raise `compat_floor`.
2. **PostgreSQL indexes on populated tables** use `CREATE INDEX CONCURRENTLY` in a revision flagged `NON_TRANSACTIONAL = True`. The runner executes that revision with `transaction_per_migration=True` and `autocommit_block()`, holding the session migration lock on a separate connection. A failure leaves an INVALID index; the revision drops and retries it.
3. **Contract changes** (drop, rename, `NOT NULL`, type change) ship at least one release after the code stopped using the old shape, and raise `compat_floor`.
4. **SQLite rebuilds** use `batch_alter_table` with the FK-off migration connection and `foreign_key_check`, plus an automatic `*.pre-<rev>-<stamp>.bak` copy of the file before a contract revision. Because CHECKs never list open vocabularies, adding a value never needs a rebuild. Batch mode recreates the table from reflection, which keeps `STRICT`, `WITHOUT ROWID`, named CHECKs and partial-index predicates but **drops `AUTOINCREMENT`** (SQLAlchemy 2.1.4 does not reflect `sqlite_autoincrement`): a rebuild of `auth_events` or `audit_log` passes `table_kwargs={"sqlite_autoincrement": True}`, and the golden SQLite DDL test after an upgrade catches any omission.
5. **No re-encryption inside a revision.** That is an operator command with a backup (the lesson of the old `0002`).
6. **No downgrades.** Roll back by restoring a backup. Expand-only releases allow an application rollback without one.
7. **Multiple instances:** `DATABASE_AUTO_MIGRATE=false`, and run `token_admin db upgrade` first.
8. **Autogenerate** misses renames, CHECK edits and anonymous constraints. Always review the generated script; the naming convention makes constraints addressable.
9. **CI:**
   - a linear revision graph;
   - `compare_schema() == []` on both backends; add a `compare_type` hook if the TypeDecorators produce false diffs (unverified);
   - golden DDL for both dialects (`tests/selfhost/ddl_postgresql_head.sql` regenerated, new `tests/selfhost/ddl_sqlite_head.sql`);
   - a PostgreSQL `reloptions`/`relpersistence` check;
   - `foreign_key_check`;
   - from the second revision on, an upgrade test from a seeded database of the previous release.

### 4.13 `import-sqlite` / transfer under v1 (`selfhost/db/transfer.py`)

- Unchanged purpose: `refuse_silent_switch` refuses an empty PostgreSQL target next to a SQLite file that holds rows.
- The procedure, which is all or nothing:
  1. Snapshot the SQLite file into a private temp directory with the backup API.
     - Open the copy, and bring it to head with a normal Alembic upgrade (no data migrations exist any more).
     - Run `PRAGMA foreign_key_check`.
  2. Open **one PostgreSQL transaction** under the migration lock.
     - Create or upgrade the schema.
     - Refuse a target whose `database_id` equals the source's, or that holds rows in any table other than `server_state` and `login_providers` (a server that started once against the empty target has written only those two: the baseline row and the startup reconcile). `login_providers` rows are merged: the source's `display_name`, `sort_rank` and reserved columns win; `configured` is recomputed at the next start.
     - For each table in `metadata.sorted_tables` (FK order) whose lifecycle is `durable`, `history` or `reserved`:
       - stream rows through the same Core table, `executemany` in chunks of 1,000;
       - the TypeDecorators convert text uuids to `uuid`, 0/1 to boolean, JSON text to `jsonb` and BLOB to `bytea`.
     - Skip `ephemeral` tables (`oauth_codes`, `login_states`).
     - `server_state`: copy `jwt_epoch` and `settings_revision + 1`, so caches rebuild. Keep the target's own `database_id` and `compat_floor`.
     - Advance the sequences for `auth_events` and `audit_log` with transactional `ALTER SEQUENCE ... RESTART WITH max(id) + 1`; entity ids are uuids and need nothing. Unlike `setval`, `RESTART` also rolls back if importing into an already initialized empty target fails.
     - Compare row counts per table.
     - Decrypt every sealed value through `SEALED`.
  3. Commit. Any failure rolls back everything.
- There is no per-table code. The six hand-kept table lists are deleted.

### 4.14 Reserved tables and columns

The tables are created by the baseline and empty. Each has a Protocol and schema tests, and no other code: the tables exist, are empty, appear in the transfer and sealed registries, and cascade correctly.

| Feature | Schema | Interface | Why reserve it now |
|---|---|---|---|
| Canvas OAuth (institutional Developer Key) | `canvas_oauth_apps`; `canvas_credentials.kind='oauth'`, `oauth_app_id`, `access_expires_at`, `scopes`; a sealed `{access, refresh}` bundle; routes `/auth/connect/canvas/{host}` and `/auth/callback/canvas/{host}` | `CanvasCredentialRepo` (the same repo as PATs) and `CanvasOAuthAppRepo` | AAD layout, key rotation and the hot read must already cover it. Canvas refresh keeps the refresh token and returns a new access token, so a refresh is one re-seal `UPDATE`. |
| Database-stored sign-in provider configuration | `login_providers.config`, `secret_*`, `config_source`, `sort_rank` | `ProviderConfigSource`: `EnvProviderConfigSource` now, `DbProviderConfigSource` later. The registry resolves per request (3.3). | The routes are already parameterised, and the secret columns are already in the rotation registry. |
| Server-side web sessions | `web_sessions` | `SessionStore` (`create`, `get`, `touch`, `revoke`, `revoke_all`). Today's sealed cookie is the v1 implementation. | It keeps the epoch rule: a row is valid only while `session_epoch` matches. |
| Per-user quotas | `account_quotas` plus `settings` defaults (`quotas.default.<name>`, registry only) | `QuotaPolicy.limit_for(account_id, key)` behind the `RateLimiters` protocol | Counters can move to Redis without a schema change. |

### 4.15 Multi-instance readiness (Redis still reserved)

- All authoritative state is in one database. Ids need no coordinator.
- The governance lock and every row lock are database-wide.
- Every consume-once operation is a conditional statement.
- Revocation, disable, JWT epoch, settings and prefs are versioned in the per-request read, so they act at the next request on every instance with no invalidation channel.
- Still in-process:
  - rate limiters (the `RateLimiters` protocol; until Redis, the effective limit is the per-process limit x N);
  - the token-health throttle (600 s, harmless);
  - the credential-generation registry (fed by the database each request);
  - the maintenance schedule (try-locks make duplicates harmless).
- Configuration that must be identical on every instance: `CANVAS_TOKEN_KEYS` (decryption and JWT keys), `PUBLIC_BASE_URL`, `SELFHOST_LOGIN_PROVIDERS` and the provider credentials. The startup reconcile of `login_providers.configured` is last-writer-wins, and the usable-owner rule reads it, so instances with different provider lists would flip it at every start. `token_admin db check` reports the `configured` set so a rolling restart can be verified.
- `SELFHOST_STATE_BACKEND=redis` stays refused. Multiple instances also require PostgreSQL and `DATABASE_AUTO_MIGRATE=false`.

### 4.16 Out of scope for v1

- Redis, and running more than one instance; only readiness is in scope.
- Implementations of Canvas OAuth, database-stored provider configuration, server-side web sessions and quotas.
- Account self-delete and export. Account deletion from the owner panel. Erasing history rows of a deleted account.
- Linking by verified e-mail. `TRUSTED_PROXY_CIDRS`, and the client address in `auth_events`.
- `/readyz`, metrics, and `token_admin backup`.
- BRIN indexes and partitioning: the tables stay far below memory size, and keyed retention is already O(chunk).
- A row-lock protocol replacing the governance lock for credential and prefs writes. The schema permits it later without a migration.
- Per-language sign-in names (D8 chose one name; per-language names would later be an expand-step `display_names jsonb` column), certificate credentials for Entra, and `form_post`.
- An owner-editable custody notice text. The notice and its version ship with the code (step 6b).

### 4.17 Rejected alternatives

| Alternative | Why rejected |
|---|---|
| Separate `canvas_pats` and `canvas_oauth_tokens` tables | Two probes or a union on the hot path, and duplicated AAD and rotation logic |
| `UNIQUE(account, host, kind)` | Needs a rule to choose between kinds that nothing requires |
| Text uuids on PostgreSQL | About 2x the index size for nothing; `uuid` sorts the same way |
| `bigint` entity ids | Enumerable, and they complicate transfer and the AAD |
| `timestamptz` | Two representations, and harder injected clocks |
| Native enums, or value-list CHECKs on growing vocabularies | PostgreSQL enum limits, and SQLite table rebuilds |
| Compressing the refresh chain to current plus previous | Breaks detection of reuse two or more generations back (a reviewed property) |
| Embedding the grant id in the refresh token | Lets anyone who learns a grant id force its revocation |
| `UNLOGGED oauth_codes` | Losing tombstones weakens code-replay revocation |
| "Env seeds an empty database" | Hidden first-boot state, re-seeding after the owner empties a list, and disagreement between instances |
| Keeping `principal_status_events` | Duplicate bookkeeping; `ix_audit_log_subject` serves the same history |
| Keeping the 5 s and 30 s caches with a `CacheInvalidator` | Still stale across instances; the per-request read already exists |
| `SERIALIZABLE` instead of the governance lock | Retry loops everywhere, and no SQLite equivalent |
| Custody acknowledgement on `accounts`, or in its own table | On `accounts` it survives a credential delete and needs a nullable column plus a cross-row rule ("no credential unless acknowledged") that no constraint can express; a separate table adds a join to the hot read. The audit log already keeps the history. |

---

## 5. Admin-editable settings

### 5.1 Data model

| What | Where | Default |
|---|---|---|
| Sign-in method display names | `login_providers.display_name`: one name per method, shown in English and Chinese alike (D8); edited in Admin > Settings | NULL, meaning the built-in name: "Microsoft", "Google", "GitHub", or the OIDC slug |
| Featured schools (ordered) | `canvas_schools.featured_rank`, `display_name`; set only in Admin > Settings or `token_admin schools` (D6) | none: the list starts empty, nothing is seeded, and no school is preset |
| Directory search | `settings['schools.directory_search']`, bool; switched in Admin > Settings (D7) | `true` (ON) |
| Sign-in event retention | `settings['retention.auth_events_days']`, int 7..3650 | 90 |
| Audit retention | `settings['retention.audit_days']`, int 0..3650 | 0 (keep forever) |
| Operator-only private-address exemption | `canvas_schools.allow_private` | false |
| Change counter | `server_state.settings_revision` | 0 |

The registry `selfhost/server_settings.py` holds `SETTINGS: dict[str, SettingSpec(type, default, validate, sensitive, editable_in_panel)]`. Of the `SETTINGS` keys, only `schools.directory_search` is `editable_in_panel` in v1 (D7); the retention keys are editable through `token_admin`. Featured schools (D6) and sign-in method names (D8) are not `SETTINGS` keys: they have their own tables and their own panel cards (5.7).

### 5.2 Precedence and removed environment variables

- **Precedence: database, then code default.** The environment is not a layer.
- **Removed** (startup refusal, 2.3):
  - `CANVAS_FEATURED_SCHOOLS` (D6), `CANVAS_SCHOOL_SEARCH` (D7), `OIDC_<SLUG>_DISPLAY_NAME` (D8);
  - `CANVAS_API_URL` in self-host mode. Upstream modes keep it and never import the data layer.
- **Why not "env seeds an empty database":**
  - After the owner empties the featured list, the next restart would re-add the schools unless a hidden "seeded" marker existed.
  - Restores and several instances would disagree.
  - Nothing is deployed, so there is nothing to carry over.
- **The old `CANVAS_API_URL` roles map as follows:**
  - "default school" disappears together with hostless rows;
  - a single-school deployment is one featured school with search off (`SchoolPolicy.sole_school` auto-selects it);
  - the DNS exemption for an internal host becomes `allow_private`, set only with `token_admin schools add <host> --allow-private`.
- **Headless setup**, using the same repo methods, governance tier and audit rows (actor `operator`):
  - `token_admin schools list|add|remove|move|rename|allow-private on|off`
  - `token_admin providers list|rename|reset-name`
  - `token_admin settings get|set|reset`

### 5.3 Validation

- **Sign-in names** (the handoff 6.2 rules, unchanged):
  - String; NFC; trimmed; whitespace collapsed.
  - 1-40 characters and at most 160 UTF-8 bytes.
  - Reject categories Cc, Cf (bidi overrides, zero-width, BOM), Cs, Co, Cn, Zl and Zp; other Zs become a space.
  - At least one letter or digit.
  - Reject `<`, `>`, `{`, `}`. Allow `&` and quotes; they are escaped on output.
  - Effective names must be unique by `casefold` across configured providers. Empty or null means reset.
  - Names for unconfigured providers are refused by the PUT.
- **Featured schools:**
  - `parse_hostname`, `is_blocked_hostname`, then `check_public_host`, unless the row is `allow_private`.
  - Name: 0-120 characters (the column limit, equal to `schools.MAX_SCHOOL_NAME`; the removed env parser and handoff 6.3 allowed 80 via `settings.MAX_FEATURED_NAME_CHARS`, which goes away), no control characters; empty means the host.
  - No duplicates; at most 50.
  - The directory lookup is advisory only: `directory_unavailable` never blocks.
  - Entries are re-validated when the snapshot is built, and enrollment repeats the DNS check.
- **Typed settings:** `SettingSpec.validate` checks type and range, and refuses NUL characters. Values are at most 8 KiB.
- **Every write** runs the owner-action pipeline:
  - fresh sign-in within 10 minutes;
  - CSRF, `Origin`, `Sec-Fetch-Site`;
  - `application/json`;
  - body cap: 8 KiB, or 32 KiB for the schools PUT;
  - in-transaction owner re-check;
  - the `settings_revision` CAS.

### 5.4 Audit

There is one audit row per save, written in the same transaction, and none for a refusal. `actor_kind` is `account` or `operator`.

| Action | `target_kind` / `target_id` | `detail` |
|---|---|---|
| `sign_in_method_renamed` | `provider` / provider id | `old`, `new` (free text is stored; names are validated and public, which answers handoff Q-R1-2) |
| `featured_schools_changed` | `setting` / `featured_schools` | `added`, `removed`, `renamed`, `reordered`, `affected_enrollments` |
| `setting_changed` | `setting` / key | `old`, `new` (omitted when `sensitive`) |
| `school_access_changed` | `school` / host | `allow_private` old and new (operator only) |

Add the new actions (and the status-event actions of 4.3.10 and `account_deleted` of 7.1) to `AUDIT_ACTIONS`, to `web/src/views/admin/AdminAuditView.tsx` `KNOWN_ACTIONS`/`KNOWN_DETAIL_KEYS`, and to `locales/{en,zh}/admin.json`. Also fix the existing gap: the `identity_*` actions are missing there (handoff 6.13). The custody audit rows (D10) are specified in step 6b.

### 5.5 Cache invalidation

- Every settings, school or provider-name write bumps `server_state.settings_revision` in the same transaction; it is the CAS itself.
- Every request surface reads the revision in a read it already makes:
  - the MCP hot statement;
  - the `/api/v1` session read;
  - the `/auth/*` `server_state` probe.
- The process keeps one immutable `ConfigSnapshot`: `SchoolPolicy`, the provider display list and the typed settings, tagged with its revision. A different revision rebuilds it with three small reads.
- **Failure rules (fail closed):**
  - The first build happens in `prepare_selfhost` after `ensure_ready`. Failure refuses startup.
  - A later rebuild failure answers 503 for that request, and the next request retries.
  - There is never a "not loaded" state and never "allow all".
- Writes in the same process replace the snapshot right after commit. Other processes, including `token_admin`, are picked up at their next request. There is no TTL and no invalidation channel.

### 5.6 API (owner unless marked)

| Method and path | Body | Result and errors |
|---|---|---|
| `GET /api/v1/admin/settings` | | `{revision, sign_in_methods: [{id, protocol, icon, configured, default_name, display_name, effective_name}], schools: {directory_search, featured: [{host, display_name, rank, enrollments, allow_private}], warnings: [...]}, retention: {...}}` |
| `PUT /api/v1/admin/settings/sign-in-methods` | `{revision, names: {"entra": "Contoso staff", "google": null}}` (string sets, null or "" resets, an absent key is unchanged) | new block. `settings_conflict` (409, `params.revision`), `validation_failed` (`field`, `reason`) |
| `PUT /api/v1/admin/settings/schools` | `{revision, featured: [{host, display_name}], confirm_affected: [host...]}` (the whole ordered list) | new block plus `affected_enrollments`. `confirmation_required` (409, `params.affected`) when search is off and a removed host has enrollments that are not confirmed. Also `school_invalid`, `school_unresolvable`, `school_address_blocked`, `settings_conflict`. |
| `POST /api/v1/admin/settings/schools/check` | `{host}` | `{valid, reason?, suggested_name?, in_directory: true|false|null}`, nothing saved. Rate-limited per account like `search_limiter`. |
| `PUT /api/v1/admin/settings/directory-search` | `{revision, enabled}` | new block |
| `GET /api/v1/providers` (public) | | effective names |
| `GET /api/v1/me/schools` (active) | | `{mode: picker|sole|none, choices, selected, sole, search_enabled}` (today `mode` is `picker|sole|fixed`, and `choices` entries carry `host`, `name` and `source`; `fixed` goes with the default school and `none` is new). `selected` is the user's current school if still offered, else `null`; nothing is preselected otherwise. |

Add the new codes to `account_api.ERROR_STATUS`, `web/src/api/errors.ts` and `locales/{en,zh}/errors.json`. Update `contract.ts`, `endpoints.ts`, `dev/mockServer.ts` and the parity and contract tests: `test_account_api_parity.py`, `test_account_api_contract.py`, `contract.test.ts`, `localeParity.test.ts`.

### 5.7 UI and CLI touchpoints

- **React:**
  - `web/src/views/admin/AdminSettingsView.tsx` at `/account/admin/settings`: a route in `router/index.tsx` and a fourth tab in `layouts/AdminLayout.tsx`.
  - "Sign-in methods" card: icon, default as the placeholder, text field with a counter, inline duplicate check, Save, Reset.
  - "Schools" card: table of host, name and enrollment count; add with "Check"; rename; move up and down; remove with a confirmation dialog stating "N people will stop being able to use this server until they enroll at another school" when search is off.
  - "Directory search" switch, stating that the typed query is sent to `canvas.instructure.com`.
  - `allow_private` is shown read-only.
  - `reauth_required` shows `ReauthNotice`. `settings_conflict` shows "changed elsewhere, reload". A successful save invalidates the `providers` and `schools` queries.
  - Strings go in `locales/{en,zh}/admin.json`.
  - `dev/mockServer.ts`: the default scenario has no featured school and `selected: null`; add a `featured` scenario.
- **Every server site that printed "Microsoft" or a frozen name** reads the snapshot instead. This is the handoff 6.2 table:
  - `login/registry.py` `LoginRuntime.entries()`;
  - `account_api.py` `providers()`;
  - `accounts.DENIAL_MESSAGES` via `render_denial(code, entra_name)`;
  - `principal_access.access_not_provisioned_message()`;
  - `request_context.not_enrolled_message()` via `names.primary_phrase()`;
  - the new `school_not_offered_message()`.
- **School sites** (handoff 6.3 "preset path 4"): `account_api.get_schools` selection, `account_web._choose_school`'s silent default (an empty school in picker mode is `school_required`), and `SchoolPolicy.build` no longer prepending a default.
- **CLI:** the `token_admin` subcommands of 5.2. `check` prints a settings summary. `--config` (`server.py` `_selfhost_summary`) says "schools and sign-in names are managed in the database (Admin > Settings)".
- **Legacy pages**: removed in step 2 (D5). The "Legacy" halves of handoff 6.2 and 6.3 do not apply. `account_web._choose_school` goes with them, or moves to `account_core.py` if the API still uses it, keeping the rule above.

### 5.8 Behaviour rules

- **Fresh install:** no featured school (D6), search on (D7). Users find their school through the Instructure directory until the owner features schools or switches search off in Admin > Settings. No school, not even an example one, is preset in code, `env.example`, `setup-env.sh`, mocks or test defaults.
- **Zero offered schools** (no featured school and search off): the server starts, logs a warning and shows an admin banner. Enrollment answers "no school is offered".
- **Removing a featured school:**
  - With search on, only the quick pick disappears.
  - With search off, enrolled users become "school not offered". Their encrypted rows are kept, re-featuring restores access at the next request, and the MCP message is the new host-free `school_not_offered_message()`.
  - The PUT requires `confirm_affected` for every such host. This answers handoff Q-R2-5 with "yes".
- **`allow_private`** is never settable from a web session.
- **The startup refusal "nothing offered"** (`app._school_problems`) becomes a warning.

### 5.9 Relation to the handoff

- **Answers.**
  - Q-R2-1: env removed (not seed).
  - Q-R2-2: `CANVAS_API_URL` removed in self-host mode.
  - Q-R2-3: start with a warning.
  - Q-R2-4: search is database-controlled, admin-editable and ON by default (D7), which supersedes the earlier env-only recommendation.
  - Q-R2-5: yes.
  - Q-R1-1: one name per method for both languages (D8).
  - Q-R1-2: yes.
- **Still open:** none.
- **Still valid:** the 6.2 and 6.3 site inventories, validation details, acceptance lists and test lists, except the parts about `server_settings`, env seeds, `DELETE` "use environment list" and the 5 s TTL.

---

## 6. Implementation plan

### 6.0 Prerequisites

- **P7 merged** into `uci-student` (handoff 6.1 [B0], findings F1-F4 closed). P7 is at `53b86dd`; its last fix round passed the full matrix but has not been independently reviewed, and every earlier review round found new owner-recovery edge cases. Merge it only after one more independent review of that round. v1 touches the same files (`accounts.py`, `identity.py`, `token_store.py`, `app.py`, `settings.py`, `request_context.py`, `account_web.py`, `login/*`, README, smoke test). Building v1 first would make P7 a rewrite.
- Branch `feature/v1-consolidation` from `uci-student`, in worktree `.worktrees/v1`.
- **One step (D1).** Steps 1 to 8 are an order of work inside one consolidation, not separate releases. Their pull requests target `feature/v1-consolidation`; it merges into `uci-student` once, when the step 8 release gate is green. No step ships alone, and there are no aliases, compatibility shims or transition releases.
- Do not push half-finished work to `uci-student`, because it publishes `:edge`.
- The owner decisions D1-D14 (1.1) settle every design question; nothing in section 7 blocks step 1. Implementer decisions with recommended defaults are listed in 7.1.

### 6.1 Test matrix (every step)

- `{dev venv (fastmcp 4.0.10, mcp 2.2.0), lock-pinned venv (fastmcp 4.0.3, mcp 2.1.1)} x {SQLite, PostgreSQL}` (handoff 2.2 and 2.4).
- `ruff check src/ tests/`, `mypy src/`, `uv lock --check`.
- `web/` lint, typecheck, vitest, build, `check:dist` when `web/` or the API changed.
- `test_english_only.py`, closing-keyword tests, and `git diff origin/main -- tests/security/test_course_cache_isolation.py` empty.
- `test_dependency_isolation.py` green: upstream modes import no SQLAlchemy, Alembic or psycopg. `settings.py`, `routes.py` and `login/config.py` stay standard library only.

### Step 1: local-only authorization

- **Files:** everything in 2.2 and the config and wiring items of 2.6; `settings.py` `REMOVED_SETTINGS` (2.3); `authz/runtime.py` (`build_auth_provider`); `pyproject.toml`, `uv.lock`. The D9 renames (`MCP_AUTH_MODE=selfhost`, `MCP_SCOPE`) across the sites of the 2.2 rename table, including the `core/cache.py` and `core/credentials.py` docstrings, keeping the upstream diff minimal; `settings.auth_mode()` refuses `entra-oauth` with the rename hint.
- **Tests:**
  - Delete, move, edit and rewrite per 2.2.
  - New `tests/selfhost/test_removed_settings.py`: each name in 2.3 produces exactly one problem naming the setting and no value; an empty value counts as present; `FASTMCP_HOME` is not refused. Renames: `ENTRA_API_SCOPE` is refused with a message naming `MCP_SCOPE`, also when `MCP_SCOPE` is set; `MCP_AUTH_MODE=entra-oauth` is refused by `auth_mode()` with a message naming `MCP_AUTH_MODE=selfhost`, both at server start and under `--config`; `MCP_AUTH_MODE=selfhost` starts the self-host mode; `legacy` and unset keep the upstream modes; an unset `MCP_SCOPE` gives `Canvas.Access`, and an invalid one is refused with the format message.
  - Smoke test (n) adds `MCP_AUTH_MODE=entra-oauth` and `ENTRA_API_SCOPE` to the refusal cases; `test_smoke_script_contract.py` follows.
  - Route-table test: no `/consent`, no bare `/auth/callback`.
- **Acceptance:**
  - [ ] `grep -rn "entra_proxy\|OAuthProxy\|AzureProvider\|FASTMCP_HOME\|OAUTH_JWT_SIGNING_KEY\|SELFHOST_AUTH_MODE" src/ web/src deploy/` finds only `REMOVED_SETTINGS`, the refusal tests (including section (n) of `deploy/selfhost/smoke-test.sh`), the README sentence that says these settings are refused, and CHANGELOG history.
  - [ ] `git grep -n "entra-oauth\|ENTRA_API_SCOPE"` finds only the refusal code, its tests, smoke test (n), the README sentence on renamed settings, CHANGELOG history, `internal/` and `proposals/` (D9).
  - [ ] `py-key-value-aio` is not a direct dependency, and `uv lock --check` is green.
  - [ ] The rewritten `tests/test_multiuser_e2e.py` passes on both backends in the CI PostgreSQL job.
  - [ ] Full matrix green.

### Step 2: legacy UI removal (D5, mandatory)

The React app becomes the only account UI. Step 2 runs before steps 3, 6 and 6b, so that the route move, the admin settings and the custody form are built once, in the SPA only.

- **Files:**
  - `account_web.py`: keep the session, CSRF and Origin guards and the consent logic, moved to `account_core.py`; delete the HTML renderers, `_bi` pages, form routes and `ACCOUNT_UI` fallback. The Entra sign-in routes and the sealed `__Host-cmcp_login` ceremony (and, on P7, the per-provider start and callback routes) move unchanged with the shared logic and stay at their old paths until step 3 replaces them.
  - `account_spa.py`: a missing or invalid bundle refuses startup.
  - `settings.py`: `ACCOUNT_UI` goes into `REMOVED_SETTINGS`.
  - `tests/test_english_only.py`: the allowlists shrink.
  - Docs.
- **Tests:** delete the legacy page tests (`test_account_web*.py`, `login/test_legacy_ui.py`, golden pages); keep the API and SPA tests; add a startup test for a missing bundle; `ACCOUNT_UI` (any value) is refused (`test_removed_settings.py`).
- **Acceptance:**
  - [ ] `ACCOUNT_UI` appears only in `REMOVED_SETTINGS`, its test and the README sentence on removed settings.
  - [ ] No HTML is rendered by Python except a minimal static 400 for an unusable ceremony.
  - [ ] Every user-visible function is reachable in the SPA.
  - [ ] `account_ops` outcome types are still used by the API.

### Step 3: routes

- **Files:**
  - New `selfhost/routes.py` and `selfhost/login/routes.py`.
  - `login/registry.py`, `login/entra.py` (Entra profile on `flows.py`), `login/google.py`, `login/github.py`, `login/oidc.py`.
  - `authz/server.py` (login redirect and bind-cookie prefix), `account_api.py` (`/api/v1`), `account_spa.py`, `edge_guard.py` (HEAD refusal on `/auth/*`, Entra bucket), `token_admin.py` (callback URLs).
  - The `web/` files of 3.8; `deploy/selfhost/{nginx.conf.example,Caddyfile.example,smoke-test.sh,README.md}`.
- **Tests:**
  - New `test_route_contract.py` (3.8).
  - Route-table test for the complete table in 3.2.
  - Ceremony tests per provider: `state` mismatch, provider mismatch between record and path, `iss` mismatch, replay, expiry, other browser, `return_to` with `/api/` or `/auth/` refused, HEAD gives 405, an unconfigured provider gives 404 with no `login_states` row written.
  - Entra-specific tests on the flow engine: `tid`, `roles`, `oid`, and the B2B guest claims fixture.
  - `test_smoke_script_contract.py`; vitest for client, endpoints and `returnTo`.
- **Acceptance:**
  - [ ] Every path in `nginx.conf.example`, `Caddyfile.example`, `smoke-test.sh`, the README and `web/src` exists in `routes.py`.
  - [ ] Entra start redirects with `redirect_uri=<base>/auth/callback/entra`; bare `/auth/callback` is 404.
  - [ ] `__Host-cmcp_login` no longer exists anywhere.
  - [ ] The image smoke test is green.

### Steps 4 and 5: data layer v1 and the store port (one pull request)

The schema change breaks every repository, so these land together. Commits inside the PR may be red, but the PR head must be green on the full matrix.

**Step 4 files:**
- New `db/types.py`, `db/vocab.py`, `db/sealed.py`.
- `db/schema.py` (section 4 metadata, naming convention, `Table.info`).
- `db/migrations/versions/0001_v1_baseline.py`; delete the three old revisions, `baseline_v4.py` and `accounts_v5.py`. The baseline already contains the D10 custody columns of `canvas_credentials` (4.3.8), so step 6b adds no revision.
- `db/migrate.py` (4.12).
- `db/engine.py`: SQLite pool and pragmas, version check, creation pragmas, FK assertion, FK-off migration connection, 250 ms best-effort path; PostgreSQL pool and `STORE_LIMITER`; `GOVERNANCE_LOCK_KEY`; maintenance try-lock helper; delete `best_effort_write(lock=True)`.
- `db/url.py` unchanged.

**Step 5 files:**
- `db/ports.py` (Protocols returning frozen dataclasses), `db/repos.py`, `db/authz_repos.py`.
- `token_store.py`:
  - single account key;
  - `canvas_credentials` with AAD v1; the credential put takes the custody acknowledgement (`notice_version`, `acked_at`) as a required argument and writes both columns (the API and UI wiring is step 6b);
  - the generation invariant helper;
  - `RETURNING` bumps;
  - audit with actor, subject and target, absorbing status events;
  - `account_write_tools`;
  - account deletion;
  - tier changes for health writes.
- `authz/store.py`: `FOR NO KEY UPDATE`, `has_rotated_child(grant_id, ...)`, `DELETE ... RETURNING` pop, revoke-all using the code index and keeping its codes-first order, `jwt_epoch` read inside the `/token` transactions, `SKIP LOCKED` touches.
- `authz/models.py`, `authz/grants.py` (remove `GrantStatusCache`), `authz/tokens.py` (delete `EpochSource`; verify with the key derived for the token's `kid` epoch; the 10-digit epoch cap), `authz/runtime.py` (no `epoch` field; `bump_jwt_epoch` no longer invalidates a cache), `authz/server.py` `load_access_token` (the request-context read).
- `db/engine.py`: the per-process governance gate for PostgreSQL G transactions (4.6).
- `request_context.py`, `principal_access.py`, `tool_gate.py`, `tool_prefs.py` (versioned LRU), `token_health.py`, `identity.py`, `login/linking.py`, `login_state.py` (bytes payload).
- `token_admin.py`: `db current` shows `database_id`, `compat_floor` and `SCHEMA_EPOCH`; new `db check` (FK check, floor, sealed probe); `accounts delete`; `history` reads the audit log.
- `core/credentials.py` (trimmed `RequestPrincipal`).

**Tests to write** (all on both backends unless marked):
- `tests/selfhost/test_v1_schema.py`:
  - `compare_schema() == []`;
  - golden DDL for both dialects;
  - one test per CHECK, FK, unique and partial-unique constraint (a violating insert raises `IntegrityError`);
  - cascade from `accounts` and from `oauth_grants`;
  - `RESTRICT` toward `login_providers`, `canvas_schools` and `canvas_oauth_apps`;
  - reserved tables exist and are empty;
  - STRICT and WITHOUT ROWID read from `sqlite_master` (SQLite);
  - `reloptions`, `relpersistence='u'` and the autovacuum parameters (PostgreSQL);
  - constraint names follow the convention;
  - every table has `Table.info["lifecycle"]`, and every `*ciphertext` column is sealed.
- `tests/selfhost/test_v1_engine.py`: `foreign_keys=1` on every pooled connection after reuse; `trusted_schema=0`; `auto_vacuum=2` and `application_id` on a new file only; SQLite older than 3.37 refused (monkeypatched `sqlite3.sqlite_version_info`); the migration connection has FKs off and fails on a `foreign_key_check` violation; the best-effort path returns within about 300 ms while another connection holds `BEGIN IMMEDIATE` (it used to stall 5.5 s), and the next statement on that pooled connection runs with `busy_timeout=5000` again, also after the best-effort statement raised; an `auth_events` table created by the baseline still says `AUTOINCREMENT` in `sqlite_master` after a test batch rebuild that passes `table_kwargs` (4.12).
- `tests/selfhost/test_v1_migrate.py`: each state of the 4.12 table, including pre-v1 refusal, newer-within-floor runs, and too-new refused; `DATABASE_AUTO_MIGRATE=false`; concurrent migrators on PostgreSQL.
- `tests/selfhost/test_repo_statements.py` (extend): every statement compiles for PostgreSQL; G-tier transactions start with the governance lock; tier-1 transactions never take it; explicit account locks render `FOR NO KEY UPDATE`; no statement uses `IN (SELECT ... LIMIT)` for deletes.
- `tests/selfhost/test_rows_by_name.py`: an AST lint that refuses integer subscripts on result rows and `*tuple(row)` in `selfhost/db`, `selfhost/authz`, `token_store.py` and `request_context.py`.
- `tests/selfhost/test_request_context_read.py`:
  - exactly one SQL statement per steady-state MCP request, counted with an SQLAlchemy `before_cursor_execute` listener, and zero writes when `last_used_at` is fresh;
  - one touch when stale;
  - (added in step 6, when the snapshot exists) a revision change rebuilds the snapshot before the credential check: a credential at a non-featured host is served while directory search is on, refused with `school_not_offered_message()` right after search is turned off in another "instance", and served again when the host is featured;
  - using two `Database` objects on the same database as two "instances": disable, grant revoke, `rotate-jwt-key`, a write-tools change and a featured-school removal on one are visible on the other at the next request;
  - 401, 403 and 503 mapping identical to today.
- `tests/selfhost/test_v1_races.py` (PostgreSQL, real concurrency, with `deadlock_timeout` lowered to 200 ms in the test session so a lock-order regression fails fast): the fourteen races of 4.6. SQLite variants where they apply.
- `tests/selfhost/authz/test_tokens.py` (extend): a token whose `kid` epoch is below, equal to or above `server_state.jwt_epoch` verifies cryptographically, and only "equal" passes the request-context read; a `kid` epoch longer than 10 digits is refused before any key derivation; `rotate-jwt-key` on one `Database` refuses the next request on another with no wait.
- `tests/selfhost/test_sealed_v1.py`: AAD binding (changing account, host, kind or key id makes decryption fail); rotation across all sealed tables; startup probe.
- Port, rather than delete, the coverage of `test_token_store.py`, `test_store_races.py`, `test_store_owner_recheck.py`, `test_credential_generation.py`, `test_tool_prefs_store.py`, `authz/test_authz_store.py`, `authz/test_authz_races.py`, `authz/test_code_epoch.py`, and the P7 `login/test_link_store.py` and bootstrap tests.
- **Optional, PostgreSQL only:** plan assertions (index names in `EXPLAIN`) for the hot statement, refresh lookup, `has_rotated_child`, the auth-event walk and the grant cull.

**Acceptance:**
- [ ] One baseline revision. `alembic history` is linear with one entry, and none of the deleted files exist.
- [ ] `compare_schema` is clean and the golden DDL matches on both backends.
- [ ] No positional row access remains (lint green).
- [ ] The P6 binding, refresh rotation, reuse revocation and usable-owner tests pass unchanged in intent on both backends and both runtimes.
- [ ] The hot path is one statement, and revocation is immediate across "instances".
- [ ] `test_v1_races.py` is green on PostgreSQL, run 20 times in a loop without a failure, and the PostgreSQL server log of those runs contains no `deadlock detected`.
- [ ] Every statement that writes `oauth_codes` in a transaction that also locks an account precedes the account lock (code review item, pinned by race 11).

### Step 6: admin-editable settings

- **Files:**
  - New `server_settings.py`: `SETTINGS`, validators, `ConfigSnapshot`, `SnapshotProvider`.
  - `db/repos.py`: `SettingsRepo`, `SchoolRepo`, `LoginProviderRepo`, `ServerStateRepo`.
  - `token_store.py`: owner-action methods with the CAS.
  - `app.py`: startup reconcile, first snapshot, `_school_problems` turned into a warning.
  - `schools.py`: `SchoolPolicy` from the snapshot, no default prepend.
  - `request_context.py`: the school check and `school_not_offered_message()`.
  - `account_api.py`: the endpoints of 5.6.
  - `login/registry.py` and every name site of 5.7.
  - `token_admin.py`: `schools`, `providers`, `settings`.
  - `deploy/selfhost/setup-env.sh`: no school prompts; prints "add schools in Admin > Settings".
  - `env.example`, README.
  - `web/` per 5.7.
- **Tests:**
  - `tests/selfhost/test_server_settings.py`: validators, registry, snapshot rebuild on revision change, fail-closed rebuild, CAS conflict, owner re-check, operator actor, audit rows and no audit on refusal.
  - `tests/selfhost/test_server_settings_api.py`: access matrix (non-owner, pending owner, stale session, CSRF, Origin, content type, oversize body, unknown provider, duplicate name, bidi or control characters, `<`/`{`); one "the name appears" test per surface, and the same name in the English and the Chinese UI (D8); the removal-confirmation guard; `/me/schools` with no featured school gives `selected: null`.
  - Fresh database (D6, D7): `GET /api/v1/admin/settings` returns `featured: []` and `directory_search: true`, `canvas_schools` has no featured row, and `settings` has no row; switching search off and on through the panel takes effect at the next request in another "instance".
  - `tests/selfhost/test_token_admin_settings.py`.
  - Startup reconcile: listed, unlisted and display name untouched.
  - The handoff 6.2 and 6.3 acceptance items that still apply.
  - vitest for `AdminSettingsView`, `SignInView`, `SchoolPicker`, `LoginHistory`, and `localeParity`.
- **Acceptance:**
  - [ ] A fresh install features no school and has directory search ON; no school is preset in code, `env.example`, `setup-env.sh` output, mocks or test defaults (D6, D7). Tests that need a featured school create it through the repo, with a neutral host such as `canvas.example.edu`.
  - [ ] The directory search switch and the featured list are editable in Admin > Settings; sign-in method names too, one name per method (D8).
  - [ ] Every removed variable refuses startup with a pointer to the panel or the CLI.
  - [ ] A rename or school change is visible without restart on every surface, including another process.
  - [ ] Concurrent saves: one wins, the other gets `settings_conflict`.
  - [ ] Names render escaped everywhere (`A & "B"`).
  - [ ] `allow_private` cannot be set through `/api/v1`.

### Step 6b: Canvas token custody acknowledgement (D10)

The schema columns are in the baseline (4.3.8) and the store put takes the acknowledgement (step 5). This step wires the notice, the API, the SPA, the MCP check and the audit.

- **Notice.**
  - `selfhost/custody.py` (new, standard library): `CUSTODY_NOTICE_VERSION = 1` and `custody_ack_required_message()`.
  - The text lives in `web/src/locales/{en,zh}/account.json` under `custody.v<N>`. It states: (1) the operator of this server can technically decrypt the stored Canvas token and could use it to act as the user in Canvas; (2) create the token for this server only, with an expiry date; (3) how to revoke: delete it in Canvas (Account > Settings > Approved Integrations), and delete it here with "Delete token", which removes the stored copy at once.
  - English draft for v1: "The operator of this server can technically decrypt the Canvas token you store here and could use it to act as you in Canvas. Create a token for this server only, and give it an expiry date. To revoke it, delete it in Canvas under Account > Settings > Approved Integrations, and delete it here with Delete token, which removes the stored copy immediately."
  - **Version rule.** Bump `CUSTODY_NOTICE_VERSION` for any change of substance (what the operator can do, the advice, the revocation steps). A wording fix that keeps the meaning keeps the version. `tests/selfhost/test_custody_notice.py` pins a SHA-256 of the English and Chinese text per version, so any text edit fails until a reviewer updates the pin and decides about the bump.
- **API contract (`/api/v1`).**
  - `GET /me/canvas-token` adds `custody: {notice_version, acknowledged_version, acknowledged_at, current}`. `notice_version` is the server's current version; the `acknowledged_*` fields are `null` when nothing is enrolled; `current` is `acknowledged_version == notice_version`.
  - `GET /me` adds `custody_ack_required` (enrolled and not current), for a banner on every page.
  - `PUT /me/canvas-token` requires `custody: {acknowledged: true, notice_version: <int>}`. It is checked after the session, CSRF, `Origin`, content-type and body-shape checks, and before the school check, any outgoing Canvas request and any write. Missing, or `acknowledged` not exactly `true`: 422 `custody_ack_required`. `notice_version` other than the current one: 409 `custody_notice_outdated` with `params.notice_version`. A refusal writes nothing and is not audited (5.4 rule).
  - On success the put's transaction writes `custody_notice_version = CUSTODY_NOTICE_VERSION` and `custody_ack_at = now` (server clock; the client never supplies a time), and the `token_enrolled` or `token_replaced` audit row carries `detail.custody_notice_version`.
  - `POST /me/canvas-token/acknowledge`, body `{notice_version}`: active session, CSRF, same version check. No credential: 404 `not_enrolled`. Writes per 4.6 plus one `custody_notice_acknowledged` audit row (target `credential` / id, `detail.old`, `detail.new`). Acknowledging the version already recorded is a 200 with no write and no audit row.
  - `GET /admin/enrollments` rows add `custody_notice_version`, `custody_ack_at` and `custody_current`. `token_admin list` adds the version column, and `token_admin db check` reports the number of credentials below the current version.
  - Add the codes to `account_api.ERROR_STATUS`, `web/src/api/errors.ts` and `locales/{en,zh}/errors.json`; update `contract.ts`, `endpoints.ts`, `dev/mockServer.ts` (default scenario: not enrolled, notice v1; new scenario `custody_outdated`) and the parity and contract tests of 5.6.
- **React** (`web/src/views/TokenView.tsx`, new `web/src/components/CustodyNotice.tsx`):
  - The notice for the server's `notice_version` sits above the token field, followed by a required MUI `Checkbox` ("I have read this notice"). It is unchecked on every mount; Save stays disabled until it is ticked; the PUT sends `custody`.
  - On `custody_notice_outdated` the view refetches, shows the new notice and unticks the box.
  - Enrolled with `current: false`: the notice, the checkbox and an "Acknowledge" button calling the acknowledge endpoint. A banner driven by `/me.custody_ack_required` links every page to `/account/token`.
  - Strings in `locales/{en,zh}/account.json`. `custody_notice_acknowledged` and `custody_notice_version` join `AdminAuditView.tsx` `KNOWN_ACTIONS`/`KNOWN_DETAIL_KEYS` and `locales/{en,zh}/admin.json`.
- **MCP.** `request_context.py`/`tool_gate.py` apply the 4.5.1 step 7 check with `custody_ack_required_message()`. It adds no statement: the version comes from the hot read.
- **Audit.** `custody_notice_acknowledged` joins `AUDIT_ACTIONS`. The audit log is the acknowledgement history (actor, credential, version, `at`); with `retention.audit_days` at its default 0 it is kept forever.
- **Tests** (both backends and both runtimes, 6.1):
  - `tests/selfhost/test_custody_ack.py`:
    - a credential insert without either custody column, or with version 0, raises `IntegrityError` (also listed in `test_v1_schema.py`);
    - PUT without `custody`, with `acknowledged: false` or a non-boolean, or with a stale version: the right code, and no credential row, no school upsert, no audit row and no outgoing Canvas request (asserted on the HTTP mock, not only on the response text);
    - success: both columns equal the current version and the injected clock; the audit row is in the same transaction; a replace records a new acknowledgement; delete then re-enroll requires a new one;
    - version bump (monkeypatched `CUSTODY_NOTICE_VERSION = 2`): the next MCP request is refused with `custody_ack_required_message()`, without decryption and without a Canvas request; `GET /me/canvas-token` shows `current: false`; acknowledging v2 restores service at the next request on another "instance" without re-entering the token; acknowledging v1 afterwards gives 409; the audit row says `old: 1, new: 2`;
    - access matrix of the acknowledge endpoint: pending, disabled, stale session, CSRF, `Origin`, content type.
  - `test_custody_notice.py`: the hash pins; both locales contain `custody.v<CUSTODY_NOTICE_VERSION>`.
  - `test_request_context_read.py`: still one statement per request with the custody check.
  - `test_transfer_v1.py` copies both columns; `test_sealed_v1.py`: rotation leaves them unchanged.
  - vitest: `TokenView.test.tsx` (Save disabled until ticked, unticked on mount and after `custody_notice_outdated`, the body carries `custody`, the outdated state shows Acknowledge), `CustodyNotice.test.tsx`, `localeParity`.
- **Acceptance:**
  - [ ] No path stores a Canvas token without recording the current notice version and the time; on both backends the schema makes it impossible.
  - [ ] Without the ticked checkbox the PUT is refused before any Canvas request or write.
  - [ ] Every acknowledgement is in the audit log with actor, credential, version and time.
  - [ ] After a version bump, MCP requests under an older acknowledgement are refused with a message naming `/account/token` until the user acknowledges; no stored token is lost.
  - [ ] The notice states the three D10 points in English and Chinese.

### Step 7: maintenance and transfer

- **Files:** new `maintenance.py` (jobs of 4.8, budgets, try-locks); `edge_guard.py` (calls the runner); `db/transfer.py` (4.13, registry-driven); `token_admin.py` (`db import-sqlite` output).
- **Tests:**
  - `tests/selfhost/test_maintenance.py`: each job deletes only due rows; step 2 repeats the due predicate (a row made not-due between the steps survives); chunking; budget stop and resume; try-lock skip (PostgreSQL); cascade removes refresh tokens; the auth-event walk with one not-due row (skewed `at`) at the lowest id still deletes every due row behind it in one run, and stops at a chunk whose last row is not due; orphan school cull respects featured, `allow_private`, credentials and apps; an `IntegrityError` in a chunk ends the job for the run without raising; `incremental_vacuum` after large deletes (SQLite).
  - `tests/selfhost/test_transfer_v1.py`: full copy of every lifecycle table, sequences advanced, counts, sealed decrypt, rollback on an injected failure, refusal of a non-empty target or the same `database_id`, ephemeral tables skipped.
  - Keep `test_silent_switch.py`.
- **Acceptance:**
  - [ ] No maintenance statement runs under the governance lock except the pending purge.
  - [ ] No unbatched delete remains.
  - [ ] Import of a populated SQLite file into PostgreSQL round-trips on both runtimes.

### Step 8: reserved interfaces, docs, release gate

- **Files:**
  - Protocols in `db/ports.py` (`CanvasCredentialRepo`, `CanvasOAuthAppRepo`), `login/registry.py` (`ProviderConfigSource`), `account_core.py` or `account_web.py` (`SessionStore`), `limits.py` (`QuotaPolicy`).
  - `deploy/selfhost/README.md`: architecture, Entra step 1 (2.5, including inviting friends as B2B guests with `Canvas.User`), routes, settings (featured schools start empty, directory search ON, both in Admin > Settings), the custody notice (D10), the renamed and removed settings with their replacements (2.3, D9), upgrading ("v1 starts from a fresh database"), backup ("schools, sign-in names and custody acknowledgements live in the database").
  - `env.example`, `setup-env.sh` (writes `MCP_AUTH_MODE=selfhost` and, only if asked, `MCP_SCOPE`), `Dockerfile.selfhost`, `docker-compose*.yml`, `CHANGELOG.md` (the v1 entry lists every rename and removal), `web/README.md`, `tests/test_selfhost_docs.py` (reduced).
  - **Neutral examples (D11).** In `deploy/selfhost/*` (README, `nginx.conf.example`, `Caddyfile.example`, `env.example`, `setup-env.sh`, `smoke-test.sh`), `web/README.md` and the fork-owned docs, the public host is `mcp.example.com` and the Canvas host is `canvas.example.edu`. At P7 `53b86dd` this replaces the owner's real host (15 occurrences in `deploy/selfhost/README.md`, 5 in `nginx.conf.example`, 1 in `Caddyfile.example`), UCI's Canvas host (2 in `deploy/selfhost/README.md`) and the placeholder `canvas.school.edu` (`README.md`, `env.example`, `setup-env.sh`). Re-run the search at the merge commit. The root `README.md` is upstream text and keeps its hosts; web test fixtures may keep their placeholder hosts.
  - **Fork statement (D12).** The name stays `canvas-mcp`. The first paragraph of `deploy/selfhost/README.md` says that this is an independent fork of `vishalsachdev/canvas-mcp`, not endorsed by upstream, and that only small core improvements are offered upstream. Recommended: the same one-line notice at the top of the fork's root `README.md`.
  - The two design documents (`deploy/selfhost/DEVELOPMENT.md`, `deploy/selfhost/V1-DESIGN.md`) are excluded from the route contract test and from the doc pin tests, because they name old paths on purpose. They stay English and ASCII-only and use no closing keywords.
- **Tests:** the reserved tables are never written (a repo audit test); `test_selfhost_docs.py` documents every setting and every rename; the image smoke test passes. New host-allowlist test (D11): every host name in `deploy/selfhost/*` and `web/README.md` is under `example.com`, `example.edu` or `example.org`, is `localhost`, or is on a short list of public services the docs must name (`login.microsoftonline.com`, `canvas.instructure.com`, `claude.ai`, `claude.com`, Google and GitHub endpoints, upstream documentation sites). The test lists allowed hosts, so it never contains the owner's real domain.
- **Acceptance:**
  - [ ] Full matrix, CI and `selfhost-image.yml` green.
  - [ ] The host-allowlist test is green; the docs carry the fork statement (D11, D12).
  - [ ] Handoff 6.12 live checks done on a staging host before the first v1 tag: claude.ai web, Desktop and Code (mobile only if the docs are to claim it); a B2B guest sign-in; refresh over several days; disable reaching MCP at the next request; nginx and Caddy log redaction.

### 6.2 Global acceptance criteria

- [ ] Only the built-in authorization server exists. Old settings refuse startup with actionable messages, and the renamed ones (`MCP_AUTH_MODE=entra-oauth`, `ENTRA_API_SCOPE`) name their replacement (D9).
- [ ] Every sign-in ceremony runs under `/auth/*` with a per-provider callback, Entra on `/auth/callback/entra`.
- [ ] The JSON API is under `/api/v1`, and `/account` serves only the SPA; no server-rendered account page remains (D5).
- [ ] One baseline revision creates the 19 tables on SQLite (STRICT, FKs on) and PostgreSQL, with identical `compare_schema` results.
- [ ] One account reference (uuid) in the database. `acct:` appears only in AAD and JWT code.
- [ ] One statement per MCP request in steady state.
- [ ] Every security invariant in handoff section 4 still holds, and every reviewed property has a passing test: P6 epoch binding, refresh rotation and reuse revocation on both backends, the usable-owner rule, and audit in the same transaction.
- [ ] Featured schools and sign-in names are managed in the panel and `token_admin`, with none featured by default; directory search is ON by default and switched in the panel (D6, D7, D8).
- [ ] Every stored Canvas token has a recorded acknowledgement of the current custody notice; an outdated one blocks MCP use until re-acknowledged (D10).
- [ ] Docs and examples use neutral hosts and state the fork relationship (D11, D12).
- [ ] `{dev, locked} x {SQLite, PostgreSQL}` green; web checks green; `test_course_cache_isolation.py` identical to upstream.

### 6.3 Risks

| Risk | Mitigation |
|---|---|
| P7's last fix round (`53b86dd`) is unreviewed, and v1 edits the same files | One more independent review before the merge (6.0). Start after B0. Re-read `login/*`, `token_store.py` and `account_web.py` at the merge commit. |
| A custody notice bump cuts every user off MCP until they re-acknowledge | Bump only for a change of substance (step 6b version rule, pinned by the hash test); the MCP message and the SPA banner point to `/account/token`; acknowledging needs no new token. |
| Reviewed concurrency code changes: `FOR UPDATE` becomes `FOR NO KEY UPDATE`, health writes leave the global lock, caches are removed | `test_v1_races.py` on PostgreSQL in a loop; keep the governance tier for every write that decides from a set predicate or owner standing. |
| A port reorders statements and reintroduces a deadlock (the lock-free tier has no global lock to hide it) | The written lock order (4.6), races 11 and 12, `deadlock_timeout` lowered in the race tests, and a check that the race-test server log has no `deadlock detected` |
| A touch or other best-effort write stalls a request behind a row lock | `SKIP LOCKED` touches (4.5.1) and race 13 |
| SQLite FK cascade during a future table rebuild deletes child rows | FK-off migration connection, `foreign_key_check` before commit, and a file backup before contract revisions |
| The `Flag`/`Uuid` TypeDecorators and Alembic `compare_type` produce false diffs | A `compare_type` hook; `compare_schema` tests on both backends from day one |
| SQLite in the image is older than 3.37 | An image test prints the version; the startup check refuses. Expected 3.46, unverified. |
| Pooled SQLite connections misbehave under threads | Port `test_store_races.py` and run with the pool; `check_same_thread=False` with the existing locks |
| A DB outage now fails every MCP request with 503 (no cached status) | Today's per-request `store.get` already had this. Document it. |
| UUIDv7 account ids reveal sign-up time (to the millisecond) to the user's own MCP clients through the JWT `sub` | Accepted (low sensitivity). Switching accounts to v4 needs no schema change. |
| Directory search on by default sends typed queries to `canvas.instructure.com` | Accepted by the owner (D7). Stated on the switch and in the README; the owner can switch it off in the panel. |
| String-pinning doc tests break on every rename | The route contract test replaces most pins |
| No fallback authorization mode, and no live proof yet | Staging pre-flight and the handoff 6.12 checks gate the first v1 tag; the compat contract test is a release blocker |
| `/auth/login/*` reachable by HEAD or a scanner creating state | GET only, edge-guard 405 on HEAD, per-provider buckets, 404 before any write for unknown providers |
| nginx `^~ /auth` matching `/authorize` | Examples and the contract test require `^~ /auth/` |

---

## 7. Open questions for the owner

None remain for this design. The former questions are answered and recorded in 1.1:
- legacy UI removal: yes (D5), so step 2 is mandatory;
- the fork-only renames: yes (D9), in step 1;
- sign-in method names: one name per method for both languages (D8).

The two upstream items once open are decided and change no step here (handoff `deploy/selfhost/DEVELOPMENT.md`, section 5 and 6.7): no reply is posted on upstream issue #484, and #491 is being strengthened while a second upstream pull request covers the discussion half of upstream issue #489.

### 7.1 Implementer decisions (recommended defaults)

These are technical choices for the implementer, not owner questions. Take the default unless the pull request records a reason for another choice.

| # | Decision | Default | Where |
|---|---|---|---|
| 1 | Governance gate for PostgreSQL G transactions | A per-process `threading.Lock` taken before a pool connection is checked out, then the advisory lock. Race 14 pins it. | 4.6, 4.10 |
| 2 | Row locks on the other owners in `usable_owner_ids` | Keep `FOR NO KEY UPDATE` although the advisory lock makes it redundant: the smallest change from the reviewed `FOR UPDATE`, and still correct if the governance lock is ever narrowed. | 4.6 |
| 3 | Cap on the `kid` epoch | 10 digits, refused before any key derivation. | 4.5.1, `authz/test_tokens.py` |
| 4 | SQLite version in the image | An image test (in `tests/test_selfhost_dockerfile.py` or the smoke test) that prints `sqlite3.sqlite_version` and fails below 3.37, plus the startup refusal. Expected 3.46 on `python:3.14-slim`, unverified. | 4.9 |
| 5 | Audit trail for operator account deletion (`token_admin accounts delete`) | One `account_deleted` audit row in the deletion transaction: actor `operator`, subject and target the account, `detail` with the counts of credentials, identities and grants removed, no names and no secrets. Earlier `audit_log` and `auth_events` rows are kept (they have no FK); erasing them stays out of scope (4.16). | 4.6, step 5 |
| 6 | Custody notice version bumps | Bump only for a change of substance; the hash pin makes every text edit a reviewed choice. | step 6b |
