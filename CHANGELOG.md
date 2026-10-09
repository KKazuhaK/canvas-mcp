# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- **Self-hosted mode: a JSON API under `/account/api` and an `ACCOUNT_UI` switch that serves the React account UI.** `ACCOUNT_UI=legacy` (the default; unset means the same) keeps the server-rendered `/account` pages exactly as they were and registers no API. `ACCOUNT_UI=react` registers the API and serves the built single-page app (`ACCOUNT_WEB_DIST`, default `/app/web-dist`, where `Dockerfile.selfhost` now sets it) at `/account/`: `index.html` and every client-side route answer with `Cache-Control: no-store`, `/account/assets/*` is immutable, an unknown asset is a plain 404, and every response carries `default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'`. The build is read into memory and checked at start (one module script under `/account/assets/`, every reference present, plain asset names, bounded sizes, nothing outside the directory); if it is missing or unusable the server logs one warning and serves the full legacy pages, so a broken page is never served. In this mode only `/account/login` and `/account/callback` stay server-side: the callback returns to a validated `return_to` below `/account` (or `/account/`), and a failed sign-in goes to `/account/sign-in?error=<code>` with a fixed code instead of a message. The API uses the same sealed session cookie as the pages, re-checked against the stored account on every request, and the same operations: enrolling or replacing a token with a school and the identity-change confirmation, deleting and re-checking it, the school list and search (a searched school must carry the signature of the caller's own search results), the write-tool switches (turning one on needs a sign-in from the last 10 minutes, `403 reauth_required`), the sign-in history, the language preference, sign-out, and the owner's accounts, enrollments, approve, deny, disable, enable, mark-invalid, remove and audit log. Every change needs the session's CSRF token in `X-CSRF-Token`, an `Origin` equal to `PUBLIC_BASE_URL`, `Sec-Fetch-Site: same-origin` when sent, and a JSON body of at most 8 KiB; there are no CORS headers; answers are `no-store` JSON with a closed error `code` and scalar `params`, never Microsoft or Canvas text. The enrolling, re-checking, write-tool and owner sequences were extracted from the pages into shared operations that both surfaces call, with the same rate limiters, audit events and cache invalidation; a parity test maps every legacy route to its API route and runs the same scenarios through both. **Behaviour change:** removing an enrollment and marking one invalid on behalf of an owner now re-check, inside the same transaction, that the acting account is still an active owner (as disable, enable, approve and deny already did). See `deploy/selfhost/README.md` (Account UI).
- **Self-hosted mode: an account model (`acct:<uuid>`), one admission policy, sign-in history and an audit log; Entra is still the only login provider.** Every person now has an account whose key `acct:<uuid>` replaces `entra:<tenant>:<object>` everywhere the server keys state (the encrypted Canvas token, the access decision and its history, write-tool switches, credential generations, the request principal). How they sign in is a separate external identity: provider `entra`, issuer `https://login.microsoftonline.com/<tid>/v2.0`, subject the `oid` claim, never `sub` and never an e-mail address, so another provider can attach to the same account later without touching a table. New tables `accounts`, `external_identities`, `auth_events` and `audit_log`; `principal_status` is absorbed into `accounts`. Admission is one policy for `/account` and the MCP endpoint: `ACCESS_POLICY` (`rules`, `approval` or `open`), `ACCESS_RULES` (`entra:role:`, `entra:group:`, `entra:tenant:`), `ACCESS_FALLBACK`, `OWNER_RULES` and `SELFHOST_BOOTSTRAP_OWNER`; the defaults reproduce the Entra app roles of the previous release, so nothing has to be set. An unknown rule prefix, a `google:`, `github:` or `oidc:` rule, or `TRUSTED_PROXY_CIDRS` stops the server at startup. In `approval` mode a new person signs in and waits; owners approve or deny at `/account/admin` (or the operator with `token_admin approve`), a waiting account cannot enroll a token or use MCP, the pending queue is capped and stale entries are removed after 30 days. The last active owner is never demoted by a sign-in and cannot be disabled except by the operator with `--allow-last-owner`. `/account` shows the last 20 sign-ins (`auth_events`, kept 90 days, a keyed hash of the user agent and no address) and owners read the audit log at `/account/admin/audit`. `token_admin` accepts `acct:<uuid>`, a bare uuid, the old `entra:<tenant>:<object>` form or the tenant and object ids, and gains `accounts`, `approve` and `promote-owner`; `list` adds the account key as a seventh column; in `access` and `history` the key column now holds `acct:<uuid>` and the old `entra:<tenant>:<object>` key is appended as a last column. **Upgrade:** the Alembic revision `0002_accounts` (schema version 5) re-encrypts every stored Canvas token under the new principal, because the principal is part of the AES-GCM associated data, in one transaction on SQLite and PostgreSQL; any mismatch rolls everything back and leaves the database untouched. `token_admin db upgrade --dry-run` reports what it would do and changes nothing, a populated SQLite file is copied to `*.pre-0002-accounts-<time>.bak` first (PostgreSQL: take a `pg_dump`), a token that does not decrypt stops the upgrade unless `--mark-undecryptable-invalid` is given, and there is no downgrade: roll back by restoring the backup. A previous-release image refuses a version 5 database on purpose. Open `/account` sessions end once (cookie format 3). New tests cover the decision table, a migration from a real schema-4 database of the previous release, tamper resistance of the associated data, and the approval, sign-up, disable and owner races on both backends. See `deploy/selfhost/README.md` (Accounts and admission, Upgrading to the account model).
- **Self-hosted mode: `SELFHOST_DISABLED_TOOLS` removes tools at startup.** A comma-separated list of tool names (read or write) that the operator wants gone from this server: a named tool is not in `tools/list`, not in `search_canvas_tools` and not on the `/account` write-tool list, and a call to it fails as an unknown tool. It can only remove tools; it never registers one and never widens `ALLOWED_WRITE_TOOLS`, `CANVAS_ROLE` or a user's own switches. A name the server does not know stops the start, and the message lists only the unknown names (an entry that is not shaped like a tool name is counted, never quoted). Unset removes nothing; `--config` shows the list. The other auth modes do not read it. New tests cover the parser, the startup wiring and the whole HTTP stack (a disabled read tool is absent and refused), and an end-to-end test proves an administrative disable survives a process restart. See `deploy/selfhost/README.md` (Disabling tools).
- **Self-hosted mode: request-local course state by default, and a startup refusal for `FASTMCP_SSRF_TRUST_PROXY`.** `SELFHOST_COURSE_STATE` is `request_local` (the default) or `per_principal`. With the default, a verified user's course list, course-policy decisions, anonymization pseudonyms and discussion hints live only inside one request (the course list and aliases work as in the upstream HTTP modes; for policy decisions, pseudonyms and hints this is stricter than upstream, which keeps them in process-wide maps shared by all callers); tools that name a course by code or title read `/courses` again on each request. `per_principal` keeps the previous cross-request, per-user caches as an explicit opt-in. The credential generation and the access checks work in both. The server now also refuses to start when `FASTMCP_SSRF_TRUST_PROXY` is set (it turns off FastMCP's private-address checks on OAuth client-metadata and key fetches). New end-to-end tests replay an authorization code, send `/authorize` without a PKCE challenge or with `plain`, and reuse a rotated refresh token through the real OAuth proxy; the README records that FastMCP refuses each but does not revoke the refresh-token family.
- **Self-hosted mode: optional PostgreSQL, Alembic-managed schema, and a repository layer behind the token store.** Everything the mode persists in its token database (enrollments and their health columns, access decisions and their history, credential generations, per-user write-tool switches, the schema marker) is now reached through repository interfaces implemented with SQLAlchemy Core for both SQLite and PostgreSQL (psycopg 3); the `TokenStore` API is unchanged. `DATABASE_URL` selects the backend: unset keeps the SQLite file exactly as before, `postgresql+psycopg://...` uses PostgreSQL. The URL is validated at startup (scheme allowlist, no memory or out-of-data-directory SQLite unless `DATABASE_ALLOW_SQLITE_OUTSIDE_DATA_DIR=true`, allowlisted query parameters only) and is never logged or printed with its credentials. Every guarantee carries over: authenticated encryption and its associated data are untouched, a status gate, a last-owner check and a generation bump still share the transaction of the write they protect, conditional updates are still guarded by the expected `updated_at` or generation, and every write is one transaction. SQLite keeps its process lock plus `BEGIN IMMEDIATE`; PostgreSQL runs `READ COMMITTED` transactions whose first statement takes a transaction-scoped advisory lock, so enrolling while disabling, two owners disabling each other, and a late Canvas verdict about a replaced token stay impossible. Pools, connect, statement, lock and idle-in-transaction timeouts are sized for one instance, and database errors become a fixed message with no SQL, values, paths or URL. The schema is managed with Alembic: the baseline revision is the frozen schema version 4, a database from any earlier release (versions 1 to 4, including the three shapes version 2 had) is adopted in place in a single transaction without changing a stored row, a database from a newer server is refused untouched, and there is no downgrade (restore the backup). Migrations run at start-up (`DATABASE_AUTO_MIGRATE`, default true, serialised by a lock) or by hand: `token_admin db current` (exit 4 when behind), `token_admin db upgrade [--backup PATH]` and `token_admin db import-sqlite PATH`, which migrates a private copy of a SQLite database (any schema, including files from before the account model) to the current schema, then creates the PostgreSQL schema and copies every row in one transaction (all or nothing: a failure leaves the database empty) and verifies that every token still decrypts (`--mark-undecryptable-invalid` marks tokens that fail under a provided key invalid, raises their credential generation, audits it and reports the count; a stored key id missing from `CANVAS_TOKEN_KEYS` always stops the import). The server and the `token_admin` commands refuse to run on a database that holds no rows (an empty schema left by `db upgrade`, a read-only command or a failed import does not count) while the default SQLite file still holds data, so a switch cannot silently re-enable disabled users. `deploy/selfhost/docker-compose.postgres.yml` adds an optional, off-by-default `postgres` service (image pinned by tag and digest, health check, named volume, no published port, internal network). Rate limiters and one-time login state are behind interfaces with in-memory implementations; `SELFHOST_STATE_BACKEND=redis` is reserved and fails closed at start-up. The FastMCP OAuth proxy state stays in its encrypted file store. CI runs the self-hosted tests against PostgreSQL in a new `test-postgres` job, and the two-connection race tests run on both backends. See `deploy/selfhost/README.md` (Database).
- **Self-hosted mode: dependency range fixed, FastMCP internals no longer used, custody documented, logs sanitized.** The lock pinned `py-key-value-aio` 0.4.5, which has no `FileTreeStore.cull()`, so the cleanup of expired OAuth records failed on the locked version; the floor is now `>=0.4.6,<0.5` (and `fastmcp>=4.0.3,<5`), `uv.lock` is updated, and tests fail if the declared range, the lock or the installed versions drift out of it. The OAuth state store is now built by this project (encrypted, lifetime-limited file store with the same directory and key derivation as FastMCP's default, so existing `FASTMCP_HOME` data keeps working, which a test proves in both directions) and passed to `AzureProvider` through its public `client_storage` parameter; the code no longer reads `provider._client_storage`. `deploy/selfhost/README.md` gains a custody and privacy-boundary section (inventory of every secret and token, who can read it, rotation, backup, deletion and retention; encryption protects a database-only leak, not a compromised runtime or an operator holding the keys and data), nginx and Caddy log configuration that keeps OAuth codes and state out of access logs, and the root README and `SECURITY.md` no longer say the server never stores tokens without naming this opt-in exception; the enrollment form says the operator can use the stored token. Application logs and audit events are scrubbed of bearer tokens, JWTs, Canvas and Entra tokens, `code=`/`state=` parameters and URL credentials; audit endpoints lose their query string and free-form error text is also stripped of e-mail addresses and cut to 300 characters.
- **Self-hosted mode: cached state, health verdicts and pending write confirmations are bound to the Canvas credential's lifecycle, not just to the user.** Each user now has a monotonic **credential generation** (new `credential_generations` table; token database schema version 4, migrated in place; an older image refuses it on purpose), raised in the same transaction when their token is saved or replaced (even the same text), removed, marked invalid or restored, or the user is disabled or enabled. The course cache, course-policy decisions, pseudonym maps and discussion hints are keyed by principal, school and generation, so a replacement (a different Canvas account at the same school, or a token with fewer permissions) never sees what the old token cached, and a write preview made before the change cannot be redeemed after it. Token-health verdicts, the dead-token probe, "last verified" writes and the `/account` re-check are guarded by the generation they started under: a probe or refresh that finishes after a replacement is discarded and cannot invalidate, verify or fill the new token's state. Each MCP request reads its token and generation together and carries them; the tool gate refuses a call from a request whose token was replaced since it began (nothing is sent to Canvas). The upstream HTTP modes keep their request-local behavior. Dispatched Canvas calls are not cancelled. See `deploy/selfhost/README.md` (Canvas credential lifecycle).
- **Self-hosted mode: revoking a user is an access decision, not the deletion of a row.** An owner (or the operator, with `token_admin disable` / `enable` / `access` / `history`) can now **disable** a user. The decision is stored apart from the enrollment in a new `principal_status` table keyed by principal key (token database schema version 3, migrated in place; an older image refuses it on purpose) together with a **session epoch**, and it is checked again on every `/account` request, sign-in, enrollment (inside the write transaction), admin action and MCP request (the request-context middleware, before any Canvas credential is loaded, and again in the tool gate before every tool call and resource read, through a 5-second cache that the process making a change clears at once). A disabled user cannot sign in, enroll or re-enroll, and an already issued, refreshed or restarted MCP token buys nothing. Deleting an enrollment row, with **Remove enrollment** (formerly **Revoke**, now `/account/admin/remove`) or the user's own **Delete my token** (a self-disconnect, audited), no longer has any bearing on it. `/account` sessions carry the epoch (cookie format 2, so everyone signs in once after the upgrade); the owner role in a session is a snapshot that is re-checked: admin pages and actions need a sign-in from the last 10 minutes and a stored owner flag, the acting owner is re-verified inside the transaction, an owner cannot disable themselves, and nobody can disable the last active owner (`--allow-last-owner` for the operator). Every transition is written to `principal_status_events` and, with `LOG_ACCESS_EVENTS`, to the audit log as `principal_status` events. The README documents the bounded delays (this server's cache, the `/account` session, the Entra access token lifetime for role or group removal) and that a request already running is not cancelled. See `deploy/selfhost/README.md`.
- **Self-hosted mode: each user turns write tools on for themselves.** `ALLOWED_WRITE_TOOLS` is now the server's ceiling only: every user starts with all write tools off and ticks the ones they want in a new **Write tools** section of `/account` (grouped as planner and calendar, submissions and comments, module completion and inbox, with a one-line note per tool and disabled rows for tools the server does not offer). A tool can act only if the server allows it, the user turned it on and the course policy allows it; the preview and confirmation step is unchanged. The credential gate refuses a call to a tool the user has not turned on and the tool list (and `search_canvas_tools`) hides it. The choice is stored by tool name in a new `user_tool_prefs` table of the token database (created on start, schema version unchanged), is cached for up to 30 seconds and dropped when the user saves, and no MCP tool can read or change it. Saving needs the signed-in `/account` session, a CSRF token and the right `Origin`; turning a tool on also needs a sign-in from the last 10 minutes, turning off never does. Each change is audited (`write_tools`, principal key and tool names only). A tool the operator adds later stays off for everyone, a tool the operator removes stops working at once, and code execution can never be turned on by a user. After upgrading, no user has any write tool turned on until they do it themselves. See `deploy/selfhost/README.md`.
- **Self-hosted mode: a Canvas token that stopped working is detected, reported and no longer used.** A Canvas `401` that looks like a dead token (a `WWW-Authenticate` header, or error text saying the access token is invalid or expired) is only a suspicion; one single-flight `GET /users/self` per token (60 s cooldown) confirms it, and only a `401` from that probe marks the token invalid (`canvas_token_rejected`). A probe that succeeds means a permission problem and the original error is returned; a `5xx`, a timeout or a network error never changes anything. An invalid token (also `decrypt_failed`, and `revoked_by_admin`) is never sent to Canvas again: tool calls return the re-enroll message, and the paged or parallel calls of the same request stop at once. `/account` shows a banner with a **Check again** button (CSRF, once a minute) that can restore the token, an optional **Token expires on** date with a reminder 7 days before, and asks for a confirmation when a new token belongs to a different Canvas user at the same school. `/account/admin` shows status, reason, invalid since and last verified, can filter the enrollments that need a new token, and lets an owner mark one invalid. Invalidation, re-checks, identity changes and the admin mark go to the audit log when it is enabled (principal key and a short code only). See `deploy/selfhost/README.md`.
- **Self-hosted mode: each user picks their own school's Canvas.** `CANVAS_FEATURED_SCHOOLS` (comma-separated `host` or `host=Display Name` entries) adds quick picks to `/account`, and the opt-in `CANVAS_SCHOOL_SEARCH=true` lets a signed-in user search Instructure's public school directory. A chosen host is accepted only if it is featured or the directory confirms that exact domain; it must be a public DNS name that resolves only to public addresses, and the token is verified against that school before it is stored. Every request then goes to the user's own school, and cached data, write confirmations and file-origin checks are keyed per school. A deployment with only `CANVAS_API_URL` behaves as before (single pinned school, no picker); with the new settings `CANVAS_API_URL` is the default school and legacy enrollments belong to it. Without `CANVAS_API_URL` the server needs a featured school or search to start. A stored school that the settings no longer allow is treated as not enrolled. `/account` shows the current school, `/account/admin` and `token_admin list` show each user's school, and `deploy/selfhost/setup-env.sh --school-search` writes both settings. Search terms are sent to Instructure and enrolling at a searched school needs `canvas.instructure.com` to be reachable (see the deploy README).
- **React account UI scaffold (`web/`).** A Vite + React + TypeScript app for
  `/account`: sign-in, Canvas token enroll/replace/delete, write tools, linked sign-in methods,
  connected apps, recent sign-ins, MCP consent and owner admin pages, in English (default) and
  Chinese, with a dev-only mock API. Cookie-only auth, CSRF header on every mutation, no inline
  script and no remote assets (works under `script-src 'self'`). `Dockerfile.selfhost` builds it
  into `/app/web-dist` and CI has a `web` job; the server renders the legacy pages unless
  `ACCOUNT_UI=react` is set (see the entry above).
- **Self-hosted multi-user mode (`MCP_AUTH_MODE=entra-oauth`).** An explicit opt-in
  mode where claude.ai, Claude Desktop and Claude Code connect through OAuth against
  your own Microsoft Entra tenant (FastMCP `AzureProvider`) and each person enrolls
  their own Canvas token at `/account` (Entra sign-in, CSRF, AES-256-GCM encrypted
  store, never through chat). Every request carries the verified Entra identity
  (tenant, app role) and uses only that person's Canvas token; startup fails closed
  on any missing or contradictory setting. Ships with `Dockerfile.selfhost`, a
  fork-only multi-arch GHCR workflow, a zero-clone compose file and Chinese docs
  under `deploy/selfhost/`. Legacy stdio and `X-Canvas-Token` HTTP modes are unchanged.
- **Result cap for claude.ai (`MCP_MAX_RESULT_CHARS`, default 140000, `0` disables).**
  Tool results are cut at a line boundary with a tool-aware continuation notice, only
  for clients that need it; errors, structured results, stdio and Claude Code are never cut.
- **Self-hosted mode hardening.** `POST /register` and `/authorize` need no sign-in and
  each call wrote files to the data volume, so they now have a process-wide rate limit
  (429 with `Retry-After`), a daily registration budget and a body size cap; dynamic client
  registrations expire after 30 days and expired OAuth records are swept from disk. The app
  pins the request scheme to https behind the TLS proxy (trailing-slash redirects no longer
  downgrade to `http://`), uvicorn's access log (which printed OAuth codes) is off, a corrupt
  token database is a logged refusal instead of a traceback, and `RequestCredentials` no longer
  shows the Canvas token in `repr()`. The `deploy/selfhost` template ships read-only (write tools
  are an opt-in block), blank host settings, a named data volume, per-IP proxy rate limits,
  an any-HTTP-answer healthcheck and a documented first-release step.
- `deploy/selfhost/setup-env.sh` writes the self-hosted `.env`:
  - It generates the three random keys locally and validates every value.
  - It reads the Entra client secret from the terminal without echo. The secret is never accepted as an argument or environment variable.
  - It writes the file mode 600 through a temp file, so the file is either complete or absent. It refuses to overwrite an existing `.env`, because regenerating would replace `CANVAS_TOKEN_KEYS`.
  - The output is read-only and anonymized by default. Writes and real names are opt-in flags (`--enable-writes`, `--real-names`). A read-only file carries the write settings commented out, so turning writes on later is an edit, not a rerun.
  - The image smoke test boots a `.env` generated by the script.
- Decluttered self-hosted `/account` pages:
  - Every page shows one language instead of stacking Chinese over English. English is the default. A header link switches to Chinese, and the choice is remembered in a cookie. The browser's `Accept-Language` is not used.
  - The header is compact: the user's name, an Admin link for owners, and Sign out.
  - The enrolled state is one status card. The replace form is collapsed by default.
  - Timestamps are shown in `TIMEZONE`, for example `2026-09-01 02:12 PDT`.
  - On phones the admin table becomes stacked cards, with the GUIDs under "Technical details".
  - Routes, CSRF, sessions, rate limits, CSP and the other security headers are unchanged.
- `read_course_file_text` (every profile; it is registered together with
  `read_course_file`, which points to it): read a course file as plain text
  with page/slide markers. PDF pages, PowerPoint slide titles/text/tables/speaker
  notes, Word paragraphs and tables, and plain text, Markdown, CSV, JSON and
  HTML. The reported size is checked before downloading (50 MB, lowered by
  `READ_FILE_MAX_SIZE_MB`), output is fenced as untrusted Canvas content, and
  the complete text is returned, never cut (`start_page`/`end_page` select a
  range). PDF/PPTX/DOCX parsing needs the new optional `documents` extra
  (`pip install 'canvas-mcp[documents]'`); without it the tool returns an
  install hint.
- Hidden Files tab fallback: when Canvas refuses `GET /courses/:id/files` with
  401/403 (students in a course whose Files tab is hidden),
  `list_course_files` lists the files linked from the course modules instead
  and says so. `read_course_file`, `download_course_file` and
  `read_course_file_text` read such a file through `GET /files/:id`, but only
  when the course links it from a module.

### Changed

- **Self-hosted mode needs the `selfhost` extra when installed with pip.** SQLAlchemy and Alembic are optional dependencies (`pip install 'canvas-mcp[selfhost]'`, or `[postgres]` for the PostgreSQL driver); the container image includes both. The stdio, `X-Canvas-Token`, access-key and Easy Auth modes do not import them, and `entra-oauth` fails at start-up with an install hint if they are missing.
- **Self-hosted mode: a new SQLite file no longer fails when two processes create it at the same time.** Switching a fresh database to WAL while another connection was writing was reported as "database is locked" at once; it now waits as long as the busy timeout would.

### Changed (breaking)

- **`read_course_file` returns the original file**, not base64 text. Non-image
  files come back as an MCP `EmbeddedResource` (`BlobResourceContents`, exact
  bytes, MIME type from the file signature); Claude Code saves it and the model
  opens it with Read, the same path as a manually attached PDF (page images
  plus text). PNG/JPEG/GIF/WebP come back as `ImageContent`. Claude Desktop
  chat and claude.ai connectors (`clientInfo.name` `claude-ai`), which mishandle
  blob resources, get the complete extracted text instead. Downloads now go
  through the same token-safe downloader as `read_course_file_text`.
- `read_course_file` returns at most 11.5 MB as a file. Claude Code drops the
  server connection on any JSON-RPC message over 16 MiB, and base64 adds a
  third, so a larger file is refused before download with a pointer to
  `read_course_file_text`. Text results from either tool that would not fit in
  one message (over 15 MB) are refused rather than cut, with a page range that
  fits. Clients that get text use the text tool's 50 MB download budget.
- On the hosted (stateless HTTP) server, where no session keeps the
  `initialize` `clientInfo`, an unnamed client gets the file only when its
  `User-Agent` is Claude Code's (`claude-code/...`); other unnamed HTTP
  clients, such as claude.ai connectors, get the extracted text.
- Text and code files (`.py`, `.java`, notebooks, XML, LaTeX, ...) are sent as
  `text/plain`, which Claude Code saves as a `.txt` its Read tool opens (it
  saves unmapped types as `.bin` and refuses them); the result names the real
  type. For PPTX/DOCX/XLSX the hint says plainly that Read cannot open them and
  points to `read_course_file_text`. `read_course_file_text` also reads text
  and code files by extension when Canvas reports a generic type.
- `get_rubric` block-fences the now-complete criterion and rating long
  descriptions instead of using the one-line inline fence.
- **`read_course_file_text` returns the complete text.** `max_chars`,
  `start_char` and the 40,000-character default are removed; only
  `start_page`/`end_page` limit it. It and `read_course_file` declare
  `anthropic/maxResultSizeChars: 500000` like the other full-content tools, so
  Claude Code delivers a large result whole instead of capping it near 25k tokens.

### Security

- **Token database schema v2 binds the principal and the Canvas host into the AES-GCM associated data.** The associated data is one versioned layout, `canvas-mcp/canvas-token/v2`, built from a single opaque `principal_key` string (today `entra:<tenant id>:<object id>`, lower case), the Canvas host and the key id, so a row whose principal or host was edited in the database fails to decrypt instead of redirecting the token to another user or school. `TokenStore` methods now take the `principal_key` (the `(tenant_id, object_id)` form still works) and the row stores it in a new unique `principal_key` column. The same migration adds token-health columns (`status`, `invalid_reason`, `invalid_since`, `last_verified_at`, `expires_hint_at`) that do not change behaviour yet. Opening a v1 database migrates it in place (idempotent); legacy rows keep decrypting with their original associated data and are re-sealed as v2 the next time they are saved, and `token_admin rotate` handles both kinds of rows. An older image refuses the upgraded database, so back up `/data` before upgrading.
- `read_course_file_text` follows download redirects one hop at a time and
  sends the Canvas token only to the configured Canvas origin; storage hops go
  out without credentials and must be HTTPS.
- `download_course_file` now uses the same per-hop downloader (on the course
  route and on the hidden-Files-tab module route), streaming to disk. It used
  to send the token to whatever URL Canvas reported for the file, follow up to
  20 redirects with the authenticated client, accept `http://` storage hops
  and write without a size limit. It now caps a download at 1 GB by default
  (refused before anything is written when Canvas reports a larger size, and
  cut off while streaming otherwise), and removes the partial file on any
  failure. **Migration:** a local user who downloads files over 1 GB sets
  `DOWNLOAD_FILE_MAX_SIZE_MB` (in MB, e.g. `4096`) in the server's
  environment; the refusal names the setting.
- Once a download hop has left the Canvas origin, every later hop goes out
  without the token, even one that redirects back to Canvas. A storage host
  can no longer make the server perform an authenticated Canvas GET and hand
  the response over as the file.
- `upload_file_to_storage` (used by `upload_course_file` and the student
  `submit_assignment` file upload) sends the token to the storage host's
  confirmation redirect only when it points at the caller's Canvas origin,
  and does not follow it further; any other `Location` is refused unsent.
- Text extraction and the PDF page count run in small thread pools of their
  own (two workers and one). Reads waiting for an extraction slot no longer
  hold threads of the event loop's default executor, which also resolves DNS
  for every Canvas request, so many concurrent file reads cannot stall
  unrelated Canvas calls.
- The file tools now reject a non-numeric `file_id` before it reaches a
  request path.
- `read_course_file` declares a returned file only with a fixed allowlist of
  MIME types (documents, text, common images); anything else, including an
  uploader-declared executable or script type, is sent as
  `application/octet-stream` with no URI extension, so Claude Code cannot be led
  to write such a type to the student's disk. The URI extension no longer
  comes from the platform's MIME registry.
- The `Pages:` count of a returned PDF is best effort: one at a time, skipped
  when busy, dropped after 5 seconds, and never holding a text-extraction
  worker.
- `read_course_file_text` refuses Office files whose XML would inflate past
  20 MB, or with any part that inflates more than 100x, before a parser runs,
  parses at most two files at once, and prints only a validated MIME token for
  the uploader-supplied content type.
- `uv.lock` now pins the `documents` extra, and the security workflow fails on
  a stale lock (`uv lock --check`) so new dependencies always reach pip-audit.

### Fixed

- **Per-caller isolation of process-global caches.** The course-code cache, course
  policy cache, anonymization map and discussion routing hints are now keyed by the
  caller (a keyed hash of the `X-Canvas-Token` in legacy HTTP mode, `local` on stdio),
  so callers with different tokens no longer share course data. Confirmation tokens
  are bound to the verified caller identity in `entra-oauth` mode. Course aliases and
  labels follow the upstream HTTP boundary: in the `X-Canvas-Token`, access-key and
  Easy Auth modes they are resolved per request under that request's own credential
  and never stored; only a verified `entra-oauth` principal keeps a course cache
  across its requests (per school), and stdio keeps its single local cache.

## [1.14.0] — 2026-10-07

### Security

- Locked dependencies moved to patched releases: `pyjwt` 2.15.1 ([#432](https://github.com/vishalsachdev/canvas-mcp/pull/432)),
  `urllib3` 2.8.0 ([#434](https://github.com/vishalsachdev/canvas-mcp/pull/434)) and `multidict` 6.9.1 ([#461](https://github.com/vishalsachdev/canvas-mcp/pull/461)). No code changes.

### Added

- **Student group tools (read-only, student profile).** ([#470](https://github.com/vishalsachdev/canvas-mcp/pull/470), [#472](https://github.com/vishalsachdev/canvas-mcp/pull/472); thanks [@KKazuhaK](https://github.com/KKazuhaK)) `list_my_groups` lists
  the groups you belong to with the course ID and group ID, `get_group_members`
  lists a group's members (names and user IDs, never emails), and
  `list_group_files` lists a group's files. Each group-scoped tool re-reads
  `/users/self/groups` first and refuses a group you are not in, even where
  Canvas would allow the read. Discussions and announcements in a group are read
  with the existing discussion tools' `group_id` (`list_discussion_topics` with
  `include_announcements=True`, then `get_discussion_with_replies`); `list_my_groups`
  prints the IDs and the call to make. Group topic records
  (`/groups/{id}/discussion_topics`) are written by group members, so they are
  anonymized in the `full` tier, which also covers the discussion tools' `group_id`
  path; `group_category_id` marks a record as a group, so a group's own name is
  no longer rewritten as a student pseudonym on `/users/self/groups`, and the
  discussion `/view` `participants` list is treated as people. Group names,
  descriptions, file names and member names are fenced as untrusted Canvas content.
  A blank `course_identifier` on `list_my_groups` is an error rather than a
  silent "all courses", and a failed Canvas request reports only its HTTP status
  (any other failure text is truncated and fenced), never the response body.
  A file's content type is printed only when it is a short ASCII MIME token with a
  registered top-level type (classmates control the value); anything else shows as
  "unknown type".
- **Student Inbox messaging.** ([#467](https://github.com/vishalsachdev/canvas-mcp/pull/467), [#476](https://github.com/vishalsachdev/canvas-mcp/pull/476); thanks [@KKazuhaK](https://github.com/KKazuhaK)) `find_message_recipients` (read-only, always
  on) looks up the people a student can message in a course and their user
  IDs. `send_message` and `reply_to_conversation` are new student write tools,
  off unless named in `STUDENT_WRITE_TOOLS` and subject to the per-course
  syllabus policy and `ALLOWED_WRITE_TOOLS`. Both preview first and need a
  single-use confirmation token bound to the recipients, subject and body.
  To keep GHSA-hmr8 closed for students, recipients must be 1-5 individual
  user IDs that Canvas lets the student message in that course (course,
  section and group addresses are refused), replies reach only a
  conversation's existing audience of at most 5 people, there are no
  attachments or bulk sends, and text carrying UNTRUSTED CANVAS CONTENT
  markers is refused. The checks fail closed: a reply is refused when the
  conversation's course cannot be fully identified, including a malformed
  `context_code` (while course policies are on), when the audience is not a
  list, or when Canvas flags it `cannot_reply` in any form. A blank subject is
  refused.
- `/search/recipients` responses now use the same `free_text` anonymization
  tier as `/conversations`: avatars and direct identifiers are removed. The
  address book lists a whole course, so while `ENABLE_DATA_ANONYMIZATION` is
  on, `find_message_recipients` and the `send_message` preview name only
  course staff and show everyone else under the same `Student_<hash>`
  pseudonym the `/courses/:id/users` tier uses. A name search then asks only
  the course's staff sub-contexts (Canvas matches `search` against real
  names, so a classmate's pseudonym would otherwise reveal whose it is) and
  returns course staff only. Known limitation, documented in
  `core/anonymization.py`: pseudonyms depend only on the user ID, so a person
  named as staff in one shared course is not anonymous where they are a
  student.
- **`raw_dates` on `list_assignments`, `get_assignment_details` and
  `get_discussion_topic_details`** (opt-in, default output unchanged). Appends a
  JSON block with `due_at`, `unlock_at`, `lock_at`, `updated_at`, `all_dates` and,
  for checkpointed discussions, `has_sub_assignments` and each checkpoint's dates,
  exactly as Canvas returns them (`null` stays `null`). A checkpointed
  discussion's parent `due_at` is null by design, which the summaries used to
  report as "no due date". Metadata only: no submission, grade or user fields.
- **Discussions inside group spaces.** ([#433](https://github.com/vishalsachdev/canvas-mcp/pull/433); thanks [@papatistos](https://github.com/papatistos)) The discussion read tools
  (`list_discussion_topics`, `get_discussion_topic_details`,
  `list_discussion_entries`, `get_discussion_entry_details`,
  `get_discussion_with_replies`) take an optional `group_id`. Topics that
  students start inside a group live only under `/groups/{id}/discussion_topics`
  and have no course-level parent, so the course-scoped tools never returned
  them. The group must belong to the named course.
- `list_group_discussion_topics` lists the topics in every group of a course
  (optionally one group set) in one call, with entry counts, and marks each
  topic as a group copy of a course topic or as started in the group.
- **Guarded body edits (issue 419).** `edit_page_content` and
  `update_assignment` take optional `expect_updated_at` (refuse if the object
  changed since it was read; `Z` and offset forms of one instant match),
  `find`/`replace` (edit one fragment, which must occur exactly once, instead
  of resending the whole body) and `require` (strings that must already be
  present). Discussion topics and the syllabus have no `updated_at`, so
  `update_discussion_topic` and `update_syllabus` take `expect_body_sha256`
  instead, plus the same `find`/`replace`/`require`; `get_syllabus` and
  `get_discussion_topic_details` now print that hash, and the syllabus
  confirmation token is unchanged and independent.
  A guarded write is read back and reported as confirmed only when the
  read-back proves it (timestamp advanced where there is one, the whole stored
  body equal to the expected body after whitespace-only normalization, every
  other requested field as sent); otherwise it is reported unconfirmed. Calls without the new
  parameters send exactly the same requests as before.
- **Student "what's new" feed (read-only, student profile).** ([#468](https://github.com/vishalsachdev/canvas-mcp/pull/468), [#471](https://github.com/vishalsachdev/canvas-mcp/pull/471); thanks [@KKazuhaK](https://github.com/KKazuhaK))
  `list_my_announcements` lists announcements across all active courses in one
  call (default last 14 days, optional course filter), and
  `get_my_activity_stream` summarises the Canvas activity stream by kind
  (announcements, discussions, conversations, grades and submission comments,
  notifications). Canvas-authored text is fenced. Previews that are shortened
  name the tool that returns the full text.
- **Student grade insight (read-only).** ([#469](https://github.com/vishalsachdev/canvas-mcp/pull/469), [#473](https://github.com/vishalsachdev/canvas-mcp/pull/473); thanks [@KKazuhaK](https://github.com/KKazuhaK)) `get_my_assignment_scores` lists every
  assignment's score and status in a course, grouped by assignment group with
  weights and drop rules. `calculate_grade_scenarios` recomputes the course grade
  the way Canvas does (weighted or total points, drop lowest/highest and
  never-drop, excused and omitted work), shows it next to Canvas's own current
  score and flags disagreement, applies what-if scores, and reports the uniform
  percentage needed on remaining work for a target percentage or letter. Both
  register for the student and all profiles; the arithmetic is in
  `core/grade_calc.py`. Both fail closed: they refuse a course that restricts
  quantitative data or does not say whether it does, assignment data that is not
  the documented shape (including non-numeric weights, points or scores and
  duplicate IDs), and
  submissions that arrive as a list (an observer token); a letter target is
  refused when the course's real letter scheme is unknown.
- **Read-only quiz awareness for students** ([#466](https://github.com/vishalsachdev/canvas-mcp/pull/466), [#474](https://github.com/vishalsachdev/canvas-mcp/pull/474); thanks [@KKazuhaK](https://github.com/KKazuhaK)) (student slice of issue 172):
  `list_quizzes` lists a course's Classic quizzes and New Quizzes with dates,
  limits and your submission state; `get_quiz_details` shows one quiz's settings
  plus your own attempts used/remaining and kept score from the latest record.
  Earlier attempt history is unavailable: its GET endpoint triggers grading of
  overdue attempts even for students, so the read-only tool never calls it. Neither tool takes a
  quiz, starts an attempt, or reads questions or answers. New Quizzes are found
  by the assignment API's `is_quiz_lti_assignment` flag (not
  `is_quiz_assignment`, which marks Classic quizzes); their settings and attempt
  history are not exposed to students by the REST API, and the tools say so.
- **Student calendar and planner tools.** ([#465](https://github.com/vishalsachdev/canvas-mcp/pull/465), [#475](https://github.com/vishalsachdev/canvas-mcp/pull/475); thanks [@KKazuhaK](https://github.com/KKazuhaK)) Student profile only.
  `list_calendar_events` shows the Canvas calendar across the student's active
  courses, their personal calendar and their groups (assignment due dates
  included, batched to Canvas's 10 calendars per request), `get_calendar_event`
  returns one event in full, and `list_planner_notes` lists the student's own
  planner notes. These add what `get_my_upcoming_assignments` cannot show:
  lectures, exams, office hours, personal events and the student's own to-dos.
  Event and note text is fenced as untrusted content, and the reads never expose
  other people (`user` and `child_events` are dropped).
- **Calendar and planner writes, off by default.** `create_planner_note`,
  `update_planner_note`, `delete_planner_note`, `mark_planner_item_complete`,
  `create_personal_calendar_event` and `delete_personal_calendar_event` exist
  only when the operator names them in `STUDENT_WRITE_TOOLS`. They act only on
  the caller's own notes and `user_<id>` calendar; a note or planner item tied
  to a course follows that course's agent policy; updates and deletes are two
  calls (preview, then a single-use token); course, group and appointment
  events are refused. `mark_planner_item_complete` on course content also needs
  `mark_module_item_done` permitted, because Canvas syncs the planner override to
  that module requirement, and it is marked destructive for the same reason.

### Fixed

- `get_my_submission_status` no longer reports graded `on_paper` or
  `none` assignments as overdue. It now follows Canvas's own `missing` flag,
  which is false for excused, graded and no-submission work and true when a
  teacher marks work missing ([#423](https://github.com/vishalsachdev/canvas-mcp/pull/423); thanks [@lindsay-cheng](https://github.com/lindsay-cheng)).
- **Full-content reads no longer cut text without saying so.** ([#458](https://github.com/vishalsachdev/canvas-mcp/pull/458), [#462](https://github.com/vishalsachdev/canvas-mcp/pull/462); thanks [@KKazuhaK](https://github.com/KKazuhaK))
  `get_discussion_with_replies` returns whole entries and replies (they were cut
  at 200 and 150 characters), `list_discussion_entries` with
  `include_full_content=True` returns whole replies (they were cut at 200), and
  `get_rubric` shows whole criterion and rating descriptions (they were cut at
  200 and 100), block-fenced as untrusted Canvas content. `get_syllabus` stays
  complete by default; its optional `max_chars` cap is kept, and a cut is always
  marked with `[truncated at N characters]`. The reading tools
  (`get_page_content`, `get_syllabus`, `get_front_page`,
  `get_assignment_details`, `get_discussion_topic_details`,
  `get_discussion_entry_details`, `get_discussion_with_replies`,
  `list_discussion_entries`, `get_conversation_details`, `get_my_submission`,
  `get_rubric`, `get_rubric_assessment`) now declare
  `anthropic/maxResultSizeChars: 500000` in `tools/list`, so Claude Code
  delivers a large result whole instead of capping it near 25k tokens; other
  clients ignore the key.
- Previews now say they are previews: `list_discussion_entries` without
  `include_full_content` names that parameter, `list_rubrics` points to
  `get_rubric` when it shortened a description, and
  `get_course_content_overview` names `get_syllabus`, `list_pages` and
  `list_modules` when it shows only a preview or the first few items.
- **Course codes with spaces, course names and bare SIS IDs now resolve.** ([#457](https://github.com/vishalsachdev/canvas-mcp/pull/457); thanks [@KKazuhaK](https://github.com/KKazuhaK))
  `get_course_id` only recognised codes containing an underscore, so a course
  addressed as `COMPSCI 161`, by its name, or by its SIS ID was sent to Canvas
  as typed and failed. A lookup that finds nothing in the cache now re-reads
  the course list once (shared between concurrent callers, and not more often
  than every 30 seconds, so a typo or garbage input cannot page through
  `/courses` on every call) and matches the identifier against course code,
  SIS ID and name, ignoring case and surrounding whitespace. An identifier
  that names more than one of your courses is never guessed at. `get_course_id`
  keeps its old pass-through for an identifier that matches nothing or several.
- **`resolve_numeric_course_id`, a resolver that never returns an unvalidated
  string.** It returns `(course_id, None)` or `(None, error)`, so its result is
  safe in a request path. `sis_course_id:<token>` is looked up only when the
  token is a single plain path segment (no `/`, backslash, `?`, `#`, `%`,
  `..`, whitespace or control characters); any other value is refused without
  a request. `list_course_files`, `read_course_file` and
  `download_course_file` use it, so a course identifier such as `1/users/503`
  or `../accounts/1` is refused with `Could not find course` before any file
  request is made.
- `assign_peer_review` no longer creates a placeholder submission. It scanned
  one page (100) of submissions for the reviewee and, on a miss, POSTed a
  placeholder on the student's behalf, so in a large assignment a truncated read
  became a write. It now reads the reviewee's submission directly and refuses
  when there is none. `reviewee_id` must be a numeric Canvas user ID (#420).
- `list_conversations` reports `returned` and `more_available` instead of
  presenting Canvas's first inbox page as the whole inbox (#420).
- `list_peer_reviews` reads every page of each submission's reviews, reports
  submissions whose reviews could not be read instead of skipping them, and
  names the reviewer from `assessor_id` (it printed the reviewee as their own
  reviewer) (#420).
- `get_course_content_overview` states how many modules its item counts cover
  (`Modules Analyzed for Items: 10 of N`) and any module it could not read (#420).
- New guard test fails CI when a tool adds a single-request GET on a Canvas
  collection endpoint (#420).
- **Anonymous discussion topics no longer read as missing** (issue 421, part 1).
  Canvas's REST API answers 404 for fully anonymous topics that its topic list
  still includes. `list_discussion_topics` and `list_group_discussion_topics`
  now show `Anonymity:` when Canvas reports an `anonymous_state`. On a 404,
  `get_discussion_topic_details`, `list_discussion_entries` and
  `get_discussion_with_replies` check the course's (or group's) topic list; a
  listed topic gets a message that it exists, REST does not serve it, and it
  can be opened in the Canvas UI. A 404 for an unlisted topic is still not found.
- **Anonymous discussion topics can be read** (issue 421, part 2). ([#439](https://github.com/vishalsachdev/canvas-mcp/pull/439), [#442](https://github.com/vishalsachdev/canvas-mcp/pull/442); thanks [@papatistos](https://github.com/papatistos)) After the
  part-1 404 check finds a topic in the list, the four topic read tools
  (`get_discussion_entry_details` included) can read it through Canvas GraphQL when
  the operator sets `DISCUSSION_GRAPHQL_ENABLED=true` (off by default), and
  return the same output as for any other topic. Anonymous posts keep only
  their anonymous alias, and replies nested deeper than one level are kept. A
  topic read this way is remembered for ten minutes, so later reads take one
  request. The client gains a `graphql` API root; every GraphQL response is
  anonymized at the full tier. If GraphQL fails too, the part-1 message is
  returned with the reason appended.
- **Anonymous discussion updates are refused** (issue 421). Every
  `update_discussion_topic` call reads the topic before writing. A listed topic
  whose detail read returns 404 is explained as existing and unsupported by
  REST; a readable topic marked anonymous is also refused. Neither path sends
  an update or a GraphQL request. Guarded edits reuse the preflight read;
  ordinary updates add one REST read before their existing write.
- **Windows support.** The full test suite now passes on Windows. ([#456](https://github.com/vishalsachdev/canvas-mcp/pull/456), [#460](https://github.com/vishalsachdev/canvas-mcp/pull/460); thanks [@KKazuhaK](https://github.com/KKazuhaK), and [@bruchris](https://github.com/bruchris) for the UTF-8 groundwork in [#445](https://github.com/vishalsachdev/canvas-mcp/pull/445))
  - `TIMEZONE` works on Windows: `tzdata` is installed there only (a Windows
    platform marker), because Windows has no IANA time zone database and every
    date fell back to UTC with a warning. Nothing changes on Linux or macOS.
  - `reset_audit_state()` closes the audit handlers instead of dropping them, so
    `audit.jsonl` is no longer left open (a leaked descriptor everywhere, and a
    file Windows could not delete or rename).
  - `.githooks/commit-msg` runs the first of `python3` and `python` that really
    is Python 3.8 or newer. On Windows `python3` is usually the Microsoft Store
    alias, which exits non-zero and used to reject every commit unscanned. With
    no working Python the hook now rejects the commit with an installation/PATH
    hint; the explicit `ALLOW_CLOSING_KEYWORD=1` bypass still works. A missing
    checker file still skips the check, with CI as that case's backstop.
  - Tests no longer assume POSIX: symlink tests fall back to a directory
    junction or skip with a stated reason where Windows refuses symlinks,
    permission-bit assertions skip on Windows, the audit tests clean up in the
    right order, two subprocess tests pin UTF-8 and no longer depend on a global
    `tsx`, and the `TIMEZONE` conversion tests run whenever the zone resolves
    and assert the `-05:00` offset that `format_date` documents.

### Changed

- CI runs the suite on Python 3.14 (Ubuntu) and on Windows with Python 3.14,
  with `PYTHONUTF8=1`. The required `test-enhancements` check now also depends
  on the Windows job. The package metadata now declares Python 3.14.

## [1.13.0] — 2026-09-27

### Security

- **Operator allowlist for tools that change anything (GHSA-hmr8-mvr2-mvw5).**
  New `ALLOWED_WRITE_TOOLS` setting decides which side-effect tools (Canvas
  writes, messages, local file writes, code execution) exist at all; a tool that
  is not allowed is removed at startup and cannot be listed or called. Read tools
  are unaffected. An assistant steered by instructions planted in student-written
  content could otherwise send course data out or change grades, and
  confirmation tokens do not stop that because the assistant can redeem its own
  token. See `env.template` and `tools/README.md`.
- `update_syllabus` now checks a supplied `confirmation_token` in every mode.
  An invalid token on `append`/`prepend` was ignored and the write went through.
- `download_course_file` is now annotated as a write (it creates a local file);
  it was marked read-only.
- `ALLOWED_WRITE_TOOLS` set but empty means `none`. Only an unset variable gets
  the transport default, so an allowlist that becomes empty fails closed.
- The `execute_typescript` sandbox runs as a non-root user (#317) with a
  read-only container root filesystem (#339), and a configured sandbox `uid:gid`
  is validated numerically (#353).

### Breaking

- **HTTP transport is read-only unless configured.** With `ALLOWED_WRITE_TOOLS`
  unset, a hosted (`streamable-http`) server registers no side-effect tools.
  Set it to the tools your deployment needs (for example
  `update_page_settings,create_announcement`), or `all` for every Canvas-write
  and local-write tool (`execute_typescript` must be named separately). stdio
  behaviour is unchanged when the setting is unset; `none` makes it read-only.
  Unknown names, read tools, or `none` combined with names stop startup.
- **`send_conversation` always previews first**, including for a single
  recipient. Call it once to get the preview and token, then again with the
  token and identical arguments. One-to-one messages used to send on the first
  call.
- **`get_conversation_details` no longer marks a conversation read**, and its
  `auto_mark_read` parameter is removed. Viewing is now strictly read-only; use
  `mark_conversations_read` to change read state. Canvas marks a conversation
  read on GET by default, so this read tool was changing inbox state.

- Rubric grading now stops when grading settings cannot be verified. Python
  bulk dry runs also reject false/missing grading flags. Post-write rubric
  results that cannot be confirmed count under bulk failures, even when the
  assessment may have been saved; check Canvas before retrying. TypeScript
  bulk grading shares one assignment lookup per run. Rubric creation remains
  supported; guarded ID-preserving edits are available through
  `update_rubric`, while structural changes still use the Canvas UI (#374,
  #375).

- **Local file exports refuse HTTP callers.** On a shared (HTTP-transport)
  server, `generate_peer_review_report(save_to_file=True)` and
  `extract_peer_review_dataset(save_locally=True)` now return an error before
  fetching anything, and `create_student_anonymization_map` refuses every HTTP
  call, so one caller's student reports, datasets and identity maps can no
  longer land on the server's disk. Migration: pass `save_to_file=False` /
  `save_locally=False` to receive the content in the response instead. Note
  that `extract_peer_review_dataset` defaults to `save_locally=True`, so its
  bare call now fails over HTTP. Local stdio servers are unchanged. The two
  export tools are no longer annotated read-only, since their local variants
  write files; `extract_peer_review_dataset` is idempotent (fixed default
  filename, overwritten in place) and `generate_peer_review_report` is not
  (timestamped default filename, a new file per call).

### Added

- **`update_rubric`** — guarded full-replacement editing for existing rubrics.
  The tool requires the complete criterion/rating set and every existing ID,
  an explicit rubric-association join-record ID, and a human-visible
  preview → confirmation step. It rechecks state before writing, preserves
  scoring/range flags, verifies the returned identities, and reads the rubric
  back after the write. Unexpected copies or mismatched content are reported
  as unconfirmed and are never retried automatically (#375).

- **`update_syllabus`** — write the course Syllabus tab, which previously had a
  read tool (`get_syllabus`) and no way to write. Supports `replace` (default),
  `append` and `prepend`. Canvas keeps no revision history for `syllabus_body`,
  so replacing a syllabus that already has content takes the same
  preview → token → confirm path as the delete tools; writing into an empty
  syllabus, appending, or prepending is a single call. The write is verified by
  reading the syllabus back, and reports `unconfirmed_write_warning` rather than
  success when the syllabus does not contain what was sent (a token without
  `manage_course_content` is the usual cause). That read-back compares visible
  text rather than markup: Canvas rewrites the body server-side, and an
  institutional theme injecting `<link>`/`<script>` tags into every syllabus
  made byte equality report failure on writes that had succeeded. When Canvas
  does rewrite the HTML the success message says so. The confirmation token is
  bound to the syllabus the preview displayed, so an edit by someone else
  between preview and confirm stops the token matching. Annotated
  `idempotentHint: false` — a repeat in `append`/`prepend` mode adds the same
  block again. Registered for the `educator` and `all` profiles only.

### Changed

- Logged Canvas URLs are redacted before they reach the log: userinfo, query
  string and fragment are stripped on top of the existing numeric-ID masking.
  A presigned upload URL's signature was previously written to the log
  verbatim.
- `get_completion_analytics` fetches the peer-review roster once per analysis
  instead of twice.
- `preview_with_token` takes an optional `action` verb (default `"delete"`, so
  every existing call site is unchanged). Delete tools were its only callers, so
  its wording was hardcoded to deletion; `update_syllabus` is the first
  irreversible write that is not a delete, and telling the user a replace would
  "delete" something describes the wrong risk.

- Migrated to FastMCP 4 and MCP SDK 2. Protocol-model attribute reads now use
  the SDK's native snake_case API, and CI disables FastMCP's temporary
  camelCase compatibility bridge to prevent regressions. Canvas API clients
  continue to use `httpx`; they are independent of FastMCP's `httpx2` transport
  stack ([issue 142](https://github.com/vishalsachdev/canvas-mcp/issues/142)).
- The Azure deployment spec (`deploy/azure/`) deploys production on a `v*`
  release tag or a manual run instead of every merge (#417), and its client
  example keeps the Canvas token out of `mcp-remote` arguments with
  `--header-file` (#422).
- Model-facing tool, skill and guidance text corrected after a prompt audit
  (#411, #412); Codex MCP setup instructions added (#381).

### Fixed

- Assignments submitted through external tools such as Gradescope are listed
  separately instead of being reported missing or overdue (#390, thanks
  @EastArctica).
- TypeScript code-API pagination follows `Link` headers and stops within a page
  budget (#403, #396).
- Confirmation tokens: burn and expiry replay gaps closed (#394); student
  submission confirmations verified (#404); confirmation workflows verified and
  peer-review outcomes corrected (#405); confirmation claims carry structured
  write outcomes (#408).
- Grading: incomplete discussion grading fixed (#406); TypeScript grading replay
  prevented (#397); batch scheduling shared across grading workflows (#407);
  rubric grading settings and returned scores verified (#378).
- Accessibility formatters return structured errors (#385).
- `search_canvas_tools` decodes code-API TypeScript files as UTF-8 (#351).

## [1.12.0] — 2026-08-30

### Breaking

Four changes need action when upgrading. Each has its migration inline.

- **`delete_announcement` removed.** Call `delete_announcement_with_confirmation`
  with the same `course_identifier` and `announcement_id`. It is two-step: the
  first call returns a preview and a `Confirmation token: <token>` line, the
  second call with `confirmation_token=<token>` and identical arguments deletes
  ([issue 318](https://github.com/vishalsachdev/canvas-mcp/issues/318)).
- **`dry_run` removed** from `delete_announcement_with_confirmation`,
  `bulk_delete_announcements` and `delete_announcements_by_criteria`. Migration:
  drop the argument. A call without `confirmation_token` *is* the dry run: it
  lists exactly what would be deleted and deletes nothing. Note that
  `bulk_delete_announcements` previously defaulted to `dry_run=False` and
  deleted on the first call; it now previews on the first call like the others
  ([issue 318](https://github.com/vishalsachdev/canvas-mcp/issues/318)).
- **`confirmation_token` required on all seven delete tools:**
  `delete_announcement_with_confirmation`, `bulk_delete_announcements`,
  `delete_announcements_by_criteria`, `delete_page`, `delete_module`,
  `delete_module_item` and the new `delete_assignment_with_confirmation`.
  Migration, per delete: (1) call the tool with your normal arguments and show
  the returned preview to the user; (2) read the token from the
  `Confirmation token:` line and call again with the *same* arguments plus
  `confirmation_token`. Tokens are single-use, expire after 5 minutes, and are
  bound to the tool, course, the ids as requested, every detail the preview
  displayed (titles, due date, points, posting dates) and the behavioural
  arguments (`stop_on_error`, `limit`). If anything changed in between, the
  call refuses and you preview again. Two calls with different arguments never
  share a token ([issue 318](https://github.com/vishalsachdev/canvas-mcp/issues/318)).
- **Python 3.10 dropped:** `requires-python >= 3.11`, ahead of 3.10's
  2026-10-31 end of life. Migration: upgrade the interpreter (3.11, 3.12 and
  3.13 are tested in CI). `pip`/`uv` will refuse to install 1.12.0 on 3.10; pin
  `canvas-mcp<1.12` if you cannot upgrade yet
  ([issue 315](https://github.com/vishalsachdev/canvas-mcp/issues/315)).

### Added

- `delete_assignment_with_confirmation`: two-step assignment deletion whose
  preview shows due date, points, and whether submissions exist, and warns that
  submissions and grades are deleted with the assignment
  ([issue 318](https://github.com/vishalsachdev/canvas-mcp/issues/318)).
- `ACCESSIBILITY_CHECKERS` setting (default `ufixit`, alias `udoit`; `none`
  leaves the three UFIXIT report tools unregistered for institutions without
  the add-on). The built-in scanner is always available. Exposed in
  `env.template`, the Desktop Extension settings and `server.json`
  ([issue 325](https://github.com/vishalsachdev/canvas-mcp/issues/325)).
- Educator-only content migration tools for previewing and confirming a full
  course-copy request, then polling its progress and reviewing all terminal
  migration issues ([issue 309](https://github.com/vishalsachdev/canvas-mcp/issues/309)).
- Skill Request issue template, so a workflow can be requested in plain
  language without a Canvas API endpoint
  ([issue 302](https://github.com/vishalsachdev/canvas-mcp/issues/302)).

### Changed

- `delete_announcements_by_criteria` is idempotent now that its token is bound
  to the exact match set; a retry can no longer delete the next batch
  ([issue 318](https://github.com/vishalsachdev/canvas-mcp/issues/318)).
- `datetime.timezone.utc` → `datetime.UTC` and `asyncio.TimeoutError` → the
  builtin alias throughout, enabled by the 3.11 floor. No behaviour change.

## [1.11.0] — 2026-08-20

### Changed

- Raised the FastMCP 3.x dependency floor from 3.4.4 to 3.4.7, picking up
  upstream fixes for Azure scope fallback, deterministic transformed-tool
  schemas, trusted OAuth metadata/JWKS proxies, and `private_key_jwt` audience
  validation
  ([issue 293](https://github.com/vishalsachdev/canvas-mcp/issues/293)).
- **Breaking:** `send_peer_review_reminders` is now
  `send_peer_review_inbox_messages` to accurately describe that it sends
  ordinary Canvas Inbox messages rather than invoking Canvas's native reminder
  action. The tool now resolves the course and requires `manage_grades` before
  previewing or sending, failing closed when permission cannot be verified
  ([issue 303](https://github.com/vishalsachdev/canvas-mcp/issues/303)).

### Fixed

- Student submission confirmations now share the verified nonce guard: changed
  content burns the token, clock rollback cannot revive expiration, and active
  submissions retain their fingerprint claims beyond the preview TTL (#404).
- Peer-review Inbox errors after dispatch report uncertain delivery instead of
  claiming nothing was sent. Follow-up campaign summaries count acknowledged
  recipient batches correctly and report partial failure as unsuccessful.
- Lean/TLA+ models and real-code regressions now cover the scoped confirmation,
  request, grading, pagination, delete and peer-review control planes. See
  `verify/README.md` for the proof boundaries and reproducible evidence.

- Tool failures now set MCP `isError: true` while preserving their existing
  text or structured payload ([issue 270](https://github.com/vishalsachdev/canvas-mcp/issues/270)).
- String-returning tools no longer duplicate the same value in text content
  and `structuredContent.result`; dictionary tools retain their structured
  schemas ([issue 271](https://github.com/vishalsachdev/canvas-mcp/issues/271)).

## [1.10.0] — 2026-08-15

A community bug-fix release driven by live reporter testing
([@khagyard](https://github.com/khagyard), [@zqian](https://github.com/zqian),
[@jonespm](https://github.com/jonespm)). One change is **breaking**.

### Changed

- **Breaking: `search_canvas_tools` response shape v2**
  ([issue 281](https://github.com/vishalsachdev/canvas-mcp/issues/281),
  [#286](https://github.com/vishalsachdev/canvas-mcp/pull/286)). The tool now
  searches the ~99 registered MCP tools as well as the TypeScript
  code-execution API files (previously it silently searched only the latter,
  so "peer review" returned nothing useful despite ~10 peer-review MCP tools
  existing). The response carries `schema_version: 2` with labeled
  `mcp_tools` and `code_execution_api` sections; the old flat `tools` key is
  gone. Diagnosis credit: [@bruchris](https://github.com/bruchris).
- **Full-detail code-API content is capped at 2,000 characters**
  ([issue 287](https://github.com/vishalsachdev/canvas-mcp/issues/287),
  [#290](https://github.com/vishalsachdev/canvas-mcp/pull/290) by
  [@SHIL0018](https://github.com/SHIL0018)) so discovery cannot flood the
  model context with entire source files.

### Fixed

- **Students' peer-review to-dos are now discoverable**
  ([issue 275](https://github.com/vishalsachdev/canvas-mcp/issues/275)).
  `get_my_peer_reviews_todo` gained a direct `assignment_identifier` lookup
  ([#277](https://github.com/vishalsachdev/canvas-mcp/pull/277)) and a
  Planner-feed discovery path
  ([#288](https://github.com/vishalsachdev/canvas-mcp/pull/288)) — the same
  data source Canvas's own student UI uses; the assignment-scoped endpoints
  the scan previously relied on are instructor-focused. Validated against a
  real production payload supplied by the reporter.
- **`create_announcement` no longer leaves a silent discussion topic behind
  on a student token**
  ([issue 283](https://github.com/vishalsachdev/canvas-mcp/issues/283)).
  Canvas answers 200 to the create but drops `is_announcement` for tokens
  without announcement permission, creating a regular discussion topic. The
  tool now pre-checks course permissions
  (`GET /courses/:id?include[]=permissions` — measured live: only the
  single-course endpoint carries the flag) and refuses before creating
  anything; if a downgrade still slips through, the unintended topic is
  deleted automatically. Both discussion tools and the error text also steer
  AI clients away from "posting it as a discussion instead"
  ([#285](https://github.com/vishalsachdev/canvas-mcp/pull/285),
  [#291](https://github.com/vishalsachdev/canvas-mcp/pull/291)). Mechanism
  identified by [@jonespm](https://github.com/jonespm).

### Security

- Stricter URL validation replaces an incomplete substring check
  (code-scanning alert, [#278](https://github.com/vishalsachdev/canvas-mcp/pull/278)).
- Docker base image bumped to `python:3.14-slim`; CI actions group updated.

## [1.9.0] — 2026-08-10

### Security

- **Canvas-authored free text is now provenance-fenced before it reaches the
  model** ([issue 239](https://github.com/vishalsachdev/canvas-mcp/issues/239)).
  Page content including titles and media inventories (`get_page_content`,
  `get_page_details`, `get_front_page`), syllabus text (`get_syllabus`,
  `get_course_content_overview`), discussion topics/entries/replies
  (`get_discussion_topic_details`, `list_discussion_entries`,
  `get_discussion_entry_details`, `get_discussion_with_replies`), and inbox
  subjects and message bodies (`list_conversations`,
  `get_conversation_details`) are wrapped in explicit
  `<<<UNTRUSTED CANVAS CONTENT ...>>>` markers stating the text is data, not
  instructions. Author-controlled *derived* values (page and discussion-topic
  titles, embedded-media src/alt inventory) sit inside the fence too, not
  around it. Content is
  otherwise unaltered (no sanitization or loss); embedded marker lookalikes
  are degraded so fenced text cannot forge its own boundary. Fencing is
  applied at the tool output-formatting boundary only — never in the
  anonymization/client layer — so no fence can leak into content written back
  to Canvas.
- **All multi-recipient message sends are now two-step** (breaking):
  `send_bulk_messages_from_list`, `send_conversation` with more than one
  recipient, `send_peer_review_reminders`, and
  `send_peer_review_followup_campaign` require a preview→confirm round-trip.
  Calling without a `confirmation_token` returns a preview (recipients,
  rendered subject/body — for the campaign, the completion analytics and who
  gets which reminder) plus a single-use, content-bound token and sends
  nothing; sending requires calling again with the token and identical
  arguments. Tokens are void if anything changed in between (including the
  campaign's completion analytics or an assignment rename that alters the
  composed reminder). `send_conversation` stays a single call only for
  exactly one plain numeric user ID — expandable recipient aliases
  (`course_*`/`group_*`) fan out server-side and are treated as
  multi-recipient. The bulk preview renders **every** outbound message (not
  a sample), and rows with invalid or alias user IDs fail the preview before
  a token is issued. The campaign previews the full rendered subject/body of
  every batch and its token commits to that text, so an assignment rename
  between preview and confirm voids the token. Confirmation claims are only
  released on provable rejections (4xx validation/auth statuses: 400, 401,
  403, 404, 422, or pre-flight validation); timeouts, 408/409/429, and all
  5xx are treated as ambiguous — the POST may have been processed — so the
  claim stays spent and a retry cannot double-send. Shared outbound
  validation (subject length, mode, marker check) is enforced at the
  conversation-POST choke point, so no composed path can route around it.
  This extends the `submit_assignment` confirmation pattern to the educator
  side, so prompt-injected content read from Canvas cannot silently trigger
  a fan-out send.
- **Completeness pass — author-controlled free text is fenced across every
  read tool.** Beyond bodies and titles, the following author-set fields are
  now provenance-fenced at their tool-output boundary: assignment
  names/descriptions, module names + item titles, discussion/announcement
  author display names, page editor display name, uploader-set filenames,
  group names + member names/emails, roster user names/emails, student
  analytics names, rubric titles + criterion/rating descriptions + assessment
  comments, peer-review comment text + participant names, and student-planner
  assignment titles. Short identity labels (names, emails, filenames) use a
  compact single-line fence so dense rosters/analytics stay readable; bodies
  and descriptions keep the block fence. A recursive key-based fence covers
  the peer-review analyzer JSON at the model-facing return only (the CSV and
  on-disk exports are untouched — CSV injection is handled separately). The
  only author-controlled fields deliberately left unfenced are course
  names/codes and the caller's own profile (low-risk course/self identity).
- **Known limitation:** enabling `execute_typescript`
  (`EXECUTE_TYPESCRIPT_ENABLED=true`; off by default, disabled on hosted
  deployments) voids the confirmation-token and fencing guarantees above —
  the sandbox receives `CANVAS_API_TOKEN` and can reach the Canvas API
  directly, so code run there can fan out messages or write content without
  any preview/confirm step. This is the known
  [issue 157](https://github.com/vishalsachdev/canvas-mcp/issues/157) class
  (the in-process network guard is bypassable); a tool-level block would be
  security theater while raw fetch to the Canvas host remains open, so it is
  documented rather than faked.
- **The confirmation-token guard authenticates before recording a nonce**, so
  a flood of forged/unsigned tokens can no longer grow its in-memory map
  (a memory-exhaustion DoS). Tokens gained a fingerprint-independent
  authenticator (so the burn-on-mismatch path can still authenticate a
  genuinely-issued token), a max-length cap, and a hard ceiling on the tracked
  nonce set. Because only authenticated, unexpired tokens can ever be
  recorded, the tracked set is inherently bounded by issuance-rate × TTL and
  each entry self-drains on its own expiry — so there is **no capacity cap and
  no eviction** (either would drop a legitimate burn or resurrect a used
  nonce). Recording is unconditional for an authenticated token, so a
  burn-on-mismatch always keeps that token invalid for its full remaining
  signed lifetime.
- Grading writers (`bulk_grade_submissions`, `grade_with_rubric`) reject
  fenced content in grade comments **and every per-criterion rubric comment**,
  so a comment lifted from fenced read output cannot publish provenance markers
  into the student-visible gradebook. The student write tools (`submit_assignment`
  body/comment, `comment_on_my_submission`) and `create_rubric`
  (title + all criterion/rating descriptions) carry the same backstop.
- Write tools that publish free text (`create_page`, `edit_page_content`,
  `post_discussion_entry`, `reply_to_discussion_entry`,
  `create_discussion_topic`, `update_discussion_topic`, `create_announcement`,
  `create_assignment`, `update_assignment`, `create_module`, `update_module`,
  `add_module_item`, `update_module_item`,
  `send_conversation`, `send_peer_review_reminders`,
  `send_bulk_messages_from_list`) refuse content containing the fence markers
  in every writable text field, titles included, so a fenced read result
  cannot be round-tripped into live Canvas content. The check also runs at
  the shared conversation-POST choke point on the final composed subject and
  body, catching markers that arrive via Canvas-authored inputs such as an
  assignment name.

### Supply chain

- **The repository now publishes an OSSF Scorecard** to the public OpenSSF API
  (`api.scorecard.dev/projects/github.com/vishalsachdev/canvas-mcp`), currently
  7.1/10, refreshed weekly and on every push to `main`. Along the way: all
  GitHub Action references are pinned by commit SHA (one was a mutable branch
  ref), every workflow declares least-privilege token permissions, the Docker
  base image is pinned by digest, and Dependabot covers pip, npm, docker, and
  Actions.
- **`canvas-mcp.mcpb` releases now ship SLSA build provenance** (attached as
  `canvas-mcp.mcpb.intoto.jsonl`, starting with this release). The bundle is
  downloaded independently of PyPI, so PyPI's provenance never covered it.
  Verify with `gh attestation verify canvas-mcp.mcpb --repo
  vishalsachdev/canvas-mcp`. The bundle is also now built in a job with no
  release-write authority, and the packing CLI is version-pinned instead of
  `@latest`.
- Patched a DoS in the `execute_typescript` sandbox's transitive `diff`
  dependency (GHSA-73rr-hh4g-fpgx; 4.0.2 → 4.0.4 via npm override).

### Removed

- **The npm setup wizard (`npx canvas-mcp setup`) is retired and the `canvas-mcp`
  npm package deprecated** (#249). The wizard wrote client configs pointing at
  the retired `mcp.illinihunt.org` hosted endpoint (no DNS record) while also
  collecting the user's Canvas API token, so every run produced a broken config.
  The documented install paths — the Desktop Extension (`.mcpb`) and manual
  client configuration per the README — were already the only ones referenced
  anywhere in the docs. The npm package name remains reserved (deprecated, not
  unpublished) so it cannot be claimed by a third party.
- `docs/workshop.html` — an orphaned March 2026 workshop page (not linked from
  the site) whose instructions were built around the retired wizard and hosted
  endpoint.

## [1.8.0] — 2026-08-09

### Security

A repository-wide security scan produced twelve findings. Eleven are addressed
here; the twelfth (sandbox egress) is partially addressed and labelled honestly
rather than papered over. Two independent review rounds ran against the result.

#### Cross-boundary primitives reachable from a remote caller

- **`download_course_file` was an arbitrary write, and `upload_course_file` an
  arbitrary read, on a shared HTTP server.** Download let the caller choose the
  destination directory while Canvas supplied the filename and bytes; upload let
  the caller name any path the service account could read and copy it into their
  own Canvas course. Both are legitimate on a local stdio server — that
  filesystem *is* the caller's own machine — so each is refused **by transport**
  rather than removed. Download points at `read_course_file`, which returns
  content in the response and was already the right tool for a remote caller.
- **Local downloads no longer overwrite.** Canvas controls the filename, so a
  course file named `.zshrc` could silently truncate a real file in the chosen
  directory. The destination is now created exclusively and owner-only
  (`O_EXCL`, `O_NOFOLLOW` where the platform has it, mode `0600`), which also
  refuses a pre-planted symlink, and a failed download unlinks its partial file
  instead of leaving truncated content behind.

#### A hard-coded `/submissions/self` suffix did not guarantee self-scoping

- **A path delimiter in an identifier retargeted self-scoped student tools at
  another student's submission.** Identifiers are typed `str | int` and
  interpolated into a path template, and that union accepts any string. Measured,
  not inferred: with `assignment_id="123/submissions/456?"`, `get_my_submission`
  issued a live request to `/api/v1/courses/60366/assignments/123/submissions/456`
  while the endpoint string still ended in `/submissions/self`. Canvas answers
  that for any token also holding grading permission, so a mixed student/grader
  account could read or comment on another student's FERPA-protected submission.
  `#` and percent-encoded `%2F` behaved the same. Closed in two layers:
  `make_canvas_request` now refuses any endpoint containing `?`, `#`, or a `..`
  segment — every caller passes query parameters via `params=`, so a delimiter in
  the path is always smuggling, and this covers all 23 interpolation sites at
  once — and `coerce_canvas_id()` pins the identifier grammar to ASCII digits at
  the self-scoped routes.

#### Privacy and untrusted content

- **The MCP Registry manifest published `ENABLE_DATA_ANONYMIZATION` default
  `false`** while the code, the Dockerfile, and `env.template` all defaulted it
  to `true`. For any Registry client that materializes declared defaults, the
  advertised install path started with student-data anonymization **off**. The
  manifest now declares `true`, and a test compares all four sources so the
  drift cannot recur silently.
- **CSV exports could hand a spreadsheet an executable formula.** Peer-review
  comment text is authored by another student, and Canvas names and emails are
  user-controlled on many instances. A comment beginning `=`, `+`, `-`, `@`, tab,
  or carriage return is evaluated as a formula when an instructor opens the
  report; quoting does not prevent this. `core/csv_safety.py` is now the single
  encoder for every export path. Two exporters also assembled CSV by string
  concatenation and escaped only double quotes, so a comment containing a comma
  or newline produced malformed rows; both now use the stdlib writer.

#### Credentials

- **A cleartext `http://` Canvas URL is refused instead of warned about.** The
  token is sent in an `Authorization` header on every request, so a cleartext
  origin exposes a credential for student records. Enforced on **both** startup
  paths — HTTP mode never calls `validate_config()`, and it is the more
  dangerous case, since the Canvas URL is server-pinned and one typo would leak
  every caller's token rather than only the operator's. `CANVAS_ALLOW_INSECURE_HTTP`
  is a development-only escape hatch restricted to loopback addresses.
- **The setup CLI writes token-bearing configs and backups `0600`** instead of
  inheriting an umask that yields `0644`, and no longer echoes the full token to
  the terminal, where it would land in scrollback and shell history.

#### Availability and blast radius

- **The unauthenticated access-confirm route is bounded.** It is intercepted
  ahead of every token gate and read an unlimited body; it now requires POST and
  stops at 8 KiB, chunked uploads included, for a payload that only ever carries
  one short signed token.
- **Denied-identity notifications are rate-limited before any work happens.** The
  403 is returned first (correctly), so a denied caller can repeat at will, and
  the duplicate-mail cooldown lived inside the scheduled task — after an Azure
  credential, a client, an asyncio task, and a storage round-trip. Admission
  control now runs first: 200 repeated denials cause one client build.
- **Code execution fails closed when isolation is unavailable.** An explicit
  `TS_SANDBOX_MODE=container` fell back to running caller-supplied TypeScript
  directly on the host when no runtime was present or the image name was
  malformed. It now refuses, and no unsandboxed mode may run while serving an
  HTTP request.
- **The weekly AI maintenance workflow lost its excess privileges.** It reviews
  public issue text and web results — writable by anyone — while holding a
  GitHub token, so the token is the control: reduced from `contents:write` +
  `pull-requests:write` + `Bash(gh:*)` to `contents:read` + `issues:write` and
  four specific `gh` commands, with the prompt now framing fetched content as
  data rather than instructions.
- **Security tests can fail the build.** `security-testing.yml` ran
  `tests/security/` with `continue-on-error: true`, so every invariant in that
  suite — including the anonymization and authorization ones predating this
  work — passed green through any regression.

#### Known limitation

- **Sandbox egress remains best-effort and now says so.** `--network=none` is
  passed when outbound is blocked and the allowlist is empty, which is real
  kernel-level enforcement — but when blocking is on, the Canvas host is
  automatically allowlisted, because executed code exists to call Canvas. So in
  every working configuration the allowlist is non-empty and egress falls back to
  patching Node APIs in-process, which `child_process`, `dgram`, and bundled
  utilities can step around while `CANVAS_API_TOKEN` is in the environment. The
  tool now emits an explicit best-effort warning instead of implying enforcement.
  Closing it needs an egress proxy or network namespace
  ([#157](https://github.com/vishalsachdev/canvas-mcp/issues/157)).

### Changed

- **Breaking: an `http://` `CANVAS_API_URL` now aborts startup** in both stdio
  and HTTP transports. Set `CANVAS_ALLOW_INSECURE_HTTP=true` for a loopback
  development Canvas; it does not permit cleartext to a remote host.
- **Breaking: `download_course_file` and `upload_course_file` are stdio-only.**
  Over HTTP transport they refuse with a message pointing at the alternative.
- **Breaking: `download_course_file` errors rather than overwriting** an existing
  destination file.
- **The MCP Registry manifest's anonymization default changed from `false` to
  `true`**, matching every other distribution channel.
- **Dependency floors raised to the first safe patch lines** (PR #255):
  `fastmcp>=3.4.4` — the previous `>=3.2` floor permitted 3.2.0–3.2.3 on a
  fresh unlocked install, which carry CVE-2026-32871 and CVE-2026-27124 —
  and `uvicorn>=0.50.0`. Locked resolutions were already safe.
- **`contents: read` least-privilege permissions on the test, deploy, and
  security workflows** (PR #255), with a policy test asserting them so the
  scope-down cannot silently regress.
- **Documented role-profile tool counts corrected to measured values**
  (PR #255): student ~37, educator ~88, all 94 by default and 99 with every
  feature-gated tool enabled. README no longer claims rubric creation must be
  done in the Canvas UI (`create_rubric` shipped in v1.3.0).

### Known issues

- The npm setup wizard still configures clients against the retired
  `mcp.illinihunt.org` endpoint, which no longer resolves. Converting it to the
  local stdio path is not a URL swap — the documented stdio config uses an
  absolute venv binary path and credentials live in the server's `.env`
  ([#249](https://github.com/vishalsachdev/canvas-mcp/issues/249)).


## [1.7.0] — 2026-08-08

### Added
- **Missing MCP tool annotations across ~29 write tools**, plus docstrings for `list_courses`' previously undocumented `include_concluded` / `include_all` flags ([#200](https://github.com/vishalsachdev/canvas-mcp/issues/200), first contribution from the Copilot coding agent in [#201](https://github.com/vishalsachdev/canvas-mcp/pull/201)).
- **`tests/test_tool_metadata.py` gates the annotation contract.** It enumerates the live registry rather than a hand-maintained list, so a *new* tool registered with a bare `@mcp.tool()` fails CI instead of shipping unannotated — the failure mode that produced #200. The registry is built with every feature gate switched on (`EXECUTE_TYPESCRIPT_ENABLED`, `STUDENT_WRITE_TOOLS`), since coverage must follow capability rather than default configuration; checking only the default set would have passed while `execute_typescript` — arbitrary TypeScript against the caller's Canvas token — shipped with no annotations at all. It is now marked destructive and non-idempotent, the conservative reading, because nothing about caller-supplied code can be inspected in advance. Classifications for grade-writing and deleting tools are pinned explicitly, so a flip has to be a deliberate edit rather than a silent diff.

### Changed
- **Tool annotations now follow the MCP spec rather than a local convention.** `destructiveHint=False` asserts a tool "performs only additive updates"; the repo had been reading it as "doesn't delete", which left `bulk_grade_submissions`, `grade_with_rubric`, `edit_page_content`, `bulk_update_pages`, `fix_accessibility_issues`, every `update_*`, `upload_course_file` and `create_student_anonymization_map` claiming to be additive-only while they overwrite grades, page bodies, files and settings. Those are now `destructiveHint=True`. A client has no way to know the server meant something narrower, and grading tools are the worst place for that gap. The `create_` prefix turned out not to be a safe guide: `create_page` with `front_page=True` unseats the course's existing front page, and both `create_rubric` with an `assignment_id` and `associate_rubric` attach a rubric over whatever was already associated, so those three are destructive too. Genuinely additive tools (`create_announcement`, `create_assignment`, `create_discussion_topic`, `create_module`, `create_rubric_from_csv`, `post_*`/`reply_*`, `send_*`, `add_module_item`, `assign_peer_review`, `mark_conversations_read`) stay `False`, so this costs no extra confirmations where none are warranted ([#204](https://github.com/vishalsachdev/canvas-mcp/issues/204)).
- **`idempotentHint` is now set on every write tool** — it was never set anywhere, leaving the third of #200's three annotations unaddressed. `update_*`, `delete_*` and `edit_page_content` converge on the same end state and are idempotent; anything that creates a record is not, including `upload_course_file`, whose default `on_duplicate="rename"` writes a new file on every call. Idempotency is judged on a tool's **whole effect, not just its primary resource**: `bulk_grade_submissions` and `grade_with_rubric` settle on the same score but append a new submission comment whenever `comment` is supplied, and `update_page_settings` / `bulk_update_pages` settle on the same body but re-notify the course whenever `notify_of_update=True` — so all four are non-idempotent. `delete_announcements_by_criteria` is non-idempotent for a related reason: it re-derives its target set at call time and slices `matched[:limit]`, so an identical retry deletes the *next* batch, up to twice the requested limit. (Its sibling `bulk_delete_announcements` takes explicit ids and remains idempotent.) A retry that silently duplicates feedback to every student in a course is the harm this hint exists to prevent. A host retrying a timed-out call can now tell these apart ([#204](https://github.com/vishalsachdev/canvas-mcp/issues/204)).
- **`check_enrollment` documentation is institution-neutral.** "NetID" is a UIUC term; the parameter accepts a NetID, uniqname, campus ID, or email-style Canvas login, and the docs now say so — along with the fact that it is not a display name, and that `role` defaults to `student` ([#199](https://github.com/vishalsachdev/canvas-mcp/issues/199)).
- **Anonymization consolidated into the client layer.** The FERPA scrub had been applied at several call sites, which is a design that fails quietly: a new tool that forgets the call is anonymized nowhere, and nothing tells you. It now runs in one place on the way out of `make_canvas_request`, so coverage follows the request rather than the author's memory ([#179](https://github.com/vishalsachdev/canvas-mcp/issues/179)).
- **Explicit `/api/quiz/v1` routing in the core client**, with `/api/v1` normalization and the anonymization gate both unchanged, plus `api_root` threaded through `fetch_all_paginated_results` so paginated calls against a non-default API root no longer fall back to `/api/v1` partway through ([#192](https://github.com/vishalsachdev/canvas-mcp/issues/192), [#193](https://github.com/vishalsachdev/canvas-mcp/pull/193), [#197](https://github.com/vishalsachdev/canvas-mcp/pull/197)).

### Fixed
- **`check_enrollment` reported "no enrollment" for people plainly on the roster.** Two independent defects, both rooted in an unverified premise about identifiers. (1) The matcher required exact equality against `login_id`/`sis_user_id`. Canvas does not define what `login_id` holds — measured live, UIUC stores the bare NetID (`vishal`), while instances that provision Canvas logins from email store the full address (`uniqname@umich.edu`), which the bare identifier could never match. Matching is now two-pass: exact equality across the whole roster first, then email-local-part equivalence, so `zqian` finds `zqian@umich.edu` and vice versa. Because this tool is documented as an external access gate, the fallback only ever runs in the direction where the roster is authoritative — a bare identifier may match a domain-qualified roster value, never the reverse. Anything it cannot verify returns the new **AMBIGUOUS** answer instead of a yes or a no: two differing full addresses (`jdoe@school.edu` vs `jdoe@other.edu`) are different people and a bare secondary `sis_user_id` on that user cannot smuggle the match back in; a bare `jdoe` matching both `jdoe@a.edu` and `jdoe@b.edu` will not let roster ordering decide an authorization question; and a qualified identifier offered to a roster that stores bare IDs is unverifiable, since `jdoe@attacker.example` has exactly as much claim on a stored `jdoe` as the real domain does. (2) An email-form identifier was rejected by the input guard *before any Canvas call was made*, because the pattern excluded `@`; `@` and `+` are now accepted ([#199](https://github.com/vishalsachdev/canvas-mcp/issues/199)).
- **A role-scoped `check_enrollment` "NO" now says what the person actually is.** `role` defaults to `student`, and the role filter was pushed to Canvas as `type[]`, which hid every other enrollment the subject held. Asking about a teacher therefore returned `NO — … has no active 'student' enrollment`: true, but indistinguishable from "not in this course". The whole roster is now fetched (the same single request) and the role evaluated locally, so a negative names the roles the subject does hold — `They ARE enrolled in this course, as: TeacherEnrollment` — while a genuine stranger still gets a clean NO with no role clause. `EnrollmentResult` gained `roles_held` ([#199](https://github.com/vishalsachdev/canvas-mcp/issues/199)).
- **`upload_course_file` no longer dumps files into a stray "unfiled" folder.** With no `folder_path`, the tool omitted `parent_folder_path` entirely — which is not "use the root", it makes Canvas create and use a folder literally named `unfiled`. The docstring had always documented the root as the default, so this was a doc-vs-behavior divergence. Verified live with a three-way A/B against a real course: no parameter → `course files/unfiled`; `parent_folder_path=""` → `course files`; `parent_folder_id=<root>` → `course files`. The empty string is now always sent, which targets the root without the extra `/folders/root` lookup the id form would need ([#198](https://github.com/vishalsachdev/canvas-mcp/issues/198)).

#### Writes that reported success without doing anything

Four reports arriving within ~40 minutes on 2026-08-03 — three from a first-time reporter testing v1.6.0 with a **student** token — turned out to be one defect class: trusting a Canvas `200` that did less than asked. All four were fixed and deployed the next morning.

- **`create_announcement` created a plain discussion topic and called it an announcement.** Canvas silently dropped `is_announcement` for a caller without announcement permission, returning `200` with an ordinary topic. The tool built its success message from `id`/`title` and never checked `is_announcement` in the response, so the post landed in the wrong place while the caller was told it worked ([#220](https://github.com/vishalsachdev/canvas-mcp/issues/220)).
- **`get_my_peer_reviews_todo` reported "no pending peer reviews ✅" when two were assigned.** Two defects stacked: a permission-gated listing returned an error dict, which a bare `isinstance(..., list)` check discarded without a word — making a `401` indistinguishable from an empty list — and the tool never filtered by `assessor_id` at all, so even when it did return rows they were not scoped to the caller. A false "you're all caught up" is the worst possible failure for this tool ([#219](https://github.com/vishalsachdev/canvas-mcp/issues/219)).
- **`mark_module_item_done` reported success on items that cannot be marked done.** Canvas's `done` endpoint only has an effect on items carrying a `must_mark_done` completion requirement; measured live, ordinary items carry `completion_requirement: null` and the `PUT` is a silent no-op. The tool now checks the requirement and says so plainly instead of claiming a state change that never happened ([#221](https://github.com/vishalsachdev/canvas-mcp/issues/221)).
- **`unconfirmed_write_warning` is now shared infrastructure.** The guard introduced for rubric writes in 1.6.0 gained a third consumer here, so it moved from a rubrics-local helper to `core/write_confirmation.py`. The rule it encodes: never report a write as successful on HTTP status alone — confirm the intended effect in the response body, and say so honestly when you cannot.

#### Other fixes

- **`get_my_upcoming_assignments` ignored the `days` range and always returned 7 days.** Self-diagnosed correctly by the reporter: `/users/self/upcoming_events` is hardcoded server-side to a 7-day window (it is the dashboard "Coming Up" feed), so the `days` parameter could only ever *narrow* an already-capped list, never widen it — `days=30` quietly lied. Now uses the Planner API with a real date window. Two bonuses fell out of the switch: planner items carry `submissions.submitted`, which removes the per-assignment N+1 the old path needed, and graded discussions are included, which the old feed omitted ([#222](https://github.com/vishalsachdev/canvas-mcp/issues/222)).
- **`bulk_update_pages` failed with a Canvas 500 on every page.** It sent a nested `wiki_page` dict with `use_form_data=True`; form encoding cannot represent nesting, so the Python `repr` of the dict went out on the wire ([#207](https://github.com/vishalsachdev/canvas-mcp/issues/207)).
- **`mark_conversations_read` errored on every call.** The mirror-image bug: it sent JSON to `/conversations`, which Canvas requires as form data, so `conversation_ids[]` never arrived as a repeated parameter. Its sibling `send_conversation` had carried a code comment about this requirement for the whole time ([#208](https://github.com/vishalsachdev/canvas-mcp/issues/208)).
- **`create_rubric_from_csv`'s documented CSV format was wrong and created zero rubrics.** The documented columns did not match what the parser read, so anyone following the docs got nothing. The format is corrected, `succeeded_with_errors` is now handled as its own outcome rather than folded into success, and `error_data` is surfaced to the caller instead of dropped ([#190](https://github.com/vishalsachdev/canvas-mcp/issues/190)).

### Security
- **`cryptography` 49.0.0 → 50.0.0**, clearing **CVE-2026-69247**. The stale lockfile had been failing the Dependency Vulnerability Scan on every PR opened that day, so this was blocking unrelated work as well ([#226](https://github.com/vishalsachdev/canvas-mcp/pull/226)).

### Internal
- **mypy is clean and gated in CI** — 229 errors to 0, with `mypy src/` added to the lint job ([#106](https://github.com/vishalsachdev/canvas-mcp/issues/106)).
- **`TOOL_MANIFEST.json` is at full registry parity and CI-gated.** The manifest documented 30 tools against a live registry of 99; the 69 missing entries were derived from each tool's real signature and registered `inputSchema` rather than written by hand ([#173](https://github.com/vishalsachdev/canvas-mcp/issues/173)).
- **`tools/README.md` documents every tool in the manifest** — 34 were missing, plus `get_course_content_overview`, which was referenced but never documented ([#215](https://github.com/vishalsachdev/canvas-mcp/issues/215)).
- **A closing-keyword guard blocks accidental issue closures.** GitHub closes an issue on any `fixes|closes|resolves #N` in a merged PR body *or* in a commit message landing on `main` — including prose that only *describes* other work. One issue was closed twice this way, the second time by a commit whose message documented the first accident. One detector (`scripts/check_closing_keywords.py`) is now shared by a `commit-msg` hook and a CI workflow; it blocks keywords mid-sentence and allows ones that open a line, a split derived by replaying it over every commit on `main` rather than chosen by taste. Contributors run `./scripts/install-hooks.sh` once per clone ([#231](https://github.com/vishalsachdev/canvas-mcp/pull/231)).

## [1.6.0] — 2026-07-30

### Added
- **Tier 1 student write tools, off by default behind a two-key gate.** A student-role caller can now act on their own work — the tools are enabled only when the operator sets `STUDENT_WRITE_TOOLS` (an explicit per-tool allowlist, empty by default), and optionally further restricted per course by `COURSE_AGENT_POLICY_ENABLED`, which can only narrow that allowlist and never widen it. The policy carrier is the **course syllabus**; a draft that used a course page as the carrier was deliberately removed, because a page's `editing_roles` proves who may edit it, not who wrote it — so a student able to edit the page could author their own permissions. Multi-worker HTTP deployments have an extra note in `env.template` for `submit_assignment` ([#170](https://github.com/vishalsachdev/canvas-mcp/issues/170)).
- **`get_my_enrollments` and `get_my_profile` tools** — answer "what am I enrolled in, and as what role?" and "who am I?" about the authenticated caller. Registered under **every** role profile because they describe only the caller and need no roster permission. `get_my_enrollments` reads `GET /courses` (which returns course name/code *and* the caller's own `enrollments[]` in one call) rather than `/users/self/enrollments`, which returns bare course IDs, and reports all roles when the caller holds more than one enrollment in a course ([#171](https://github.com/vishalsachdev/canvas-mcp/issues/171)).

### Changed
- **⚠️ BREAKING for existing `execute_typescript` users: code execution is now opt-in.** `EXECUTE_TYPESCRIPT_ENABLED` defaults to **`false`** (it was effectively `true` for stdio installs). If you use `execute_typescript`, you must now set `EXECUTE_TYPESCRIPT_ENABLED=true` explicitly — otherwise the tool is unavailable. This follows the hardening direction in [#157](https://github.com/vishalsachdev/canvas-mcp/issues/157): a code-execution surface should be a deliberate choice, not something you get by default ([#178](https://github.com/vishalsachdev/canvas-mcp/issues/178)).
- **The Docker image now ships `ENABLE_DATA_ANONYMIZATION=true`** (was `false`), matching the code default. The FERPA layer is opt-out rather than opt-in for anyone deploying from the image ([#178](https://github.com/vishalsachdev/canvas-mcp/issues/178)).
- **Upgraded to `fastmcp` 3.x** (`>=3.2,<4`, from 2.14.7), which clears **PYSEC-2026-2475** and **PYSEC-2026-2476**. No user-facing changes: same tools, same transports, HTTP endpoint unchanged at `/mcp`. Staging-validated before production deploy ([#145](https://github.com/vishalsachdev/canvas-mcp/issues/145)).
- **`list_courses` and `get_course_details` now surface your own role in each course.** Canvas already returns the caller's `enrollments[]` on both endpoints; the tools were discarding it, which pushed agents toward roster tools they have no permission for. `get_course_details` now says "You have no enrollment in this course" explicitly rather than staying silent ([#171](https://github.com/vishalsachdev/canvas-mcp/issues/171)).

### Fixed
- **`associate_rubric` never actually attached the rubric.** It sent a nested `rubric_association` JSON body to `PUT /courses/:id/rubrics/:id` with no form encoding. Canvas answered **200** — the rubric itself is valid — but never parsed the association parameters, so nothing appeared on the assignment page while the tool reported "successfully associated". Now posts flat bracket-notation form data to `POST /courses/:id/rubric_associations`. Verified against a live Canvas instance with an A/B against the old code path: old → `rubric_association: None` and no rubric in the UI; fixed → association created and rendered ([#181](https://github.com/vishalsachdev/canvas-mcp/issues/181)).
- **No rubric write reports success without a confirmed association.** [#180](https://github.com/vishalsachdev/canvas-mcp/issues/180) and [#181](https://github.com/vishalsachdev/canvas-mcp/issues/181) were the same defect in two different functions, each with its own idea of what counted as proof. The check now lives in one place (`rubric_association_id`), which requires an **id** in the payload rather than a truthy dict — closing a latent hole where an association object carrying no id was accepted as a successful bookmark.
- **Created rubrics are bookmarked into the course so Canvas shows them.** A rubric returned with `rubric_association: null` is listed by `GET /courses/:id/rubrics` but does not appear in the Canvas Rubrics UI. `create_rubric` now creates the Course bookmark association explicitly and never reports plain success on an orphaned rubric ([#180](https://github.com/vishalsachdev/canvas-mcp/issues/180)).
- **HTTP transport now runs stateless (`stateless_http=True`)**, eliminating the stale-session hang for hosted deployments. Previously the server kept an in-memory session table; a host restart (e.g. Azure App Service recycle) dropped it, the next request's `Mcp-Session-Id` drew a 404, and `mcp-remote` hung indefinitely instead of re-initializing. With stateless HTTP every request is self-contained — credentials already arrive per-request via `X-Canvas-Token`, and no tool uses server-initiated session features, so nothing can go stale ([#159](https://github.com/vishalsachdev/canvas-mcp/issues/159)).
- **`create_student_anonymization_map` produced a useless map.** It fetched the roster *through* the anonymizer, so it recorded pseudonym-to-pseudonym pairs; the tool cannot have worked as intended since anonymization became default-on. `fetch_all_paginated_results` gained an opt-in `skip_anonymization` flag (default off, so every other caller is unchanged) and this one caller uses it. The export writes a local file for an instructor who already has roster access ([#179](https://github.com/vishalsachdev/canvas-mcp/issues/179)).
- **`check_enrollment` no longer returns a confident false negative when the token lacks roster rights.** Canvas gates `user.login_id` and `user.sis_user_id` on roster-admin permission but does **not** error without it: the request returns HTTP 200 with the full roster and every `user` object silently reduced to `{created_at, id, name, short_name, sortable_name}`. The NetID match therefore never succeeded, and the tool answered a definitive "NO". It now detects that the identifier fields were withheld and returns **INDETERMINATE** — permission-blindness is not absence. A genuinely empty roster still returns a real "NO". A non-match is only reported as "NO" when **every** row exposed a matchable identifier: with even one row's identifiers withheld, the requested NetID could be sitting in it, so the answer is INDETERMINATE. A positive match is always trustworthy, however much of the roster is hidden. The prior docstring claim that a student token "yields a clean Canvas 403" was measured to be false and has been corrected ([#171](https://github.com/vishalsachdev/canvas-mcp/issues/171)).

### Security
- **The anonymizer now runs a recursive identity scrub as the baseline on every sensitive payload**, with the typed per-shape handlers demoted to additive refinements. Previously the `data_type` heuristic could mis-route a dict or fabricate fields, so nested identities slipped through unscrubbed. Key properties, all under test: anonymization **never adds a key that was not in the input**; `name`/`display_name` are rewritten only with a corroborating user signal, so course, group, and module labels survive intact; endpoint matching is segment-aware and query-stripped (mirroring the [#165](https://github.com/vishalsachdev/canvas-mcp/issues/165) gate fix); `time_zone`/`locale` are nulled on person records only. `/submissions/self` is excluded so a student can read their own submission back, anchored on the literal `self` segment with regression tests against the [#164](https://github.com/vishalsachdev/canvas-mcp/issues/164) bypass class ([#166](https://github.com/vishalsachdev/canvas-mcp/issues/166)).
- **Anonymization now covers the Inbox and page authorship, via three tiers instead of an all-or-nothing switch.** `/conversations` was matched by none of the gate's sensitive segments (`users`/`submissions`/`enrollments`/`analytics`), so `list_conversations` and `get_conversation_details` returned the raw payload: real names, `pronouns`, subject lines, and student email addresses inside message previews. Verified live against a real inbox (97 records, 3 distinct addresses). It is now `free_text` tier, which redacts free text and nulls `pronouns` while **keeping** `participants[].name`, because pseudonymising your own inbox makes "who emailed me?" useless and protects nobody: the caller is a participant in every record returned. `/pages` is now `identity` tier, which scrubs `last_edited_by` (previously passed through untouched) while leaving page bodies alone, since instructors legitimately publish contact details on course pages. Everything previously anonymized stays `full`, and the sensitive-segment checks still run FIRST so the #164 ordering bug cannot recur ([#179](https://github.com/vishalsachdev/canvas-mcp/issues/179)).
- **Covered the email-bearing keys the anonymizer missed:** `primary_email`, `unconfirmed_email`, and `contact_info` are now pseudonymised; `pronunciation` is nulled; `communication_channels[].address` is nulled container-scoped (so a calendar event's location is untouched); `full_name` and `unique_id` are *ambiguous* rather than strict, so they scrub on a person record but survive on a conversation participant. Not all of these were reachable by a registered tool, but `get_my_profile` (#171) reads `/users/self/profile`, which is where `primary_email` lives — fixing the key list before that shipped turns a future leak into a non-event ([#179](https://github.com/vishalsachdev/canvas-mcp/issues/179)).
- **Narrow anonymization carve-out for the caller's own identity.** `users/self` and `users/self/profile` are exempt from the anonymizer, because anonymizing them tells callers their *own* name is `Student_<hash>` — FERPA protects a record from others, never from its subject. This is a deliberate loosening of a privacy control, so it is an **exact full-path allowlist**, never a prefix or substring rule: `/users/self/enrollments` (which Canvas expands with `include[]=observed_users`, returning *other* students, and this gate cannot see request parameters), `/users/self/observees`, `/users/self/courses/*`, `/courses/*/enrollments`, `/courses/*/users`, and `/users/<other-id>/profile` all still anonymize, with explicit anti-bypass tests for each ([#171](https://github.com/vishalsachdev/canvas-mcp/issues/171)).
- **Fixed an anonymization bypass for `/courses/`-scoped student-data endpoints.** `_should_anonymize_endpoint()` checked its safe-endpoint list (which includes the substring `/courses`) before the student-data list, so enrollments, submissions, analytics, and discussion-content responses skipped central anonymization for nearly all real traffic. Sensitive checks now run first, discussion `/view`, `/entry_list`, and `/replies` endpoints are matched as student content, and the anonymizer now recurses into the discussion `/view` wrapper (`view`/`participants`/`replies`) and enrollment records' nested `user` dict — two shapes it previously passed through untouched. Added direct unit tests for the endpoint gate, which was previously untested ([#164](https://github.com/vishalsachdev/canvas-mcp/issues/164)).

### Internal
- **`ruff check src/ tests/` now runs in CI and is a required status check on `main`**, with the 13 pre-existing findings cleaned up so the gate starts green. First outside contribution to this repo — thanks @w3lld1 ([#175](https://github.com/vishalsachdev/canvas-mcp/issues/175), [#186](https://github.com/vishalsachdev/canvas-mcp/pull/186)).
- **`claude-review` removed from required status checks.** GitHub withholds repository secrets from `pull_request` workflows on forks, so the job's OAuth-token guard hard-failed on every external contribution — making outside PRs unmergeable without an admin bypass, with a misleading "secret is not set" error. It still runs and reports; it is now advisory ([#188](https://github.com/vishalsachdev/canvas-mcp/issues/188)).

## [1.5.0] — 2026-07-04

### Added
- **`get_syllabus` tool** — returns the complete Canvas Syllabus tab content without truncation (the overview tools only expose a ~1000-character preview, hiding later sections like grading policies and weighting). Supports `output_format` (`text`/`html`/`both`) and an optional `max_chars` cap that is explicitly marked when applied ([#134](https://github.com/vishalsachdev/canvas-mcp/issues/134)).
- **`create_rubric_from_csv` tool** — create a rubric from a CSV string via Canvas's native rubric CSV import endpoint, polling the import job to completion. A simpler alternative to the criteria-JSON `create_rubric` API ([#119](https://github.com/vishalsachdev/canvas-mcp/issues/119)).
- **`update_discussion_topic` tool** — educator-only partial update of an existing discussion topic or announcement (title, message, published/pinned/locked, `delayed_post_at`/`lock_at`, `require_initial_post`) via `PUT /courses/:id/discussion_topics/:topic_id`, mirroring the `update_assignment` pattern ([#154](https://github.com/vishalsachdev/canvas-mcp/issues/154)).

### Changed
- **Migrated to standalone `fastmcp` 2.x** from the frozen FastMCP 1.0 bundled in the MCP SDK (`mcp.server.fastmcp`). No user-facing changes: same tools, same transports, HTTP endpoint unchanged at `/mcp` ([#145](https://github.com/vishalsachdev/canvas-mcp/issues/145)).

### Security
- **Upgraded dependencies to clear known advisories** (`starlette`, `python-multipart`, `pyjwt`, `cryptography`, `pygments`, `idna`, `pydantic-settings`, `pytest`) via a full `uv.lock` refresh; all HTTP-transport-facing packages now ship fixed versions.
- **The dependency-scan CI now gates the build.** `pip-audit` runs against the exact locked dependency set (`uv.lock`, incl. the `hosted` extra) and fails on findings, instead of `continue-on-error` passing regardless. (`CVE-2025-69872` in the transitive `diskcache` is ignored pending an upstream fix.)
- **Hardened the `execute_typescript` container sandbox.** The workspace is now mounted read-only with a writable `tmpfs` for scratch, the container runs with `--cap-drop=ALL`, `--security-opt=no-new-privileges`, and `--pids-limit`, and the Canvas token is passed by env-var name rather than in the container runtime's argv (no longer visible via `ps`/`/proc`).
- **Added upper version bounds** on direct dependencies (`httpx`, `python-dotenv`, `pydantic`, `uvicorn`) so downstream installs can't silently pull an untested new major.

### Fixed
- **`strip_html_tags` no longer concatenates adjacent block elements.** Block-level tags (headings, paragraphs, list items, table rows, `<br>`) now convert to line breaks, so plain-text syllabus/overview output preserves structure instead of merging content across boundaries (e.g. `Grading` and `Final exam...`). Entity decoding now uses the stdlib `html.unescape`, covering smart quotes, dashes, and accents.
- **`summarize-course` prompt rendered raw JSON.** The prompt returned an out-of-spec `system`-role message that MCP clients received as literal JSON text; it now renders as a single user message ([#145](https://github.com/vishalsachdev/canvas-mcp/issues/145)).
- **`CANVAS_API_URL` is normalized to its canonical `/api/v1` form** at startup, so values with a trailing slash, missing `/api/v1` suffix, or bare hostname all work instead of producing 404s on every call ([#148](https://github.com/vishalsachdev/canvas-mcp/issues/148)).
- **`list_courses` honors `CANVAS_ROLE`** and scopes results to active enrollments, so student-profile servers no longer list courses from a teacher's perspective ([#140](https://github.com/vishalsachdev/canvas-mcp/issues/140)).
- **Docker image installs the `[hosted]` extra** (`azure-data-tables`, `azure-communication-email`, `azure-identity`), so the hosted access-approval flow ([#150](https://github.com/vishalsachdev/canvas-mcp/pull/150)) works in containerized deployments; stdio installs are unaffected ([#153](https://github.com/vishalsachdev/canvas-mcp/pull/153)).

## [1.4.0] — 2026-06-17

### Added
- **`check_enrollment` tool** — a data-minimizing roster-membership check (is a given NetID enrolled in a course?). Returns only a yes/no plus minimal enrollment metadata, never the roster, names, or grades. Requires a teacher-scoped token ([#126](https://github.com/vishalsachdev/canvas-mcp/pull/126)).
- **Claude Desktop Extension (`.mcpb`)** — one-click install in Claude Desktop (no terminal, no config-file editing). Built and attached to each GitHub Release automatically; prompts for your Canvas URL + token (stored in the OS keychain).

### Changed
- **Authenticated institutional hosted deployment.** The HTTP/streamable transport now supports Microsoft Entra ID (Azure AD) platform authentication fronting App Service, so an in-tenant institutional deployment can require campus identity per request ([#115](https://github.com/vishalsachdev/canvas-mcp/issues/115), [#125](https://github.com/vishalsachdev/canvas-mcp/pull/125)).

### Security
- **HTTP mode fails closed.** The server refuses to start in HTTP mode without an auth gate configured, unless `MCP_ALLOW_UNAUTHENTICATED=true` is explicitly set for an externally-authenticated front (e.g. Entra) ([#123](https://github.com/vishalsachdev/canvas-mcp/pull/123)).
- **Retired the public hosted server (`mcp.illinihunt.org`).** It had been
  deployed without an authentication gate, which left the sandboxed
  `execute_typescript` tool and an unvalidated `X-Canvas-URL` (SSRF shape)
  publicly reachable. No data was stored server-side and the published package
  itself was unaffected. Self-hosting the HTTP/streamable transport remains
  supported **behind your own authentication**; an authenticated institutional
  deployment is tracked in [#115](https://github.com/vishalsachdev/canvas-mcp/issues/115).

## [1.3.0] — 2026-05-02

### Added
- **`create_rubric`** — Programmatic rubric creation with criteria, ratings, and
  optional assignment association. Uses Canvas's bracket-notation form-data
  encoding (the encoding shape that previously caused the Canvas API 500
  errors). ([#100](https://github.com/vishalsachdev/canvas-mcp/pull/100))
- **`read_course_file`** — Read course file content. Enables remote MCP
  deployments to access uploaded Canvas files without requiring local
  filesystem access. Thanks [@DomBarker99](https://github.com/DomBarker99)!
  ([#90](https://github.com/vishalsachdev/canvas-mcp/pull/90))

### Fixed
- **"Event loop is closed" on user-scoped tools** (`get_my_todo_items`,
  `get_my_upcoming_assignments`, `get_my_peer_reviews_todo`, etc.). The shared
  `httpx.AsyncClient` and `asyncio.Semaphore` are now weakref-tracked against
  their owning event loop and recreated when a new loop starts (e.g., across
  multiple `asyncio.run()` calls in HTTP transport mode).
  ([#99](https://github.com/vishalsachdev/canvas-mcp/pull/99))

### ⚠️ Behavior change — bulk delete safety
- **`bulk_delete_announcements` now refuses batches over 25 IDs by default.**
  Pass `limit=N` to raise the cap, or `dry_run=True` to preview the titles
  that would be deleted without deleting them. **Existing callers passing
  more than 25 IDs in a single call must add `limit=N` explicitly.**
  ([#96](https://github.com/vishalsachdev/canvas-mcp/pull/96))
- Added a "Permanent — Canvas may retain a recycle-bin copy depending on
  admin settings" hint to the docstrings of `delete_page`,
  `delete_announcement`, `bulk_delete_announcements`,
  `delete_announcement_with_confirmation`, and
  `delete_announcements_by_criteria` so the irreversibility note appears in
  the tool description LLMs read, not just in the MCP `destructiveHint`
  annotation that most clients ignore.

### Maintenance
- Drop unused standalone `fastmcp` dependency; the bundled `FastMCP` from the
  official `mcp` SDK was already in use. Pin `mcp>=1.26,<2`. Pruned ~30
  unused transitive deps; net −794 lines from `uv.lock`.
  ([#93](https://github.com/vishalsachdev/canvas-mcp/pull/93))
- Remove dead code paths and bump dependency version floors.
  ([#92](https://github.com/vishalsachdev/canvas-mcp/pull/92))

**Tool count:** 88 → 90.

---

## [1.2.0] — 2026-04-10

- **Role-Based Tool Filtering** — Set `CANVAS_ROLE` to `student`, `educator`,
  or `admin` to see only relevant tools
  ([@Promithius-DR](https://github.com/Promithius-DR),
  [#84](https://github.com/vishalsachdev/canvas-mcp/pull/84))
- **Accessibility Remediation** — New `fix_accessibility_issues` tool for
  automated WCAG fixes; scanner expanded from 4 to 20 checks
- **Security Hardening** — Path traversal and symlink protections across all
  file I/O operations
- **Windows Support** — Fixed `execute_typescript` compatibility on Windows
  ([#85](https://github.com/vishalsachdev/canvas-mcp/pull/85))
- **CI Improvements** — Consolidated workflows (11 → 8 checks), fork-aware
  pipelines

## [1.1.0]

- Hosted Server (`mcp.illinihunt.org`)
- Learning Designer tools + 3 skills
- Agent Skills on skills.sh
- File Management ([@Metzpapa](https://github.com/Metzpapa),
  [#75](https://github.com/vishalsachdev/canvas-mcp/pull/75))
- Token Optimization
- Generic Distribution

## [1.0.8]

- Security Hardening (PII sanitization, audit logging, sandbox-by-default)
- Ruff linting
- 235+ tests

## [1.0.7]

- Assignment Update Tool (`update_assignment`), complete CRUD, 9 tests

## [1.0.6]

- Module Management (7 tools), Page Settings (2 tools), 235+ tests

## [1.0.5]

- Claude Code Skills, GitHub Pages site

## [1.0.4]

- Code Execution API for token-efficient bulk operations, MCP 2.14 compliance
