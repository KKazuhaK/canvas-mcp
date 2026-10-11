# canvas-mcp self-hosted mode: developer handoff

Snapshot date: 2026-10-11. Audience: a developer who has never seen this project and must continue it alone. The document is written in English so it can be committed. Location: `deploy/selfhost/DEVELOPMENT.md`. Its companion, the v1 consolidation design, is `deploy/selfhost/V1-DESIGN.md`; this document calls it "V1-DESIGN" and cites its sections as "V1-DESIGN 4.6".

Conventions in this document:
- Paths are relative to the repository root unless they say otherwise.
- "P7 branch" means code that exists only on `feature/p7-login-providers`.
- "v1" means the consolidation the owner decided on 2026-10-11 (decisions D1-D14, section 5). It is designed (V1-DESIGN) but not started. Sections 3 and 4 describe the code as it is today and mark what v1 removes or renames.
- "(unverified)" means it was read or inferred but not run or confirmed.
- Line numbers are approximate; function and constant names are the stable anchors. Line numbers for `account_web.py`, `account_api.py`, `token_admin.py`, `deploy/selfhost/README.md` and `tests/selfhost/login/*` refer to the P7 branch (the checkout on `uci-student` has fewer lines: `account_web.py` 4129 vs about 4890, README "Multiple schools" at ~730 vs ~845, "Proven with claude.ai" row at ~436 vs ~438).

---

## 1. Purpose and status at a glance

This repository (`KKazuhaK/canvas-mcp`) is an **independent fork** of `vishalsachdev/canvas-mcp`. It keeps the name. It is not endorsed by upstream (D12). Its addition is a self-hosted, multi-user deployment mode: friends at several schools sign in through the owner's own Microsoft Entra tenant (as B2B guests assigned `Canvas.User`), each stores their own Canvas token (encrypted), and Claude clients connect to the owner's server. Upstream has not reviewed, endorsed or accepted this mode. Only small core fixes go upstream. Nothing is deployed yet (D1).

| Area | State | Where |
|---|---|---|
| P0 token AAD v2, principal keys | Done, merged | `src/canvas_mcp/core/selfhost/token_store.py` |
| P1 Canvas token health | Done, merged | `core/token_health.py`, `core/selfhost/token_health.py` |
| P2 per-user write-tool opt-in | Done, merged | `core/selfhost/tool_prefs.py`, `tool_gate.py` |
| P3 data layer (SQLAlchemy Core + Alembic; SQLite default, PostgreSQL optional) | Done, merged; v1 replaces the schema with one baseline (D4) | `core/selfhost/db/` |
| P4 account model, admission policy, audit | Done, merged (Entra only) | `accounts.py`, `identity.py`, migration `0002_accounts` |
| Multi-school (featured list + Instructure directory search) | Done, merged, env-configured; v1 moves both to the admin panel (D6, D7) | `schools.py`, `settings.py`, `app.selfhost_school_policy` |
| P5 React `/account` UI + `/account/api` | Done, merged, opt-in today (`ACCOUNT_UI=react`); v1 makes it the only UI and moves the API to `/api/v1` (D3, D5) | `web/`, `account_api.py`, `account_spa.py` |
| P6 own MCP authorization server | Done, merged, opt-in today (`SELFHOST_AUTH_MODE=local`; default `entra_proxy`); v1 makes it the only path and deletes `entra_proxy` (D2) | `core/selfhost/authz/`, migration `0003_oauth_authz` |
| P7+P8 Google, GitHub, generic OIDC sign-in, linking, per-provider admission, "usable owner" rule | UNMERGED branch at `53b86dd` (clean, unpushed, 32 commits ahead of `uci-student`). The last fix round passed the full matrix but has NOT been independently reviewed. Merge only after one more independent review (6.1) | `.worktrees/p7-providers`, `core/selfhost/login/` |
| v1 consolidation (D1-D10) | Designed, not started | V1-DESIGN; backlog 6.1a |
| Custody notice and acknowledgement (D10) | Notice partial (legacy pages only); acknowledgement not started | 6.4 |
| README independent-fork framing (D12), neutral examples (D11) | Not started | 6.5 |
| Maintainer's #484 items (pilot profile, tested-clients table) | Not started | 6.6 |
| Upstream PRs #490, #491 | Open, review required, no comments; listed by upstream triage for the maintainer's decision | 6.7 |
| Upstream issue #489 (caller boundaries in HTTP caches) | Opened by the maintainer 2026-10-11; #491 covers only the course-policy half | 6.7 |
| Upstream sync | `uci-student` is 7 commits behind the local `origin/main` ref (not re-fetched for this snapshot) | 6.1 step 6 |
| Design documents | This handoff and V1-DESIGN exist outside the repository; to be committed (homes above) | |
| Release | Latest tag `v1.14.0-uci.1-beta.2`; next tag after v1 (6.10) | `.github/workflows/selfhost-image.yml` |
| Live verification (real clients, real IdPs, proxies) | None done; gates the first v1 tag | 6.12 |
| CI | Green on `uci-student` at `71602e6` | `.github/workflows/canvas-mcp-testing.yml`, `selfhost-image.yml` |

---

## 2. Getting started

### 2.1 Repository, branches, remotes, worktrees

- Remotes in the owner's clone: `fork` = `KKazuhaK/canvas-mcp` (push here), `origin` = `vishalsachdev/canvas-mcp` (upstream; never push fork work here). A fresh clone of the fork names it `origin`; add upstream as a second remote and adapt the commands below.
- Main fork branch: `uci-student`. HEAD at snapshot: `71602e6` ("Merge upstream main (2026-10-10, triage notes) into uci-student"). The fork's GitHub default branch is `main`, which is not the working branch (dependabot runs there).
- Worktrees (`git worktree list`):

| Worktree | Branch | Purpose |
|---|---|---|
| repo root | `uci-student` | main line |
| `.worktrees/p7-providers` | `feature/p7-login-providers` | P7+P8; HEAD `53b86dd`, clean, not pushed, 32 commits ahead of `uci-student` |
| `.worktrees/up-repr` | `fix/request-credentials-repr` | upstream PR #490 (HEAD `ee843f5`) |
| `.worktrees/up-policy` | `test/course-policy-caller-boundary` | upstream PR #491 (HEAD `6b64885`) |
| `.worktrees/v1` (to create) | `feature/v1-consolidation` from `uci-student` after B0 | v1 (V1-DESIGN 6.0) |

- Tags: `v1.13.0-uci.1`, `v1.14.0-uci.1-beta.1`, `v1.14.0-uci.1-beta.2`.
- Install the commit hook once per clone: `bash scripts/install-hooks.sh` (sets `core.hooksPath .githooks`; `commit-msg` refuses closing keywords).

### 2.2 Two Python runtimes (both are required)

Self-hosted tests must pass on both, because the authorization server depends on FastMCP / MCP SDK internals that differ between versions (for example mcp 2.1.1's `RefreshToken` has no `resource`). After v1 the authorization server is the only MCP auth path, so a failure on either runtime is a release blocker.

Placeholders: `<dev-venv>` is a virtualenv with the project's dev dependencies resolved to the newest allowed versions (`uv sync --all-extras` into any directory); `<locked-venv>` is a second virtualenv built exactly from `uv.lock` (command below); `<cpg>` is the directory of the throwaway PostgreSQL recipe in 2.4. On Windows the interpreter is `Scripts/python.exe`, elsewhere `bin/python`.

| Runtime | Path (placeholder) | Versions | Role |
|---|---|---|---|
| dev venv | `<dev-venv>/Scripts/python.exe` (has `uv.exe`, `ruff`, `mypy`, `pytest`) | fastmcp 4.0.10, mcp 2.2.0 | newest resolvable deps (matches CI `test` matrix) |
| lock-pinned venv | `<locked-venv>/Scripts/python.exe` (no uv) | fastmcp 4.0.3, mcp 2.1.1, joserfc 1.7.2 | exactly `uv.lock`; what CI `test-locked` and the image use; the authority |

Refresh the locked venv after a lock change:
```bash
UV_PROJECT_ENVIRONMENT=<locked-venv> \
  <dev-venv>/Scripts/uv.exe sync --locked --all-extras
```
On a new machine: create two venvs, one with `uv sync --locked --all-extras` and one with `pip install -e ".[selfhost,postgres]"` plus test deps at latest versions. Always check `python -c "import canvas_mcp; print(canvas_mcp.__file__)"` points into the intended worktree.

Environment for every run (Git for Windows bash or any POSIX shell):
```bash
cd <worktree>
export PYTHONPATH=$PWD/src PYTHONUTF8=1 FASTMCP_MCP_CAMELCASE_COMPAT=false
PY=<locked-venv>/Scripts/python.exe   # or the dev venv
```
`pyproject.toml` sets `pythonpath=["src"]` and `asyncio_mode=auto`; `tests/conftest.py` sets `PYTHON_DOTENV_DISABLED=1`.

### 2.3 Commands

```bash
$PY -m pytest tests/selfhost -q -p no:cacheprovider        # self-hosted (~4660 tests on the P7 branch)
$PY -m pytest tests -q -p no:cacheprovider                 # whole suite (~8700 on the P7 branch)
$PY -m pytest tests/selfhost tests/test_multiuser_e2e.py tests/test_fastmcp_compat.py -q   # what CI test-postgres runs
$PY -m ruff check src/ tests/
$PY -m mypy src/                                           # needs .[selfhost,postgres] installed
<dev-venv>/Scripts/uv.exe lock --check   # from the checkout; fails if uv.lock is stale
```
Web (Node 24.19; CI pins 24.19.0):
```bash
cd web && npm ci --ignore-scripts
npm run lint; npm run typecheck; npm test; npm run build; npm run check:dist
npm run dev:mock    # http://127.0.0.1:5175/account/ with an in-browser mock API (?mock=owner, fresh, local-owner, ...)
```
Root-level `npm ci && npm run build && npm test` is upstream's TypeScript code API (CI job `test-code-api`).

### 2.4 Local PostgreSQL (throwaway, no system install)

The owner uses PostgreSQL 16.2 binaries from the `pgserver` wheel in a CPython 3.12 venv. Keep the path short; long paths break it.
```bash
BIN=<cpg>/venv/Lib/site-packages/pgserver/pginstall/bin
CPG=<cpg>
$BIN/initdb.exe -D $CPG/data -U canvas -A trust -E UTF8                      # first time only
$BIN/pg_ctl.exe -D $CPG/data -o "-p 54329 -c listen_addresses=127.0.0.1" -l $CPG/pg.log -w start
$BIN/createdb.exe -h 127.0.0.1 -p 54329 -U canvas canvas_test               # first time only
export CANVAS_MCP_TEST_BACKEND=postgres
export CANVAS_MCP_TEST_DATABASE_URL=postgresql+psycopg://canvas@127.0.0.1:54329/canvas_test
$PY -m pytest tests/selfhost -q -p no:cacheprovider
$BIN/pg_ctl.exe -D $CPG/data -m fast stop
```
Elsewhere, any PostgreSQL 16+ reachable at that URL works (Docker `postgres:16` is fine).
- If the backend is requested but unreachable, `tests/conftest.py` aborts the run (it does not skip), so green means PostgreSQL was exercised.
- Only `CANVAS_MCP_TEST_DATABASE_URL` set (no backend var): the SQLite run also executes `@pytest.mark.postgres` tests. `@pytest.mark.sqlite_only` tests skip on PostgreSQL.
- Tests create and drop scratch schemas (`tests/dbbackend.py`).
- CI uses `postgres:18.6-alpine` pinned by digest; CI is the authority.

**The full matrix for any self-hosted change: {dev venv, locked venv} x {SQLite, PostgreSQL}**, plus ruff, mypy, `uv lock --check`, and the web checks if `web/` or the API changed. v1 adds its own checks (V1-DESIGN 6.1).

### 2.5 CI (`.github/workflows/canvas-mcp-testing.yml`)

Runs on pushes to `main`, `development`, `uci-student`, `feature/**`, `fix/**`, `ci/**`, PRs into `main`/`uci-student`, and manual dispatch.

| Job | Checks |
|---|---|
| `lint` | ruff; installs `.[selfhost,postgres]` + pinned mypy; `mypy src/` |
| `test-code-api` | upstream TypeScript code API |
| `web` | `web/`: lint (oxlint), typecheck, vitest, build, `check:dist` |
| `verify-confirmation` | Lean 4.19.0 and TLA+ proofs (`verify/run.py`) |
| `test` | `pytest tests/` on Python 3.11-3.14 with latest deps, `fetch-depth: 0` (closing-keyword history replay) |
| `test-windows` | same on Windows, 3.14, `PYTHONUTF8=1` |
| `test-locked` | `uv sync --locked`, `uv run --locked pytest tests/` on 3.14 |
| `test-postgres` | PostgreSQL service container; `tests/selfhost tests/test_multiuser_e2e.py tests/test_fastmcp_compat.py` |
| `test-enhancements` | aggregator; requires all above |

Other workflows: `closing-keyword-guard.yml`; `selfhost-image.yml` (section 8); upstream's `scorecard.yml`, `deploy-*.yml`, `publish-mcp.yml`, `create-release.yml`, `claude-code-review.yml`, `claude.yml` (their jobs are guarded by `github.repository == 'vishalsachdev/canvas-mcp'`, so they do nothing in the fork); `security-testing.yml` and `weekly-maintenance.yml` have no such guard but GitHub shows them as `disabled_fork` in the fork, as `scorecard.yml`. On a fork PR into upstream, upstream's `claude-code-review.yml` runs without the secret and `claude-review` goes red; upstream's triage (2026-10-11) records this as an upstream workflow issue.

### 2.6 Is this failure environmental?

| Symptom | Cause | Action |
|---|---|---|
| Some `test_closing_keyword_guard.py` hook tests fail locally | they need a real `.git`, POSIX exec bits and a working `dirname` on PATH (upstream's CLAUDE.md records 3 `test_hook_rejects_commit_without_usable_python` cases failing in a primary checkout that has a wrapper hook). All 56 tests passed in both the `uci-student` checkout and the P7 worktree on the owner's machine at snapshot, so a failure there is new | compare with a run on the base commit; CI is the authority |
| `test_setup_env_script.py` skipped | no bash found | run from Git for Windows bash |
| run aborts at start with a PostgreSQL error | backend requested but server not running | start the server or unset the backend variable |
| authz tests pass on one venv, fail on the other | SDK internals drift | real bug: fix inside `authz/fastmcp_compat.py` only |
| `uv lock --check` fails | `pyproject.toml` changed without `uv lock` | run `uv lock` and commit `uv.lock` |
| `claude-review` red on a fork PR to upstream | fork PRs cannot read upstream's secret (upstream workflow issue) | nothing to fix |
| Docker smoke test | only runs in CI (`selfhost-image.yml`) | push to `uci-student` or a tag and watch the run |
| encoding failures on Windows | missing `PYTHONUTF8=1`, or a text read/write without `encoding=` | set the variable; `test_text_encoding_guard.py` requires explicit encodings |

---

## 3. Architecture map (self-hosted mode)

This section describes the code at `uci-student` plus the P7 branch. Section 3.0 lists what v1 removes or renames; the subsections mark it with "(v1: ...)".

### 3.0 What disappears or changes in v1

| Today | v1 | Decision / V1-DESIGN |
|---|---|---|
| `SELFHOST_AUTH_MODE` (`entra_proxy` default, `local`), `oauth.py` (FastMCP `OAuthProxy`/`AzureProvider`, Fernet file store), `OAUTH_JWT_SIGNING_KEY`, `FASTMCP_HOME`, `GRANT_STATUS_CACHE_S`, `py-key-value-aio` | deleted; the built-in authorization server is the only MCP auth path; old settings refuse startup naming the replacement (`FASTMCP_HOME` is ignored, not refused) | D2; 2.2, 2.3 |
| Entra app registration with "Expose an API", `Canvas.Access` scope, proxy redirect URIs | plain OIDC web client, one redirect URI `/auth/callback/entra` | D2, D3; 2.5 |
| `MCP_AUTH_MODE=entra-oauth`, `ENTRA_API_SCOPE` | `MCP_AUTH_MODE=selfhost`, `MCP_SCOPE` (default `Canvas.Access`); old names refused with a message naming the replacement | D9; 2.3, step 1 |
| `/account/login`, `/account/login/<provider>`, `/account/callback`, `/account/callback/<provider>`; proxy `/auth/callback` and `/consent` | `/auth/login`, `/auth/login/{provider}`, `/auth/callback/{provider}` (`oidc/{slug}` for generic OIDC); bare `/auth/callback` and `/consent` are 404 | D3; 3.2-3.7 |
| `/account/api/*` | `/api/v1/*`; `/account` is only the React app | D3; 3.5 |
| Legacy server-rendered pages (`account_web.py` HTML, `_bi(zh, en)` pages, form POSTs), `ACCOUNT_UI` | deleted; session, CSRF, Origin and consent logic move to `account_core.py`; `ACCOUNT_UI` refused; a missing bundle refuses startup | D5; step 2 |
| Sealed `__Host-cmcp_login` Entra ceremony | Entra on P7's flow engine, `__Host-cmcp_flow` | D2; 2.6 |
| `CANVAS_FEATURED_SCHOOLS`, `CANVAS_SCHOOL_SEARCH`, `CANVAS_API_URL` (self-host mode), `OIDC_<SLUG>_DISPLAY_NAME` | refused at startup; featured schools, directory search (on by default) and sign-in names live in the database, edited in Admin > Settings or `token_admin` | D6, D7, D8; 5 |
| Migrations `0001_baseline_v4`, `0002_accounts`, `0003_oauth_authz`, `baseline_v4.py`, `accounts_v5.py`, legacy adoption and data migrations; tables `meta`, `canvas_tokens`, `user_tool_prefs`, `credential_generations`, `principal_status_events`; principal keys `acct:<uuid>` in rows | one baseline `0001_v1_baseline`, 19 tables, UUIDv7 account ids (`acct:` only in AAD and JWT claims) | D4; 4 |
| `PrincipalAccessCache`, `GrantStatusCache`, `IdentityCache`, `EpochSource`, tool-prefs TTL | one statement per MCP request; revocation and disable act at the next request | D4; 4.5.1 |
| No custody acknowledgement | required checkbox, recorded on the credential row with time and notice version, checked on every MCP request | D10; 4.3.8, step 6b |

### 3.1 Layout

| Path | Contents |
|---|---|
| `src/canvas_mcp/server.py` | CLI entry; `_main_selfhost()` loads settings, prints `--config` via `_selfhost_summary()`, validates, builds the ASGI app |
| `src/canvas_mcp/core/selfhost/` | the self-hosted mode (~28.7k lines on the P7 branch) |
| `core/selfhost/db/` | data layer (v1: rebuilt, V1-DESIGN 4) |
| `core/selfhost/authz/` | own OAuth authorization server (today the `local` mode; v1: the only mode) |
| `core/selfhost/login/` | P7 branch: sign-in providers |
| `core/` outside `selfhost/` | upstream code that selfhost hooks into: `credentials.py` (request ContextVars), `token_health.py`, `cache.py`, `audit.py`, `config.py`, `client.py`, `course_files.py`, `tool_policy.py`, `untrusted_content.py` |
| `web/` | React UI (Vite 8, React 19, TypeScript 7, MUI 9.4 with Emotion (D14), React Router 8, TanStack Query 5, i18next en/zh); `web/README.md` covers mock mode and security rules; `web/dist` is built output, gitignored (`dist/`) and never committed: CI (`web` job) and `Dockerfile.selfhost` build it, and `npm run check:dist` validates a local build |
| `deploy/selfhost/` | `README.md` (operator guide, the reference for deployment), `env.example`, `setup-env.sh`, `smoke-test.sh`, `docker-compose.yml`, `docker-compose.postgres.yml`, `Caddyfile.example`, `nginx.conf.example` |
| `Dockerfile.selfhost` | Node builds `web/`, uv installs from `uv.lock`, slim runtime (v1: no `/data/fastmcp`, no `ENV FASTMCP_HOME`). Root `Dockerfile` is upstream's; leave it |
| `tests/selfhost/**` | self-hosted tests (`authz/`, `login/` on P7, `fixtures/`); helpers in `tests/selfhost/conftest.py` (`make_account`, `make_principal`, `acct_key`), `tests/selfhost/authz/stack.py`, `tests/selfhost/login/stack_providers.py` |
| `tests/` top level | guards: `test_english_only.py`, `test_closing_keyword_guard.py`, `test_text_encoding_guard.py`, `test_selfhost_docs.py`, `test_selfhost_dockerfile.py`, `test_selfhost_compose*.py`, `test_multiuser_e2e.py`, `test_fastmcp_compat.py` |
| `tests/security/` | `test_selfhost_workflow.py` (image workflow policy), `test_course_cache_isolation.py` (byte-identical to upstream) |
| `proposals/selfhost-pilot/` | `stage-a-main.md`, `stage-a-appendix.md` (written for #484; history, see 6.8) |
| `CHANGELOG.md` | `[Unreleased]` has one long entry per phase (v1: one "v1 consolidation (breaking)" entry) |

### 3.2 Modules in `core/selfhost/`

- `settings.py`: the environment contract. `load_selfhost_settings()` collects all problems and raises `SelfhostConfigError`. Standard library only. Holds `_parse_featured_schools`, `_parse_disabled_tools`, auth-mode/state-backend/account-UI constants, TTL defaults. (v1: loses the auth-mode, signing-key, `FASTMCP_HOME`, school and account-UI parsing; gains `REMOVED_SETTINGS`, V1-DESIGN 2.3.)
- `app.py`: `validate_selfhost_startup` (`_school_problems`, `_data_layer_problem`, `_owner_path_problem`), `prepare_selfhost()` (store, identity, health, caches, authz), `install_selfhost()` (middleware, `/healthz`), `build_selfhost_asgi_app()`, `selfhost_school_policy()`, `apply_disabled_tools`. (v1: `runtime.authz` required; `_school_problems` refusal becomes a warning; startup provider reconcile and first settings snapshot.)
- `edge_guard.py`: outermost ASGI shim: scheme, host/Origin, abuse limits, periodic prune/cull. (v1: maintenance moves to `maintenance.py`; HEAD on `/auth/*` refused; Entra gets a per-provider bucket.)
- `request_context.py`: `SelfhostRequestContextMiddleware`, the MCP-path gate (3.3).
- `identity.py`: `IdentityService`, claims to account under the admission policy. (v1: the request-time Entra path and `IdentityCache` go; sign-in resolution stays.)
- `accounts.py`: pure admission logic: `ACCESS_RULES`, `OWNER_RULES`, `ACCESS_POLICY`, `ACCESS_FALLBACK`, verdicts, `DENIAL_MESSAGES`, `PROVIDER_ENTRA/GOOGLE/GITHUB`.
- `principal_access.py`: per-principal "may use the server" with a short cache. (v1: a pure function over the request-context row.)
- `token_store.py`: `TokenStore` facade (accounts, encrypted Canvas tokens, status history, owner rules, audit, prefs, login events). `AUDIT_ACTIONS` closed set (~line 205), `LOGIN_PROVIDERS_META_KEY` (P7; v1: the `login_providers` table).
- `token_admin.py`: operator CLI, `python -m canvas_mcp.core.selfhost.token_admin` (`check`, `list`, `accounts`, `approve`, `promote-owner`, `disable`, `enable`, `access`, `history`, `remove`/`revoke`, `rotate`, `list-grants`, `revoke-grant`, `rotate-jwt-key`, `db current|upgrade|import-sqlite`; P7: `identities`, `unlink-identity`, `login-providers [--check]`). (v1 adds `schools`, `providers`, `settings`, `db check`, `accounts delete`.)
- `token_health.py`, `tool_gate.py` (`SelfhostCredentialGate`), `tool_prefs.py`.
- `schools.py`: `parse_hostname`, `is_blocked_hostname`, `check_public_host` (SSRF-style checks), `SchoolDirectory` (Instructure directory), `FeaturedSchool`, `School`, `SchoolPolicy` (`build`, `pinned`, `resolve_stored`, `picker_enabled`, `sole_school`), `MAX_FEATURED = 50`. (v1: `SchoolPolicy` built from the settings snapshot, no default school.)
- `limits.py`, `login_state.py`: rate limits and one-time state; memory backend only.
- `oauth.py`: Entra proxy provider (default `entra_proxy`) and OAuth state cull. (v1: deleted; `build_auth_provider` moves to `authz/runtime.py`.)
- `account_web.py` (4129 lines on `uci-student`, ~4890 on the P7 branch): legacy server-rendered `/account`, plus shared account logic: routes, sealed cookie sessions, CSRF/Origin (`_guard_post`), `_bi(zh, en)` strings, `_signed_in_recently`, `_FRESH_SIGN_IN_SECONDS = 600`, `_MAX_BODY_BYTES = 8192`. (v1: HTML deleted; shared logic moves to `account_core.py`, D5.)
- `account_api.py`: JSON API at `/account/api` (v1: `/api/v1`); `route_table()` of `(path, {METHOD: endpoint})` with `access=public|session|active|owner` (default `active`), `mutating`, `csrf`, `body`, `local_authz` (v1: removed) and (P7) `linking`. Unknown paths give JSON 404. `providers()` ~line 730-754.
- `account_ops.py`: outcome types shared by HTML and JSON surfaces (v1: used by the API only).
- `account_spa.py`: serves `ACCOUNT_WEB_DIST` under `/account/` with CSP and SPA fallback (v1: an unusable bundle refuses startup).
- `db/`: `schema.py` (metadata, `TABLE_NAMES`, `VERSION_TABLE = "canvas_mcp_alembic_version"`), `engine.py`, `url.py`, `ports.py`, `repos.py`, `authz_repos.py`, `migrate.py` (`ensure_ready`: uninitialized/legacy/behind/current/newer-refused/unreadable-refused; SQLite auto-backup; PostgreSQL advisory lock), `transfer.py` (SQLite to PostgreSQL, `COPIED_TABLES`), frozen DDL `baseline_v4.py`, `accounts_v5.py`, `migrations/versions/0001_baseline_v4.py`, `0002_accounts.py`, `0003_oauth_authz.py`. (v1: replaced per V1-DESIGN 4.12-4.13; new `types.py`, `vocab.py`, `sealed.py`.)
- `authz/`: `server.py` (FastMCP `OAuthProvider` subclass: `/authorize`, `/token`, `/revoke`; `/register` from FastMCP), `clients.py` (DCR + CIMD, SSRF-pinned fetcher), `consent.py`, `grants.py` (minting, replay, `GRANT_STATUS_CACHE_S`), `tokens.py`, `transactions.py`, `store.py`, `models.py`, `urls.py`, `runtime.py`, `fastmcp_compat.py` (the ONLY module allowed to import FastMCP/MCP internals).
- `login/` (P7): `config.py` (`SELFHOST_LOGIN_PROVIDERS`, `GOOGLE_*`, `GITHUB_*`, `OIDC_<SLUG>_*`, `MAX_DISPLAY_NAME_CHARS = 40`; standard library only), `protocol.py` (`LoginProvider`, `ProviderDisplay(name, icon)`, icons `microsoft|google|github|key`), `entra.py`, `google.py`, `github.py`, `oidc.py`, `idtoken.py`, `jwks.py`, `metadata.py`, `http.py` (SafeHttp), `registry.py` (`build_login_runtime`, `LoginRuntime.entries()`), `flows.py`, `ceremony.py` (state 10 min, server side), `linking.py` ("usable owner" rule). (v1: new `login/routes.py`; paths from the new `selfhost/routes.py`.)
- `web/src`: `api/` (`contract.ts`, `endpoints.ts`, `errors.ts`), `query/`, `stores/`, `i18n/`, `locales/{en,zh}/{common,auth,account,admin,errors}.json`, `router/`, `layouts/`, `views/` (`views/admin/`: Accounts, Audit, Enrollments; v1 adds Settings), `components/`, `dev/mockServer.ts` (dev only, never statically imported).

### 3.3 Request flows

**MCP call** (today, both auth modes):
1. `edge_guard.py`: scheme, host/Origin, rate limits.
2. FastMCP auth. `entra_proxy`: the Entra proxy validates the token (tenant `tid`, `azp`, roles). `local`: `authz` validates its own JWT and checks grant status through a cache (up to `GRANT_STATUS_CACHE_S`, 30 s).
3. `SelfhostRequestContextMiddleware`: claims to principal `acct:<uuid>` (`IdentityService` or `LocalClaimsResolver`); account status via `PrincipalAccessCache` (disabled/pending/missing = 403, DB down = 503); loads the caller's encrypted Canvas token and maps the stored host through `SchoolPolicy.resolve_stored` (no longer allowed = "not enrolled"; never falls back to the default school); publishes `RequestCredentials`, principal, health, prefs, credential generation via ContextVars in `core/credentials.py`.
4. `tool_gate.py` refuses calls with no identity/token and write tools the user has not opted into. `SELFHOST_DISABLED_TOOLS` removes tools at startup.
5. The tool calls `make_canvas_request()` with the caller's token. Course cache and health are keyed by principal and credential generation.

v1: step 2 is always the built-in server; steps 2-3 become one statement read in `load_access_token` and published in a ContextVar (V1-DESIGN 4.5.1); a host that is no longer offered gets the new `school_not_offered_message()`.

**`/account`** (today):
- Legacy (default): `/account/login` to Entra, `/account/callback` back, sealed `__Host-` HttpOnly cookie session. Mutations check CSRF and Origin. Owner pages and enabling a write tool need a sign-in within 10 minutes (`reauth_required`).
- React (`ACCOUNT_UI=react`): `account_spa.py` serves the bundle; the app calls `/account/api/*` with cookie + `X-CSRF-Token`. Sign-in is a full-page navigation to `/account/login`. `GET /account/api/me` returns `features` flags. If `ACCOUNT_WEB_DIST` is unusable it falls back to legacy with a warning.
- Local-mode consent at `/account/consent` (and connected apps); in `entra_proxy` these answer `not_found`.
- P7: `/account/login/<provider>` starts, `/account/callback/google`, `/account/callback/github`, `/account/callback/oidc/<slug>`; Entra keeps `/account/login` and `/account/callback` when it is the only provider, and uses `/account/login/entra` (`ENTRA_LOGIN_PATH`) for its start when several are listed (the callback stays `/account/callback`). Identities API at `/account/api/me/identities*`.

v1 (D3, D5): only the React app under `/account/*`; the API at `/api/v1/*`; every ceremony under `/auth/*` with a per-provider callback, Entra included (`/auth/callback/entra`); the complete route table is V1-DESIGN 3.2 and the old-to-new map is V1-DESIGN 3.7.

**Owner-action pipeline** (reuse it for every new admin feature; unchanged in v1 apart from paths): method, session, pending check, owner flag re-derived from the DB per request, fresh sign-in within 10 min (even for GET), `Origin == PUBLIC_BASE_URL` and `Sec-Fetch-Site` same-origin, `X-CSRF-Token`, `application/json`, 8 KiB body cap, then the handler; the store call re-checks the owner inside its write transaction (`_require_owner_actor`) and appends the audit row in the same transaction. Legacy forms use `_guard_post(request, owner_only=True)` (v1: gone with the forms).

### 3.4 Data model (today; v1 replaces it, V1-DESIGN 4)

One database: SQLite at `<SELFHOST_DATA_DIR>/canvas-mcp/tokens.sqlite3`, or PostgreSQL via `DATABASE_URL`. Single instance (one process).

Tables (the 15 in `db/schema.TABLE_NAMES`, plus `canvas_mcp_alembic_version`):
- `meta(key, value)`: schema markers (`schema_version`), `mcp_jwt_epoch`, P7 `login_providers`. Not copied as a table by `db import-sqlite` (it is absent from `COPIED_TABLES`), but the JWT epoch is carried over automatically (read in `_private_migrated_copy`, written by `populate` via `jwt_epoch.set`); `login_providers` is not carried. `COPIED_TABLES` has 12 tables; `oauth_codes` and `login_states` are deliberately not copied (`EPHEMERAL_TABLES`).
- `accounts(id, status, role, role_source, role_seen_at, admitted_via, display_name, contact_email, ui_locale, created_at, approved_at/by, disabled_reason/at/by, last_login_at, session_epoch, updated_at)`; principal key `acct:<id>`.
- `external_identities(id, account_id, provider_id, issuer, subject, username, email, email_verified, linked_at, last_login_at)`.
- `canvas_tokens(principal_key, key_id, nonce, ciphertext, canvas_user_id/name, created/updated/last_used, canvas_host, status, invalid_reason, invalid_since, last_verified_at, expires_hint_at)`: AES-256-GCM with keyring `CANVAS_TOKEN_KEYS`; the AAD binds principal and key id and, for a row with a host, the host (v2: principal, host, key id); a row without a host (default school, account principal only) uses AAD v3 (principal, key id) (`token_store._aad_for_principal`).
- `user_tool_prefs`, `principal_status_events`, `credential_generations`.
- `auth_events` (sign-in history, pruned at 90 days), `audit_log(id, at, actor, action, target, reason, detail)`.
- Authz: `oauth_clients`, `cimd_clients`, `oauth_grants`, `oauth_codes`, `oauth_refresh_tokens`, `login_states` (also holds sign-in ceremonies).

v1 (D4): 19 tables (16 live, 3 reserved and empty), FKs on every ownership edge, one credential table `canvas_credentials` with AAD v1, a school registry `canvas_schools` with a nullable `featured_rank`, typed `server_state` and `settings`, `login_providers` with owner-edited display names; full DDL in V1-DESIGN 4.3, hot paths 4.5, locking 4.6.

Migration rules today: frozen DDL in the revision file; never import `db.schema` from a revision; never edit `baseline_v4.py`, `accounts_v5.py` or an existing revision; bump `COMPAT_SCHEMA_VERSION` only when an older server would misread the data; update `tests/selfhost/ddl_postgresql_head.sql` and keep `compare_metadata` clean. P7 adds no migration.

v1 rules (V1-DESIGN 4.12): one hand-written baseline `0001_v1_baseline` that does not import `db/schema.py`; a pre-v1 database is refused ("nothing is deployed, so delete it"); later revisions follow expand/contract guarded by `server_state.compat_floor` (replaces `meta.schema_version` and `COMPAT_SCHEMA_VERSION`); no downgrades, no re-encryption inside a revision. There is no `0004` revision: the former `0004_server_settings` plan is superseded (6.1a).

### 3.5 Settings

All env parsing: `settings.py` (+ `login/config.py`). Documented in `deploy/selfhost/env.example`; `tests/test_selfhost_docs.py` requires every setting to be documented. "(v1: removed)" means the setting refuses startup with a message naming the replacement (V1-DESIGN 2.3).
- Mode/URL: `MCP_AUTH_MODE=entra-oauth` (v1: renamed `MCP_AUTH_MODE=selfhost`, D9), `SELFHOST_AUTH_MODE` (`entra_proxy` default | `local`; v1: removed), `PUBLIC_BASE_URL`.
- Entra: `ENTRA_TENANT_ID`, `ENTRA_CLIENT_ID`, `ENTRA_CLIENT_SECRET`, `ENTRA_REQUIRED_ROLE` (`Canvas.User`), `ENTRA_OWNER_ROLE` (`Canvas.Owner`), `ENTRA_API_SCOPE` (v1: renamed `MCP_SCOPE`, default `Canvas.Access`, D9).
- Also in `settings.py`: `OAUTH_ALLOWED_REDIRECT_URIS` (redirect allow-list, defaults in `DEFAULT_REDIRECT_URIS`), `ACCOUNT_SESSION_TTL_SECONDS` (default 900, allowed 60-3600).
- Secrets: `CANVAS_TOKEN_KEYS`, `OAUTH_JWT_SIGNING_KEY` (v1: removed; JWT keys derive from `CANVAS_TOKEN_KEYS`), `ACCOUNT_SESSION_SECRET`.
- Storage: `SELFHOST_DATA_DIR`, `DATABASE_URL`, `DATABASE_AUTO_MIGRATE`, `SELFHOST_STATE_BACKEND` (`memory` only), `FASTMCP_HOME` (REQUIRED today, absolute path; `env.example` sets `/data/fastmcp`; v1: no longer used, ignored, removed from image and docs).
- UI: `ACCOUNT_UI` (v1: removed, D5), `ACCOUNT_WEB_DIST`.
- Admission: `ACCESS_POLICY`, `ACCESS_RULES`, `ACCESS_FALLBACK`, `OWNER_RULES`, `SELFHOST_BOOTSTRAP_OWNER`, `ACCESS_OPEN_ACKNOWLEDGE_PUBLIC`.
- Behaviour: `SELFHOST_COURSE_STATE`, `SELFHOST_DISABLED_TOOLS`, `ALLOWED_WRITE_TOOLS` (ceiling).
- Schools: `CANVAS_API_URL`, `CANVAS_FEATURED_SCHOOLS`, `CANVAS_SCHOOL_SEARCH` (v1: all three removed in self-host mode, D6, D7; upstream modes keep `CANVAS_API_URL`).
- Authz tuning: `ACCESS_TOKEN_TTL`, `REFRESH_ABSOLUTE_TTL`, `REFRESH_REUSE_GRACE_S`, `GRANT_STATUS_CACHE_S` (v1: removed), `CIMD_ENABLED`, `CIMD_FETCH_TIMEOUT_S`, `CIMD_STALE_MAX`, `MAX_UPSTREAM_AUTH_AGE`.
- P7: `SELFHOST_LOGIN_PROVIDERS` (unset = `entra` alone), `GOOGLE_*`, `GITHUB_*`, `OIDC_<SLUG>_*` (incl. `OIDC_<SLUG>_DISPLAY_NAME`, 40 characters at most; v1: removed, D8). Today every provider except `entra` needs `SELFHOST_AUTH_MODE=local` (startup problem otherwise; `login/config.py`; v1: the check goes with the mode), at most 8 providers. `SELFHOST_BOOTSTRAP_OWNER=token_admin` is also a P7 value.
- Refused at startup today: `CANVAS_API_TOKEN`, `MCP_ACCESS_KEYS`, `ENTRA_AUTH_ENABLED`, `MCP_ALLOW_UNAUTHENTICATED`, `ACCESS_REQUEST_ENABLED` (`app.validate_selfhost_startup`), `FASTMCP_SSRF_TRUST_PROXY` (`app._ssrf_trust_proxy_enabled`), `TRUSTED_PROXY_CIDRS` (reserved; `accounts.parse_access_settings`), `SELFHOST_STATE_BACKEND=redis`, enabling `execute_typescript`; P7 only: `ACCOUNT_LINK_BY_VERIFIED_EMAIL` (reserved; `accounts.LINK_BY_EMAIL_ENV` does not exist on `uci-student`). All stay refused in v1.
- No admin-editable server configuration exists today. v1 adds it (V1-DESIGN 5).

---

## 4. Invariants and conventions (do not break)

Security properties (all hold through v1; V1-DESIGN 6.2 requires a passing test for each reviewed property):
1. Every MCP call runs with the caller's own Canvas token, resolved per request; there is no shared token and no fallback to a default school or another user's credential (v1 removes the default school entirely).
2. Revocation is an authorization decision, not row deletion (fixed in `51ed351`); state is bound to the credential generation (`d91e7ca`; v1: `accounts.credential_generation`).
3. Fail closed: unknown, disabled, pending, unreadable or unavailable means refuse (403/503), never allow. A settings snapshot that cannot be built is a 503, never "allow all".
4. Owner actions: stored owner role, fresh sign-in (10 min), CSRF + Origin + `Sec-Fetch-Site`, in-transaction owner re-check, one audit row in the same transaction; refusals write no change.
5. At least one usable owner must always exist (P7 rule; enforced on disable, demote, unlink, startup, bootstrap).
6. Secrets are never logged or echoed. Messages name settings, not values. Client secrets and tokens are `repr=False`.
7. Output is escaped: React renders text only, no `dangerouslySetInnerHTML` (`sourceGuards.test.ts`), and the SPA has a CSP. Today's legacy pages also escape (`html.escape` / `_e`) and use no JavaScript for forms; they are deleted in v1 (D5), after which Python renders no HTML except a minimal static 400 for an unusable ceremony.
8. Outbound fetches of user-influenced hosts go through the SSRF checks (`check_public_host`, SafeHttp, the pinned CIMD fetcher). `allow_private` (v1) is settable only by the operator CLI, never from a web session.
9. Canvas tokens are sent only to the Canvas origin; downloads off Canvas require HTTPS (`core/course_files.stream_file_download`).
10. (v1, D10) A Canvas token is stored only with a recorded custody acknowledgement (notice version and server time), and an MCP request is served only while that acknowledgement is of the current notice version (6.4).

Boundaries:
- Upstream (non-selfhost) modes stay free of the data layer: `tests/selfhost/test_dependency_isolation.py` runs subprocesses where SQLAlchemy, Alembic and psycopg cannot be imported. `settings.py`, `login/config.py` and (v1) `routes.py` stay standard library only.
- Only `authz/fastmcp_compat.py` imports FastMCP/MCP internals (`tests/selfhost/authz/test_authz_compat_contract.py`; a release blocker in v1).
- `tests/security/test_course_cache_isolation.py` stays byte-identical to upstream (the #480 HTTP-boundary test). Check after every merge: `git diff origin/main -- tests/security/test_course_cache_isolation.py` must be empty.
- New write paths: `test_repo_statements.py` compiles every statement for PostgreSQL and checks locking (today: `FOR UPDATE`, writer lock first, `ON CONFLICT`; v1: the tiers and lock order of V1-DESIGN 4.6).
- API parity: anything added to `account_api.py` must also go into `web/src/api/contract.ts`, `endpoints.ts`, `dev/mockServer.ts`, both locales, and `errors.ts` for new error codes (`test_account_api_contract.py`, `contract.test.ts`, `localeParity.test.ts`). `web/dist` is not committed; run `npm run build` and `npm run check:dist` after changing `web/` (`checkDist.test.ts` tests the checker script on fake builds; it does not need a real build). In v1 the API prefix is `/api/v1` and the route contract test (V1-DESIGN 3.8) pins every path named in docs, proxies, the smoke test and `web/src`.

Repository text:
- English only (`tests/test_english_only.py`). Chinese is allowed only in explicit allowlists: `_DENIAL_ZH`, `_DENIAL_ZH_FALLBACK`, `_ZH_ENDONYM`, first argument of `_bi(zh, en)`, `web/src/locales/zh/`, the endonym in `web/src/locales/en/common.json`, and tests listed in `ZH_RENDERING_TESTS`. A new zh test file must be added there with a reason. The allowlists shrink when the legacy UI goes (V1-DESIGN step 2).
- No closing keywords (a closing verb directly followed by an issue reference) anywhere in commit messages or PR bodies, even when quoting (`scripts/check_closing_keywords.py`, `.githooks/commit-msg`, `closing-keyword-guard.yml`). Write "Part of the staged discussion in #484" or "related to issue N".
- No AI attribution: no `Co-Authored-By` trailers, no "Generated with" lines in commits, PRs, docs, code comments or metadata. Commits use the owner's identity; never change git `user.name`/`user.email`.
- Examples in repository docs and proxy configs use neutral names: `mcp.example.com` for the server, `canvas.example.edu` for a school (D11). Never the owner's real domain or a real school's Canvas host.
- Explicit encodings on every text read/write (`test_text_encoding_guard.py`). `*.sh` files are LF (`.gitattributes`).
- Upstream style (`CLAUDE.md`): type hints, `X | Y` unions, ruff line length 88 (`pyproject.toml`), one sibling worktree per change from `origin/main`, branch prefixes `feature/`, `fix/`, `docs/`, `refactor/`, a failing regression test first for a reproducible bug, never send live Canvas writes to verify a patch. Conventional commit prefixes (`feat`, `fix`, `docs`, `test`, `style`, `chore`) are the history's practice, not a `CLAUDE.md` rule.

Process:
- Every self-hosted change passes {dev, locked} x {SQLite, PostgreSQL}.
- Every user-visible change gets a CHANGELOG `[Unreleased]` entry; every new setting goes into `env.example` and `deploy/selfhost/README.md`.
- Pushing `uci-student` publishes `:edge`; do not push half-finished work there. v1 lives on `feature/v1-consolidation` until it is complete.
- Every new feature is built once, in the React UI and `/api/v1` (D5).

---

## 5. Decisions log

Owner decisions are authoritative. A later row supersedes an earlier one where it says so.

| Date | Decision | Reason / note |
|---|---|---|
| (P3) | SQLite default, PostgreSQL optional, Redis reserved | single small deployment; one process. Kept in v1 |
| (P3/P5) | React + Vite UI, legacy pages stay default | SUPERSEDED by D5 |
| (P4) | No Canvas OAuth login | needs an institutional Developer Key; restated by D13 |
| (P6) | Own authorization server opt-in; `entra_proxy` stays default and is not removed | SUPERSEDED by D2 |
| (P7) | `OWNER_RULES` are Entra-only; Google/GitHub/OIDC claims never make an owner (bootstrap and `token_admin` can) | limit escalation paths. Kept |
| (P7) | No linking by e-mail | account-takeover risk. Kept |
| 2026-10-10 | The fork is "our own version": keep the name canvas-mcp, say clearly it is an independent fork not endorsed upstream | restated by D12 |
| 2026-10-10 | Only small core improvements go upstream | maintainer welcomed #490-style PRs; restated by D12 |
| 2026-10-10 | Friends at several schools use the owner's deployment | |
| 2026-10-10 | Sign-in is the owner's own Entra tenant; friends are invited as Entra B2B guests and assigned `Canvas.User`; default `SELFHOST_AUTH_MODE=entra_proxy` | the auth-mode part is SUPERSEDED by D2; the rest is restated by D2 |
| 2026-10-10 | No Google/GitHub for now; P7 code stays available but off | restated by D2 |
| 2026-10-10 | Canvas OAuth (institutional Developer Key) rejected for now, reserved as a design note | "needs the school's cooperation"; restated by D13 |
| 2026-10-10 | Multi-user features stay in the code | |
| 2026-10-10 | Upstream pilot (Stage A) not pursued; fork continues independently | |
| 2026-10-10 | Owner accepts the Instructure API Policy risk for a small trusted group | section 10 |
| 2026-10-11 | (earlier R1, R2) admin-named sign-in methods; no featured school by default | SUPERSEDED in detail by D6 and D8 |
| 2026-10-11 | D1: Nothing is deployed; do the consolidation in one step ("do it once properly") | no migration of existing data, no aliases, no intermediate compatibility layer |
| 2026-10-11 | D2: Remove `entra_proxy`; the own authorization server is the only MCP auth path; Entra (the owner's own tenant) is the default sign-in provider; friends join as Entra B2B guests assigned `Canvas.User`; Google/GitHub/OIDC stay available but off until listed in `SELFHOST_LOGIN_PROVIDERS` | V1-DESIGN 2 |
| 2026-10-11 | D3: Routes `/auth/login`, `/auth/login/{provider}`, `/auth/callback/{provider}` (Entra: `/auth/callback/entra`), per RFC 9700 section 4.4.2.2; JSON API moves to `/api/v1`; `/account` is the React UI | V1-DESIGN 3 |
| 2026-10-11 | D4: Squash all revisions into one clean v1 baseline designed for extensibility and performance | V1-DESIGN 4 |
| 2026-10-11 | D5: The React UI becomes the ONLY account UI; legacy server-rendered pages are removed (V1-DESIGN step 2 is mandatory); every new feature is built once | answers the former V1-DESIGN open question 1 and Q-UI |
| 2026-10-11 | D6: Featured schools come only from the admin panel; the list starts empty (no preset, not UCI, not UBC); `CANVAS_FEATURED_SCHOOLS` is removed | V1-DESIGN 5. V1-DESIGN also gives the same code path a headless `token_admin schools` twin (audited as operator); it adds no other source, and the owner may drop it |
| 2026-10-11 | D7: The school directory search switch is admin-editable, ON by default; `CANVAS_SCHOOL_SEARCH` is removed | supersedes the earlier "keep search env-only" recommendation (Q-R2-4) |
| 2026-10-11 | D8: Custom sign-in method names: one name per method, shared by English and Chinese; editable by the owner in the admin panel (not hardcoded, not env-only) | answers Q-R1-1 and the former V1-DESIGN open question 3; `OIDC_<SLUG>_DISPLAY_NAME` removed; V1-DESIGN also offers `token_admin providers rename` as a twin of the panel |
| 2026-10-11 | D9: Rename now: `MCP_AUTH_MODE=entra-oauth` -> `MCP_AUTH_MODE=selfhost`; `ENTRA_API_SCOPE` -> `MCP_SCOPE` (default value `Canvas.Access` kept); old names refused at startup with a message naming the replacement | answers the former V1-DESIGN open question 2; done in V1-DESIGN step 1 |
| 2026-10-11 | D10: Custody acknowledgement before a Canvas token is enrolled: a notice (the operator can technically decrypt stored tokens; create tokens with an expiry; how to revoke in Canvas and delete here) plus a REQUIRED checkbox; recorded server-side with time and notice version; a changed notice version requires a new acknowledgement | answers Q-CUST; 6.4 |
| 2026-10-11 | D11: Repo docs and nginx/Caddy examples use neutral examples (`mcp.example.com`, `canvas.example.edu`) instead of the owner's real domain and UCI's Canvas host | answers Q-README; 6.5 |
| 2026-10-11 | D12: Keep the name canvas-mcp; state clearly that this is an independent fork of `vishalsachdev/canvas-mcp`, not endorsed by upstream; only small core improvements go upstream | 6.5 |
| 2026-10-11 | D13: Canvas OAuth (institutional Developer Key) is rejected for now and only reserved | reserved schema and routes in V1-DESIGN 4.14 |
| 2026-10-11 | D14: Stay on Python + React/TypeScript; MUI 9 stays the UI library | V1-DESIGN 1.1 |
| 2026-10-11 | D15: No reply on #484. The maintainer is not waiting on anything (his own triage brief lists #484 as needing nothing); his invited items are delivered as #490 and #491; the remaining items concerned the upstream pilot, which is withdrawn. The withdrawal is recorded in the fork's proposals status banner (6.8) instead; context goes only into future upstream PRs if needed | 6.8, 6.9 |

Defaults chosen for minor questions (the owner may override any of them):

| Topic | Default |
|---|---|
| Where the documents go | `deploy/selfhost/DEVELOPMENT.md` (this handoff) and `deploy/selfhost/V1-DESIGN.md` (the consolidation design). `deploy/selfhost/` has no ignore rule (unlike `internal/`, which is deny-by-default in `.gitignore`) |
| Upstream PRs with no response | wait about two weeks, then one polite ping; never close them unilaterally |
| Pilot profile (maintainer item 5) | an optional preset that also refuses incompatible settings (6.6.1) |
| Off-Canvas download hops | refusing them is NOT the default for every deployment; only the pilot profile refuses them |
| V1-DESIGN 7.1 technical questions | implementer decisions with the document's recommended default: the governance gate is a per-process lock taken before a pool connection (4.6); keep `FOR NO KEY UPDATE` on other owners' rows in `usable_owner_ids` (4.6); cap the JWT `kid` epoch at 10 digits (4.5.1); verify the SQLite version inside the image with a test (4.9); operator account deletion writes one audit row per deleted account in the same transaction and keeps history rows (4.6, 4.16); bump `CUSTODY_NOTICE_VERSION` only for a change of substance (step 6b) |

---

## 6. Backlog

Priority order: 6.1 B0, then 6.1a v1 (with 6.2 and 6.3 as its site inventories and 6.4 for D10), then 6.5 to 6.12. 6.13 is a pool of small independent fixes.

### 6.0 Open questions, answers and defaults

Still open (owner decision pending):
- None. Every owner-level question is answered below.

Answered (kept for the identifiers that other documents cite):

| Id | Question | Answer |
|---|---|---|
| Q-UP-489 | Strengthen #491 and open a second upstream PR for the discussion half of #489? | Yes (2026-10-11), because the maintainer opened #489 himself with acceptance criteria. #491 gets the missing coverage (both caller orders, concurrency, credential changes, outgoing-request assertions); a second PR covers the discussion REST availability hints (`_unservable_topics` in `tools/discussions.py`). The owner reviews a new PR body before it is opened (6.7). |
| Q-484 | Post a reply on #484, and mention friends using the deployment? | No reply (D15). Record the withdrawal in the fork's proposals status banner (6.8). |
| Q-DOC | where to commit this document | default chosen: `deploy/selfhost/DEVELOPMENT.md`, with `deploy/selfhost/V1-DESIGN.md` (section 5) |
| Q-R1-1 | one name per method or separate en/zh names | one name, shared by both languages (D8) |
| Q-R1-2 | may the audit log store the free-text names | yes (V1-DESIGN 5.4) |
| Q-R2-1 | precedence of `CANVAS_FEATURED_SCHOOLS` vs the database | the variable is removed and refused; the database is the only source (D6) |
| Q-R2-2 | role of `CANVAS_API_URL` | removed in self-host mode; a single-school deployment is one featured school with search off (V1-DESIGN 5.2) |
| Q-R2-3 | startup with zero offered schools | starts with a warning and an admin banner (V1-DESIGN 5.8) |
| Q-R2-4 | owner control of directory search | admin-editable, on by default (D7) |
| Q-R2-5 | removing a school with enrollments | explicit confirmation when directory search is off (with search on, only the quick pick disappears); rows kept; re-featuring restores access (V1-DESIGN 5.8) |
| Q-CUST | checkbox recorded server-side, or notice only | required checkbox, recorded with time and notice version (D10) |
| Q-PILOT-1 | preset + startup guard, or presets only | default chosen: optional preset that also refuses incompatible settings |
| Q-PILOT-2 | no off-Canvas hops for every deployment | default chosen: no; only the pilot profile |
| Q-UP | what to do if #490/#491 get no response | default chosen: about two weeks, one polite ping, never close unilaterally |
| Q-README | neutral names in docs and examples | yes (D11) |
| Q-UI | make the React UI the default | it becomes the only UI (D5) |
| V1-DESIGN former Q1 | remove the legacy UI | yes (D5) |
| V1-DESIGN former Q2 | rename `MCP_AUTH_MODE=entra-oauth` and `ENTRA_API_SCOPE` | yes (D9) |
| V1-DESIGN former Q3 | per-language sign-in names | no, one name (D8) |
| V1-DESIGN 7.1 technical items | governance gate, `FOR NO KEY UPDATE` on other owners, `kid` epoch cap, SQLite version in the image, audit for operator account deletion, custody notice version bumps | implementer decisions; recommended defaults in section 5 |

### 6.1 [B0] Independent review and merge of P7; upstream sync

- **Goal:** `feature/p7-login-providers` reviewed independently, merged into `uci-student`, then `origin/main` merged in.
- **Why:** v1 starts on top of P7 (V1-DESIGN 6.0); building v1 first would make P7 a rewrite.
- **Current state:** HEAD `53b86dd`, clean, not pushed. The last fix round (`53b86dd`, on top of `ae015d5`) changed 12 files (+400/-51) and passed the full test matrix, but has NOT been independently reviewed. Every earlier review round found new owner-recovery edge cases, so treat this one as unreviewed code. What `53b86dd` claims to fix:
  - F1: a bootstrap owner, or an owner re-sourced to bootstrap or operator, whose account the access rules no longer admit kept `admitted_via = "rules"`, got one session, and was then denied while still counting as a usable owner. `decide()` now sets `admitted_via` to `bootstrap` when the bootstrap raises, re-sources or admits an active account that was not personally admitted; `_apply_role` writes and audits it; `promote_owner` does the same (`operator`) when it re-sources an unusable owner. A plain promotion is unchanged.
  - F2: `token_admin` vs a stale record of listed providers. The server now records its listed providers before the owner-path check, so a refused start leaves the list it was refused for. `token_admin` notes when `SELFHOST_LOGIN_PROVIDERS` in its environment differs from the record and counts owners as usable only under providers in both lists (the record stands when they share none).
  - F3: an Entra-only bootstrap admitted while rules deny with zero owners (differed from base). Not named in the `53b86dd` message; the reviewer must confirm its state (touched in `accounts.py`, `app.py`, `tests/selfhost/login/test_bootstrap_startup.py` in `ae015d5` or earlier; unverified).
  - F4: a re-source is recorded as `owner_re_sourced` instead of `owner_gained`; the audited `unusable_owners` count no longer includes the account itself.
- **Steps:**
  1. Independent review by someone (or an agent) who did not write the fix rounds. Scope: the diff `uci-student..53b86dd`, with depth on `ae015d5..53b86dd`. Focus: every path that can leave zero usable owners or lock an owner out (bootstrap, re-source, `admitted_via`, rules that stop admitting, unlink, disable, demote, startup refusal, `token_admin` with a differing environment). Each finding needs a failing-before/passing-after test.
  2. If the review finds anything: fix on the branch, rerun the full matrix, and review again (at least the new diff). Repeat until a round finds nothing.
  3. Full matrix (2.4), web checks, `test_english_only.py`, closing-keyword tests, `test_course_cache_isolation.py` unchanged, `uv lock --check`.
  4. `git checkout uci-student && git merge --ff-only feature/p7-login-providers` (if `uci-student` moved, use a merge commit and expect CHANGELOG conflicts).
  5. Push `fork uci-student`; confirm `canvas-mcp-testing.yml` and `selfhost-image.yml` (incl. the smoke test) are green.
  6. Upstream sync (7.2). The local `origin/main` ref is 7 commits ahead of `uci-student`: `d2de3af` (#486 docs: Canvas OAuth scope inventory, `tools/oauth/*`), `6111789` (#463 claude-code-action bump), `4ec9dbb` (#453 @types/node bump), and the triage commits `5cef947`, `615aa2e`, `156c58c`, `63f4222` (#492, `internal/issue-triage/2026-10-11.md`). The combined diff touches no selfhost file (`.github/workflows/claude*.yml`, `weekly-maintenance.yml`, `package*.json`, `tools/`, `internal/issue-triage/`). Fetch first; more may have landed.
- **Acceptance:**
  - [ ] An independent review round with no open findings; F1-F4 each covered by a test that fails on `ae015d5` (or the base) and passes after.
  - [ ] Full matrix green; CI green on the merge commit; image smoke test green.
  - [ ] Entra-only behaviour byte-identical (`tests/selfhost/login/test_entra_only_golden.py`).
  - [ ] `test_course_cache_isolation.py` identical to upstream after the sync.
- **Risks:** merging on green unit tests alone (every earlier round passed tests and still had findings). Large CHANGELOG `[Unreleased]` hunks conflict easily.
- **Size:** S-M, depending on review findings.

### 6.1a [V1] v1 consolidation (D1-D10)

The former 6.1a design (a `server_settings` JSON table in a separate Alembic revision `0004_server_settings`, per-row versions, a 5 s TTL cache, env-seeded lists) is SUPERSEDED and deleted. The authoritative design is V1-DESIGN; this item only sequences it and records how the owner's decisions apply. Do not duplicate the design here.

- **Prerequisites (V1-DESIGN 6.0):** 6.1 done; branch `feature/v1-consolidation` in `.worktrees/v1`; the former V1-DESIGN open questions are answered (D5, D8, D9), so no step is conditional.
- **One step (D1, V1-DESIGN 6.0):** steps 1 to 8 are an order of work inside one consolidation, not releases. Their pull requests target `feature/v1-consolidation`, which merges into `uci-student` once, when the step 8 release gate is green. No aliases, shims or transition releases.
- **Test matrix for every step:** V1-DESIGN 6.1.
- **Steps (V1-DESIGN section 6):**

| Step | Scope | Decisions | V1-DESIGN |
|---|---|---|---|
| 1 | Local-only authorization: delete `entra_proxy`, `oauth.py`, the auth-mode setting, signing key, `FASTMCP_HOME`, grant-status cache, `py-key-value-aio`; `REMOVED_SETTINGS`; the Entra app registration stops being an API (V1-DESIGN 2.5; the sign-in ceremony itself moves to the flow engine in step 3); the D9 renames (about 22 files, keep the upstream diff minimal) | D2, D9 | 2.1-2.6, step 1 |
| 2 | Legacy UI removal (mandatory): move session, CSRF, Origin and consent logic (and, until step 3, the Entra sign-in routes) to `account_core.py`; delete the HTML; `ACCOUNT_UI` refused; unusable bundle refuses startup | D5 | step 2 |
| 3 | Routes: `selfhost/routes.py`, `login/routes.py`, `/auth/*`, `/api/v1`, Entra on the flow engine, proxy examples, smoke test, route contract test | D3 | 3, step 3 |
| 4+5 | Data layer v1 and the store port, one pull request: baseline `0001_v1_baseline`, 19 tables (incl. the D10 custody columns), types, sealed registry, hot path, locking tiers, races | D4, D10 | 4, steps 4 and 5 |
| 6 | Admin-editable settings: schools, directory search, sign-in names, `token_admin schools|providers|settings`, Admin > Settings in React | D6, D7, D8 | 5, step 6; inventories in 6.2 and 6.3 below |
| 6b | Custody acknowledgement: notice, `/api/v1` contract, React form, MCP check, audit | D10 | 4.3.8, 4.5.1, step 6b; 6.4 below |
| 7 | Maintenance and transfer | D4 | 4.8, 4.13, step 7 |
| 8 | Reserved interfaces, docs (incl. neutral examples and the fork statement), release gate (live checks 6.12 before the first v1 tag) | D11, D12, D13 | 4.14, step 8; 6.5 below |

- **How the decisions shape the plan (all reflected in V1-DESIGN):**
  - Nothing is conditional: step 2 and the D9 renames are part of the plan. `ACCOUNT_UI` refuses startup (`ACCOUNT_WEB_DIST` stays; a missing or invalid bundle refuses startup); `ENTRA_API_SCOPE` refuses naming `MCP_SCOPE`; `MCP_AUTH_MODE=entra-oauth` is refused by `settings.auth_mode()` naming `MCP_AUTH_MODE=selfhost` (V1-DESIGN 2.3). Messages name the setting, never its value.
  - The "legacy" halves of 6.2 and 6.3 are not built.
  - D11 and D12 are done in step 8 (6.5); any doc or example touched earlier already uses the neutral names.
- **Behaviour changes the owner accepted with D2 (V1-DESIGN 2.4):** an account is created only by a sign-in ceremony (one operator exception: `token_admin disable` for someone who has not signed in yet creates a disabled account); Entra role changes reach the server at the next sign-in or after `MAX_UPSTREAM_AUTH_AGE` (14 days), so offboarding is "disable in the panel first, then remove in Entra"; there is no fallback auth mode; revocation, disable and `rotate-jwt-key` act at the next request.
- **Acceptance:** V1-DESIGN 6.2 (global) plus each step's list.
- **Risks:** V1-DESIGN 6.3. In particular, start only after 6.1, and re-read `login/*`, `token_store.py` and `account_web.py` at the merge commit.
- **Size:** L (several pull requests; steps 4+5 are one).

### 6.2 [V1-NAMES] Sign-in method names: site inventory for V1-DESIGN step 6

Former R1. The data model, precedence, API shape and audit actions of the former design are SUPERSEDED by V1-DESIGN 4.3.3 and 5 (names live in `login_providers.display_name`; one global `settings_revision` CAS instead of per-row versions; `PUT /api/v1/admin/settings/sign-in-methods`; audit action `sign_in_method_renamed`; no legacy pages, D5; no `OIDC_<SLUG>_DISPLAY_NAME`, D8). What remains here is what V1-DESIGN 5.7 and 5.9 cite: the site inventory, acceptance and tests.

- **Effective name:** the owner's name if set, else the built-in default ("Microsoft", "Google", "GitHub", or the OIDC slug). Defaults are unchanged, so existing pinned tests stay green with no saved names. Icons stay built-in per kind and are not editable (reserved). One name per method for both languages (D8).
- **Validation:** V1-DESIGN 5.3 (the former 6.2 rules, unchanged).
- **History pages** show the CURRENT name of a provider (`auth_events` stores the provider id). Document this; no history of names is kept.
- **Consent:** the consent page names no provider; its sign-in step (`consentLoginPath` in `web/src/utils/appRedirect.ts`, v1: `/auth/login?txn=`) goes through the provider chooser, so the name reaches the consent flow there. Test it.
- **Sites that still apply after D5** (all under `core/selfhost/` unless a path says otherwise):

| Site | Change |
|---|---|
| `login/entra.py` `ProviderDisplay("Microsoft","microsoft")`, `login/google.py`, `login/github.py`, `login/oidc.py` | defaults only |
| `login/registry.py` `LoginRuntime.entries()` | names from the settings snapshot per call, never cached in `__init__` |
| `account_api.py` `providers()` (~730; v1 `GET /api/v1/providers`) | both branches use the snapshot (the Entra-only branch has a literal `"Microsoft"`) |
| `accounts.py` `DENIAL_MESSAGES[DENY_WRONG_TENANT/DENY_ACCESS_DENIED]` (~175-200) | add `render_denial(code, entra_name)`; returns the identical constant when the name is "Microsoft" (`tests/selfhost/test_identity.py:125`) |
| `principal_access.access_not_provisioned_message()` (returns `DENIAL_MESSAGES[DENY_ACCESS_DENIED]`) | route through `render_denial`; module-level, so add a name parameter |
| `request_context.not_enrolled_message()` (~217, "your Microsoft account ... sign in with Microsoft") | use `names.primary_phrase()` (the sole configured provider's name, else neutral wording such as "Sign in at <account_url>"); MCP tool error read by the model |
| new `school_not_offered_message()` | host-free; no provider name needed |
| React: `views/SignInView.tsx`, `views/SignInMethodsView.tsx`, `components/LoginHistory.tsx`, `components/admin/AccountIdentities.tsx` | already API-driven; invalidate the `providers` query after a save |
| `web/src/dev/mockServer.ts` (default `name: 'Microsoft'` at ~99 and ~679; keep) | mock settings endpoints and a custom-name scenario |
| `AdminAuditView.tsx` `KNOWN_ACTIONS`, `KNOWN_DETAIL_KEYS`; `admin.json` `audit.actions` | add the V1-DESIGN 5.4 actions and detail keys; also fix the existing gap: `identity_linked`, `identity_unlinked`, `identity_link_refused` render as "Other" |
| `account_web.py` sites (`_provider_label`, `_identity_line`, `signed_out_page`, callback failures, `_choose_provider`, sign-in methods card, link/unlink messages, admin identities, `_DENIAL_ZH`/`_denial_html`) | deleted with the legacy UI (V1-DESIGN step 2); nothing to change. Their messages must exist in the SPA (error codes and locale strings) |

- **Acceptance:**
  - [ ] With no saved names, all existing tests (as ported to v1) pass unchanged.
  - [ ] After a rename (no restart, also from another process), the new name appears in: the SPA sign-in chooser, `GET /api/v1/providers`, the sign-in methods page, login history, admin identities, failure and refusal messages (en and zh), the last-owner message, and both MCP-side messages.
  - [ ] Refused with the documented code and no change: non-owner, pending/disabled owner, stale session (`reauth_required`), missing/wrong CSRF, wrong Origin, wrong content type, oversize body, unconfigured provider id, duplicate name, control or bidi character, `<`/`{`.
  - [ ] Concurrent saves: one wins, the other gets `settings_conflict`. One audit row per change, none per refusal.
  - [ ] Names render escaped (try `A & "B"`); no injection sinks.
- **Tests:** V1-DESIGN step 6 (`test_server_settings.py`, `test_server_settings_api.py`, `test_token_admin_settings.py`); extend `login/test_provider_react.py`, `test_account_api_parity.py`, `test_account_api_contract.py`; vitest for `AdminSettingsView`, `SignInView`, `LoginHistory`; `localeParity`; `test_selfhost_docs.py`.
- **Tests pinning today's text (should stay green with defaults, where they survive step 2):** `test_account_api.py` (~258), `login/test_identities_api.py` (~147), `login/test_provider_react.py` (~49), `login/test_provider_signin.py`, `test_account_spa.py`, `test_account_access_lifecycle.py` (`SIGN_IN_TEXT`), `test_multiuser_e2e.py`, `test_identity.py:125`, `test_selfhost_docs.py` (~1254). `login/test_entra_only_golden.py`, `login/test_legacy_ui.py` and `test_account_web.py` go with the legacy pages.
- **Risks:** missing one hardcoded site (grep `Microsoft` in `src/` and `web/src` after the change; README mentions of Microsoft Entra setup stay); freezing names at startup again.

### 6.3 [V1-SCHOOLS] Featured schools and directory search: site inventory for V1-DESIGN step 6

Former R2. SUPERSEDED parts: the env seed and "Use environment list" (`DELETE`), `CANVAS_API_URL` as a "pin", per-row versions and the 5 s TTL, the 80-character name limit (now 120, V1-DESIGN 5.3), keeping `CANVAS_SCHOOL_SEARCH` env-only (D7), the legacy forms (D5), the API paths `/account/api/admin/settings/featured-schools` (now `PUT /api/v1/admin/settings/schools`, `POST .../schools/check`, `PUT .../directory-search`) and the audit action `server_setting_changed` (now `featured_schools_changed`, `setting_changed`, `school_access_changed`). Data model: `canvas_schools.featured_rank` (V1-DESIGN 4.3.4); rules: V1-DESIGN 5.2-5.8.

- **Target behaviour (D6, D7):** a fresh install features no school and has directory search on; users find their school through the Instructure directory. Nothing is preselected: `selected` is the user's current school if still offered, else `null`. An empty school in picker mode is `school_required`. A single-school deployment is one featured school with search off (`sole_school` auto-selects it).
- **Sites that preset or prefer a school today (all must go; `get_schools`, `_choose_school` and `_school_choices` are the former "preset path 4" that V1-DESIGN 5.7 cites):**
  - `deploy/selfhost/setup-env.sh --school-search` writes `CANVAS_FEATURED_SCHOOLS=${CANVAS_HOST}` (~246; commented variant ~254; help ~51-52) and requires `CANVAS_API_URL` (`ask` plus the regex and `die` at ~147-155). v1: no school prompts; prints "add schools in Admin > Settings". Pins: `tests/test_selfhost_docs.py` ~490, `tests/test_setup_env_script.py` ~395-461.
  - `SchoolPolicy.build` (`schools.py` ~292) always puts the `CANVAS_API_URL` host first in `featured`.
  - `account_api.get_schools` (~826-831): `selected` = enrolled, else `schools.default.host`, else `choices[0]`.
  - `account_web._choose_school` (~2851-2853): an EMPTY posted school in picker mode silently enrolls at the default school; the API token PUT uses the same function (v1: moves to `account_core.py`; must answer `school_required`).
  - `account_web._school_choices` (~1229-1232): preselects the default (legacy; deleted with step 2).
  - `web/src/dev/mockServer.ts` default scenario (~91-95, ~364-367): three featured schools and `selected: 'canvas.example.edu'`. v1: none and `null`; add a `featured` scenario.
  - The README "with the host of `CANVAS_API_URL` as the first featured school" text and the `env.example` school block (~187-209).
  - The operator's own `.env`: in v1 the removed variables refuse startup, so nothing carries over silently.
- **Other sites:** `app._school_problems` (refusal becomes a warning plus admin banner); `request_context.py` (~299, ~451: the `school is None` branch reuses `not_enrolled_message` today; v1 uses `school_not_offered_message()`); every `self.schools` reader in `account_web.py` (21 references; most go with step 2, the survivors move to `account_core.py`) and `account_api.py` (6-7 sites) read the per-request snapshot; `server.py` `--config` (~622 prints `featured=` from env; v1 says schools are managed in the database); admin tables already flag `offered:false` rows (`_school_of`, `TokenSection.tsx`).
- **Validation and removal rules:** V1-DESIGN 5.3 and 5.8 (host checks, directory advisory only, at most 50, confirmation when search is off and a removed host has enrollments, rows kept, re-featuring restores access at the next request).
- **Acceptance:**
  - [ ] Fresh install shows no quick pick; no real school is preset in code, `env.example`, `setup-env.sh` output, mocks or test defaults.
  - [ ] Picker mode: `selected` is `null` for a new user; an empty school is refused with `school_required` (API).
  - [ ] Owner can add, rename, reorder, remove and toggle directory search in the SPA and with `token_admin`; changes reach the picker, `GET /api/v1/me/schools` and the MCP path without restart, also in another process.
  - [ ] Hosts failing syntax, blocked suffix or public-address checks cannot be saved; a directory outage never blocks.
  - [ ] Removal behaves as specified, with the confirmation guard and the distinct MCP message.
  - [ ] `allow_private` cannot be set through `/api/v1`.
  - [ ] Startup with zero offered schools succeeds with a warning.
- **Tests:** update `test_schools.py` (~424 "default is implicitly featured and first"), `test_startup.py` (~386-441), `test_account_schools.py` (~208, 219, 529), `test_setup_env_script.py`, `test_settings.py`, `test_selfhost_docs.py`; add the V1-DESIGN step 6 tests and `test_request_context_read.py` (snapshot rebuild on revision change). Full matrix. `test_course_cache_isolation.py` untouched.
- **Risks:** a stale snapshot ignoring a removal; any "allow all" during the first snapshot build (the first build happens at startup; failure refuses startup).

### 6.4 [CUST] D10 custody acknowledgement

- **Goal:** before a Canvas token is enrolled, the user sees the custody notice and must tick a REQUIRED checkbox; the server records the acknowledgement; a changed notice requires a new one.
- **Specification (authoritative):** V1-DESIGN step 6b, with the schema home in 4.3.8 (`canvas_credentials.custody_notice_version`, `custody_ack_at`, both NOT NULL) and the per-request check in 4.5.1 step 7. Do not duplicate it here. In short:
  - Notice text: the operator can technically decrypt the stored token and could act as the user in Canvas; create a token for this server only, with an expiry date; how to revoke (delete it in Canvas under Approved Integrations, and delete it here). en and zh, in `locales/{en,zh}/account.json` under `custody.v<N>`; version constant `CUSTODY_NOTICE_VERSION` in the new `selfhost/custody.py`, hash-pinned by a test.
  - `PUT /api/v1/me/canvas-token` requires `custody: {acknowledged: true, notice_version}`, checked before any Canvas request or write (`custody_ack_required` 422, `custody_notice_outdated` 409); the server clock sets the time; the enrollment audit row carries the version.
  - A notice version bump makes older acknowledgements insufficient: MCP requests under them are refused with `custody_ack_required_message()` until the user re-acknowledges with `POST /api/v1/me/canvas-token/acknowledge` (audited as `custody_notice_acknowledged`); no stored token is lost.
  - React: the notice above the token field, a required checkbox unticked on every mount, a banner from `GET /me` `custody_ack_required`.
- **Current state:** legacy `account_web._token_form` already states most of the notice (deleted in v1). React `components/token/TokenForm.tsx` only says "stored encrypted and never shown again" (`locales/en/account.json` `enroll.helper`). Nothing is recorded.
- **Also:** policy facts (section 10) go in docs, not on the form; align README "Custody and privacy boundary" (V1-DESIGN step 8).
- **Acceptance and tests:** V1-DESIGN step 6b.
- **Size:** S-M, inside v1 (schema in steps 4+5, the rest in step 6b).

### 6.5 [FORK] README fork framing (D12) and neutral examples (D11)

- **Goal:** readers immediately see this is an independent fork; no fork-owned doc or example names the owner's real domain or a real school's Canvas host.
- **Where it is specified:** V1-DESIGN step 8 ("Neutral examples (D11)", "Fork statement (D12)", the host-allowlist test). Do it there, in the same pass as the route and settings doc changes, so the proxy examples are edited once.
- **Current state:** `README.md` is upstream's; self-hosting appears at ~line 30, 308 (custody), 316. The owner's production domain appears in `deploy/selfhost/README.md`, `nginx.conf.example`, `Caddyfile.example`, `tests/test_selfhost_docs.py` (5 lines) and `proposals/selfhost-pilot/stage-a-appendix.md` (1); `deploy/selfhost/README.md` also uses UCI's Canvas host (line 5 and ~63); counts at P7 are in V1-DESIGN step 8. Locate with `git grep -n -i -e uci.edu -e <owner domain>` at the merge commit.
- **Design (summary of V1-DESIGN step 8, plus fork-level items it does not cover):**
  - D11: `mcp.example.com` for the server and `canvas.example.edu` for a school in `deploy/selfhost/*`, `web/README.md` and the fork-owned docs; the docs-test pins that contain the real domain are rewritten (the new host-allowlist test lists allowed hosts, so it never contains the real domain). The root `README.md` is upstream text and keeps its own hosts. `proposals/` files are history (V1-DESIGN 2.2); default: replace the hostname there too.
  - D12: the first paragraph of `deploy/selfhost/README.md` states the independent fork of `vishalsachdev/canvas-mcp`, not endorsed by upstream, only small core improvements offered upstream. Recommended: the same one-line notice under the title of the root `README.md`, with where to report issues (the fork's tracker) and a link to `deploy/selfhost/README.md`. On #484 the maintainer said the full stack stays out of upstream; say nothing that implies otherwise.
  - `SECURITY.md`: fork-specific code -> the fork's security advisories; upstream code -> upstream.
  - This document and V1-DESIGN are excluded from the route contract test and the doc pin tests (they name old paths on purpose); they stay English and ASCII-only with no closing keywords, and name the owner's domain nowhere.
  - Leave `pyproject.toml`, `manifest.json`, `server.json`, `glama.json`, `CNAME` alone (upstream identity; merge-conflict magnets). `publish-mcp.yml` and `create-release.yml` only run for `vishalsachdev/canvas-mcp`, so the fork cannot publish under upstream's identity.
- **Acceptance:** V1-DESIGN step 8, plus [ ] root `README.md` notice present (if the owner keeps the recommendation); [ ] no claim of endorsement; [ ] no closing keywords.
- **Size:** S.

### 6.6 [M484] Maintainer items: pilot profile and tested-clients table

**6.6.1 Pilot profile** (maintainer item 5: also exclude `read_course_file`; no off-Canvas download hops by default in a pilot)
- **Default chosen:** an optional preset that also refuses incompatible settings. It is not the default for the owner's deployment, and refusing off-Canvas hops is not the default for every deployment.
- **Current state:** `SELFHOST_DISABLED_TOOLS` (`settings._parse_disabled_tools`, validated against `TOOL_EFFECTS`; `app.apply_disabled_tools`). Downloads go through `core/course_files.stream_file_download` (~208; hop-by-hop redirects; token only to the Canvas origin; HTTPS off Canvas). Callers: `tools/files.py` `read_course_file` (~595), `download_course_file` (~442, refused over HTTP), `tools/file_text.py` `read_course_file_text` (~241). The Stage A main document says off-Canvas hops are an accepted residual; `deploy/selfhost/README.md` does not say this.
- **Key fact:** every Canvas file download hops from Canvas to a storage host, so "no off-Canvas hops" = "no file downloads".
- **Design:**
  1. `SELFHOST_PROFILE=pilot` in `settings.py`: adds `read_course_file`, `read_course_file_text`, `download_course_file` to the disabled set and turns off-site downloads off.
  2. Guard: refuse startup (naming settings only) if `ALLOWED_WRITE_TOOLS` is set, code execution is enabled, or `SELFHOST_COURSE_STATE` is not request-local. In v1, schools and directory search are database settings, so the "one school, no search" condition cannot be an env check: check it against the first settings snapshot at startup (refuse), and refuse the admin and `token_admin` writes that would turn search on or feature a second school while the profile is active (a new error code). The owner's multi-school deployment does not qualify; the profile documents what a pilot means.
  3. Guard in `core/course_files.py`: module-level switch, default True (upstream unchanged), set once from `install_selfhost`. When False, a hop leaving the Canvas origin returns `{"error": "Downloads that leave Canvas are disabled on this server"}` before the request. Keep the function's name and shape (small upstream diff).
  4. Leftover: the `list_course_files` fallback notice (`tools/files.py` ~872) and the `download_course_file` description mention removed tools; optionally omit when not registered.
- **When:** after V1-DESIGN step 6 (it depends on the settings snapshot).
- **Tests:** `tests/selfhost/test_settings.py`, `test_disabled_tools.py`, `test_startup.py`, the settings API tests (refused writes), `test_selfhost_docs.py`; a unit test next to the existing `stream_file_download` tests; keep `tests/security/test_file_tool_host_boundary.py` and `test_local_export_host_boundary.py` green.
- **Size:** S-M.

**6.6.2 Tested-clients table** (maintainer item 6: advertise only clients actually exercised)
- **Current state:** `deploy/selfhost/README.md` line 3 says claude.ai web, desktop, mobile and Claude Code can connect; the auth-mode table (~438) has "Proven with claude.ai, Desktop, mobile and Claude Code | Yes". Nothing has been tested live, so these overclaim. The auth-mode table goes away in v1 (one mode).
- **Design:** "Tested clients" section: columns client/surface, client version, server version or image digest, date, tester, result (`Not tested`/`Passed`/`Partial`/`Failed`), evidence, notes. Rows: claude.ai web, Claude Desktop, Claude mobile, Claude Code; all start `Not tested`. Reword line 3 and any CHANGELOG wording to "see Tested clients; only Passed rows are claims". Mobile is not claimed until tested.
- **Tests:** docs test: table exists, allowed vocabulary, intro does not name a surface whose rows are all `Not tested`.
- **Size:** S (doc), done with V1-DESIGN step 8; rows filled by 6.12.

### 6.7 [UPPR] Upstream items: #489, #491, #490 (decided: option C, in progress)

Keep every upstream change independent of the fork's hosting stack, one concern per PR, no closing keywords (write "Part of #489" or "related to issue 489", never a closing verb before the reference).

- **#490** `fix: exclude RequestCredentials.api_token from repr` (branch `fix/request-credentials-repr`, `ee843f5`; tests in `tests/test_http_transport.py`). Open, review required, no comments. Upstream's triage executor (`internal/issue-triage/2026-10-11.md`, PR #492) verified it independently (3239 passed) and listed it for the maintainer's review and merge decision. Action: none until the maintainer responds; then the no-response default (about two weeks, one polite ping, never close).
- **#491** `fix: keep course-policy verdicts within the HTTP caller` (branch `test/course-policy-caller-boundary`, `6b64885`; `tests/security/test_course_policy_caller_boundary.py`, 8 tests; in HTTP mode `get_course_policy` bypasses `_policy_cache`). Open, review required, no comments. The triage verified that its regression reproduces on unpatched main (7 of 8 fail) and listed it for the maintainer's decision. It covers only the course-policy half of #489 and does not yet test concurrency or credential changes.
- **#489** (opened by the maintainer 2026-10-11, labels bug, security) "Audit caller boundaries in HTTP course-policy and discussion caches". Acceptance criteria: two HTTP credentials, same course id, different outcomes; both caller orders, concurrent calls and credential changes; a cached denial must not poison another caller and a cached verdict must not skip caller-specific checks; audit the discussion REST availability hints (`tools/discussions.py` `_unservable_topics`, keyed by `(prefix, topic_id)`, ~391-440 on `origin/main`) under two callers; use the request-local boundary; preserve stdio and #480; verify forbidden side effects and outgoing requests, not only response text; anonymization map sharing is assessed separately (out of scope here).
- **Decision (Q-UP-489, 2026-10-11): option C, both A and B.** Work in progress at the time of writing: A as new commits on the #491 branch (worktree `.worktrees/up-policy`), B on branch `test/discussion-hint-caller-boundary` from `origin/main` (worktree `.worktrees/up-discussions`). Check `gh pr view 491` and the branch before continuing. The options as originally considered:
  - A. Strengthen #491 to meet the course-policy half of #489: add both caller orders, concurrent calls, a credential change between calls, "cached denial does not poison", "cached verdict does not skip caller checks", and assertions on outgoing requests (respx call lists) and side effects, not only response text; keep stdio and #480 behaviour pinned. Push to the same branch; say in a PR comment what was added and what was not verified.
  - B. A second upstream PR for the discussion half: a regression test with two HTTP callers sharing `_unservable_topics` (both orders, concurrency, credential change; outgoing requests asserted), then the smallest fix that keys or bypasses the hint per request-local boundary. Branch from `origin/main` (7.1), not from `uci-student`.
  - C. Both A and B.
  - D. Neither: leave #489 to the maintainer; #491 stays as is.
  - For any option, if upstream `main` moves, rebase only on conflict; answer review comments with facts, evidence and what was not verified; if asked about the red `claude-review` check, point to the secret restriction (upstream's triage already calls it an upstream workflow issue).
- **After merge upstream:** the next sync (7.2) brings them into `uci-student`; check the fork has no duplicate copy.
- **Size:** S each (A, B).

### 6.8 [PROP] Proposals update: gateway evaluation and Stage A status

- **Current state:** `proposals/selfhost-pilot/stage-a-main.md` and `stage-a-appendix.md` (dated 2026-10-09, describe `f32b9d3`, `MCP_AUTH_MODE=entra-oauth`, one pinned Canvas, "multi-school deferred", "gateway not evaluated"). Draft evaluation: `proposals/selfhost-pilot/gateway-evaluation-draft.md` (committed with this document; English, sources [1]-[45], dated 2026-10-10, UNVERIFIED items marked).
- **Design:**
  - Rename the draft to `proposals/selfhost-pilot/gateway-evaluation.md` with the same front matter style; re-date figures that go stale (it quotes a diff size against `71602e6`); keep UNVERIFIED marks; add a "Status" paragraph: the owner keeps the fork's own portal; the built-in authorization server is the only MCP auth path and Entra is a sign-in method (D2); Canvas OAuth is rejected for now and only reserved (D13).
  - Status banner in both Stage A files (`status:` front matter + a first paragraph): historical record; upstream pilot not pursued; fork continues independently; documents describe `f32b9d3` (incl. the old `entra-oauth` mode name and the Entra proxy, both gone in v1); gates G1 and G2 unmet and not claimed; multi-school since added by owner choice.
  - `proposals/selfhost-pilot/README.md` indexing the three files.
  - D11 for hostnames in these files (6.5).
  - Check the draft for non-English text before committing (`test_english_only.py`).
- **Acceptance:** [ ] three files + index; [ ] English-only and closing-keyword guards green.
- **Size:** S.

### 6.9 [R484] Reply on #484: decided, no reply

- **Status:** decided 2026-10-11 (D15): do not post on #484. Nothing to build.
- **Instead:** the Stage A status banner and the proposals README from 6.8 record that the upstream pilot is withdrawn and the fork continues independently. If a future upstream PR (for example a #489 follow-up, 6.7) needs context, state it in that PR body, factually and without claiming any approval by upstream, Instructure or a school.
- **Size:** none.

### 6.10 [REL] Beta release

- **When:** after V1-DESIGN step 8 and the live checks of 6.12 (the first v1 tag is gated on them). Nothing is deployed (D1), so no tag is needed between B0 and v1; staging can run `:edge` or a digest from a `uci-student` push. The owner may still tag an earlier beta.
- **Name:** `v<upstream x.y.z>-uci.1-beta.<n>`; today that is `v1.14.0-uci.1-beta.3` unless the upstream version moved with the sync.
- **Steps:**
  1. CHANGELOG `[Unreleased]` covers all user-visible changes, incl. the "v1 consolidation (breaking)" entry.
  2. CI green on the exact commit of `uci-student`.
  3. `git tag -a <tag> -m "<tag>: <summary> (beta)"`.
  4. `git push fork <tag>` (in the owner's clone `origin` is upstream; never push the tag there).
  5. Watch `selfhost-image.yml`; record the multi-arch index digest.
- **Result:** `ghcr.io/kkazuhak/canvas-mcp:<version>` and `:beta`; `:latest` unchanged (beta tag); it still points at the image of the stable tag `v1.13.0-uci.1` (section 8).
- **Fix while here:** the README release example uses `git push origin`; say `fork` (or "your fork remote").
- **Size:** S.

### 6.11 [OPS] Operator deployment guide

- **Goal:** a walkthrough for the owner's actual setup, linking to `deploy/selfhost/README.md` rather than duplicating it. Write it against v1 (after V1-DESIGN step 8).
- **Content:** host prerequisites; DNS and TLS (Caddy or nginx examples, `location ^~ /auth/` with the trailing slash); the simplified Entra app registration in the owner's tenant (V1-DESIGN 2.5: Web platform, one redirect URI `https://<host>/auth/callback/entra`, single tenant, app roles `Canvas.User`/`Canvas.Owner`, "Assignment required" on, admin consent once, no "Expose an API"); inviting friends as B2B guests and assigning `Canvas.User`; owner role `Canvas.Owner` or `SELFHOST_BOOTSTRAP_OWNER`; `setup-env.sh` (no school prompts); first start and `token_admin check`; sign-in names, featured schools and directory search in Admin > Settings or `token_admin providers|schools|settings`; backup/restore (database incl. settings + `CANVAS_TOKEN_KEYS`); upgrades (pin a version or digest; `docker compose pull`; migrations auto or `token_admin db upgrade`; v1 starts from a fresh database); offboarding ("disable in the panel first, then remove in Entra"); key rotation (`token_admin rotate`, `rotate-jwt-key`). Use the D11 neutral names.
- **Note:** `docker-compose.yml` pulls `:latest`. The README (~392-402) and `tests/test_selfhost_docs.py` (~418-424, which pins the wording "manifest unknown") say `:latest` does not exist until a stable tag, but the stable tag `v1.13.0-uci.1` was pushed on 2026-10-07 and its `Self-hosted image` run (id 37572192539) succeeded, so `:latest` very probably exists and holds that OLD image (commit `01ee7ec`, 2026-10-06, before accounts, multi-school and the React UI). The registry was not queried (needs `read:packages`); check it, then either fix the README/test wording or pin `:beta` or a version in the compose file.
- **Size:** M (later).

### 6.12 [LIVE] Live verification checklist

None of these has been done. They gate the first v1 tag (V1-DESIGN 2.4, step 8). Use a staging hostname; the README has a staging checklist (~487-510) that stays as an operator pre-flight, and the Stage A appendix has L1-L16. There is one MCP auth mode in v1, so each client is tested once against the built-in server.
- [ ] claude.ai web, Claude Desktop, Claude Code, and Claude mobile (required only if the docs are to claim phone support, 6.6.2); record in the tested-clients table (6.6.2).
- [ ] Refresh behaviour over several days (rotation, `REFRESH_ABSOLUTE_TTL`, grace window).
- [ ] CIMD fetch from the deployed host.
- [ ] Entra sign-in through `/auth/login` -> `/auth/callback/entra`; a B2B guest end to end, including a guest whose home account is in another school's tenant.
- [ ] Real Google, GitHub and OIDC IdPs (only if the owner lists them).
- [ ] Disable in the panel reaches MCP at the next request; then removal in Entra; `MAX_UPSTREAM_AUTH_AGE` (14 days) for role changes.
- [ ] Custody acknowledgement flow (6.4) on a real enrollment; directory search sends only the typed query to `canvas.instructure.com`.
- [ ] nginx and Caddy limits and log redaction (no tokens, codes, `state`, `txn` or secrets in access logs, including `/auth/*` callbacks).
- [ ] Docker smoke test is CI-only; on the server run `token_admin check` and `/healthz`.

### 6.13 [RES] Known residuals worth fixing (small, independent)

| Residual | Where | Suggested fix | Size |
|---|---|---|---|
| zh rate-limit strings mix two wordings | `web/src/locales/zh/*.json` (legacy `_bi` strings go in v1) | pick one wording | XS |
| audit detail values stay raw under zh | `AdminAuditView.tsx` | label known enum values via locale tables | S |
| expiry date input `min` uses the browser's day; server uses its own zone | `TokenForm.tsx` | send server "today" in `/me` or relax `min` by one day; server stays the authority | XS |
| React audit view lacks `identity_*` actions | `AdminAuditView.tsx` `KNOWN_ACTIONS` | add with locale labels (with V1-DESIGN 5.4) | XS |
| P6: out-of-process revoke/disable takes up to 30 s | `authz/grants.py` cache | resolved by v1 (per-request read, V1-DESIGN 4.5.1) | v1 |
| P6: real SSRF-pinned CIMD fetcher covered offline only by refusal tests | `authz/clients.py` | live test (6.12) | live |
| P6: replay within grace can return a sibling refresh token while a disable waits on the grant lock | `authz/grants.py` | harmless (grant revoked right after); leave documented | none |
| `auth_events` client address is always `unknown` | `TRUSTED_PROXY_CIDRS` is reserved | v1 drops the column; design trusted-proxy parsing first | M |
| DNS of a school checked only at enrollment | `schools.py` | accepted limit (the address guard runs on every Canvas call); document | none |
| PgBouncer transaction mode untested | README | keep "use a direct connection" (V1-DESIGN 4.10) | none |

---

## 7. Upstream workflow

### 7.1 Sending a small PR upstream

1. `git fetch origin && git worktree add .worktrees/up-<topic> -b fix/<topic> origin/main` (never from `uci-student`; no selfhost, web or PostgreSQL code).
2. One concern; minimal diff; regression test that fails before and passes after. Do not touch `tests/security/test_course_cache_isolation.py`.
3. Run what upstream CI runs: `ruff check src/ tests/`, `mypy src/` (CI runs it on Linux with no `--platform` flag; on Windows add `--platform linux` yourself to match), `pytest tests/ -q`.
4. PR body: `## What` / `## Why` / `## Tests` / `## Scope` (audits: summary, scope and method, findings per mode, fix, cost, what tests pin, out of scope, checks). State evidence and what was not verified; report test counts honestly, including unrelated failures. Reference "Part of the staged discussion in #484" or the relevant issue without a closing keyword. No attribution.
5. Fork-only features (multi-school, React UI, accounts, authz, v1) are not sent upstream.
6. No response: wait about two weeks, then one polite ping; never close a PR unilaterally (default).

### 7.2 Syncing upstream into the fork

1. `git fetch origin`; `git rev-list --count uci-student..origin/main` (7 at snapshot, before fetching).
2. On a clean `uci-student` (or a branch from it): `git merge origin/main -m "Merge upstream main (YYYY-MM-DD, <topic>) into uci-student"`. Real merge commits, no rebase.
3. Conflicts: take upstream as the base and re-apply fork hooks (principal-keyed course cache in `core/cache.py`, `tool_policy.py`, `untrusted_content.py` additions, role counts, docs). For big merges, record per-file decisions in the commit body (see `ab6450b`). Regenerate `uv.lock` with `uv lock` instead of hand-merging.
4. Recompute tool counts if the registry changed; full matrix; ruff, mypy, `uv lock --check`; `test_course_cache_isolation.py` identical to upstream.
5. `git push fork uci-student` (publishes `:edge`).
6. During v1, merge `uci-student` into `feature/v1-consolidation` after each sync rather than letting the branch drift.

### 7.3 What the maintainer expects (from #484, 2026-10-10, and #489, 2026-10-11)

- Keep the proposal in the fork; #484 is the upstream decision tracker.
- Testing with your own accounts does not authorize enrolling others. G1 (independent review) and G2 (institutional authority) remain prerequisites for any upstream pilot; no reviewer is appointed; no commitment to host or maintain the stack. Missing gates must not become "approved by silence".
- Before any pilot decision, review must cover pinned dependencies and running config, refresh races/reuse, SSRF defences, restore/revocation behaviour, log/secret handling.
- Welcomed: small isolation PRs (#490, #491). General log redaction separately, only if offered.
- #489 sets the bar for caller-boundary work: two callers, both orders, concurrency, credential changes, outgoing requests and side effects verified, request-local boundary, stdio and #480 preserved, independent of the fork's hosting stack (6.7).
- Pilot profile without `read_course_file` and `read_course_file_text`; off-Canvas hops not accepted by default in a pilot (6.6.1).
- Advertise only clients exercised; web + Claude Code + Desktop or mobile is reasonable initial evidence; mobile evidence before claiming phone support (6.6.2).
- The maintainer's triage executor (`internal/issue-triage/2026-10-11.md`, #492) independently verified #490 and #491 and listed both for the maintainer's review and merge decision.

### 7.4 Gates (as written in Stage A)

| Gate | State |
|---|---|
| G1 independent review | Not met; no reviewer |
| G2 institutional authority (Canvas institution's position, FERPA) | Not met |
| G3 pre-pilot OAuth fixes (appendix G.1) | Done |
| G4 request-local course state default | Done |

These gates were for an upstream-blessed pilot. The owner's deployment does not meet G1/G2; state that plainly, never as waived.

---

## 8. Release and deployment notes

Reference: `deploy/selfhost/README.md` (do not duplicate it).
- Tag format `v<x.y.z>-uci.<n>[-suffix]`, regex `^[0-9]+\.[0-9]+\.[0-9]+-uci\.[0-9]+(-[0-9A-Za-z.]+)?$` (enforced in the `meta` job). `x.y.z` = the upstream version synced (`pyproject.toml` 1.14.0).
- `selfhost-image.yml`: triggers on push to `uci-student` (paths-ignore for markdown/docs/tests/examples), tags `v*-uci.*` (always build), manual dispatch; no pull_request trigger; jobs only in `KKazuhaK/canvas-mcp`; only `GITHUB_TOKEN`. Jobs: `meta`; `build` (native amd64 + arm64, builds `Dockerfile.selfhost`, runs `deploy/selfhost/smoke-test.sh`, pushes by digest only after the smoke test); `publish` (multi-arch index, annotations, provenance attestation). Policy pinned by `tests/security/test_selfhost_workflow.py`; unchanged by v1 (the smoke test's content changes, V1-DESIGN 3.8).
- Image `ghcr.io/kkazuhak/canvas-mcp` channels: `:edge` every `uci-student` push; `:<version>` per tag; `:beta` every tag; `:latest` stable tags only (no suffix). The stable tag `v1.13.0-uci.1` exists and its image run succeeded (run 37572192539, 2026-10-07), so `:latest` very probably points at that old image (unverified: the registry was not queried); every other tag is a `-beta.N` pre-release. The deployment README and `test_selfhost_docs.py` still describe `:latest` as missing (stale; 6.11).
- Upgrade path: pin a version or digest; `docker compose pull && docker compose up -d`; migrations run per `DATABASE_AUTO_MIGRATE` or `token_admin db upgrade`; an older image refuses a too-new database, so roll back by restoring the backup, not by downgrading the image alone. v1 refuses any pre-v1 database (nothing is deployed, so start fresh). After v1, expand-only releases allow an application rollback without a restore (V1-DESIGN 4.12).
- `create-release.yml` fires on `v*` tags but its jobs require `vishalsachdev/canvas-mcp`, so nothing happens in the fork.

---

## 9. Reserved, not to build now

| Item | Reason | Revisit when |
|---|---|---|
| Canvas OAuth credential source (institutional Developer Key) | needs the school's cooperation; rejected for now (D13). v1 reserves `canvas_oauth_apps`, `canvas_credentials.kind='oauth'` and the routes `/auth/connect/canvas/{host}`, `/auth/callback/canvas/{host}` (not registered) | a school agrees to issue a Developer Key; this would be the policy-compliant path (section 10) |
| Redis state backend (`SELFHOST_STATE_BACKEND=redis` refused); more than one instance | single replica; v1 is multi-instance ready (V1-DESIGN 4.15) but runs one | more than one process or replica is needed |
| Passkey, SAML, captcha, notifier | no demand at this scale | an IdP or abuse case requires it |
| Account self-delete and export; account deletion from the owner panel | small trusted group; owner disables, user deletes token; v1 has operator `token_admin accounts delete` only | data-protection request or larger audience |
| Per-user quotas, per-account write ceiling, course allowlists | not needed for a trusted group; v1 reserves `account_quotas` | abuse or a write-enabled audience |
| Server-side web sessions | sealed cookie suffices; v1 reserves `web_sessions` | sessions must be listed or revoked individually |
| DB-stored provider configuration (P8 follow-up) | secrets would move into the DB; v1 stores display names only and reserves `login_providers.config`/`secret_*` | providers must change without restart |
| Per-language sign-in names | one name per method (D8) | the owner asks; an expand-step column |
| `ACCOUNT_LINK_BY_VERIFIED_EMAIL` | account-takeover risk | never by default; only with per-IdP e-mail verification guarantees |
| `TRUSTED_PROXY_CIDRS` | needs a careful forwarded-header design | client addresses are needed in `auth_events` |
| Health/metrics endpoints with DB and keyring self-test, `/readyz`, `token_admin backup` | backup documented in README | operations need monitoring |
| Icon choice per provider; storage-host allow-list with per-hop DNS/IP checks for downloads | not requested / needs reviewer sign-off on parsers | owner asks; or file reading must be re-enabled safely |

---

## 10. Policy and custody notes (factual)

- Instructure's Canvas OAuth documentation ("Manual Token Generation", checked 2026-10-10) says applications in use by multiple users must use OAuth to obtain tokens, and that asking other users to paste manually generated tokens violates the API Policy.
- The Instructure API Policy (effective 12 August 2025), section 3(i), lists using MCP servers not approved by Instructure as a prohibited use.
- This deployment asks users to paste personal access tokens into a server not approved by Instructure. The owner accepted this risk for a small trusted group of friends (2026-10-10). No approval from Instructure, any school, or the upstream maintainer exists or may be claimed.
- Custody: tokens are AES-256-GCM encrypted at rest, but the operator holds `CANVAS_TOKEN_KEYS` and can technically decrypt and use every token. Users should create tokens with an expiry and can revoke them in Canvas at any time. The model can disclose what it reads to the client provider. From v1, each enrollment requires an acknowledgement of this (D10, 6.4).
- G1 and G2 (section 7.4) are unmet.

---

## 11. References

Design documents:
- V1-DESIGN (`deploy/selfhost/V1-DESIGN.md`): the authoritative technical design for D2-D10.
- Older drafts, NOT in the repository (some are in Chinese; copy any decision you need into the repo in English): `<owner design notes, not shared>`
  - `identity-design-draft.md`: account model, admission, phases (sections G and H), reserved items.
  - `p6-plan.md`, `p6-spike-findings.md`, `p6-spike-research.json`: local authorization server.
  - `login-providers-research.md`: P7/P8.
  - `multi-school-goal.md`, `multi-school-plan.md`: multi-school (its env-based configuration is superseded by D6, D7).
  - `gateway-evaluation-draft.md`: gateway vs portal (English; to be copied, 6.8).

Commits:
- `71602e6` `uci-student` HEAD (merge upstream 2026-10-10); `ab6450b` merge upstream v1.14.0 (per-file resolution notes); `ef70fb4`, `ba9e2e3`, `83a8d6f`, `be810b2` earlier syncs.
- `51ed351` revocation as authorization; `d91e7ca` credential generation; `3cf72ad`, `4e27d1c` dependencies and custody; `5b89477` request-local course state default; `40d4b4e` codes bound to the session epoch.
- `f32b9d3` state described by Stage A; `d40a2e1` Stage A docs as posted.
- P7: `53b86dd` (HEAD, unreviewed fix round), `ae015d5`, `ac40be7`, `11575c5`, `c736e0d`.
- Upstream pending in the local `origin/main` ref: `d2de3af` (#486), `6111789` (#463), `4ec9dbb` (#453), `5cef947`, `615aa2e`, `156c58c`, `63f4222` (#492).

GitHub:
- Issue `vishalsachdev/canvas-mcp#484` (decision tracker; maintainer review 2026-10-10).
- Issue `vishalsachdev/canvas-mcp#489` (caller boundaries in HTTP caches; opened 2026-10-11).
- PRs `vishalsachdev/canvas-mcp#490`, `#491` (open); `#492` (upstream triage of 2026-10-11).
- Upstream #480 (HTTP boundary; source of `test_course_cache_isolation.py`), #236 (scoped Canvas developer-key OAuth), #470 (example of PR style).

In-repo documents: `deploy/selfhost/README.md`, `deploy/selfhost/env.example`, `web/README.md`, `CHANGELOG.md` `[Unreleased]`, `proposals/selfhost-pilot/`, `internal/` (upstream-focused), `CLAUDE.md` (upstream contributor rules).
