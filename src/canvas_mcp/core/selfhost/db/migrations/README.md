# Isolated database upgrade tooling

`0004_onboarding_and_icons` adds nullable provider PNG presentation and assigns
unique system names only to previously unnamed accounts. Account ids, existing
UPNs, roles, passwords and sessions remain unchanged. Revisions 0001-0003 stay
frozen, and the compatibility floor remains 2. No temporary account-name
backfill lives in the runtime.

Keep all schema upgrade, migration, backup and database transfer code in this
package. Application repositories and the normal connection pool must not
contain DDL upgrades, legacy data adapters or foreign-key-off connections.

`0001_v1_baseline` remains the frozen nineteen-table baseline.
`0002_local_credentials` is an additive twentieth table for salted password
hashes. Automatic upgrade preserves existing accounts, sealed provider/Canvas
credentials and the database identity. Existing installations do not gain a
default password or reopen first-install setup.

`0003_account_login_policy` is the contract revision for account-level UPN,
provider-instance association flags and generic issuer/subject ownership. It
removes the redundant local username after preserving it as the account UPN,
adds the account policy and allowlist tables, and raises compatibility floor to
2. SQLite takes the existing automatic contract backup; PostgreSQL upgrades in
one transaction. An older image requires restoring its matching database backup.
Historical subjects owned by different accounts refuse the upgrade without
merging or overwriting either account. This data-dependent backfill requires an
online migration connection; offline SQL rendering remains available for the
frozen baseline and additive local-credential revision, not for this contract.

The two-file container deployment saves its automatically generated encryption
and session keys in `/data/runtime-secrets.json`. Back up and restore this private
file together with the database. A SQL-only backup does not include it. Keep any
explicit key overrides in `.env` as well; a missing key file on an existing
database is refused rather than silently generating a different identity.

- `runner.py`: schema compatibility checks, upgrade execution and SQLite backup.
- `connections.py`: dedicated migration transactions and PostgreSQL migration
  lock connections; these never enter the request pool.
- `cli.py`: registration and execution of the operator's `db` commands.
- `baseline_v1.py`, `baselines/`, `versions/`, `env.py`, `script.py.mako`:
  frozen Alembic revision graph and shipped DDL.
- `transfer.py`: SQLite-to-PostgreSQL import and the silent-switch guard.
- `provider_environment.py`: explicit adoption of old provider configuration,
  exposed by `token_admin login-providers --import-env`; the CLI imports this
  adapter lazily only when the operator requests adoption. It also contains
  guarded removal of an old beta's entirely empty startup metadata and the
  legacy environment owner-inventory checks. Native DB-owned registrations
  exclude those old environment checks entirely.
- `site_environment.py`: one-time adoption of the previous environment-owned
  public origin; subsequent edits use the normal governed configuration path.
  Retain the stored setting when removing this adapter.
  Adoption is atomic and never replaces database-owned values.
- `legacy_setup_env.sh`: legacy environment export for deliberate adoption.
  New installations never use this helper or generate keys manually.
- `policy.py`: forward revision flags, SQLite rebuild invariants and PostgreSQL
  concurrent-index recovery. This is upgrade tooling, not a runtime repository.

Pre-v1 adapters are deleted. Import snapshots a v1 source and upgrades only the
private copy; every target table, count and sealed value is handled in one
transaction. Table lifecycle metadata determines what is copied.

Runtime entry points delegate here lazily. Do not add compatibility modules at
the previous file locations. If upgrades are retired later, replace those
delegations with a schema-state check, then remove this package and its dedicated
migration tests together. Keep `db/schema.py`, ordinary engines, portable types
and application repositories: they define current runtime persistence.

The only bridges outside this package are `app.py` (dependency, silent-switch
checks and explicit provider-input adoption), `token_store.py` (startup readiness), and `token_admin.py` (CLI
registration/execution and the operator silent-switch check). Boundary tests
reject new callers, metadata DDL and direct Alembic use elsewhere.
They also reject database backup calls and foreign-key-off SQL outside this
package. New upgrade or compatibility behavior belongs here; current request
handlers accept only the native v1 format and do not adopt old data or cookies.

## Later revisions

The production graph retains its frozen v1 baseline. Tests build temporary
future revision graphs against seeded current databases. Every later revision declares boolean `CONTRACT` and
`NON_TRANSACTIONAL` flags (both default false).

Expand revisions leave `server_state.compat_floor` unchanged. Contract revisions
raise it only after a release stopped reading the contracted shape.
The runner checks each revision before its version transaction commits:
expand revisions must preserve the floor, contract revisions must raise it,
and no revision can set a floor above this build's schema epoch. A failed check
rolls back ordinary DDL and the revision marker. Already committed concurrent
DDL still requires the documented retry/recovery procedure.

SQLite
automatically takes an exclusive-created `*.pre-<revision>-<time>.bak` snapshot
before a pending contract plan, under the write gate; `--backup PATH` chooses
the backup name. Sources are opened read-only with SQLite's backup API. A failed
upgrade rolls back its changes and retains the backup. Dry runs do not create
backups; fresh database creation needs no contract backup.

Use `policy.rebuild_sqlite_table()` for SQLite contract rebuilds. Its dedicated
connection has foreign keys off, validates `foreign_key_check` before commit and
never enters the request pool. The helper preserves STRICT, WITHOUT ROWID,
AUTOINCREMENT and the sequence high-water mark, including previously deleted
history IDs. Batch reflection preserves named CHECKs and partial indexes;
revisions must explicitly remove checks/indexes that refer to a dropped column.

On PostgreSQL, populated-table indexes declare `NON_TRANSACTIONAL = True` and
use `policy.concurrent_index()` (or an explicitly reviewed Alembic autocommit
block). Alembic uses one short transaction per revision; the migration session
lock stays held on a separate connection throughout. DDL connections use
NullPool and the application's search path. Failure can leave an INVALID index;
the helper drops it concurrently and retries. It can also recognize an already
completed ordinary index after a failed version update. Existing partial or
mismatched indexes require explicit revision validation, since PostgreSQL
rewrites predicates and comparing raw SQL would be unsound.

Nontransactional plans refuse `--dry-run` and atomic import before any revision
runs. Ordinary upgrades/imports still commit or roll back as one unit. In a
nontransactional plan, completed earlier revisions remain committed on failure;
repair the cause and rerun rather than implying the whole plan was rolled back.
No upgrade re-encrypts stored secrets and no downgrade is supported.

## Moving from a pre-v1 deployment

Start a fresh v1 database, re-enroll Canvas credentials and reconnect clients.
Pre-v1 database files are refused; this package does not convert them. Keep the
old database and its matching keyring for recovery with the old image.

| Former setting | v1 action |
| --- | --- |
| `MCP_AUTH_MODE=entra-oauth` | Use `MCP_AUTH_MODE=selfhost` |
| `ENTRA_API_SCOPE` | Use `MCP_SCOPE`, default `Canvas.Access` |
| `SELFHOST_AUTH_MODE` | Delete; the built-in authorization server is always used |
| `ACCOUNT_UI` | Delete; the built React account UI is required |
| `OAUTH_JWT_SIGNING_KEY` | Delete; JWT keys derive from `CANVAS_TOKEN_KEYS` |
| `GRANT_STATUS_CACHE_S` | Delete; committed authorization state is read per request |
| `CANVAS_API_URL` | Delete in selfhost mode; each account selects a school |
| `CANVAS_FEATURED_SCHOOLS`, `CANVAS_SCHOOL_SEARCH` | Delete; configure schools/search in Admin > Settings or `token_admin` |
| `OIDC_<SLUG>_DISPLAY_NAME` | Delete; configure the public sign-in name in Admin > Settings or `token_admin providers` |

These removals apply to selfhost mode; the separate legacy stdio/Canvas-token
HTTP configurations retain their own contract. Do not copy old switches or
environment-owned school defaults into the v1 environment template.

## Operator commands

Run these with the server's database and matching `CANVAS_TOKEN_KEYS`. The
commands live in this package and are lazily registered by `token_admin`.

```sh
python -m canvas_mcp.core.selfhost.token_admin db current
python -m canvas_mcp.core.selfhost.token_admin db upgrade --dry-run
python -m canvas_mcp.core.selfhost.token_admin db upgrade
# SQLite: choose a new private backup file in an existing protected directory.
python -m canvas_mcp.core.selfhost.token_admin db upgrade --backup /data/backups/pre-upgrade.sqlite3
```

`db current` returns 0 for a compatible database, 4 for an empty or behind
schema and 2 for an unusable state. A compatible newer expand schema is served
without upgrading its unknown revision. A raised compatibility floor refuses
older application code. Set `DATABASE_AUTO_MIGRATE=false` when upgrades must be
performed separately before starting the service. No pre-v1 import or downgrade
is offered. Keep backups with the keyring that encrypted their data.

For an enrolled **v1** SQLite-to-PostgreSQL transfer, stop the service, back up
SQLite and its keyring, configure `POSTGRES_PASSWORD` and `DATABASE_URL`, then
start only the empty PostgreSQL target. Do not start the app on that target
before import. From `deploy/selfhost`, with the reviewed v1 image selected:

```sh
docker compose stop canvas-mcp
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d postgres
docker compose -f docker-compose.yml -f docker-compose.postgres.yml run --rm --no-deps \
  canvas-mcp python -m canvas_mcp.core.selfhost.token_admin db import-sqlite /data/canvas-mcp/tokens.sqlite3
docker compose -f docker-compose.yml -f docker-compose.postgres.yml run --rm --no-deps \
  canvas-mcp python -m canvas_mcp.core.selfhost.token_admin check
docker compose -f docker-compose.yml -f docker-compose.postgres.yml up -d
```

The source in the existing `canvas-mcp-data` volume is not modified. Import
snapshots it read-only, validates/upgrades only a private copy, requires the
empty target, verifies every copied seal/count/FK and commits durable tables
atomically. Reserved provider/OAuth-app secrets are included. Ephemeral protocol
state is omitted. The target keeps its own database ID, and imported account
epochs/configuration revision are raised: users reconnect their MCP apps and
browser sessions. A failed import leaves the target unchanged. Preserve the
source and its backup until the new deployment passes validation.

For PostgreSQL database backups, use your protected `pg_dump`/restore workflow
and verify a restore with the matching keyring. `--backup` is SQLite-only. Do not
copy a live SQLite file without its WAL; use the SQLite backup API or stop all
writers first. Future flagged nontransactional PostgreSQL revisions require
operator-reviewed recovery rather than claiming a failed run rolled everything
back.
