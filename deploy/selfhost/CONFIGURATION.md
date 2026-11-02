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
