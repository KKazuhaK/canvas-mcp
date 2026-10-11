# Runtime maintenance and account deletion

Runtime housekeeping is implemented in `selfhost/maintenance.py`. It makes no
schema changes. All creation, upgrade, transfer and compatibility policy remains
in the separately removable `selfhost/db/migrations/` package.

OAuth traffic schedules a background pass at most hourly in each process. A long
pass cannot overlap the next pass. Each job runs short independent transactions,
with a per-job budget of two seconds on SQLite or ten seconds on PostgreSQL.
SQLite yields for 50 ms between chunks. PostgreSQL uses a distinct transaction
advisory try-lock for each job and `FOR UPDATE SKIP LOCKED` for candidate rows.
Busy jobs retry at the next scheduled pass.

Candidates are selected with an explicit limit and ordering, then deleted by
their primary keys in the same transaction. The delete repeats the due predicate.
Plain-row chunks contain at most 500 rows on SQLite or 2,000 on PostgreSQL;
grant chunks contain at most 200 rows on either database.

| Records | Retention |
| --- | --- |
| Login states | Until expiry |
| Authorization code tombstones | One hour after expiry |
| Revoked or expired grants | 30 days; refresh tokens leave by cascade |
| DCR clients | Until their extended expiry |
| CIMD snapshots | Configured stale window plus one day |
| Sign-in history | `retention.auth_events_days`, default 90 |
| Audit history | `retention.audit_days`, default 0: keep forever |
| Pending accounts | 30 days, at most 100 accounts per run |
| Orphan schools | One day; only unfeatured, public schools without credentials or OAuth apps |

History jobs walk the primary key. An earlier record with a timestamp in the
future is skipped without prematurely stopping a chunk whose last record is due.
Pending deletion takes the governance transaction, deletes authorization codes
before accounts, and writes one `pending_purged` audit entry per deleted account.
Other maintenance jobs do not take the global governance lock. A database or
integrity failure rolls back the current chunk and ends that job for the pass;
logs contain only a fixed message and job name.

An enrollment upserts its school with `DO UPDATE SET updated_at`, locking the
parent before inserting a credential. School maintenance skips a parent already
locked by an enrollment. An enrollment that follows deletion creates a fresh
parent. The school delete repeats both reference checks.

After more than 1,000 top-level rows are deleted, SQLite runs incremental vacuum
for up to 2,000 pages. It runs `PRAGMA optimize` at most once daily per process.

## Operator account deletion

Use the canonical bare account UUID printed by the account list:

```sh
python -m canvas_mcp.core.selfhost.token_admin accounts delete ACCOUNT_UUID
```

Deletion is operator-only. It refuses deletion of the last usable owner or last
active owner. Authorization codes are deleted before locking the account; account
children, grants and refresh families then leave by cascade. Existing sign-in and
audit history is retained. A new `account_deleted` audit entry records the UUID
and counts of removed credentials, identities and grants, without names or secrets.
Deletion and its audit entry commit together. Exit codes are 0 for deletion,
1 for a missing account, 2 for an invalid UUID/configuration, and 3 for owner
protection. This command permanently removes bindings; credential-only deletion
remains a separate operation.

`tests/selfhost/test_v1_maintenance.py` covers bounds, due rechecks, history skew,
retention, rollback and CLI behavior. `tests/selfhost/test_v1_races.py` pins both
orders of first code exchange versus deletion/disablement/revocation, and school
culling versus enrollment on PostgreSQL.
