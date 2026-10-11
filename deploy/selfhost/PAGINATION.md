# Bounded list reads

The six browser lists and operator grant inventory use keyset pagination. The
API accepts `cursor` and `limit` (default 50, maximum 200), and always returns
`next_cursor`: a string for another page, or `null` at the end. No endpoint uses
OFFSET or silently truncates an unpaginated list.

| List | Route | Descending key |
|---|---|---|
| Accounts | `/api/v1/admin/accounts` | account UUID |
| Enrollments | `/api/v1/admin/enrollments` | credential UUID |
| Sign-in history | `/api/v1/me/login-history` | event integer ID |
| Audit | `/api/v1/admin/audit` | audit integer ID |
| Own connected apps | `/api/v1/me/grants` | grant UUID |
| Account connected apps | `/api/v1/admin/accounts/{id}/grants` | grant UUID |

Pass the returned cursor unchanged. Cursors bind the list, account and server
filter; changing `status`, enrollment `filter` or audit `account_id` starts a new
list without a cursor. Malformed/old cursors, duplicate query parameters and
limits outside 1-200 return `422 validation_failed`. `before` is removed.
Authorization is checked again on each page; a cursor never grants access.

Rows inserted above a cursor appear on a new traversal, and deleting its boundary
does not repeat or skip older surviving rows. Pages are independently read,
not a multi-request database snapshot. Account and enrollment totals are native
aggregates across the whole database, independent of the page and filter. Names,
identities and primary credentials are read only for the current page's IDs.

Enrollment rows represent stored credentials, including secondary credentials;
pending accounts without a credential appear in Accounts. Token actions are
offered only for the primary credential. The UI has Load more on every list.
Account-name search and audit-action filtering cover loaded rows; the screen
states that scope. Changing a server filter resets its pagination query.

Operator `accounts`, `list`, `identities`, `access` and `list-grants` walk bounded
pages, so inventories are not capped at 200/500/2000 records. `check` uses SQL
aggregates rather than loading every account or credential. Account targets are
canonical bare UUIDs; pre-v1 principal forms and the old `revoke` alias are gone.

`history [UUID] --limit N [--cursor CURSOR]` reads one bounded audit page. It prints
the next cursor to stderr separately from tab-separated records, and can read
retained history after the account was deleted. Encrypted tokens, codes and
hashes are never included in these operator records.
