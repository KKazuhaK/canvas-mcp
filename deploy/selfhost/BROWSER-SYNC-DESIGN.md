# Browser sync: Canvas data for schools without API tokens

Some schools do not let students create Canvas access tokens. Canvas's own web
pages still read `/api/v1` with the signed-in session, so a browser extension
can read the same JSON while the student is signed in to Canvas and push it to
the Portal. The Portal then answers the read-only student tools from that data.

This document is the contract between three parts: the Portal server
(`src/canvas_mcp/core/selfhost/`), the account UI (`web/`) and the extension
(`browser-extension/`).

## Decisions

- **Push snapshots, not a live proxy.** The extension fetches a server-defined
  plan of GET requests and uploads the raw Canvas JSON. A proxy would need the
  browser online for every tool call (useless from a phone) and would let the
  server issue arbitrary requests as the student.
- **The tools are unchanged.** `make_canvas_request()` and
  `fetch_all_paginated_results()` answer from stored snapshots when the request's
  data source is the browser binding. Writes are refused.
- **Cookies never leave the browser.** The extension has no `cookies`
  permission. It reads Canvas from a Canvas tab with same-origin `fetch`, and it
  uploads with `credentials: "omit"` and a bearer upload token.
- **A usable personal access token wins.** If the account has a valid token for
  the school, live API calls are used and snapshots are ignored.
- **Page parsing is detection only.** If session requests to `/api/v1` return
  401 or 403, the extension uploads that status and the Portal reports that the
  school blocks session API access. DOM parsing is out of scope until a real
  school needs it.
- **Not synced in this version:** conversations, file contents, group members,
  discussion entries written by other students.

Only users who reach the Portal through its own `/mcp` endpoint benefit, which
includes MCPHub connecting to the Portal with personal OAuth. MCPHub's stdio
mode with a per-user token slot does not use the Portal and is unaffected.

## Data model (migration `0007_browser_sync`)

`extension_bindings`
- `id` (uuid text, PK), `account_id` (FK accounts, cascade delete)
- `token_hash` (sha256 hex of the upload token, unique)
- `canvas_host` (nullable until the first upload), `canvas_user_id` (nullable)
- `created_at`, `last_upload_at`, `revoked_at`
- At most one non-revoked binding per account. Pairing again revokes the old
  binding and deletes its snapshots.

`extension_pairing_codes`
- `code_hash` (PK), `account_id`, `created_at`, `expires_at` (5 minutes),
  `claimed_at`. Single use.

`browser_snapshots`
- `binding_id` (FK, cascade), `resource_key` (text), `captured_at`,
  `canvas_status` (int), `key_id`, `nonce`, `ciphertext`
- PK `(binding_id, resource_key)`. `resource_key` is the canonical form of
  `path` plus the sorted `query` **without the date window** (`start_date`,
  `end_date`): the window moves every day, and the newest upload of a resource
  replaces the previous one. The window is part of the sealed envelope, so
  matching still sees it.
- The sealed plaintext is `{"path", "query" (including the window), "body"}`,
  sealed with the existing token keyring (AES-256-GCM). The AAD follows the
  registry layout of every sealed column:
  `canvas-mcp/browser-snapshot/v1 \x1f binding_id \x1f resource_key \x1f key_id`,
  so key rotation (`token_admin`, `db/sealed.py`) re-seals snapshots like any
  other secret, and a row moved to another binding or key does not decrypt.
- `extension_bindings` and `browser_snapshots` are `durable`; all three tables
  cascade with the account and have maintenance jobs (below). The migration is
  an expand revision (it does not raise the compatibility floor).

## HTTP API

All bodies are JSON. Timestamps are ISO 8601 UTC.

Extension endpoints (`/api/v1/extension/*`):
- A request whose `Origin` is present must carry an extension origin
  (`chrome-extension://[a-p]{32}` or `moz-extension://<uuid>`); any other value,
  including `null` and the Portal's own origin, gets 403 `origin_not_allowed`
  without CORS headers. This is what keeps web pages out: browsers always send
  `Origin` on cross-origin fetches. A request with **no** `Origin` is accepted
  (without CORS headers), because Chrome does not send one on GETs made from an
  extension service worker that holds host permission for the target. Origin is
  not authentication either way: the bearer token or pairing code, the cookie
  refusal and the rate limits still apply. A preflight (`OPTIONS`) always needs
  an extension origin.
  A request that carries a `Cookie` header is refused with 400
  `cookies_not_allowed` (also on the preflight). CORS answers only extension
  origins, methods `GET, POST, DELETE`, headers `Authorization, Content-Type`,
  `Max-Age 600`, never credentials. The server's Host/Origin guard
  (`allowed_origins`) lets `chrome-extension://*` and `moz-extension://*` through
  so the endpoints can apply the exact check above; `/mcp` still needs an OAuth
  bearer token.
- Rate limits (429 `rate_limited`, `Retry-After`). The Portal sees only the
  proxy's address (`proxy_headers` is off), so no limit is per client address:
  an address key would be one key for everybody, and a loop of anonymous
  requests would lock every user out. Instead:
  - `/capabilities` is static and never limited.
  - Token endpoints (`plan`, `snapshots`, `binding`) do the hash lookup first. A
    valid token counts against its binding (120 requests/minute) and an
    authenticated-only process-wide ceiling (3000/minute). An unknown or revoked
    token counts only in a separate failure bucket (600/minute), which turns
    further failures into 429 and never touches valid requests.
  - `/claim` looks the code up first. A valid unexpired code is never limited: its
    about 60 bits and 5 minutes are the protection. Only failed claims count, in
    their own bucket (600 per 10 minutes).
    The lookup is a read-only indexed query, so a junk code never takes the write
    lock or opens a write transaction (on SQLite that would serialise every
    writer); the write transaction opens only for a live code, and its conditional
    UPDATE settles races. It costs what any public endpoint costs; per-client
    throttling belongs in the proxy.
  Real per-client limiting belongs in the reverse proxy.
- Body limit 4 MiB (413 `payload_too_large`, checked on `Content-Length` and while
  streaming).
- Errors are `{"error": "<code>"}` with codes `invalid_request` (400),
  `invalid_code` (400), `unsupported_schema` (400), `invalid_token` (401),
  `origin_not_allowed` (403), `method_not_allowed` (405), `canvas_mismatch` (409),
  `plan_outdated` (409), `payload_too_large` (413), `quota_exceeded` (413),
  `unsupported_media_type`
  (415), `rate_limited` (429), `unavailable` (503).

| Method and path | Auth | Request | Response |
| --- | --- | --- | --- |
| `GET /api/v1/extension/capabilities` | none | | `{"browserSync": 1, "maxBodyBytes": 4194304}` |
| `POST /api/v1/extension/claim` | none | `{"code": "<pairing code>"}` | `{"uploadToken": "...", "bindingId": "..."}`; 400 `invalid_code` for unknown, expired or used |
| `GET /api/v1/extension/plan` | `Bearer <uploadToken>` | | plan (below) |
| `POST /api/v1/extension/snapshots` | `Bearer <uploadToken>` | upload (below) | `{"accepted": n, "rejected": [{"path": ..., "reason": ...}]}` |
| `DELETE /api/v1/extension/binding` | `Bearer <uploadToken>` | | 204; revokes and deletes snapshots |

The pairing code is 12 characters from an alphabet without look-alikes, shown as
`ABCD-EFGH-JKLM`; it is accepted in any case and with or without separators.
It is stored as a hash, valid for 5 minutes, spent by one conditional update, and
a new code for the same account replaces its unclaimed ones. A successful claim
revokes the account's previous binding and deletes its snapshots. A code of an
account that is no longer active is spent and refused.

401 `{"error": "invalid_token"}` for an unknown or revoked token tells the
extension to pair again.

Account endpoints (signed-in session, mutations need `X-CSRF-Token` and the
usual `Origin` check):

| Method and path | Response |
| --- | --- |
| `POST /api/v1/me/extension/pairing` | `{"code": "...", "expiresAt": "..."}` |
| `GET /api/v1/me/extension` | `{"binding": null}` or `{"binding": {"createdAt", "lastUploadAt", "canvasHost", "resources": [{"path", "capturedAt", "canvasStatus"}], "active": bool, "reason": null or "token_preferred" or "school_unknown"}}` |
| `DELETE /api/v1/me/extension` | 204; revokes and deletes snapshots |

`reason` is `token_preferred` when the account has a usable token (stored, not
marked invalid), and `school_unknown` when the binding has no Canvas host yet,
its host is not a school the server offers, or it differs from the school of the
account's (unusable) token. Pairing is limited to 10 codes per 10 minutes per
account.

## Pairing

1. The popup takes the Portal origin (HTTPS, no path; `http://localhost` and
   `http://127.0.0.1` allowed for development), checks
   `GET /api/v1/extension/capabilities`, generates a random `state` and opens
   `<portal>/account/browser-extension#extension-auth=<state>`.
2. The page requires sign-in, calls `POST /api/v1/me/extension/pairing` and
   renders `<div id="canvas-extension-authorization" data-state="<state>"
   data-code="<code>" hidden>`. It also shows the code for manual entry.
3. The extension injects its link script only into that tab, reads the element,
   and the background checks the sender tab, origin, path and state before it
   calls `POST /api/v1/extension/claim` with `credentials: "omit"`.
4. The upload token is 32 random bytes, base64url. It only works on
   `/api/v1/extension/*`; it is not an MCP or account credential.

## Plan

```json
{
  "planVersion": 1,
  "canvasHost": "canvas.example.edu",
  "maxPages": 50,
  "resources": [
    {"path": "/users/self", "query": {}},
    {"path": "/courses", "query": {"include[]": ["term", "total_scores"], "enrollment_state": "active"}, "paginate": true},
    {"path": "/courses/{course_id}/assignments", "query": {"include[]": ["submission"]}, "paginate": true, "perCourse": true}
  ]
}
```

- `path` is relative to `/api/v1`. `canvasHost` is null until the first upload
  sets it, and it is then fixed for the binding.
- `perCourse: true` expands `{course_id}` for every course id returned by
  `/courses` in the same run, in the path and in every query value (for example
  `context_codes[]=course_{course_id}` on `/announcements`). The placeholder
  must appear in at least one of them, and a brace left after expansion is a
  rejection. `{user_id}` is filled by the server, so personal-calendar
  resources appear in the plan only after the first upload.
- Dates are concrete (the server computes the window, about 60 days back and
  120 days ahead).
- The server derives the resources from what the student read tools request.
  A test (`tests/selfhost/test_browser_sync_coverage.py`) runs every student
  read tool against snapshots built from the plan and fails on any miss; each
  read tool is either covered or listed there as a known gap.
- The resources (`selfhost/browser_plan.py`): `/users/self`, `/users/self/profile`,
  `/users/self/todo`, `/users/self/groups`, `/users/self/activity_stream` and
  `.../summary` (`only_active_courses=true`); four `/courses` lists (bare,
  `enrollment_state=active`, plus `state[]=available`, and the `term`-only list
  with `state[]=available,unpublished`), all with the include superset the tools
  ask for; `/planner/items` (window), `/planner/items?filter=incomplete_items`,
  `/planner_notes` (window); per course: `assignments`
  (`include[]=all_dates,checkpoints,submission`), `assignment_groups`
  (`assignments,submission`), `quizzes`, `modules` (`include[]=items`),
  `front_page`, `discussion_topics` and `discussion_topics?only_announcements=true`,
  `/announcements` (that course, `active_only`, window) and `/calendar_events`
  for `type=event` and `type=assignment` (that course, window,
  `excludes[]=child_events`). Once the first upload has told the server the
  student's id, the same two calendar resources are added for `user_<id>`.
- The window is `[today 00:00Z - 60 days, today 00:00Z + 120 days]`.
- Not in the plan, because the extension's allowlist cannot carry them: pages,
  module items, quiz submissions and permissions, group members and files,
  conversations and the address book, planner overrides, group calendars,
  discussion entries, submissions, grading standards. The affected tools fail
  with `SOURCE_UNAVAILABLE` ("not synced by the browser extension yet").

The extension enforces its own allowlist regardless of the plan: GET only,
path matches `^/(users/self(/(profile|todo|groups|activity_stream(/summary)?))?|courses(/\d+(/(assignments|assignment_groups|modules|quizzes|front_page|discussion_topics))?)?|planner/items|planner_notes|calendar_events|announcements)$`
after `{course_id}` expansion, and only on the user's Canvas origin.

## Upload

```json
{
  "schemaVersion": 1,
  "canvasOrigin": "https://canvas.example.edu",
  "canvasUserId": 123,
  "capturedAt": "2026-11-01T12:00:00Z",
  "planVersion": 1,
  "resources": [
    {"path": "/courses/123/assignments", "query": {"include[]": ["submission"]}, "status": 200, "body": []}
  ]
}
```

- `body` is the full JSON after stripping the `while(1);` prefix and merging
  all pages. A non-200 `status` is stored with a null body.
- The server rejects the whole upload (409 `canvas_mismatch`) when
  `canvasOrigin` is not a plain HTTPS origin (scheme and host only, no port or
  path) of a school in the directory,
  differs from the binding's `canvas_host`, or `canvasUserId` differs from the
  binding's stored id. The first upload pins both, in the same transaction that
  stores the rows. 400 `unsupported_schema` for another `schemaVersion`, 409
  `plan_outdated` for another `planVersion`, 400 `invalid_request` for a
  malformed header or a `capturedAt` before 2020 or more than five minutes ahead.
- A resource is rejected (listed in `rejected` with a `reason`; the rest of the
  upload is kept) when:
  `not_in_plan` (after `{course_id}` expansion; course ids come from `/courses`
  snapshots, including one in the same upload, and only a course list the plan
  asked for counts), `invalid_resource` (path outside the extension allowlist,
  malformed query, status outside 100-599, a 200 body that is not a list or
  object, a missing, reversed or longer than 400 day window, or a window on a
  resource the plan does not date), `duplicate_in_upload`, or
  `older_than_stored` (the stored copy of that resource was captured later; an
  equal time replaces).
- A non-200 `status` is stored with no body. A transient 408/429/5xx during a sync must not erase good
  data. Only transient results (408, 429, any 5xx) are kept out: the resource is
  rejected with `kept_stored_data` and the old copy keeps serving with its age
  note. 401, 403, 404 and other 4xx are answers (access lost, content deleted)
  and replace the old copy. "This school blocks session access" is only
  said when a 401/403 is all there is.
- Limits per binding (constants in `browser_plan.py` and `browser_store.py`, not
  settings): at most 200 distinct course ids, not counting the course lists the upload really replaces (newer, and not a transient failure kept out) so a new term can roll over (a `/courses` list that would exceed
  it, or is longer than 1000 entries, is rejected with `too_many_courses` before
  the plan is expanded, and so is everything depending on it), at most 3000
  stored snapshot rows and 64 MiB of sealed bytes. An upload that would go over
  the row or byte quota is refused whole with 413 `quota_exceeded`; replacing
  rows already held only counts the difference. Plan expansion and validation run
  off the event loop.
- The extension splits uploads to stay under `maxBodyBytes`; an upload has at
  most 600 resources.

## Answering tool requests

Request credentials gain a source: a token, or a browser binding. With a
binding:

- Only `api_root="rest"` GET requests are answered. Anything else returns
  `{"error": ...}` with code `PERMISSION_DENIED` ("browser sync is read-only")
  or `SOURCE_UNAVAILABLE`. File downloads (`canvas_authenticated_client`) are
  refused too: browser mode has no Canvas credential and never opens a
  connection to Canvas.
- Match: snapshots with the same path. Incoming `per_page` and `page` are
  ignored; incoming `include[]` must be a subset of the stored `include[]`;
  every other parameter must equal the stored value (a parameter on only one
  side is a miss), except:
  - `start_date` and `end_date` need a stored window that covers the asked one
    (a request without a window, or a stored copy without one, does not match);
    items are then filtered locally by `plannable_date` (`/planner/items`),
    `start_at`/`end_at` overlap (`/calendar_events`), `posted_at`
    (`/announcements`) or `todo_date` (`/planner_notes`). Date-only bounds are
    read as days in the student's Canvas time zone (Canvas applies
    `beginning_of_day`/`end_of_day` there), the end covering its whole day. The
    zone is `time_zone` of the stored `/users/self/profile` snapshot, else the
    server's `TIMEZONE`; with neither, a date-only bound is a miss. Bounds with
    an offset need no zone.
  - `context_codes[]` is answered from the union of stored copies, one per
    context, and every code asked for must be covered by one (otherwise a miss).
    `/planner/items` and `/planner_notes` stored without codes cover any code.
    Items are filtered by `context_code`, `course_id` or `group_id`.
  - `type`: equal to the stored `type`, or filtered locally when the stored copy
    has none.
  - `excludes[]`: what the stored copy left out must be a subset of what is
    asked; extra excluded fields are removed locally. `child_events` (other
    students' appointment reservations) is never stored and always treated as
    excluded.
  - `all_dates` is ignored when the stored `include[]` has `all_dates`.
  No match returns `SOURCE_UNAVAILABLE` "not synced by the browser extension
  yet".
- A stored non-200 status returns `SOURCE_UNAVAILABLE` naming the Canvas status
  ("this school blocks session access to the Canvas API").
- A single-object path whose last segment is a numeric id (for example
  `/courses/1/assignments/9`, `/courses/1`, `/calendar_events/5`) is answered
  from the stored list at the parent path by `id` when no exact snapshot exists.
  Window, context and type are ignored for this lookup (they narrow lists);
  `include[]` must still be covered. An id that is not in the list is a
  `SOURCE_UNAVAILABLE` miss ("not found in the synced data").
- Paginated reads return the whole stored list with no next link.
- Anonymization runs exactly as for live responses.
- Freshness: the oldest `captured_at` used in a tool call is reported. The tool
  result gains a final text block "Data synced from your browser N minutes ago."
  (only on success, only when browser data was used). Over 12 hours it adds "It
  may be out of date; open Canvas in the browser to refresh it." Over 14 days the
  snapshot is not used (`SOURCE_UNAVAILABLE`, "more than 14 days old"). Snapshots
  older than 30 days are deleted by the maintenance loop (jobs
  `browser_snapshots`, `extension_codes` for spent or expired codes, and
  `revoked_bindings` after the same age). The thresholds are operator settings
  (`token_admin settings set`): `browser_sync.fresh_hours` (12),
  `browser_sync.max_age_days` (14), `browser_sync.purge_days` (30).

## How a request chooses browser mode

`SelfhostRequestContextMiddleware` publishes a `BrowserSource` (and no
`RequestCredentials`) when the account has no usable token for its school and an
active binding whose `canvas_host` is a school the server offers and equals the
school of the account's unusable token, if it has one. "No usable token" means
no primary credential, or one marked invalid. A usable token always wins, and
snapshots are then ignored. A request has a token or a browser source, never
both (`set_request_credentials` and `set_browser_source` exclude each other).
Anything cached per principal is keyed with the binding, so nothing learned under
a token is served from browser data or the other way round.

## Sync triggers (extension)

- A Canvas tab finishes loading and the last sync is more than 10 minutes old.
- A 60-minute alarm: try a service worker `fetch` with
  `credentials: "include"`; if Canvas answers 401 or a login redirect, wait for
  the next page visit instead. Never open background tabs.
- The popup's "Sync now".

## Permissions

`storage`, `alarms`, `scripting`, `activeTab`; `optional_host_permissions` for
any HTTPS host plus plain HTTP on `localhost` and `127.0.0.1` (development). The
popup asks only for the user's Canvas origin and Portal origin.
