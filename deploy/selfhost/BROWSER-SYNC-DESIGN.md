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
- **Not synced in this version:** the Inbox and discussion entry endpoints,
  file contents, group members. The activity stream still carries Inbox
  previews, other people's discussion posts and comments, and notifications,
  and discussion topics carry their authors' text; `browser-extension/PRIVACY.md`
  says so.

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
  so the endpoints can apply the exact check above. The outer edge guard
  (`SelfhostEdgeGuard`) refuses those origins with 403 on every path outside
  `/api/v1/extension/`, so `/mcp`, OAuth and the account API never see them.
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
| `GET /api/v1/me/extension` | `{"binding": null}` or `{"binding": {"createdAt", "lastUploadAt", "canvasHost", "resources": [{"path", "capturedAt", "canvasStatus"}], "active": bool, "reason": null or "token_preferred" or "school_unknown" or "user_mismatch"}}` |
| `DELETE /api/v1/me/extension` | 204; revokes and deletes snapshots |

`reason` is `token_preferred` when the account has a usable token (stored, not
marked invalid), and `school_unknown` when the binding has no Canvas host yet,
its host is not a school the server offers, or it differs from the school of the
account's (unusable) token. It is `user_mismatch` when that token names a Canvas
user and the binding is pinned to a different one: switching the account to
another Canvas user goes through the token's identity-change confirmation, so a
browser signed in as someone else is never served in its place. The binding
stays pinned to its first user, so this clears only when the token is replaced
or removed, or the extension is disconnected and paired again while signed in to
Canvas as the token's user. Pairing is limited to 10 codes per 10 minutes per
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

Plan version 2 (the extension still accepts version 1; an upload may carry
`planVersion` 1 or 2). A sync is light: a few aggregate requests per visit, with
per-course content refreshed at most every 12 hours.

```json
{
  "planVersion": 2,
  "canvasHost": "canvas.example.edu",
  "maxPages": 50,
  "coldIntervalHours": 12,
  "resources": [
    {"path": "/users/self", "query": {}, "tier": "hot"},
    {"path": "/courses", "query": {"include[]": ["term", "total_scores"], "enrollment_state": "active"}, "paginate": true, "tier": "hot", "courseSource": true},
    {"path": "/announcements", "query": {"context_codes[]": ["course_{course_id}"], "active_only": "true", "start_date": "2026-09-01T00:00:00Z", "end_date": "2027-03-01T00:00:00Z"}, "paginate": true, "tier": "hot", "expand": "courseList", "chunk": 10},
    {"path": "/courses/{course_id}/assignments", "query": {"include[]": ["submission"]}, "paginate": true, "tier": "cold", "expand": "eachCourse"}
  ]
}
```

- `path` is relative to `/api/v1`. `canvasHost` is null until the first upload
  sets it, and it is then fixed for the binding.
- **`tier`**: `hot` resources are fetched on every sync. `cold` ones only when the
  extension's last successful fetch of that expanded key is older than
  `coldIntervalHours` (12), or has never happened. A "fetch" here is the last
  attempt that should not be repeated at once: a response the portal stored, kept
  older data for, or rejected (its checks give the same answer on a retry), and a
  response that could not be read (too many pages, a failed page, bad JSON) or was
  too large to upload. Only network errors, Canvas throttling and a lost session
  leave no time, so they retry on the next run. Without this, such a key would
  rank first for the cold budget on every run and starve the rest. Keys sort their
  query parameters, so a key from the plan and one from an upload always match.
- **`refreshMinutes`** (optional, hot resources only): the extension refetches the
  resource only when its last successful fetch is older than this many minutes;
  without it a hot resource is fetched on every sync. Set on
  `/users/self/activity_stream` and `.../summary` (60: a large feed Canvas is slow
  to answer) and on every `/calendar_events` chunk, both `type=event` and
  `type=assignment` (30: events change rarely and only in Canvas itself, since
  writes are refused here; due dates are also in `/planner/items`, which stays on
  every sync with the rest of the hot set). The assignment entries nest the whole
  assignment object, and `list_calendar_events` prints `Assignment ID` from
  `assignment.id` (the event's own id is `assignment_<n>`), so they cannot be
  trimmed with `excludes[]=assignment`; refreshing them less often is the saving.
  The freshness note reports the real age of whatever a tool read.
- **`expand`** (replaces the v1 `perCourse: true`, which meant `eachCourse`; the
  server still emits `perCourse: true` next to `expand: "eachCourse"` so a v1
  extension keeps expanding those, and leaves it off `courseList` entries, which a
  v1 extension then rejects locally and visibly):
  - `eachCourse`: one request per course, `{course_id}` replaced in the path and in
    query values.
  - `courseList`: the query array element containing `{course_id}` (for example
    `context_codes[]: ["course_{course_id}"]`) is replaced by one element per
    course. The ids are de-duplicated, sorted ascending **as numbers**, and cut
    into chunks of `chunk` ids (10: Canvas caps `context_codes[]` at ten on the
    calendar). Each chunk is one request, keyed by its full query. The server
    cuts the same chunks from the same ids to check an upload, so both sides must
    use exactly this rule.
  - The ids come only from the `/courses` resources marked `"courseSource": true`
    in the same run: the `enrollment_state=active` lists whose `state[]` has no
    `unpublished` (two of the four). **The exact rule, which the extension
    mirrors:** from those lists take every object whose `id` is an integer and
    whose `workflow_state` is not `"unpublished"`, de-duplicate, sort ascending as
    numbers, then chunk. A student gets 403 on every sub-resource of an unpublished
    course, and Canvas rejects a whole `/calendar_events` chunk when one code in it
    is forbidden. The unpublished variant is still stored (a tool reads it) but
    never expands. The unfiltered
    `/courses` list is still fetched and stored, since tools read it, but does not
    expand: it also lists concluded courses whose sub-resources Canvas usually
    refuses. A placeholder must appear in the path or a query value, and a brace
    left after expansion is a rejection.
  - `{user_id}` is filled by the server, so the personal-calendar resources
    (`user_<id>`, hot, two types) appear in the plan only after the first upload.
  - Group calendars are filled by the server too. Once a 200 `/users/self/groups`
    is stored, the plan has plain hot `/calendar_events` resources (`type=event`
    and `type=assignment`) whose `context_codes[]` are the concrete `group_<id>`
    values: distinct ids sorted ascending as numbers, ten to a request, no
    placeholders (at most 200 groups; a refused or failed group list plans none).
    A group whose `context_type` is `"Course"` is included only when its
    `course_id` is one of the expansion course ids (course-source lists, minus
    unpublished): the groups of an unpublished or concluded course are forbidden,
    and Canvas would reject the whole chunk. Groups of another context (an
    account) stay.
    An upload is validated against exactly those. On the very first sync the
    extension's second pass over the plan (it runs because `canvasHost` was still
    null) fetches them; afterwards a changed group list takes effect on the sync
    after the one that uploads it.
- Dates are concrete (the server computes the window, 30 days back and 90 days
  ahead).
- The server derives the resources from what the student read tools request.
  A test (`tests/selfhost/test_browser_sync_coverage.py`) runs every student
  read tool against snapshots of a full sync (hot plus cold) built from the plan
  and fails on any miss; each read tool is either covered or listed there as a
  known gap.
- The resources (`selfhost/browser_plan.py`), tier and expansion:

  | Resource | Tier | Expand |
  | --- | --- | --- |
  | `/users/self`, `/users/self/profile`, `/users/self/todo`, `/users/self/groups` | hot | |
  | `/users/self/activity_stream`, `.../summary` (`only_active_courses=true`) | hot | |
  | `/courses` x4: unfiltered, and `enrollment_state=active` (plain, `state[]=available`, `term` with `state[]=available,unpublished`; these three are `courseSource`) | hot | |
  | `/planner/items` (window), `/planner/items?filter=incomplete_items`, `/planner_notes` (window) | hot | |
  | `/calendar_events` `type=event` and `type=assignment`, `user_<id>` (after the first upload) | hot | |
  | `/announcements` (`active_only`, window) | hot | courseList, 10 |
  | `/calendar_events` `type=event` and `type=assignment` (window, `excludes[]=child_events`) | hot | courseList, 10 |
  | `/courses/{id}/assignments` (`include[]=all_dates,checkpoints,submission`), `assignment_groups` (`assignments,submission`), `quizzes`, `modules` (`include[]=items`), `front_page`, `discussion_topics`, `discussion_topics?only_announcements=true` | cold | eachCourse |

  The four `/courses` variants are kept: one stored list cannot reproduce
  Canvas's `enrollment_state=active` and `state[]` filtering exactly (enrollment
  states, term dates and invitations are not all visible in the course objects).
  Cold content can therefore be up to about 12 hours old plus the time to the next
  visit (submission status in `get_my_submission_status` is cold; "upcoming" reads
  `/planner/items`, which is hot).
- The window is `[today 00:00Z - 30 days, today 00:00Z + 90 days]`. The tools'
  defaults are 14 days from today (calendar, planner notes), the 14 days before
  today (announcements) and 7 days (upcoming assignments), so each has a margin of
  at least double. The documented maximum span of the calendar tools (366 days,
  from any start date) does not fit any fixed window, before or after this change;
  a request outside the window is a "not synced" miss.
- Payload: each include is there because a tool asks for it, on the one `/courses`
  query that tool issues. The unfiltered list has none (course-code resolution);
  the plain active list has `total_scores`, `current_grading_period_scores`,
  `grading_scheme`, `restrict_quantitative_data` and the heavy `syllabus_body`
  (grade tools; by id the syllabus and grading fields, so a by-id request for a
  course with no active enrollment, such as a concluded one, is a "not synced"
  miss); `state[]=available` has
  `teachers`, `term` and `total_students` (`list_courses`); the `unpublished`
  variant has `term` (`get_my_enrollments`). `type=assignment` calendar chunks also
  exclude `description` (the whole assignment text per entry): assignment entries
  have non-numeric ids so no tool reads one by id, and the list tools exclude
  descriptions by default; only `include_descriptions=true` for assignment entries
  is not served.
- Not in the plan, because the extension's allowlist cannot carry them: pages,
  module items, quiz submissions and permissions, group members and files,
  conversations and the address book, planner overrides, group calendars,
  discussion entries, submissions, grading standards. The affected tools fail
  with `SOURCE_UNAVAILABLE` ("not synced by the browser extension yet").
- `list_calendar_events` fetches the personal, course and group contexts as
  separate requests and reports a failed one ("Some entries may be missing")
  without failing the tool. A group chunk stored as 403 therefore gives the other
  events plus an honest "Canvas refused access to this data (HTTP 403)" for those
  groups; nothing is dropped silently.
- Answering `context_codes[]`: a tool may ask for any subset or grouping of
  course codes. The matcher answers from the union of the stored chunk
  snapshots, filters each item by its `context_code`, applies the window rule
  per snapshot, and misses if any requested code is in no stored chunk.

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
  and replace the old copy.
- The lists that decide the plan are protected. A `/courses` list (any variant)
  or `/users/self/groups` that comes back with any non-200 status never replaces a
  stored 200 for that key (`kept_stored_data`): only a good list can change the
  course or group set, so one bad sync (a gateway 403 while `/users/self` works)
  cannot empty the plan. As a second guard, pruning (next item) is skipped
  entirely if any course-source or group row it would compute from is not a 200.
- Rows that left the plan are deleted. On every accepted upload, in the same
  transaction, the binding's rows whose `resource_key` is not in the current
  expected set are removed (hot and cold, computed from the course and group lists
  as they are after the upload): an old calendar chunk naming a course that is now
  unpublished, a per-course row of such a course, rows of an older plan version.
  A row is never deleted just because an upload did not mention it, so cold rows
  that are not due stay. Independently, a tool request is answered only from rows
  whose key the current plan can hold, so a stale row can never be served even
  before it is deleted.
- Limits per binding (constants in `browser_plan.py` and `browser_store.py`, not
  settings): at most 200 distinct course ids (counted over the course-source lists only; a per-course resource for any other id is `not_in_plan`, and a tool pointed at a concluded course gets a "not synced" miss), not counting the course lists the upload really replaces (newer, and not a transient failure kept out) so a new term can roll over (a `/courses` list that would exceed
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
- A stored non-200 status returns `SOURCE_UNAVAILABLE` naming the Canvas status.
  A 401/403 says "Canvas refused access to this data (HTTP 403)" when the binding
  has a 200 `/users/self` snapshot (the session works; this data is forbidden),
  and "this school blocks session access to the Canvas API" only when it has none.
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
  (only on success, only when browser data was used). Over 24 hours it adds "It
  may be out of date; open Canvas in the browser to refresh it." Over 14 days the
  snapshot is not used (`SOURCE_UNAVAILABLE`, "more than 14 days old"). Snapshots
  older than 30 days are deleted by the maintenance loop (jobs
  `browser_snapshots`, `extension_codes` for spent or expired codes, and
  `revoked_bindings` after the same age). The thresholds are operator settings
  (`token_admin settings set`): `browser_sync.fresh_hours` (24: cold content is refreshed every 12 hours, plus the time to the next visit),
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
- The popup's "Sync now" (a full sync: hot and cold).
- Each sync fetches the hot resources and the cold ones whose last successful
  fetch is older than `coldIntervalHours`. An upload of hot resources only leaves
  the stored cold rows as they are (a resource replaces only its own row).

## Permissions

`storage`, `alarms`, `scripting`, `activeTab`; `optional_host_permissions` for
any HTTPS host plus plain HTTP on `localhost` and `127.0.0.1` (development). The
popup asks only for the user's Canvas origin and Portal origin.
