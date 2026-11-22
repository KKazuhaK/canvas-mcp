# Canvas MCP Sync (browser extension)

Some schools do not let students create Canvas access tokens. Canvas's own web
pages still read `/api/v1` with the signed-in session, so this extension reads
the same read-only JSON while you are signed in to Canvas and pushes it to your
own Canvas MCP Portal. The Portal then answers the read-only student tools from
that data. The contract between the extension, the Portal and the account page
is `deploy/selfhost/BROWSER-SYNC-DESIGN.md`.

## Build

Requires Node 22.18 or newer (the tests run TypeScript directly).

```sh
cd browser-extension
npm install
npm test            # unit tests
npm run typecheck
npm run build           # Chrome / Edge / Chromium  -> dist/chrome
npm run build:firefox   # Firefox 142 or newer      -> dist/firefox
```

Set `CANVAS_SYNC_FIREFOX_ADDON_ID` before `build:firefox` to use your own
Firefox add-on id (default `canvas-mcp-sync@mcp.kazuhahub.com`, the listed one).

## Privacy

[PRIVACY.md](PRIVACY.md) (Chinese: [PRIVACY.zh.md](PRIVACY.zh.md)) is the privacy policy linked from the store listings:
what the extension reads, where it sends it, and what it keeps.

## Release builds

The extension's version is `version` in `src/manifest.json`, separate from the
server version. Merging a change to that version into `selfhost` runs
`.github/workflows/browser-extension-release.yml`, which creates the release
`extension-v<version>` with the Chrome and Firefox zips and this folder's
source and, when store credentials are configured, submits the version to the
Chrome Web Store, Microsoft Edge Add-ons and Firefox Add-ons. A stable server
release (`v<x.y.z>`) also gets the zips but submits nothing.
[STORE-PUBLISHING.md](STORE-PUBLISHING.md) sets up the stores and their
credentials; [STORE-LISTING.md](STORE-LISTING.md) has what to enter when each
store listing is first created by hand. To reproduce a release build exactly (Node 24):

```sh
cd browser-extension
npm ci
npm run build
CANVAS_SYNC_FIREFOX_ADDON_ID=<gecko id> npm run build:firefox
```

Release builds use the manifest version as is. `EXTENSION_VERSION=x.y.z`
overrides it for a local build; `release-tools/` pins the
`web-ext` used for Firefox submission.

## Load

- Chrome / Edge: open `chrome://extensions`, enable Developer mode, choose
  "Load unpacked" and select `browser-extension/dist/chrome`.
- Firefox: open `about:debugging#/runtime/this-firefox`, choose "Load Temporary
  Add-on" and select `browser-extension/dist/firefox/manifest.json`. Temporary
  add-ons are removed when Firefox restarts; a permanent install needs signing.

## Use

1. Sign in to your Portal, open its `/account/browser-extension` page and click
   the extension's icon there. Press **Connect to <your portal>** and allow
   access to that one site; the page then hands the extension a one-time pairing
   code and the Canvas address it knows for your account, by itself. No Portal
   is built in.
2. If the extension may already read that Canvas site, it saves it and starts the
   first sync right away. Otherwise a tab opens with one button to allow access
   to that site only (a web page cannot ask for site access itself).
3. From anywhere else, or with a pairing code typed by hand: open the popup and
   use **Portal address, or a pairing code**. The browser asks you to allow access to
   that address only. Chrome closes the popup while it asks; the extension keeps
   the request and finishes it once you allow, so nothing has to be entered again.
4. Sync happens right after pairing or choosing the Canvas site, when a Canvas
   page finishes loading (at most every 10 minutes), every 30 minutes and once
   a minute after the browser starts if Canvas is signed in, when you open the
   Portal's browser-extension page with data more than an hour old, and when
   you press **Sync now** (in the popup or on that page). The extension never
   opens background tabs, and never opens Canvas by itself: when background
   sync cannot run (for example while you are signed out of Canvas) and the data
   is older than the age you choose (1 day by default, 3 days, 1 week or never),
   it opens a reminder page with a button to open Canvas, or to snooze.

**Disconnect** revokes the upload token at the Portal (which deletes the stored
snapshots) and clears everything stored in the browser.

## How pairing works

From the Portal's page: the popup, opened on a Portal's browser-extension page,
offers that Portal. Once the person allows access to it, the extension registers
a bridge script for that origin's `/account/*` pages at runtime
(`scripting.registerContentScripts`) and injects it into the open tab. The page
sees the extension, asks the Portal for a pairing code and posts it to the
bridge (same window and origin only); the background script accepts it only
from a top-frame tab on that Portal, then claims it as below. The bridge stays
registered for the paired Portal (for Sync now on its page) and is removed on
Disconnect. It never reads anything else on the page.

From the popup (any Portal): the popup generates a random 32-byte `state`, valid for 10 minutes, and opens
`<portal>/account/browser-extension#extension-auth=<state>`. A small script is
injected into that one tab only. It reads the pairing code from the page element
`#canvas-extension-authorization` and sends it to the background script, which
checks that the message came from that tab, at that exact URL, with that state,
before it calls `POST /api/v1/extension/claim` (no cookies, no redirects). The
upload token is stored in `chrome.storage.local`, restricted to trusted
extension contexts where the browser supports it. It is only ever sent to the
paired Portal origin.

## Privacy

What is read, from your Canvas site, only while you are signed in and only
through Canvas's own read-only API with a plain `GET`:

- Your profile, courses, assignments (with your submission status and scores),
  assignment groups, modules, quizzes, front pages, discussion
  topics, announcements, your to-do list, planner items and notes, calendar
  events and the activity stream.
- Which resources are read is decided by a plan the Portal publishes, but the
  extension expands per-course resources by replacing `{course_id}` in the path
  and in query values with each course id from the same run's `/courses` result,
  and also enforces its own fixed list of allowed paths and refuses
  everything else, including any non-GET request and any other origin.

What is uploaded: that JSON, exactly as Canvas returned it, to the Portal you
paired with, with the upload token. Nothing is sent to any other address. Data
stays on the Portal until you disconnect, then it is deleted.

What is never touched:

- Cookies. The extension has no `cookies` permission and never reads or sends
  them. Canvas requests carry your session only because the browser attaches it
  to same-site requests; uploads are made with credentials omitted.
- Conversations and inbox messages, file contents, grades of other students,
  group members, and anything outside the allowlist.
- Any site other than the Portal and Canvas addresses you approved. There are no
  static host permissions, no `tabs` permission and no remote code.

Permissions: `storage`, `alarms`, `scripting`, `activeTab`, and optional host
access requested one origin at a time.
