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
Firefox add-on id.

## Privacy

[PRIVACY.md](PRIVACY.md) is the privacy policy linked from the store listings:
what the extension reads, where it sends it, and what it keeps.

## Release builds

Publishing a stable `v<x.y.z>` release runs
`.github/workflows/browser-extension-release.yml`, which attaches the Chrome and
Firefox zips and this folder's source to the release and, when store
credentials are configured, submits the version to the Chrome Web Store and
Firefox Add-ons. To reproduce a release build exactly (Node 24):

```sh
cd browser-extension
npm ci
EXTENSION_VERSION=x.y.z npm run build
EXTENSION_VERSION=x.y.z CANVAS_SYNC_FIREFOX_ADDON_ID=<gecko id> npm run build:firefox
```

`EXTENSION_VERSION` replaces the manifest version; `release-tools/` pins the
`web-ext` used for Firefox submission.

## Load

- Chrome / Edge: open `chrome://extensions`, enable Developer mode, choose
  "Load unpacked" and select `browser-extension/dist/chrome`.
- Firefox: open `about:debugging#/runtime/this-firefox`, choose "Load Temporary
  Add-on" and select `browser-extension/dist/firefox/manifest.json`. Temporary
  add-ons are removed when Firefox restarts; a permanent install needs signing.

## Use

1. Open the extension popup. Enter your Portal address (HTTPS; `http://localhost`
   is allowed for development) and press **Connect**. The browser asks you to
   allow access to that address only.
2. A Portal tab opens at `/account/browser-extension`. Sign in and approve. The
   extension reads the one-time pairing code from that tab and exchanges it for
   an upload token. If that does not work, paste the code shown on the page into
   "Have a pairing code?".
3. Open your Canvas site and open the popup: the Canvas address is filled in
   from the current tab. Press **Save Canvas site**; the browser asks you to
   allow access to that site only.
4. Sync happens when a Canvas page finishes loading (at most every 10 minutes),
   hourly if Canvas is already open and signed in, and when you press
   **Sync now**. The extension never opens background tabs.

**Disconnect** revokes the upload token at the Portal (which deletes the stored
snapshots) and clears everything stored in the browser.

## How pairing works

The popup generates a random 32-byte `state`, valid for 10 minutes, and opens
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
