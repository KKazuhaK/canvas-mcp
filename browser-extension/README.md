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

Publishing a stable `v<x.y.z>` release runs
`.github/workflows/browser-extension-release.yml`, which attaches the Chrome and
Firefox zips and this folder's source to the release and, when store
credentials are configured, submits the version to the Chrome Web Store,
Microsoft Edge Add-ons and Firefox Add-ons. [STORE-LISTING.md](STORE-LISTING.md)
has what to enter when each store listing is first created by hand. To reproduce a release build exactly (Node 24):

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

1. Installing the extension opens the default Portal's `/account/browser-extension`
   page (the popup's **Open the portal to connect** does the same). Sign in and
   press **Connect this browser**: the page hands the extension a one-time
   pairing code and the Canvas address it knows for your account.
2. If the extension may already read that Canvas site, it saves it and starts the
   first sync right away. Otherwise a tab opens with one button to allow access
   to that site only (a web page cannot ask for site access itself).
3. Another Portal, or a pairing code typed by hand: open the popup and expand
   **Another portal, or a pairing code**. The browser asks you to allow access to
   that address only. Chrome closes the popup while it asks; the extension keeps
   the request and finishes it once you allow, so nothing has to be entered again.
4. Sync happens when a Canvas page finishes loading (at most every 10 minutes),
   hourly if Canvas is already open and signed in, and when you press
   **Sync now**. The extension never opens background tabs.

**Disconnect** revokes the upload token at the Portal (which deletes the stored
snapshots) and clears everything stored in the browser.

## How pairing works

From the default Portal's page: a bridge script, declared in the manifest for
that Portal only, lets the page see that the extension is installed. When the
person clicks **Connect this browser**, the page asks the Portal for a pairing
code and posts it to the bridge (same window and origin only); the background
script accepts it only from a top-frame tab on that Portal, then claims it as
below. The bridge never reads anything else on the page.

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
- Any site other than the Portal and Canvas addresses you approved. The only
  static host permission is the default Portal, where the pairing bridge runs;
  there is no `tabs` permission and no remote code.

Permissions: `storage`, `alarms`, `scripting`, `activeTab`, host access to the
default Portal, and optional host access requested one origin at a time.
