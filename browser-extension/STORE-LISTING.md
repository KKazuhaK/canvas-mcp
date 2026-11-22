# Store listings: Canvas MCP Sync

What to enter when the extension is first listed in each store by hand. After
the first listing, `.github/workflows/browser-extension-release.yml` submits
each new extension version (a version bump in `src/manifest.json` merged to
`selfhost`) automatically; [STORE-PUBLISHING.md](STORE-PUBLISHING.md) covers
the API credentials and how to store them. Keep this file in step with [PRIVACY.md](PRIVACY.md) and
`src/manifest.json`.

## Before the first upload

- Firefox add-on id: `canvas-mcp-sync@mcp.kazuhahub.com` (the build default).
  Add-ons ties the listing to this id for good. Do not set the repository
  variable `FIREFOX_ADDON_ID` yet: it turns on the Firefox submission job,
  which needs the listing to exist (see "Firefox Add-ons" below).
- Package for the first upload: the `canvas-mcp-sync-chrome-<version>.zip`
  (Chrome Web Store and Edge Add-ons) and `canvas-mcp-sync-firefox-<version>.zip`
  plus `canvas-mcp-sync-source-<version>.zip` (Firefox Add-ons) attached to an
  `extension-v<version>` release (see "Order of work" in
  [STORE-PUBLISHING.md](STORE-PUBLISHING.md)). Use a release built with the id
  above: a Firefox zip from an older release carries
  `canvas-mcp-sync@canvas-mcp.invalid`.
- Store versions only go up. The store version is `version` in
  `src/manifest.json`: bump it for every extension change. Each bump merged to
  `selfhost` is released and submitted.
- Screenshots (1280x800 PNG; Chrome and Edge need at least one, Firefox
  recommends one): the popup connected to a Portal with the last sync time, and
  the Portal's Browser extension page after pairing. Use a test account; do
  not show real course names or other people's posts.
- Chrome Web Store small promo tile: 440x280 PNG (required by Chrome; Edge
  accepts it as optional).
- Store icon: `src/icons/icon-128.png`.

## Shared text

**Name:** Canvas MCP Sync

**Summary** (Chrome: at most 132 characters; also the Edge short description
and the Firefox summary):

> Sends read-only snapshots of your own Canvas courses to your Canvas MCP Portal, for schools that do not allow Canvas access tokens.

**Description:**

> Some schools do not let students create Canvas access tokens, so AI assistants
> and other apps connected to a Canvas MCP Portal cannot read your courses.
> Canvas MCP Sync fills that gap. While you are signed in to Canvas, it reads
> your own course data through Canvas's read-only API, with your existing
> session, and sends a snapshot to the Canvas MCP Portal you choose. The Portal
> then answers questions about your courses, assignments, due dates and
> announcements from that snapshot.
>
> - Read only: it never submits, posts or changes anything in Canvas.
> - Your choice of server: it sends data only to the Portal address you enter.
>   No server address is built in.
> - No cookies are sent to the Portal: it has no cookies permission, and
>   uploads use an upload token issued when you pair with the Portal.
> - Access one site at a time: the browser asks you to allow your Canvas site
>   and your Portal when you set them up, and nothing else.
> - Disconnect clears everything in the browser and asks the Portal to delete
>   the synced data.
>
> You need an account on a Canvas MCP Portal (open-source, self-hostable:
> https://github.com/KKazuhaK/canvas-mcp). This extension is an independent
> open-source project and is not made by or affiliated with Instructure or
> your school.

**Category:** Chrome: Productivity > Education (or Tools); Edge: Productivity;
Firefox: Other (no education category).

**Language:** English.

**Homepage / support URL:** https://github.com/KKazuhaK/canvas-mcp/tree/selfhost/browser-extension

**Privacy policy URL:** https://github.com/KKazuhaK/canvas-mcp/blob/selfhost/browser-extension/PRIVACY.md

**License (Firefox):** MIT (the repository licence).

## Chrome Web Store: Privacy practices tab

**Single purpose:**

> Copy a read-only snapshot of the signed-in student's own Canvas data to the Canvas MCP Portal the student chooses, so the apps connected to that Portal can answer questions about the student's courses.

**Permission justifications:**

| Permission | Justification |
| --- | --- |
| `storage` | Keeps the Portal and Canvas addresses, the Portal upload token and the last sync status on this device. |
| `alarms` | Runs the background sync every 30 minutes, and once shortly after the browser starts. |
| `scripting` | Runs the read-only Canvas API requests inside the user's open Canvas tab, and reads the one-time pairing code from the Portal tab the user opened to pair. |
| `activeTab` | Reads the address of the tab the popup is opened from, to fill in the user's Canvas address. |
| Host permission and content script (`https://canvas.mcp.kazuhahub.com/*`) | The default Canvas MCP Portal. A small bridge script there lets the Portal's own "Connect this browser" button hand the extension a one-time pairing code; it reads nothing else on the page. The extension uploads snapshots to this Portal. |
| Host permissions (optional, `https://*/*`, `http://localhost/*`, `http://127.0.0.1/*`) | Requested at runtime for exactly two origins the user enters: their Canvas site (to read their own data) and their Canvas MCP Portal (to upload it). Each school and each Portal has its own address, so they cannot be listed in advance. Localhost is for developers running a Portal locally. |

**Remote code:** No, I am not using remote code. All scripts are bundled in the package.

**Data usage** (tick these):

- Personally identifiable information: the user's Canvas profile name and email, and the names of teachers and other course members shown in course data.
- Personal communications: Inbox previews and other people's posts that Canvas includes in the activity stream.
- Authentication information: the Portal upload token.
- Website content: course, assignment, module, page, announcement and calendar data from Canvas.

Leave the others unticked (health, financial, location, web history, user
activity). Tick all three certifications (not sold, not used for unrelated
purposes, not used for creditworthiness).

## Microsoft Edge Add-ons (Partner Center)

Edge takes the Chrome zip unchanged. Use the shared text above.

- **Privacy policy:** required, because the extension handles personal data;
  same URL.
- **Notes for certification:**

> The extension needs a Canvas site and a Canvas MCP Portal account to do anything beyond its popup. To try the pairing flow without Canvas: open the popup, enter https://canvas.mcp.kazuhahub.com as the Portal address and press Connect; the browser asks for access to that origin only, and the Portal's sign-in page opens. Source: https://github.com/KKazuhaK/canvas-mcp/tree/selfhost/browser-extension (build: npm ci && npm run build).

After the product exists, Partner Center > Publish API (v1.1) gives the Client
ID and API key for `EDGE_CLIENT_ID` and `EDGE_API_KEY`; the product id from the
extension overview page goes in `EDGE_PRODUCT_ID`. The API key expires; renew
it there before the date it shows.

## Firefox Add-ons (AMO)

- Distribution: **On this site (listed)**, so Firefox updates it
  automatically. The workflow submits to the listed channel.
- Source code: upload `canvas-mcp-sync-source-<version>.zip`. Build steps for
  the reviewer:

> Node 24. cd browser-extension && npm ci && CANVAS_SYNC_FIREFOX_ADDON_ID=canvas-mcp-sync@mcp.kazuhahub.com npm run build:firefox. Output: browser-extension/dist/firefox. esbuild bundles src/background.ts, src/link.ts and src/popup; the output is not minified.

- Data collection: the manifest already declares `authenticationInfo`,
  `personallyIdentifyingInfo`, `personalCommunications` and `websiteContent`
  as required; AMO shows them on the listing.
- Notes to reviewer: the same text as the Edge certification notes.

After the listing exists, Tools > Manage API Keys gives the JWT issuer and
secret for `AMO_JWT_ISSUER` and `AMO_JWT_SECRET`; then set the variable
`FIREFOX_ADDON_ID=canvas-mcp-sync@mcp.kazuhahub.com`, which turns the job on.
