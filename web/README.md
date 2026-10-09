# canvas-mcp-account-web

The React account UI for the self-hosted Canvas MCP server. It replaces the
server-rendered `/account` pages and is served by the Python server under
`/account/` when `ACCOUNT_UI=react` is set (see
[Serving](#serving) and `deploy/selfhost/README.md`, "Account UI"). With
`ACCOUNT_UI=legacy` (the default) the server-rendered pages stay in charge and none of
this is used.

Vite + React 19 + TypeScript 7, MUI 9, React Router 8 (data router), TanStack
Query 5 for server state, i18next for English and Chinese, axios for the one
same-origin HTTP client. Every dependency is pinned to an exact version
(`.npmrc` sets `save-exact=true`) and `package-lock.json` is committed.

## Develop

Needs Node 24 or newer.

```sh
cd web
npm ci --ignore-scripts      # never `npm install` in CI or Docker
npm run dev:mock             # http://127.0.0.1:5175/account/ with the in-browser mock API (no backend needed)
npm run dev                  # same, but proxies /account/api, /account/login and /account/callback to the Python server
```

`npm run dev` proxies those three paths to `http://127.0.0.1:8819` (override with
`CANVAS_MCP_DEV_PROXY_TARGET`) and passes cookies through unchanged. A real server
only accepts changes whose `Origin` equals its `PUBLIC_BASE_URL` and sets
`__Host-` cookies (HTTPS, no `Domain`), and that check is never relaxed for
development, so the proxy is useful only when the Vite server is reached on the same
HTTPS origin the server is configured for (for example through a tunnel). Everything
else is what the mock mode is for.

### Mock mode

`npm run dev:mock` runs Vite with `--mode mock`, which loads `.env.mock`
(`VITE_MOCK=1`). `src/main.tsx` then swaps the axios adapter for
`src/dev/mockServer.ts`, an in-memory implementation of every `/account/api`
route. It is built from the same `Contract` table as the real client (see
[API contract](#api-contract)), so a handler that returns the wrong shape does not
compile. It copies the server's pipeline too: the session and pending checks, the
owner check with the fresh-sign-in rule (`reauth_required`), the `X-CSRF-Token`
check on every change and on the school search, and the closed error codes. The real
interceptors still run, so the CSRF path is exercised in development as well.

Pick a scenario with `?mock=<name>` on the first page load:

| scenario | what you get |
| --- | --- |
| `enrolled` (default) | active user, valid Canvas token, one school |
| `fresh` | active user, no token yet (the enroll form) |
| `signed-out` | `/me` answers 401; sign-in page and landing page |
| `pending` | account waiting for owner approval |
| `invalid` / `token-invalid` | Canvas rejected the stored token (banner, replace form open, re-check) |
| `revoked` | an administrator marked the token invalid (no re-check) |
| `expiring` | the noted expiry date is a few days away (reminder banner) |
| `picker` | no token yet; featured schools plus the directory search |
| `identity-change` | replacing the token asks to confirm a different Canvas user |
| `owner` | owner: Admin pages, with accounts, enrollments and audit data |
| `stale-owner` | owner whose sign-in is older than 10 minutes (`reauth_required`) |
| `no-write-tools` | the server has no write-tool catalog (the screen is hidden) |
| `error-503` | saving the token answers `token_store_unavailable` |
| `rate-limited` | token save and re-check answer `rate_limited` |

Handy URLs: `/account/?mock=fresh`, `/account/admin?mock=owner`,
`/account/write-tools?mock=stale-owner`. Token inputs containing `rejected` or
`offline` trigger `token_rejected` and `canvas_unavailable`; a search containing
`offline` triggers `directory_unavailable`. The sign-in hand-off (a full-page
navigation to `/account/login`) is bounced back into the app by a tiny dev-only Vite
middleware. Mock state resets on reload.

The mock can never ship: it is reached only through
`if (import.meta.env.DEV && import.meta.env.VITE_MOCK === '1') await import(...)`,
which a production build folds away. `scripts/check-dist.mjs` greps `dist/` for the
module and its fixtures, and `src/test/checkDist.test.ts` builds with
`--mode mock` (and once with `NODE_ENV=development`, which must be rejected) to
prove it.

## Scripts

| script | what it does |
| --- | --- |
| `npm run dev` / `dev:mock` | dev server (proxy / mock) |
| `npm run build` | `tsc -b && vite build` into `web/dist` (git-ignored) |
| `npm run check:dist` | static checks on `dist/` (run after build) |
| `npm run lint` | `oxlint src`: hook rules, `react/no-danger`, `no-eval`, `no-implied-eval`, `no-new-func` |
| `npm run typecheck` | `tsc -b` |
| `npm test` | `vitest run --maxWorkers=2` (jsdom, Testing Library) |
| `npm run preview` | serve the built app at `/account/` |

CI runs `npm ci --ignore-scripts`, lint, typecheck, test, build and
`check:dist` (job `web` in `.github/workflows/canvas-mcp-testing.yml`).

## Layout

```
src/api/        axios client (CSRF, error normalisation), closed error codes, DTOs,
                contract.ts (the route table), endpoints.ts (one function per route)
src/query/      QueryClient policy, key factory, hooks, session wiring (401 / csrf_invalid)
src/stores/     language, theme (tiny zustand stores; the only localStorage users), toast
src/i18n/       i18next init (no detector) and bundled locales (en, zh) in src/locales
src/router/     route table (basename /account), RequireAuth, RequireOwner, RequireFeature
src/layouts/    PublicLayout, AccountLayout, AccountShell (status gate), AdminLayout
src/views/      one file per screen (admin/ for the owner pages)
src/components/ shared pieces (token form, school picker, confirm dialog, copy field, ...)
src/utils/      returnTo (redirect validation), tokenInput, time, errorText
src/dev/        DEV-ONLY mock server; never imported statically
scripts/        check-dist.mjs
```

Screens: signed-out landing and sign-in (with the fixed text for a failed sign-in),
pending account, Canvas token enroll / replace / re-check / delete (school list or
directory search, optional expiry date, identity-change confirmation, invalid-token
and expiry banners), write tools (with **Turn all off**), recent sign-ins, and
owner-only accounts, enrollments and audit log. Layout is phone-first (16 px
gutters, stacked cards below 900 px, no horizontal page scroll at 360 px) and
follows `prefers-color-scheme` with an optional light/dark toggle.

What is **not** here on purpose: linked sign-in methods, connected apps, MCP consent,
role changes, "sign out everywhere". The server does not have them yet; it says so in
`features` of `GET /account/api/me`, those routes are not in `contract.ts`, and the
navigation lists only what `features` allows (`RequireFeature` answers a deep link to
a missing feature like any unknown page). They come back with the server work.

## Language

English is the default no matter what the browser says. There is no language
detection anywhere (no `i18next-browser-languagedetector`, no `navigator.language`).
The language changes only through the toggle, which stores `en` or `zh` in
`localStorage` under `canvas_mcp_lang` (a per-viewer convenience, always wrapped
in try/catch), or through an explicit `?lang=en|zh` link, which applies for that
page view and is not stored. When signed in, the toggle also tells the server
(`PUT /account/api/me/ui-locale`), which keeps it in the `canvas_mcp_lang` cookie the
server-rendered pages read; in another browser that has made no choice, that
remembered value (`ui_locale` of `GET /me`) is applied for the page view. Locale files
live in `src/locales/{en,zh}/` as the namespaces `common`, `auth`, `account`, `admin`,
`errors`. `src/i18n/localeParity.test.ts` fails when the key sets, `{{placeholders}}` or
markup tags differ; `src/api/errors.test.ts` fails when any `ApiErrorCode` lacks a
string in either language. Markup inside a translation (the bold and code
fragments in the Canvas how-to) uses `<Trans components>`; translations are never
given to raw-HTML APIs.

## Security rules

These are enforced by tests (`src/test/sourceGuards.test.ts`, `checkDist.test.ts`,
the client and screen tests), lint, or `check-dist.mjs`:

- **Cookie-only auth.** The session is an HttpOnly, Secure, SameSite=Lax cookie
  set by the server. The SPA never reads, stores or sends a bearer token or JWT and
  never writes a credential, session id, CSRF token or Canvas token to
  `localStorage`, `sessionStorage`, IndexedDB, JS cookies or a URL. `localStorage`
  is used only by `stores/language.ts` and `stores/theme.ts`. Signing in is never an
  XHR: it is a full-page navigation to the server's `/account/login`, which goes to
  the identity provider and returns through `/account/callback`.
- **Same origin only.** `baseURL` is `/account/api`, `withCredentials` is true,
  there are no absolute API URLs, CORS or third-party requests.
- **CSRF.** Every POST/PUT/PATCH/DELETE, and the school search GET (which the server
  counts as a change), sends `X-CSRF-Token` from the in-memory result of `GET /me`
  (React Query cache, never persisted). `403 csrf_invalid` refetches `/me` once and
  then shows the error.
- **The Canvas token is write-only.** Password-type input, autocomplete and
  spellcheck off, sent in the PUT body, cleared from state when the request settles
  (success or failure), never rendered, logged, put in a query key or URL. The form
  deliberately does not use `useMutation`, whose `variables` would sit in the mutation
  cache. The normalised error carries no reference to the request. The one exception
  is the "this token belongs to a different Canvas user" question: the server asks
  for a confirmation and the same token is sent again together with it, so it stays in
  component state until the person answers, and is cleared when they cancel or the
  request ends.
- **Closed error vocabulary.** User-facing error text comes only from the
  `ApiErrorCode` to i18n map (`CODE_SET` in `src/api/errors.ts`, which a server test
  compares with the server's own code list). Server free text, IdP messages and
  `?error=` values are never displayed; unknown codes show the generic message.
- **No injection sinks.** No `dangerouslySetInnerHTML`, `innerHTML`, `eval`,
  `new Function` or `document.write` (lint plus a guard test plus `check-dist`). Names
  that come from Canvas or the identity provider are rendered as React text.
- **Redirect safety.** `return_to` goes through `utils/returnTo.ts`, which applies the
  same rules as the server's `sanitize_return_to` (at most 512 ASCII characters,
  inside `/account`, not `/account/api`, `/account/login` or `/account/callback`, no
  `//`, backslash, control character or dot segment, and again after percent-decoding).
  A provider's `start_url` is used only if it is a plain path on this site. There is no
  automatic redirect to the provider: a person who just signed out, or whose browser
  drops the session cookie, would loop.
- **A recent sign-in** is required for owner pages and for turning a write tool on
  (`reauth_required`). The screen shows a **Sign in again** button that goes through
  `/account/login?return_to=<this page>`; it does not redirect by itself, because that
  would throw away unsaved changes and could loop.
- **External links** render through `components/ExternalLink.tsx`: https only,
  `target="_blank" rel="noopener noreferrer"`, otherwise plain text.
  `index.html` sets `referrer: no-referrer` and `robots: noindex`.
- **No remote assets.** System font stack, inline SVG icons, bundled favicon;
  `assetsInlineLimit: 0`, no source maps.
- **Destructive actions** (delete token, turn all write tools off, deny, disable,
  mark invalid, remove a token) go through a confirm dialog and are disabled while
  the request is in flight. Mutations never retry. Requests time out after 30 s.
  The error boundary shows a fixed message, never a stack.
- **Session loss.** A 401 `not_authenticated` from any call other than the `/me`
  probe clears the whole QueryClient and the CSRF value and goes to `/sign-in`
  (keeping a validated `return_to`). Sign out posts `/session/logout`, clears the
  cache and hard-navigates to `/account/`.
- **The client gates are UX only.** `RequireAuth`, `RequireOwner` and `RequireFeature`
  decide what to draw; the server re-authorises every call.

### Content-Security-Policy

The server sends this with every response of the app, and the built page works under it:

```
default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none';
base-uri 'none'; form-action 'self'
```

`index.html` has exactly one external module script and no inline script, no
inline handlers and no runtime config injected by script. `script-src` needs no
nonce and no `'unsafe-eval'`. The one concession is `style-src 'unsafe-inline'`:
MUI/Emotion injects `<style>` tags at runtime, as the legacy pages already did.
A nonce-based `style-src` would need a per-request nonce in `index.html` and an
Emotion cache created with that nonce (`createCache({ key: 'css', nonce })`);
deferred until the owner wants it. `form-action 'self'` stays because the sign-in
hand-off is a top-level navigation, not a form post.

## Serving

`Dockerfile.selfhost` builds `web/` in a Node stage and copies the result to
`/app/web-dist`; `ACCOUNT_WEB_DIST` points there (from a checkout, point it at
`web/dist`). With `ACCOUNT_UI=react` the Python server reads the build into memory at
start and checks it (`src/canvas_mcp/core/selfhost/account_spa.py`): one `index.html`
that loads one module script from `/account/assets/`, plain asset names, every
reference present. It then serves `index.html` with `Cache-Control: no-store` for
`/account/` and every other GET below it that is not `/account/api`, the hashed files
under `/account/assets/` as immutable, and an unknown asset as a plain 404. If the
build is missing or unusable it logs one line and serves the legacy pages instead,
never a broken app. `scripts/check-dist.mjs` and the server's loader enforce the same
shape, so a build that passes `npm run check:dist` loads.

Because the mount path is fixed, the app's own routes are `/account/` (home),
`/account/sign-in`, `/account/token`, `/account/write-tools`, `/account/activity` and
`/account/admin[/enrollments|/audit]`. `/account/login` and `/account/callback` are
the server's, not the app's.

## API contract

All routes are same-origin under `/account/api`, JSON in and out, every response
`Cache-Control: no-store`, failures as `{ "error": { "code", "params?" } }`.

- `src/api/contract.ts` is the route table: one entry per `METHOD /path` with its
  query, body and response types. `endpoints.ts` makes every HTTP call from it, the
  mock handlers are registered under its keys, and `src/api/contract.test.ts` checks
  that each route has a call and a mock handler.
- `src/api/types.ts` holds the wire types, written from the server's
  `account_api.py`. `src/api/errors.ts` holds the closed code set.
- `tests/selfhost/test_account_api_contract.py` (Python side) parses `contract.ts` and
  `errors.ts` and fails when the routes or codes differ from the server's.

A change to the API is therefore one edit to the server, one to `contract.ts` /
`types.ts` / `errors.ts` (and the locale strings for a new code), and the compiler
shows what else needs touching.

## Extension points

- **More sign-in providers.** `GET /providers` already returns a list with a
  `start_url` per provider, and the sign-in page renders one button for each; a new
  provider needs an icon in `components/ProviderIcon.tsx` (unknown ones get a key icon).
- **Features that are not built yet** (linked sign-in methods, connected apps, consent,
  role changes, sign out everywhere): add the routes to `contract.ts` and `types.ts`,
  the screens under `src/views/`, and gate them on the matching `features` flag, which
  is already in `GET /me` (`RequireFeature`, `navFor` in `layouts/AccountLayout.tsx`).
