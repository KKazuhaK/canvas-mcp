# canvas-mcp-account-web

The React account UI for the self-hosted Canvas MCP server. It replaces the
server-rendered `/account` pages and is served by the Python server under
`/account/`.

> Status: under construction. The Python server does not serve this app yet; the
> legacy server-rendered pages stay live until this UI reaches parity (see
> [Serving](#serving-later-phase)). Nothing here changes runtime behaviour today.

Vite + React 19 + TypeScript 7, MUI 9, React Router 8 (data router), TanStack
Query 5 for server state, i18next for English and Chinese, axios for the one
same-origin HTTP client. Every dependency is pinned to an exact version
(`.npmrc` sets `save-exact=true`) and `package-lock.json` is committed.

## Develop

Needs Node 24 or newer.

```sh
cd web
npm ci --ignore-scripts      # never `npm install` in CI or Docker
npm run dev                  # http://127.0.0.1:5175/account/, proxies /account/api to the Python server
npm run dev:mock             # same, but with the in-browser mock API (no backend needed)
```

`npm run dev` proxies `/account/api` to `http://127.0.0.1:8819` (override with
`CANVAS_MCP_DEV_PROXY_TARGET`). Cookies pass through unchanged.

### Mock mode

`npm run dev:mock` runs Vite with `--mode mock`, which loads `.env.mock`
(`VITE_MOCK=1`). `src/main.tsx` then swaps the axios adapter for
`src/dev/mockServer.ts`, an in-memory implementation of every `/account/api`
route. The real interceptors still run, and the mock checks `X-CSRF-Token` on
every mutation, so the CSRF path is exercised in development too.

Pick a scenario with `?mock=<name>` on the first page load:

| scenario | what you get |
| --- | --- |
| `enrolled` (default) | active user, valid Canvas token |
| `fresh` | active user, no token yet (the enroll form) |
| `signed-out` | `/me` answers 401; sign-in page and landing page |
| `pending` | account waiting for owner approval |
| `disabled` | disabled account |
| `invalid` / `token-invalid` | Canvas rejected the stored token (banner, replace form open) |
| `owner` | owner: Admin pages, with accounts, enrollments and audit data |
| `error-503` | saving the token answers `token_store_unavailable` |
| `rate-limited` | token save and re-check answer `rate_limited` (retry after 30 s) |
| `single-provider` | one sign-in provider, so `/login` auto-redirects |
| `no-provider` | no provider configured |

Handy URLs: `/account/?mock=fresh`, `/account/admin?mock=owner`,
`/account/consent/t_9f2` (`/account/consent/expired` for the expired state).
Token inputs containing `rejected` or `offline` trigger `token_rejected` and
`canvas_unavailable`; anything under 20 characters triggers
`token_invalid_format`. The sign-in hand-off (a full-page navigation to
`/account/api/login/<id>/start`) is bounced back into the app by a tiny dev-only
Vite middleware. Mock state resets on reload.

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
src/api/        axios client (CSRF, error normalisation), closed error codes, DTOs, one function per route
src/query/      QueryClient policy, key factory, hooks, session wiring (401 / csrf_invalid)
src/stores/     language, theme (tiny zustand stores; the only localStorage users), toast
src/i18n/       i18next init (no detector) and bundled locales (en, zh) in src/locales
src/router/     route table (basename /account), RequireAuth, RequireOwner
src/layouts/    PublicLayout, AccountLayout, AccountShell (status gate), AdminLayout
src/views/      one file per screen (admin/ for the owner pages)
src/components/ shared pieces (token form, confirm dialog, copy field, responsive table, ...)
src/utils/      returnTo (redirect validation), tokenInput, time, errorText
src/dev/        DEV-ONLY mock server; never imported statically
scripts/        check-dist.mjs
```

Screens: sign-in, signed-out landing, pending and disabled account, Canvas
token enroll / replace / re-check / delete (with the invalid-token banner),
write tools, sign-in methods, connected apps, recent sign-ins, MCP consent,
and owner-only accounts, enrollments and audit log. Layout is phone-first (16 px
gutters, stacked cards below 900 px, no horizontal page scroll at 360 px) and
follows `prefers-color-scheme` with an optional light/dark toggle.

## Language

English is the default no matter what the browser says. There is no language
detection anywhere (no `i18next-browser-languagedetector`, no `navigator.language`).
The language changes only through the toggle, which stores `en` or `zh` in
`localStorage` under `canvas_mcp_lang` (a per-viewer convenience, always wrapped
in try/catch), or through an explicit `?lang=en|zh` link, which applies for that
page view and is not stored. Locale files live in `src/locales/{en,zh}/` as the
namespaces `common`, `auth`, `account`, `admin`, `errors`.
`src/i18n/localeParity.test.ts` fails when the key sets, `{{placeholders}}` or
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
  is used only by `stores/language.ts` and `stores/theme.ts`.
- **Same origin only.** `baseURL` is `/account/api`, `withCredentials` is true,
  there are no absolute API URLs, CORS or third-party requests.
- **CSRF.** Every POST/PUT/PATCH/DELETE sends `X-CSRF-Token` from the in-memory
  result of `GET /me` (React Query cache, never persisted). `403 csrf_invalid`
  refetches `/me` once and then shows the error. Pages that mutate without
  rendering `/me` (consent) load it first.
- **The Canvas token is write-only.** Password-type input, autocomplete and
  spellcheck off, sent once in the PUT body, cleared from state when the request
  settles (success or failure), never rendered, logged, put in a query key or URL.
  The form deliberately does not use `useMutation`, whose `variables` would sit in
  the mutation cache. The normalised error carries no reference to the request.
- **Closed error vocabulary.** User-facing error text comes only from the
  `ApiErrorCode` to i18n map. Server free text, IdP messages and `?error=` values
  are never displayed; unknown codes show the generic message.
- **No injection sinks.** No `dangerouslySetInnerHTML`, `innerHTML`, `eval`,
  `new Function` or `document.write` (lint plus a guard test plus `check-dist`).
- **Redirect safety.** `return_to` and `txn` go through `utils/returnTo.ts`
  (single leading `/`, no `//`, backslashes, control characters or encoded
  variants, inside `/account` and outside `/account/api`). Consent and link
  hand-offs navigate only to a URL the server returned in JSON, and only if it is
  http(s). The login auto-redirect fires only with exactly one provider and no
  `?error` (loop guard).
- **External links** render through `components/ExternalLink.tsx`: https only,
  `target="_blank" rel="noopener noreferrer"`, otherwise plain text.
  `index.html` sets `referrer: no-referrer` and `robots: noindex`.
- **No remote assets.** System font stack, inline SVG icons, bundled favicon;
  `assetsInlineLimit: 0`, no source maps.
- **Destructive actions** (delete token, revoke grant or enrollment, unlink,
  disable, sign out everywhere) go through a confirm dialog and are disabled while
  the request is in flight. Mutations never retry. Requests time out after 30 s.
  The error boundary shows a fixed message, never a stack.
- **Session loss.** A 401 `not_authenticated` from any call other than the `/me`
  probe clears the whole QueryClient and the CSRF value and goes to `/login`
  (keeping a validated `return_to`). Sign out posts `/session/logout`, clears the
  cache and hard-navigates to `/account/login`.
- **The client gates are UX only.** `RequireAuth` and `RequireOwner` decide what to
  draw; the server re-authorises every call.

### Content-Security-Policy

The built page works under:

```
default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self'; connect-src 'self'; form-action 'self';
frame-ancestors 'none'; base-uri 'none'; object-src 'none'
```

`index.html` has exactly one external module script and no inline script, no
inline handlers and no runtime config injected by script. `script-src` needs no
nonce and no `'unsafe-eval'`. The one concession is `style-src 'unsafe-inline'`:
MUI/Emotion injects `<style>` tags at runtime, as the legacy pages already did.
A nonce-based `style-src` would need a per-request nonce in `index.html` and an
Emotion cache created with that nonce (`createCache({ key: 'css', nonce })`);
deferred until the owner wants it. `form-action 'self'` stays because OAuth
hand-offs are top-level navigations, not form posts.

## Serving (later phase)

The Python server will mount `web/dist` at `/account/` (assets under
`/account/assets/`, immutable) and answer every other GET below `/account/` that is
not `/account/api/*` with `index.html` (`no-store`). The old routes stay behind a
flag until parity (for example `ACCOUNT_UI=react|legacy`). `Dockerfile.selfhost`
already builds `web/` in a Node stage and copies the result to `/app/web-dist`; it
is not served yet.

## API contract

All routes are same-origin under `/account/api`, JSON in and out, every response
`Cache-Control: no-store`, failures as `{ "error": { "code", "params?" } }`. The
typed contract is `src/api/types.ts` and `src/api/endpoints.ts`.

Two places where this UI had to assume something the contract does not say:

- **`GET /me/login-history`, `GET /me/identities`, `GET /admin/enrollments`** are
  the obvious paths for the read endpoints the contract names by DTO only.
- **Admin "unlink sign-in"** sends the chosen provider id as `identity_id`, because
  `AdminAccount` lists provider ids, not identity ids. Revisit when the backend
  exposes identity ids there.

## Extension points

- **School picker.** `components/token/SchoolCard.tsx` is a documented placeholder
  (a disabled field; nothing is sent). The real picker replaces it and passes the
  chosen school to the token PUT once the contract defines the field.
