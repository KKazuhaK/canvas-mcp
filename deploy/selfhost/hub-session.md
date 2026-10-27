# Reuse MCPHub sign-in for Canvas

Canvas can offer **MCPHub** alongside its existing login methods. Hub passwords
are never requested by Canvas. The bridge verifies the current Better Auth
session against Hub's existing HTTPS APIs, then returns a short-lived,
single-use PKCE-bound code to the Canvas login ceremony. Hub's source, image,
Compose, database, service definitions and `/api/` routes remain unchanged.

## Operator setup

1. Deploy the Canvas build containing the `hub` login provider. Preserve its
   existing public URL, volume, database, internal keys and login providers.
   For example, Canvas can stay at `https://canvas.example.com`.
2. In Canvas **Admin → Settings → Login provider configuration**, add **MCPHub**
   and enter the Hub origin, for example `https://hub.example.com`. No OAuth
   application registration, client ID, shared token or client secret is needed.
3. Add the exact location from `hub-session-nginx.conf.example` to the **Hub
   hostname's existing HTTPS reverse proxy**, pointing at the Canvas container's
   existing loopback port. Validate nginx before reloading. This is a proxy
   addition, not a Hub application modification. Do not proxy the whole Canvas
   account UI or `/api/` onto Hub.
4. Keep the current Canvas admission policy. Enabling the login method does not
   grant Canvas access or owner privileges to every Hub user. With approval
   policy, users may need approval; with rules policy, the operator can explicitly
   include `hub:any` in `ACCESS_RULES` to admit any account Hub itself admits.
   Preserve other existing rules. Hub's `isAdmin` never grants Canvas ownership.

For an already initialized Canvas installation, edit providers through its UI or
`token-admin login-providers --configure hub`; editing an old import environment
alone does not override database-managed registrations. A CLI input is:

```json
{
  "revision": 0,
  "config": {"origin": "https://hub.example.com"},
  "enabled": true,
  "rank": 1
}
```

Replace `revision` with `token-admin login-providers --revision` and `rank` with
the desired unused position. No `client_secret` is supplied. Do not overwrite
existing providers, reset the database, or disable the last usable owner login.

## Users

New users choose **MCPHub** on the Canvas sign-in page, confirm the Hub account
shown, then configure their Canvas connection through the existing Canvas UI.
If signed out of Hub, they sign in there and start the Canvas flow again.

Existing users first sign in to their original Canvas account, open
**Sign-in methods**, and add **MCPHub**. This requires a fresh Canvas sign-in and
confirmation of the current Hub identity. All tokens, account settings, OAuth
app grants and reminders stay attached to the original Canvas account. A Hub
identity already attached to another account is refused; accounts are never
silently merged by matching email or username.

Hub sign-in is reused during onboarding and reauthentication. Canvas still
issues its own bounded browser session, and authorized MCP clients still use
Canvas OAuth access/refresh tokens. Signing out of Hub does not revoke existing
Canvas browser sessions or MCP grants. Revoke those through Canvas when needed.
The integration does not promise cross-application single logout.

## Trust boundary and checks

- The identity key is `hub` + configured HTTPS origin + Better Auth `user.id`.
  `/oauth/userinfo.sub` and `/api/better-auth/user.username` are not stable IDs.
- Only Better Auth session-token cookies are forwarded, only to the configured
  Hub HTTPS origin. Cached session-data cookies, authorization keys and claimed
  username headers are ignored. The cookie is never stored in Canvas.
- Both `/api/auth/better/get-session` and `/api/better-auth/user` must verify.
  Session expiry, subject mismatch, HTML/redirect responses, Hub refusals and
  network failures never create a Canvas account or session.
- The exact bridge path accepts the configured Hub host. Every other Canvas
  route retains the existing host/origin guards. No CORS is opened.
- Confirmation is a same-origin POST bound to a sealed HttpOnly browser cookie,
  one-use server state, the original Hub user ID and a CSRF token. Changing Hub
  accounts between preview and confirmation is refused.
- Login/link callbacks retain Canvas's existing state, browser binding, account
  epoch and configuration revision checks. The returned code lasts 60 seconds;
  the confirmation expires after five minutes. Codes are never user credentials.
- This first adapter targets the default Better Auth `/api/auth/better` base
  path and `better-auth.session_token` cookie name (including its secure prefix).
  Custom cookie names, gateway-only identities or another Better Auth base path
  require an explicit adapter change; no permissive fallback is used.

Local tests use synthetic Hub identities and the real Canvas account store,
OAuth flow and MCP handlers. Before opening production access, test two real
Hub accounts in separate browser profiles, existing-account linking, sign-out,
expired sessions, and unchanged original login/OAuth behavior. Do not use real
Canvas writes as a deployment test.

## Rollback

Disable only the new Hub login provider in Canvas and remove the exact reverse
proxy location after a successful `nginx -t`. Existing identities and credentials
are retained; users can use their previous login method. Provider safeguards
refuse disabling the last usable owner method. Do not remove data volumes.
