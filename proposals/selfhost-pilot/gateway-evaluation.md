---
title: "External OAuth gateway plus per-user credential resolver"
issue: vishalsachdev/canvas-mcp#484
status: historical source snapshot; fork decision recorded; not an upstream proposal
date: 2026-10-11
source-snapshot-date: 2026-10-10
---

# External OAuth gateway plus per-user credential resolver: evaluation for #484

Sources were fetched on 2026-10-10; product, price and client claims below remain
that dated snapshot and have not been refreshed. The editorial/status update is
dated 2026-10-11. Items marked UNVERIFIED remain unverified.

## Status

The upstream pilot is not pursued. The owner keeps the fork's own portal; v1
uses its built-in authorization server as the only MCP authorization path.
Entra is the default sign-in provider; Google, GitHub and OIDC remain off unless
explicitly listed. Canvas OAuth with an institutional Developer Key is rejected
for now and only reserved. The implementation remains in the fork, with full
scope and acceptance in [DEVELOPMENT.md](../../deploy/selfhost/DEVELOPMENT.md)
and [V1-PROGRESS.md](../../deploy/selfhost/V1-PROGRESS.md). Historical G1 and G2
are unmet and are not claimed; no upstream, institutional or client approval is
implied. The comparison is retained as context, not a current vendor recommendation.

## 1. Question and scope

On #484 the maintainer asked for "a short evaluation of a maintained external OAuth gateway plus a per-user credential resolver before committing to an upstream account portal", comparing credential custody, revocation, client support and maintenance burden, and noted that "a shared header-injecting gateway does not satisfy individual identity." This note covers claude.ai (web, Desktop, mobile) and Claude Code as clients, and a single student operator as the deployer. It does not cover tool-platform rewrites such as Arcade or Composio, or enterprise-only products.

**Baseline.** Not every client needs a server-side credential. The fork keeps local stdio as the recommended default [14]. Claude Desktop can run a local desktop extension (MCPB) [2]. Claude Code can generate headers on the user's machine with `headersHelper` [3]. Only claude.ai on the web and mobile strictly need a remote server, and all hosted surfaces share one OAuth client and one callback [1]. A remote connector added in claude.ai also loads in Claude Code when it is signed in with a claude.ai subscription [3]. On the Free plan a user can add one custom connector [2].

## 2. Architectures compared

**A. External gateway + resource server + resolver.** A maintained product is the MCP authorization server. It signs users in through an IdP and passes canvas-mcp a verifiable per-user identity. That identity is either a signed JWT assertion, as with Pomerium [17] or Cloudflare [24], or an access token whose `aud` names the MCP server and which canvas-mcp verifies against a JWKS [27][29]. canvas-mcp then maps that identity to a Canvas credential. There are three resolver variants:
- **A1, Canvas OAuth tokens.** These come from an institutional Developer Key [9], and the gateway or a vault holds them per user [15][20][34].
- **A2, vaulted personal access tokens (PATs).** These sit in a product that stores user-supplied API keys [31][35].
- **A3, IdP token vault.** The IdP stores tokens per connected account and canvas-mcp fetches them at call time [30][34]. Auth0's vault documents only OAuth tokens [33][34], so with Auth0 this needs A1's Developer Key. With Descope's API-key connections it is the same as A2 [31].

**B. The fork's own portal and authorization server.** The v1 implementation handles configured Entra, Google, GitHub or OIDC sign-in and PAT enrollment encrypted with AES-256-GCM under operator-held keys. Revocation is disable-first. Its own authorization server is the only MCP authorization path; the Entra proxy is removed. This is the owner's fork decision, with live validation still pending [13][14].

**C. Shared header-injecting gateway.** Included only to show why it fails. On a Team or Enterprise plan, an Owner enters the static header once and Claude sends it on every member's calls. Anthropic says to treat it as the organization's credential and not to use it to identify the user [1]. Headers can be sent alongside OAuth, but each connector still has one stored value [2]. On an individual plan, a user who adds their own connector could put their own credential in a header. The feature is in beta for a limited set of organizations, though [2], and the server would then receive a raw Canvas token on every request. Claude Code's `headersHelper` is per-user but runs only on the client [3].

## 3. Comparison

| | A1 Canvas OAuth via gateway | A2 Vaulted PAT | A3 IdP token vault | B Fork portal | C Shared header |
|---|---|---|---|---|---|
| **Credential custody** | The gateway or vault vendor holds refresh tokens. Canvas reuses refresh tokens instead of rotating them [8]. Pomerium caches upstream tokens [20], and it does not encrypt databroker records [42] (UNVERIFIED for tokens) | Vault vendor. Descope says "securely" without naming a scheme [30]. LiteLLM says "encrypted", scheme not described [35] | IdP vendor. Auth0 describes no encryption scheme [34] | Operator. Anyone with `.env` plus `/data`, or a compromised runtime, can decrypt every token [14] | One credential for everyone [1] |
| **Revocation: user** | The app can revoke its own token (`DELETE login/oauth2/token`) [8] | Delete own key in LiteLLM [35]. Descope documents admin deletion only [30]. The PAT stays valid in Canvas | Deleting a connected account in Auth0 does not revoke at the provider [33] | Revoke a connection under Connected apps [13]. Removing the enrollment leaves the PAT valid in Canvas [14] | None per user |
| **Revocation: admin** | Removing a scope invalidates the key's tokens. A disabled global key returns 401 [9] | LiteLLM admin can revoke [35]; Descope admin can delete [30] | Per vendor | Owner or operator disable: immediate in-process, within 5 s from the CLI [14] | Rotate for everyone |
| **Revocation: IdP removal** | Pomerium: a cached token outlives upstream revocation until it expires, so remove the session as well [21]. Cloudflare's default access-token lifetime is 15 min [24] | Same as the gateway | Same as the gateway | Bounded by the Entra token lifetime, so disable first [14] | n/a |
| **Revocation: Canvas side** | Key disable or scope removal [9]. Token deletion API [10] | Token deletion API [10] | As A1 if OAuth | Token deletion API [10] | n/a |
| **Client support** | Depends on the gateway (section 4) | Same | Same | DCR, CIMD and PKCE are built in. Live L1-L16 acceptance is unverified [14] | Beta, limited organizations [1][2] |
| **Maintenance** | Upstream: JWT verifier and resolver. Operator: the gateway | Verifier, resolver and vendor SDK | Verifier, resolver and vendor SDK | Measured 2026-10-11 at fork `ac5fe4f` against upstream `63f4222`: 475 files, +111,253/-925, including UI/tests. `core/selfhost/` alone: 87 files, +27,880. One owner [14] | Trivial |
| **Cost for a student** | Needs a Developer Key from a root-account admin [9]. Self-hosted Pomerium Core is Apache-2.0 [23] | Descope Free Forever: 7,500 MAU, 2,000 active tokens [32]. LiteLLM is MIT outside `enterprise/` [43] | Auth0 Free: Token Vault "2", unit not stated [44]. Also needs A1's key | One VM. SQLite or Postgres [13] | Free |

## 4. Findings

**Client requirements.** For claude.ai to start sign-in, the server must return a 401 with a `resource_metadata` pointer, and Claude uses only the first entry in `authorization_servers`. Claude uses CIMD only when the metadata advertises both `client_id_metadata_document_supported` and `none`; otherwise it falls back to DCR. The authorization server must support S256 PKCE, rotate refresh tokens for public clients, accept the callback `https://claude.ai/api/mcp/auth_callback`, and be reachable from 160.79.104.0/21. Claude Code adds loopback redirects that must match on any port [1][6]. Anthropic says Claude follows the authorization specs up to 2025-11-25 [4]. The 2026-07-28 spec deprecates DCR in favour of CIMD [5], so a gateway should offer both. Entra publishes no DCR endpoint [38], so something has to stand in front of it. In the fork that is FastMCP's OAuth proxy [14][39], and agentgateway does the same job with a static-client shim [40].

**Products whose docs meet the inbound requirements and pass an individual identity:**
- **Pomerium.** Apache-2.0; v0.33.4 was released 2026-10-02 [23]. Its MCP authorization server accepts inbound CIMD, has inbound DCR behind a flag that is off by default in core, and matches loopback ports for Claude Code [18]. It tracks upstream connections per user [15] and passes a signed per-user JWT upstream [17]. Two caveats. Its docs disagree on the header name [16][17]. In open issue #6675, the reporter says CIMD broke Claude Code cloud sessions, and a Pomerium member reports CIMD working in both clients [19]. Interoperability is therefore UNVERIFIED. The free hosted tier, Zero Personal, is "for personal use" [22], so a shared deployment would use self-hosted Core.
- **Keycloak.** Version 26.8.0, released 2026-10-01 [26]. DCR is supported, but CIMD, RFC 8707 and conformance with every MCP revision after 2025-03-26 are experimental. It documents client profiles for Claude Code and Claude Desktop, and none for claude.ai on the web [25].
- **WorkOS AuthKit** [27] and **Descope** [29]. Both are hosted, support CIMD and DCR (WorkOS's CIMD is off by default), and issue access tokens with an `aud` bound to the MCP server. WorkOS's example reads `sub` [27].
- **Cloudflare Access Managed OAuth.** It supports DCR and RFC 9728 discovery and sends a signed `Cf-Access-Jwt-Assertion`. It does not mention CIMD, and it replaces the origin's own 401 responses [24].

Not meeting the bar on its own: **Azure API Management** validates Entra tokens and can inject OAuth tokens into backend calls, but documents no DCR or CIMD [45]. Entra has neither [38].

No vendor documents an end-to-end connection from claude.ai. Open issue #1123 (one reporter, opened 2026-10-08) shows claude.ai failing before OAuth against a WorkOS-backed server that looks compliant [41]. Any choice needs a live test.

**Per-user Canvas credential.** The upstream-credential docs of Pomerium [20], Zuplo [37] and Auth0 Token Vault [34] describe OAuth only. They help only under A1, which needs a Developer Key that a root-account admin creates [9]. Upstream's #236 inventory records that pilot tests P1-P8 have not been run, so scope enforcement and refresh behaviour are still unverified [12]. For PATs, the documented per-user stores are Descope's API Key Connection [31] and LiteLLM's BYOK credentials [35]. WorkOS Pipes mentions API-key credentials but does not document how a user supplies one [28]. LiteLLM authenticates callers with virtual keys [35]. Its only documented OAuth front for MCP clients, `dcr_bridge`, names Claude Code and Desktop but not claude.ai, and it does not mention CIMD [36].

**What upstream would still have to write under A.** At a minimum:
- a resource-server mode that checks issuer, audience, expiry and signature against a pinned JWKS [17][39] and rejects any client-supplied copy of the identity header;
- a resolver interface from `sub` to a Canvas credential;
- a per-request status check, so that disabling a user takes effect;
- the write-tool opt-in.

Under A2 and A3 it also needs an enrollment page or vendor flow, plus a vendor SDK call on every request. A gateway mainly replaces the fork's authorization-server and sign-in code. It does not replace the custody, enrollment and revocation logic.

**What a gateway does not remove:**
- **PAT custody moves; it does not go away.** Deleting a stored PAT does not invalidate it; only revocation in Canvas does [13][14].
- **The policy exposure stays.** Instructure says multi-user apps "MUST use OAuth" and that asking users to paste tokens violates the API Policy [7]. That affects A2, B and any PAT variant. The policy also prohibits "model context protocol servers ... not approved by Instructure" (clause 3(i)) and requires disclosure of generative-AI use (2E) [11]. Those two apply to every option, local stdio included.
- **Institutional gates stay.** The fork's gate G2 is still unmet: the institution's position on token storage and on education records (FERPA in the US) [14]. A different gateway does not change that.

## 5. Options for the maintainer

1. **Identity-only gateway mode upstream (A, with the operator choosing the gateway).** Add an optional trusted-identity resource-server mode plus a resolver interface, and document self-hosted Pomerium Core [23] or Keycloak [25] as recipes. The upstream surface is small and standard. Credential custody stays in canvas-mcp, so the resolver and enrollment code are still needed, and so is a gateway to operate.
2. **Full delegation through Canvas OAuth (A1).** This is closest to Instructure's guidance [7], and canvas-mcp could become nearly stateless. It is blocked until an institution issues a scoped Developer Key and the #236 matrix (P1-P8) is run. P7 (refresh behaviour) and the scope-enforcement tests decide whether a gateway's refresh handling works with Canvas [12].
3. **Hosted vault for PATs (A2 with Descope).** Least custom crypto. The cost is a third party holding student tokens with an undocumented encryption scheme [30], and the PAT policy problem remains.
4. **Keep B as a pilot candidate in the fork,** outside upstream, while options 1 or 2 are evaluated. The proposal already lists the unevaluated gateway as open question Q3 [14].

**Evidence that would decide between them:**
- a live claude.ai, mobile and Claude Code connection through the chosen gateway, including revocation timing;
- results of the #236 P1-P8 tests against a real scoped key;
- the institution's answer on PAT storage and clause 3(i);
- for option 3, documented encryption and per-user deletion from the vendor.

If an institution provides a Developer Key, option 2 is preferable. If it does not, options 1 and 4 differ mainly in who maintains the sign-in code, not in who holds custody.

## 6. Sources

1. https://claude.com/docs/connectors/building/authentication: auth types, static headers (Owner-entered, not user identity, beta), CIMD/DCR selection, 401 and PRM rules, PKCE, refresh rotation, callbacks, shared hosted client, egress range.
2. https://claude.com/docs/connectors/custom/add-unlisted.md: request headers (beta, up to four, alongside OAuth, no `Authorization` on OAuth connections); one custom connector on Free; desktop extensions.
3. https://code.claude.com/docs/en/mcp: Claude Code `headersHelper`, `--client-id`, CIMD discovery, claude.ai connectors in Claude Code.
4. https://claude.com/docs/connectors/building/index.md: Claude follows the 2025-03-26, 2025-06-18 and 2025-11-25 authorization specs.
5. https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization: PRM required, CIMD SHOULD, DCR deprecated, audience validation.
6. https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization/security-considerations: no token passthrough, PKCE S256, refresh rotation for public clients.
7. https://developerdocs.instructure.com/services/canvas/oauth2/file.oauth: multi-user apps must use OAuth; manual tokens violate the API Policy.
8. https://developerdocs.instructure.com/services/canvas/oauth2/file.oauth_endpoints: 1-hour access tokens, reused refresh token, app-side DELETE revocation, no PKCE parameters.
9. https://developerdocs.instructure.com/services/canvas/oauth2/file.developer_keys: keys created by root-account admins or Instructure; scope removal invalidates tokens; disabled global key gives 401.
10. https://developerdocs.instructure.com/services/canvas/resources/access_tokens: Access Tokens API list and delete endpoints (who may call is not stated).
11. https://www.instructure.com/policies/api-policy: effective 12 August 2025; clause 3(i) on MCP servers; 2E on generative AI.
12. `git show origin/main:tools/oauth/README.md`: #236 inventory; P1-P8 not run.
13. Fork `deploy/selfhost/README.md`: custody, Connected apps revocation, enrollment removal.
14. Fork `proposals/selfhost-pilot/stage-a-main.md`: historical gates G1/G2, custody, revocation and local stdio default. Current fork decisions: `deploy/selfhost/DEVELOPMENT.md` and `V1-PROGRESS.md`. Diff sizes measured locally on 2026-10-11 with `git diff --shortstat 63f4222 ac5fe4f [-- src/canvas_mcp/core/selfhost/]`; these describe that frozen comparison, not a later HEAD.
15. https://www.pomerium.com/docs/capabilities/mcp: MCP gateway, per-user upstream connections and token refresh.
16. https://www.pomerium.com/docs/capabilities/mcp/reference: `X-Pomerium-Assertion`, `mcp_allowed_client_id_domains`.
17. https://www.pomerium.com/docs/capabilities/getting-users-identity: signed per-user JWT in `X-Pomerium-Jwt-Assertion`, JWKS, `sub`/`aud`/`iss` checks.
18. https://www.pomerium.com/changelog/mcp-oauth-compatibility-hardening (2026-08-21): MCP authorization server, inbound DCR flag (off by default in core), inbound CIMD, port-agnostic loopback matching.
19. https://github.com/pomerium/pomerium/issues/6675: open; conflicting reports of Claude Code behaviour over CIMD.
20. https://www.pomerium.com/docs/capabilities/mcp/mcp-upstream-oauth: upstream handling is OAuth only; tokens cached, storage not described.
21. https://www.pomerium.com/docs/guides/mcp-bridge: cached access token works after upstream revocation until it expires; remove the Pomerium session.
22. https://www.pomerium.com/pricing: Zero Personal free "for personal use"; MCP features listed.
23. https://api.github.com/repos/pomerium/pomerium and https://api.github.com/repos/pomerium/pomerium/releases/latest: Apache-2.0; v0.33.4, 2026-10-02.
24. https://developers.cloudflare.com/cloudflare-one/access-controls/applications/http-apps/managed-oauth/: Managed OAuth, DCR, RFC 9728, 15-minute default, `Cf-Access-Jwt-Assertion`, replaces the origin's 401.
25. https://www.keycloak.org/securing-apps/mcp-authz-server: DCR supported; CIMD, RFC 8707 and post-2025-03-26 MCP revisions experimental; Claude Code and Claude Desktop profiles.
26. https://api.github.com/repos/keycloak/keycloak/releases/latest: 26.8.0, 2026-10-01.
27. https://workos.com/docs/authkit/mcp: CIMD (off by default) and DCR, `aud` = resource, example reads `sub`, JWKS.
28. https://workos.com/docs/pipes: per-user connections; API-key credentials mentioned only in passing.
29. https://docs.descope.com/agentic-identity-hub/mcp-servers: DCR and CIMD, `aud`, vault fetch at call time.
30. https://docs.descope.com/agentic-identity-hub/core-components/connections: per-user OAuth/API-key vault, admin deletion, no encryption detail.
31. https://docs.descope.com/identity-federation/outbound-apps/connect: per-user API Key Connection.
32. https://www.descope.com/pricing: Free Forever (7,500 MAU, 2,000 monthly active tokens).
33. https://auth0.com/docs/secure/call-apis-on-users-behalf/token-vault/connected-accounts-for-token-vault.md: deleting a connected account does not revoke at the provider.
34. https://auth0.com/ai/docs/intro/token-vault: per-account OAuth token storage, token exchange.
35. https://docs.litellm.ai/docs/mcp_per_user_auth: per-user BYOK keys stored encrypted, user delete, admin revoke, virtual-key auth.
36. https://docs.litellm.ai/docs/mcp_oauth_passthrough: `dcr_bridge`; names Claude Code/Desktop, not claude.ai; no CIMD.
37. https://zuplo.com/docs/mcp-gateway/auth/upstream-oauth.md: per-user upstream OAuth only.
38. https://learn.microsoft.com/en-us/microsoft-365/copilot/extensibility/plugin-authentication-dynamic-client-registration: Entra has no RFC 7591 endpoint.
39. https://gofastmcp.com/servers/auth/authentication: JWTVerifier (JWKS, issuer, audience), RemoteAuthProvider, OAuthProxy.
40. https://agentgateway.dev/docs/standalone/latest/integrations/auth/entra/: Entra DCR shim with a static client ID.
41. https://github.com/anthropics/claude-ai-mcp/issues/1123: open, single reporter, claude.ai fails before OAuth (WorkOS AuthKit).
42. https://www.pomerium.com/docs/internals/data-storage: databroker record values not encrypted (page covers sessions).
43. https://raw.githubusercontent.com/BerriAI/litellm/main/LICENSE: MIT except the `enterprise/` directory.
44. https://auth0.com/pricing: Free plan; Token Vault value "2" with no unit.
45. https://learn.microsoft.com/en-us/azure/api-management/secure-mcp-servers: Entra token validation, credential manager for outbound OAuth; no DCR/CIMD.

**UNVERIFIED (not stated as fact above):**
- Whether Pomerium CIMD or DCR works end to end with claude.ai, mobile and Claude Code, and which assertion header reaches MCP upstreams.
- Whether Pomerium encrypts stored upstream tokens.
- Cloudflare Managed OAuth with Claude clients: CIMD support, plan and user limits, admission of Anthropic's egress range through WAF rules.
- Descope encryption and key custody, user self-deletion, and whether MCP auth and Connections are on the Free plan.
- WorkOS Pipes pricing, release stage, and fit for a Canvas PAT.
- Whether LiteLLM BYOK needs an Enterprise licence, and whether claude.ai can authenticate to LiteLLM at all.
- Whether Auth0 accepts an unregistered CIMD client ID; what the Token Vault limit of "2" counts.
- Whether request headers are offered to individual (Free/Pro/Max) accounts.
- Canvas PKCE support, refresh-token lifetime, who may call the token-deletion API, and whether the Developer Key scopes in #236 are enforced.
- Whether claude.ai supports MCP revision 2026-07-28.
- UCI's position on PAT creation and storage.
- Whether Instructure has an approval route for MCP servers under clause 3(i).
