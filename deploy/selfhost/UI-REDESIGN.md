# Selfhost frontend usability follow-up

Originally ordered after HANDOFF; on October 13 the owner authorized frontend
implementation in parallel with the remaining live checks. Those checks remain
open and must not be represented as completed by frontend work. Keep the existing major
account/admin areas, with English and Chinese interfaces, mobile layouts and
the existing governed API. The aim is to make common tasks easy to find and
understand, not merely restyle the same long forms.

## Reference and current problems

Use [PSP](https://github.com/KazuhaHub/Passwall-Sub-Panel) as an interaction
reference: topic tabs with URL state, consistent page headers, coherent form
sections, concise list rows, details on demand, and visible save feedback.
Inspect its current source again when implementing; do not transplant its
product-specific infrastructure or subscription flows into Canvas MCP.

The current Canvas settings page puts provider setup, local-account creation,
site address, browser duration, SMTP, login policy, provider names and schools
into one long view. The home page repeats full token editing and unrelated
settings. Account rows embed identity details and several controls, obscuring
the primary actions. Each existing feature must remain reachable after cleanup.

## Target organization

| Area | Default content | Secondary tasks |
| --- | --- | --- |
| Account home | Account identity, Canvas connection health/expiry, connected-client summary and clear next action | Direct links to token replacement, reminder preferences and sign-in/security details |
| Canvas token | School, custody notice, connection state, expiry provenance and last verification | Explicit replace/recheck/remove flows; unknown versus unlimited stays clear |
| Write tools | Current permission state and grouped available operations | Explicit opt-in/save; keep course and operator restrictions visible |
| Sign-in methods | Linked methods, local-password state and applicable account restrictions | Link/unlink and password changes with protected confirmation/reauth flows |
| Connected apps | Compact client list, last use and connection status | Per-client details and revoke confirmation; explain next-request effect |
| Recent activity | Relevant sign-ins with simple status/time filters | Details on demand, readable localized refusal reasons |
| Admin accounts | Compact searchable/filterable table with account, role, state and last sign-in | One account detail view with profile, sign-in policy, identities, Canvas and connected apps; no forms embedded in every row |
| Admin enrollments | Connection state, school and expiry | A focused enrollment detail view; remove/mark-invalid remain explicit |
| Admin settings | Topic navigation with a brief explanation of each category | Site; sign-in providers; account/access policy; schools/directory; mail/reminders |
| Admin audit | Filters, localized action/result and time | Actor/target details and pagination, without exposing secrets |

Provider name/icon/enablement/configuration should be presented together per
provider. Local-account creation belongs with account management; keep the
last-local-administrator recovery status easy to see. Browser session duration
belongs under account/security policy, with recent-login requirements explained
separately. SMTP connection settings and reminder behavior belong together.

## Source inventory and preservation map

The following is the implementation starting inventory at beta.11. Expand it to
individual controls while changing each view; do not remove a control merely
because it is absent from a compact summary. Source paths are under `web/src`.

| Existing controls/source | Planned location and behavior to preserve |
| --- | --- |
| `HomeView`, `AccountUpnSettings` | Home shows read-only identity/UPN. Only the administrator editor can change UPN; required-UPN notices must remain visible without offering personal editing. |
| `TokenView`, `token/TokenSection`, token form/status components | Token page retains school selection/search, required custody notice, enrollment, replacement, recheck, removal, offered-school warning, automatic expiry/source and verification times. Home keeps actionable health summaries and direct links. |
| `NotificationSettings` | Token page reminder preferences: opt-in, recipient, save, availability/window, unknown/unlimited exclusions. Home retains an imminent-expiry action; no manual date input returns. |
| `McpUrlCard` | Home keeps a concise copyable MCP address and connection guidance. |
| `LocalPasswordSettings`, `SignInMethodsView` | Sign-in methods/security retains password creation/change, linked identities, link/unlink, lock/allowed-method explanations and reauthentication. Password change still explains session/app invalidation. |
| `WriteToolsView` | Existing write-tools area retains individual opt-ins, policy constraints, pending/empty/refused states and explicit save feedback. |
| `ConnectedAppsView`, `ActivityView` | Existing app/activity areas retain details, pagination, localized reasons and explicit grant revocation. A loaded-page filter must clearly state its scope; it must not imply a search of all history. |
| `AdminAccountsView`, `AdminActions`, `AccountUpnEditor` | Account list retains counts, status/search/load-more; the selected account detail retains UPN, approval/denial, enable/disable and the server-provided token actions with last-owner protections. Role/deletion controls that currently belong to the operator CLI retain that boundary; reorganizing the UI does not invent a new API. Search scope is explicit when only loaded rows are searched. |
| `AccountLoginPolicy`, `AccountIdentities`, `AccountApps` | Selected-account sections retain method allowlists, single-SSO lock/unlock, identity details/removal and individual app revocation. Operator-only bulk revocation retains its current boundary. Unlock never deletes or silently links an identity. |
| `LocalAccountCreate` | Move from provider settings to admin accounts. Retain UPN/password/owner inputs and the existing recovery and last-local-administrator rules. |
| `AdminEnrollmentsView` | Enrollment list/detail retains school, Canvas identity, health/refusal reasons, times and account status. Account moderation remains an explicit selected-account action. |
| `SiteAddressSettings` | Site topic retains saved database origin, callback impact, current revision and confirmation/conflict behavior. Deployment fallback remains separate from editable product settings. |
| `LoginProviderSettings`, `ProviderConfigurationForm`, provider-name editor | Providers topic combines list, create/edit, enablement/rank, kind-specific issuer/client/claim/role settings, sealed secret replacement, display name/icon and callback guidance. Multiple custom OIDC records remain distinct. Keep reload, save/refusal and policy-generation effects. |
| `LoginPolicySettings`, `BrowserSessionSettings` | Access topic retains automatic registration/admission, account-linking and conflict policies, per-provider auto-link rules and browser lifetime. Keep the protected local administrator recovery status visible. |
| School/directory editor in `AdminSettingsView` | Schools topic retains host check, suggested name, featured list, names/order/remove, directory switch, private-school indicator and affected-enrollment confirmation. Private exceptions remain governed by their existing operator boundary. |
| `MailSettingsPanel` | Mail topic retains enablement, transport/certificate settings, SMTP username/write-only password, sender, reminder window, save and saved-connection probe. Describe accurately that the probe sends no message. |
| `AdminAuditView` | Audit area retains loaded action filter, localized known detail values, unknown plain-text fallback, actors/targets and load-more; details can be secondary without hiding failures. |
| `SetupView`, `SignInView`, `ConsentView`, auth/owner/feature route guards | Keep multi-provider setup/chooser, local login, custom provider icons, pending/denied/expired states, safe return targets, client consent and guarded routes. Reorganizing account pages cannot weaken these flows. |
| Account/public layouts, `PageHeader`, `BuildFooter`, `ErrorNotice` | Keep skip link, navigation, responsive language/theme controls, logout, build identity and useful error/retry feedback consistently available. |

## Interaction requirements

- Keep major routes and old deep links usable. Settings topic selection belongs
  in the URL, so refresh, browser Back and a direct link restore the same view.
  Invalid or obsolete topics get a predictable fallback. Do not put identity,
  credential or mail data in topic/filter URLs.
- Show summaries/status first. Put advanced identifiers, technical details and
  destructive actions in explicit secondary sections. Do not hide a failed
  connection or a required action inside a collapsed section.
- Give every form one clear save action, dirty/pending/saved feedback and
  field-level errors. Switching topics or receiving a new revision must not
  silently discard an unsaved edit. Preserve revision conflict and reauth flows.
- Separate save, check, link, replace and revoke actions. Confirm only operations
  that need it; show the actual affected account/client/school and consequence.
- Use one consistent title/subtitle/action layout, form spacing and responsive
  table/detail treatment. Keyboard navigation and mobile layouts must remain
  practical; icon-only actions need accessible labels.
- Preserve secret handling: write-only provider/SMTP secrets, password fields,
  no tokens or private state in URLs/browser persistence, no hidden credentials
  in displayed technical details. Preserve all owner/CSRF/origin/access guards.

## Completion evidence

Inventory every existing control and record its new location before removal.
Verify normal, empty, loading, error, stale-revision, reauth and disabled states.
Run meaningful routing/form regressions, all UI checks and the required backend
contract checks. Inspect actual English/Chinese account and admin flows in
desktop and mobile widths, including a normal Canvas enrollment/replacement,
provider edit, account policy change and connected-app revocation. Record live
deployment observations separately from local mocks. This follow-up is complete
only when the reorganized workflows are implemented, released and verified.
