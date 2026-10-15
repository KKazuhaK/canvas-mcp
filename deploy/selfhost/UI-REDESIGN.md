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

Before beta.12, the Canvas settings page put provider setup, local-account creation,
site address, browser duration, SMTP, login policy, provider names and schools
into one long view. The home page repeated full token editing and unrelated
settings. Account rows embedded identity details and several controls, obscuring
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

The following records the beta.11 control inventory and its preserved location in
the implementation candidate. No control is removed merely because it is absent
from a compact summary. Source paths are under `web/src`.

| Existing controls/source | Candidate location and preserved behavior |
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

## Candidate implementation checkpoint — October 13

`SettingsTopics` provides the five URL-addressed categories. `useSettingsDraft`
keeps edits in memory across topic switches and unrelated revisions; concurrent
changes to the same section require explicit draft disposal/reload. Provider
display-name saving and configuration saving retain separate revision-protected
requests without remounting an edited secret/configuration. New provider creation
offers its display-name editor only after the provider record exists.

`CanvasConnectionSummary` and `ConnectedAppsSummary` provide the home summaries.
The client preview preserves verified-domain/unverified-name labels and makes no
claim to a total across unloaded pages. Password creation/change is on Sign-in
methods even when external linking is unavailable; disabled linking hides cached
identities and does not request the identity API. Token editing, school search,
custody acknowledgement and notification preferences remain on Canvas token.

`DetailDrawer` contains selected-account/profile/sign-in/Canvas/app sections and
selected-enrollment details. Protected reads are deferred until their section is
active. The account list retains immediate pending approval and otherwise offers
Manage. Individual app revocation names the account/client, confirms the next-
request effect and requires renewed consent. Local-account creation is in Accounts.
The drawer sits above the fixed navigation while nested confirmation dialogs keep
their normal modal layer. Technical identifiers and successful audit detail are
secondary; failure reasons remain visible.

Recent-login result/time filters explicitly cover loaded records and retain load-
more. Unknown reason codes render as escaped plain text. Owner expiry metadata is
an additive governed DTO change, with no database migration or credential write.

Local rendered evidence includes English provider edits/name saves, English mobile
account details, English/Chinese desktop account management, Chinese mobile home/
token replacement and English mock client revocation. At 390 pixels, inspected
home/details have no document-level horizontal overflow. These mock observations
exercise the interface without modifying live identities, credentials or grants.
This checkpoint describes local mock observations. The release evidence below
supersedes its CI/publication gate; deployed-page acceptance is still required.
Remaining live HANDOFF checks are unchanged.

## Merged and published checkpoint — October 14 UTC

[PR #17](https://github.com/KKazuhaK/canvas-mcp/pull/17) merged as
`12e28987049615bb3a632b8819642ebb9cb15e33`, with the same file tree as reviewed
candidate `c6fca41752c92536fc1b88020d5585a1660c3ebc`. The
[complete candidate matrix](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38487993088)
and [complete post-merge matrix](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38490456467)
passed, including all 527 UI tests and required API, Python, PostgreSQL, formal
confirmation and native image checks. The final SMTP/session-duration conflict
regressions prove explicit reload discards the stale draft and permits a new
edit/save; failed reloads stay in the normal visible error flow.

[Beta.12](https://github.com/KKazuhaK/canvas-mcp/releases/tag/v1.14.0-beta.12)
is published and its amd64/arm64 version, source and build-time stamps were
verified. Downloaded Compose/env assets are unchanged from beta.11. This is a
released implementation with automated and rendered mock evidence. The operator
updated to beta.12; the public version endpoint confirmed the release commit and
build timestamp. Deployed home/token/provider/account pages and the local-owner
safeguard were inspected. Existing Claude Code and claude.ai grants each completed
one read-only profile call after the upgrade without renewed consent. These calls
do not prove refresh rotation or several days of operation. Remaining live HANDOFF
checks, including mail delivery and the unavailable B2B guest, remain open.

## Provider editor refinement

Provider rows now align the icon, display name, identifier, enabled status and
outlined Edit action. Refresh lives beside the list heading; provider creation has
a separate footer with a primary Add action. Selecting a provider replaces the
list with its editor instead of leaving disabled Edit links above a long form.
The editor groups appearance, connection settings and sign-in rules, with related
connection fields paired on desktop and stacked on narrow screens. Save/cancel
actions share a footer and a secondary Back to providers action is available at
the top. Display-name saving remains independent and retains the configuration
draft; Enter in that field cannot submit the credential form. No database,
authentication-policy or deployment-configuration change is involved.

Shared secondary actions use outlined buttons with consistent sizing and keyboard
focus rings. Reauthentication has a filled icon-labelled button beneath its
explanation, rather than a text link at the alert's far edge. Token invalidation
and removal retain their confirmations and use warning/error outlined actions.
Drawer surfaces use the application's normal dark background and a visible Close
button. Navigation utilities retain their compact header presentation.

## Beta.13 deployed observation and follow-up

The operator's update was confirmed by the public version endpoint and footer:
`1.14.0-beta.13`, source `272b114b803b51fb860f328c04669f43826cda92`, built UTC
`2026-10-14T10:06:36Z`. The real expired recent-login notice has a filled icon
button; completing organization verification returned to the providers topic.
The deployed editor has appearance, connection and rules sections. Own-account
token controls have warning/error outlines and icons, and the drawer closes.
These checks did not save live configuration or invalidate/remove a token.

Further feedback identified lowercase internal IDs in provider cards. The
candidate shows localized protocol names, keeps configured display names and
distinguishes unnamed custom OIDC instances by slug. It uses the same type labels
in installation and creation choices. Stable provider IDs and callback URLs are
retained. The refinement was merged in PR 21 and published in beta.14; its
complete candidate/post-merge matrices and tagged native images passed. Deployed
beta.14 version/health and automatic expiry acceptance passed after the operator's
update: token recheck displays a Canvas-sourced date, removes the unknown notice
and updates the home summary without replacing the token. After recent
administrator sign-in, deployed English/Chinese provider labels, visible edit
buttons and the Entra editor/callback passed inspection. A 390-pixel browser
viewport retained usable labels/actions without document-level horizontal
overflow; this does not claim mobile MCP-client compatibility. Language and
viewport were restored, with no provider configuration saved.
At narrow widths, the missing-local-administrator action sits below its warning
and the header language label stays on one line.

## Independent navigation and content scrolling

The signed-in layout uses a viewport-height frame. Its top bar stays outside the
scroll regions, the desktop sidebar scrolls independently when its menu exceeds
the available height, and only the right-hand main region scrolls through page
content and the build footer. The temporary mobile drawer retains its existing
navigation and close behavior. Changing routes starts the main region at the
top; changing a settings topic or language does not discard in-memory edits.
The main region remains the keyboard-accessible skip-link target.

Local rendered verification scrolled the English mail page to its bottom:
main scrollTop changed from 0 to 616 while the sidebar stayed at y=64.67,
the top bar stayed at y=0 and the document stayed at scrollTop=0. In a
1280-by-320 viewport, the sidebar scrolled independently to 104.67 while the
main region stayed at 616. Selecting Canvas token returned the main region to
0. At 390 pixels the Chinese mobile navigation opened, changed routes and
closed, with no document-level or main-region horizontal overflow. Locale and
viewport were restored. All 531 frontend tests, type checking, lint and
production build/distribution checks passed. The first full test attempt had a
Windows Node worker access violation; its 8-case file passed independently and
the complete repeated run passed. These are local mock observations; deployed
acceptance still requires the next image update.
