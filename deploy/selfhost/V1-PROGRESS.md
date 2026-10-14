# v1 implementation progress

This is a working checkpoint, not a deployment or release approval. Follow
`V1-DESIGN.md` for the target and `DEVELOPMENT.md` for the complete handoff.

## Current status

The current published prerelease and latest observed deployment are beta.14.
The provider/action refinement and its test-clock correction are merged in PRs 19
and 20, released and inspected on the deployed site. The provider-label and
sharded-expiry correction merged in PR 21 and is published in beta.14. Its live
token recheck now supplies the actual expiry in the token page and home summary.
Start with the completion audit and
current image record below; later dated checkpoints preserve implementation history.

### HANDOFF completion audit

Checked on October 14 UTC against the current source, published release, CI records
and available live evidence. Automated checks prove their covered behavior;
they do not replace the live checks in DEVELOPMENT 6.12. A beta deployment does
not complete HANDOFF or authorize a stable release.

| Original item | Current result | Evidence and remaining boundary |
|---|---|---|
| 6.1 B0/P7 | Published, independently reviewed, repaired and merged | [B0 review](B0-REVIEW.md), fork PR 4 and its post-merge CI. The historical sync happened before the owner's later independent-selfhost decision; no further sync is permitted. |
| 6.1a v1 consolidation | Implemented and merged | Fork PR 5, current complete CI and native images. Later owner-requested account/session/notification work is recorded separately below. |
| 6.2 provider naming | Implemented; automated validation passed | Governed provider configuration, React views, bilingual messages and current full CI. Later icon customization is implemented too. |
| 6.3 schools and directory | Implemented; automated validation passed | Database-owned school policy, settings/API/CLI checks, address protection and current full CI. Exact live directory egress remains a 6.12 check. |
| 6.4 custody acknowledgement | Implemented; real enrollment exercised | Custody/API/MCP regressions and owner-performed real enrollment. No unattended enrollment of others is claimed. |
| 6.5 fork framing | Implemented | Neutral examples, independent-fork notices and documentation checks. |
| 6.6 pilot/client documentation | Pilot restriction implemented; client acceptance partial | Pilot-mode regressions and tested-client table. Web and Code have successful live reads. The owner accepts the shared web/Desktop remote-service path without a duplicate Desktop call; Desktop UI/build and mobile support are not separately verified. |
| 6.7 small upstream PRs | Submitted and updated; maintainer decision remains external | October 13 GitHub inspection: 490 is open/review required; 491 and 494 are open/approved. Their updates were not merged into `selfhost`. |
| 6.8 proposal records | Implemented | Three historical proposal records plus their index; old claims retain their dates and UNVERIFIED marks. |
| 6.9 issue 484 reply | No reply, as instructed | Historical proposal banners record the independent-fork decision; no new upstream pilot is claimed. |
| 6.10 beta release | Published through beta.14 | Exact reviewed/post-merge matrices and native release smoke passed. Owner-authorized early betas supersede the original first-tag timing gate; stable publication is not authorized. |
| 6.11 operator deployment | Implemented and deployed | Compose plus complete env template, unchanged assets, owner update confirmation, health/version/OAuth checks. |
| 6.12 live verification | Incomplete | Detailed live boundary below; partial client observations must not be promoted to broad compatibility. |
| 6.13 residuals | Source fixes implemented | Bilingual audit enum labels and identity actions, consistent rate-limit wording, native per-request authorization, accepted limitations in README. The manual expiry input was removed by the later automatic-only requirement. |

Remaining live evidence is specific: a B2B guest (the owner currently
has no test guest); consecutive-day refresh including rotation/absolute TTL and
grace behavior; whole-account disable followed by Entra removal/role aging;
proxy limits, failure behavior and actual log redaction; live signing/encryption
key rotation; and directory query egress. Enabled Entra tenant-member sign-in,
custody enrollment, deployed-host CIMD fetch, web/Code read-only calls, operator
store check and health are exercised. Only Entra and local are configured;
unconfigured Google/GitHub/custom OIDC and mobile are not live-support claims.
The school's sanitized expiry diagnosis and deployed automatic recheck are
complete. The owner confirmed successful execution and receipt of the authorized
single test message on October 14 UTC. This is operator-observed delivery;
no SMTP response log was supplied. Scheduled expiry-reminder delivery remains
unverified, and SMTP authentication alone does not prove that scheduling.

The frontend reorganization is merged and published in beta.12 through
[PR #17](https://github.com/KKazuhaK/canvas-mcp/pull/17). Its complete CI and local
rendered mock evidence are recorded below and in [UI-REDESIGN.md](UI-REDESIGN.md).
Deployed beta.12 home/token/admin pages, the local-owner safeguard and existing
Code/web client reads were inspected after the operator's update. The provider
list/editor and action-button usability feedback led to the PR 19 refinement.
The owner authorized one test message to a privately supplied recipient and
confirmed command success and receipt. No second message is authorized or sent.
Direct server execution remains unavailable.

### Sender-name follow-up

The owner requested a customizable email sender name after the delivered test
message showed only the address. The implementation candidate adds **Sender name**
to the database-owned mail settings, defaults to **Canvas MCP**, and restores
that default when saved blank. Unicode names use a structured From header;
control/hidden characters and oversize names are refused. The setting is stored
once in `settings` as `notifications.sender_name`; the existing SMTP JSON and
sealed password remain unchanged. Existing rows obtain the normal setting
default without a data backfill or schema migration. Compose/env are unchanged.
This candidate is not yet merged, released or inspected on the deployed site.
Local validation passed 100 focused mail/settings/boundary tests, 531 frontend
tests, type checking, lint and production asset checks. In the rendered local
mock, English custom-name saving and Chinese blank-name reset succeeded; the
390-pixel Chinese form has no document-level horizontal overflow. These are
synthetic local observations, not an additional outbound mail or deployment.
The complete local selfhost suite also passed 4,347 tests with 54 platform or
database-dependent skips; PostgreSQL coverage still requires the CI matrix.

### Shared remote connector acceptance

On October 13, the owner clarified that Desktop and claude.ai use the same
remote connector and accepted their shared remote-service path without a
duplicate Desktop tool call. This supersedes the separate Desktop-call gate
in earlier checkpoints. Existing web OAuth, discovery and successful read
evidence remains the basis of this acceptance; no new Desktop interaction is
claimed. Its UI and application build were not separately tested. Claude Code
has separate real HTTP-client observations, and mobile remains unverified.

### Implementation inventory

The native runtime, required React UI, database-owned configuration, custody,
maintenance, pagination, reserved contracts, operator/Docker guides, historical
proposals and optional pilot profile are merged into `selfhost` through
[fork PR #5](https://github.com/KKazuhaK/canvas-mcp/pull/5), at
`b739665ef0fc8e146e0c4d13aead964efb322d66` (2026-10-11).
Upgrade, transfer, backup and compatibility code lives only in
`core/selfhost/db/migrations/`, with four structural boundary tests and three
lazy startup/CLI bridges. Its README explains how to remove the package later.

The two-file deployment and database-storage guard are merged through fork
[PR #6](https://github.com/KKazuhaK/canvas-mcp/pull/6) and
[PR #7](https://github.com/KKazuhaK/canvas-mcp/pull/7). The complete reviewed
[CI matrix](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38189360639)
passed at `105706fa9beba38a0f185ea20fdc1527b5b422ae`; the final squash merge
`ab64798f7c6fcb7606dee7182de1e872f3ae292d` has the identical file tree.
Post-merge focused checks passed 114 tests with five platform/database skips.
The separate post-merge full matrix also passed in
[run 38190515625](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38190515625).
The [release image publication](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38190557563)
passed native amd64/arm64 container and actual Compose checks. GHCR index
annotations and each architecture's labels independently confirm the final
merge commit. The stable `latest` digest remains unchanged.

The owner supplies staging and reverse-proxy deployment; real IdP/B2B/client,
proxy and multiday refresh acceptance remain required. The owner approved
`v1.14.0-beta.3` for staging before those live checks, superseding the initial
first-tag timing gate. The development/publishing branch is `selfhost`, while
`main` remains the upstream mirror. New version names carry no school suffix.
Upstream PR #490 still awaits maintainer review. The maintainer approved #491
and #494 and requested fresh branches. Both were updated from upstream main
`7c4229c` on October 12, with their reviewed source/tests unchanged; complete
application CI and required checks passed for
[#491 at ca2563f](https://github.com/vishalsachdev/canvas-mcp/actions/runs/38322496722)
and [#494 at cf2c287](https://github.com/vishalsachdev/canvas-mcp/actions/runs/38322500393).
The separate review-secret workflow remains unavailable on fork PRs. Their
updated bodies record local full-suite results and CI evidence; merge is left
to the upstream maintainer. The hosting stack is maintained independently on
the fork; these upstream-PR updates were not merged into `selfhost`. No
real-client compatibility row is marked passed.

`v1.14.0-beta.4` is published. The two-file deployment follow-up in fork PR #6
reduces initial configuration to the public origin and three Entra credentials,
defaults Compose to the beta image, and automatically persists separate random
encryption/session keys on the data volume. Native image smoke checks exercise
the actual Compose and minimal `.env`, operator CLI and container recreation.
Fork PR #7 also refuses inaccessible or non-regular database storage before
generating keys. Existing data without its original keys is never re-keyed.

Database-owned login registration and protected first-install setup are merged
through [PR #8](https://github.com/KKazuhaK/canvas-mcp/pull/8), at
`8147922dfa31b65d8cce70be5073f99f176edf8e`. A fresh deployment now needs only the
public origin in `.env`; Entra, Google, GitHub and OIDC credentials, enablement,
role names and ordering are managed in the database. Private expiring setup
authority, write-only sealed secrets, complete-policy validation, per-request
login generations and governed configuration checks cover initialization,
editing and in-flight callbacks. Owner mutations read current provider
enablement inside their transaction. All legacy environment adoption, export
and inventory checks remain in the removable migration package.

## Deployable staging image

The current prerelease is
[v1.14.0-beta.14](https://github.com/KKazuhaK/canvas-mcp/releases/tag/v1.14.0-beta.14),
source `967011723af64f00f0287ea4760f61e1a71b85bb`, built at
`2026-10-14T19:57:43Z`. Both `:beta` and `:1.14.0-beta.14` resolve to:

`ghcr.io/kkazuhak/canvas-mcp@sha256:b01e5c8889d907f4d5bd8eb13c07fe58b6e16e32fae78198eea969b1b32a2c75`

The [reviewed-head matrix](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38552532301),
[complete post-merge matrix](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38624740657)
and [native release publication](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38628018415)
passed. Anonymous registry inspection confirmed the index annotations and both
amd64/arm64 labels match the source, version and build time. Stable `:latest`
was unchanged. The downloaded release assets match the source bytes and beta.11:

- Compose SHA-256: `91e193483bb76bd13879c02bdbd21c7d7e1aefede4db0bc5cd9d40fcbf192b9f`.
- Env template SHA-256: `4f0e1ff437d4d6b26943e0a6e8c2e2ef044f1fb9a5a2b2a5a6ed2af634f25075`.

No schema migration, credential rewrite, new system environment variable or extra
deployment file is required. The operator confirmed the upgrade; beta.14
version, health, automatic expiry and existing Code grant were verified below.

## Last observed deployed image: beta.14

The operator confirmed deployment. Public version and account footer identify
`1.14.0-beta.14`, source `967011723af64f00f0287ea4760f61e1a71b85bb`, built UTC
`2026-10-14T19:57:43Z`; health returned 200. A normal recheck of the existing
token completed without replacement, showing a calendar date and timestamp with
Canvas as the source. The unknown-expiry notice disappeared. The home summary
also displays the date; the manual date input remains absent. Reminder opt-in
is still off and the recipient blank, unchanged by this acceptance.

The existing Claude Code grant completed one read-only profile call at
`2026-10-14T21:33:13Z`, 127,439 seconds after the first successful read, with the
expected Canvas account and no renewed consent. No HTTP refresh trace was
captured; rotation, absolute TTL, grace and several days remain unproven.
After a recent administrator sign-in, the deployed provider list and Entra
editor were inspected in English and Chinese. Microsoft Entra ID and Local
account/localized type labels replace the lowercase internal captions; the
configured display names remain unchanged. Edit opens the intended provider and
the Entra callback remains unchanged. At a 390-pixel browser viewport, labels and
edit buttons remain usable without document-level horizontal overflow. The
original language and viewport were restored; no provider configuration was saved.
This responsive-browser inspection is not a mobile MCP-client support claim.
Actual mail delivery and other HANDOFF gates remain open.

### Earlier beta.13 observation

The operator confirmed the update. The public version endpoint and account footer
identify `1.14.0-beta.13`, source `272b114b803b51fb860f328c04669f43826cda92`, built
at `2026-10-14T10:06:36Z`; health returned 200. The expired administrator recent-login
check displayed the filled 40-pixel login-icon button. Clicking it entered the
normal sign-in flow and, after the owner completed organization verification,
returned to the original providers topic. Provider Edit controls, separated
appearance/connection/rules sections and saved-secret placeholder were inspected.
Own-account token actions have warning/error outlines and icons; Close dismissed
the drawer. No provider configuration, token or access policy was changed.

The existing Claude Code grant completed exactly one read-only profile call at
`2026-10-14T10:21:04Z`, 87,110 seconds after the first successful call, without
renewed consent. The expected Canvas account matched. This crosses one day;
several-day refresh rotation, absolute TTL and grace traces remain unproven.

The owner's bounded read-only server diagnosis returned 200, matching user and a
parseable expiry. Its visible mask exactly matched the submitted shard prefix
plus hint, but not the unsharded mask expected by beta.13. No token or identifiers
were disclosed. This establishes an expiry compatibility defect, not missing
school metadata. The correction below must be released and rechecked before
claiming that automatic expiry is working on this deployment. Mail delivery and
the remaining 6.12 gates are still outstanding.

### Earlier beta.12 observation

The latest public version observation identifies
[v1.14.0-beta.12](https://github.com/KKazuhaK/canvas-mcp/releases/tag/v1.14.0-beta.12),
source `12e28987049615bb3a632b8819642ebb9cb15e33`, built at
`2026-10-14T01:02:03Z`. Its immutable image is:

`ghcr.io/kkazuhak/canvas-mcp@sha256:e0b7e7f7931d4f7666b728ce08ed1563a3ff428f42ac6c9441e9dd2f3641c09e`

The operator confirmed the upgrade; the public version endpoint and account
footer match that source, version and build time. Health and both OAuth discovery
paths returned 200. Home/token pages retain automatic-only expiry and the existing
valid token with unknown expiry. Admin pages show Entra/local providers and the
protected local-owner entry point. Existing Claude Code and claude.ai connections
each completed one read-only profile call after the upgrade, without renewed
consent. The Code observation at `2026-10-14T07:41:50Z` was 77,556 seconds after
the first successful read; it does not prove several days, refresh rotation,
absolute TTL or grace behavior. SMTP delivery, unavailable B2B guest and the other
6.12 gates remain unverified. Compose/env asset hashes are unchanged.

## Historical beta.9 staging image

`v1.14.0-beta.9` was published on 2026-10-13 UTC from
`82fd81e0d001119c4cad1d7c1030833e52f2af0a`, the squash merge of
[PR #13](https://github.com/KKazuhaK/canvas-mcp/pull/13). The merge has the identical
file tree to reviewed head `b03c6a795e9a45dfab463c035b71139acefef4bf`.
The [reviewed-head matrix](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38342368893)
and [post-merge matrix](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38344422827)
passed, including all supported Python versions, Windows, latest/locked
PostgreSQL, web checks and both native Docker architectures on SQLite/PostgreSQL.
Each PostgreSQL group passed 90 preflight checks and 4,396 complete selfhost
checks (11 skips). Locked Linux passed 8,214 tests (65 skips), Windows 8,208
(71 skips), and the primary checkout 8,205 (74 skips). The UI passed all 498 tests;
the primary UI build and distribution checks passed too.

The [release image workflow](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38356178848)
passed on native amd64 and arm64. Anonymous registry inspection of the index and
both architecture labels confirmed source `82fd81e` and version `1.14.0-beta.9`.
Both `:beta` and `:1.14.0-beta.9` resolve to:

`ghcr.io/kkazuhak/canvas-mcp@sha256:d52daf0fc11b4957b295cae500f062e5b375caacb9fc312fa31eab1c9bc7bb4c`

Stable `:latest` remained
`sha256:9eeeaea8365ecad39ea02704b867f2dfae03521c229938ce78e8937fcbf1cdfb`.
The [prerelease](https://github.com/KKazuhaK/canvas-mcp/releases/tag/v1.14.0-beta.9)
contains only `docker-compose.yml` and `default.env` (save as `.env`). Downloaded
bytes match the repository blobs and the existing beta.8 deployment files:

- Compose SHA-256: `91e193483bb76bd13879c02bdbd21c7d7e1aefede4db0bc5cd9d40fcbf192b9f`.
- Environment template SHA-256: `4f0e1ff437d4d6b26943e0a6e8c2e2ef044f1fb9a5a2b2a5a6ed2af634f25075`.

The release adds database-managed browser duration (default 7 days), corrected
expired-session redirects, supported Canvas expiry discovery and active-token
rechecks, plus opt-in SMTP reminders. SMTP secrets participate in transfer and
rotation. Upgrade/adoption code remains isolated under migrations. Back up before
upgrading: the new sealed column raises compatibility floor to 3, and an older
image needs its matching database backup. No new environment values are needed.

The owner reported deployed labels matching the full source above and version
`1.14.0-beta.9`. Live account settings show 10,080 minutes and the protected local
administrator entry point. A session remained signed in beyond the old 15-minute
limit; seven elapsed days have not yet been observed. Reopening the old duplicated
basename return target and completing sign-in reached the correct account home.
An active-token recheck succeeded without replacement; this school's metadata did
not supply usable automatic expiry, so beta.9 retained its manual fallback.
The original claude.ai connector then completed one successful `get_my_profile`
call after upgrade, without interactive connector reauthorization or Canvas writes.
Personal results were not displayed. Health and both OAuth discovery endpoints
returned 200; the new notification API returned 401 without authentication.
SMTP configuration is being supplied by the owner; connection and actual delivery
remain unverified. Earlier beta.8 client observations below remain partial. B2B
guest, other client surfaces, account disablement, key rotation/proxy failure and
consecutive-day refresh acceptance remain outstanding. There is no available B2B
test guest, and no client compatibility row is promoted by this release.

## Historical beta.8 staging image

The earlier published staging release was
[v1.14.0-beta.8](https://github.com/KKazuhaK/canvas-mcp/releases/tag/v1.14.0-beta.8),
from `85ffeca785885efdfce83121c5004ef22df6c858` and
[fork PR #11](https://github.com/KKazuhaK/canvas-mcp/pull/11).
UPN edits are administrator-only, with fresh authentication, Origin/CSRF,
revision CAS, uniqueness, actor audit and target session/code/grant revocation.
Personal pages show a read-only UPN. SSO registration automatically chooses an
available trusted email or a unique system name under the admission policy.
Account UUIDs and immutable external identity ownership remain unchanged.

At least one independent active local administrator with a password and permitted
local login is retained once one exists. A remaining SSO owner cannot replace
that path. Disabling providers/accounts, changing method restrictions, unlinking
or deleting accounts cannot remove the final local administrator. A second local
administrator allows rotation. Owners can explicitly create a local administrator;
ordinary local accounts remain the default. Older SSO-only deployments show an
actionable warning without silently changing roles or assigning passwords.

Each provider registration can store/reset a bounded embedded PNG sign-in icon
in SQL. Home now says My account and login identifies Canvas MCP. Provider-neutral
issuer/subject binding, multiple OIDC instances, per-instance matching-email
association, account restrictions and audited SSO unlock continue to apply.
Product settings, provider credentials and the canonical public origin live in SQL.

Additive isolated revision 0004 adds icons and assigns unique names to previously
unnamed accounts. Existing ids, UPNs, hashes, roles and epochs are retained.
Frozen revisions 0001-0003 are unchanged; compatibility floor stays 2. Keep
.env and canvas-mcp-data with its keys, and retain a PostgreSQL backup before
upgrading. Returning to an older image requires the matching database backup.
All upgrade/backfill/backup/transfer code remains in db/migrations.

Deployment uses only
[docker-compose.yml](https://github.com/KKazuhaK/canvas-mcp/releases/download/v1.14.0-beta.8/docker-compose.yml)
and the complete [.env template](https://github.com/KKazuhaK/canvas-mcp/releases/download/v1.14.0-beta.8/default.env).
Existing deployments keep their files and run docker compose pull followed by
docker compose up -d --wait. No host/system environment variables are set.
Both beta and 1.14.0-beta.8 resolve to `sha256:6dbebfcada679750a0047461a088a21472bfe7475114b360b52611297cc0557e`;
linux/amd64 and linux/arm64 index/config labels confirm the source and version.

- Reviewed complete [CI](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38316757675)
  passed at bfc1012; the squash merge has the identical file tree. Local selfhost
  regression passed 4,257 tests with 54 platform/network skips. Frontend passed
  all 487 tests, with production typecheck/build/dist and Ruff/Linux mypy green.
- Independent post-merge [complete CI](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38319630025)
  passed every job, including Windows, Python 3.11-3.14, locked dependencies,
  both native PostgreSQL dependency sets and both native Docker architectures.
  Post-merge focused API/database, migration and documentation checks passed 81.
- Native [release image checks](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38321688858)
  passed SQLite/PostgreSQL smoke and actual Compose startup/recreation.
- Downloaded release asset SHA-256: Compose
  `91e193483bb76bd13879c02bdbd21c7d7e1aefede4db0bc5cd9d40fcbf192b9f`;
  env template `4f0e1ff437d4d6b26943e0a6e8c2e2ef044f1fb9a5a2b2a5a6ed2af634f25075`.
- Stable latest remains
  `sha256:9eeeaea8365ecad39ea02704b867f2dfae03521c229938ce78e8937fcbf1cdfb`.

The owner reports successful Entra tenant-member login and updating staging to
beta.8. After the owner's aaPanel proxy adjustment, October 12 live probes
confirmed 200 JSON at both OAuth discovery paths. Authorization metadata, MCP
resource and the unauthenticated POST /mcp 401 challenge agree on the HTTPS
origin and Canvas.Access scope. Health, provider discovery and the account UI
also return 200; Entra and local sign-in are offered.

Real Windows Claude Code 2.1.285 completed browser OAuth sign-in. Its
`claude mcp login` reported authenticated, and `claude mcp get` reported
Connected over HTTP. The connection is restricted to a temporary local project,
not the user's global MCP list. Actual get_my_profile execution is still
unverified: the attempted model request stopped with authentication_failed
because Claude Code's own model-account OAuth session had expired. This is
separate from the successful MCP OAuth ceremony. No Canvas write was attempted.
The tested-client row is Partial, not a compatibility claim.

On October 12 the owner supplied successful on-server inspect/check output:
revision 85ffeca785885efdfce83121c5004ef22df6c858, version 1.14.0-beta.8,
two active accounts, one observed owner, Entra/local providers, settings revision
8, and one connected app before the web-client test. Zero credentials/school
bindings at that point were expected fresh enrollment state, not data loss.
The check also reported an unknown-setting warning; a local regression identifies
that ConfigSnapshots treated the known login.account_policy row as unknown.
The follow-up validates that structured policy, rejects malformed values and
preserves redacted warnings for genuinely newer keys; no schema/data rewrite.

The owner then approved adding the claude.ai web connector and personally
completed consent. Claude's cloud discovery selected its published CIMD identity,
and the connected client exposed 48 read-only tools. A real get_my_profile call
without enrollment returned the expected missing-Canvas-token error. After the
owner saved a school/token and acknowledged custody, the live account UI confirmed
enrollment and a second real get_my_profile call succeeded. No Canvas write was
made; the chat response withheld personal profile fields. Web app build is not
exposed, so record surface/date rather than inventing a version.

The temporary Claude Code grant was then revoked through the account panel.
Its first subsequent CLI connection check changed from Connected to Needs
authentication; the panel retained the claude.ai grant. Its local test-project
MCP entry was removed afterward. Revocation UI wording in this follow-up uses
the next-request contract rather than the obsolete 30-second cache language.

Both real-client rows remain Partial: these results establish web consent/CIMD,
tool discovery, missing-credential refusal, successful Canvas reading and Code
grant revocation, but not the remaining B2B, other Claude surfaces, account
disable/key rotation/proxy failure and consecutive-day refresh gates. No full
compatibility claim is made. Later checkpoints do not change the beta.8 source.
Complete follow-up CI at 6f19941 and the documentation checkpoint at 9b4e20d
both passed; the beta.8 image is unchanged.

## Historical beta.7 staging image

The preceding published staging release was
[v1.14.0-beta.7](https://github.com/KKazuhaK/canvas-mcp/releases/tag/v1.14.0-beta.7).
The account/login redesign is merged through
[fork PR #10](https://github.com/KKazuhaK/canvas-mcp/pull/10), with release source
`d19623918ffd458768973871e3573a248bb051e9`. Account UUIDs remain permanent;
one unique account UPN drives local login. Provider-neutral issuer/subject
ownership survives email changes and supports multiple OIDC registrations.
Each SSO registration independently opts into matching-email association,
without another mailbox challenge. Account method restrictions and SSO locks
take precedence. Audited administrator unlock preserves the original identity
and protects the final usable administrator.

PUBLIC_BASE_URL seeds SQL once. Later confirmed domain changes belong in
Settings, invalidate sessions/codes/grants, and require restarting the service
and updating proxy/provider callbacks. Contract migration 0003 preserves
account ids, local login names/hashes and existing identity aliases, and raises
compatibility floor to 2. All upgrade/adoption/backup/transfer code stays in the
isolated migrations package. Preserve the existing .env and canvas-mcp-data
volume. SQLite keeps an automatic pre-upgrade backup; PostgreSQL needs an
operator backup. Returning to an older image requires the matching old database.

Deployment still uses only
[docker-compose.yml](https://github.com/KKazuhaK/canvas-mcp/releases/download/v1.14.0-beta.7/docker-compose.yml)
and the complete [.env template](https://github.com/KKazuhaK/canvas-mcp/releases/download/v1.14.0-beta.7/default.env).
Existing deployments keep their files and run `docker compose pull` followed by
`docker compose up -d --wait`. No host/system environment variables are set.
The beta and 1.14.0-beta.7 image aliases both resolve to `sha256:b2eba17b179548d64489b7cb52734089258041f775a796ee0260641711c2f39b`;
native linux/amd64 and linux/arm64 labels identify the release source above.

- Reviewed complete [CI](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38289432633)
  passed on the identical pre-squash file tree, including 482 frontend checks.
- Independent post-merge [complete CI](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38293755401)
  passed all jobs. PostgreSQL latest and locked each passed 4,333 tests with
  eleven skips. Post-merge local migration/policy/origin checks passed 58 tests.
- Native [release image checks](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38296420627)
  passed SQLite/PostgreSQL container smoke and actual Compose boot/recreation.
- Downloaded release asset SHA-256: Compose
  `91e193483bb76bd13879c02bdbd21c7d7e1aefede4db0bc5cd9d40fcbf192b9f`;
  env template `4f0e1ff437d4d6b26943e0a6e8c2e2ef044f1fb9a5a2b2a5a6ed2af634f25075`.
- Stable latest remains
  `sha256:9eeeaea8365ecad39ea02704b867f2dfae03521c229938ce78e8937fcbf1cdfb`.

The owner reported successful real Entra tenant-member sign-in on October 12.
Exact client/version, image and secret-free trace were not supplied, so this is
recorded as an owner observation, not B2B or MCP-client certification.
B2B/client/proxy and consecutive-day refresh acceptance remain pending.
The October 12 public probe returned 200 from /healthz but nginx HTML 404 from
both OAuth discovery paths under /.well-known/. Those paths must reach the
application before client acceptance. No production/client compatibility row
is marked passed. This release source is the tested merge commit; later
documentation checkpoints do not change that immutable source or image.

## Historical beta.6 staging image

The preceding published staging release was
[v1.14.0-beta.6](https://github.com/KKazuhaK/canvas-mcp/releases/tag/v1.14.0-beta.6).
Local accounts and selectable optional external login are merged through
[fork PR #9](https://github.com/KKazuhaK/canvas-mcp/pull/9), at
`3c6a4b2809a8f5493b9d145b89170c594b77f72c`. First installation creates a local
administrator and optionally configures Entra, Google, GitHub or generic OIDC.
Owners create regular local accounts in Settings. Passwords are salted scrypt
hashes in SQL; password changes invalidate sessions, unused authorization codes
and connected app grants. No public local registration is offered. The additive
`0002_local_credentials` revision remains in the isolated migration package;
the original nineteen-table baseline stays frozen.

Download only its
[docker-compose.yml](https://github.com/KKazuhaK/canvas-mcp/releases/download/v1.14.0-beta.6/docker-compose.yml)
and [.env template](https://github.com/KKazuhaK/canvas-mcp/releases/download/v1.14.0-beta.6/default.env),
save the template as `.env`, fill `PUBLIC_BASE_URL` and run
`docker compose up -d --wait`. `DATABASE_URL` is optional for an existing
PostgreSQL server. Existing deployments keep their `.env` and data volume,
then run `docker compose pull` and `docker compose up -d --wait`.
No host environment exports, setup script or manual internal-key generation are
required. Open `/account/setup`, use the private code from the container logs
and create the local administrator. Provider configuration belongs in the
browser and database. Existing initialized installations do not reopen setup
or gain a preset password.

The Compose default is `:beta`. For repeatable acceptance, optionally pin:

```dotenv
CANVAS_MCP_IMAGE=ghcr.io/kkazuhak/canvas-mcp@sha256:ee1facc05aef1067cd782c8049da5a33d3dbbd7ddc5a41e96e5da5bcfc59661b
```

- Source: `3c6a4b2809a8f5493b9d145b89170c594b77f72c`.
- Registry version: `1.14.0-beta.6`; platforms: `linux/amd64`, `linux/arm64`.
- Complete reviewed [CI matrix](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38221903221)
  passed. The squash merge has the identical file tree. PostgreSQL latest and
  locked each passed 4,295 tests; Linux Python matrix runs passed 8,112 tests.
  All 478 frontend tests passed. Local sign-in is exercised through real PKCE,
  consent, token exchange and MCP, with old access and refresh tokens refused
  after a password change. SQLite-to-PostgreSQL transfer verifies copied local
  credentials by authenticating on the destination.
- Independent post-merge [complete CI](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38224806048) also passed.
- Native multi-architecture [release image checks](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38224841039)
  passed actual Compose boot, initialization and container recreation. Registry
  annotations confirm the source and version; both beta aliases match.
- Downloaded release asset SHA-256: Compose
  `91e193483bb76bd13879c02bdbd21c7d7e1aefede4db0bc5cd9d40fcbf192b9f`;
  env template `79a8781d61206e55a0c4d95b82a351d93200a3905dff4bf8d099ed4396b30f24`.
- The pre-v1 stable image remains at
  `sha256:9eeeaea8365ecad39ea02704b867f2dfae03521c229938ce78e8937fcbf1cdfb`.

The observed staging installation was still uninitialized on October 12.
Its public OAuth authorization metadata path returned nginx HTML 404;
`/.well-known/` must reach the application before real client acceptance.

Deployment and live acceptance are pending. Record the staging origin, exact
client versions, timestamps and secret-free evidence in the README's tested-client
table. Follow its complete staging checklist, including Entra B2B guests,
separate users/schools, configured providers, custody, revocation and rotation,
both persistence backends, proxy failure/log redaction and consecutive-day
refresh. Keep production and client compatibility claims gated until these
observations are complete; a stable release also requires them. Earlier branch labels below use the current name;
commit IDs and historical release tags retain their original evidence.

## Historical account login redesign checkpoints

The checkpoints below record pre-publication work. The complete reviewed and
post-merge matrices and beta.7 publication above supersede their pending gates.

The next candidate adds permanent account UPNs, provider-neutral issuer/subject
ownership, per-provider opt-in automatic association, account restrictions and
audited SSO unlock. It also adopts the public origin into SQL with an explicit
domain-change/restart boundary. Existing beta.6 accounts and local hashes are
preserved by isolated contract revision `0003_account_login_policy`; older
images require restoration of their matching pre-upgrade database backup.

Local checks: 481 frontend tests, production build/dist checks, 166-source-file
mypy and Ruff passed. Focused regression checks passed 111 tests with nine
platform skips; 18 real-graph migration checks passed, including populated
beta.6 and conflicting canonical ownership rollback. Full selfhost regression,
native PostgreSQL CI and both Docker architectures remain required before
publication. Complete local selfhost regression passed 4,233 checks with 54
platform skips. Additional focused checks passed 32 account-policy/site-origin
checks, including case-insensitive UPN collision and a rename during password
verification. The account-unlock UI sends only its governed unlock request,
without deleting or linking identities. The initial Docker run exposed a smoke
assertion that omitted the canonical OAuth issuer's trailing slash; the corrected
assertion requires a new exact-head native image run. This candidate is not a
published deployment image yet.

The corrected native image boot/recreation passed on SQLite. Its PostgreSQL
startup exposed an explicit FK name exceeding PostgreSQL's identifier limit;
the runtime metadata and contract now share a shorter name. A portability
regression checks the contract's explicit constraint names before runtime.
The corrected schema/migration/account-policy checks passed 46 tests with seven
backend-only skips, and the real-graph migration suite passed all 19 checks.
Native PostgreSQL and final Docker CI remain required; superseded failed runs
were cancelled after recording their failures.

Both native architectures then passed actual SQLite and PostgreSQL Docker smoke.
The final association regression also covers Google entering an existing Entra
account through its saved mail-style provider login name after account UPN rename;
81 account-policy/link-store checks passed. A new exact-head full matrix is
required for that last runtime correction before publication.

The full PostgreSQL latest run passed 4,329 checks and exposed four fixture
failures: restarting via the whole-stack environment factory reset PostgreSQL
public, and transfer still expected compatibility floor 1. Restart checks now
reuse the running database target without resetting it, and transfer asserts
floor 2. Focused SQLite checks passed 20 tests with seven PostgreSQL-only skips.
CI runs the account/transfer/origin checks first on both PostgreSQL dependency
sets, followed by the unchanged full suite. The job allowance is 30 minutes;
an earlier slower runner reached the former 20-minute limit, while the complete
latest result took 15 minutes. Final exact-head CI remains the publication gate.

## Historical checkpoints

The sections below retain dated development checkpoints. Their earlier
unfinished-work descriptions and test failures are historical, superseded by
later checkpoints; they are not the current status.

## Completed prerequisite

P7 was independently reviewed, corrected and merged through fork PR #4. The
fork main line is `selfhost` at `3926f04934dc56cfd1f025cb4f37fb4e1168fa0b`,
including the upstream synchronization. Post-merge test workflow `38125252305`
and self-host image workflow `38125252313` passed. See `B0-REVIEW.md` for review
findings and validation. These images precede the v1 consolidation.

The approved upstream discussion cache fix is in upstream PR #494; the
course-policy cache boundary fix is in #491. Both await upstream maintainer
review. Fork deployment changes stay on the fork.

## Implementation branch

Continue in `.worktrees/v1`, branch `feature/v1-consolidation`. Its database
foundation checkpoint `484decb` is pushed to the fork. There are also unfinished,
uncommitted changes in that worktree; preserve them.

Implemented foundations:

- Frozen nineteen-table v1 DDL shipped inside the Python wheel, separately
  validated on SQLite and PostgreSQL. The baseline seeds only `server_state`.
- UUIDv7 generation and portable UUID, boolean, JSON and timestamp types.
- SQLite creation and connection policy, cross-thread pooling, a dedicated
  foreign-key-off migration connection with validation before commit, and a
  PostgreSQL governance gate before pool checkout.
- A ten-worker limiter for database offloading.
- Immutable, single-statement MCP and session snapshot readers, including
  caller ownership and immediate visibility of committed revocation and epochs.
- Typed database setting defaults, public provider-name validation, atomic
  revision CAS saves, in-transaction owner checks, operator actors and audit.
- JWT header epoch bounds and signature/claim validation before server-state
  reads. Invalid signatures and claims do not reach the database.

Routing and UI work in progress removes the proxy and server-rendered account
pages, requires the React bundle, and unifies provider routes and verified
Entra OIDC ceremonies with the other providers. Focused tests cover flow-cookie
binding, single use, refusal redirects, callback cookie clearing and official
SDK token exchanges. React validation passed 450 tests, type checking and a
production build before this checkpoint.

## Validation at this checkpoint

- SQLite foundation plus existing migration regression suite: 131 passed,
  3 skipped (PostgreSQL-only checks).
- Locked-dependency PostgreSQL foundation suite: 56 passed.
- JWT tests after the verification-order change: 106 passed.
- Source Ruff and Linux-target mypy passed (138 source files).
- A whole self-host test collection still reports imports of removed legacy
  interfaces. It is not green. Port their relevant security and lifecycle tests
  to the local authorization stack and JSON API; do not restore compatibility
  aliases just to make collection pass.

## Required work still outstanding

1. Finish transaction lock order, pagination and deletion around the ported
   repositories and stores. Bare UUIDs, frozen named rows, native JSON/hash types,
   credential AAD, generation guards and custody persistence are implemented.
2. Keep the single-read MCP and browser-session snapshots covered while
   finishing lifecycle operations. Their configuration revision now selects an
   immutable database-owned snapshot; steady requests perform no configuration
   read beyond that authoritative snapshot.
3. Complete remaining configuration integration: displayed-name denial messages,
   per-call Canvas address protection, CLI provenance and deployment examples.
   Provider order reconciliation, atomic CAS settings/school/name saves, the five
   admin API endpoints, React settings and headless commands are implemented.
4. Keep the custody API, single-read MCP check and bilingual required checkbox
   covered while completing the remaining API and configuration work. The
   current API, MCP and frontend validations pass, including re-acknowledgement.
5. Finish batch maintenance, deletion, reserved
   interfaces and keyset pagination; run the prescribed PostgreSQL races.
6. Port the remaining tests; pass complete SQLite/PostgreSQL and latest/locked
   dependency matrices, lint, typing, frontend and documentation checks.
7. Finish independent-fork framing, neutral deployment examples, client and
   pilot documentation, then build and smoke-test the consolidated Docker
   image. Merge the completed v1 through one fork PR.

The owner will deploy staging and configure the reverse proxy. Real IdP/B2B,
Claude-client, proxy and multi-day refresh checks require that staging and
remain gates for the first v1 tag. No v1 release has been published.

## Migration isolation

All upgrades and database transfer tooling now live under
`src/canvas_mcp/core/selfhost/db/migrations/`, including the dedicated migration
connections, CLI implementation, frozen DDL and revision graph. Normal engines
contain no migration connection methods. The package README lists the cleanup
boundary. Pre-v1 transfer dependencies are deleted. The v1 import snapshots
the source read-only, upgrades only the private copy and copies tables according
to lifecycle metadata. One target transaction includes DDL, streaming batches,
row-count checks and every sealed-value check. Transactional sequence restart
also rolls back on failure; the target keeps its own database identity.

The real migration graph, schema constraints, baseline and settings suite passed
63 checks on locked-dependency PostgreSQL. After relocating migration code, the
SQLite suite including engine and request-snapshot checks passed 71 checks with
2 PostgreSQL-only skips. The same relocated suite passed all 73 checks on
PostgreSQL. The built wheel contains the isolated package and byte-identical SQL
assets, with no modules at the former migration paths. Full runtime validation
is still outstanding.

## Runtime port and custody checkpoint

- Actual v1 repositories return frozen named records. Entities use bare UUIDv7
  ids; account generation and write-preference versions live on the account row.
  Consume-once login states use conditional `DELETE ... RETURNING`.
- The sealed-column registry covers all three encrypted tables, including
  reserved provider and Canvas OAuth app secrets. Startup probes and chunked
  rotation use that registry; custody and lifecycle metadata stay unchanged.
- The custody API refuses missing, false, non-boolean or stale acknowledgements
  before directory, DNS or Canvas calls and any write. Re-acknowledgement is
  idempotent and preserves the credential and its generation. Notice texts have
  reviewed hash pins for both languages.
- The combined latest-dependency SQLite foundation, repository, identity,
  migration, sealed, custody API and login-route suite passed 176 tests with
  10 PostgreSQL-only skips. The dedicated locked PostgreSQL migration, transfer,
  sealed and store suite passed all 46 tests. Linux-target mypy passed all 74
  self-host source files before the final custody wiring.
- Whole self-host collection still has 27 legacy-interface import errors.
  The remaining security tests must be ported; full runtime and Docker checks
  are not complete.

## Authenticated request checkpoint

- JWT verification is entirely independent of database reads. Its decoded
  result carries the authenticated signing epoch. Code exchange, replay sibling
  and refresh results carry the epoch read inside their own transaction; signing
  after commit does not consult a later epoch.
- `load_access_token` performs one grant/account/primary-credential/server-state
  query after signature and claim checks. A request-scoped frozen value feeds
  the account resolver, credential mount and tool gate. Every instance reads
  committed revocation, disablement and JWT epoch at the next request.
- A database outage after a previous successful request returns 503. The
  request context never reuses a previous snapshot. Expired custody notices
  block before decryption; acknowledgement restores access without replacing
  the credential or changing its generation.
- Write-tool preferences use a 4,096-entry LRU keyed by account and version,
  with one prefix read on a miss. Usage writes are deduplicated and only run
  when the snapshot's last-use timestamp is stale; steady requests issue one
  data query and no writes. The following configuration checkpoint completes
  revision refresh before credential checks.
- Latest-dependency SQLite: 132 JWT, grant and MCP checks passed; the complete
  token/refresh/revocation HTTP suite passed all 79 checks. Locked-dependency
  PostgreSQL: 173 JWT, grant, MCP, login, custody and snapshot checks passed.
  Before this request wiring, the combined PostgreSQL foundation/store/import
  suite passed all 186 checks. Source Ruff and Linux-target mypy passed, with
  76 self-host source files checked by mypy.
- The complete frontend suite passed 457 tests; type checking, production
  build and lint passed. Whole self-host collection finds 3,235 tests and 27
  remaining imports of removed interfaces; this is not a passing full suite.

## Database configuration checkpoint

- MCP requests use the settings revision from the same authoritative read before
  checking school availability or decrypting a token. Browser sessions use one
  account/status/role/epoch/revision query. Public routes probe the revision;
  unknown providers and methods still reject before database access.
- Configuration bundles are frozen and keyed by revision. A warm hit needs no
  query, a rebuild uses three joined reads, and mixed PostgreSQL READ COMMITTED
  revisions retry. DNS validation runs after the read connection is released.
  Failed validation keeps the previous bundle unmodified but refuses requests
  requiring the newer revision; a subsequent request retries.
- Provider reconciliation records the configured order without replacing edited
  names. Schools have no environment default, implicit picker selection or
  default-school DNS exemption. Private exceptions are explicit operator changes.
- The five owner settings endpoints apply recent-session, Origin, CSRF, closed
  JSON body and size checks. Governance transactions recheck the active owner,
  perform global revision CAS and record audit actions. Removing a school with
  search disabled requires confirmation of affected bindings; encrypted rows
  remain stored. Retention values are operator-only.
- Admin > Settings has bilingual name, school and search controls, address checks,
  ordering, reset, affected-binding confirmation, conflict reload and reauth.
  Headless `providers`, `schools` and `settings` commands share runtime repository
  methods. See [CONFIGURATION.md](CONFIGURATION.md).
- Latest SQLite configuration suite: 28 passed, including native CLI commands,
  immutable refresh, revision races, permission changes during DNS checks,
  readonly private flags, strict body limits and school-name round trips.
  API route/error parity is ported to the v1 stack and passes. Previous complete
  SQLite MCP and token/refresh/revocation run passed 113 checks before the final
  CLI and additional configuration tests.
- Locked PostgreSQL configuration/API/MCP/token-flow suite: 154 passed before
  the final cross-instance school recovery check; the final configuration and
  API contract suite passes all 30 tests, including that recovery check.
- Full frontend: 460 passed; the final settings UI suite passes all 5 tests
  including the added conflict reload interaction. Build/typecheck and lint passed. Source Ruff and
  Linux-target mypy pass (79 self-host source files).
- Current whole self-host collection: 3,034 tests collected and 30 imports of
  removed interfaces still fail. This remains an incomplete full runtime matrix;
  port those regression tests instead of restoring compatibility adapters.

## Bounded maintenance and deletion checkpoint

- Runtime cleanup now lives in `selfhost/maintenance.py`, separate from the
  removable `db/migrations/` upgrade/transfer package. The traffic scheduler is
  hourly and does not overlap a still-running pass. Each job has bounded,
  independently committed chunks, backend-specific budgets, PostgreSQL advisory
  try-locks and row selection with `SKIP LOCKED`.
- Deletion repeats its due predicate. Grants use separate revoked/expired jobs
  with 200-row chunks; refresh rows leave only by grant cascade. History walks
  primary keys and tolerates earlier clock-skewed records. Pending purge is a
  governance operation capped at 100 accounts, codes first, one audit each.
  SQLite housekeeping commits its vacuum/optimize transaction.
- Credential enrollment now locks an existing school with an upsert timestamp
  update. The PostgreSQL race caught the previous `DO NOTHING` parent race; both
  put-first and cull-first orders now pass. School deletion repeats reference and
  policy predicates.
- Disable/deny delete unused codes before account locks. Operator account deletion
  deletes all codes first, checks last usable/active owner protection, cascades
  children and records counts in a retained `account_deleted` audit entry.
  `token_admin accounts delete UUID` is available; the panel shows the new audit
  action in both languages. Tier-zero writes no longer have a governance variant.
- Locked PostgreSQL maintenance and first-exchange/school races: 23 passed.
  The preceding maintenance/store/configuration/race run passed all 63 checks.
  The broader authorization/edge/store run passed 117 checks before the two
  maintenance failures were fixed and independently revalidated. No PostgreSQL
  log entry reported a deadlock during these runs; the test server was stopped.
- Latest SQLite maintenance/store/configuration/token-flow/edge matrix: 148 passed,
  10 PostgreSQL-only skips. Frontend admin pages: 20 passed, lint passed. Source
  Ruff and Linux-target mypy pass (80 self-host files). See
  [MAINTENANCE.md](MAINTENANCE.md) for retention and operator deletion.
- Whole self-host collection now finds 3,058 tests with 30 old-interface import
  errors. This is still not a passing whole runtime matrix.

Next: finish reserved interfaces and the remaining lifecycle/lock audits;
port the remaining security suites and validate the complete matrix.
Keep every upgrade and transfer change inside `db/migrations/`. Docker/staging
and the first v1 tag remain outstanding.

## Pagination and isolated upgrade policy checkpoint

- Native keyset pages replace unbounded account, enrollment, history, audit and
  grant reads. Limits are 50 by default and at most 200; canonical opaque cursors
  bind the list/account/filter. Counts are independent SQL aggregates. Prefix
  lookups for names, identities and primary credentials only cover the current
  page. Secondary credential rows are visible without primary-token actions.
- The React lists append pages through Load more. Changing server filters resets
  pagination; loaded-name search states its scope. The native CLI streams full
  inventories through bounded reads and exposes history continuation separately
  from tab-separated output. Retained audit is readable after account deletion.
  Pre-v1 principal-key adapters and CLI forms/aliases are removed; account targets
  are canonical bare UUIDs. See [PAGINATION.md](PAGINATION.md).
- Every upgrade/backup/transfer helper, Alembic dependency probe, frozen baseline,
  revision template and future DDL policy is under `db/migrations/`. Runtime
  repositories contain no upgrade DDL. Structural boundary tests enforce that
  split; [the package README](../../src/canvas_mcp/core/selfhost/db/migrations/README.md)
  explains how to retire the tooling later.
- SQLite contract plans automatically back up before changing existing schema.
  The rebuild helper retains STRICT, WITHOUT ROWID, named checks, partial indexes,
  AUTOINCREMENT and the sequence high-water mark, even after the largest historical
  ID was deleted. PostgreSQL DDL uses dedicated NullPool connections; session
  migration locks remain held separately while flagged concurrent indexes run.
  INVALID indexes and completed indexes with a failed version update can be
  recovered. Nontransactional plans refuse dry runs/atomic import before changes.
  The production revision graph remains one frozen baseline; seeded temporary
  revision graphs exercise future behavior in tests.
- Latest-dependency SQLite foundation/configuration/maintenance/pagination/MCP/
  token-flow/API matrix: 301 passed, 15 backend-specific skips. Locked PostgreSQL
  equivalent plus native races: 322 passed, 2 SQLite-only skips. The migration,
  transfer and recovery-focused PostgreSQL run separately passed 29 checks with
  2 SQLite-only skips. Subsequent boundary/dependency-isolation checks: 11 passed.
  Those checks also found and fixed premature optional SQLAlchemy imports; base
  modes and the CLI again give the intended missing-extra behavior.
- Complete frontend: 468 passed. Production build/typecheck and lint passed.
  Source Ruff and Linux-target mypy pass (83 self-host source files), including
  the final dependency-import cleanup. Subsequent API/MCP/configuration/pagination
  runs passed 125 checks on each backend. Production dist checks passed. The
  scratch PostgreSQL server was stopped; its log showed no deadlock.
- Whole self-host collection: 3,100 tests and 30 imports of removed interfaces
  still fail, before the two additional structural boundary tests. This is not
  a passing full runtime matrix. Preserve the remaining security coverage while
  porting fixtures; do not restore deleted adapters to make collection green.
- Docker, deployment docs, remaining reserved-interface checks, full runtime
  matrix and the first v1 tag remain outstanding. Real IdP/Claude/multiday staging
  checks follow the owner's deployment; these local results do not satisfy them.

## Native regression ports and deployment preparation checkpoint

- Ported encrypted-token, credential status, write preferences and account
  governance suites to the native UUID/schema interfaces. Last-owner and
  enrollment/disable races remain covered. Known-corrupt credentials no longer
  prevent ordinary startup key probes, but every referenced key is still required
  and strict transfer verification still decrypts every value.
- SQLite native store matrix: 230 passed, 1 skip. Locked PostgreSQL equivalent:
  227 passed, 4 SQLite-only skips. The PostgreSQL server was stopped and its log
  had no deadlock. The later custody and authorization-flow matrix passed 55
  checks, including hashed codes and native retained audit actors.
- Replaced pre-v1 deployment settings, routes and smoke expectations. Compose
  requires an explicit reviewed image; a source-build override is available.
  The real Bash setup script passed 40 checks with 2 platform-specific skips.
  Docker/Compose structure passed 40 checks. A combined native store/deployment/
  route/migration-boundary checkpoint passed 378 checks with 4 skips before the
  final CI-only image-verification assertion was added.
- Vite's mock login now handles bare and provider-specific native routes. All
  five redirect variants were exercised over HTTP. Production build/typecheck,
  dist checks and lint passed. Ruff covers all source and tests; Linux-target
  mypy passes all 83 self-host source files.
- Upgrade, backup and transfer instructions and implementation remain together
  in [db/migrations/](../../src/canvas_mcp/core/selfhost/db/migrations/README.md).
  The normal deployment guide links to that removable package.
- Added read-only amd64/arm64 CI image build and smoke jobs with no registry
  publication. Docker is unavailable on this workstation: actual image build
  and container smoke must be confirmed by those jobs before Docker is ready.
- Whole self-host collection currently finds 3,319 tests and 25 removed-interface
  import errors. Remaining regression ports and the complete runtime matrix are
  required; this checkpoint is not a release or a passing full test suite.
  Real IdP, guest, Claude and multiday staging acceptance still follows the
  owner's deployment, and the first v1 tag remains gated by that acceptance.

## Enforced migration boundary and native request security checkpoint

- Every upgrade, backup, transfer, frozen revision and compatibility policy stays
  in `db/migrations/`. Only the documented `app.py`, `token_store.py` and
  `token_admin.py` bridges may import it. Boundary tests reject other callers,
  runtime metadata DDL, direct Alembic imports and revision re-encryption.
- Compatibility floor policy is now enforced for each revision before Alembic
  finalizes its transaction. Expand must preserve the floor; contract must raise
  it; unsupported floors refuse the upgrade. Rejected ordinary DDL and version
  markers roll back. Concurrent PostgreSQL DDL retains its explicit retry policy.
- Native request-context, credential-health, write-preference, local-claim and
  school suites pass 250 checks. The additional real account-disable/re-enable
  suite passes 10; revocation preserves enrollment, refuses old access/refresh
  tokens and leaves another user's grant usable. New native AAD tests cover all
  four binding fields, bit flips, moved seals and wrong-snapshot decryption.
- The latest SQLite combined checkpoint passes 303 checks with 11 skips. The
  preceding locked PostgreSQL request/migration/transfer checkpoint passed 285
  checks with 2 SQLite-only skips, including concurrent-index recovery and floor
  enforcement. The scratch server was stopped and its log had no deadlock.
- Retired the old adoption/account-migration suites, schema-4 fixtures/generator
  and obsolete PostgreSQL DDL snapshot, as required by the v1 design. Native
  schema, migration, transfer and AAD suites replace their applicable coverage.
- Read-only CI run
  [38147469848](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38147469848)
  built and container-smoked the image on amd64 and arm64 at `2267d82`. The smoke
  checks hardened fresh startup, React/API routes, OAuth metadata/challenge,
  public registration and startup refusal semantics. The dummy Entra tenant
  intentionally fails discovery closed; optional real-tenant start checks do not
  claim a real sign-in. Added a second smoke pass against the Compose-pinned
  PostgreSQL image; that additional container pass awaits its new CI run.
- Docker/Compose/route/smoke replay checks: 72 passed, 1 platform-specific skip.
  Source/tests Ruff and Linux-target mypy pass. Whole self-host collection now
  finds 3,597 tests with 16 removed-interface imports still failing. These ports
  and the complete runtime matrix remain required before merge/release. Real
  IdP/guest/Claude/multiday gates still follow the owner's deployment.

## Native login and Docker PostgreSQL checkpoint

- Read-only CI at `1fcd39f`,
  [38148498544](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38148498544),
  built amd64 and arm64 images and passed both SQLite and Compose-pinned
  PostgreSQL container smoke on each. The disposable CI database has no
  published port; the app loopback port is reachable over the CI bridge.
  Production Compose retains its internal database network. No registry image
  or tag was published.
- Ported credential generation, public-edge limits, login-state contracts,
  Entra-only native ceremonies, provider hardening and identity API tests.
  Coverage retains delayed health verdicts, generation changes, cache purges,
  strict Origin/CSRF, last-identity/last-owner protections, binding, callback
  replay checks and membership lookup failures versus actual admission loss.
  Browser failures now assert closed error redirects and absence of sessions.
- Native housekeeping now uses the authorization runtime's wall clock. This
  keeps expiration decisions consistent with grant/client creation, including
  the injected clock in real-stack tests; rate limiting still uses monotonic
  time. Legacy file-store cleanup assertions are replaced by native row limits
  and the bounded housekeeping suite.
- Combined SQLite checkpoint: 191 passed, 1 PostgreSQL-only skip. Locked
  PostgreSQL equivalents: 136 plus 56 passed across two focused runs. Both
  scratch runs stopped the server; their logs contain no deadlock. Source/tests
  Ruff and Linux-target mypy pass (83 source files).
- Whole self-host collection now finds 3,770 tests with 9 remaining imports of
  removed account interfaces. Continuing beyond those collection errors exposes
  additional old hash/storage/schema assertions in authorization suites. The
  full runtime/CI matrix remains incomplete; focused and container results do
  not satisfy it. Real IdP/guest/Claude/multiday acceptance and the first v1 tag
  remain gated on the owner's staging deployment.
- Upgrade, compatibility, backup and database transfer code remains isolated
  in `db/migrations/`; its structural boundary checks pass on both backends.

## Native authorization, React serving and provider navigation checkpoint

- The entire authorization package passes on SQLite: 983 passed, 4 skips.
  Locked PostgreSQL passes the authorization package plus migration boundary
  checks: 989 passed, 2 external-network skips. This includes real MCP SDK
  sessions, code/refresh replay, custody, request snapshots, native hash storage,
  login-state consumption, operator commands and the PostgreSQL concurrency
  gates. Its scratch server was stopped; the log contains no deadlock.
- Native authorization and React static-serving/sign-in checks: SQLite 232
  passed, 3 platform/backend skips; locked PostgreSQL 234 passed, 1 platform skip.
  Failure responses expose closed redirect codes and never provider prose.
- Startup configuration and metadata/code-epoch/CIMD checks: 208 passed,
  2 external-network skips on each backend. Startup requires the sole built-in
  authorization server; no removed mode, separate JWT secret, cached grant
  standing or HTML fallback is restored. JWT rotation's CLI output now describes
  refusal on the next request.
- Provider callback order, bootstrap standing, external identity, configuration
  and React chooser navigation checks: 199 passed on each backend. The locked
  PostgreSQL scratch server was stopped after the run. HTML chooser,
  language-toggle and identity-form assertions were retired with their removed
  production surface; applicable protocol checks now use native React/API paths,
  identity authorization stays covered by the native identity API suite, and
  localized rendering/icons stay in the frontend suite.
- Source/tests Ruff, formatting of changed Python files and Linux-target mypy
  pass (83 source files). The latest completed read-only image verification at
  `a856369` is [38149719136](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38149719136):
  amd64 and arm64 builds and SQLite/PostgreSQL container smoke pass. No registry
  image or release was published.
- Whole self-host collection finds 3,841 tests with 8 remaining imports of
  removed account interfaces. Other provider/account/operator regression ports
  and the complete runtime matrix remain required. Focused and container green
  results do not satisfy the full handoff; real IdP/guest/Claude/multiday gates
  still follow the owner's deployment.

## Complete native login regression and removable migration checkpoint

- The entire login package plus the four migration boundary checks passes on
  SQLite with both latest and locked dependencies: 921 passed, 1 optional
  external-network smoke skip. Verified Google, GitHub, generic OIDC and Entra
  sign-ins, approval, consent, MCP tool calls, refresh, admission loss, link
  conflicts, replay, unlink epochs, retained connected apps, owner governance
  and the operator identity commands all use the native runtime.
- Locked PostgreSQL passes the same login/boundary package plus migration policy
  and SQLite-to-PostgreSQL transfer: 939 passed, 3 skips (one optional external
  network check and two SQLite-specific backup checks). The scratch database
  was stopped after the run. The native migration/transfer checks validate
  compatibility floors, concurrent-index recovery, atomic import, seal failures,
  native types and sequence restoration.
- Upgrade, compatibility policy, backup and transfer implementation remains in
  `db/migrations/`. Boundary checks now also reject backup calls and SQL that
  disables foreign keys outside that package. Its README names the three
  removable startup/CLI bridges. The login runtime no longer accepts cookies
  missing their explicit ceremony purpose; no old-cookie adapter is added.
- Applicable old browser checks were ported to JSON responses and real provider
  callbacks. Identity-management CLI targets are canonical bare account UUIDs;
  old provider/`acct:` aliases are refused. Configured provider inventory is
  seeded explicitly in fixtures and cannot be invented from a missing or
  unreadable shell environment. The removed proxy's token-role demotion tests
  are retired; verified sign-in demotion and last-usable-owner protection remain.
- Source/tests Ruff, changed-file formatting, Linux-target mypy (83 source files)
  and whitespace checks pass. Read-only image run at `6faa945`,
  [38151987699](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38151987699),
  passed both native architectures and SQLite/PostgreSQL container smoke. The
  complete workflow is still red because the remaining legacy account suites
  have not been ported. No image or release was published.
- Whole self-host collection now finds 3,844 tests with the same 8 legacy
  account-interface import errors. Port their applicable lifecycle/security
  coverage to the native API; keep the complete CI matrix and staging gates
  outstanding. This checkpoint does not complete the full handoff.

## Native account APIs, lifecycle and audit checkpoint

- All eight removed-account-interface collection errors are eliminated. Native
  account fixtures use the actual authorization server, verified offline Entra
  callbacks, required React bundle and database-owned school configuration.
  Credential saves explicitly acknowledge custody; no HTML, old verifier,
  account-key or schema adapter is added to the runtime.
- Account/API, lifecycle, default Canvas HTTP checker and health-verdict
  regression: 321 passed on locked PostgreSQL. The scratch server was stopped.
  The selected account/rule/identity/race/audit/English/boundary checkpoint
  passes locked SQLite: 545 passed, 2 PostgreSQL-specific skips. Latest SQLite
  account/race/rule/boundary groups: 468 passed, 2 backend skips; native identity
  and audit groups: 77 passed. Additional locked PostgreSQL identity, audit,
  transaction races, rule, fixture and boundary checks: 223 passed.
- The production audit emitter now attributes a native bare account UUID from
  verified request identity. It preserves an explicitly named target of an
  owner action, excludes token cache keys and never appends school or credential
  data. Audit regressions cover these boundaries.
- Applicable legacy security coverage now uses the native API: real-CSRF
  disabled-session replay, disable/enable epochs, cookie claim validation,
  owner rechecks inside writes, admission, per-user rate budgets, school DNS
  rebinding and signed search choices, token identity-change confirmation,
  health-verdict invalidation, audit/history pagination and default HTTP token
  validation without redirect following. The old HTML-form parity test instead
  proves those retired POST paths cannot mutate a native account. HTML layout,
  radio/form and language-toggle assertions retire with that removed UI;
  localized rendering remains in the React suite.
- Concurrent approval/deny, sign-up limits, credential replacement, key rotation
  and last-owner role loss use real separate connections on both backends.
  PostgreSQL's row-conditional health write may finish against the old credential
  before a replacement locks that row; the regression verifies neither ordering
  can write a stale verdict to the replacement.
- Source/tests Ruff, changed-file formatting, Linux-target mypy (84 source
  files including the audit emitter) and whitespace checks pass. Upgrade,
  compatibility, backup and transfer tooling remains confined to
  `db/migrations/`; all four structural boundary checks pass.
- Full runtime/CI validation remains outstanding. Broader collection now works,
  but legacy repository-statement, startup, disabled-tool and whole-stack fixtures
  still need their native ports. Focused results do not complete the handoff;
  real IdP/guest/Claude/reverse-proxy/multiday gates follow the owner's staging
  deployment. No registry image or release was published.

## Complete native startup, operator and whole-stack regression checkpoint

- Remaining repository, startup, operator CLI, credential gate, disabled-tool
  and whole-stack regressions now exercise canonical native accounts and the
  actual local authorization server. Two-user MCP tests include verified Entra
  login, custody, encrypted PAT storage, CSRF, course-cache isolation, refresh
  rotation/replay, PKCE, disable/enable epochs, credential replacement and
  cross-account confirmation refusal. Legacy HTTP and stdio checks remain.
- Write preference tests use the committed database version, with no TTL or
  timed revocation assumptions. A new committed version reloads preferences;
  concurrent reads cannot cache under a different version. Operator policy,
  user opt-in, course policy and disabled tools retain their separate checks.
- The root security registry tests use native verified identity and request
  snapshots. Only the authenticated JSON account API delegates preference writes
  to the account core. The static token scan excludes public schema constraint
  names and the RFC 9207 discovery field; it still checks other long literals.
- Retired proxy/HTML/TTL assumptions are replaced by their native security
  contracts, rather than adding runtime adapters. Provider/admission and token
  family coverage remains in the complete login and authorization suites.
  Database CLI tests explicitly refuse pre-v1 sources without adoption or data
  changes. Native v1 transfer checks verify sealed values, source preservation,
  retained target identity, populated-target refusal and transactional rollback.
  Removed lossy import flags are refused.
- Three focused production fixes accompany these ports: a silent-switch
  preflight does not create an absent SQLite target; SQLite bootstrap redacts
  corrupt-driver errors through the normal store exception; a missing/invalid
  mandatory React bundle closes the store and exits with configuration errors.
- Complete self-host, root multi-user and FastMCP compatibility regression:
  4,155 passed, 48 backend/platform/network skips on latest SQLite and the same
  result on locked SQLite. Locked PostgreSQL startup/whole-stack/transfer group:
  290 passed, 2 SQLite-specific skips. Additional native database CLI, account
  CLI, gate and preference tests: 253 passed on locked PostgreSQL. Scratch
  servers were stopped after those groups. A complete PostgreSQL run is pending.
- Source/tests Ruff, changed-file formatting, whitespace checks and Linux-target
  mypy pass; mypy now checks all 149 source files. Upgrade/compatibility/backup/
  transfer code stays in `db/migrations/`, with four structural boundary checks.
- The complete repository and CI matrix, and the new Docker image checks, remain
  pending at this checkpoint. Real IdP/B2B, Claude, reverse-proxy and multiday
  acceptance follow the owner's staging deployment. No release was published.

## Reserved contracts and owner deployment walkthrough checkpoint

- Added the remaining declared seams from design 4.14: a frozen sealed
  Developer Key row and `CanvasOAuthAppRepo`, `ProviderConfigSource` with the
  immutable environment mapping used by the registry, `SessionStore` and
  `QuotaPolicy`. No Canvas OAuth, database provider-secret configuration,
  server-side session or quota implementation is activated. A real sign-in,
  PAT enrollment and local grant ceremony leave all three reserved tables empty;
  the reserved Canvas routes remain absent. Repository audits reject reserved
  inserts/updates outside transfer and seal rotation tooling.
- Added `OPERATOR.md`, linking the configuration and dedicated upgrade guides.
  It covers fresh Docker startup, Entra owner/B2B admission, proxy setup,
  database-owned schools, custody, offboarding, recovery and separate encryption/
  JWT rotation. The README and root README explicitly identify the independent,
  unendorsed fork. The four client rows start `Not tested`; version, date, tester
  and evidence are required for a recorded result.
- Public deployment and smoke examples now use `mcp.example.com`. The host test
  scans deployment files and the web guide against example domains, loopback
  addresses and an explicit public-service list without naming any owner's host.
- Latest SQLite login/reserved/migration checks: 923 passed, 1 external-network
  skip. Locked SQLite complete authorization/login/reserved checks: 1,902 passed,
  5 platform/network skips. Documentation/English/reserved checks: 41 passed.
  All 149 source files pass Linux-target mypy. The complete repository remainder
  at the preceding checkpoint passed 3,844 tests with 20 environment skips.
- Exact-head CI must rerun after these additions. Previous `7292fad` CI has
  passed both Docker architectures, Linux Python 3.11-3.14, locked dependencies,
  lint, frontend, code API, both PostgreSQL dependency sets and formal confirmation
  checks; Windows is still running. Live staging and release gates remain open.

## Foreground SQL observation reliability

- Complete CI at `7292fad` passed, including Windows, both PostgreSQL dependency
  sets and both Docker architectures, in run `38158443958`. The later reserved/
  operator additions at `876a535` passed all Linux interpreters, locked SQLite,
  frontend, lint, code API, formal confirmation and both Docker image checks;
  PostgreSQL and Windows were still running at the time of this note.
- The local locked PostgreSQL full collection ran 4,203 checks: 4,184 passed,
  14 skipped and 5 failed test assertions. Four observers counted concurrent
  housekeeping statements in foreground request SQL; the actual disable,
  pending, revocation and JWT epoch refusals were correct. The fifth asserted
  a workstation-dependent 100ms read deadline and observed 101.7ms. This run
  is recorded as failing, not as a complete passing local matrix.
- Hot-read query accounting now disables housekeeping scheduling only in that
  observer fixture. Real housekeeping remains covered by its own runner tests.
  The pool test proves a normal read completes while the governance writer still
  holds its lock, without a sub-100ms performance threshold. No production
  authorization or database behavior changed for these corrections.
- Corrected hot-read/pool/reserved/maintenance checks: 40 passed on locked
  PostgreSQL, with the scratch server stopped; latest SQLite: 38 passed and
  2 PostgreSQL-only skips. The new exact-head full CI run remains required.

## Historical proposals and UI residuals

- HANDOFF 6.8: the gateway draft is now `gateway-evaluation.md`, indexed with
  both Stage A records. Their banners state that the upstream pilot is not
  pursued, G1/G2 remain unmet, and the fork continues independently. The gateway
  comparison records the native selfhost decision and a frozen local diff at
  `ac5fe4f` against upstream `63f4222a`; external claims retain their original
  date and all UNVERIFIED markers. No reply on issue 484 was posted.
- HANDOFF 6.13: known audit detail enum values now have English and Chinese
  labels; unknown values and user text remain plain text. The language-switch
  regression verifies both translation and an unknown-value fallback. Chinese
  rate-limit wording is consistent. The expiry input leaves one calendar day
  for browser/server timezone differences, with server validation authoritative.
- Complete frontend: 468 tests passed; lint, TypeScript/build and distribution
  checks passed. Documentation, English-only and closing-keyword checks: 95
  passed. No migration or compatibility code was added outside the isolated
  `core/selfhost/db/migrations/` package.
- Remaining implementation review identified HANDOFF 6.6.1's optional pilot
  profile as still outstanding. Live staging and the first v1 tag remain gated.

## Optional pilot and final release notes checkpoint

- HANDOFF 6.6.1 is implemented as an opt-in profile, never the owner's default.
  It removes all three file-download tools, refuses off-Canvas download hops
  before requesting them, requires request-local course state and refuses write
  tools/code execution. Startup requires exactly one featured school and search
  disabled. Database-backed panel and CLI changes cannot widen those settings;
  incompatible out-of-process revisions refuse runtime snapshot refresh.
- A specific `pilot_profile_restricted` API error is included in the backend,
  typed frontend, mock status table and both languages. Operator failures name
  the profile without exposing input values. Documentation describes initial
  school configuration before enabling the optional profile.
- `[Unreleased]` now describes the final v1 behavior and breaking configuration,
  fresh-database, API, custody and Docker changes. Superseded pre-v1 development
  entries were removed from this pending release; published release history stays.
- Focused latest SQLite checks: 352 passed, 2 platform skips. Locked SQLite:
  356 passed, 2 skips, including the four migration-isolation checks. Frontend
  error/route/locale contracts: 30 passed; lint, build and dist passed. Ruff and
  Linux mypy passed all 150 source files. Docs/English/closing/migration checks:
  99 passed.
- The first local PostgreSQL configuration run passed 30 tests and failed one
  foreground SQL assertion because the engine observer included housekeeping.
  That single observer now disables scheduling before the login ceremony;
  independent housekeeping tests remain active. The corrected locked PostgreSQL
  configuration suite passed all 31 tests; the scratch server was stopped.
- Complete CI at `ac5fe4f` passed all jobs in run `38160020585`, including Windows,
  both PostgreSQL dependency sets and both Docker architectures. A new complete
  exact-head CI is required after these pilot/release-note changes. Live staging
  and first v1 tag gates remain outstanding; no v1 release has been published.

## Final error-code contract correction

- Full exact-head CI at `f5d3109` passed frontend, lint, code API, formal
  confirmation and both Docker architectures. Locked SQLite ran 8,018 passing
  checks with 63 skips and one failure: a second backend API error-code contract
  still expected the pre-pilot set. Linux Python 3.11 showed the same omitted
  `pilot_profile_restricted` value. Those runs are failing, not complete-green.
- The independent documented set now includes the intentionally added pilot
  refusal. Backend/frontend parity and the real pilot API's 409 refusal remain
  asserted. Complete account API, route/error contract and native configuration
  checks pass 294 tests on each of latest and locked SQLite. This changes the
  contract fixture only; all production pilot constraints remain unchanged.
- The next exact-head full matrix is required before merging the fork PR.

## PostgreSQL authorization-code replay lock order

- The PR full matrix at `af2a371` passed every job in run `38162626262`.
  Its independent push matrix `38162623339` failed locked PostgreSQL: one
  six-thread authorization-code exchange raised `DeadlockDetected`, alongside
  4,202 passes and 11 skips. A passing duplicate matrix did not justify merge.
- The former design exception (grant before code in a replay) was incorrect.
  A consume waiter can retain a PostgreSQL tuple lock while rechecking a used
  code. A replay holding the grant and then incrementing the code counter can
  cycle with that waiter. The exchange now explicitly locks the code record
  `FOR NO KEY UPDATE` after conditional consume and before any grant lock,
  including the replay path. Loading a code for validation remains read-only.
- A deterministic PostgreSQL regression pauses the replay before the grant lock
  and probes its code with NOWAIT. It failed on the old implementation because
  a competing writer could take the code; after the repair the probe gets
  `55P03`, proving code ownership before attempting the grant. The six-thread
  one-winner/grace-cap test now runs eight rounds; refresh families, disablement,
  code epoch and account deletion assertions remain intact.
- Corrected locked PostgreSQL races/epoch/deletion checks: 65 passed; scratch
  server stopped. Complete latest and locked SQLite authorization checks: each 990 passed,
  5 backend/network skips. Docs/English/closing/migration/SQL compilation:
  120 passed. Ruff, changed-source formatting and Linux-target mypy for all
  150 source files passed. A new complete exact-head matrix is required.


### Account sessions and expiry reminders — implementation checkpoint

- Browser duration is SQL-owned, defaults to 7 days, and keeps sensitive-operation
  reauthentication separate. Expiry redirects handle the production basename and
  reject duplicated-basename return targets, including old links.
- Token verification reads supported Canvas metadata; account-home notices link
  directly to replacement. Existing active tokens can explicitly re-check expiry
  without replacing their PAT or revoking their connected apps.
- SQL-owned SMTP settings and opt-in recipient preferences use independent hourly
  work, durable claims, bounded retries and redacted failures. SMTP secrets join
  the existing verified rotation registry. All adoption/upgrade code is isolated
  under migrations; floor 3 prevents older key tooling from handling this database.
- The final complete local suite passed 8,204 tests with 74 skips; the account UI
  passed all 498 tests. Ruff, Linux-target mypy, UI lint/typecheck, production build
  and distribution checks passed. Exact-head PostgreSQL, locked-dependency and
  native Docker CI were required before publication. The beta.9 release record
  above supplies their completed results and the subsequent live observations.
- On October 12, the original claude.ai connection made another successful, read-only
  `get_my_profile` call more than one hour after its first successful call, without
  interactive reauthentication or Canvas writes. This is an elapsed-time observation;
  refresh HTTP traffic was not captured. Consecutive-day validation is still pending.

### Automatic expiry only — implementation checkpoint

- Token enrollment and replacement no longer offer or accept a manually entered
  date. Only Canvas metadata drives home-page notices and SMTP delivery; unavailable
  metadata remains unknown, while explicit null expiration means no permanent
  expiry. Unknown and unlimited tokens remain usable but receive no expiry mail.
- Historical typed dates remain stored without rewriting account IDs, identities,
  token ciphertexts, credential generations or app grants. They are neither exposed
  as expiration nor selected/claimed by reminder workers. No schema or environment
  change is needed; existing migration history remains frozen and isolated.
- Local complete Python checks passed 8,202 tests with 75 skips before the last four
  additional state/notification regressions. The final expiry/reminder group passed
  all 31 checks; docs/English plus that group passed 64 checks. Complete UI checks
  passed 497 tests; the final token-view group passed 28 after two new state checks.
  Ruff, Linux-target changed-source mypy, UI lint, production build and distribution
  checks passed. The local Chinese form was inspected without the manual input.
- Exact-head PostgreSQL, locked-dependency and Docker CI remain required before
  deployment. The live beta.9 school check did not return usable automatic expiry;
  this observation must not be described as successful automatic discovery.

### Beta.10 deployment and automatic-expiry compatibility

- Beta.10 source is `446d2c22887e9d5735430365830f75cff6da6ef3`; reviewed and
  post-merge complete matrices passed, including both PostgreSQL dependency
  sets and native amd64/arm64 Docker/Compose checks. The release image index is
  `sha256:6301746f4fa197b86cbc473b6b9c8135d01bbc71fb9f241b8a196d556b3a09c8`.
- The operator confirmed the update on October 13. Live checks confirmed the
  automatic-only form, removal of historical typed dates from presentation,
  active-token recheck and another successful read-only claude.ai profile call
  through the existing connection without interactive OAuth reauthorization.
  No refresh HTTP trace was captured. This is not completed consecutive-day
  validation. SMTP connection, STARTTLS and authentication succeeded earlier;
  actual reminder delivery and B2B guest sign-in remain unverified.
- Automatic expiry remained unknown at this checkpoint. Canvas's current
  upstream serializer emits an exact `visible_token` mask instead of the
  documented `token_hint`; accepting only the latter was a compatibility gap.
  The new parser regression covers the real response shape while rejecting
  conflicting identifiers and other users. The deployed school's raw response
  was not inspected, so its exact failure cause remains unconfirmed.
- The next image embeds version, full source SHA and one UTC build timestamp
  shared across architecture builds. Account/sign-in footers, startup logs,
  `/api/v1/version` and OCI labels use that same stamp. Source builds honestly
  report `dev`, `none`, `unknown`. Deployment still uses only Compose and the
  existing env template. Operator update confirmations are accepted without
  repeatedly requesting Docker label output.

### Claude Code read-only acceptance

- On October 13, Windows Claude Code 2.1.285 completed a new real OAuth
  ceremony through the verified Claude CIMD identity and a loopback callback.
  The owner personally approved Canvas.Access. The client reported Connected.
- A Sonnet/low-effort call in a temporary project invoked exactly one
  `mcp__canvas_acceptance__get_my_profile` tool, received a non-error result and
  returned `PROFILE_READ_OK`, with process exit 0 and no permission denials.
  Built-in tools were disabled; only that read was permitted. No Canvas write
  or additional tool call occurred. Personal output was withheld; the raw local
  response was replaced with a non-sensitive event-count/result record.
- The endpoint was the operator-confirmed beta.10 deployment at this point;
  beta.11 was building and was not yet reported deployed. After the operator
  confirmed the upgrade, the version endpoint confirmed beta.11 and a second
  check at 10:17:37 UTC again returned `PROFILE_READ_OK`, with one successful
  profile tool call, exit 0 and no permission denials. It reused the same grant
  without an interactive OAuth ceremony. This is not proof of refresh rotation
  or consecutive-day operation. The temporary local project connection is
  retained for subsequent elapsed-time/refresh checks,
  without changing the global MCP list. Earlier beta.8 grant revocation remains
  separate evidence. This client row is Partial until remaining live gates pass.
- A further check completed on October 13 at 18:23:14 UTC, approximately eight
  hours after the first successful call. The existing grant again allowed exactly
  one `get_my_profile` call: process exit 0, one matching non-error result, expected
  Canvas user matched locally, no permission denials and `PROFILE_READ_OK`.
  The public version endpoint still confirmed beta.11 and source `af65c436bda3`.
  Raw profile output and client stderr were replaced with a sanitized local proof.
  This extends the observed session duration; no refresh HTTP trace was captured,
  so rotation, absolute expiry, grace handling and consecutive-day operation remain
  unverified. The existing connection remains available for later checks.
- Another check completed at `2026-10-14T00:08:55Z`, 50,381 seconds (about 14
  hours) after the first success. The same grant again completed exactly one
  matching `get_my_profile` call, with one non-error result, no permission denials
  and `PROFILE_READ_OK`. The sanitized proof confirms beta.11 and the same source.
  No new consent or refresh HTTP trace was captured. This extends the elapsed-time
  observation without proving rotation, absolute TTL, grace or consecutive-day use.

### Beta.11 release and live acceptance

- Reviewed head `e91631849c6b22c690cccd4034a89cf5490d0651` passed complete CI
  run `38374966678`. PR 15 merged as
  `af65c436bda3b9390c1923a877d4c340151cff48`; the merged tree matched the reviewed
  tree, complete post-merge CI `38378233262` passed, and the local source suite
  passed 8,230 checks with 74 skips. UI checks passed all 503 tests. Both latest
  and locked PostgreSQL jobs and native amd64/arm64 SQLite, PostgreSQL and
  Compose smoke passed. Image smoke also compared the installed version
  endpoint with OCI labels.
- Prerelease `v1.14.0-beta.11` was published on October 13 after release image
  run `38381338817` passed. The `:beta` and `:1.14.0-beta.11` image index is
  `sha256:7bd4ada1c0ba542b2ed97faaf9d78124b216b88a324e93be5dbfffa461e94f2b`;
  both architecture labels match the source SHA, version `1.14.0-beta.11` and
  UTC build time `2026-10-13T10:08:47Z`. Stable `:latest` was not moved. The two
  deployment assets remain Compose plus the complete env template, with no
  changes required to existing deployment or SMTP settings.
- After the operator confirmed the upgrade, `/api/v1/version` and the account
  footer showed those exact build values. Health and both OAuth discovery
  endpoints returned 200. The existing browser session remained usable and
  the active Canvas token recheck succeeded. Automatic expiry still displayed
  unknown. Accepting the upstream `visible_token` mask fixes a proven parser
  gap, but does not establish this deployed school's response or failure cause.
  A bounded read-only server diagnostic is prepared to report only status,
  field types and match booleans; no token, hint, URL, profile or raw response
  is to be included in acceptance evidence.
- Live expiry discovery and actual reminder delivery remain unverified.
  Desktop, B2B guest, consecutive-day refresh, proxy failure/log redaction and
  the remaining account-disable/key-rotation gates also remain outstanding.

### Frontend follow-up authorized in parallel

The owner originally requested a full usability reorganization after the remaining
HANDOFF tasks, then on October 13 explicitly allowed implementation in parallel
with the outstanding live checks. Retain the current major areas and use PSP as an interaction
reference. The current settings page stacks unrelated forms in one long view;
account rows combine several management actions; the home view repeats token
editing, mail settings and account-security forms. The implementation scope and
acceptance criteria are in [UI-REDESIGN.md](UI-REDESIGN.md). The implementation
candidate now includes topic navigation and retained drafts, focused token/reminder/
security pages, home connection/client summaries, local-account creation in account
management, selected-account/enrollment detail drawers, per-provider appearance/
configuration grouping, loaded-history filters and audit details on demand.

The API adds automatic expiry metadata to owner enrollment DTOs using the same
Canvas-only interpretation as the personal view. This does not initialize or alter
the database, replace stored credentials, or revive historical manual expiry hints.
All 8,236 Python tests passed locally, with 74 environment-dependent skips; the
API/contract/parity subset passed 279 checks. Ruff, Linux-target mypy (176 files),
TypeScript, UI lint and the production distribution checks passed. Existing list
action tests now use the selected-account workflow while retaining their original
request, CSRF, confirmation, refusal and reauthentication assertions.

An earlier full Windows UI run passed 522 checks. Later runs covering the expanded
525 checks encountered native worker exits, including a single-worker run; this is
not recorded as a full pass. Focused regression results and the final complete CI
matrix are required before merge. The project retains normal test isolation and
its two-worker CI command.

English/Chinese mock previews were inspected at desktop and 390-pixel mobile widths.
Provider-name saving retained an edited configuration across topic switches; a
selected-account policy retained its draft across detail tabs and saved with the
session-invalidation message; a synthetic token replacement cleared the input and
kept unknown expiry explicit; individual mock app revocation updated the list.
Home and account detail mobile widths matched their document scroll widths. Two
rendered issues were repaired: screen-reader-only table dimensions caused desktop
overflow, and the fixed app bar covered the detail drawer's mobile close button.
Saved account policies now stop displaying an obsolete unsaved marker.

These are local candidate checks, not new live HANDOFF evidence. The later release
checkpoint supersedes the publication gate; deployed-page acceptance remains open.

### Beta.12 frontend release checkpoint

- The final candidate `c6fca41752c92536fc1b88020d5585a1660c3ebc` passed complete
  CI `38487993088`, including 527 UI tests, 8,246 Linux Python tests, 8,240
  Windows Python tests and 4,426 checks in each PostgreSQL dependency variant.
  Native amd64/arm64 image checks and formal confirmation guards passed too.
  CI retained standard isolation and the two-worker UI command. The last two
  UI regressions cover explicit stale-revision recovery for SMTP and session
  duration forms without silently losing the unsaved draft.
- PR 17 merged as `12e28987049615bb3a632b8819642ebb9cb15e33`; its file tree
  matches the reviewed candidate. Full post-merge CI `38490456467` passed.
- Beta.12 was published at `2026-10-14T01:06:08Z` after release workflow
  `38493480057` passed. The registry stamp and downloaded two-file assets were
  verified as recorded above. No stable release was published.
- At publication, the latest observed public deployment was beta.11. The operator received
  the existing two Compose update commands. This historical publication checkpoint
  predates the later deployed beta.12 observations recorded above. Actual SMTP
  delivery and remaining live HANDOFF checks are still outstanding.

### Provider/action refinement checkpoint

PR 19 merged as `e5ea38ab67882cec2c69bfad07d064466740ab0c`, with the same file
tree as reviewed candidate `82975c86b4b08bf9823cfbd4f2716b3758aab47e`.
The complete candidate matrix `38535054974` passed 529 UI tests, 8,246 Python
tests per Linux version and 4,426 checks per PostgreSQL dependency variant,
including native amd64/arm64 image verification and confirmation guards.
The first post-merge matrix `38538075000` failed one Python 3.14 assertion in the
start-limit test; its dependent aggregate consequently failed. The test's clock
followed real time, so a scheduling delay could refill a token between draining
the bucket and the HTTP refusal check. A 250 ms delay reproduced the failure;
the corrected test passed ten rounds with the same delay and 26 related checks.
PR 20 merged the controlled-clock correction as
`272b114b803b51fb860f328c04669f43826cda92`, with the identical file tree to reviewed
candidate `aec85e5fb3021a31d9c18d1a40d1f26d02f24f8a`. Its complete candidate matrix
`38540596076` passed, including Python 3.14, 529 UI checks and both PostgreSQL
dependency variants. No assertion was removed or runtime limit altered. The
corrected post-merge matrix `38544069245` passed, including all 529 UI checks,
8,246 tests per Linux Python version, 8,240 Windows checks and 4,426 checks in
each PostgreSQL dependency set. Both native image checks passed too. Beta.13 was
published at `2026-10-14T10:12:23Z` from that reviewed/verified commit after native
release workflow `38547234225` passed. Anonymous registry inspection verified the
index and both architecture stamps; downloaded Compose/env bytes are unchanged.
Post-merge edge image workflow `38538075015` passed; both architectures carry
source `e5ea38ab67882cec2c69bfad07d064466740ab0c` and build time
`2026-10-14T08:51:13Z`. An edge build is not a published beta.13 release.

The refinement separates the provider list from the selected editor, groups
appearance/connection/sign-in settings and makes account actions recognizable
as buttons. Reauthentication has a filled icon-labelled button; secondary and
token-management actions have visible outlines. Confirmation, revision, secret
handling and local-owner guards remain in place. Synthetic desktop/mobile
English/Chinese dark/light previews exercised these controls. No live provider,
account policy, credential or grant was modified for those previews. The operator
updated to beta.13 and the deployed observations are recorded above.

### Sharded expiry and provider labels follow-up

The live diagnostic isolated an exact shard-prefixed visible mask mismatch.
Two timestamp/no-expiry regressions reproduced the rejection before the fix.
Discovery now accepts either the exact unsharded mask or the exact submitted
shard-prefixed mask. Other shards, other users, extra suffixes and conflicting
identifiers remain unknown. No credential generation, grant, schema or stored
manual date is changed. API enrollment is covered for both mask formats.

Provider lists show translated protocol names rather than lowercase internal IDs,
while retaining configured display names. Unnamed custom OIDC entries retain a
readable slug to distinguish multiple instances. Installation and provider-type
choices use the same labels. IDs, persistence and callback paths remain unchanged.
This candidate checkpoint predates the beta.14 publication recorded below.
Local full Python regression passed 8,244 checks with 74 environment-dependent
skips. Final expiry coverage passed all 36 checks. The full UI run passed 530
checks; subsequent narrow-layout/provider changes passed the 19 focused settings
checks, production TypeScript build, lint and distribution validation. English
and Chinese previews retain readable labels; the settled 390-pixel view has no
document-level horizontal overflow. The complete CI and release results below
supersede this candidate checkpoint's remaining publication gate.

### Beta.14 release checkpoint

[PR 21](https://github.com/KKazuhaK/canvas-mcp/pull/21) merged as
`967011723af64f00f0287ea4760f61e1a71b85bb`, with the same tree
`626a2257fb0744a5a17da7863462ed2e3418a836` as reviewed candidate
`c82b15f95ab553f4400407fc712253bebd09253c`. Complete candidate CI `38552532301`
and post-merge CI `38624740657` passed: 530 UI checks, 8,254 checks per Linux
Python variant, 8,248 on Windows and 4,434 in each PostgreSQL dependency variant
(11 skips each). Each PostgreSQL variant also passed its 115-check preflight.
The merged primary checkout passed 8,245 checks with 74 environment-dependent
skips; dotenv loading was disabled in that test process.

Native tagged workflow `38628018415` passed both architectures and manifest
publication. Beta.14 was published at `2026-10-14T20:01:04Z`; registry annotations
and both platform labels identify the release commit/version and build time
`2026-10-14T19:57:43Z`. Fixed and beta tags have the digest recorded above;
stable latest remains unchanged. Downloaded release assets contain exactly the
unchanged Compose and complete env template, with the hashes recorded above.

At publication, the public endpoint still reported beta.13. The operator has
received the existing two update commands and a request to recheck the stored
token after upgrading. Automatic expiry on the deployed site, mail delivery and
the other live HANDOFF gates remain unverified.
