# P7 independent review and integration evidence

Review date: 2026-10-11. Scope: `feature/p7-login-providers`, from `53b86dd` through the repair commit `be36a025190bd00bd1a8f7c20d93e3d149c8c5f8` and CI completion commit `e62deb9d72b5ea9edc2eb2672e223844a50cb64c`. The branch is published in the independent fork; fork PR [4](https://github.com/KKazuhaK/canvas-mcp/pull/4) targets `uci-student`.

## Findings and repairs

An independent, read-only review of the provider ceremonies, account admission, usable-owner checks, startup and operator commands found four additional defects. Each was reproduced with a failing regression on `53b86dd`, then repaired in `be36a02`:

1. Activating a pending bootstrap owner could retain rules-based admission. A later admission-rule change then stranded that owner. Bootstrap activation now grants personal bootstrap admission.
2. Promoting an ordinary rules-admitted account could leave its admission dependent on rules. Operator promotion now records personal operator admission, preserving any existing personal admission.
3. Using only the intersection of recorded and explicit provider lists could allow an unlink or disable that stranded the actual server's last usable owner. Both lists are now protected independently inside the same write transaction; the explicit operator override remains available.
4. Reusing an OIDC provider slug with a different issuer could count an unreachable identity as a usable owner. Startup now refuses that change when identities for the slug exist, names the setting without revealing its value, and directs the operator to use a new slug.

The final independent review found no remaining actionable implementation defect in these repairs. The earlier handoff findings F1-F4 also have regression evidence: F1/F2/F4 fail on `ae015d5`, and the Entra-only F3 bootstrap decision fails on `fcc2952`; the corrected tests pass on P7.

## Validation

- Exact P7 head: `e62deb9d72b5ea9edc2eb2672e223844a50cb64c`; its runtime code is unchanged from `be36a02`.
- GitHub CI run [38122566181](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38122566181) on `be36a02`: all required jobs pass, including Python 3.11-3.14, Windows, lock-pinned SQLite and PostgreSQL, web, code API, static checks and formal checks. The PR merge-head run [38122476644](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38122476644) also passes.
- The original CI PostgreSQL job used only `uv.lock`. Commit `e62deb9` adds separate latest/locked PostgreSQL jobs, retaining both in the required aggregate. The new policy regression fails on the old workflow; all 38 focused workflow/Compose checks pass after the change.
- Complete latest/locked SQLite/PostgreSQL matrix at `e62deb9`: all required jobs pass in PR run [38124092586](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38124092586).
- Local web: lint, typecheck, 451 tests, build and distribution checks pass. Root TypeScript code API: build and 96 tests pass.
- Local Ruff, Linux-target mypy (130 source files), and `uv lock --check` pass.
- The targeted repair and startup regression set passes. No live Canvas writes were made.

Interrupted local whole-suite attempts are not counted as successful runs. CI now supplies all four matrix cells rather than relying on local runs. Throwaway local PostgreSQL uses separate databases per runtime to avoid schema-reset interference; its durability settings are relaxed for test speed, so those runs do not establish crash durability.

## Merge and upstream synchronization

Fork PR 4 was merged at its reviewed head `e62deb9`, producing
`09c676e8f9fc10658e2a5cda3527aae97f195ffa`. Its tree exactly matches the tested
merge preview (`4af06d1e2e582e8b41f322a4039483d09a0b6927`). The seven upstream
commits through `63f4222` were then merged, producing
`3926f04934dc56cfd1f025cb4f37fb4e1168fa0b` on `uci-student`.

Post-merge CI [38125252305](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38125252305)
is fully green. Image run
[38125252313](https://github.com/KKazuhaK/canvas-mcp/actions/runs/38125252313)
passes amd64 and arm64 build/smoke checks and publishes the multiarchitecture image.
No v1 release tag has been created.

## Limits and deployment boundary

No live IdP, Claude client, reverse proxy or multi-day refresh test is claimed. The owner will deploy the prepared Docker stack and configure the reverse proxy. Live verification and the first v1 tag remain pending until that deployment is available.

The existing documented limitation concerning stale Entra role evidence remains: operator disable is the immediate offboarding control. This review does not establish that removing an upstream role alone immediately changes stored owner evidence.

## Upstream follow-up

- [491](https://github.com/vishalsachdev/canvas-mcp/pull/491): course-policy caller isolation at `4d60feb`, with controlled concurrency, credential changes and forbidden-write assertions. Revalidated locally: 3282 passed, 20 skipped; Ruff and Linux-target mypy pass. Evidence comment posted.
- [494](https://github.com/vishalsachdev/canvas-mcp/pull/494): discussion REST hint isolation at `0560f4b`. All 38 new cases pass; 23 fail on unpatched `63f4222`. Full local suite: 3276 passed, 20 skipped; Ruff and Linux-target mypy pass. Existing detailed audit body retained and validation updated after owner approval.
- [490](https://github.com/vishalsachdev/canvas-mcp/pull/490): no action pending maintainer review, as the handoff specifies.
- No reply posted on issue 484.
