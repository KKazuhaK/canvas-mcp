# v1 implementation progress

This is a working checkpoint, not a deployment or release approval. Follow
`V1-DESIGN.md` for the target and `DEVELOPMENT.md` for the complete handoff.

## Completed prerequisite

P7 was independently reviewed, corrected and merged through fork PR #4. The
fork main line is `uci-student` at `3926f04934dc56cfd1f025cb4f37fb4e1168fa0b`,
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

1. Replace the live legacy metadata, repository rows, store and Alembic graph
   with the v1 baseline. The new DDL and readers are tested foundations, but the
   running store still uses the old schema. Complete bare UUIDs, named rows,
   credential AAD, custody columns, row-local guards and transaction lock order.
2. Wire the one-read request snapshot into JWT, session and MCP paths; remove
   grant, account-standing and JWT-epoch TTL caches. Preserve immediate
   cross-instance revocation, disable, preference and settings semantics.
3. Implement provider reconciliation and immutable configuration snapshots;
   connect settings, schools and provider-name saves to the API, React and CLI.
4. Complete custody acknowledgement before any outbound enrollment probe and
   its version checks, audit and bilingual UI.
5. Finish batch maintenance, deletion, key rotation, transfer, reserved
   interfaces and keyset pagination; run the prescribed PostgreSQL races.
6. Port the remaining tests; pass complete SQLite/PostgreSQL and latest/locked
   dependency matrices, lint, typing, frontend and documentation checks.
7. Finish independent-fork framing, neutral deployment examples, client and
   pilot documentation, then build and smoke-test the consolidated Docker
   image. Merge the completed v1 through one fork PR.

The owner will deploy staging and configure the reverse proxy. Real IdP/B2B,
Claude-client, proxy and multi-day refresh checks require that staging and
remain gates for the first v1 tag. No v1 release has been published.
