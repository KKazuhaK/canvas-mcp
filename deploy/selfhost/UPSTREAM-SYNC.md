# Selective upstream MCP and Canvas API synchronization

The owner permits selective upstream MCP/Canvas API updates. The selfhost stack
remains independently maintained. Review changes before porting; an upstream
merge is not authorization to replace fork behavior or weaken its safeguards.

## Scope

- Include MCP tools, Canvas API request/response behavior, privacy and permission
  fixes, and meaningful regression tests. Tool contract changes carry their
  matching documentation, manifests and required dependencies/integration when
  needed to make the MCP/API functionality work in this fork.
- Preserve selfhost accounts, authentication, provider policies, database,
  administration UI, Compose/env and release workflows. Review a shared-core
  change against selfhost integration tests rather than overwriting that code.
- Do not merge upstream main wholesale. Upstream triage records, hosted Azure
  configuration, unrelated workflows/dependency bumps and version metadata do not
  belong to this synchronization scope.
- Keep upgrade/migration code in `core/selfhost/db/migrations/`. A core port
  without a schema change needs no migration or data reset.

## Reviewed checkpoint

Upstream repository: `vishalsachdev/canvas-mcp`.
Previous common source: `63f4222a5838710806377ad05cb4eeed91796790`.
Reviewed main: `230a993ffe8c7c8c716b11dcd20a78754bec4616`.
Fork base: beta.15, `65d738c9ec740a0746134ea0a81054d1405dfcb5`.

| Upstream change | Port decision |
| --- | --- |
| [490](https://github.com/vishalsachdev/canvas-mcp/pull/490), `ee843f5` | Credential repr hiding already exists. Port value-semantics and outgoing-header regressions; preserve the current credential context. |
| [491](https://github.com/vishalsachdev/canvas-mcp/pull/491), `6b64885` / `4d60feb` | Port the controlled-transport regressions and prevent unverified HTTP requests from reusing/publishing course-policy verdicts. Preserve verified selfhost request-local and opt-in per-principal stores. |
| [494](https://github.com/vishalsachdev/canvas-mcp/pull/494), `0560f4b` | Port the controlled-transport regressions and prevent unverified HTTP requests from reusing/publishing REST-unservable hints. Preserve verified selfhost stores and stdio repeat-read optimization. |
| Triage and review-workflow changes through the reviewed main | Outside the MCP/Canvas API scope; not imported. |

The imported policy tests use this fork's existing `(principal, course)` cache
key representation when seeding/checking stdio entries. Their outgoing request,
denial, concurrent-order and no-write assertions are retained. No new tool,
manifest, API schema, database or deployment change is required.

Before the runtime port, the imported regressions exposed shared-map publication,
same-token stale policy decisions after Canvas revocation, and a token-less HTTP
request reusing a stdio grant. Retain a failing-before/passing-after record and
run both imported suites alongside the selfhost cache-mode, credential-generation
and principal regressions. The complete fork CI remains a merge gate. This
checkpoint records reviewed/ported source; it is not proof of live deployment.

For the next update, fetch upstream main and inspect the diff from the reviewed
main above. Check every relevant MCP/API change against this port and current
fork behavior. Record each included, already-equivalent or excluded change and
advance this checkpoint only after the corresponding tests and review pass.

## Publication checkpoint

PR 24 merged the core port as `b574eff52f8f6d2d4c557cf671a029290be5c498`.
Complete candidate CI `38668726987` and post-merge CI `38694340307` passed.
The imported regressions failed before the port; the final focused set passed
282 checks and the merged primary suite passed 8,343 with 74 environment skips.
The final upstream inspection also checked `992bb2c3396635daa3e6af1dfa09b349f79d00f8`:
its three additional commits only update `internal/issue-triage/2026-10-15.md`,
so they were excluded. Use that inspection as context, while retaining
`230a993` as the core port checkpoint above.

The port is published in beta.16 with the independently developed scrolling and
icon-storage changes, as recorded in [V1-PROGRESS.md](V1-PROGRESS.md).
Publication does not establish deployed acceptance or complete the live HANDOFF.
