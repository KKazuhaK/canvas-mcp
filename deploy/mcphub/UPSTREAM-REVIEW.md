# Canvas upstream review and fork release — 2026-10-26

## Release identity

The independent fork release is 1.14.1. It selectively ports upstream fixes;
it does not claim parity with upstream 1.16.0. The MCPHub template pins the
`v1.14.1` tag, enables the student profile, disables all writes and TypeScript
execution, and requires each user to bind their own Canvas URL and token.
Anteater is pinned to `v1.0.0-beta.2`,
application version 1.0.0-beta.2, with Node 24.21.0 as its runtime.

## Reviewed upstream

Reviewed upstream main: `cbf98ff` (2026-10-26), including release
[v1.16.0](https://github.com/vishalsachdev/canvas-mcp/releases/tag/v1.16.0).
The security port in [PR 32](https://github.com/KKazuhaK/canvas-mcp/pull/32)
is reused, with two subsequent fixes:

- `62bf534`, PR 535: match script/style closing tags using ASCII rules, so
  Unicode case-folding or whitespace lookalikes cannot expose hidden text.
- `a8fcd2a`, PR 542: decode arbitrarily long decimal HTML entities without
  Python's integer-string digit-limit failure, including course policy and groups.

The release also ports dependency, HTML/email parsing, accessibility read-back,
announcement-type validation, untrusted-content fencing and Node permission
hardening. Upstream educator features such as course-group creation and optional
submission-body listings remain outside this port.

## Version discovery and credentials

Canvas now supplies its application version explicitly to FastMCP for modern
MCP discovery and legacy initialization. An unnamed VCS `--from` specification
preserves the source pin and document extra without comparing the independent
fork to the upstream PyPI distribution. Older revisions report the framework
version through this fallback and must retain their named specification.

Hub selects the first explicit npx package for registry checks. The Anteater
source archive precedes Node in the launcher, so the application reports its
own version. A GitHub codeload archive avoids the deployed npm Git fetcher's
`GitFetcher requires an Arborist constructor to pack a tarball` error.

Preserve server names and personal env-slot declarations when updating an
existing Hub installation. Verify configured bindings and online status after
saving. Public visibility makes the server definition available to authenticated
users; each user's personal Canvas binding remains necessary.

## Verification

Regression tests reproduced the HTML-decoding failures and the incorrect MCP
version before the fixes. The focused HTML, version and OAuth compatibility
set passed 132 tests. Controlled real stdio clients verified separate identities,
48 read-only tools and the reported application version without production data.
Self-hosted SQL result annotations also resolve the existing whole-project mypy
failures without weakening the type-checker configuration. Full release checks
and build results are recorded in the release pull request and CI.
