# Client ID Metadata Documents of Claude

`claude-ai.json` and `claude-code.json` are the documents that Anthropic hosts at
`https://claude.ai/oauth/mcp-oauth-client-metadata` and
`https://claude.ai/oauth/claude-code-client-metadata`.

They are written from the facts recorded on 2026-10-08, when both URLs were fetched live through
FastMCP's SSRF-pinned fetcher (`tests/selfhost/authz/test_cimd_documents.py` documents the
facts it relies on): the `client_id` equals the URL, the method is `none`, `claude-ai.json` has one
redirect URI (`https://claude.ai/api/mcp/auth_callback`), grant types that include the jwt-bearer
type, and **no `scope`**; `claude-code.json` lists `http://localhost/callback` and
`http://127.0.0.1/callback` without a port. The human-readable names (`client_name`) were not
part of what was recorded and are plausible placeholders; no test depends on them.

They are not byte-for-byte copies. To compare them with what Anthropic serves today, run the
opt-in drift test, which needs network access:

    CANVAS_MCP_LIVE_CIMD=1 pytest tests/selfhost/authz/test_cimd_documents.py -k live

If the live documents differ in a field the tests use (redirect URIs, grant types, method,
scope), update the fixtures and the allowlist guidance in `deploy/selfhost/README.md`.
