# MCPHub runs Canvas and Anteater directly

The primary configuration is now `mcp_settings.example.json`: **stdio child
processes inside MCPHub's container**, with no independent Canvas or Anteater
container required for these Hub connections. Canvas uses personal credentials
only; Anteater has separate personal and shared entries.

Canvas users now bind their institution URL and token in **MCPHub Credentials**.
The existing Canvas website, school directory, account panel, token store, OAuth
consent and per-account write preferences do not participate in this stdio path.
No existing accounts or credentials are migrated or deleted. The supplied Canvas
entry explicitly permits no write tools or code execution. Removing a user's Hub
binding ends their personal runtime; changing the old Canvas website does not
revoke a separately bound Hub token. Revoke that token in Canvas itself when needed.

## Use the existing Hub image directly

Import `mcp_settings.example.json` into a stock Hub with Python >=3.11, uv/uvx,
Node/npm/npx and Git (provided by the upstream Dockerfile). Canvas is installed
from a pinned public Git revision using `uvx`. Anteater is installed from a pinned
Git revision using `npx` from a fixed GitHub source archive, which also provides Node 24 for the child process. This
works around the Hub image's default Node 22 without changing the Hub runtime.
Neither an extra service container nor a custom Hub image is required.

Keep outbound access and writable package caches for first startup. Cache reuse
makes later personal-process launches cheaper; first discovery can take longer
while packages download. Commands pin source revisions so they do not silently
follow a repository branch. Update pins deliberately after validation. These pins
run the published Git source, not uncommitted changes in a local checkout.

## Import and bind

The example is a complete **settings-file/API configuration**, not a promise
that every UI batch importer accepts all fields. The deployed Hub v1.1.10 batch
importer rejects `owner`, `credentialTemplate`, `idleTimeoutMs` and
`startOnDemand`, although its Add/Edit form supports personal slots. For that
version, configure personal entries through **Add/Edit > Advanced Options >
Per-user credential slots**; do not remove the template and import a personal
entry as a shared process. Alternatively, merge the definitions into the actual
settings file and reload using the deployment's supported procedure.

Merge the example's `mcpServers` into your existing Hub settings file.
Keep other server definitions. Do not overwrite the existing settings file or
replace users/groups while importing. Change `owner` if your administrator has
a different username.

- **canvas-personal**: each user binds `CANVAS_API_URL` (their institution HTTPS
  URL) and `CANVAS_API_TOKEN` (their own raw token). Both slots are required.
  Different users can choose different institutions. There is no shared account
  or fallback. The process uses the student profile and is explicitly read-only.
- **anteater-shared**: uses the Hub process variable `ANTEATER_SHARED_API_KEY`,
  passed to the child's `ANTEATER_API_KEY`. Users share its upstream quota. An
  empty shared key uses anonymous upstream quota. No personal binding is needed.
- **anteater-personal**: each user binds `ANTEATER_API_KEY`; the Hub starts a
  separate process for that user. Missing bindings fail rather than falling back
  to the public entry. Select the shared entry deliberately to use shared quota.

Use each person's own user-level Hub bearer key or user OAuth authorization in
their MCP client. Do not share the operator's system key. Personal stdio children
are isolated by user and credentials; the host/operator remains trusted.
`visibility: public` means all authenticated Hub users can discover the entry.
Use `visibility: group` / `sharedWithUsers` to restrict it to named friends.
Keep tool-result compression disabled and use normal group/server routes;
personal catalogs are not indexed by vector smart routing.

The upstream Canvas services may remain available to other clients. Stop their
containers only after verifying the new connections, and only if nothing else
uses their websites or HTTP endpoints. Direct stdio connections need no Canvas
OAuth callback URL. Hub's own downstream OAuth endpoints must still work if
clients authenticate to the Hub with OAuth; user bearer keys are an alternative.

## Optional: bundle both checkouts in a custom Hub image

`Dockerfile.hub` extends the upstream Hub image, installs this exact Canvas
checkout using its frozen Python lockfile, and copies the Anteater source from a
named build context. It includes Node 24 separately because the upstream Hub
Dockerfile currently installs Node 22, while Anteater requires Node >=24.
No unpublished npm package or same-named upstream Canvas PyPI package is used.
Only explicitly named source files enter the image; no `.env` or real keys are copied.

Requirements: Docker with BuildKit, Compose >=2.17 (additional build contexts),
and outbound access for the dependency/image downloads. You still run one Hub
container; it launches/recycles the individual stdio processes on demand.

Use `mcp_settings.bundled.example.json` with the bundled paths.

Use `compose.hub.yaml` and `hub.env.example` as references for your **existing Hub
deployment**. Preserve its real data mount, JWT/encryption secrets, auth/SSO
settings, port, networks and proxy configuration. Do not run a second instance
against the same data directory. Prefer adopting the `build`, `image` and
`ANTEATER_SHARED_API_KEY` entries into the current Compose service.

For a new deployment using the supplied example, save a private `hub.env` beside
these files, set absolute `ANTEATER_SOURCE_DIR` and `MCPHUB_DATA_DIR`, then from
the Canvas repository root:

```sh
docker compose --env-file deploy/mcphub/hub.env -f deploy/mcphub/compose.hub.yaml config --quiet
docker compose --env-file deploy/mcphub/hub.env -f deploy/mcphub/compose.hub.yaml up -d --build
```

For production, pin `MCPHUB_IMAGE` and `NODE_IMAGE` to reviewed digests. The example
uses tags so it can be built without inventing a deployment-specific digest.
The Hub data directory holds users, settings and credential encryption keys:
preserve the entire directory and any externally configured keys.


## Market and public submission

`market-manifest.json` is a **draft MCPM directory entry**, separate from the
multi-user Hub configuration. It pins a public Git source revision and uses
`uvx`; it does not depend on publishing this fork as the upstream `canvas-mcp`
PyPI package. The entry is named `canvas-mcp-kazuhahub` to distinguish the fork.
Check the pinned revision is still the intended release before submitting.

MCPHub currently reads `servers.json`; its Docker build downloads that catalog
from `https://mcpm.sh/api/servers.json`, falling back to its bundled file on
failure. Public inclusion therefore should target the MCPM catalog in
`pathintegral-institute/mcpm.sh`, `mcp-registry/servers/`, not only a change to
MCPHub's fallback file. Submit `canvas-mcp-kazuhahub.json` and validate against
MCPM's `mcp-registry/schema/server-schema.json` using its
`scripts/validate_manifest.py`. Maintainers review acceptance; no approval or
release-propagation time is guaranteed.

The current Market UI seeds command/args/env, not `credentialTemplate`.
Installing a catalog entry alone is not a complete multi-user configuration:
an admin must add both personal env slots and remove fixed token/URL values,
or import our prepared `mcp_settings.example.json` instead. Ordinary users bind
credentials; only administrators should install executable stdio definitions.
The draft's generic installation needs Python >=3.11, uv/uvx and Git.
The pinned source launchers have been checked locally; actual Hub Market
installation and per-user acceptance still require deployment verification.

A private Market can merge this draft into its full `servers.json` keyed by the
manifest's `name`, then mount the complete catalog at `/app/servers.json`.
Preserve existing entries. The generic catalog command downloads its pinned Git
source; to run the bundled local checkout, use the prepared stdio config instead.

No submission, package publication or remote deployment is performed by preparing
these files. Keep real tokens and private deployment domains out of manifests.

## Verification

Before switching clients, bind two different Canvas identities and verify
`get_my_profile` returns the corresponding person for each. An unbound user must
fail. Bind different Anteater keys and verify the personal/public quota selection;
removing one person's binding must leave other users unaffected. These are
read-only checks: never submit live Canvas writes for validation.

Both draft manifests passed the upstream MCPM validator. Both pinned Git
launchers ran locally. Two real Canvas stdio clients returned different personal
profiles and exposed 48 read-only tools against a local mock API; no live Canvas
requests were made. A Docker image build and real Hub multi-user acceptance must
be confirmed separately on a Docker-capable host.
For the earlier HTTP approach, see `mcp_settings.oauth.example.json` and
`mcp_settings.headers.example.json`; they still require the separate services.

## Verified deployed behavior

On the deployed Hub v1.1.10, the npm Git fetcher failed with
`GitFetcher requires an Arborist constructor to pack a tarball`. The configuration
therefore uses GitHub's `codeload.github.com/.../tar.gz/<commit>` archive for
Anteater, preserving the exact source revision without npm's Git pack step.
The public Anteater entry connected with 20 tools, 6 prompts and 4 resources.
The Credentials page exposed the required Canvas URL/token and Anteater API-key
slots. Actual personal calls still require each user's own binding. No live
Canvas credentials were entered during configuration.

## Version labels for pinned source installations

The stock Hub updater selects the first explicit npx package. Put the pinned
Anteater source archive before the Node runtime package so Node's version is not
reported as the server's version. The source archive is not an npm registry
package, so the Hub omits the registry update badge instead of inventing an
Anteater upgrade. Record the application version and source revision in the
server note. For Canvas, the v1.14.1 launcher uses an unnamed VCS `--from` specification
with `[documents]`. This release explicitly reports the application version in
the MCP handshake, so the Hub can display 1.14.1 without comparing the fork to
an unrelated upstream PyPI release. Do not apply the unnamed specification to
older fork revisions: those report the FastMCP framework version instead.

Prepare and test launcher corrections before changing live entries. Preserve
the server name and env-slot declarations and verify binding status afterwards.
Renaming while changing connection fields, or changing a personal OAuth server
definition, can require authorization again; never assume bindings survived.

## Official Hub with an independent Canvas Portal

For a Hub that follows official images without custom reminder code, restore this fork's self-hosted Canvas Portal and connect it as a personal OAuth upstream. The Portal stores Canvas tokens, manages user preferences and runs the existing email reminder worker. The official Hub only stores delegated per-user OAuth grants. See [the server deployment task](PORTAL-SERVER-PROMPT.md) and [trial connection template](mcp_settings.portal.example.json).

Start with a separate `canvas-portal` definition and verify two consenting users before replacing the existing `canvas-personal` stdio entry. Each user enrolls in the Portal and authorizes the Hub once. Existing Hub manual bindings are not automatically migrated; users enter their own token in the Portal. Unknown expiry and actual email delivery remain separate acceptance checks. Token rotation/revocation can require reconnecting a grant. Keep the official Hub and Portal versions independently pinned and retain both services' data and encryption keys.
