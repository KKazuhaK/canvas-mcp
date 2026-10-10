#!/usr/bin/env bash
# Smoke test for the self-hosted image. Usage: smoke-test.sh IMAGE
#
# Boots the REAL entra-oauth mode with dummy (non-secret, throwaway) values and
# checks the externally visible contract, then the fail-closed paths and that
# legacy mode still boots. Nothing here talks to Entra or Canvas: the server
# does no network I/O at startup, and every request below is answered locally.
#
# CI runs it against the image built for each architecture BEFORE anything is
# pushed to the registry. Exit 0 means every check passed.
set -euo pipefail

IMAGE="${1:?usage: smoke-test.sh IMAGE}"

PORT=18819
BASE="http://127.0.0.1:${PORT}"
PUBLIC="https://canvas.example.test"
SUFFIX="$$"
MAIN="canvas-mcp-smoke-${SUFFIX}"
LEGACY="canvas-mcp-smoke-legacy-${SUFFIX}"
FAILCLOSED="canvas-mcp-smoke-fc-${SUFFIX}"
GENERATED="canvas-mcp-smoke-gen-${SUFFIX}"
REACT="canvas-mcp-smoke-react-${SUFFIX}"
REACT_BAD="canvas-mcp-smoke-reactbad-${SUFFIX}"
LOCAL="canvas-mcp-smoke-local-${SUFFIX}"
LOCAL_REACT="canvas-mcp-smoke-localreact-${SUFFIX}"
VOLUMES=()
WORKDIR="$(mktemp -d)"

cleanup() {
  docker rm -f "$MAIN" "$LEGACY" "$FAILCLOSED" "$GENERATED" "$REACT" "$REACT_BAD" "$LOCAL" "$LOCAL_REACT" >/dev/null 2>&1 || true
  local v
  for v in "${VOLUMES[@]:-}"; do
    [ -n "$v" ] && docker volume rm -f "$v" >/dev/null 2>&1 || true
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

dump_logs() {
  local c
  for c in "$MAIN" "$LEGACY" "$FAILCLOSED" "$GENERATED" "$REACT" "$REACT_BAD" "$LOCAL" "$LOCAL_REACT"; do
    if docker inspect "$c" >/dev/null 2>&1; then
      echo "----- docker logs ${c} -----" >&2
      docker logs "$c" 2>&1 | tail -n 80 >&2 || true
    fi
  done
}

fail() {
  echo "SMOKE TEST FAILED: $*" >&2
  dump_logs
  exit 1
}

ok() { echo "ok: $*"; }

# Sets NEW_VOLUME (not command substitution, so the cleanup list keeps it).
new_volume() {
  NEW_VOLUME="canvas-mcp-smoke-vol-${SUFFIX}-$1"
  docker volume create "$NEW_VOLUME" >/dev/null
  VOLUMES+=("$NEW_VOLUME")
}

# Dummy values only. The generated secrets live for this run and are never printed.
SIGNING_KEY="$(openssl rand -base64 48)"
SESSION_SECRET="$(openssl rand -base64 32)"
TOKEN_KEYS="k1:$(openssl rand -base64 32)"

# Environment for entra-oauth mode. CANVAS_TOKEN_KEYS is kept out of this list
# so the fail-closed check can omit exactly that one variable.
entra_env() {
  printf '%s\n' \
    -e MCP_AUTH_MODE=entra-oauth \
    -e PUBLIC_BASE_URL="$PUBLIC" \
    -e ENTRA_TENANT_ID=11111111-1111-1111-1111-111111111111 \
    -e ENTRA_CLIENT_ID=22222222-2222-2222-2222-222222222222 \
    -e ENTRA_CLIENT_SECRET=smoke-secret-not-real-0000 \
    -e OAUTH_JWT_SIGNING_KEY="$SIGNING_KEY" \
    -e ACCOUNT_SESSION_SECRET="$SESSION_SECRET" \
    -e CANVAS_API_URL="$PUBLIC" \
    -e CANVAS_ROLE=student
}

# Wait up to $2 seconds for container $1 to answer $3; fail early if it exits.
wait_for() {
  local name="$1" limit="$2" url="$3" i
  for ((i = 0; i < limit; i++)); do
    if [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || echo false)" != "true" ]; then
      fail "container ${name} exited before it became ready"
    fi
    if curl -fs -o /dev/null --max-time 3 "$url" 2>/dev/null; then
      return 0
    fi
    sleep 1
  done
  fail "container ${name} not ready after ${limit}s (${url})"
}

# ---------------------------------------------------------------- (a) non-root
uid="$(docker run --rm --entrypoint id "$IMAGE" -u)"
[ "$uid" != "0" ] || fail "image runs as root (uid ${uid})"
ok "image runs as uid ${uid}"

# ------------------------------------------------------- (b) boot entra-oauth
mapfile -t ENTRA_ENV < <(entra_env)
new_volume main
DATA_VOL="$NEW_VOLUME"
docker run -d --name "$MAIN" \
  --read-only --tmpfs /tmp \
  -v "${DATA_VOL}:/data" \
  "${ENTRA_ENV[@]}" \
  -e CANVAS_TOKEN_KEYS="$TOKEN_KEYS" \
  -p "127.0.0.1:${PORT}:8819" \
  "$IMAGE" >/dev/null
wait_for "$MAIN" 60 "${BASE}/healthz"
ok "/healthz answers"

# ------------------------------------------- (c) unauthenticated MCP -> 401
INIT_BODY='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"0"}}}'
code="$(curl -s -o /dev/null -D "$WORKDIR/mcp.headers" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data "$INIT_BODY" "${BASE}/mcp")"
[ "$code" = "401" ] || fail "POST /mcp without a bearer returned ${code}, expected 401"
grep -i '^www-authenticate:' "$WORKDIR/mcp.headers" \
  | grep -q "resource_metadata=\"${PUBLIC}/.well-known/oauth-protected-resource/mcp\"" \
  || fail "WWW-Authenticate lacks the expected resource_metadata"
ok "POST /mcp is 401 with resource_metadata"

# ------------------------------------ (d) protected resource metadata (RFC 9728)
curl -fsS "${BASE}/.well-known/oauth-protected-resource/mcp" -o "$WORKDIR/prm.json" \
  || fail "protected resource metadata not served"
python3 - "$WORKDIR/prm.json" "$PUBLIC" <<'PY' || fail "protected resource metadata has the wrong content"
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
public = sys.argv[2]
assert doc["resource"] == public + "/mcp", doc.get("resource")
assert doc["authorization_servers"][0].rstrip("/") == public, doc.get("authorization_servers")
PY
ok "protected resource metadata"

# ------------------------------------------ (e) authorization server metadata
curl -fsS "${BASE}/.well-known/oauth-authorization-server" -o "$WORKDIR/as.json" \
  || fail "authorization server metadata not served"
python3 - "$WORKDIR/as.json" <<'PY' || fail "authorization server metadata has the wrong content"
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert "S256" in doc["code_challenge_methods_supported"], doc.get("code_challenge_methods_supported")
assert doc["client_id_metadata_document_supported"] is True, doc.get("client_id_metadata_document_supported")
PY
ok "authorization server metadata"

# ----------------------------------------------------- (f) /account headers
code="$(curl -s -o /dev/null -D "$WORKDIR/account.headers" -w '%{http_code}' "${BASE}/account")"
[ "$code" = "200" ] || fail "GET /account returned ${code}, expected 200"
grep -i '^cache-control:' "$WORKDIR/account.headers" | grep -qi 'no-store' \
  || fail "/account lacks Cache-Control: no-store"
grep -i '^content-security-policy:' "$WORKDIR/account.headers" | grep -qi "frame-ancestors 'none'" \
  || fail "/account lacks CSP frame-ancestors 'none'"
grep -i '^x-frame-options:' "$WORKDIR/account.headers" | grep -qi 'DENY' \
  || fail "/account lacks X-Frame-Options: DENY"
ok "/account security headers"

# ------------------------------------------------------ (g) Host protection
code="$(curl -s -o /dev/null -w '%{http_code}' -H 'Host: evil.example' "${BASE}/healthz")"
[ "$code" = "421" ] || fail "request with Host: evil.example returned ${code}, expected 421"
ok "foreign Host header is refused (421)"

docker rm -f "$MAIN" >/dev/null

# --------------------------------------------------------- (h) fail closed
# A boot that cannot be trusted must exit, not limp along. `timeout` kills a
# server that wrongly keeps running; 124 is its "timed out" status.
expect_refusal() {
  local label="$1"
  shift
  local rc=0
  timeout 30 "$@" >"$WORKDIR/refusal.log" 2>&1 || rc=$?
  docker rm -f "$FAILCLOSED" >/dev/null 2>&1 || true
  if [ "$rc" -eq 0 ]; then
    cat "$WORKDIR/refusal.log" >&2
    fail "${label}: the server started instead of refusing"
  fi
  if [ "$rc" -eq 124 ]; then
    cat "$WORKDIR/refusal.log" >&2
    fail "${label}: the server kept running instead of exiting"
  fi
  ok "${label}: refused to start (exit ${rc})"
}

new_volume fc1
FC_VOL="$NEW_VOLUME"
expect_refusal "missing CANVAS_TOKEN_KEYS" \
  docker run --name "$FAILCLOSED" --read-only --tmpfs /tmp -v "${FC_VOL}:/data" \
  "${ENTRA_ENV[@]}" "$IMAGE"

new_volume fc2
FC_VOL2="$NEW_VOLUME"
expect_refusal "entra-oauth together with MCP_ACCESS_KEYS" \
  docker run --name "$FAILCLOSED" --read-only --tmpfs /tmp -v "${FC_VOL2}:/data" \
  "${ENTRA_ENV[@]}" -e CANVAS_TOKEN_KEYS="$TOKEN_KEYS" -e MCP_ACCESS_KEYS=x "$IMAGE"

# ------------------------------- (i) a .env written by setup-env.sh boots
# The operator path in README step 3: generate the file with the real script
# (dummy IDs, a throwaway secret on stdin, both opt-in flags) and start the
# image from it exactly as compose would, via --env-file.
SETUP_SCRIPT="$(cd "$(dirname "$0")" && pwd)/setup-env.sh"
GENERATED_ENV="$WORKDIR/generated.env"
# setup-env.sh prints only a summary without secrets, so its log is safe to show.
printf '%s\n' 'smoke-secret-not-real-0000' \
  | PUBLIC_BASE_URL="$PUBLIC" \
    ENTRA_TENANT_ID=11111111-1111-1111-1111-111111111111 \
    ENTRA_CLIENT_ID=22222222-2222-2222-2222-222222222222 \
    CANVAS_API_URL="$PUBLIC" \
    bash "$SETUP_SCRIPT" --enable-writes --real-names --output "$GENERATED_ENV" \
    >"$WORKDIR/setup.log" 2>&1 \
  || { cat "$WORKDIR/setup.log" >&2; fail "setup-env.sh did not write a .env"; }
new_volume gen
GEN_VOL="$NEW_VOLUME"
docker run -d --name "$GENERATED" \
  --read-only --tmpfs /tmp \
  -v "${GEN_VOL}:/data" \
  --env-file "$GENERATED_ENV" \
  -p "127.0.0.1:${PORT}:8819" \
  "$IMAGE" >/dev/null
wait_for "$GENERATED" 60 "${BASE}/healthz"
code="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/account")"
[ "$code" = "200" ] || fail "GET /account from the generated .env returned ${code}, expected 200"
docker rm -f "$GENERATED" >/dev/null
ok "a .env written by setup-env.sh boots (healthz, /account)"

# -------------------------------------------------- (j) legacy mode still boots
new_volume legacy
LEGACY_VOL="$NEW_VOLUME"
docker run -d --name "$LEGACY" \
  --read-only --tmpfs /tmp \
  -v "${LEGACY_VOL}:/data" \
  -e MCP_ACCESS_KEYS=smoke \
  -e CANVAS_API_URL="$PUBLIC" \
  -p "127.0.0.1:${PORT}:8819" \
  "$IMAGE" >/dev/null

legacy_code=000
for ((i = 0; i < 60; i++)); do
  if [ "$(docker inspect -f '{{.State.Running}}' "$LEGACY" 2>/dev/null || echo false)" != "true" ]; then
    fail "legacy container exited before it became ready"
  fi
  legacy_code="$(curl -s -o /dev/null --max-time 3 -w '%{http_code}' -X POST \
    -H 'Content-Type: application/json' \
    -H 'Accept: application/json, text/event-stream' \
    --data "$INIT_BODY" "${BASE}/mcp" || true)"
  [ "$legacy_code" != "000" ] && break
  sleep 1
done
[ "$legacy_code" = "401" ] || fail "legacy POST /mcp without the key returned ${legacy_code}, expected 401"
ok "legacy mode boots and rejects a missing access key (401)"
docker rm -f "$LEGACY" >/dev/null

# ------------------------------------- (k) ACCOUNT_UI=react serves the built app
# The image ships the React build at /app/web-dist; with ACCOUNT_UI=react the server
# must serve it at /account/ under the strict CSP, never cache the index, cache the
# hashed assets for good, answer deep links with the index, and protect the JSON API.
REACT_CSP="default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
new_volume react
REACT_VOL="$NEW_VOLUME"
docker run -d --name "$REACT" \
  --read-only --tmpfs /tmp \
  -v "${REACT_VOL}:/data" \
  "${ENTRA_ENV[@]}" \
  -e CANVAS_TOKEN_KEYS="$TOKEN_KEYS" \
  -e ACCOUNT_UI=react \
  -p "127.0.0.1:${PORT}:8819" \
  "$IMAGE" >/dev/null
wait_for "$REACT" 60 "${BASE}/healthz"

code="$(curl -s -o "$WORKDIR/spa.html" -D "$WORKDIR/spa.headers" -w '%{http_code}' "${BASE}/account/")"
[ "$code" = "200" ] || fail "GET /account/ returned ${code}, expected 200 (react UI)"
grep -i '^content-type:' "$WORKDIR/spa.headers" | grep -qi 'text/html' \
  || fail "/account/ is not text/html"
grep -i '^cache-control:' "$WORKDIR/spa.headers" | grep -qi 'no-store' \
  || fail "/account/ (index.html) lacks Cache-Control: no-store"
tr -d '\r' <"$WORKDIR/spa.headers" | grep -i '^content-security-policy:' | grep -qF "$REACT_CSP" \
  || fail "/account/ lacks the exact CSP (script-src 'self', frame-ancestors 'none', ...)"
grep -q 'id="root"' "$WORKDIR/spa.html" || fail "/account/ has no root element"
grep -q '/account/assets/' "$WORKDIR/spa.html" || fail "/account/ does not load /account/assets/"
ok "/account/ serves the built app with no-store and the strict CSP"

ASSET="$(grep -o '/account/assets/[A-Za-z0-9._-]*\.js' "$WORKDIR/spa.html" | head -n 1 || true)"
[ -n "$ASSET" ] || fail "the index does not reference a script asset"
code="$(curl -s -o /dev/null -D "$WORKDIR/asset.headers" -w '%{http_code}' "${BASE}${ASSET}")"
[ "$code" = "200" ] || fail "GET ${ASSET} returned ${code}, expected 200"
grep -i '^cache-control:' "$WORKDIR/asset.headers" | grep -qi 'immutable' \
  || fail "${ASSET} is not served immutable"
grep -i '^content-type:' "$WORKDIR/asset.headers" | grep -qi 'text/javascript' \
  || fail "${ASSET} is not text/javascript"
code="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/account/assets/does-not-exist.js")"
[ "$code" = "404" ] || fail "an unknown asset returned ${code}, expected 404"
ok "assets are immutable text/javascript; an unknown asset is 404"

code="$(curl -s -o "$WORKDIR/deep.html" -w '%{http_code}' "${BASE}/account/token")"
[ "$code" = "200" ] || fail "deep link /account/token returned ${code}, expected 200"
cmp -s "$WORKDIR/spa.html" "$WORKDIR/deep.html" || fail "deep link did not return the index"
ok "a deep link returns the index"

# A failed sign-in lands on the app's own sign-in page (a client-side route), which the
# server answers with the index too; the error code in the query is for the app alone.
code="$(curl -s -o "$WORKDIR/signin.html" -w '%{http_code}' "${BASE}/account/sign-in?error=provider_error")"
[ "$code" = "200" ] || fail "/account/sign-in returned ${code}, expected 200"
cmp -s "$WORKDIR/spa.html" "$WORKDIR/signin.html" || fail "/account/sign-in did not return the index"
ok "/account/sign-in returns the index"

# The sign-in itself stays a server-side redirect: /account/login is not the app's.
code="$(curl -s -o /dev/null -D "$WORKDIR/login.headers" -w '%{http_code}' "${BASE}/account/login?return_to=%2Faccount%2Ftoken")"
[ "$code" = "302" ] || fail "GET /account/login returned ${code}, expected 302"
tr -d '\r' <"$WORKDIR/login.headers" | grep -i '^location:' | grep -q '/oauth2/v2.0/authorize' \
  || fail "/account/login did not redirect to the identity provider"
grep -i '^set-cookie:' "$WORKDIR/login.headers" | grep -qi 'HttpOnly' \
  || fail "/account/login did not set the sealed HttpOnly login cookie"
ok "/account/login still redirects to the identity provider"

code="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}/account/api/providers")"
[ "$code" = "200" ] || fail "GET /account/api/providers returned ${code}, expected 200"
code="$(curl -s -o "$WORKDIR/me.json" -D "$WORKDIR/me.headers" -w '%{http_code}' "${BASE}/account/api/me")"
[ "$code" = "401" ] || fail "GET /account/api/me without a session returned ${code}, expected 401"
grep -i '^cache-control:' "$WORKDIR/me.headers" | grep -qi 'no-store' \
  || fail "/account/api/me lacks Cache-Control: no-store"
grep -q 'not_authenticated' "$WORKDIR/me.json" || fail "/account/api/me did not answer not_authenticated"
ok "the JSON API answers 401 not_authenticated with no-store"
docker rm -f "$REACT" >/dev/null

# ------------------- (l) ACCOUNT_UI=react with no usable build falls back to legacy
new_volume reactbad
REACT_BAD_VOL="$NEW_VOLUME"
docker run -d --name "$REACT_BAD" \
  --read-only --tmpfs /tmp \
  -v "${REACT_BAD_VOL}:/data" \
  "${ENTRA_ENV[@]}" \
  -e CANVAS_TOKEN_KEYS="$TOKEN_KEYS" \
  -e ACCOUNT_UI=react \
  -e ACCOUNT_WEB_DIST=/nonexistent \
  -p "127.0.0.1:${PORT}:8819" \
  "$IMAGE" >/dev/null
wait_for "$REACT_BAD" 60 "${BASE}/healthz"
code="$(curl -s -o "$WORKDIR/fallback.html" -D "$WORKDIR/fallback.headers" -w '%{http_code}' "${BASE}/account")"
[ "$code" = "200" ] || fail "GET /account with a missing build returned ${code}, expected 200"
grep -q 'Sign in with Microsoft' "$WORKDIR/fallback.html" \
  || fail "a missing build did not fall back to the legacy page"
if grep -i '^content-security-policy:' "$WORKDIR/fallback.headers" | grep -qi 'script-src'; then
  fail "the legacy fallback page was served with the app's CSP"
fi
docker logs "$REACT_BAD" 2>&1 | grep -q 'serving the legacy /account pages' \
  || fail "the fallback was not logged"
docker rm -f "$REACT_BAD" >/dev/null
ok "ACCOUNT_UI=react with a missing build serves the legacy pages and logs it"

# ----------- (m) SELFHOST_AUTH_MODE=local: the server is its own authorization server
# The default stays entra_proxy (sections b to l). Here the same image, with the same dummy
# values plus SELFHOST_AUTH_MODE=local, must publish its own metadata, refuse what it should
# without any sign-in, and not serve the proxy's routes.
new_volume local
LOCAL_VOL="$NEW_VOLUME"
docker run -d --name "$LOCAL" \
  --read-only --tmpfs /tmp \
  -v "${LOCAL_VOL}:/data" \
  "${ENTRA_ENV[@]}" \
  -e CANVAS_TOKEN_KEYS="$TOKEN_KEYS" \
  -e SELFHOST_AUTH_MODE=local \
  -p "127.0.0.1:${PORT}:8819" \
  "$IMAGE" >/dev/null
wait_for "$LOCAL" 60 "${BASE}/healthz"
ok "local mode boots (healthz)"

curl -fsS "${BASE}/.well-known/oauth-authorization-server" -o "$WORKDIR/local-as.json" \
  || fail "local mode: authorization server metadata not served"
python3 - "$WORKDIR/local-as.json" "$PUBLIC" <<'PY' || fail "local mode: authorization server metadata has the wrong content"
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
public = sys.argv[2]
assert doc["issuer"] == public + "/", doc.get("issuer")
assert doc["token_endpoint_auth_methods_supported"] == ["none"], doc.get("token_endpoint_auth_methods_supported")
assert doc["revocation_endpoint_auth_methods_supported"] == ["none"], doc.get("revocation_endpoint_auth_methods_supported")
assert doc["revocation_endpoint"] == public + "/revoke", doc.get("revocation_endpoint")
assert doc["code_challenge_methods_supported"] == ["S256"], doc.get("code_challenge_methods_supported")
assert doc["authorization_response_iss_parameter_supported"] is True
assert doc["client_id_metadata_document_supported"] is True
assert "offline_access" not in doc.get("scopes_supported", [])
PY
curl -fsS "${BASE}/.well-known/oauth-protected-resource/mcp" -o "$WORKDIR/local-prm.json" \
  || fail "local mode: protected resource metadata not served"
python3 - "$WORKDIR/local-prm.json" "$PUBLIC" <<'PY' || fail "local mode: protected resource metadata has the wrong content"
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
public = sys.argv[2]
assert doc["resource"] == public + "/mcp", doc.get("resource")
assert doc["authorization_servers"] == [public + "/"], doc.get("authorization_servers")
PY
ok "local mode: authorization server and protected resource metadata"

code="$(curl -s -o /dev/null -D "$WORKDIR/local-mcp.headers" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' \
  -H 'Accept: application/json, text/event-stream' \
  --data "$INIT_BODY" "${BASE}/mcp")"
[ "$code" = "401" ] || fail "local mode: POST /mcp without a bearer returned ${code}, expected 401"
grep -i '^www-authenticate:' "$WORKDIR/local-mcp.headers" \
  | grep -q "resource_metadata=\"${PUBLIC}/.well-known/oauth-protected-resource/mcp\"" \
  || fail "local mode: WWW-Authenticate lacks the expected resource_metadata"
ok "local mode: POST /mcp is 401 with resource_metadata"

UNKNOWN_CLIENT="00000000-0000-4000-8000-000000000000"
# A registration whose redirect is not on the allow-list is refused; a good one is a public client.
code="$(curl -s -o "$WORKDIR/local-reg-evil.json" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' \
  --data '{"client_name":"smoke","redirect_uris":["https://evil.example/cb"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}' \
  "${BASE}/register")"
[ "$code" = "400" ] || fail "local mode: /register with an evil redirect returned ${code}, expected 400"
grep -q 'invalid_redirect_uri' "$WORKDIR/local-reg-evil.json" || fail "local mode: /register did not say invalid_redirect_uri"
code="$(curl -s -o "$WORKDIR/local-reg.json" -w '%{http_code}' -X POST \
  -H 'Content-Type: application/json' \
  --data '{"client_name":"smoke","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}' \
  "${BASE}/register")"
[ "$code" = "201" ] || fail "local mode: /register with an allowed redirect returned ${code}, expected 201"
KNOWN_CLIENT="$(python3 - "$WORKDIR/local-reg.json" <<'PY' || true
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert doc.get("client_secret") in (None, ""), "a public client must not get a secret"
assert doc["token_endpoint_auth_method"] == "none", doc.get("token_endpoint_auth_method")
print(doc["client_id"])
PY
)"
[ -n "$KNOWN_CLIENT" ] || fail "local mode: /register did not return a public client"
ok "local mode: /register refuses an evil redirect and registers a public client"

# /revoke: an unknown client is invalid_client (401), a known one needs a token (400), and
# garbage is answered 200 whatever it is (nothing is revealed).
code="$(curl -s -o "$WORKDIR/local-revoke1.json" -w '%{http_code}' -X POST \
  --data-urlencode "token=garbage" "${BASE}/revoke")"
[ "$code" = "401" ] || fail "local mode: /revoke without a client returned ${code}, expected 401"
code="$(curl -s -o "$WORKDIR/local-revoke2.json" -w '%{http_code}' -X POST \
  --data-urlencode "client_id=${UNKNOWN_CLIENT}" --data-urlencode "token=garbage" "${BASE}/revoke")"
[ "$code" = "401" ] || fail "local mode: /revoke for an unknown client returned ${code}, expected 401"
grep -q 'invalid_client' "$WORKDIR/local-revoke2.json" || fail "local mode: /revoke did not say invalid_client"
code="$(curl -s -o "$WORKDIR/local-revoke3.json" -w '%{http_code}' -X POST \
  --data-urlencode "client_id=${KNOWN_CLIENT}" "${BASE}/revoke")"
[ "$code" = "400" ] || fail "local mode: /revoke without a token returned ${code}, expected 400"
code="$(curl -s -o /dev/null -w '%{http_code}' -X POST \
  --data-urlencode "client_id=${KNOWN_CLIENT}" --data-urlencode "token=garbage" "${BASE}/revoke")"
[ "$code" = "200" ] || fail "local mode: /revoke of garbage returned ${code}, expected 200"
ok "local mode: /revoke (invalid_client, 400 without a token, 200 for garbage)"

code="$(curl -s -o "$WORKDIR/local-token.json" -w '%{http_code}' -X POST \
  --data-urlencode "grant_type=authorization_code" --data-urlencode "code=cmcp_ac_nope" \
  --data-urlencode "client_id=${UNKNOWN_CLIENT}" \
  --data-urlencode "redirect_uri=https://claude.ai/api/mcp/auth_callback" \
  --data-urlencode "code_verifier=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" "${BASE}/token")"
[ "$code" = "401" ] || fail "local mode: /token for an unknown client returned ${code}, expected 401"
grep -q 'invalid_client' "$WORKDIR/local-token.json" || fail "local mode: /token did not say invalid_client"
ok "local mode: /token for an unknown client is invalid_client (401)"

# An unknown client is shown an error, never redirected anywhere.
code="$(curl -s -o /dev/null -D "$WORKDIR/local-authorize.headers" -w '%{http_code}' -G \
  --data-urlencode "response_type=code" --data-urlencode "client_id=${UNKNOWN_CLIENT}" \
  --data-urlencode "redirect_uri=https://claude.ai/api/mcp/auth_callback" \
  --data-urlencode "code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" \
  --data-urlencode "code_challenge_method=S256" --data-urlencode "state=smoke" \
  "${BASE}/authorize")"
[ "$code" = "400" ] || fail "local mode: /authorize for an unknown client returned ${code}, expected 400"
if grep -qi '^location:' "$WORKDIR/local-authorize.headers"; then
  fail "local mode: /authorize for an unknown client redirected"
fi
ok "local mode: /authorize for an unknown client is a 400 without a redirect"

# A sign-in request that does not exist (or is not this browser's) is refused before Microsoft.
code="$(curl -s -o "$WORKDIR/local-login.html" -D "$WORKDIR/local-login.headers" -w '%{http_code}' "${BASE}/account/login?txn=bogus")"
[ "$code" = "400" ] || fail "local mode: /account/login?txn=bogus returned ${code}, expected 400"
if grep -qi '^location:' "$WORKDIR/local-login.headers"; then
  fail "local mode: /account/login?txn=bogus redirected"
fi
grep -q 'opened in another browser' "$WORKDIR/local-login.html" \
  || fail "local mode: /account/login?txn=bogus did not explain itself"
ok "local mode: /account/login?txn=bogus is a 400 and never reaches Microsoft"

# The proxy's own routes are not served.
for path in /consent /auth/callback /.well-known/openid-configuration; do
  code="$(curl -s -o /dev/null -w '%{http_code}' "${BASE}${path}")"
  [ "$code" = "404" ] || fail "local mode: GET ${path} returned ${code}, expected 404"
done
ok "local mode: /consent, /auth/callback and the OpenID metadata are not served"
docker rm -f "$LOCAL" >/dev/null

# ---- (m2) local mode with the React UI and CIMD off: the API, the consent route, the metadata
new_volume localreact
LOCAL_REACT_VOL="$NEW_VOLUME"
docker run -d --name "$LOCAL_REACT" \
  --read-only --tmpfs /tmp \
  -v "${LOCAL_REACT_VOL}:/data" \
  "${ENTRA_ENV[@]}" \
  -e CANVAS_TOKEN_KEYS="$TOKEN_KEYS" \
  -e SELFHOST_AUTH_MODE=local \
  -e ACCOUNT_UI=react \
  -e CIMD_ENABLED=false \
  -p "127.0.0.1:${PORT}:8819" \
  "$IMAGE" >/dev/null
wait_for "$LOCAL_REACT" 60 "${BASE}/healthz"
curl -fsS "${BASE}/.well-known/oauth-authorization-server" -o "$WORKDIR/local-as-nocimd.json" \
  || fail "local mode (CIMD off): authorization server metadata not served"
python3 - "$WORKDIR/local-as-nocimd.json" <<'PY' || fail "local mode (CIMD off): metadata still advertises client metadata documents"
import json
import sys

doc = json.load(open(sys.argv[1], encoding="utf-8"))
assert "client_id_metadata_document_supported" not in doc, doc
assert doc["token_endpoint_auth_methods_supported"] == ["none"]
PY
ok "local mode (CIMD off): the metadata does not advertise client metadata documents"

code="$(curl -s -o /dev/null -D "$WORKDIR/local-react-login.headers" -w '%{http_code}' "${BASE}/account/login?txn=bogus")"
[ "$code" = "303" ] || fail "local mode (react): /account/login?txn=bogus returned ${code}, expected 303"
tr -d '\r' <"$WORKDIR/local-react-login.headers" | grep -i '^location:' | grep -q '/account/sign-in?error=authorization_invalid' \
  || fail "local mode (react): a request that is not this browser's did not end on the sign-in page with authorization_invalid"
ok "local mode (react): a bad sign-in request ends on /account/sign-in?error=authorization_invalid"

TXN="$(printf 'A%.0s' $(seq 1 43))"
code="$(curl -s -o "$WORKDIR/local-consent.html" -w '%{http_code}' "${BASE}/account/consent?txn=${TXN}")"
[ "$code" = "200" ] || fail "local mode (react): /account/consent returned ${code}, expected 200 (the app)"
grep -q 'id="root"' "$WORKDIR/local-consent.html" || fail "local mode (react): /account/consent is not the single-page app"
if grep -q 'name="decision"' "$WORKDIR/local-consent.html"; then
  fail "local mode (react): /account/consent is a server-rendered form"
fi
for path in "/account/api/consent?txn=${TXN}" /account/api/me/grants; do
  code="$(curl -s -o "$WORKDIR/local-api.json" -w '%{http_code}' "${BASE}${path}")"
  [ "$code" = "401" ] || fail "local mode (react): GET ${path} without a session returned ${code}, expected 401"
  grep -q 'not_authenticated' "$WORKDIR/local-api.json" || fail "local mode (react): ${path} did not answer not_authenticated"
done
ok "local mode (react): the consent screen is the app, and its API wants a session"
docker rm -f "$LOCAL_REACT" >/dev/null

# ------------------------------------------ (n) an unknown SELFHOST_AUTH_MODE fails closed
new_volume fc3
FC_VOL3="$NEW_VOLUME"
expect_refusal "SELFHOST_AUTH_MODE=bogus" \
  docker run --name "$FAILCLOSED" --read-only --tmpfs /tmp -v "${FC_VOL3}:/data" \
  "${ENTRA_ENV[@]}" -e CANVAS_TOKEN_KEYS="$TOKEN_KEYS" -e SELFHOST_AUTH_MODE=bogus "$IMAGE"
new_volume fc4
FC_VOL4="$NEW_VOLUME"
expect_refusal "SELFHOST_AUTH_MODE=local with ACCESS_TOKEN_TTL=1" \
  docker run --name "$FAILCLOSED" --read-only --tmpfs /tmp -v "${FC_VOL4}:/data" \
  "${ENTRA_ENV[@]}" -e CANVAS_TOKEN_KEYS="$TOKEN_KEYS" -e SELFHOST_AUTH_MODE=local -e ACCESS_TOKEN_TTL=1 "$IMAGE"

echo "SMOKE TEST PASSED"
