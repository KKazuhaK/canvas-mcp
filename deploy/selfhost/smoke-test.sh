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
VOLUMES=()
WORKDIR="$(mktemp -d)"

cleanup() {
  docker rm -f "$MAIN" "$LEGACY" "$FAILCLOSED" "$GENERATED" "$REACT" "$REACT_BAD" >/dev/null 2>&1 || true
  local v
  for v in "${VOLUMES[@]:-}"; do
    [ -n "$v" ] && docker volume rm -f "$v" >/dev/null 2>&1 || true
  done
  rm -rf "$WORKDIR"
}
trap cleanup EXIT

dump_logs() {
  local c
  for c in "$MAIN" "$LEGACY" "$FAILCLOSED" "$GENERATED" "$REACT" "$REACT_BAD"; do
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

echo "SMOKE TEST PASSED"
