#!/usr/bin/env bash
# Validate a built v1 image using throwaway credentials and fresh volumes.
# Usage: bash deploy/selfhost/smoke-test.sh IMAGE
# Optional SMOKE_EXPECT_PROVIDERS=google,github checks start redirects and needs outbound HTTPS.
# Optional SMOKE_ENTRA_TENANT_ID checks discovery/start for an existing public tenant.
# This does not authenticate real IdP users or prove a client's multiday refresh.
set -euo pipefail
{ set +x; } 2>/dev/null
IMAGE="${1:?usage: smoke-test.sh IMAGE}"
PORT="${SMOKE_PORT:-18819}"
BASE="http://127.0.0.1:${PORT}"
PUBLIC="https://canvas.example.test"
MAIN="canvas-mcp-smoke-$$"
REFUSAL="canvas-mcp-smoke-refusal-$$"
PROVIDERS_C="canvas-mcp-smoke-providers-$$"
VOLUME="canvas-mcp-smoke-data-$$"
PROVIDERS_VOLUME="canvas-mcp-smoke-providers-data-$$"
WORKDIR="$(mktemp -d)"
cleanup() {
  docker rm -f "$MAIN" "$REFUSAL" "$PROVIDERS_C" >/dev/null 2>&1 || true
  docker volume rm "$VOLUME" "$PROVIDERS_VOLUME" >/dev/null 2>&1 || true
  rm -rf -- "$WORKDIR"
}
trap cleanup EXIT
fail() {
  echo "SMOKE TEST FAILED: $*" >&2
  docker logs "$MAIN" 2>&1 | tail -n 60 >&2 || true
  exit 1
}
ok() { echo "ok: $*"; }
command -v docker >/dev/null || fail "Docker is required"
command -v curl >/dev/null || fail "curl is required"
command -v python3 >/dev/null || fail "python3 is required"
command -v openssl >/dev/null || fail "openssl is required"
SESSION_SECRET="$(openssl rand -base64 32 | tr -d '\r\n')"
TOKEN_KEYS="k1:$(openssl rand -base64 32 | tr -d '\r\n')"
ENV=(
  -e MCP_AUTH_MODE=selfhost -e PUBLIC_BASE_URL="$PUBLIC"
  -e ENTRA_TENANT_ID="${SMOKE_ENTRA_TENANT_ID:-11111111-2222-3333-4444-555555555555}"
  -e ENTRA_CLIENT_ID=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee
  -e ENTRA_CLIENT_SECRET=smoke-not-a-real-secret-0123456789
  -e ACCOUNT_SESSION_SECRET="$SESSION_SECRET" -e CANVAS_TOKEN_KEYS="$TOKEN_KEYS"
  -e CANVAS_ROLE=student
)
wait_for() {
  local name="$1" i
  for ((i=0; i<60; i++)); do
    [ "$(docker inspect -f '{{.State.Running}}' "$name" 2>/dev/null || true)" = true ] || fail "$name exited"
    if curl -fsS --max-time 3 -o /dev/null "${BASE}/healthz" 2>/dev/null; then return; fi
    sleep 1
  done
  fail "$name did not become ready"
}
status() {
  local wanted="$1" path="$2"; shift 2
  local actual
  actual="$(curl -sS --max-time 10 -o "$WORKDIR/body" -D "$WORKDIR/headers" -w '%{http_code}' "$@" "${BASE}${path}")"
  [ "$actual" = "$wanted" ] || fail "$path returned $actual, expected $wanted"
}

# (a) hardened native image
[ "$(docker run --rm --entrypoint id "$IMAGE" -u)" = 10001 ] || fail "unexpected runtime uid"
docker volume create "$VOLUME" >/dev/null
docker run -d --name "$MAIN" --read-only --tmpfs /tmp --cap-drop ALL \
  --security-opt no-new-privileges:true -v "$VOLUME:/data" \
  -p "127.0.0.1:${PORT}:8819" "${ENV[@]}" "$IMAGE" >/dev/null
wait_for "$MAIN"
ok "non-root, read-only image boots with a fresh SQL store"

# (b) local OAuth metadata and unauthenticated MCP
status 200 /.well-known/oauth-authorization-server
python3 - "$WORKDIR/body" "$PUBLIC" <<'PY' || fail "OAuth metadata"
import json, sys
m = json.load(open(sys.argv[1])); base = sys.argv[2]
assert m['issuer'].rstrip('/') == base
assert m['authorization_endpoint'] == base + '/authorize'
assert m['token_endpoint'] == base + '/token'
assert m['revocation_endpoint'] == base + '/revoke'
assert m['token_endpoint_auth_methods_supported'] == ['none']
assert m['code_challenge_methods_supported'] == ['S256']
assert m['authorization_response_iss_parameter_supported'] is True
assert m['client_id_metadata_document_supported'] is True
PY
status 200 /.well-known/oauth-protected-resource/mcp
python3 - "$WORKDIR/body" "$PUBLIC" <<'PY' || fail "resource metadata"
import json, sys
m = json.load(open(sys.argv[1])); base = sys.argv[2]
assert m['resource'] == base + '/mcp'
assert [v.rstrip('/') for v in m['authorization_servers']] == [base]
PY
INIT='{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-03-26","capabilities":{},"clientInfo":{"name":"smoke","version":"1"}}}'
status 401 /mcp -X POST -H 'Content-Type: application/json' -H 'Accept: application/json, text/event-stream' --data "$INIT"
grep -qi 'www-authenticate:.*resource_metadata=' "$WORKDIR/headers" || fail "MCP resource challenge missing"
ok "local issuer metadata and MCP 401 challenge"

# (c) mandatory React and native account API
status 200 /account/token
grep -q 'id="root"' "$WORKDIR/body" || fail "React build missing"
status 200 /account/consent?txn=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
grep -q 'id="root"' "$WORKDIR/body" || fail "React consent route missing"
status 200 /api/v1/providers
python3 - "$WORKDIR/body" <<'PY' || fail "provider routes"
import json, sys
p = json.load(open(sys.argv[1]))['providers']
assert [v['id'] for v in p] == ['entra']
assert p[0]['start_url'].startswith('/auth/login/entra')
PY
for path in /api/v1/me /api/v1/me/grants /api/v1/consent?txn=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA; do
  status 401 "$path"
  grep -q not_authenticated "$WORKDIR/body" || fail "$path does not require a browser session"
  grep -qi 'cache-control:.*no-store' "$WORKDIR/headers" || fail "$path cache policy"
done
for path in /api/v1/unknown /consent /auth/callback /.well-known/openid-configuration; do
  status 404 "$path"
done
# Unknown account GETs deliberately return the React shell for its not-found
# view. They must not become JSON endpoints, redirects or form handlers.
for path in /account/api/me /account/login /account/callback; do
  status 200 "$path"
  grep -q 'id="root"' "$WORKDIR/body" || fail "$path did not return the SPA shell"
  grep -qi '^content-type: text/html' "$WORKDIR/headers" || fail "$path became an API"
  if grep -qi '^location:' "$WORKDIR/headers"; then fail "$path became a redirect"; fi
  status 405 "$path" -X POST
done
status 303 /auth/login?txn=bogus
grep -qi '^location:.*account/sign-in?error=authorization_invalid' "$WORKDIR/headers" || fail "invalid transaction redirect"
if [ -n "${SMOKE_ENTRA_TENANT_ID:-}" ]; then
  status 302 /auth/login/entra
  grep -qi '^location: https://login.microsoftonline.com/' "$WORKDIR/headers" || fail "Entra start redirect"
  grep -qi '^set-cookie:.*httponly' "$WORKDIR/headers" || fail "sealed sign-in cookie missing"
else
  # The throwaway tenant deliberately does not exist. Discovery must fail closed,
  # rather than manufacture a flow from unverified metadata.
  status 303 /auth/login/entra
  grep -qi '^location:.*account/sign-in?error=provider_error' "$WORKDIR/headers" || fail "invalid tenant did not fail closed"
  if grep -qi '^set-cookie:.*cmcp_flow=' "$WORKDIR/headers"; then fail "failed discovery created a ceremony"; fi
fi
ok "React, account API and distinct sign-in paths"

# (d) registration and protocol refusal contract
REG='{"client_name":"smoke","redirect_uris":["https://claude.ai/api/mcp/auth_callback"],"grant_types":["authorization_code","refresh_token"],"response_types":["code"],"token_endpoint_auth_method":"none"}'
status 201 /register -H 'Content-Type: application/json' --data "$REG"
CLIENT_ID="$(python3 - "$WORKDIR/body" <<'PY'
import json, sys
m = json.load(open(sys.argv[1])); assert not m.get('client_secret')
assert m['token_endpoint_auth_method'] == 'none'
print(m['client_id'])
PY
)"
status 401 /token --data 'grant_type=authorization_code&code=cmcp_ac_nope&client_id=missing'
status 401 /revoke --data 'token=garbage'
status 200 /revoke --data-urlencode "client_id=$CLIENT_ID" --data 'token=garbage'
status 400 /authorize?response_type=code\&client_id=missing
ok "public-client registration and refusal semantics"

# (e) startup refuses removed settings and unusable React build
expect_refusal() {
  local label="$1" result marker; shift
  set +e
  timeout 30 docker run --rm --name "$REFUSAL" --read-only --tmpfs /tmp \
    "${ENV[@]}" "$@" "$IMAGE" >"$WORKDIR/refusal" 2>&1
  result=$?
  set -e
  docker rm -f "$REFUSAL" >/dev/null 2>&1 || true
  [ "$result" != 0 ] && [ "$result" != 124 ] || fail "$label did not refuse startup"
  case "$label" in
    "missing React build") marker='Account UI';;
    "reserved state backend") marker='SELFHOST_STATE_BACKEND';;
    *) marker="$label";;
  esac
  grep -qiF "$marker" "$WORKDIR/refusal" || fail "$label had an unexpected failure"
  ok "$label refuses startup"
}
for removed in SELFHOST_AUTH_MODE OAUTH_JWT_SIGNING_KEY GRANT_STATUS_CACHE_S CANVAS_API_URL CANVAS_FEATURED_SCHOOLS CANVAS_SCHOOL_SEARCH ACCOUNT_UI ENTRA_API_SCOPE; do
  expect_refusal "$removed" -e "$removed="
done
expect_refusal "MCP_AUTH_MODE" -e MCP_AUTH_MODE=entra-oauth
expect_refusal "ACCESS_TOKEN_TTL" -e ACCESS_TOKEN_TTL=1
expect_refusal "CANVAS_TOKEN_KEYS" -e CANVAS_TOKEN_KEYS=
expect_refusal "missing React build" -e ACCOUNT_WEB_DIST=/does-not-exist
expect_refusal "reserved state backend" -e SELFHOST_STATE_BACKEND=redis
ok "all v1 startup refusal paths"

# (o) optional: sign-in providers (SMOKE_EXPECT_PROVIDERS)
if [ -n "${SMOKE_EXPECT_PROVIDERS:-}" ]; then
  docker rm -f "$MAIN" >/dev/null
  PROVIDER_LIST=""
  PROVIDER_ENV=()
  PROVIDER_SECRET="smoke-not-a-real-provider-secret-0123456789"
  IFS=',' read -r -a providers <<< "$SMOKE_EXPECT_PROVIDERS"
  for provider in "${providers[@]}"; do
    case "$provider" in
      google) PROVIDER_ENV+=(-e GOOGLE_CLIENT_ID=smoke-not-real.apps.googleusercontent.com -e GOOGLE_CLIENT_SECRET="$PROVIDER_SECRET");;
      github) PROVIDER_ENV+=(-e GITHUB_CLIENT_ID=smoke-not-real-github -e GITHUB_CLIENT_SECRET="$PROVIDER_SECRET");;
      *) fail "SMOKE_EXPECT_PROVIDERS: unsupported provider";;
    esac
    PROVIDER_LIST+=",$provider"
  done
  docker volume create "$PROVIDERS_VOLUME" >/dev/null
  docker run -d --name "$PROVIDERS_C" --read-only --tmpfs /tmp --cap-drop ALL \
    --security-opt no-new-privileges:true -v "$PROVIDERS_VOLUME:/data" \
    -p "127.0.0.1:${PORT}:8819" "${ENV[@]}" "${PROVIDER_ENV[@]}" \
    -e "SELFHOST_LOGIN_PROVIDERS=entra${PROVIDER_LIST}" "$IMAGE" >/dev/null
  wait_for "$PROVIDERS_C"
  status 200 /api/v1/providers
  python3 - "$WORKDIR/body" "entra${PROVIDER_LIST}" <<'PY' || fail "optional provider list"
import json, sys
p = json.load(open(sys.argv[1]))['providers']
assert [v['id'] for v in p] == sys.argv[2].split(',')
assert all(v['start_url'].startswith('/auth/login/') for v in p)
PY
  for provider in "${providers[@]}"; do
    case "$provider" in google) host="accounts.google.com";; github) host="github.com";; esac
    status 302 "/auth/login/${provider}"
    python3 - "$WORKDIR/headers" "$host" <<'PY' || fail "optional provider redirect"
from urllib.parse import urlsplit, parse_qs
import sys
headers = open(sys.argv[1]).read().splitlines()
location = next(v.partition(':')[2].strip() for v in headers if v.lower().startswith('location:'))
u = urlsplit(location); q = parse_qs(u.query)
assert u.scheme == 'https' and u.hostname == sys.argv[2]
assert q['client_id'] and q['state'] and q['redirect_uri']
assert q['code_challenge_method'] == ['S256']
PY
  done
  docker rm -f "$PROVIDERS_C" >/dev/null
  ok "optional provider starts (no code exchange or real sign-in)"
fi
echo "SMOKE TEST PASSED"
