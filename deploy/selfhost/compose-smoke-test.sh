#!/usr/bin/env bash
# CI contract: deploy with exactly docker-compose.yml and .env, no setup script.
set -euo pipefail
{ set +x; } 2>/dev/null
IMAGE="${1:?usage: compose-smoke-test.sh IMAGE}"
SOURCE="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
WORK="$(mktemp -d)"
PROJECT="canvas-twofile-$$"
OWN_VOLUME=false
compose() { docker compose -p "$PROJECT" -f "$WORK/docker-compose.yml" "$@"; }
cleanup() {
  if [ "$OWN_VOLUME" = true ]; then compose down -v >/dev/null 2>&1 || true; fi
  rm -rf -- "$WORK"
}
trap cleanup EXIT
if docker volume inspect canvas-mcp-data >/dev/null 2>&1; then
  echo "Two-file smoke refuses an existing canvas-mcp-data volume" >&2
  exit 1
fi
cp -- "$SOURCE/docker-compose.yml" "$WORK/docker-compose.yml"
umask 077
cat >"$WORK/.env" <<EOF
PUBLIC_BASE_URL=https://mcp.example.com
CANVAS_MCP_IMAGE=$IMAGE
EOF
compose config --quiet
# The local smoke image has not been published yet.
OWN_VOLUME=true
compose up -d --pull never --wait --wait-timeout 120
curl -fsS http://127.0.0.1:8819/healthz
compose exec -T canvas-mcp python -m canvas_mcp.core.selfhost.token_admin check
# First-install configuration uses the HTTP API, not provider environment variables.
compose exec -T canvas-mcp python - <<'PY'
import json
from pathlib import Path
from urllib.request import Request, urlopen

def api(method, body=None):
    request = Request('http://127.0.0.1:8819/api/v1/setup',
        data=None if body is None else json.dumps(body).encode(), method=method,
        headers={'Host': 'mcp.example.com', 'Origin': 'https://mcp.example.com', 'Content-Type': 'application/json'})
    with urlopen(request, timeout=10) as response:
        assert response.status == 200
        return json.load(response)

status = api('GET')
assert status['initialized'] is False
code = json.loads(Path('/data/installation-code.json').read_text())['code']
api('POST', {'revision': status['revision'], 'code': code,
    'config': {'tenant_id': '11111111-2222-3333-4444-555555555555', 'client_id': 'aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee'},
    'client_secret': 'smoke-not-a-real-secret-0123456789'})
assert api('GET')['initialized'] is True
PY
# Seal a throwaway value and a browser-session key fingerprint before recreation.
compose exec -T canvas-mcp python - <<'PY'
import base64, hashlib, json, os
from pathlib import Path
from canvas_mcp.core.selfhost.runtime_secrets import with_saved_secrets
from canvas_mcp.core.selfhost.token_store import Keyring
env = with_saved_secrets(os.environ)
sealed = Keyring.parse(env['CANVAS_TOKEN_KEYS']).encrypt(b'two-file-test', b'smoke')
payload = {'sealed': [sealed[0], *(base64.b64encode(v).decode() for v in sealed[1:])],
           'session': hashlib.sha256(env['ACCOUNT_SESSION_SECRET'].encode()).hexdigest()}
Path('/data/smoke-seal.json').write_text(json.dumps(payload), encoding='utf-8')
PY
compose up -d --pull never --force-recreate --wait --wait-timeout 120
compose exec -T canvas-mcp python - <<'PY'
import base64, hashlib, json, os, stat
from canvas_mcp.core.selfhost.app import prepare_selfhost
from canvas_mcp.core.selfhost.settings import load_selfhost_settings
from pathlib import Path
from canvas_mcp.core.selfhost.runtime_secrets import with_saved_secrets
from canvas_mcp.core.selfhost.token_store import Keyring
env = with_saved_secrets(os.environ)
payload = json.loads(Path('/data/smoke-seal.json').read_text(encoding='utf-8'))
kid, nonce, ciphertext = payload['sealed']
assert Keyring.parse(env['CANVAS_TOKEN_KEYS']).decrypt(kid, base64.b64decode(nonce), base64.b64decode(ciphertext), b'smoke') == b'two-file-test'
assert hashlib.sha256(env['ACCOUNT_SESSION_SECRET'].encode()).hexdigest() == payload['session']
info = Path('/data/runtime-secrets.json').stat()
assert stat.S_IMODE(info.st_mode) == 0o600 and info.st_uid == 10001
assert 'CANVAS_TOKEN_KEYS' not in os.environ and 'ACCOUNT_SESSION_SECRET' not in os.environ
assert not any(name.startswith('ENTRA_') for name in os.environ)
runtime = prepare_selfhost(load_selfhost_settings(env))
try:
    providers = runtime.provider_store
    assert providers.load_snapshot().providers[0].client_secret == 'smoke-not-a-real-secret-0123456789'
    assert not providers.setup_available()
finally:
    runtime.store.close()
PY
compose exec -T canvas-mcp python -m canvas_mcp.core.selfhost.token_admin check
curl -fsS http://127.0.0.1:8819/.well-known/oauth-authorization-server >/dev/null
echo "TWO-FILE COMPOSE TEST PASSED: origin-only boot, HTTP setup and encrypted configuration survive recreation"
