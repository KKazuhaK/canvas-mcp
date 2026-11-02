# End-to-end demo: a school that disables Canvas access tokens

This runs the real extension in Chromium against a fake Canvas that refuses
every `Authorization` header and answers `/api/v1` only for a signed-in session
(with the `while(1);` prefix and `Link` pagination), and against a local Portal.
It then signs an MCP client in with OAuth and calls student tools through `/mcp`.

It is a manual check, not part of CI.

## Pieces

- `fake_canvas.py`: the fake school, served as `https://canvas.nopat-demo.edu`
  (Chromium maps that name to `127.0.0.1:8443`). `GET /__demo/requests` lists
  what it received, so you can confirm no request carried a token.
- `tls_relay.py`: TLS on `https://localhost:9443` in front of the Portal on
  `127.0.0.1:8819`, because the Portal requires an https public URL.
- `demo.mjs`: Playwright script. Headless Chromium cannot click the permission
  prompt, so it loads a copy of the built extension with the two demo origins as
  `host_permissions`; the shipped manifest asks for them at runtime instead.

## Run

```sh
# 1. a self-signed certificate for both names
openssl req -x509 -newkey rsa:2048 -nodes -keyout e2e/.work/key.pem -out e2e/.work/cert.pem \
  -days 7 -subj "/CN=localhost" -addext "subjectAltName=DNS:localhost,DNS:canvas.nopat-demo.edu"

# 2. fake Canvas and the TLS relay (any Python with starlette and uvicorn; the project venv has both)
python e2e/fake_canvas.py --port 8443 --cert e2e/.work/cert.pem --key e2e/.work/key.pem &
python e2e/tls_relay.py e2e/.work/cert.pem e2e/.work/key.pem &

# 3. the Portal from the repository root, self-host mode, SQLite in a scratch directory
MCP_AUTH_MODE=selfhost SELFHOST_DATA_DIR=/tmp/portal-demo PUBLIC_BASE_URL=https://localhost:9443 \
  ACCOUNT_WEB_DIST=$PWD/web/dist CANVAS_ROLE=student ENABLE_DATA_ANONYMIZATION=true \
  python -m canvas_mcp.core.selfhost.container canvas-mcp-server --transport streamable-http \
  --host 127.0.0.1 --port 8819

# 4. the demo (build the extension and web/ first)
npm run build
npm install --no-save playwright@1.64.1 && npx playwright install chromium
INSTALL_CODE=<code printed by the Portal on first start> \
  TOOLS=get_my_upcoming_assignments,get_my_course_grades,list_my_announcements,list_calendar_events \
  REVOKE=1 node e2e/demo.mjs
```

The first run creates a local administrator with a random password saved in
`e2e/.work/demo-admin.json`. Screenshots land in `e2e/.work/`.

Expected: pairing completes, every Canvas request carries the session and no
token, the tools return the fake school's data with the "Data synced from your
browser" note, a write tool is refused, and after "Disconnect" the tools fall
back to the "no Canvas access token" answer and the extension asks to reconnect.
