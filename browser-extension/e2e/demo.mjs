// End-to-end demo: fake no-token Canvas -> extension -> local Portal -> MCP tool call.
import { chromium } from 'playwright';
import { createHash, randomBytes } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';

process.env.NODE_TLS_REJECT_UNAUTHORIZED = '0';
const D = process.env.DEMO_DIR ?? new URL('./.work', import.meta.url).pathname;
mkdirSync(D, { recursive: true });
const PORTAL = 'https://localhost:9443';
const CANVAS = 'https://canvas.nopat-demo.edu';
const SRC = new URL('../dist/chrome', import.meta.url).pathname;
const EXT = D + '/ext-demo';
const step = (s) => console.log(`\n=== ${s}`);
const shot = (p, n) => p.screenshot({ path: `${D}/shot-${n}.png`, fullPage: true });

// Demo copy: grant the two origins up front because headless Chromium cannot click the permission prompt.
rmSync(EXT, { recursive: true, force: true });
cpSync(SRC, EXT, { recursive: true });
const manifest = JSON.parse(readFileSync(EXT + '/manifest.json', 'utf8'));
manifest.host_permissions = ['https://localhost/*', 'https://canvas.nopat-demo.edu/*'];
writeFileSync(EXT + '/manifest.json', JSON.stringify(manifest, null, 2));

const credsFile = D + '/demo-admin.json';
const creds = existsSync(credsFile)
  ? JSON.parse(readFileSync(credsFile, 'utf8'))
  : { upn: 'demo-admin@example.edu', password: randomBytes(18).toString('base64url') };
writeFileSync(credsFile, JSON.stringify(creds));

const ctx = await chromium.launchPersistentContext(D + '/profile', {
  channel: 'chromium', headless: true, ignoreHTTPSErrors: true, viewport: { width: 1200, height: 900 },
  args: [`--disable-extensions-except=${EXT}`, `--load-extension=${EXT}`, '--ignore-certificate-errors',
    '--host-resolver-rules=MAP canvas.nopat-demo.edu 127.0.0.1:8443'],
});
let [sw] = ctx.serviceWorkers();
if (!sw) sw = await ctx.waitForEvent('serviceworker');
const extId = sw.url().split('/')[2];
console.log('extension id', extId);
const page = await ctx.newPage();

step('Portal: first-run setup or sign-in');
await page.goto(PORTAL + '/account/');
await page.waitForLoadState('networkidle');
if (page.url().includes('/setup')) {
  await page.getByLabel(/^Installation code/).first().fill(process.env.INSTALL_CODE);
  await page.getByLabel(/^Account UPN/).first().fill(creds.upn);
  await page.getByLabel(/^Password/).first().fill(creds.password);
  await page.getByLabel(/^Confirm password/).first().fill(creds.password);
  await page.getByRole('button', { name: 'Initialize sign-in' }).click();
  await page.waitForTimeout(2500);
}
await page.goto(PORTAL + '/account/sign-in');
await page.waitForLoadState('networkidle');
if (page.url().includes('/sign-in')) {
  await page.getByLabel(/^Account UPN/).first().fill(creds.upn);
  await page.getByLabel(/^Password/).first().fill(creds.password);
  await page.getByRole('button', { name: 'Sign in with local account' }).click();
  await page.waitForURL((u) => !u.pathname.endsWith('/sign-in'), { timeout: 15000 });
  await page.waitForLoadState('networkidle');
}
console.log('portal at', page.url());
await shot(page, '02-portal-home');

step('Canvas: sign in to the fake school (tokens disabled)');
const canvasTab = await ctx.newPage();
await canvasTab.goto(CANVAS + '/login');
await canvasTab.click('#login');
await canvasTab.waitForURL(CANVAS + '/');
console.log('canvas tab', canvasTab.url(), '|', await canvasTab.locator('p').innerText());
const tokenProbe = await fetch(CANVAS.replace('canvas.nopat-demo.edu', '127.0.0.1:8443') + '/api/v1/users/self',
  { headers: { Authorization: 'Bearer any-token', Host: 'canvas.nopat-demo.edu' } });
console.log('Canvas API with a bearer token ->', tokenProbe.status, await tokenProbe.text());

step('Extension popup: connect to the Portal');
const popup = await ctx.newPage();
await popup.goto(`chrome-extension://${extId}/popup.html`);
await popup.fill('#portal', PORTAL);
const pairingTabPromise = ctx.waitForEvent('page');
await popup.click('#connect-btn');
const pairingTab = await pairingTabPromise;
await pairingTab.waitForLoadState('networkidle');
console.log('pairing tab', pairingTab.url().replace(/extension-auth=.*/, 'extension-auth=<state>'));
await pairingTab.waitForSelector('#canvas-extension-authorization[data-result]', { state: 'attached', timeout: 20000 })
  .catch(() => console.log('no data-result on the authorization element'));
console.log('link result', await pairingTab.locator('#canvas-extension-authorization')
  .getAttribute('data-result').catch(() => 'n/a'));
await shot(pairingTab, '03-pairing-page');
await popup.reload();
await popup.waitForTimeout(800);

step('Extension popup: set the Canvas site and sync');
await popup.fill('#canvas-origin', CANVAS);
await popup.click('#canvas-btn');
await popup.waitForTimeout(800);
await canvasTab.bringToFront();
await popup.click('#sync-btn');
for (let i = 0; i < 40; i++) {
  await popup.waitForTimeout(500);
  const t = await popup.locator('#headline').innerText();
  if (/synced|error|fail/i.test(t) && !/syncing/i.test(t)) break;
}
console.log('popup status:\n' + (await popup.locator('main').innerText()));
if (process.env.SYNC_TWICE === '1') {
  await popup.waitForTimeout(61000); // the extension spaces attempts at least a minute apart
  await popup.click('#sync-btn');
  await popup.waitForTimeout(5000);
  console.log('second sync:', await popup.locator('#headline').innerText(), '|', await popup.locator('#message').innerText());
}
await shot(popup, '04-popup-after-sync');

const log = await (await fetch('https://127.0.0.1:8443/__demo/requests')).json();
const sessionReads = log.filter((r) => r.session && !r.auth_header);
console.log(`fake Canvas saw ${log.length} API requests: ${sessionReads.length} with the session cookie and no Authorization header;`,
  `methods: ${[...new Set(log.map((r) => r.method))].join(',')}`);

step('Portal account page: browser extension status');
await page.goto(PORTAL + '/account/browser-extension');
await page.waitForLoadState('networkidle');
await page.waitForTimeout(800);
console.log((await page.locator('main').innerText()).slice(0, 1500));
await shot(page, '05-account-extension');

step('MCP client: OAuth (DCR + PKCE) and tool calls');
const redirectUri = 'http://127.0.0.1:7777/callback';
const reg = await (await fetch(PORTAL + '/register', {
  method: 'POST', headers: { 'Content-Type': 'application/json' },
  body: JSON.stringify({ client_name: 'Browser sync demo client', redirect_uris: [redirectUri],
    grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' }),
})).json();
const verifier = randomBytes(32).toString('base64url');
const challenge = createHash('sha256').update(verifier).digest('base64url');
const state = randomBytes(12).toString('base64url');
const authUrl = `${PORTAL}/authorize?` + new URLSearchParams({ response_type: 'code', client_id: reg.client_id,
  redirect_uri: redirectUri, code_challenge: challenge, code_challenge_method: 'S256', state,
  scope: 'Canvas.Access', resource: PORTAL + '/mcp' });
let code = null;
await page.route('http://127.0.0.1:7777/**', (route) => {
  code = new URL(route.request().url()).searchParams.get('code');
  route.fulfill({ status: 200, body: 'ok' });
});
await page.goto(authUrl);
await page.waitForLoadState('networkidle');
if (!code) {
  await shot(page, '06-consent');
  const allow = page.getByRole('button', { name: /allow|approve|authorize|continue/i }).first();
  await allow.click();
  for (let i = 0; i < 20 && !code; i++) await page.waitForTimeout(250);
}
const tok = await (await fetch(PORTAL + '/token', {
  method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
  body: new URLSearchParams({ grant_type: 'authorization_code', code, redirect_uri: redirectUri,
    client_id: reg.client_id, code_verifier: verifier, resource: PORTAL + '/mcp' }),
})).json();
console.log('access token issued:', Boolean(tok.access_token));

let sid = null;
let rpcId = 0;
async function mcp(method, params) {
  const headers = { Authorization: `Bearer ${tok.access_token}`, 'Content-Type': 'application/json',
    Accept: 'application/json, text/event-stream', 'MCP-Protocol-Version': '2025-06-18' };
  if (sid) headers['Mcp-Session-Id'] = sid;
  const body = method.startsWith('notifications/') ? { jsonrpc: '2.0', method, params }
    : { jsonrpc: '2.0', id: ++rpcId, method, params };
  const res = await fetch(PORTAL + '/mcp', { method: 'POST', headers, body: JSON.stringify(body) });
  sid = res.headers.get('mcp-session-id') ?? sid;
  const text = await res.text();
  const line = text.split('\n').find((l) => l.startsWith('data: '));
  return line ? JSON.parse(line.slice(6)) : (text ? JSON.parse(text) : null);
}
await mcp('initialize', { protocolVersion: '2025-06-18', capabilities: {}, clientInfo: { name: 'demo', version: '1' } });
await mcp('notifications/initialized', {});
const tools = (await mcp('tools/list', {})).result.tools.map((t) => t.name);
console.log(`${tools.length} tools; student read tools:`, tools.filter((n) => /my_|announce|calendar|todo|grade/.test(n)).join(', '));
const calls = (process.env.TOOLS ?? '').split(',').filter(Boolean);
for (const name of calls) {
  const [tool, argJson] = name.split('=');
  const r = await mcp('tools/call', { name: tool, arguments: argJson ? JSON.parse(argJson) : {} });
  const out = r.result?.content?.map((c) => c.text).join('\n') ?? JSON.stringify(r.error);
  console.log(`\n--- ${tool} (isError=${r.result?.isError ?? 'n/a'})\n${out.slice(0, 1400)}`);
}
writeFileSync(D + '/mcp-session.json', JSON.stringify({ token: tok.access_token }));

if (process.env.REVOKE === '1') {
  step('Revoke from the account page, then call a tool again');
  await page.goto(PORTAL + '/account/browser-extension');
  await page.waitForLoadState('networkidle');
  await page.getByRole('button', { name: /disconnect/i }).first().click();
  await page.getByRole('dialog').getByRole('button', { name: /disconnect|delete|confirm/i }).last().click();
  await page.waitForTimeout(1500);
  await shot(page, '07-after-revoke');
  const r = await mcp('tools/call', { name: calls[0].split('=')[0], arguments: {} });
  console.log('after revoke:', (r.result?.content?.map((c) => c.text).join('\n') ?? JSON.stringify(r.error)).slice(0, 500));
  await popup.reload();
  await popup.click('#sync-btn');
  await popup.waitForTimeout(3000);
  console.log('popup after revoke + sync:\n' + (await popup.locator('main').innerText()).slice(0, 600));
}
await ctx.close();
