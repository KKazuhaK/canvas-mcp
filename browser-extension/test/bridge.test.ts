import test from 'node:test';
import assert from 'node:assert/strict';
import { createController } from '../src/lib/controller.ts';
import { looksLikeCanvas } from '../src/lib/origin.ts';
import { CANVAS, EXT_ID, POPUP_URL, PORTAL, TOKEN, jsonResponse, makeChrome } from './helpers.ts';

const NOW = Date.parse('2026-11-21T12:00:00Z');
const popup = { id: EXT_ID, url: POPUP_URL };
const page = { id: EXT_ID, tab: { id: 5 }, frameId: 0, url: `${PORTAL}/account/browser-extension` };
const CODE = 'ABCD-EFGH-JKLM';

function setup(chromeOpts: Parameters<typeof makeChrome>[0] = {}) {
  const m = makeChrome(chromeOpts);
  const requests: string[] = [];
  const fetchFn = (async (input: any) => {
    const url = String(input);
    requests.push(url);
    if (url.endsWith('/extension/claim')) return jsonResponse({ uploadToken: TOKEN, bindingId: 'b1' });
    if (url.endsWith('/extension/capabilities')) return jsonResponse({ browserSync: 1 });
    return jsonResponse({}, { status: 500 });
  }) as typeof fetch;
  const c = createController(m.api, { fetch: fetchFn, now: () => NOW, randomBytes: (n) => new Uint8Array(n).fill(2), defaultPortal: PORTAL });
  return { ...m, c, requests };
}

test('bridge: only the default portal page, in the top frame, may pair or read the status', async () => {
  const s = setup();
  for (const sender of [
    { ...page, url: 'https://evil.example/account/browser-extension' },
    { ...page, frameId: 3 },
    { ...page, id: 'other-extension' },
    { ...page, tab: undefined },
    popup,
  ]) {
    await assert.rejects(s.c.handleMessage({ type: 'canvas.bridge.claim', code: CODE }, sender), /refused/);
    await assert.rejects(s.c.handleMessage({ type: 'canvas.bridge.status' }, sender), /refused/);
  }
  assert.deepEqual(s.requests, []);
  const none = createController(makeChrome().api, { fetch, now: () => NOW, randomBytes: (n) => new Uint8Array(n) });
  await assert.rejects(none.handleMessage({ type: 'canvas.bridge.status' }, page), /refused/);
  assert.deepEqual(await s.c.handleMessage({ type: 'canvas.bridge.status' }, page), { ok: true, connected: false, canvasOrigin: null });
});

test('bridge: a suggested Canvas site with access is saved and the first sync starts at once', async () => {
  const s = setup({ permissions: [`${CANVAS}/*`] });
  assert.deepEqual(await s.c.handleMessage({ type: 'canvas.bridge.claim', code: CODE, canvasOrigin: CANVAS }, page), { ok: true });
  assert.equal(s.requests[0], `${PORTAL}/api/v1/extension/claim`);
  assert.equal(s.storage.data.portalOrigin, PORTAL);
  assert.equal(s.storage.data.canvasOrigin, CANVAS);
  assert.equal(s.created.length, 0);
  await new Promise((r) => setTimeout(r, 0));
  // The sync asks the portal for its plan right away instead of waiting for a Canvas page visit.
  assert.ok(s.requests.some((u) => u.startsWith(`${PORTAL}/api/v1/extension/plan`)), s.requests.join('\n'));
  assert.deepEqual(await s.c.handleMessage({ type: 'canvas.bridge.status' }, page), { ok: true, connected: true, canvasOrigin: CANVAS });
});

test('bridge: without Canvas access the popup opens in a tab to ask for it with one click', async () => {
  const s = setup();
  assert.deepEqual(await s.c.handleMessage({ type: 'canvas.bridge.claim', code: CODE, canvasOrigin: CANVAS }, page), { ok: true, needsCanvasAccess: true });
  assert.equal(s.storage.data.suggestedCanvasOrigin, CANVAS);
  assert.equal(s.storage.data.canvasOrigin, undefined);
  assert.deepEqual(s.created.map((t) => t.url), [`${POPUP_URL}?setup=canvas`]);
  // A malformed suggestion is ignored, never stored.
  const bad = setup();
  await bad.c.handleMessage({ type: 'canvas.bridge.claim', code: CODE, canvasOrigin: 'javascript:alert(1)' }, page);
  assert.equal(bad.storage.data.suggestedCanvasOrigin, undefined);
  await assert.rejects(bad.c.handleMessage({ type: 'canvas.bridge.claim', code: 'x' }, page), /invalid pairing code/);
});

test('intent: a request saved before the access prompt is finished once access is granted', async () => {
  const s = setup({ permissions: [`${PORTAL}/*`, `${CANVAS}/*`] });
  s.storage.data.pendingIntent = { type: 'pair.manual', portalOrigin: PORTAL, code: CODE, at: NOW - 1000 };
  assert.deepEqual(await s.c.resumeIntent(), { ok: true });
  assert.equal(s.storage.data.pendingIntent, undefined);
  assert.equal(s.storage.data.uploadToken, TOKEN);
  s.storage.data.pendingIntent = { type: 'canvas.set', canvasOrigin: CANVAS, at: NOW };
  assert.deepEqual(await s.c.handleMessage({ type: 'canvas.intent.resume' }, popup), { ok: true });
  assert.equal(s.storage.data.canvasOrigin, CANVAS);
  // Nothing saved: nothing to do.
  assert.deepEqual(await s.c.resumeIntent(), { ok: true });
});

test('intent: an expired request or one without access does nothing and says why', async () => {
  const late = setup({ permissions: [`${PORTAL}/*`] });
  late.storage.data.pendingIntent = { type: 'pair.manual', portalOrigin: PORTAL, code: CODE, at: NOW - 6 * 60_000 };
  const r = await late.c.resumeIntent();
  assert.equal(r.ok, false);
  assert.deepEqual(late.requests, []);
  assert.match(String(late.storage.data.notice), /expired/);
  const denied = setup();
  denied.storage.data.pendingIntent = { type: 'canvas.set', canvasOrigin: CANVAS, at: NOW };
  assert.equal((await denied.c.resumeIntent()).ok, false);
  assert.equal(denied.storage.data.canvasOrigin, undefined);
  await assert.rejects(denied.c.handleMessage({ type: 'canvas.intent.resume' }, page), /refused/);
});

test('install opens the portal pairing page; an update does not', async () => {
  const s = setup();
  await s.c.onInstalled({ reason: 'update' });
  await s.c.onInstalled({ reason: 'install' });
  assert.deepEqual(s.created.map((t) => t.url), [`${PORTAL}/account/browser-extension`]);
});

test('only Canvas-looking https tabs are offered as the Canvas site', () => {
  assert.equal(looksLikeCanvas('https://school.instructure.com/courses/1'), true);
  assert.equal(looksLikeCanvas('https://canvas.ubc.ca/'), true);
  assert.equal(looksLikeCanvas('https://canvas.portal.example/x', 'https://canvas.portal.example'), false);
  assert.equal(looksLikeCanvas('https://www.google.com/'), false);
  assert.equal(looksLikeCanvas('http://school.instructure.com/'), false);
  assert.equal(looksLikeCanvas('chrome://extensions'), false);
});
