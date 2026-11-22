import test from 'node:test';
import assert from 'node:assert/strict';
import { ALARM_MINUTES, ALARM_NAME, STARTUP_ALARM, createController } from '../src/lib/controller.ts';
import { looksLikeCanvas } from '../src/lib/origin.ts';
import { CANVAS, EXT_ID, POPUP_URL, PORTAL, TOKEN, jsonResponse, makeChrome } from './helpers.ts';

const NOW = Date.parse('2026-11-21T12:00:00Z');
const popup = { id: EXT_ID, url: POPUP_URL };
const page = { id: EXT_ID, tab: { id: 5 }, frameId: 0, url: `${PORTAL}/account/browser-extension` };
const CODE = 'ABCD-EFGH-JKLM';

function setup(chromeOpts: Parameters<typeof makeChrome>[0] = {}, { chosen = true } = {}) {
  // By default the person already chose this portal (its page bridge is registered).
  const m = makeChrome({ ...chromeOpts, storage: { ...(chosen ? { bridgeOrigin: PORTAL } : {}), ...chromeOpts.storage } });
  const requests: string[] = [];
  const fetchFn = (async (input: any) => {
    const url = String(input);
    requests.push(url);
    if (url.endsWith('/extension/claim')) return jsonResponse({ uploadToken: TOKEN, bindingId: 'b1' });
    if (url.endsWith('/extension/capabilities')) return jsonResponse({ browserSync: 1 });
    return jsonResponse({}, { status: 500 });
  }) as typeof fetch;
  const c = createController(m.api, { fetch: fetchFn, now: () => NOW, randomBytes: (n) => new Uint8Array(n).fill(2) });
  return { ...m, c, requests };
}

test('bridge: only the chosen portal page, in the top frame, may pair or read the status', async () => {
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
  // No portal is built in: until the person chooses one, no page may talk to the extension.
  const none = setup({}, { chosen: false });
  await assert.rejects(none.c.handleMessage({ type: 'canvas.bridge.status' }, page), /refused/);
  assert.deepEqual(await s.c.handleMessage({ type: 'canvas.bridge.status' }, page), {
    ok: true,
    connected: false,
    pending: true,
    canvasOrigin: null,
    lastSyncAt: null,
    lastError: null,
  });
});

test('connecting from the portal page: the popup choice registers the bridge there, and forgetting removes it', async () => {
  const s = setup({ permissions: [`${PORTAL}/*`] }, { chosen: false });
  s.storage.data.pendingIntent = { type: 'page', portalOrigin: PORTAL, tabId: 5, at: NOW };
  assert.deepEqual(await s.c.resumeIntent(), { ok: true });
  assert.equal(s.storage.data.bridgeOrigin, PORTAL);
  assert.deepEqual(s.registered, [
    { id: 'canvas-portal-bridge', matches: [`${PORTAL}/account/*`], js: ['bridge.js'], runAt: 'document_idle', persistAcrossSessions: true },
  ]);
  assert.deepEqual(s.injected.at(-1), { target: { tabId: 5 }, files: ['bridge.js'] });
  // The page pairs by itself, through the bridge.
  assert.deepEqual(await s.c.handleMessage({ type: 'canvas.bridge.claim', code: CODE }, page), { ok: true, needsCanvasAccess: true });
  assert.equal(s.storage.data.portalOrigin, PORTAL);
  await s.c.handleMessage({ type: 'canvas.disconnect' }, popup);
  assert.deepEqual(s.registered, []);
  assert.equal(s.storage.data.bridgeOrigin, undefined);
  // Without access to the portal the request does nothing.
  const denied = setup({}, { chosen: false });
  denied.storage.data.pendingIntent = { type: 'page', portalOrigin: PORTAL, tabId: 5, at: NOW };
  assert.equal((await denied.c.resumeIntent()).ok, false);
  assert.deepEqual(denied.registered, []);
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
  assert.deepEqual(
    { ...(await s.c.handleMessage({ type: 'canvas.bridge.status' }, page)), lastSyncAt: undefined, lastError: undefined },
    { ok: true, connected: true, pending: false, canvasOrigin: CANVAS, lastSyncAt: undefined, lastError: undefined },
  );
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

test('installing opens no page: no portal is built in', async () => {
  const s = setup();
  await s.c.onInstalled({ reason: 'install' });
  await s.c.onInstalled({ reason: 'update' });
  assert.deepEqual(s.created, []);
});

test('only Canvas-looking https tabs are offered as the Canvas site', () => {
  assert.equal(looksLikeCanvas('https://school.instructure.com/courses/1'), true);
  assert.equal(looksLikeCanvas('https://canvas.ubc.ca/'), true);
  assert.equal(looksLikeCanvas('https://canvas.portal.example/x', 'https://canvas.portal.example'), false);
  assert.equal(looksLikeCanvas('https://www.google.com/'), false);
  assert.equal(looksLikeCanvas('http://school.instructure.com/'), false);
  assert.equal(looksLikeCanvas('chrome://extensions'), false);
});

test('sync now from the page: only the chosen portal page, only once connected there', async () => {
  const s = setup({ permissions: [`${CANVAS}/*`] });
  await assert.rejects(s.c.handleMessage({ type: 'canvas.bridge.sync' }, { ...page, url: 'https://evil.example/' }), /refused/);
  await assert.rejects(s.c.handleMessage({ type: 'canvas.bridge.sync' }, page), /Connect this browser first/);
  s.storage.data.portalOrigin = 'https://other-portal.example';
  s.storage.data.uploadToken = TOKEN;
  await assert.rejects(s.c.handleMessage({ type: 'canvas.bridge.sync' }, page), /Connect this browser first/);
  Object.assign(s.storage.data, { portalOrigin: PORTAL, canvasOrigin: CANVAS });
  const before = s.requests.length;
  const r = (await s.c.handleMessage({ type: 'canvas.bridge.sync', force: true }, page)) as { ok: boolean; error?: string };
  // The stand-in portal answers 500 to the plan, so the run fails, but it did ask the portal.
  assert.equal(r.ok, false);
  assert.ok(r.error);
  assert.ok(s.requests.slice(before).some((u) => u.startsWith(`${PORTAL}/api/v1/extension/plan`)));
  assert.equal((s.storage.data.lastResult as { trigger: string }).trigger, 'manual');
});

test('the periodic sync starts a minute after connecting and repeats every 30 minutes', async () => {
  const s = setup({ storage: { portalOrigin: PORTAL, uploadToken: TOKEN } });
  await s.c.ensureAlarm();
  assert.deepEqual(s.alarms.get(ALARM_NAME), { delayInMinutes: 1, periodInMinutes: 30 });
  assert.equal(ALARM_MINUTES, 30);
});

test('a browser start syncs once a minute later, unless the last sync is recent', async () => {
  const stale = setup({
    storage: { portalOrigin: PORTAL, uploadToken: TOKEN, canvasOrigin: CANVAS, lastSyncAt: new Date(NOW - 3 * 3600_000).toISOString() },
    permissions: [`${CANVAS}/*`],
    // An open Canvas tab: the run goes straight to the portal's plan instead of probing Canvas first.
    tabs: [{ id: 1, url: `${CANVAS}/courses`, status: 'complete' }],
  });
  await stale.c.onStartup();
  assert.deepEqual(stale.alarms.get(STARTUP_ALARM), { delayInMinutes: 1 });
  await stale.c.onAlarm({ name: STARTUP_ALARM });
  assert.ok(stale.requests.some((u) => u.startsWith(`${PORTAL}/api/v1/extension/`)), stale.requests.join('\n'));
  const fresh = setup({
    storage: { portalOrigin: PORTAL, uploadToken: TOKEN, canvasOrigin: CANVAS, lastSyncAt: new Date(NOW - 60_000).toISOString() },
    permissions: [`${CANVAS}/*`],
  });
  await fresh.c.onAlarm({ name: STARTUP_ALARM });
  assert.deepEqual(fresh.requests, []);
  const signedOut = setup();
  await signedOut.c.onStartup();
  assert.equal(signedOut.alarms.get(STARTUP_ALARM), undefined);
});

test('reminder: stale data opens the reminder page once, never Canvas, and an ignored one snoozes', async () => {
  const { reminderDue, remindHours } = await import('../src/lib/reminder.ts');
  const old = new Date(NOW - 30 * 3600_000).toISOString();
  const s = setup({ storage: { portalOrigin: PORTAL, uploadToken: TOKEN, canvasOrigin: CANVAS, lastSyncAt: old } });
  await s.c.maybeRemind();
  assert.deepEqual(s.created.map((t) => t.url), [`chrome-extension://${EXT_ID}/reminder.html`]);
  assert.equal(s.storage.data.snoozeUntil, NOW + 12 * 3600_000);
  await s.c.maybeRemind();
  assert.equal(s.created.length, 1, 'snoozed, and already open');
  // Off, fresh, or not set up: nothing opens.
  for (const extra of [{ remindAfterHours: 0 }, { lastSyncAt: new Date(NOW - 3600_000).toISOString() }, { canvasOrigin: undefined }]) {
    const quiet = setup({ storage: { portalOrigin: PORTAL, uploadToken: TOKEN, canvasOrigin: CANVAS, lastSyncAt: old, ...extra } });
    await quiet.c.maybeRemind();
    assert.equal(quiet.created.length, 0, JSON.stringify(extra));
  }
  assert.equal(remindHours(undefined), 24);
  assert.equal(remindHours(7), 24);
  assert.equal(reminderDue({ connectedAt: new Date(NOW - 25 * 3600_000).toISOString() }, NOW), true);
  assert.equal(reminderDue({ lastSyncAt: old, snoozeUntil: NOW + 1 }, NOW), false);
});
