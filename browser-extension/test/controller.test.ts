import test from 'node:test';
import assert from 'node:assert/strict';
import { createController } from '../src/lib/controller.ts';
import { pairingUrl } from '../src/lib/pairing.ts';
import { CANVAS, EXT_ID, POPUP_URL, PORTAL, TOKEN, jsonResponse, makeChrome } from './helpers.ts';

const popup = { id: EXT_ID, url: POPUP_URL };
const NOW = Date.parse('2026-11-01T12:00:00Z');
const rand = (n: number) => new Uint8Array(n).fill(1);

function setup(chromeOpts: Parameters<typeof makeChrome>[0] = {}, fetchImpl?: (url: string, init: any) => Response | Promise<Response>) {
  const m = makeChrome(chromeOpts);
  const requests: { url: string; init: any }[] = [];
  const fetchFn = (async (input: any, init: any = {}) => {
    requests.push({ url: String(input), init });
    return fetchImpl ? fetchImpl(String(input), init) : jsonResponse({});
  }) as typeof fetch;
  const c = createController(m.api, { fetch: fetchFn, now: () => NOW, randomBytes: rand });
  return { ...m, c, requests };
}

const connected = { portalOrigin: PORTAL, uploadToken: TOKEN, canvasOrigin: CANVAS };
const granted = ['https://school.instructure.com/*', 'https://portal.example.com/*'];

test('pairing: start checks capabilities, opens the pairing tab and injects only there', async () => {
  const s = setup({ permissions: granted }, () => jsonResponse({ browserSync: 1, maxBodyBytes: 100000 }));
  assert.deepEqual(await s.c.handleMessage({ type: 'canvas.pair.start', portalOrigin: PORTAL }, popup), { ok: true });
  assert.equal(s.requests[0]?.url, `${PORTAL}/api/v1/extension/capabilities`);
  assert.equal(s.created.length, 1);
  assert.match(s.created[0].url, /^https:\/\/portal\.example\.com\/account\/browser-extension#extension-auth=[a-f0-9]{64}$/);
  assert.equal(s.injected.length, 1);
  assert.deepEqual(s.injected[0].target, { tabId: 100 });
  assert.deepEqual(s.injected[0].files, ['link.js']);
  const pairing = s.storage.data.pairing as any;
  assert.equal(pairing.tabId, 100);
  assert.equal(pairing.expires, NOW + 600_000);
});

test('pairing: refuses without host permission or when capabilities are missing', async () => {
  const noPerm = setup({}, () => jsonResponse({ browserSync: 1 }));
  await assert.rejects(noPerm.c.handleMessage({ type: 'canvas.pair.start', portalOrigin: PORTAL }, popup), /Allow the extension/);
  const old = setup({ permissions: granted }, () => jsonResponse({}, { status: 404 }));
  await assert.rejects(old.c.handleMessage({ type: 'canvas.pair.start', portalOrigin: PORTAL }, popup), /does not support browser sync/);
  assert.equal(old.created.length, 0);
});

async function startedPairing() {
  const s = setup({ permissions: granted }, (url) =>
    url.endsWith('/capabilities') ? jsonResponse({ browserSync: 1 }) : jsonResponse({ uploadToken: TOKEN, bindingId: 'b1' }),
  );
  await s.c.handleMessage({ type: 'canvas.pair.start', portalOrigin: PORTAL }, popup);
  const p = s.storage.data.pairing as any;
  return { s, p, sender: { id: EXT_ID, tab: { id: p.tabId }, url: pairingUrl(p) } };
}

test('pairing: a valid claim stores the connection with credentials omitted', async () => {
  const { s, p, sender } = await startedPairing();
  assert.deepEqual(await s.c.handleMessage({ type: 'canvas.pair.claim', state: p.state, code: 'abcdef123456' }, sender), { ok: true });
  const claim = s.requests.at(-1)!;
  assert.equal(claim.url, `${PORTAL}/api/v1/extension/claim`);
  assert.equal(claim.init.credentials, 'omit');
  assert.equal(claim.init.redirect, 'error');
  assert.equal(s.storage.data.uploadToken, TOKEN);
  assert.equal(s.storage.data.portalOrigin, PORTAL);
  assert.equal((s.storage.data.pairing as any).status, 'connected');
  assert.ok(s.alarms.has('canvas-sync'));
});

test('pairing: claims from the wrong tab, origin, state or after expiry are refused and nothing is stored', async () => {
  const { s, p, sender } = await startedPairing();
  const before = s.requests.length;
  await assert.rejects(s.c.handleMessage({ type: 'canvas.pair.claim', state: p.state, code: 'abcdef123456' }, { ...sender, tab: { id: 5 } }));
  await assert.rejects(s.c.handleMessage({ type: 'canvas.pair.claim', state: p.state, code: 'abcdef123456' }, { ...sender, url: sender.url.replace(PORTAL, 'https://evil.example') }));
  await assert.rejects(s.c.handleMessage({ type: 'canvas.pair.claim', state: '0'.repeat(64), code: 'abcdef123456' }, sender));
  await assert.rejects(s.c.handleMessage({ type: 'canvas.pair.claim', state: p.state, code: 'abcdef123456' }, { ...sender, id: 'other' }));
  assert.equal(s.requests.length, before);
  assert.equal(s.storage.data.uploadToken, undefined);
  const expired = createController(s.api, { fetch: s.c as any, now: () => NOW + 11 * 60_000, randomBytes: rand });
  await assert.rejects(expired.handleMessage({ type: 'canvas.pair.claim', state: p.state, code: 'abcdef123456' }, sender), /expired/);
});

test('pairing: a rejected code is recorded as an error and not retried', async () => {
  const s = setup({ permissions: granted }, (url) => (url.endsWith('/capabilities') ? jsonResponse({ browserSync: 1 }) : jsonResponse({ error: 'invalid_code' }, { status: 400 })));
  await s.c.handleMessage({ type: 'canvas.pair.start', portalOrigin: PORTAL }, popup);
  const p = s.storage.data.pairing as any;
  await assert.rejects(s.c.handleMessage({ type: 'canvas.pair.claim', state: p.state, code: 'abcdef123456' }, { id: EXT_ID, tab: { id: p.tabId }, url: pairingUrl(p) }), /invalid, expired/);
  assert.equal((s.storage.data.pairing as any).status, 'error');
  assert.equal(s.storage.data.uploadToken, undefined);
});

test('messages: popup-only requests are refused from content scripts, other extensions and web pages', async () => {
  const s = setup({ storage: connected, permissions: granted });
  for (const type of ['canvas.sync.now', 'canvas.disconnect', 'canvas.pair.start', 'canvas.pair.manual', 'canvas.canvas.set']) {
    await assert.rejects(s.c.handleMessage({ type }, { id: EXT_ID, url: 'https://school.instructure.com/', tab: { id: 1 } }), /refused/, type);
    await assert.rejects(s.c.handleMessage({ type }, { id: 'other-extension', url: POPUP_URL }), /refused/, type);
    await assert.rejects(s.c.handleMessage({ type }, {}), /refused/, type);
  }
  assert.equal(s.requests.length, 0);
  assert.equal(s.storage.data.uploadToken, TOKEN);
});

test('canvas.set requires host permission and a valid origin; a new school resets sync history', async () => {
  const s = setup({ storage: { ...connected, lastSyncAt: 'x' }, permissions: granted });
  await assert.rejects(s.c.handleMessage({ type: 'canvas.canvas.set', canvasOrigin: 'https://other.instructure.com' }, popup), /Allow the extension/);
  await assert.rejects(s.c.handleMessage({ type: 'canvas.canvas.set', canvasOrigin: 'https://a.com/path' }, popup));
  s.granted.add('https://other.instructure.com/*');
  await s.c.handleMessage({ type: 'canvas.canvas.set', canvasOrigin: 'https://other.instructure.com' }, popup);
  assert.equal(s.storage.data.canvasOrigin, 'https://other.instructure.com');
  assert.equal(s.storage.data.lastSyncAt, undefined);
});

function syncFetch(opts: { uploadStatus?: number; uploadBody?: unknown } = {}) {
  return (url: string) => {
    if (url.endsWith('/capabilities')) return jsonResponse({ browserSync: 1, maxBodyBytes: 4194304 });
    if (url.endsWith('/plan')) return jsonResponse({ planVersion: 1, canvasHost: null, maxPages: 5, resources: [{ path: '/users/self', query: {} }] });
    if (url.endsWith('/snapshots')) return jsonResponse(opts.uploadBody ?? { accepted: 1, rejected: [] }, { status: opts.uploadStatus ?? 200 });
    return jsonResponse({});
  };
}
const canvasTab = [{ id: 5, url: `${CANVAS}/`, status: 'complete' }];
const tabScript = async () => [{ result: [{ path: '/users/self', query: {}, status: 200, body: { id: 9 }, pages: 1 }] }];

test('sync.now runs the fetches inside the Canvas tab and records the result', async () => {
  const s = setup({ storage: connected, permissions: granted, tabs: canvasTab, executeScript: tabScript }, syncFetch());
  const res: any = await s.c.handleMessage({ type: 'canvas.sync.now' }, popup);
  assert.equal(res.ok, true);
  assert.equal(s.injected.length, 1);
  assert.equal(s.injected[0].target.tabId, 5);
  assert.equal(s.injected[0].args[0], CANVAS);
  assert.equal(typeof s.injected[0].func, 'function');
  assert.equal(s.storage.data.lastSyncAt, new Date(NOW).toISOString());
  assert.equal((s.storage.data.lastResult as any).counts.accepted, 1);
});

test('storage handling: 401 forgets the token and keeps settings; 409 keeps the connection', async () => {
  const unauth = setup({ storage: connected, permissions: granted, tabs: canvasTab, executeScript: tabScript }, syncFetch({ uploadStatus: 401, uploadBody: { error: 'invalid_token' } }));
  const r1: any = await unauth.c.handleMessage({ type: 'canvas.sync.now' }, popup);
  assert.equal(r1.ok, false);
  assert.equal(unauth.storage.data.uploadToken, undefined);
  assert.equal(unauth.storage.data.needsReconnect, true);
  assert.equal(unauth.storage.data.portalOrigin, PORTAL);
  assert.equal(unauth.storage.data.canvasOrigin, CANVAS);

  const mismatch = setup({ storage: connected, permissions: granted, tabs: canvasTab, executeScript: tabScript }, syncFetch({ uploadStatus: 409, uploadBody: { error: 'canvas_mismatch' } }));
  const r2: any = await mismatch.c.handleMessage({ type: 'canvas.sync.now' }, popup);
  assert.match(r2.error, /different from the one paired/);
  assert.equal(mismatch.storage.data.uploadToken, TOKEN);
  assert.equal((mismatch.storage.data.lastResult as any).code, 'canvas_mismatch');
  assert.equal(mismatch.storage.data.lastSyncAt, undefined);
});

test('429 sets a back-off that blocks the next run', async () => {
  const s = setup({ storage: connected, permissions: granted, tabs: canvasTab, executeScript: tabScript }, (url) =>
    url.endsWith('/snapshots') ? new Response('', { status: 429, headers: { 'retry-after': '600' } }) : (syncFetch() as any)(url),
  );
  await s.c.handleMessage({ type: 'canvas.sync.now' }, popup);
  assert.equal(s.storage.data.backoffUntil, NOW + 600_000);
  const again: any = await s.c.handleMessage({ type: 'canvas.sync.now' }, popup);
  assert.equal(again.outcome.code, 'rate_limited');
});

test('sync without Canvas host permission or connection does not call anything', async () => {
  const noPerm = setup({ storage: connected, permissions: [] });
  const r: any = await noPerm.c.handleMessage({ type: 'canvas.sync.now' }, popup);
  assert.equal(r.ok, false);
  assert.equal(noPerm.requests.length, 0);
  const none = setup({});
  assert.equal(((await none.c.handleMessage({ type: 'canvas.sync.now' }, popup)) as any).outcome.code, 'not_connected');
});

test('alarm with no Canvas tab probes from the service worker and stays silent when signed out', async () => {
  const realFetch = globalThis.fetch;
  const probes: string[] = [];
  globalThis.fetch = (async (u: any, i: any) => {
    probes.push(`${u}|${i?.credentials}`);
    return jsonResponse('<html>', { headers: { 'content-type': 'text/html' } });
  }) as typeof fetch;
  try {
    const s = setup({ storage: connected, permissions: granted, tabs: [] }, syncFetch());
    await s.c.onAlarm({ name: 'canvas-sync' });
    assert.deepEqual(probes, [`${CANVAS}/api/v1/users/self|include`]);
    assert.equal(s.requests.length, 0); // portal untouched
    assert.equal(s.storage.data.lastResult, undefined);
    assert.equal(s.injected.length, 0);
    assert.equal(s.created.length, 0); // never opens tabs
  } finally {
    globalThis.fetch = realFetch;
  }
});

test('disconnect revokes at the portal and clears all stored data', async () => {
  const s = setup({ storage: { ...connected, lastSyncAt: 'x', lastResult: {} }, permissions: granted }, () => new Response(null, { status: 204 }));
  s.alarms.set('canvas-sync', {});
  const res: any = await s.c.handleMessage({ type: 'canvas.disconnect' }, popup);
  assert.equal(res.remoteRevoked, true);
  assert.equal(s.requests[0]?.init.method, 'DELETE');
  assert.equal(s.requests[0]?.url, `${PORTAL}/api/v1/extension/binding`);
  assert.equal(s.requests[0]?.init.headers.Authorization, `Bearer ${TOKEN}`);
  assert.equal(s.requests[0]?.init.credentials, 'omit');
  assert.deepEqual(Object.keys(s.storage.data), []);
  assert.equal(s.alarms.size, 0);
});

test('disconnect still clears local data when the portal is unreachable and says so', async () => {
  const s = setup({ storage: connected, permissions: granted }, () => {
    throw new TypeError('offline');
  });
  const res: any = await s.c.handleMessage({ type: 'canvas.disconnect' }, popup);
  assert.equal(res.remoteRevoked, false);
  assert.match(res.message, /remove the connection from your account page/);
  assert.deepEqual(Object.keys(s.storage.data), []);
});

test('tab visit throttling: skips recent syncs and non-Canvas origins', async () => {
  const recent = setup({ storage: { ...connected, lastSyncAt: new Date(NOW - 5 * 60_000).toISOString() }, permissions: granted, tabs: canvasTab, executeScript: tabScript }, syncFetch());
  await recent.c.onTabUpdated(5, { status: 'complete' }, { url: `${CANVAS}/courses` });
  const foreign = setup({ storage: connected, permissions: granted, tabs: canvasTab, executeScript: tabScript }, syncFetch());
  await foreign.c.onTabUpdated(5, { status: 'complete' }, { url: 'https://school.instructure.com.evil.com/' });
  await foreign.c.onTabUpdated(5, { status: 'loading' }, { url: `${CANVAS}/` });
  await new Promise((r) => setTimeout(r, 1800));
  assert.equal(recent.requests.length, 0);
  assert.equal(foreign.requests.length, 0);
});

test('tab visit after 10+ minutes triggers a sync', async () => {
  const s = setup({ storage: { ...connected, lastSyncAt: new Date(NOW - 11 * 60_000).toISOString() }, permissions: granted, tabs: canvasTab, executeScript: tabScript }, syncFetch());
  await s.c.onTabUpdated(5, { status: 'complete' }, { url: `${CANVAS}/courses` });
  await new Promise((r) => setTimeout(r, 1800));
  assert.ok(s.requests.some((r) => r.url.endsWith('/snapshots')));
});

test('lastFetchedAt: set after a sync, pruned when keys leave the plan, and "Sync now" forces cold resources', async () => {
  const plan = { planVersion: 2, canvasHost: null, maxPages: 5, coldIntervalHours: 12, resources: [{ path: '/users/self', query: {} }, { path: '/announcements', query: {}, tier: 'cold' }] };
  const recent = new Date(NOW - 3600_000).toISOString();
  const script = async (d: any) => [{ result: d.args[1].map((j: any) => ({ path: j.path, query: j.query, status: 200, body: j.path === '/users/self' ? { id: 9 } : [], pages: 1 })) }];
  const s = setup(
    { storage: { ...connected, lastFetchedAt: { '/announcements?{}': recent, '/stale?{}': recent } }, permissions: granted, tabs: canvasTab, executeScript: script },
    (url) => (url.endsWith('/plan') ? jsonResponse(plan) : (syncFetch() as any)(url)),
  );
  await s.c.handleMessage({ type: 'canvas.sync.now' }, popup);
  const lf = s.storage.data.lastFetchedAt as Record<string, string>;
  assert.deepEqual(Object.keys(lf).sort(), ['/announcements?{}', '/users/self?{}']);
  assert.equal(lf['/announcements?{}'], new Date(NOW).toISOString()); // forced by Sync now, so refreshed
  // A page visit does not force: the cold item is now fresh and is skipped.
  s.injected.length = 0;
  await s.c.runSyncOnce('tab');
  assert.deepEqual(s.injected[0].args[1].map((j: any) => j.path), ['/users/self']);
});

const V2 = (resources: object[]) => ({ planVersion: 2, canvasHost: 'school.instructure.com', maxPages: 5, coldIntervalHours: 12, resources });
const COURSE_SRC = { path: '/courses', query: { enrollment_state: 'active' }, paginate: true, courseSource: true };
const COLD_MODULES = { path: '/courses/{course_id}/modules', query: {}, expand: 'eachCourse', tier: 'cold' };
const modKey = (id: number) => `/courses/${id}/modules?{}`;

test('after a course set change, stored fetch times keep only keys of this run and per-course entries are reset', async () => {
  const plan = V2([{ path: '/users/self', query: {} }, COURSE_SRC, COLD_MODULES]);
  const script = async (d: any) => [{ result: d.args[1].map((j: any) => ({ path: j.path, query: j.query, status: 200, pages: 1,
    body: j.path === '/users/self' ? { id: 9 } : j.path === '/courses' ? [{ id: 2 }, { id: 3 }] : [] })) }];
  const recent = new Date(NOW - 3600_000).toISOString();
  const s = setup(
    { storage: { ...connected, lastCourseIds: [1, 2], lastFetchedAt: { [modKey(1)]: recent, [modKey(2)]: recent } }, permissions: granted, tabs: canvasTab, executeScript: script },
    (url) => (url.endsWith('/plan') ? jsonResponse(plan) : (syncFetch() as any)(url)),
  );
  await s.c.runSyncOnce('tab');
  const lf = s.storage.data.lastFetchedAt as Record<string, string>;
  assert.equal(lf[modKey(1)], undefined); // left the plan
  assert.equal(lf[modKey(2)], new Date(NOW).toISOString()); // refetched under the new set
  assert.equal(lf[modKey(3)], new Date(NOW).toISOString());
  assert.deepEqual(s.storage.data.lastCourseIds, [2, 3]);
});


test('page visits and the alarm are budgeted once synced before; Sync now and the first sync are not; timing is stored', async () => {
  const plan = V2([{ path: '/users/self', query: {} }, COURSE_SRC, COLD_MODULES]);
  const script = async (d: any) => [{ result: d.args[1].map((j: any) => ({ path: j.path, query: j.query, status: 200, pages: 1, ms: 7, bytes: 11,
    body: j.path === '/users/self' ? { id: 9 } : j.path === '/courses' ? Array.from({ length: 40 }, (_, i) => ({ id: i + 1 })) : [] })) }];
  const mk = (extra: Record<string, unknown>) => setup(
    { storage: { ...connected, ...extra }, permissions: granted, tabs: canvasTab, executeScript: script },
    (url) => (url.endsWith('/plan') ? jsonResponse(plan) : (syncFetch() as any)(url)),
  );
  const perCourseRequests = (s: ReturnType<typeof mk>) => s.injected.flatMap((d: any) => d.args[1]).filter((j: any) => j.path.endsWith('/modules')).length;
  const first = mk({});
  await first.c.runSyncOnce('tab');
  assert.equal(perCourseRequests(first), 40); // no lastSyncAt: first sync after pairing is unbudgeted
  const visit = mk({ lastSyncAt: new Date(NOW - 3600_000).toISOString(), lastCourseIds: Array.from({ length: 40 }, (_, i) => i + 1) });
  await visit.c.runSyncOnce('tab');
  assert.equal(perCourseRequests(visit), 30);
  const manual = mk({ lastSyncAt: new Date(NOW - 3600_000).toISOString(), lastCourseIds: Array.from({ length: 40 }, (_, i) => i + 1) });
  await manual.c.runSyncOnce('manual');
  assert.equal(perCourseRequests(manual), 40);
  const timing = (visit.storage.data.lastResult as any).timing;
  assert.equal(typeof timing.totalMs, 'number');
  assert.ok(timing.slowest.length > 0 && timing.slowest.length <= 5);
});
