import test from 'node:test';
import assert from 'node:assert/strict';
import { runSync, type SyncDeps } from '../src/lib/sync.ts';
import type { FetchJob } from '../src/lib/allowlist.ts';
import type { FetchResult } from '../src/lib/canvas-fetch.ts';
import { CANVAS, PORTAL, TOKEN, jsonResponse } from './helpers.ts';

const PLAN = {
  planVersion: 3, canvasHost: null, maxPages: 7,
  resources: [
    { path: '/users/self', query: {} },
    { path: '/courses', query: { 'include[]': ['term'] }, paginate: true },
    { path: '/courses/{course_id}/assignments', query: {}, paginate: true, perCourse: true },
    { path: '/conversations', query: {} },
  ],
};

const CLEAN_PLAN = { ...PLAN, resources: PLAN.resources.filter((r) => r.path !== '/conversations') };

interface Setup {
  plan?: unknown;
  planStatus?: number;
  uploadStatus?: number;
  uploadBody?: unknown;
  canvas?: (job: FetchJob) => Partial<FetchResult>;
  maxBodyBytes?: number;
}

function setup(o: Setup = {}) {
  const posts: any[] = [];
  const canvasCalls: { jobs: FetchJob[]; maxPages: number }[] = [];
  const deps: SyncDeps = {
    now: () => new Date('2026-11-01T12:00:00Z'),
    fetch: (async (input: any, init: RequestInit = {}) => {
      const url = String(input);
      if (url.endsWith('/capabilities')) return jsonResponse({ browserSync: 1, maxBodyBytes: o.maxBodyBytes ?? 4194304 });
      if (url.endsWith('/plan')) return jsonResponse(o.plan ?? PLAN, { status: o.planStatus ?? 200 });
      if (url.endsWith('/snapshots')) {
        assert.equal(init.credentials, 'omit');
        assert.equal((init.headers as any).Authorization, `Bearer ${TOKEN}`);
        posts.push(JSON.parse(String(init.body)));
        const status = o.uploadStatus ?? 200;
        return jsonResponse(o.uploadBody ?? { accepted: posts.at(-1).resources.length, rejected: [] }, { status });
      }
      throw new Error('unexpected ' + url);
    }) as typeof fetch,
    readCanvas: async (_origin, jobs, maxPages) => {
      canvasCalls.push({ jobs, maxPages });
      return jobs.map((j) => {
        const base: FetchResult = { path: j.path, query: j.query, status: 200, body: [], pages: 1 };
        if (j.path === '/users/self') base.body = { id: 42 };
        if (j.path === '/courses') base.body = [{ id: 10 }, { id: 11 }];
        return { ...base, ...(o.canvas?.(j) ?? {}) };
      });
    },
  };
  return { deps, posts, canvasCalls };
}

const input = { portalOrigin: PORTAL, uploadToken: TOKEN, canvasOrigin: CANVAS };

test('happy path: plan, expansion over /courses ids, upload shape', async () => {
  const { deps, posts, canvasCalls } = setup();
  const out = await runSync(input, deps);
  assert.equal(out.ok, true);
  assert.deepEqual(canvasCalls[0]?.jobs.map((j) => j.path), ['/users/self', '/courses']);
  assert.deepEqual(canvasCalls[1]?.jobs.map((j) => j.path), ['/courses/10/assignments', '/courses/11/assignments']);
  assert.equal(canvasCalls[0]?.maxPages, 7);
  assert.equal(posts.length, 1);
  const p = posts[0];
  assert.equal(p.schemaVersion, 1);
  assert.equal(p.canvasOrigin, CANVAS);
  assert.equal(p.canvasUserId, 42);
  assert.equal(p.planVersion, 3);
  assert.equal(p.capturedAt, '2026-11-01T12:00:00.000Z');
  assert.equal(p.resources.length, 4);
  assert.equal(out.counts.skipped, 1); // /conversations is not on the allowlist
  assert.equal(out.counts.accepted, 4);
  assert.equal(out.code, 'partial');
});

test('splits the upload into several POSTs under maxBodyBytes', async () => {
  const { deps, posts } = setup({ maxBodyBytes: 12000, canvas: (j) => (j.path.endsWith('/assignments') ? { body: ['x'.repeat(5000)] } : {}) });
  const out = await runSync(input, deps);
  assert.equal(out.ok, true);
  assert.ok(posts.length >= 2);
  for (const p of posts) assert.ok(new TextEncoder().encode(JSON.stringify(p)).length <= 12000);
});

test('401 on plan or upload asks to reconnect', async () => {
  const a = await runSync(input, setup({ planStatus: 401 }).deps);
  assert.equal(a.code, 'unauthorized');
  assert.equal(a.reconnect, true);
  const b = await runSync(input, setup({ uploadStatus: 401, uploadBody: { error: 'invalid_token' } }).deps);
  assert.equal(b.reconnect, true);
});

test('409 canvas_mismatch explains the account or school differs', async () => {
  const out = await runSync(input, setup({ uploadStatus: 409, uploadBody: { error: 'canvas_mismatch' } }).deps);
  assert.equal(out.code, 'canvas_mismatch');
  assert.match(out.message, /different from the one paired/);
  assert.equal(out.reconnect, undefined);
});

test('413 and 429 are reported; 429 carries a back-off', async () => {
  const big = await runSync(input, setup({ uploadStatus: 413, uploadBody: {} }).deps);
  assert.equal(big.code, 'too_large');
  const { deps } = setup();
  const orig = deps.fetch;
  deps.fetch = (async (u: any, i: any) => (String(u).endsWith('/snapshots') ? new Response('', { status: 429, headers: { 'retry-after': '120' } }) : orig(u, i))) as typeof fetch;
  const limited = await runSync(input, deps);
  assert.equal(limited.code, 'rate_limited');
  assert.equal(limited.retryAfterMs, 120_000);
});

test('not signed in to Canvas stops before any upload', async () => {
  const s = setup({ canvas: (j) => (j.path === '/users/self' ? { status: null, body: null, error: 'not_signed_in' } : {}) });
  const out = await runSync(input, s.deps);
  assert.equal(out.code, 'not_signed_in');
  assert.equal(s.posts.length, 0);
  const s401 = setup({ canvas: (j) => (j.path === '/users/self' ? { status: 401, body: null } : {}) });
  assert.equal((await runSync(input, s401.deps)).code, 'not_signed_in');
});

test('non-200 resources are uploaded as status with null body; failed fetches are not', async () => {
  const s = setup({ canvas: (j) => (j.path === '/courses' ? { status: 403, body: null } : j.path === '/users/self' ? {} : {}) });
  const out = await runSync(input, s.deps);
  const courses = s.posts[0].resources.find((r: any) => r.path === '/courses');
  assert.equal(courses.status, 403);
  assert.equal(courses.body, null);
  // /courses failed, so per-course resources are skipped
  assert.ok(!s.posts[0].resources.some((r: any) => r.path.includes('/assignments')));
  assert.equal(out.ok, true);

  const s2 = setup({ canvas: (j) => (j.path === '/courses' ? { status: null, body: null, error: 'pagination_moved' } : {}) });
  const out2 = await runSync(input, s2.deps);
  assert.ok(!s2.posts[0].resources.some((r: any) => r.path === '/courses'));
  assert.ok(out2.counts.canvasErrors >= 1);
});

test('plan canvasHost that differs from the configured Canvas is refused', async () => {
  const s = setup({ plan: { ...PLAN, canvasHost: 'other.instructure.com' } });
  const out = await runSync(input, s.deps);
  assert.equal(out.code, 'canvas_mismatch');
  assert.equal(s.canvasCalls.length, 0);
});

test('a malformed plan is rejected without touching Canvas', async () => {
  const s = setup({ plan: { nope: true } });
  assert.equal((await runSync(input, s.deps)).code, 'plan_invalid');
  assert.equal(s.canvasCalls.length, 0);
});

test('alarm probe: signed-out Canvas ends quietly before contacting the portal', async () => {
  let portalCalls = 0;
  const s = setup({ canvas: () => ({ status: null, body: null, error: 'not_signed_in' }) });
  const orig = s.deps.fetch;
  s.deps.fetch = ((u: any, i: any) => (portalCalls++, orig(u, i))) as typeof fetch;
  const out = await runSync({ ...input, probeFirst: true }, s.deps);
  assert.equal(out.waiting, true);
  assert.equal(portalCalls, 0);
});

test('first upload (canvasHost null): plan is refetched once and only new resources are synced', async () => {
  const s = setup();
  const orig = s.deps.fetch;
  let planCalls = 0;
  const extra = { path: '/calendar_events', query: { 'context_codes[]': ['user_42'] }, paginate: true };
  s.deps.fetch = (async (u: any, i: any) => {
    if (String(u).endsWith('/plan')) {
      planCalls++;
      return jsonResponse(planCalls === 1 ? PLAN : { ...PLAN, canvasHost: null, planVersion: 4, resources: [...PLAN.resources, extra] });
    }
    return orig(u, i);
  }) as typeof fetch;
  const out = await runSync(input, s.deps);
  assert.equal(out.ok, true);
  assert.equal(planCalls, 2); // at most once more per run
  assert.equal(s.posts.length, 2);
  assert.deepEqual(s.posts[1].resources.map((r: any) => [r.path, r.query]), [[extra.path, extra.query]]);
  assert.equal(s.posts[1].canvasUserId, 42);
  assert.equal(s.posts[1].planVersion, 4);
  // Canvas was read for the new resource only (users/self and courses are not refetched).
  assert.deepEqual(s.canvasCalls.at(-1)?.jobs.map((j) => j.path), ['/calendar_events']);
  assert.equal(s.canvasCalls.length, 3);
  assert.equal(out.counts.accepted, 5);
});

test('no second pass when the plan already has a canvasHost', async () => {
  const s = setup({ plan: { ...PLAN, canvasHost: 'school.instructure.com' } });
  let planCalls = 0;
  const orig = s.deps.fetch;
  s.deps.fetch = ((u: any, i: any) => (String(u).endsWith('/plan') && planCalls++, orig(u, i))) as typeof fetch;
  await runSync(input, s.deps);
  assert.equal(planCalls, 1);
  assert.equal(s.posts.length, 1);
});

test('too_many_courses in rejected[] is a quota: plain English, backs off, no second pass', async () => {
  const s = setup({ uploadBody: { accepted: 1, rejected: [{ path: '/courses', reason: 'too_many_courses' }] } });
  const out = await runSync(input, s.deps);
  assert.equal(out.code, 'quota_exceeded');
  assert.equal(out.ok, false);
  assert.match(out.message, /more courses than the portal accepts/);
  assert.equal(out.retryAfterMs, 3_600_000);
  assert.ok(out.skipReasons?.some((r) => r.includes('more courses')));
  assert.equal(s.posts.length, 1);
});

test('kept_stored_data is expected: not rejected, not a skip, counted as kept', async () => {
  const s = setup({ plan: CLEAN_PLAN, uploadBody: { accepted: 3, rejected: [{ path: '/courses', reason: 'kept_stored_data' }] } });
  const out = await runSync(input, s.deps);
  assert.equal(out.ok, true);
  assert.equal(out.code, 'ok');
  assert.equal(out.counts.rejected, 0);
  assert.equal(out.counts.kept, 1);
  assert.deepEqual(out.skipReasons, []);
  assert.match(out.message, /1 kept previous data/);
});

test('other rejection reasons stay ordinary rejections', async () => {
  const out = await runSync(input, setup({ plan: CLEAN_PLAN, uploadBody: { accepted: 3, rejected: [{ path: '/x', reason: 'older_than_stored' }] } }).deps);
  assert.equal(out.code, 'partial');
  assert.equal(out.counts.rejected, 1);
  assert.deepEqual(out.skipReasons, ['/x: rejected by the portal (older_than_stored)']);
});

test('413 quota_exceeded backs off for an hour; other 413s keep the too-large handling', async () => {
  const q = await runSync(input, setup({ uploadStatus: 413, uploadBody: { error: 'quota_exceeded' } }).deps);
  assert.equal(q.code, 'quota_exceeded');
  assert.equal(q.retryAfterMs, 3_600_000);
  assert.match(q.message, /3000 items or 64 MiB/);
  const other = await runSync(input, setup({ uploadStatus: 413, uploadBody: { error: 'payload_too_large' } }).deps);
  assert.equal(other.code, 'too_large');
  assert.equal(other.retryAfterMs, undefined);
});

test('other 4xx errors back off but are not treated as quota', async () => {
  const other = await runSync(input, setup({ uploadStatus: 400, uploadBody: { error: 'bad_request' } }).deps);
  assert.equal(other.code, 'portal_error');
  assert.ok((other.retryAfterMs ?? 0) > 0);
  const server = await runSync(input, setup({ uploadStatus: 500, uploadBody: {} }).deps);
  assert.equal(server.retryAfterMs, undefined);
});
