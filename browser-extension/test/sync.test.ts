import test from 'node:test';
import assert from 'node:assert/strict';
import { runSync, type SyncDeps } from '../src/lib/sync.ts';
import { validateQuery } from '../src/lib/allowlist.ts';
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

test('courseSource: per-course expansion uses only flagged /courses results', async () => {
  const plan = {
    ...PLAN,
    resources: [
      { path: '/users/self', query: {} },
      { path: '/courses', query: { enrollment_state: 'active' }, paginate: true, courseSource: true },
      { path: '/courses', query: {}, paginate: true },
      { path: '/courses/{course_id}/assignments', query: {}, paginate: true, perCourse: true },
    ],
  };
  const s = setup({
    plan,
    canvas: (j) => (j.path === '/courses' ? { body: j.query.enrollment_state ? [{ id: 10 }] : [{ id: 10 }, { id: 99 }] } : {}),
  });
  await runSync(input, s.deps);
  assert.deepEqual(s.canvasCalls[1]?.jobs.map((j) => j.path), ['/courses/10/assignments']);
});

test('without any courseSource flag, all /courses results are used (older portals)', async () => {
  const plan = {
    ...PLAN,
    resources: [
      { path: '/users/self', query: {} },
      { path: '/courses', query: { enrollment_state: 'active' }, paginate: true },
      { path: '/courses', query: {}, paginate: true },
      { path: '/courses/{course_id}/assignments', query: {}, perCourse: true },
    ],
  };
  const s = setup({
    plan,
    canvas: (j) => (j.path === '/courses' ? { body: j.query.enrollment_state ? [{ id: 10 }] : [{ id: 99 }] } : {}),
  });
  await runSync(input, s.deps);
  assert.deepEqual(s.canvasCalls[1]?.jobs.map((j) => j.path).sort(), ['/courses/10/assignments', '/courses/99/assignments']);
});

test('a resource still throttled by Canvas is left out of the upload with a skip reason', async () => {
  const s = setup({ plan: CLEAN_PLAN, canvas: (j) => (j.path === '/courses' ? { status: null, body: null, error: 'rate_limited' } : {}) });
  const out = await runSync(input, s.deps);
  assert.ok(!s.posts[0].resources.some((r: any) => r.path === '/courses'));
  assert.ok(s.posts[0].resources.every((r: any) => r.status !== 403));
  assert.ok(out.skipReasons?.includes('/courses: rate limited by Canvas'));
  assert.equal(out.counts.skipped >= 1, true);
  assert.equal(out.counts.canvasErrors, 0);
});

// ---- plan v2: tiers and courseList ----
const COLD_KEY = '/announcements?{}';
const V2_PLAN = {
  planVersion: 2, canvasHost: 'school.instructure.com', maxPages: 5, coldIntervalHours: 12,
  resources: [
    { path: '/users/self', query: {} },
    { path: '/announcements', query: {}, tier: 'cold' },
  ],
};
const hoursAgo = (h: number) => new Date(Date.parse('2026-11-01T12:00:00Z') - h * 3600_000).toISOString();
const fetchedPaths = (s: ReturnType<typeof setup>) => s.canvasCalls.flatMap((c) => c.jobs.map((j) => j.path));

test('cold tier gating: never fetched is fetched', async () => {
  const s = setup({ plan: V2_PLAN });
  const out = await runSync({ ...input, lastFetched: {} }, s.deps);
  assert.ok(fetchedPaths(s).includes('/announcements'));
  assert.ok(out.fetchedKeys?.includes(COLD_KEY));
  assert.equal(out.counts.notDue ?? 0, 0);
});

test('cold tier gating: not due is skipped on purpose, not uploaded, not an error', async () => {
  const s = setup({ plan: V2_PLAN });
  const out = await runSync({ ...input, lastFetched: { [COLD_KEY]: hoursAgo(1) } }, s.deps);
  assert.ok(!fetchedPaths(s).includes('/announcements'));
  assert.ok(!s.posts[0].resources.some((r: any) => r.path === '/announcements'));
  assert.equal(out.counts.notDue, 1);
  assert.equal(out.code, 'ok');
  assert.ok(!out.fetchedKeys?.includes(COLD_KEY));
  assert.ok(out.planKeys?.includes(COLD_KEY)); // still in the plan, so it is not pruned
  assert.match(out.message, /1 not due yet/);
});

test('cold tier gating: due after coldIntervalHours, and forced by Sync now', async () => {
  const due = setup({ plan: V2_PLAN });
  await runSync({ ...input, lastFetched: { [COLD_KEY]: hoursAgo(13) } }, due.deps);
  assert.ok(fetchedPaths(due).includes('/announcements'));
  const forced = setup({ plan: V2_PLAN });
  const out = await runSync({ ...input, force: true, lastFetched: { [COLD_KEY]: hoursAgo(1) } }, forced.deps);
  assert.ok(fetchedPaths(forced).includes('/announcements'));
  assert.equal(out.counts.notDue ?? 0, 0);
});

test('hot resources (and a missing tier) are fetched every time', async () => {
  const s = setup({ plan: { ...V2_PLAN, resources: [...V2_PLAN.resources, { path: '/planner_notes', query: {}, tier: 'hot' }] } });
  await runSync({ ...input, lastFetched: { '/planner_notes?{}': hoursAgo(0.1) } }, s.deps);
  assert.ok(fetchedPaths(s).includes('/planner_notes'));
});

test('a cold /courses list or profile is still fetched, since they drive expansion', async () => {
  const plan = { ...V2_PLAN, resources: [{ path: '/users/self', query: {}, tier: 'cold' }, { path: '/courses', query: {}, tier: 'cold', courseSource: true }] };
  const s = setup({ plan });
  const out = await runSync({ ...input, lastFetched: { '/users/self?{}': hoursAgo(1), '/courses?{}': hoursAgo(1) } }, s.deps);
  assert.equal(out.ok, true);
  assert.deepEqual(fetchedPaths(s), ['/users/self', '/courses']);
});

test('courseList over courseSource ids uploads chunked requests; mixed v1 and v2 resources work together', async () => {
  const ids = Array.from({ length: 23 }, (_, i) => 23 - i); // descending on purpose
  const plan = {
    planVersion: 2, canvasHost: 'school.instructure.com', maxPages: 5, coldIntervalHours: 12,
    resources: [
      { path: '/users/self', query: {} },
      { path: '/courses', query: { enrollment_state: 'active' }, paginate: true, courseSource: true },
      { path: '/courses', query: {}, paginate: true },
      { path: '/courses/{course_id}/modules', query: {}, perCourse: true }, // v1 style
      { path: '/announcements', query: { 'context_codes[]': ['course_{course_id}'] }, paginate: true, expand: 'courseList', tier: 'cold' },
    ],
  };
  const s = setup({
    plan,
    canvas: (j) => (j.path === '/courses' ? { body: j.query.enrollment_state ? ids.map((id) => ({ id })) : [{ id: 999 }] } : {}),
  });
  const out = await runSync({ ...input, lastFetched: {} }, s.deps);
  assert.equal(out.ok, true);
  const jobs = s.canvasCalls[1]!.jobs;
  const announcements = jobs.filter((j) => j.path === '/announcements');
  assert.deepEqual(announcements.map((j) => (j.query['context_codes[]'] as string[]).length), [10, 10, 3]);
  assert.equal(jobs.filter((j) => j.path.endsWith('/modules')).length, 23); // v1 perCourse = eachCourse
  assert.ok(!jobs.some((j) => j.path.includes('999')));
  // Everything fetched is reported so the caller can record last-fetched times.
  assert.equal(out.fetchedKeys?.filter((k) => k.startsWith('/announcements')).length, 3);
});

test('fetch times are recorded for every uploaded resource, rejected ones too (they wait one interval)', async () => {
  const plan = {
    planVersion: 2, canvasHost: 'school.instructure.com', maxPages: 5, coldIntervalHours: 12,
    resources: ['/users/self', '/announcements', '/planner_notes', '/calendar_events', '/courses', '/planner/items'].map((path) => ({ path, query: {}, tier: 'cold' })),
  };
  const rejected = [
    { path: '/announcements', reason: 'kept_stored_data' },
    { path: '/planner_notes', reason: 'older_than_stored' },
    { path: '/calendar_events', reason: 'not_in_plan' },
    { path: '/courses', reason: 'too_many_courses' },
    { path: '/planner/items', reason: 'invalid_resource' },
  ];
  const out = await runSync({ ...input, force: true }, setup({ plan, uploadBody: { accepted: 1, rejected } }).deps);
  const keys = (out.fetchedKeys ?? []).map((k) => k.split('?')[0]).sort();
  assert.deepEqual(keys, ['/announcements', '/calendar_events', '/courses', '/planner/items', '/planner_notes', '/users/self']);
});

test('an unreadable upload acknowledgement records no fetch times', async () => {
  const s = setup({ plan: V2_PLAN, uploadBody: 'not json' });
  const out = await runSync(input, s.deps);
  assert.deepEqual(out.fetchedKeys, []);
});

test('course ids skip unpublished courses and non-integers, keep objects without workflow_state, for both expand modes', async () => {
  const courses = [
    { id: 30, workflow_state: 'available' }, { id: 10 }, { id: 20, workflow_state: 'unpublished' },
    { id: 1.5, workflow_state: 'available' }, { id: '7' }, { id: 10, workflow_state: 'available' }, { id: 5, workflow_state: 'completed' }, null,
  ];
  const plan = {
    planVersion: 2, canvasHost: 'school.instructure.com', maxPages: 5, coldIntervalHours: 12,
    resources: [
      { path: '/users/self', query: {} },
      { path: '/courses', query: { enrollment_state: 'active' }, paginate: true, courseSource: true },
      { path: '/courses/{course_id}/modules', query: {}, expand: 'eachCourse' },
      { path: '/announcements', query: { 'context_codes[]': ['course_{course_id}'] }, expand: 'courseList', chunk: 2 },
    ],
  };
  const s = setup({ plan, canvas: (j) => (j.path === '/courses' ? { body: courses } : {}) });
  await runSync(input, s.deps);
  const jobs = s.canvasCalls[1]!.jobs;
  assert.deepEqual(jobs.filter((j) => j.path.endsWith('/modules')).map((j) => j.path), ['/courses/5/modules', '/courses/10/modules', '/courses/30/modules']);
  assert.deepEqual(jobs.filter((j) => j.path === '/announcements').map((j) => j.query['context_codes[]']), [['course_5', 'course_10'], ['course_30']]);
});

test('fallback (no courseSource flag) applies the same unpublished filter', async () => {
  const plan = {
    ...PLAN, canvasHost: 'school.instructure.com',
    resources: [{ path: '/users/self', query: {} }, { path: '/courses', query: {} }, { path: '/courses/{course_id}/modules', query: {}, perCourse: true }],
  };
  const s = setup({ plan, canvas: (j) => (j.path === '/courses' ? { body: [{ id: 2, workflow_state: 'unpublished' }, { id: 1 }] } : {}) });
  await runSync(input, s.deps);
  assert.deepEqual(s.canvasCalls[1]!.jobs.map((j) => j.path), ['/courses/1/modules']);
});

test('group_<id> context codes pass validation and are synced by the first-upload second pass', async () => {
  assert.equal(validateQuery({ 'context_codes[]': ['group_123'], type: 'event' }), null);
  const s = setup();
  const orig = s.deps.fetch;
  let planCalls = 0;
  const group = { path: '/calendar_events', query: { 'context_codes[]': ['group_123'], type: 'event' }, paginate: true, tier: 'hot' };
  s.deps.fetch = (async (u: any, i: any) =>
    String(u).endsWith('/plan')
      ? jsonResponse(++planCalls === 1 ? { ...PLAN, canvasHost: null } : { ...PLAN, canvasHost: null, resources: [...PLAN.resources, group] })
      : orig(u, i)) as typeof fetch;
  const out = await runSync(input, s.deps);
  assert.equal(out.ok, true);
  assert.deepEqual(s.canvasCalls.at(-1)!.jobs.map((j) => j.query['context_codes[]']), [['group_123']]);
  assert.equal(s.posts.at(-1).resources[0].query['context_codes[]'][0], 'group_123');
});

// ---- course-set consistency and upload ordering ----
const V2 = (resources: object[]) => ({ planVersion: 2, canvasHost: 'school.instructure.com', maxPages: 5, coldIntervalHours: 12, resources });
const COURSE_SRC = { path: '/courses', query: { enrollment_state: 'active' }, paginate: true, courseSource: true };
const COLD_MODULES = { path: '/courses/{course_id}/modules', query: {}, expand: 'eachCourse', tier: 'cold' };
const modKey = (id: number) => `/courses/${id}/modules?{}`;

test('a changed course set refetches all per-course data even when cold items are not due; an unchanged set does not', async () => {
  const plan = V2([{ path: '/users/self', query: {} }, COURSE_SRC, COLD_MODULES]);
  const canvas = (j: FetchJob) => (j.path === '/courses' ? { body: [{ id: 1 }, { id: 2 }, { id: 3 }] } : {});
  const recent = { [modKey(1)]: hoursAgo(1), [modKey(2)]: hoursAgo(1), [modKey(3)]: hoursAgo(1) };
  const changed = setup({ plan, canvas });
  const out = await runSync({ ...input, lastFetched: recent, lastCourseIds: [1, 2] }, changed.deps);
  assert.equal(changed.canvasCalls[1]!.jobs.length, 3);
  assert.equal(out.courseSetChanged, true);
  assert.deepEqual(out.courseIds, [1, 2, 3]);
  assert.deepEqual([...(out.perCourseKeys ?? [])].sort(), [modKey(1), modKey(2), modKey(3)]);
  const same = setup({ plan, canvas });
  const out2 = await runSync({ ...input, lastFetched: recent, lastCourseIds: [3, 2, 1] }, same.deps);
  assert.equal(same.canvasCalls.length, 1); // nothing per-course is due
  assert.equal(out2.courseSetChanged, false);
  assert.equal(out2.counts.notDue, 3);
});

test('if a courseSource list fails, nothing is expanded, nothing is recorded, and the reason is "course list unavailable"', async () => {
  const plan = V2([
    { path: '/users/self', query: {} }, COURSE_SRC,
    { path: '/courses', query: { enrollment_state: 'completed' }, courseSource: true },
    COLD_MODULES,
    { path: '/announcements', query: { 'context_codes[]': ['course_{course_id}'] }, expand: 'courseList' },
  ]);
  const s = setup({ plan, canvas: (j) => (j.path === '/courses' ? (j.query.enrollment_state === 'completed' ? { status: 500, body: null } : { body: [{ id: 1 }] }) : {}) });
  const out = await runSync({ ...input, lastFetched: {} }, s.deps);
  assert.equal(s.canvasCalls.length, 1); // no per-course reads
  assert.ok(!out.fetchedKeys?.some((k) => k.includes('/modules') || k.startsWith('/announcements')));
  assert.equal(out.planKeys, undefined); // plan not fully seen, so no pruning
  assert.equal(out.courseIds, undefined);
  assert.equal(out.skipReasons?.filter((r) => r.endsWith('course list unavailable')).length, 2);
  assert.equal(out.counts.skipped, 2);
});

test('a fetch error or rate limit on the only course list also blocks expansion', async () => {
  const plan = V2([{ path: '/users/self', query: {} }, COURSE_SRC, COLD_MODULES]);
  const s = setup({ plan, canvas: (j) => (j.path === '/courses' ? { status: null, body: null, error: 'network' } : {}) });
  const out = await runSync(input, s.deps);
  assert.equal(s.canvasCalls.length, 1);
  assert.ok(out.skipReasons?.includes('/courses/{course_id}/modules: course list unavailable'));
});

test('lists, courseList chunks and group-calendar chunks are uploaded together and first', async () => {
  const plan = V2([
    { path: '/users/self', query: {} },
    { path: '/planner_notes', query: {} },
    { path: '/planner/items', query: {} },
    COURSE_SRC,
    { path: '/users/self/groups', query: {}, paginate: true },
    { path: '/announcements', query: { 'context_codes[]': ['course_{course_id}'] }, expand: 'courseList', chunk: 1 },
    { path: '/calendar_events', query: { 'context_codes[]': ['group_7'], type: 'event' } },
  ]);
  const s = setup({
    plan, maxBodyBytes: 12000,
    canvas: (j) => (j.path === '/courses' ? { body: [{ id: 1 }, { id: 2 }] } : j.path.startsWith('/planner') ? { body: ['x'.repeat(5000)] } : {}),
  });
  const out = await runSync({ ...input, lastFetched: {} }, s.deps);
  assert.equal(out.ok, true);
  assert.ok(s.posts.length >= 2);
  const first = s.posts[0].resources.map((r: any) => r.path);
  assert.deepEqual(first.slice(0, 2), ['/courses', '/users/self/groups']);
  assert.deepEqual(first.slice(2, 5).sort(), ['/announcements', '/announcements', '/calendar_events']);
  const later = s.posts.slice(1).flatMap((p: any) => p.resources.map((r: any) => r.path));
  assert.ok(!later.some((p: string) => ['/courses', '/users/self/groups', '/announcements', '/calendar_events'].includes(p)));
});

// ---- cold budget and timing ----
const MODS = (id: number) => `/courses/${id}/modules?{}`;
const budgetPlan = V2([{ path: '/users/self', query: {} }, COURSE_SRC, COLD_MODULES]);
const fiveCourses = (j: FetchJob) => (j.path === '/courses' ? { body: [1, 2, 3, 4, 5].map((id) => ({ id })) } : {});
const ages = { [MODS(1)]: hoursAgo(13), [MODS(2)]: hoursAgo(40), [MODS(3)]: hoursAgo(20), [MODS(5)]: hoursAgo(15) }; // course 4 never fetched
const moduleIds = (s: ReturnType<typeof setup>) => s.canvasCalls.flatMap((c) => c.jobs.map((j) => j.path)).filter((p) => p.endsWith('/modules')).map((p) => Number(p.split('/')[2])).sort();

test('cold budget takes the most overdue first (never fetched, then oldest) and defers the rest as not due', async () => {
  const s = setup({ plan: budgetPlan, canvas: fiveCourses });
  const out = await runSync({ ...input, budget: 2, lastFetched: ages, lastCourseIds: [1, 2, 3, 4, 5] }, s.deps);
  assert.deepEqual(moduleIds(s), [2, 4]);
  assert.equal(out.counts.notDue, 3);
  assert.equal(out.code, 'ok');
  assert.ok(!out.fetchedKeys?.includes(MODS(3)));
  assert.ok(out.planKeys?.includes(MODS(3))); // deferred, not pruned
});

test('forced runs, unbudgeted runs and a changed course set ignore the budget', async () => {
  const forced = setup({ plan: budgetPlan, canvas: fiveCourses });
  await runSync({ ...input, budget: 2, force: true, lastFetched: ages, lastCourseIds: [1, 2, 3, 4, 5] }, forced.deps);
  assert.deepEqual(moduleIds(forced), [1, 2, 3, 4, 5]);
  const unbudgeted = setup({ plan: budgetPlan, canvas: fiveCourses });
  await runSync({ ...input, lastFetched: ages, lastCourseIds: [1, 2, 3, 4, 5] }, unbudgeted.deps);
  assert.deepEqual(moduleIds(unbudgeted), [1, 2, 3, 5, 4].sort());
  const changed = setup({ plan: budgetPlan, canvas: fiveCourses });
  await runSync({ ...input, budget: 1, lastFetched: ages, lastCourseIds: [1, 2, 3] }, changed.deps);
  assert.deepEqual(moduleIds(changed), [1, 2, 3, 4, 5]);
});

test('timing: total duration and at most 5 slowest resources, ids stripped, no bodies', async () => {
  const s = setup({
    plan: V2([{ path: '/users/self', query: {} }, COURSE_SRC, { path: '/courses/{course_id}/modules', query: {}, expand: 'eachCourse' }]),
    canvas: (j) => (j.path === '/courses' ? { body: [1, 2, 3, 4, 5, 6].map((id) => ({ id })), ms: 5, bytes: 100 } : { ms: j.path.includes('modules') ? Number(j.path.split('/')[2]) * 10 : 1, bytes: 2048 }),
  });
  const out = await runSync(input, s.deps);
  const t = out.timing!;
  assert.equal(typeof t.totalMs, 'number');
  assert.equal(t.slowest.length, 5);
  assert.deepEqual(Object.keys(t.slowest[0]!).sort(), ['bytes', 'ms', 'path']);
  assert.deepEqual(t.slowest.map((x) => x.ms), [...t.slowest.map((x) => x.ms)].sort((a, b) => b - a));
  assert.equal(t.slowest[0]!.path, '/courses/:id/modules');
  assert.equal(t.slowest[0]!.ms, 60);
  assert.ok(!t.slowest.some((x) => /\/\d/.test(x.path)));
});

// ---- refreshMinutes on hot resources ----
const AS_KEY = '/users/self/activity_stream?{}';
const minutesAgo = (m: number) => new Date(Date.parse('2026-11-01T12:00:00Z') - m * 60_000).toISOString();
const refreshPlan = (extra: object[] = []) => V2([
  { path: '/users/self', query: {}, refreshMinutes: 5 },
  { path: '/users/self/activity_stream', query: {}, refreshMinutes: 30 },
  { path: '/planner_notes', query: {} },
  ...extra,
]);
const paths = (s: ReturnType<typeof setup>) => s.canvasCalls.flatMap((c) => c.jobs.map((j) => j.path));

test('refreshMinutes: a recently fetched hot resource is skipped on visit/alarm runs and counted as not due', async () => {
  const s = setup({ plan: refreshPlan() });
  const out = await runSync({ ...input, budget: 30, lastFetched: { [AS_KEY]: minutesAgo(10), '/users/self?{}': minutesAgo(1) } }, s.deps);
  assert.ok(!paths(s).includes('/users/self/activity_stream'));
  assert.ok(paths(s).includes('/planner_notes')); // no refreshMinutes: always fetched
  assert.ok(paths(s).includes('/users/self')); // the profile is never skipped
  assert.equal(out.counts.notDue, 1);
  assert.equal(out.code, 'ok');
  assert.ok(out.planKeys?.includes(AS_KEY));
});

test('refreshMinutes: missing or older than the interval is fetched', async () => {
  const missing = setup({ plan: refreshPlan() });
  await runSync({ ...input, budget: 30, lastFetched: {} }, missing.deps);
  assert.ok(paths(missing).includes('/users/self/activity_stream'));
  const old = setup({ plan: refreshPlan() });
  await runSync({ ...input, budget: 30, lastFetched: { [AS_KEY]: minutesAgo(31) } }, old.deps);
  assert.ok(paths(old).includes('/users/self/activity_stream'));
});

test('refreshMinutes: Sync now and the first sync (no budget) still fetch it', async () => {
  const fresh = { [AS_KEY]: minutesAgo(1) };
  const forced = setup({ plan: refreshPlan() });
  await runSync({ ...input, budget: 30, force: true, lastFetched: fresh }, forced.deps);
  assert.ok(paths(forced).includes('/users/self/activity_stream'));
  const first = setup({ plan: refreshPlan() });
  await runSync({ ...input, lastFetched: fresh }, first.deps);
  assert.ok(paths(first).includes('/users/self/activity_stream'));
});

test('refreshMinutes: a changed course set fetches per-course hot resources; an unchanged set skips them', async () => {
  const plan = refreshPlan([COURSE_SRC, { path: '/courses/{course_id}/assignments', query: {}, expand: 'eachCourse', refreshMinutes: 60 }]);
  const canvas = (j: FetchJob) => (j.path === '/courses' ? { body: [{ id: 1 }, { id: 2 }] } : {});
  const lastFetched = { [AS_KEY]: minutesAgo(5), '/courses/1/assignments?{}': minutesAgo(5), '/courses/2/assignments?{}': minutesAgo(5) };
  const same = setup({ plan, canvas });
  const o1 = await runSync({ ...input, budget: 30, lastFetched, lastCourseIds: [1, 2] }, same.deps);
  assert.ok(!paths(same).some((p) => p.endsWith('/assignments')));
  assert.equal(o1.counts.notDue, 3); // activity_stream + 2 assignments
  const changed = setup({ plan, canvas });
  await runSync({ ...input, budget: 30, lastFetched, lastCourseIds: [1] }, changed.deps);
  assert.equal(paths(changed).filter((p) => p.endsWith('/assignments')).length, 2);
});

test('refreshMinutes does not affect cold resources', async () => {
  const plan = V2([{ path: '/users/self', query: {} }, { path: '/announcements', query: {}, tier: 'cold', refreshMinutes: 5 }]);
  const s = setup({ plan });
  await runSync({ ...input, budget: 30, lastFetched: { '/announcements?{}': minutesAgo(60) } }, s.deps);
  assert.ok(!paths(s).includes('/announcements')); // cold: only the 12 h interval counts
});

test('refreshMinutes: the keys a sync records gate the next visit, whatever the query key order', async () => {
  const cal = { path: '/calendar_events', query: { type: 'event', 'context_codes[]': ['user_1'], start_date: '2026-10-01' }, refreshMinutes: 30 };
  const first = setup({ plan: refreshPlan([cal]) });
  const o1 = await runSync({ ...input, budget: 30, lastFetched: {} }, first.deps);
  assert.ok(paths(first).includes('/calendar_events'));
  const lastFetched = Object.fromEntries((o1.fetchedKeys ?? []).map((k) => [k, minutesAgo(5)]));
  const second = setup({ plan: refreshPlan([cal]) });
  await runSync({ ...input, budget: 30, lastFetched }, second.deps);
  assert.ok(!paths(second).includes('/calendar_events'));
  assert.ok(!paths(second).includes('/users/self/activity_stream'));
});

test('an unreadable or oversized resource records an attempt; a network error does not', async () => {
  const plan = {
    planVersion: 2, canvasHost: 'school.instructure.com', maxPages: 5, coldIntervalHours: 12,
    resources: ['/users/self', '/announcements', '/planner_notes', '/calendar_events'].map((path) => ({ path, query: {}, tier: 'cold' })),
  };
  const canvas = (j: FetchJob) =>
    j.path === '/announcements' ? { status: null, body: null, error: 'too_many_pages' as const }
      : j.path === '/planner_notes' ? { status: null, body: null, error: 'network' as const }
        : j.path === '/calendar_events' ? { body: ['x'.repeat(20000)] }
          : {};
  const out = await runSync({ ...input, force: true }, setup({ plan, canvas, maxBodyBytes: 12000 }).deps);
  const keys = (out.fetchedKeys ?? []).map((k) => k.split('?')[0]).sort();
  assert.deepEqual(keys, ['/announcements', '/calendar_events', '/users/self']);
});
