import test, { afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { runFetches } from '../src/lib/canvas-fetch.ts';
import { jsonResponse } from './helpers.ts';

const ORIGIN = 'https://school.instructure.com';
const realFetch = globalThis.fetch;
afterEach(() => {
  globalThis.fetch = realFetch;
});

function mockFetch(handler: (url: string, init: RequestInit) => Response | Promise<Response>) {
  const calls: { url: string; init: RequestInit }[] = [];
  globalThis.fetch = (async (input: any, init: RequestInit = {}) => {
    calls.push({ url: String(input), init });
    return handler(String(input), init);
  }) as typeof fetch;
  return calls;
}

const job = (path: string, paginate = false, query = {}) => ({ path, query, paginate });

test('strips the while(1); prefix and sends credentialed same-origin JSON requests', async () => {
  const calls = mockFetch(() => jsonResponse('while(1);{"id":5}'));
  const [r] = await runFetches(ORIGIN, [job('/users/self')], 50);
  assert.deepEqual(r?.body, { id: 5 });
  assert.equal(r?.status, 200);
  assert.equal(calls[0]?.url, `${ORIGIN}/api/v1/users/self`);
  assert.equal(calls[0]?.init.credentials, 'include');
  assert.deepEqual(calls[0]?.init.headers, { Accept: 'application/json' });
});

test('follows rel="next" within the same path and merges pages', async () => {
  const calls = mockFetch((url) => {
    const page = new URL(url).searchParams.get('page');
    if (!page) return jsonResponse('while(1);[1,2]', { headers: { link: `<${ORIGIN}/api/v1/courses?page=2&per_page=100>; rel="next", <${ORIGIN}/api/v1/courses?page=1>; rel="first"` } });
    if (page === '2') return jsonResponse([3], { headers: { link: `<${ORIGIN}/api/v1/courses?page=3&per_page=100>; rel="next"` } });
    return jsonResponse([4], { headers: { link: `<${ORIGIN}/api/v1/courses?page=1>; rel="first"` } });
  });
  const [r] = await runFetches(ORIGIN, [job('/courses', true, { 'include[]': ['term'] })], 50);
  assert.deepEqual(r?.body, [1, 2, 3, 4]);
  assert.equal(r?.pages, 3);
  assert.ok(calls[0]?.url.includes('per_page=100'));
});

test('stops and fails the resource when the next link changes origin', async () => {
  mockFetch(() => jsonResponse([1], { headers: { link: '<https://evil.example/api/v1/courses?page=2>; rel="next"' } }));
  const [r] = await runFetches(ORIGIN, [job('/courses', true)], 50);
  assert.equal(r?.error, 'pagination_moved');
  assert.equal(r?.body, null);
});

test('stops and fails the resource when the next link changes path', async () => {
  const calls = mockFetch(() => jsonResponse([1], { headers: { link: `<${ORIGIN}/api/v1/accounts/1/users?page=2>; rel="next"` } }));
  const [r] = await runFetches(ORIGIN, [job('/courses', true)], 50);
  assert.equal(r?.error, 'pagination_moved');
  assert.equal(calls.length, 1);
});

test('maxPages cap marks the resource failed rather than returning a partial list', async () => {
  let n = 0;
  mockFetch(() => jsonResponse([n++], { headers: { link: `<${ORIGIN}/api/v1/courses?page=${n + 1}>; rel="next"` } }));
  const [r] = await runFetches(ORIGIN, [job('/courses', true)], 3);
  assert.equal(r?.error, 'too_many_pages');
  assert.equal(r?.body, null);
  assert.equal(n, 3);
});

test('non-paginated resources ignore next links', async () => {
  const calls = mockFetch(() => jsonResponse([1], { headers: { link: `<${ORIGIN}/api/v1/courses?page=2>; rel="next"` } }));
  const [r] = await runFetches(ORIGIN, [job('/courses', false)], 50);
  assert.equal(calls.length, 1);
  assert.deepEqual(r?.body, [1]);
});

test('records non-200 status with a null body', async () => {
  mockFetch(() => jsonResponse({ errors: [] }, { status: 403 }));
  const [r] = await runFetches(ORIGIN, [job('/courses')], 50);
  assert.equal(r?.status, 403);
  assert.equal(r?.body, null);
  assert.equal(r?.error, undefined);
});

test('a login redirect or HTML response is reported as not signed in', async () => {
  mockFetch(() => jsonResponse('<html></html>', { url: `${ORIGIN}/login/canvas`, redirected: true, headers: { 'content-type': 'text/html' } }));
  assert.equal((await runFetches(ORIGIN, [job('/users/self')], 5))[0]?.error, 'not_signed_in');
  mockFetch(() => jsonResponse('<html></html>', { headers: { 'content-type': 'text/html; charset=utf-8' } }));
  assert.equal((await runFetches(ORIGIN, [job('/users/self')], 5))[0]?.error, 'not_signed_in');
  mockFetch(() => jsonResponse({}, { url: 'https://sso.example.com/api/v1/users/self', redirected: true }));
  assert.equal((await runFetches(ORIGIN, [job('/users/self')], 5))[0]?.error, 'not_signed_in');
});

test('network errors and bad JSON fail only that resource', async () => {
  let i = 0;
  mockFetch(() => {
    i++;
    if (i === 1) throw new TypeError('boom');
    if (i === 2) return jsonResponse('not json');
    return jsonResponse({ ok: true });
  });
  const r = await runFetches(ORIGIN, [job('/courses'), job('/planner_notes'), job('/announcements')], 5);
  assert.deepEqual(r.map((x) => x.error), ['network', 'bad_json', undefined]);
});

test('a failing later page fails the resource instead of storing a partial list', async () => {
  let i = 0;
  mockFetch(() => (i++ === 0 ? jsonResponse([1], { headers: { link: `<${ORIGIN}/api/v1/courses?page=2>; rel="next"` } }) : jsonResponse({}, { status: 500 })));
  const [r] = await runFetches(ORIGIN, [job('/courses', true)], 5);
  assert.equal(r?.error, 'page_failed');
  assert.equal(r?.body, null);
});

test('at most 3 resources are in flight, results keep their order, pages stay sequential', async () => {
  let inFlight = 0;
  let max = 0;
  mockFetch(async (url) => {
    inFlight++;
    max = Math.max(max, inFlight);
    await new Promise((r) => setTimeout(r, 15));
    inFlight--;
    return jsonResponse({ url });
  });
  const jobs = Array.from({ length: 12 }, (_, i) => job(`/courses/${i + 1}`));
  const results = await runFetches(ORIGIN, jobs, 5);
  assert.equal(max, 3);
  assert.deepEqual(results.map((r) => r.path), jobs.map((j) => j.path));
  assert.ok(results.every((r) => r.status === 200));
});

test('a 429 pauses new requests for Retry-After, then the request is retried', async () => {
  const times: number[] = [];
  let first = true;
  mockFetch(() => {
    times.push(Date.now());
    if (first) {
      first = false;
      return new Response('', { status: 429, headers: { 'retry-after': '1' } });
    }
    return jsonResponse([]);
  });
  const results = await runFetches(ORIGIN, [job('/courses'), job('/planner_notes'), job('/announcements')], 5);
  assert.ok(results.every((r) => r.status === 200));
  // The three initial requests start together; the retry waits out Retry-After.
  assert.equal(times.length, 4);
  assert.ok(times[3]! - times[0]! >= 900);
});

const throttle403 = () =>
  new Response('403 Forbidden (Rate Limit Exceeded)', { status: 403, headers: { 'retry-after': '0.05', 'x-rate-limit-remaining': '0' } });

test('a throttle-403 is retried like a 429 and then succeeds with the real status', async () => {
  let n = 0;
  const calls = mockFetch(() => (n++ < 2 ? throttle403() : jsonResponse([1])));
  const [r] = await runFetches(ORIGIN, [job('/courses')], 5);
  assert.equal(calls.length, 3);
  assert.equal(r?.status, 200);
  assert.deepEqual(r?.body, [1]);
  assert.equal(r?.error, undefined);
});

test('a persistent throttle-403 is never recorded as a status', async () => {
  const calls = mockFetch(() => throttle403());
  const [r] = await runFetches(ORIGIN, [job('/courses')], 5);
  assert.equal(calls.length, 4); // first try + 3 retries
  assert.equal(r?.error, 'rate_limited');
  assert.equal(r?.status, null);
  assert.equal(r?.body, null);
});

test('a real 403 without rate-limit text is still recorded as 403', async () => {
  const calls = mockFetch(() => jsonResponse({ errors: [{ message: 'user not authorized' }] }, { status: 403 }));
  const [r] = await runFetches(ORIGIN, [job('/courses')], 5);
  assert.equal(calls.length, 1);
  assert.equal(r?.status, 403);
  assert.equal(r?.error, undefined);
});

test('after any throttle the rest of the run goes one request at a time', async () => {
  let inFlight = 0;
  let throttled = false;
  let maxAfter = 0;
  let first = true;
  mockFetch(async () => {
    inFlight++;
    if (throttled) maxAfter = Math.max(maxAfter, inFlight);
    await new Promise((r) => setTimeout(r, 15));
    inFlight--;
    if (first) {
      first = false;
      throttled = true;
      return new Response('', { status: 429, headers: { 'retry-after': '0.02' } });
    }
    return jsonResponse([]);
  });
  const jobs = Array.from({ length: 10 }, (_, i) => job(`/courses/${i + 1}`));
  const results = await runFetches(ORIGIN, jobs, 5);
  assert.ok(results.every((r) => r.status === 200));
  // Requests already in flight when the throttle hit may finish; nothing new overlaps afterwards.
  assert.ok(maxAfter <= 3);
  const late: number[] = [];
  let live = 0;
  mockFetch(async () => {
    live++;
    late.push(live);
    const isFirst = late.length === 1;
    await new Promise((r) => setTimeout(r, 10));
    live--;
    return isFirst ? new Response('', { status: 429, headers: { 'retry-after': '0.02' } }) : jsonResponse([]);
  });
  await runFetches(ORIGIN, Array.from({ length: 12 }, (_, i) => job(`/courses/${i + 1}`)), 5);
  assert.ok(late.slice(4).every((n) => n === 1), JSON.stringify(late));
});

test('paginated requests send per_page=100, others do not, and results carry timing and size', async () => {
  const calls = mockFetch(() => jsonResponse([1, 2]));
  const r = await runFetches(ORIGIN, [job('/courses', true, { enrollment_state: 'active' }), job('/planner_notes', false)], 5);
  assert.ok(calls.find((c) => c.url.includes('/api/v1/courses?'))!.url.includes('per_page=100'));
  assert.ok(!calls.find((c) => c.url.includes('/planner_notes'))!.url.includes('per_page'));
  assert.equal(typeof r[0]?.ms, 'number');
  assert.equal(r[0]?.bytes, 5);
});
