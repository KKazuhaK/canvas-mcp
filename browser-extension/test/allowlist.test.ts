import test from 'node:test';
import assert from 'node:assert/strict';
import { buildUrl, expandPlan, parsePlan, validateRequest } from '../src/lib/allowlist.ts';

test('allowlist accepts the documented read paths', () => {
  for (const p of [
    '/users/self', '/users/self/profile', '/users/self/todo', '/users/self/groups', '/users/self/activity_stream', '/users/self/activity_stream/summary',
    '/courses', '/courses/12', '/courses/12/assignments', '/courses/12/assignment_groups', '/courses/12/modules', '/courses/12/quizzes',
    '/courses/12/front_page', '/courses/12/discussion_topics', '/planner/items', '/planner_notes', '/calendar_events', '/announcements',
  ]) assert.equal(validateRequest(p, {}), null, p);
});

test('allowlist rejects traversal, smuggling, unknown paths and non-GET', () => {
  for (const p of [
    '/courses/../users/self', '/courses/12/../../accounts', '/courses/12/assignments/9', '/courses/abc/assignments', '/courses/12/files',
    '/courses/12/assignments?x=1', '/courses/12/assignments#frag', '/courses/12/assignments%2f..', '/courses//12', '/courses/12/assignments/',
    '/courses/12/assignments\n', 'courses', '/conversations', '/users/self/files', '/users/1', '/accounts/1', 'https://evil.example/courses', '//evil.example/courses',
    '/courses/{course_id}/assignments', '/api/v1/courses', '/courses/12/enrollments', '/courses/12/users',
  ]) assert.notEqual(validateRequest(p, {}), null, JSON.stringify(p));
  assert.notEqual(validateRequest('/courses', {}, 'POST'), null);
  assert.notEqual(validateRequest('/courses', {}, 'DELETE'), null);
  assert.notEqual(validateRequest(5, {}), null);
});

test('query validation blocks token smuggling and odd keys', () => {
  assert.equal(validateRequest('/courses', { 'include[]': ['term'], enrollment_state: 'active' }), null);
  assert.notEqual(validateRequest('/courses', { access_token: 'x' }), null);
  assert.notEqual(validateRequest('/courses', { 'a&b': '1' }), null);
  assert.notEqual(validateRequest('/courses', { page: '2' }), null);
  assert.notEqual(validateRequest('/courses', { a: 5 as any }), null);
  assert.notEqual(validateRequest('/courses', { a: 'x\ny' }), null);
  assert.notEqual(validateRequest('/courses', [] as any), null);
});

test('buildUrl stays on the given origin under /api/v1 and encodes arrays', () => {
  assert.equal(
    buildUrl('https://s.example.com', '/courses', { 'include[]': ['term', 'total_scores'], enrollment_state: 'active' }, { per_page: '100' }),
    'https://s.example.com/api/v1/courses?include%5B%5D=term&include%5B%5D=total_scores&enrollment_state=active&per_page=100',
  );
});

test('parsePlan validates shape, caps maxPages and rejects bad resources', () => {
  const { plan, rejected } = parsePlan({
    planVersion: 1, canvasHost: null, maxPages: 9999,
    resources: [{ path: '/users/self', query: {} }, { path: '/courses', query: { access_token: 'x' } }, null, { query: {} }],
  });
  assert.equal(plan.maxPages, 200);
  assert.equal(plan.canvasHost, null);
  assert.equal(plan.resources.length, 1);
  assert.equal(rejected.length, 3);
  assert.throws(() => parsePlan({ resources: [] }));
  assert.throws(() => parsePlan(null));
  assert.equal(parsePlan({ planVersion: 1, resources: [] }).plan.maxPages, 50);
});

test('expandPlan expands perCourse over course ids and validates the result', () => {
  const resources = parsePlan({
    planVersion: 1,
    resources: [
      { path: '/users/self' },
      { path: '/courses', paginate: true },
      { path: '/courses/{course_id}/assignments', query: { 'include[]': ['submission'] }, paginate: true, perCourse: true },
      { path: '/courses/{course_id}/files', perCourse: true },
      { path: '/courses/5/modules', perCourse: true },
      { path: '/courses/{course_id}/modules' },
      { path: '/conversations' },
    ],
  }).plan.resources;
  const r = expandPlan(resources, [3, 7, 7, -1, 1.5]);
  assert.deepEqual(r.plain.map((j) => j.path), ['/users/self', '/courses']);
  assert.deepEqual(r.perCourse.map((j) => j.path), ['/courses/3/assignments', '/courses/7/assignments']);
  assert.deepEqual(r.rejected.map((x) => x.path).sort(), ['/conversations', '/courses/5/modules', '/courses/{course_id}/files', '/courses/{course_id}/modules'].sort());
  const noCourses = expandPlan(resources, null);
  assert.equal(noCourses.perCourse.length, 0);
  assert.ok(noCourses.rejected.some((x) => x.reason.includes('no course list')));
});

test('perCourse placeholders in query values and mixed path+query expand; bad cases are rejected', () => {
  const resources = parsePlan({
    planVersion: 1,
    resources: [
      { path: '/announcements', query: { 'context_codes[]': ['course_{course_id}'], active_only: 'true' }, paginate: true, perCourse: true },
      { path: '/courses/{course_id}/assignments', query: { note: 'c{course_id}' }, perCourse: true },
      { path: '/calendar_events', query: { 'context_codes[]': 'course_{course_id}' }, perCourse: true },
      { path: '/calendar_events', query: { type: 'event' }, perCourse: true },
      { path: '/announcements', query: { 'context_codes[]': ['course_{course_id}'] } },
      { path: '/announcements', query: { x: 'a{b}', y: '{course_id}{' }, perCourse: true },
      { path: '/courses/{course_id}/modules', query: { x: '{other}' }, perCourse: true },
    ],
  }).plan.resources;
  const r = expandPlan(resources, [3, 7]);
  assert.deepEqual(r.perCourse.map((j) => [j.path, j.query]), [
    ['/announcements', { 'context_codes[]': ['course_3'], active_only: 'true' }],
    ['/announcements', { 'context_codes[]': ['course_7'], active_only: 'true' }],
    ['/courses/3/assignments', { note: 'c3' }],
    ['/courses/7/assignments', { note: 'c7' }],
    ['/calendar_events', { 'context_codes[]': 'course_3' }],
    ['/calendar_events', { 'context_codes[]': 'course_7' }],
  ]);
  const reasons = r.rejected.map((x) => x.reason);
  assert.ok(reasons.includes('perCourse resource has no {course_id}'));
  assert.equal(reasons.filter((x) => x === 'leftover brace after expansion').length, 3);
  assert.equal(r.plain.length, 0);
});
