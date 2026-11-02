import test from 'node:test';
import assert from 'node:assert/strict';
import { byteLength, splitUploads, type UploadResource } from '../src/lib/upload.ts';

const header = { schemaVersion: 1 as const, canvasOrigin: 'https://s.example.com', canvasUserId: 1, capturedAt: '2026-11-01T00:00:00.000Z', planVersion: 1 };
const res = (path: string, n: number): UploadResource => ({ path, query: {}, status: 200, body: 'x'.repeat(n) });

test('splits into batches that each serialise under the limit', () => {
  const items = Array.from({ length: 10 }, (_, i) => res(`/courses/${i}`, 400));
  const { batches, oversized } = splitUploads(header, items, 1500);
  assert.equal(oversized.length, 0);
  assert.ok(batches.length > 1);
  for (const b of batches) assert.ok(byteLength(JSON.stringify({ ...header, resources: b })) <= 1500);
  assert.equal(batches.flat().length, 10);
  assert.deepEqual(batches.flat().map((r) => r.path), items.map((r) => r.path));
});

test('a single resource over the limit is reported as oversized and the rest still upload', () => {
  const { batches, oversized } = splitUploads(header, [res('/a', 10), res('/big', 5000), res('/b', 10)], 1000);
  assert.deepEqual(oversized.map((r) => r.path), ['/big']);
  assert.equal(batches.flat().length, 2);
});

test('counts multi-byte characters in bytes, not characters', () => {
  const { batches, oversized } = splitUploads(header, [{ path: '/a', query: {}, status: 200, body: '\u5b57'.repeat(200) }], 700);
  assert.equal(batches.length + oversized.length, 1);
  assert.equal(oversized.length, 1);
});

test('empty input gives no batches', () => {
  assert.deepEqual(splitUploads(header, [], 1000), { batches: [], oversized: [] });
});

import { orderForUpload } from '../src/lib/upload.ts';

test('orderForUpload puts lists first, then chunks, then the rest, keeping relative order', () => {
  const r = (path: string, q: Record<string, string | string[]> = {}): UploadResource => ({ path, query: q, status: 200, body: [] });
  const list = [
    r('/users/self'), r('/announcements', { 'context_codes[]': ['course_1'] }), r('/planner_notes'), r('/users/self/groups'),
    r('/calendar_events', { 'context_codes[]': ['group_5'] }), r('/calendar_events', { 'context_codes[]': ['user_5'] }), r('/courses'),
  ];
  const out = orderForUpload(list, (x) => (x.path === '/announcements' ? 'courseList' : null));
  assert.deepEqual(out.map((x) => x.path + JSON.stringify(x.query['context_codes[]'] ?? '')), [
    '/users/self/groups""', '/courses""', '/announcements["course_1"]', '/calendar_events["group_5"]', '/users/self""', '/planner_notes""', '/calendar_events["user_5"]',
  ]);
});
