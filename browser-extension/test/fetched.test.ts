import test from 'node:test';
import assert from 'node:assert/strict';
import { isDue, updateFetched } from '../src/lib/fetched.ts';

const NOW = '2026-11-01T12:00:00.000Z';

test('isDue: never fetched, fresh, stale, unreadable', () => {
  const now = Date.parse(NOW);
  assert.equal(isDue(undefined, 12, now), true);
  assert.equal(isDue('2026-11-01T11:00:00Z', 12, now), false);
  assert.equal(isDue('2026-11-01T00:00:00Z', 12, now), true); // exactly 12 h
  assert.equal(isDue('garbage', 12, now), true);
});

test('updateFetched records fetched keys and prunes keys that left the plan', () => {
  const prev = { a: '2026-10-31T00:00:00Z', gone: '2026-10-31T00:00:00Z' };
  const next = updateFetched(prev, ['b'], ['a', 'b', 'c'], NOW);
  assert.deepEqual(Object.keys(next).sort(), ['a', 'b']);
  assert.equal(next.b, NOW);
  assert.equal(next.a, '2026-10-31T00:00:00Z');
  assert.deepEqual(prev, { a: '2026-10-31T00:00:00Z', gone: '2026-10-31T00:00:00Z' }); // input not mutated
});

test('updateFetched does not prune when the plan was not fully seen, and caps by dropping the oldest', () => {
  const kept = updateFetched({ old: '2026-10-01T00:00:00Z' }, ['b'], undefined, NOW);
  assert.deepEqual(Object.keys(kept).sort(), ['b', 'old']);
  const prev = { k1: '2026-10-01T00:00:00Z', k2: '2026-10-02T00:00:00Z', k3: '2026-10-03T00:00:00Z' };
  const capped = updateFetched(prev, ['k4'], undefined, NOW, 3);
  assert.deepEqual(Object.keys(capped).sort(), ['k2', 'k3', 'k4']);
});

import { coldOffsetMs, overdueMs } from '../src/lib/fetched.ts';

test('cold offset is deterministic, within 0-25% of the interval, and spreads keys', () => {
  const max = 0.25 * 12 * 3600_000;
  const values = Array.from({ length: 300 }, (_, i) => coldOffsetMs(`/courses/${i}/modules?{}`, 12));
  assert.deepEqual(values, Array.from({ length: 300 }, (_, i) => coldOffsetMs(`/courses/${i}/modules?{}`, 12)));
  assert.ok(values.every((v) => v >= 0 && v < max));
  assert.ok(new Set(values).size > 250);
  assert.ok(Math.max(...values) > max * 0.9 && Math.min(...values) < max * 0.1);
});

test('with offsets, keys fall due between 75% and 100% of the interval after the last fetch', () => {
  const now = Date.parse(NOW);
  const ago = (h: number) => new Date(now - h * 3600_000).toISOString();
  const keys = Array.from({ length: 200 }, (_, i) => `/courses/${i}/modules?{}`);
  assert.ok(keys.every((k) => !isDue(ago(8.9), 12, now, k)));
  assert.ok(keys.every((k) => isDue(ago(12), 12, now, k)));
  const dueAt105 = keys.filter((k) => isDue(ago(10.5), 12, now, k)).length;
  assert.ok(dueAt105 > 20 && dueAt105 < 180, String(dueAt105));
  assert.equal(overdueMs(undefined, 12, now, 'k'), Infinity);
  assert.ok(overdueMs(ago(20), 12, now, 'k') > overdueMs(ago(14), 12, now, 'k'));
});
