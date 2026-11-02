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
