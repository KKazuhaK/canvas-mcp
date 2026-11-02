import test from 'node:test';
import assert from 'node:assert/strict';
import { hostPattern, parseOrigin, sameOrigin } from '../src/lib/origin.ts';
import { describeStatus, relativeTime } from '../src/lib/status.ts';
import { isPopupSender } from '../src/lib/senders.ts';
import { EXT_ID, POPUP_URL, PORTAL, CANVAS, TOKEN } from './helpers.ts';

test('parseOrigin accepts https and localhost http, rejects the rest', () => {
  assert.equal(parseOrigin('https://portal.example.com/'), 'https://portal.example.com');
  assert.equal(parseOrigin(' https://portal.example.com:8443 '), 'https://portal.example.com:8443');
  assert.equal(parseOrigin('http://localhost:8080'), 'http://localhost:8080');
  assert.equal(parseOrigin('http://127.0.0.1:9000'), 'http://127.0.0.1:9000');
  for (const bad of ['http://portal.example.com', 'http://localhost.evil.com', 'https://a.com/path', 'https://a.com?x=1', 'https://a.com#x', 'https://u:p@a.com', 'ftp://a.com', 'nonsense', '', 5, null]) {
    assert.throws(() => parseOrigin(bad));
  }
});

test('hostPattern drops the port; sameOrigin compares exactly', () => {
  assert.equal(hostPattern('https://a.example.com:8443'), 'https://a.example.com/*');
  assert.equal(hostPattern('http://localhost:3000'), 'http://localhost/*');
  assert.equal(sameOrigin('https://a.com/x', 'https://a.com'), true);
  assert.equal(sameOrigin('https://a.com.evil.com/x', 'https://a.com'), false);
  assert.equal(sameOrigin(undefined, 'https://a.com'), false);
});

test('only the extension popup page passes the popup sender check', () => {
  assert.equal(isPopupSender({ id: EXT_ID, url: POPUP_URL }, EXT_ID, POPUP_URL), true);
  assert.equal(isPopupSender({ id: EXT_ID, url: POPUP_URL + '?x=1', tab: { id: 1 } }, EXT_ID, POPUP_URL), true); // popup opened as a tab
  assert.equal(isPopupSender({ id: 'other', url: POPUP_URL }, EXT_ID, POPUP_URL), false);
  assert.equal(isPopupSender({ id: EXT_ID, url: 'https://school.instructure.com/', tab: { id: 1 } }, EXT_ID, POPUP_URL), false); // content script
  assert.equal(isPopupSender({ id: EXT_ID }, EXT_ID, POPUP_URL), false);
});

test('status text is plain English and never includes the token', () => {
  const now = Date.parse('2026-11-01T12:00:00Z');
  assert.equal(relativeTime(undefined, now), 'never');
  assert.equal(relativeTime('2026-11-01T11:55:00Z', now), '5 minutes ago');
  const v = describeStatus(
    { portalOrigin: PORTAL, uploadToken: TOKEN, canvasOrigin: CANVAS, lastSyncAt: '2026-11-01T11:55:00Z',
      lastResult: { at: '', trigger: 'tab', ok: true, code: 'ok', message: 'Synced 4 items.', counts: { planned: 4, fetched: 4, canvasErrors: 0, skipped: 0, accepted: 4, rejected: 0 } } },
    now,
  );
  assert.equal(v.connected, true);
  assert.deepEqual(v.rows.map((r) => r[0]), ['Portal', 'Canvas', 'Last sync', 'Last run']);
  assert.equal(JSON.stringify(v).includes(TOKEN), false);
  assert.equal(v.error, null);
  const dis = describeStatus({ portalOrigin: PORTAL, needsReconnect: true }, now);
  assert.equal(dis.connected, false);
  assert.match(dis.error ?? '', /Connect again/);
});
