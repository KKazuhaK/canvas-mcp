import test from 'node:test';
import assert from 'node:assert/strict';
import { claimCode, mayInject, newPairing, pairingUrl, validateClaim } from '../src/lib/pairing.ts';
import { EXT_ID, PORTAL, TOKEN, jsonResponse } from './helpers.ts';

const rand = (n: number) => new Uint8Array(n).fill(0xab);
const NOW = 1_000_000;
function pending() {
  const p = newPairing(PORTAL, NOW, rand);
  p.tabId = 7;
  return p;
}
const goodSender = (p: ReturnType<typeof pending>) => ({ id: EXT_ID, tab: { id: 7 }, url: pairingUrl(p) });

test('state is 32 random bytes in hex and expires after 10 minutes', () => {
  const p = newPairing(PORTAL, NOW, rand);
  assert.match(p.state, /^[a-f0-9]{64}$/);
  assert.equal(p.expires, NOW + 600_000);
  assert.equal(pairingUrl(p), `${PORTAL}/account/browser-extension#extension-auth=${p.state}`);
});

test('link script may be injected only into the pairing tab at the exact URL', () => {
  const p = pending();
  assert.equal(mayInject(p, 7, pairingUrl(p), NOW + 1), true);
  assert.equal(mayInject(p, 8, pairingUrl(p), NOW + 1), false);
  assert.equal(mayInject(p, 7, pairingUrl(p).replace(PORTAL, 'https://evil.example'), NOW + 1), false);
  assert.equal(mayInject(p, 7, `${PORTAL}/other#extension-auth=${p.state}`, NOW + 1), false);
  assert.equal(mayInject(p, 7, `${PORTAL}/account/browser-extension#extension-auth=${'0'.repeat(64)}`, NOW + 1), false);
  assert.equal(mayInject(p, 7, pairingUrl(p), p.expires), false);
  assert.equal(mayInject(undefined, 7, pairingUrl(p), NOW), false);
  assert.equal(mayInject({ ...p, status: 'connected' }, 7, pairingUrl(p), NOW), false);
});

test('validateClaim accepts the matching tab, url, state and code', () => {
  const p = pending();
  assert.equal(validateClaim(p, goodSender(p), EXT_ID, { state: p.state, code: 'ABCD-efgh_1234' }, NOW + 5), 'ABCD-efgh_1234');
});

test('validateClaim rejects wrong tab, origin, path, state, sender id, expiry and bad code', () => {
  const p = pending();
  const ok = { state: p.state, code: 'abcdef123456' };
  const bad = (sender: any, msg: any = ok, now = NOW + 5, pairing: any = p) =>
    assert.throws(() => validateClaim(pairing, sender, EXT_ID, msg, now));
  bad({ ...goodSender(p), tab: { id: 9 } });
  bad({ ...goodSender(p), tab: undefined });
  bad({ ...goodSender(p), id: 'someone-else' });
  bad({ ...goodSender(p), url: `https://evil.example/account/browser-extension#extension-auth=${p.state}` });
  bad({ ...goodSender(p), url: `${PORTAL}/elsewhere#extension-auth=${p.state}` });
  bad(goodSender(p), { ...ok, state: 'f'.repeat(64) });
  bad(goodSender(p), { ...ok, code: 'has space' });
  bad(goodSender(p), { ...ok, code: 123 });
  bad(goodSender(p), ok, p.expires + 1);
  bad(goodSender(p), ok, NOW, null);
  bad(goodSender(p), ok, NOW, { ...p, status: 'connected' });
});

test('claimCode posts without credentials, refuses redirects and validates the token', async () => {
  let seen: any;
  const f = (async (url: any, init: any) => {
    seen = { url: String(url), init };
    return jsonResponse({ uploadToken: TOKEN, bindingId: 'b' });
  }) as typeof fetch;
  assert.equal(await claimCode(f, PORTAL, 'abcdef123456'), TOKEN);
  assert.equal(seen.url, `${PORTAL}/api/v1/extension/claim`);
  assert.equal(seen.init.credentials, 'omit');
  assert.equal(seen.init.redirect, 'error');
  assert.deepEqual(JSON.parse(seen.init.body), { code: 'abcdef123456' });
  await assert.rejects(claimCode((async () => jsonResponse({ error: 'invalid_code' }, { status: 400 })) as any, PORTAL, 'abcdef123456'), /invalid, expired or already used/);
  await assert.rejects(claimCode((async () => jsonResponse({ uploadToken: 'short' })) as any, PORTAL, 'abcdef123456'), /unexpected/);
  await assert.rejects(claimCode((async () => { throw new TypeError('x'); }) as any, PORTAL, 'abcdef123456'), /Could not reach/);
});
