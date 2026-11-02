import { UserError } from './errors.ts';
import { CODE_RE, TOKEN_RE, type Pairing } from './state.ts';

export const PAIRING_PATH = '/account/browser-extension';
export const PAIRING_TTL_MS = 10 * 60_000;

const hex = (bytes: Uint8Array): string => Array.from(bytes, (n) => n.toString(16).padStart(2, '0')).join('');

export function newPairing(portalOrigin: string, now: number, randomBytes: (n: number) => Uint8Array): Pairing {
  return { portalOrigin, state: hex(randomBytes(32)), expires: now + PAIRING_TTL_MS, status: 'pending' };
}

export const pairingUrl = (p: Pairing): string => `${p.portalOrigin}${PAIRING_PATH}#extension-auth=${p.state}`;

function urlMatches(p: Pairing, url: string | undefined): boolean {
  if (!url) return false;
  try {
    const u = new URL(url);
    return u.origin === p.portalOrigin && u.pathname === PAIRING_PATH && u.hash === `#extension-auth=${p.state}`;
  } catch {
    return false;
  }
}

// The link script may only be injected into the pairing tab, on the exact URL.
export function mayInject(p: Pairing | undefined, tabId: number, url: string | undefined, now: number): boolean {
  return !!p && p.status === 'pending' && p.tabId === tabId && p.expires > now && urlMatches(p, url);
}

// Validates a claim message coming from the link script. The state in the
// message, the sending tab, its URL and the expiry must all match.
export function validateClaim(
  p: Pairing | undefined,
  sender: { id?: string; tab?: { id?: number }; url?: string },
  extensionId: string,
  message: { state?: unknown; code?: unknown },
  now: number,
): string {
  if (!p || p.status !== 'pending' || p.expires <= now) {
    throw new UserError('pairing_expired', 'Pairing expired. Start again from the extension popup.');
  }
  if (sender.id !== extensionId || sender.tab?.id === undefined || sender.tab.id !== p.tabId || !urlMatches(p, sender.url)) {
    throw new UserError('pairing_mismatch', 'This pairing request did not come from the page the extension opened.');
  }
  if (message.state !== p.state || typeof message.code !== 'string' || !CODE_RE.test(message.code)) {
    throw new UserError('pairing_mismatch', 'The pairing details do not match this browser. Start again from the extension popup.');
  }
  return message.code;
}

// Exchanges a pairing code for an upload token. No cookies are sent.
export async function claimCode(fetchImpl: typeof fetch, portalOrigin: string, code: string): Promise<string> {
  let res: Response;
  try {
    res = await fetchImpl(`${portalOrigin}/api/v1/extension/claim`, {
      method: 'POST',
      credentials: 'omit',
      redirect: 'error',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ code }),
      signal: AbortSignal.timeout(15000),
    });
  } catch {
    throw new UserError('portal_unreachable', 'Could not reach the portal. Check the address and your connection.');
  }
  if (res.status === 400) {
    await res.body?.cancel();
    throw new UserError('invalid_code', 'That pairing code is invalid, expired or already used. Generate a new one.');
  }
  if (!res.ok) {
    await res.body?.cancel();
    throw new UserError('portal_error', `The portal refused the pairing (HTTP ${res.status}).`);
  }
  let body: { uploadToken?: unknown } | null;
  try {
    body = (await res.json()) as { uploadToken?: unknown };
  } catch {
    body = null;
  }
  if (!body || typeof body.uploadToken !== 'string' || !TOKEN_RE.test(body.uploadToken)) {
    throw new UserError('portal_error', 'The portal returned an unexpected pairing response.');
  }
  return body.uploadToken;
}
