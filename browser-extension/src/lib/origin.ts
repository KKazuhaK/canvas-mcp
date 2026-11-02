import { UserError } from './errors.ts';

export function isLocalDevHost(hostname: string): boolean {
  return hostname === 'localhost' || hostname === '127.0.0.1';
}

// Accepts an HTTPS origin (or http on localhost / 127.0.0.1 for development)
// with no credentials, path, query or fragment. Returns the normalised origin.
export function parseOrigin(raw: unknown, what = 'address'): string {
  const fail = () =>
    new UserError('bad_origin', `Enter the ${what} as an https:// address with no path (for example https://school.instructure.com).`);
  if (typeof raw !== 'string') throw fail();
  let u: URL;
  try {
    u = new URL(raw.trim());
  } catch {
    throw fail();
  }
  const okScheme = u.protocol === 'https:' || (u.protocol === 'http:' && isLocalDevHost(u.hostname));
  if (!okScheme || u.username || u.password || u.search || u.hash || !['', '/'].includes(u.pathname)) throw fail();
  return u.origin;
}

// Match patterns carry no port, so the pattern covers every port of the host.
export function hostPattern(origin: string): string {
  const u = new URL(origin);
  return `${u.protocol}//${u.hostname}/*`;
}

export function sameOrigin(url: string | undefined, origin: string): boolean {
  if (!url) return false;
  try {
    return new URL(url).origin === origin;
  } catch {
    return false;
  }
}
