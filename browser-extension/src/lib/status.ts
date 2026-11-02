import { isConnected, type Stored } from './state.ts';

export function relativeTime(iso: string | undefined, now: number): string {
  if (!iso) return 'never';
  const secs = Math.max(0, Math.round((now - Date.parse(iso)) / 1000));
  if (Number.isNaN(secs)) return 'never';
  if (secs < 60) return 'just now';
  const mins = Math.round(secs / 60);
  if (mins < 60) return `${mins} minute${mins === 1 ? '' : 's'} ago`;
  const hours = Math.round(mins / 60);
  if (hours < 48) return `${hours} hour${hours === 1 ? '' : 's'} ago`;
  return `${Math.round(hours / 24)} days ago`;
}

export interface StatusView {
  connected: boolean;
  headline: string;
  rows: [string, string][];
  error: string | null;
  skipReasons: string[];
}

export function describeStatus(s: Stored, now: number): StatusView {
  const connected = isConnected(s);
  const rows: [string, string][] = [];
  let headline: string;
  if (connected) {
    headline = s.canvasOrigin ? 'Connected' : 'Connected, choose your Canvas site';
    rows.push(['Portal', new URL(s.portalOrigin!).host]);
  } else {
    headline = s.needsReconnect ? 'Reconnect needed' : 'Not connected';
  }
  if (s.canvasOrigin) rows.push(['Canvas', new URL(s.canvasOrigin).host]);
  if (connected && s.canvasOrigin) {
    rows.push(['Last sync', relativeTime(s.lastSyncAt, now)]);
    const c = s.lastResult?.counts;
    if (c) {
      const parts = [`${c.accepted} stored`];
      if (c.canvasErrors) parts.push(`${c.canvasErrors} unreadable`);
      if (c.skipped) parts.push(`${c.skipped} skipped`);
      if (c.rejected) parts.push(`${c.rejected} rejected`);
      rows.push(['Last run', parts.join(', ')]);
    }
  }
  let error: string | null = null;
  if (s.needsReconnect && !connected) error = 'The portal no longer accepts this browser. Connect again to continue.';
  else if (s.pairing?.status === 'error' && s.pairing.message) error = s.pairing.message;
  else if (s.lastResult && !s.lastResult.ok) error = s.lastResult.message;
  else if (s.lastResult?.code === 'partial') error = s.lastResult.message;
  return { connected, headline, rows, error, skipReasons: (s.lastResult?.skipReasons ?? []).slice(0, 3) };
}
