// Extension state lives in chrome.storage.local (restricted to trusted contexts
// when the browser supports it). The upload token is never read by content scripts.
export interface Pairing {
  portalOrigin: string;
  state: string;
  expires: number;
  tabId?: number;
  status: 'pending' | 'connected' | 'error';
  message?: string;
}

export interface Counts {
  planned: number;
  fetched: number;
  canvasErrors: number;
  skipped: number;
  accepted: number;
  rejected: number;
  kept?: number; // resources where the server kept an older good copy
  notDue?: number; // cold resources deliberately not fetched yet
}

export interface LastResult {
  at: string;
  trigger: 'tab' | 'alarm' | 'manual';
  ok: boolean;
  code: string;
  message: string;
  counts: Counts;
  skipReasons?: string[];
  timing?: { totalMs: number; slowest: { path: string; ms: number; bytes: number }[] };
}

export interface Stored {
  portalOrigin?: string;
  uploadToken?: string;
  canvasOrigin?: string;
  lastSyncAt?: string;
  lastAttemptAt?: string;
  lastResult?: LastResult;
  lastFetchedAt?: Record<string, string>;
  lastCourseIds?: number[];
  needsReconnect?: boolean;
  backoffUntil?: number;
  pairing?: Pairing;
  /** A Canvas address the portal suggested; used once the person allows access to it. */
  suggestedCanvasOrigin?: string;
  /** What the popup asked for before a permission prompt closed it (see the controller's resumeIntent). */
  pendingIntent?: Intent;
  /** Why a request the popup could not see through failed; shown the next time it opens. */
  notice?: string;
  /** When this browser was paired (ISO 8601): the age of the data before its first sync. */
  connectedAt?: string;
  /** Remind when the data is older than this many hours; 0 turns reminders off (see reminder.ts). */
  remindAfterHours?: number;
  /** No reminder before this time (epoch ms). */
  snoozeUntil?: number;
}

export type Intent =
  | { type: 'pair.start'; portalOrigin: string; at: number }
  | { type: 'pair.manual'; portalOrigin: string; code: string; at: number }
  | { type: 'canvas.set'; canvasOrigin: string; at: number };

export const STORAGE_KEYS: (keyof Stored)[] = [
  'portalOrigin',
  'uploadToken',
  'canvasOrigin',
  'lastSyncAt',
  'lastAttemptAt',
  'lastResult',
  'lastFetchedAt',
  'lastCourseIds',
  'needsReconnect',
  'backoffUntil',
  'pairing',
  'suggestedCanvasOrigin',
  'pendingIntent',
  'notice',
  'connectedAt',
  'remindAfterHours',
  'snoozeUntil',
];

export interface StorageArea {
  get(keys?: string | string[] | null): Promise<Record<string, unknown>>;
  set(items: Record<string, unknown>): Promise<void>;
  remove(keys: string | string[]): Promise<void>;
}

export const TOKEN_RE = /^[A-Za-z0-9_-]{32,128}$/;
export const CODE_RE = /^[A-Za-z0-9_-]{6,128}$/;

export async function readState(area: StorageArea): Promise<Stored> {
  return (await area.get(STORAGE_KEYS)) as Stored;
}

export const isConnected = (s: Stored): boolean =>
  !!s.portalOrigin && typeof s.uploadToken === 'string' && TOKEN_RE.test(s.uploadToken);

export async function saveConnection(area: StorageArea, portalOrigin: string, uploadToken: string): Promise<void> {
  await area.set({ portalOrigin, uploadToken, needsReconnect: false, connectedAt: new Date().toISOString() });
  await area.remove('snoozeUntil');
  await area.remove(['lastResult', 'lastSyncAt', 'lastAttemptAt', 'lastFetchedAt', 'lastCourseIds', 'backoffUntil']);
}

// The server no longer accepts the token: forget it but keep the settings so
// that reconnecting is one click.
export async function markDisconnected(area: StorageArea): Promise<void> {
  await area.remove(['uploadToken', 'backoffUntil']);
  await area.set({ needsReconnect: true });
}

export async function clearAll(area: StorageArea): Promise<void> {
  await area.remove(STORAGE_KEYS as string[]);
}
