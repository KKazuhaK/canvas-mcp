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
}

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
  await area.set({ portalOrigin, uploadToken, needsReconnect: false });
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
