// When each expanded request was last fetched successfully by this extension.
// It gates cold resources and is stored in chrome.storage.local.
export type Fetched = Record<string, string>;

export const MAX_FETCHED_KEYS = 1500;

// Deterministic per-key offset of 0 to 25% of the interval (FNV-1a hash of the key), so
// cold resources fetched together do not all fall due at the same moment.
export function coldOffsetMs(key: string, intervalHours: number): number {
  let h = 0x811c9dc5;
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i);
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return Math.floor((h / 0x100000000) * 0.25 * intervalHours * 3600_000);
}

// When the key falls due: interval minus its offset after the last fetch. The offset only
// ever shortens the interval, so data is never older than coldIntervalHours.
function dueAt(last: string | undefined, intervalHours: number, key?: string): number {
  if (!last) return -Infinity;
  const t = Date.parse(last);
  if (Number.isNaN(t)) return -Infinity;
  return t + intervalHours * 3600_000 - (key ? coldOffsetMs(key, intervalHours) : 0);
}

export function isDue(last: string | undefined, intervalHours: number, now: number, key?: string): boolean {
  return now >= dueAt(last, intervalHours, key);
}

// How long past due (ms); Infinity when never fetched. Used to pick the most overdue first.
export function overdueMs(last: string | undefined, intervalHours: number, now: number, key?: string): number {
  const d = dueAt(last, intervalHours, key);
  return d === -Infinity ? Infinity : now - d;
}

// Records the keys fetched in this run. When the run saw the whole plan
// (planKeys given), keys that left the plan are dropped. The map is capped,
// dropping the oldest entries.
export function updateFetched(
  prev: Fetched | undefined,
  fetchedKeys: string[],
  planKeys: string[] | undefined,
  nowIso: string,
  cap = MAX_FETCHED_KEYS,
): Fetched {
  let next: Fetched = { ...(prev ?? {}) };
  if (planKeys) {
    const keep = new Set(planKeys);
    next = Object.fromEntries(Object.entries(next).filter(([k]) => keep.has(k)));
  }
  for (const k of fetchedKeys) next[k] = nowIso;
  const entries = Object.entries(next);
  if (entries.length > cap) {
    entries.sort((a, b) => Date.parse(b[1]) - Date.parse(a[1]));
    next = Object.fromEntries(entries.slice(0, cap));
  }
  return next;
}
