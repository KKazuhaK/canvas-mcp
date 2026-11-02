// When each expanded request was last fetched successfully by this extension.
// It gates cold resources and is stored in chrome.storage.local.
export type Fetched = Record<string, string>;

export const MAX_FETCHED_KEYS = 1500;

export function isDue(last: string | undefined, intervalHours: number, now: number): boolean {
  if (!last) return true;
  const t = Date.parse(last);
  return Number.isNaN(t) || now - t >= intervalHours * 3600_000;
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
