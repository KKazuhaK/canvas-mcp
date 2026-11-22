export const EXT_ID = 'abcdefghijklmnopabcdefghijklmnop';
export const POPUP_URL = `chrome-extension://${EXT_ID}/popup.html`;
export const PORTAL = 'https://portal.example.com';
export const CANVAS = 'https://school.instructure.com';
export const TOKEN = 'T'.repeat(43);

export function makeStorage(initial: Record<string, unknown> = {}) {
  const data: Record<string, unknown> = { ...initial };
  return {
    data,
    async get(keys?: string | string[] | null) {
      if (keys == null) return { ...data };
      const list = Array.isArray(keys) ? keys : [keys];
      return Object.fromEntries(list.filter((k) => k in data).map((k) => [k, data[k]]));
    },
    async set(items: Record<string, unknown>) {
      Object.assign(data, JSON.parse(JSON.stringify(items)));
    },
    async remove(keys: string | string[]) {
      for (const k of Array.isArray(keys) ? keys : [keys]) delete data[k];
    },
  };
}

export interface MockOpts {
  storage?: Record<string, unknown>;
  permissions?: string[]; // granted match patterns
  tabs?: { id: number; url: string; status?: string }[];
  executeScript?: (details: any) => Promise<any[]>;
}

export function makeChrome(opts: MockOpts = {}) {
  const storage = makeStorage(opts.storage);
  const created: any[] = [];
  const injected: any[] = [];
  const registered: any[] = [];
  const alarms = new Map<string, any>();
  const tabs = [...(opts.tabs ?? [])];
  const granted = new Set(opts.permissions ?? []);
  const api = {
    runtime: { id: EXT_ID, getURL: (p: string) => `chrome-extension://${EXT_ID}/${p}` },
    storage: { local: storage },
    permissions: { contains: async ({ origins }: { origins: string[] }) => origins.every((o) => granted.has(o)) },
    alarms: {
      get: async (n: string) => alarms.get(n),
      create: async (n: string, i: any) => void alarms.set(n, i),
      clear: async (n: string) => alarms.delete(n),
    },
    tabs: {
      create: async (o: { url: string }) => {
        const t = { id: 100 + created.length, url: o.url, status: 'complete' };
        created.push(t);
        tabs.push(t);
        return t;
      },
      get: async (id: number) => tabs.find((t) => t.id === id),
      query: async () => tabs,
      remove: async (ids: number | number[]) => {
        for (const id of Array.isArray(ids) ? ids : [ids]) {
          const i = tabs.findIndex((t) => t.id === id);
          if (i >= 0) tabs.splice(i, 1);
        }
      },
    },
    scripting: {
      executeScript: async (d: any) => {
        injected.push(d);
        return opts.executeScript ? opts.executeScript(d) : [{ result: undefined }];
      },
      registerContentScripts: async (list: any[]) => void registered.push(...list),
      unregisterContentScripts: async ({ ids }: { ids: string[] }) => {
        for (const id of ids) {
          const i = registered.findIndex((r) => r.id === id);
          if (i >= 0) registered.splice(i, 1);
        }
      },
    },
  };
  return { api: api as any, storage, created, injected, alarms, tabs, granted, registered };
}

export function jsonResponse(body: unknown, init: { status?: number; headers?: Record<string, string>; url?: string; redirected?: boolean } = {}) {
  const text = typeof body === 'string' ? body : JSON.stringify(body);
  const res = new Response(text, { status: init.status ?? 200, headers: { 'content-type': 'application/json', ...(init.headers ?? {}) } });
  if (init.url) Object.defineProperty(res, 'url', { value: init.url });
  if (init.redirected) Object.defineProperty(res, 'redirected', { value: true });
  return res;
}
