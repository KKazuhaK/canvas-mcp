// IMPORTANT: runFetches is serialised by chrome.scripting.executeScript and run
// inside a Canvas page, so it must be fully self-contained: no references to
// imports or module-level values, only its arguments and web platform globals.

export type FetchErrorCode =
  | 'not_signed_in'
  | 'pagination_moved'
  | 'too_many_pages'
  | 'page_failed'
  | 'rate_limited'
  | 'bad_json'
  | 'network';

export interface FetchJobInput {
  path: string;
  query: Record<string, string | string[]>;
  paginate: boolean;
}

export interface FetchResult {
  path: string;
  query: Record<string, string | string[]>;
  status: number | null;
  body: unknown;
  error?: FetchErrorCode;
  pages: number;
}

export async function runFetches(origin: string, jobs: FetchJobInput[], maxPages: number): Promise<FetchResult[]> {
  const API = '/api/v1';

  const stripPrefix = (text: string): string => text.replace(/^\s*while\(1\);?/, '');

  // Returns the target of a rel="next" link, or null.
  const nextLink = (header: string | null): string | null => {
    if (!header) return null;
    const re = /<([^>]*)>\s*((?:;\s*[^;,]+)*)/g;
    let m: RegExpExecArray | null;
    while ((m = re.exec(header))) {
      const rel = /;\s*rel\s*=\s*"?([^";]*)"?/i.exec(m[2] ?? '');
      if (rel && (rel[1] ?? '').toLowerCase().split(/\s+/).includes('next')) return m[1] ?? null;
    }
    return null;
  };

  const urlFor = (job: FetchJobInput): string => {
    const params = new URLSearchParams();
    for (const [k, v] of Object.entries(job.query)) {
      for (const item of Array.isArray(v) ? v : [v]) params.append(k, item);
    }
    if (job.paginate) params.set('per_page', '100');
    const qs = params.toString();
    return `${origin}${API}${job.path}${qs ? `?${qs}` : ''}`;
  };

  const CONCURRENCY = 2;
  const MAX_429_RETRIES = 3;
  let pauseUntil = 0;
  const sleep = (ms: number) => new Promise<void>((resolve) => setTimeout(resolve, ms));

  // Canvas throttles with 429, or with 403 and a "Rate Limit Exceeded" body. Either
  // pauses every worker's next request for Retry-After (default 5 s, at most 30 s)
  // and retries this request. A throttle response is never returned as a status.
  const doFetch = async (url: string): Promise<{ res: Response; throttled: boolean }> => {
    for (let attempt = 0; ; attempt++) {
      const wait = pauseUntil - Date.now();
      if (wait > 0) await sleep(wait);
      const res = await fetch(url, {
        credentials: 'include',
        headers: { Accept: 'application/json' },
        signal: AbortSignal.timeout(30000),
      });
      let throttled = res.status === 429;
      if (res.status === 403) {
        try {
          throttled = /rate limit exceeded/i.test(await res.clone().text());
        } catch {
          throttled = false;
        }
      }
      if (!throttled) return { res, throttled: false };
      if (attempt >= MAX_429_RETRIES) return { res, throttled: true };
      const secs = Number(res.headers.get('retry-after'));
      const ms = Number.isFinite(secs) && secs > 0 ? Math.min(secs * 1000, 30000) : 5000;
      pauseUntil = Math.max(pauseUntil, Date.now() + ms);
      await res.body?.cancel();
    }
  };

  const runJob = async (job: FetchJobInput): Promise<FetchResult> => {
    const out: FetchResult = { path: job.path, query: job.query, status: null, body: null, pages: 0 };
    const apiPath = `${API}${job.path}`;
    let url: string | null = urlFor(job);
    let merged: unknown = null;
    try {
      while (url) {
        if (out.pages >= (job.paginate ? maxPages : 1)) {
          // More pages exist than the cap allows: a partial list would mislead.
          out.error = 'too_many_pages';
          out.body = null;
          out.status = null;
          break;
        }
        const { res, throttled } = await doFetch(url);
        if (throttled) {
          out.pages++;
          out.error = 'rate_limited';
          out.status = null;
          out.body = null;
          break;
        }
        out.pages++;
        let finalUrl: URL | null = null;
        try {
          finalUrl = new URL(res.url || url);
        } catch {
          finalUrl = null;
        }
        const redirectedAway =
          res.redirected && (!finalUrl || finalUrl.origin !== origin || !finalUrl.pathname.startsWith(`${API}/`));
        const html = /text\/html/i.test(res.headers.get('content-type') ?? '');
        if (redirectedAway || (res.status === 200 && html)) {
          out.error = 'not_signed_in';
          out.status = null;
          out.body = null;
          break;
        }
        if (res.status !== 200) {
          if (out.pages > 1) {
            out.error = 'page_failed';
            out.status = null;
            out.body = null;
          } else {
            out.status = res.status;
            out.body = null;
          }
          break;
        }
        let page: unknown;
        try {
          page = JSON.parse(stripPrefix(await res.text()));
        } catch {
          out.error = 'bad_json';
          out.status = null;
          out.body = null;
          break;
        }
        if (merged === null) merged = page;
        else if (Array.isArray(merged) && Array.isArray(page)) merged = merged.concat(page);
        else {
          out.error = 'bad_json';
          out.status = null;
          out.body = null;
          break;
        }
        out.status = 200;
        out.body = merged;
        if (!job.paginate) break;
        const next = nextLink(res.headers.get('link'));
        if (!next) break;
        let target: URL;
        try {
          target = new URL(next, finalUrl ?? url);
        } catch {
          out.error = 'pagination_moved';
          out.status = null;
          out.body = null;
          break;
        }
        // Follow only links that stay on the same origin and API path.
        if (target.origin !== origin || target.pathname !== apiPath) {
          out.error = 'pagination_moved';
          out.status = null;
          out.body = null;
          break;
        }
        url = target.toString();
      }
    } catch {
      out.error = 'network';
      out.status = null;
      out.body = null;
    }
    return out;
  };

  // Resources run with a small concurrency cap; pages within one resource stay sequential.
  const results: FetchResult[] = new Array(jobs.length);
  let nextIndex = 0;
  const worker = async () => {
    while (nextIndex < jobs.length) {
      const i = nextIndex++;
      results[i] = await runJob(jobs[i] as FetchJobInput);
    }
  };
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, jobs.length) }, worker));
  return results;
}
