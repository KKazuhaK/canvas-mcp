import { expandPlan, parsePlan, type FetchJob } from './allowlist.ts';
import type { FetchResult } from './canvas-fetch.ts';
import type { Counts } from './state.ts';
import { splitUploads, type UploadResource } from './upload.ts';

export interface SyncInput {
  portalOrigin: string;
  uploadToken: string;
  canvasOrigin: string;
  // Alarm runs with no Canvas tab probe Canvas first and stay silent when signed out.
  probeFirst?: boolean;
}

export interface SyncDeps {
  fetch: typeof fetch;
  readCanvas(origin: string, jobs: FetchJob[], maxPages: number): Promise<FetchResult[]>;
  now(): Date;
}

export interface Outcome {
  ok: boolean;
  code: string;
  message: string;
  counts: Counts;
  reconnect?: boolean;
  retryAfterMs?: number;
  waiting?: boolean;
  skipReasons?: string[];
}

class Stop extends Error {
  code: string;
  extra: Partial<Outcome>;
  constructor(code: string, message: string, extra: Partial<Outcome> = {}) {
    super(message);
    this.code = code;
    this.extra = extra;
  }
}

const DEFAULT_MAX_BODY = 4 * 1024 * 1024;
const DEFAULT_RETRY_MS = 15 * 60_000;
export const zeroCounts = (): Counts => ({ planned: 0, fetched: 0, canvasErrors: 0, skipped: 0, accepted: 0, rejected: 0 });

const QUOTA_BACKOFF_MS = 60 * 60_000;
const QUOTA_MESSAGE =
  "Your portal's storage for browser sync is full (3000 items or 64 MiB). The extension will not retry for an hour; remove old data in your account or ask the portal administrator.";
const COURSES_MESSAGE =
  'You are enrolled in more courses than the portal accepts, so some of your data was not stored. The extension will not retry for an hour.';

const SELF: FetchJob = { path: '/users/self', query: {}, paginate: false };

function retryAfter(res: Response): number {
  const n = Number(res.headers.get('retry-after'));
  return Number.isFinite(n) && n > 0 ? Math.min(n * 1000, 6 * 3600_000) : DEFAULT_RETRY_MS;
}

export async function runSync(input: SyncInput, deps: SyncDeps): Promise<Outcome> {
  const counts = zeroCounts();
  const reasons: string[] = [];
  let quotaMessage = '';
  const skip = (path: string, reason: string) => {
    if (reasons.length < 10) reasons.push(`${path.slice(0, 60)}: ${reason}`);
  };
  const auth = { Authorization: `Bearer ${input.uploadToken}` };
  const canvasHost = new URL(input.canvasOrigin).host;

  const portal = async (path: string, init: RequestInit = {}): Promise<Response> => {
    let res: Response;
    try {
      res = await deps.fetch(input.portalOrigin + path, {
        credentials: 'omit',
        redirect: 'error',
        signal: AbortSignal.timeout(30000),
        ...init,
      });
    } catch {
      throw new Stop('portal_unreachable', 'Could not reach the portal. It will be retried later.');
    }
    if (res.status === 401) {
      await res.body?.cancel();
      throw new Stop('unauthorized', 'The portal no longer accepts this browser. Reconnect it from the popup.', { reconnect: true });
    }
    if (res.status === 429) {
      await res.body?.cancel();
      throw new Stop('rate_limited', 'The portal asked the extension to slow down. It will try again later.', { retryAfterMs: retryAfter(res) });
    }
    return res;
  };

  try {
    if (input.probeFirst) {
      let probe: FetchResult[] = [];
      try {
        probe = await deps.readCanvas(input.canvasOrigin, [SELF], 1);
      } catch {
        /* treated as signed out */
      }
      if (probe[0]?.status !== 200) {
        return { ok: false, code: 'waiting', message: 'Not signed in to Canvas; waiting for the next Canvas page visit.', counts, waiting: true };
      }
    }

    interface Prev {
      keys: Set<string>;
      canvasUserId: number;
      courseIds: number[] | null;
    }
    const pass = async (prev: Prev | null) => {
      // 1. Plan
      const planRes = await portal('/api/v1/extension/plan', { headers: auth });
      if (!planRes.ok) {
        await planRes.body?.cancel();
        throw new Stop('portal_error', `The portal could not provide a sync plan (HTTP ${planRes.status}).`);
      }
      let parsed;
      try {
        parsed = parsePlan(await planRes.json());
      } catch {
        throw new Stop('plan_invalid', 'The portal sent a sync plan the extension could not read.');
      }
      const { plan } = parsed;
      if (!prev) {
        counts.skipped += parsed.rejected.length;
        for (const r of parsed.rejected) skip(r.path, r.reason);
      }
      if (plan.canvasHost && plan.canvasHost.toLowerCase() !== canvasHost.toLowerCase()) {
        throw new Stop('canvas_mismatch', `Your portal is set up for ${plan.canvasHost}, but this extension is set to ${canvasHost}. Change the Canvas site in the popup.`);
      }

      let maxBody = DEFAULT_MAX_BODY;
      try {
        const capRes = await deps.fetch(`${input.portalOrigin}/api/v1/extension/capabilities`, {
          credentials: 'omit',
          redirect: 'error',
          signal: AbortSignal.timeout(10000),
        });
        const cap = (await capRes.json()) as { maxBodyBytes?: unknown };
        if (typeof cap.maxBodyBytes === 'number' && cap.maxBodyBytes > 10_000) maxBody = cap.maxBodyBytes;
      } catch {
        /* keep the default */
      }

      // 2. Canvas reads: plain resources, then per-course resources.
      const startedAt = deps.now();
      const first = expandPlan(plan.resources, null);
      const results: FetchResult[] = [];
      const read = async (jobs: FetchJob[]) => {
        if (!jobs.length) return [];
        let out: FetchResult[];
        try {
          out = await deps.readCanvas(input.canvasOrigin, jobs, plan.maxPages);
        } catch (e) {
          if (e instanceof Stop) throw e;
          throw new Stop('canvas_unavailable', 'Could not read Canvas. Open a Canvas tab and try again.');
        }
        results.push(...out);
        return out;
      };
      const keyOf = (j: FetchJob) => j.path + '?' + JSON.stringify(j.query);
      const fresh = (j: FetchJob) => !prev || !prev.keys.has(keyOf(j));
      const freshPlain = first.plain.filter(fresh);
      const plainResults = await read(freshPlain);
      counts.planned += freshPlain.length;

      let canvasUserId: number;
      let courseIds: number[] | null;
      if (prev) {
        canvasUserId = prev.canvasUserId;
        courseIds = prev.courseIds;
      } else {
        const selfResult = plainResults.find((r) => r.path === '/users/self');
        if (!selfResult) throw new Stop('plan_invalid', 'The sync plan does not include the Canvas profile, so nothing was synced.');
        if (selfResult.error === 'not_signed_in' || selfResult.status === 401) {
          throw new Stop('not_signed_in', 'Not signed in to Canvas (or this school does not allow session access to its API). Sign in to Canvas and try again.');
        }
        const self = selfResult.body as { id?: unknown } | null;
        if (selfResult.status !== 200 || !self || typeof self.id !== 'number') {
          throw new Stop('no_user', `Canvas did not return your profile${selfResult.status ? ` (HTTP ${selfResult.status})` : ''}, so nothing was synced.`);
        }
        canvasUserId = self.id;

        const coursesResult = plainResults.find((r) => r.path === '/courses' && r.status === 200 && Array.isArray(r.body));
        courseIds = coursesResult
          ? [...new Set((coursesResult.body as { id?: unknown }[]).map((c) => c?.id).filter((id): id is number => typeof id === 'number'))]
          : null;
      }

      const second = expandPlan(plan.resources, courseIds);
      // The second expansion reports every invalid resource once (plain ones too).
      if (!prev) {
        counts.skipped += second.rejected.length;
        for (const r of second.rejected) skip(r.path, r.reason);
      }
      const freshCourse = second.perCourse.filter(fresh);
      counts.planned += freshCourse.length;
      await read(freshCourse);

      // 3. Collect what can be uploaded.
      const upload: UploadResource[] = [];
      for (const r of results) {
        if (r.error === 'not_signed_in') {
          throw new Stop('not_signed_in', 'Your Canvas session ended during the sync. Sign in to Canvas and try again.');
        }
        if (r.error) {
          counts.canvasErrors++;
          continue;
        }
        if (r.status === null) {
          counts.canvasErrors++;
          continue;
        }
        if (r.status === 200) counts.fetched++;
        else counts.canvasErrors++;
        upload.push({ path: r.path, query: r.query, status: r.status, body: r.status === 200 ? r.body : null });
      }
      if (!upload.length && prev) return { plan, keys: new Set([...first.plain, ...second.perCourse].map(keyOf)), canvasUserId, courseIds };
      if (!upload.length) {
        throw new Stop('nothing_to_upload', 'Canvas data could not be read, so nothing was uploaded.');
      }

      // 4. Upload in batches under the server's body limit.
      const header = {
        schemaVersion: 1 as const,
        canvasOrigin: input.canvasOrigin,
        canvasUserId,
        capturedAt: startedAt.toISOString(),
        planVersion: plan.planVersion,
      };
      const { batches, oversized } = splitUploads(header, upload, Math.floor(maxBody * 0.75));
      counts.skipped += oversized.length;
      for (const r of oversized) skip(r.path, 'too large to upload');
      for (const batch of batches) {
        const res = await portal('/api/v1/extension/snapshots', {
          method: 'POST',
          headers: { ...auth, 'Content-Type': 'application/json' },
          body: JSON.stringify({ ...header, resources: batch }),
        });
        if (res.status === 409) {
          let code = '';
          try {
            code = ((await res.json()) as { error?: string }).error ?? '';
          } catch {
            /* ignore */
          }
          if (code === 'canvas_mismatch') {
            throw new Stop('canvas_mismatch', 'This Canvas account or school is different from the one paired with your portal. Disconnect and pair again to switch.');
          }
          throw new Stop('conflict', 'The portal rejected the upload as conflicting with the paired Canvas account.');
        }
        if (res.status === 413) {
          let code = '';
          try {
            code = ((await res.json()) as { error?: string }).error ?? '';
          } catch {
            /* no readable body */
          }
          if (code === 'quota_exceeded') throw new Stop('quota_exceeded', QUOTA_MESSAGE, { retryAfterMs: QUOTA_BACKOFF_MS });
          throw new Stop('too_large', 'The portal says the upload is too large. Try again after the next portal update.');
        }
        if (!res.ok) {
          let code = '';
          try {
            code = ((await res.json()) as { error?: string }).error ?? '';
          } catch {
            /* no readable body */
          }
          if (code === 'quota_exceeded') throw new Stop('quota_exceeded', QUOTA_MESSAGE, { retryAfterMs: QUOTA_BACKOFF_MS });
          // A client error will not fix itself on an immediate retry.
          throw new Stop('portal_error', `The portal could not store the upload (HTTP ${res.status}).`, res.status >= 400 && res.status < 500 ? { retryAfterMs: DEFAULT_RETRY_MS } : {});
        }
        try {
          const body = (await res.json()) as { accepted?: number; rejected?: unknown[] };
          counts.accepted += typeof body.accepted === 'number' ? body.accepted : 0;
          for (const r of Array.isArray(body.rejected) ? (body.rejected as { path?: unknown; reason?: unknown }[]) : []) {
            const reason = typeof r?.reason === 'string' ? r.reason : 'unknown';
            const path = typeof r?.path === 'string' ? r.path : 'upload';
            if (reason === 'kept_stored_data') {
              // Expected: the server kept an older good copy. Not an error.
              counts.kept = (counts.kept ?? 0) + 1;
              continue;
            }
            counts.rejected++;
            if (reason === 'too_many_courses') {
              quotaMessage = COURSES_MESSAGE;
              skip(path, 'more courses than the portal accepts');
            } else skip(path, `rejected by the portal (${reason.slice(0, 80)})`);
          }
        } catch {
          /* an unreadable acknowledgement is not fatal */
        }
      }
      return { plan, keys: new Set([...first.plain, ...second.perCourse].map(keyOf)), canvasUserId, courseIds };
    };

    const done = await pass(null);
    // On a first upload the plan has no Canvas host yet, and the server adds
    // user-specific resources only after it learns the user id. Fetch the plan
    // once more and sync just what is new.
    if (done.plan.canvasHost === null && !quotaMessage) await pass(done);

    if (quotaMessage) {
      return {
        ok: false,
        code: 'quota_exceeded',
        message: `${quotaMessage} ${counts.accepted} item${counts.accepted === 1 ? ' was' : 's were'} stored.`,
        counts,
        skipReasons: reasons,
        retryAfterMs: QUOTA_BACKOFF_MS,
      };
    }
    const notes: string[] = [];
    if (counts.canvasErrors) notes.push(`${counts.canvasErrors} could not be read from Canvas`);
    if (counts.skipped) notes.push(`${counts.skipped} skipped`);
    if (counts.rejected) notes.push(`${counts.rejected} rejected by the portal`);
    const kept = counts.kept ? ` ${counts.kept} kept previous data.` : '';
    return {
      ok: true,
      code: notes.length ? 'partial' : 'ok',
      message: `Synced ${counts.accepted} item${counts.accepted === 1 ? '' : 's'}${notes.length ? ` (${notes.join('; ')})` : ''}.${kept}`,
      counts,
      skipReasons: reasons,
    };
  } catch (e) {
    if (e instanceof Stop) return { ok: false, code: e.code, message: e.message, counts, skipReasons: reasons, ...e.extra };
    return { ok: false, code: 'error', message: 'The sync failed unexpectedly.', counts, skipReasons: reasons };
  }
}
