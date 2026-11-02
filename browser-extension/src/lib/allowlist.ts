// The extension's own allowlist. It applies regardless of what the plan says.
export const ALLOWED_PATH =
  /^\/(users\/self(\/(profile|todo|groups|activity_stream(\/summary)?))?|courses(\/\d+(\/(assignments|assignment_groups|modules|quizzes|front_page|discussion_topics))?)?|planner\/items|planner_notes|calendar_events|announcements)$/;

export type Query = Record<string, string | string[]>;

export interface PlanResource {
  path: string;
  query: Query;
  paginate: boolean;
  perCourse: boolean;
}

export interface Plan {
  planVersion: number;
  canvasHost: string | null;
  maxPages: number;
  resources: PlanResource[];
}

export interface Rejected {
  path: string;
  reason: string;
}

export interface FetchJob {
  path: string;
  query: Query;
  paginate: boolean;
}

const KEY = /^[A-Za-z0-9_.[\]-]{1,64}$/;
const FORBIDDEN_KEYS = new Set(['access_token', 'page', 'per_page']);
// No control characters in values; keeps the query free of anything odd.
// eslint-disable-next-line no-control-regex
const VALUE = /^[^\u0000-\u001f\u007f]{0,200}$/;

export function validateQuery(query: unknown): string | null {
  if (query === undefined) return null;
  if (typeof query !== 'object' || query === null || Array.isArray(query)) return 'query is not an object';
  const entries = Object.entries(query as Record<string, unknown>);
  if (entries.length > 20) return 'too many query parameters';
  for (const [k, v] of entries) {
    if (!KEY.test(k) || FORBIDDEN_KEYS.has(k)) return `query key not allowed: ${k.slice(0, 30)}`;
    const values = Array.isArray(v) ? v : [v];
    if (values.length > 20) return 'too many query values';
    for (const item of values) {
      if (typeof item !== 'string' || !VALUE.test(item)) return `query value not allowed for ${k}`;
    }
  }
  return null;
}

// Path must already be expanded ({course_id} replaced).
export function validateRequest(path: unknown, query: unknown, method: unknown = 'GET'): string | null {
  if (method !== 'GET') return 'only GET requests are allowed';
  if (typeof path !== 'string') return 'path is not a string';
  if (!ALLOWED_PATH.test(path)) return 'path is not on the allowlist';
  return validateQuery(query);
}

export function buildUrl(origin: string, path: string, query: Query, extra: Query = {}): string {
  const params = new URLSearchParams();
  for (const [k, v] of Object.entries({ ...query, ...extra })) {
    for (const item of Array.isArray(v) ? v : [v]) params.append(k, item);
  }
  const qs = params.toString();
  return `${origin}/api/v1${path}${qs ? `?${qs}` : ''}`;
}

export function parsePlan(raw: unknown): { plan: Plan; rejected: Rejected[] } {
  const r = raw as Record<string, unknown> | null;
  if (!r || typeof r !== 'object' || typeof r.planVersion !== 'number' || !Array.isArray(r.resources)) {
    throw new Error('plan is malformed');
  }
  const canvasHost = typeof r.canvasHost === 'string' && r.canvasHost ? r.canvasHost : null;
  const maxPages = typeof r.maxPages === 'number' && r.maxPages >= 1 ? Math.min(Math.floor(r.maxPages), 200) : 50;
  const resources: PlanResource[] = [];
  const rejected: Rejected[] = [];
  for (const item of r.resources.slice(0, 500)) {
    const it = item as Record<string, unknown> | null;
    const path = it && typeof it.path === 'string' ? it.path : '';
    if (!it || typeof it !== 'object' || !path) {
      rejected.push({ path: String(path).slice(0, 80), reason: 'resource is malformed' });
      continue;
    }
    const query = (it.query ?? {}) as Query;
    const bad = validateQuery(query);
    if (bad) {
      rejected.push({ path, reason: bad });
      continue;
    }
    resources.push({ path, query, paginate: it.paginate === true, perCourse: it.perCourse === true });
  }
  return { plan: { planVersion: r.planVersion, canvasHost, maxPages, resources }, rejected };
}

// Expands the plan into concrete requests. Plain resources first; per-course
// resources are expanded over the supplied course ids.
export function expandPlan(
  resources: PlanResource[],
  courseIds: number[] | null,
): { plain: FetchJob[]; perCourse: FetchJob[]; rejected: Rejected[] } {
  const plain: FetchJob[] = [];
  const perCourse: FetchJob[] = [];
  const rejected: Rejected[] = [];
  const seen = new Set<string>();
  const add = (list: FetchJob[], job: FetchJob) => {
    const bad = hasBrace(job) ? 'leftover brace after expansion' : validateRequest(job.path, job.query);
    if (bad) {
      rejected.push({ path: job.path.slice(0, 80), reason: bad });
      return;
    }
    const id = job.path + '?' + JSON.stringify(job.query);
    if (seen.has(id)) return;
    seen.add(id);
    list.push(job);
  };
  const PLACEHOLDER = '{course_id}';
  const fill = (res: PlanResource, id: string): FetchJob => ({
    path: res.path.replaceAll(PLACEHOLDER, id),
    query: Object.fromEntries(
      Object.entries(res.query).map(([k, v]) => [
        k,
        Array.isArray(v) ? v.map((x) => x.replaceAll(PLACEHOLDER, id)) : v.replaceAll(PLACEHOLDER, id),
      ]),
    ),
    paginate: res.paginate,
  });
  const hasBrace = (job: FetchJob): boolean =>
    /[{}]/.test(job.path) || Object.values(job.query).some((v) => (Array.isArray(v) ? v : [v]).some((x) => /[{}]/.test(x)));
  const hasPlaceholder = (res: PlanResource): boolean =>
    res.path.includes(PLACEHOLDER) ||
    Object.values(res.query).some((v) => (Array.isArray(v) ? v : [v]).some((x) => x.includes(PLACEHOLDER)));
  for (const res of resources) {
    if (!res.perCourse) {
      // A placeholder here would be sent literally; validateRequest rejects it.
      add(plain, { path: res.path, query: res.query, paginate: res.paginate });
      continue;
    }
    if (!hasPlaceholder(res)) {
      rejected.push({ path: res.path, reason: 'perCourse resource has no {course_id}' });
      continue;
    }
    const probe = fill(res, '1');
    const bad = hasBrace(probe) ? 'leftover brace after expansion' : validateRequest(probe.path, probe.query);
    if (bad) {
      rejected.push({ path: res.path, reason: bad });
      continue;
    }
    if (!courseIds) {
      rejected.push({ path: res.path, reason: 'no course list available to expand' });
      continue;
    }
    for (const id of courseIds) {
      if (!Number.isSafeInteger(id) || id <= 0) continue;
      add(perCourse, fill(res, String(id)));
    }
  }
  return { plain, perCourse, rejected };
}
