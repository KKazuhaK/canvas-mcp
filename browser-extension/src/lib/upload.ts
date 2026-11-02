export interface UploadHeader {
  schemaVersion: 1;
  canvasOrigin: string;
  canvasUserId: number;
  capturedAt: string;
  planVersion: number;
}

export interface UploadResource {
  path: string;
  query: Record<string, string | string[]>;
  status: number;
  body: unknown;
}

const encoder = new TextEncoder();
export const byteLength = (s: string): number => encoder.encode(s).length;

// Splits resources into batches whose serialised upload stays under limitBytes.
// A single resource that cannot fit on its own is returned in `oversized`.
export function splitUploads(
  header: UploadHeader,
  resources: UploadResource[],
  limitBytes: number,
): { batches: UploadResource[][]; oversized: UploadResource[] } {
  const base = byteLength(JSON.stringify({ ...header, resources: [] }));
  const batches: UploadResource[][] = [];
  const oversized: UploadResource[] = [];
  let current: UploadResource[] = [];
  let size = base;
  for (const r of resources) {
    const n = byteLength(JSON.stringify(r)) + 1; // + comma
    if (base + n > limitBytes) {
      oversized.push(r);
      continue;
    }
    if (size + n > limitBytes && current.length) {
      batches.push(current);
      current = [];
      size = base;
    }
    current.push(r);
    size += n;
  }
  if (current.length) batches.push(current);
  return { batches, oversized };
}

// Upload order. The portal prunes old per-course chunk rows when it sees new
// course and group lists, so the lists must travel in the same batch as every
// courseList chunk and group-calendar chunk (lists first). If that set is bigger
// than one batch it still goes first, lists together with as many chunks as fit,
// ahead of all other resources. The sort is stable.
export function rankForUpload(r: UploadResource, expand: string | null | undefined): 0 | 1 | 2 {
  if (r.path === '/courses' || r.path === '/users/self/groups') return 0;
  const codes = r.query['context_codes[]'];
  const list = Array.isArray(codes) ? codes : codes ? [codes] : [];
  const groupCalendar = r.path === '/calendar_events' && list.length > 0 && list.every((c) => c.startsWith('group_'));
  return expand === 'courseList' || groupCalendar ? 1 : 2;
}

export function orderForUpload(resources: UploadResource[], expandOf: (r: UploadResource) => string | null | undefined): UploadResource[] {
  return resources
    .map((r, i) => ({ r, i, rank: rankForUpload(r, expandOf(r)) }))
    .sort((a, b) => a.rank - b.rank || a.i - b.i)
    .map((x) => x.r);
}
