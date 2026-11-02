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
