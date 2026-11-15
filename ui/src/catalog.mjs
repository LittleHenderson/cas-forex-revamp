/** Optional steward catalog extension. Exact references only; never a semantic verifier. */
import { assertSchema, freeze, parseUniqueJSON } from './wire.mjs';
import { canonicalJSON } from './decision-read.mjs';

export const MAX_CATALOG_RECORD_BYTES = 1048576;
export const MAX_CATALOG_BYTES = 8388608;
export const MAX_CATALOG_REFERENCES = 1024;
const FIELDS = ['record_id', 'record_version', 'record_sha256', 'unavailable_reason'];
const fail = (reason) => { throw new Error(reason); };
const same = (left, right) => canonicalJSON(left) === canonicalJSON(right);
const pointer = (key) => String(key).replaceAll('~', '~0').replaceAll('/', '~1');

/** Collect only shared reference objects, not URL-like IDs or prose locators. */
export function collectCatalogReferences(envelope, schema) {
  const unique = new Map(); const absent = [];
  function visit(value, path) {
    if (value === null || typeof value !== 'object') return;
    if (!Array.isArray(value) && FIELDS.every((field) => Object.hasOwn(value, field))) {
      assertSchema(value, schema.$defs.reference, schema);
      if (value.record_id === null) {
        if (value.record_version !== null || value.record_sha256 !== null || !value.unavailable_reason?.trim()) fail('Malformed unavailable catalog reference.');
        absent.push({ path, reason: value.unavailable_reason });
      } else {
        if (value.record_version === null || value.record_sha256 === null || value.unavailable_reason !== null) fail('Catalog reference lacks an exact version/hash.');
        const identity = canonicalJSON(value);
        if (!unique.has(identity)) unique.set(identity, { reference: structuredClone(value), paths: [] });
        unique.get(identity).paths.push(path);
      }
      return;
    }
    for (const [key, child] of Object.entries(value)) visit(child, `${path}/${pointer(key)}`);
  }
  visit(envelope, '$');
  return freeze({ references: [...unique.values()], absent });
}

function assertJSONValue(value, depth = 0, budget = { entries: 0 }) {
  if (depth > 32 || ++budget.entries > 16384) fail('Catalog record exceeds display complexity limits.');
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return;
  if (typeof value === 'number' && Number.isSafeInteger(value)) return;
  if (typeof value !== 'object' || (!Array.isArray(value) && ![Object.prototype, null].includes(Object.getPrototypeOf(value)))) fail('Catalog record is not supported canonical JSON.');
  for (const child of Object.values(value)) assertJSONValue(child, depth + 1, budget);
}

export async function inspectCatalogRecord(response, anchor, reference, hashBytes) {
  const fields = ['schema_version', 'anchor_id', 'producer_id', 'reference', 'record'];
  if (!response || Object.keys(response).length !== fields.length || !fields.every((field) => Object.hasOwn(response, field)) || response.schema_version !== 'forex.catalog-record/1') fail('Unsupported catalog response.');
  if (response.anchor_id !== anchor.anchor_id || response.producer_id !== anchor.producer_id) fail('Catalog response belongs to another read/producer.');
  if (!same(response.reference, reference)) fail('Catalog reference id/version/hash differs from the requested reference.');
  assertJSONValue(response.record);
  const canonical = canonicalJSON(response.record);
  const bytes = new TextEncoder().encode(canonical);
  if (bytes.byteLength > MAX_CATALOG_RECORD_BYTES) fail('Catalog record exceeds the 1 MiB display limit.');
  if (await hashBytes(bytes) !== reference.record_sha256) fail('Catalog canonical record bytes differ from the referenced hash.');
  return freeze({ record: parseUniqueJSON(canonical, MAX_CATALOG_RECORD_BYTES), bytes: bytes.byteLength });
}

export async function resolveCatalog({ envelope, schema, anchor, resolve, hashBytes, checkActive = () => {} }) {
  const collected = collectCatalogReferences(envelope, schema);
  const entries = []; let retainedBytes = 0;
  // Bounds are explicit local inspection limits; all unattempted references retain reasons.
  for (let start = 0; start < collected.references.length; start += 4) {
    checkActive();
    const group = collected.references.slice(start, start + 4);
    const results = await Promise.all(group.map(async (entry, offset) => {
      if (typeof resolve !== 'function') return { ...entry, status: 'UNAVAILABLE', reason: 'The attached bridge has no resolveEvidence extension.' };
      if (start + offset >= MAX_CATALOG_REFERENCES || retainedBytes >= MAX_CATALOG_BYTES) return { ...entry, status: 'UNAVAILABLE', reason: 'Catalog inspection limit reached; this exact reference was not resolved.' };
      try {
        const response = await resolve({ anchor_id: anchor.anchor_id, reference: entry.reference });
        checkActive();
        const record = await inspectCatalogRecord(response, anchor, entry.reference, hashBytes);
        checkActive();
        return { ...entry, status: 'MATCHED', reason: 'Exact catalog identity and canonical bytes matched for this issued read.', ...record };
      } catch (error) {
        checkActive(); // Detachment/scope replacement invalidates the entire in-flight read.
        return { ...entry, status: 'UNAVAILABLE', reason: error instanceof Error ? error.message : 'Exact catalog record could not be verified.' };
      }
    }));
    for (const result of results) {
      if (result.status === 'MATCHED' && retainedBytes + result.bytes > MAX_CATALOG_BYTES) {
        const { record: _record, bytes: _bytes, ...rest } = result;
        entries.push({ ...rest, status: 'UNAVAILABLE', reason: 'Catalog retained-byte limit reached; record omitted explicitly.' });
      } else { entries.push(result); retainedBytes += result.bytes ?? 0; }
    }
  }
  const matched = entries.filter((entry) => entry.status === 'MATCHED').length;
  const status = typeof resolve !== 'function' ? 'UNAVAILABLE' : entries.length === 0 ? 'NO_REFERENCES' : matched === entries.length ? 'MATCHED_REFERENCES' : matched ? 'PARTIAL' : 'UNAVAILABLE';
  return freeze({ status, entries, absent: collected.absent, matched_count: matched, requested_count: entries.length, unavailable_count: entries.length - matched, retained_bytes: retainedBytes, semantic_verification: 'NOT_ESTABLISHED', reason: 'Only exact supplied non-null references are checked. Absent references, coverage, current state, effects and inference require their separate evidence checks.' });
}
